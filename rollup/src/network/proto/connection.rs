use super::{ProtocolEvent, ProtocolState, RollupProtoMessage, RollupProtoMessageKind};
use crate::db::Database;
use crate::{crypto::aggregate::aggregate_sk, DATABASE_PATH};
use crate::crypto::data::ExtractedKey;
use alloy_rlp::Encodable;
use ark_bls12_381::{G1Projective, G2Projective};
use ark_serialize::CanonicalSerialize;
use dashmap::DashMap;
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol,
};
use reth_network::protocol::{ConnectionHandler, OnNotSupported};
use reth_network_api::Direction;
use reth_primitives::{Address, BytesMut, B256};
use reth_rpc_types::PeerId;
use rusqlite::Connection;
use std::{
    collections::HashMap,
    fmt::Debug,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::sync::{mpsc, oneshot};
const THRESHOLD: usize = 10;

pub(crate) enum RollupCommand {
  
    Attestation(B256, oneshot::Sender<Vec<Address>>),
}

pub(crate) struct RollupConnection {
    conn: ProtocolConnection,
    received: DashMap<Vec<u8>, Vec<ExtractedKey>>,
    dec_keys: DashMap<Vec<u8>, G2Projective>,
    initial_ping: Option<RollupProtoMessage>,
}

impl Stream for RollupConnection {
    type Item = BytesMut;
 
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(initial_ping) = this.initial_ping.take() {
            return Poll::Ready(Some(initial_ping.encoded()));
        }

        loop {
            let Some(msg) = ready!(this.conn.poll_next_unpin(cx)) else { return Poll::Ready(None) };

            let Some(msg) = RollupProtoMessage::decode_message(&mut &msg[..]) else {
                return Poll::Ready(None);
            };

            match msg.message {
                RollupProtoMessageKind::Message(message) => {
                    let key = serde_json::from_value(message.key_share.into()).unwrap();
                    this.received.entry(message.id.clone()).or_insert(Vec::new()).push(key);
                    if this.received.get(&message.id).unwrap().len() >= THRESHOLD {
                        if !this.dec_keys.contains_key(&message.id) {
                            if let Some(keys) = this.received.get(&message.id) {
                                let extracted_keys_vec = keys.clone();
                                let (dec_key, _) = aggregate_sk(
                                    extracted_keys_vec,
                                    Vec::new(),
                                    message.id.as_slice(),
                                );
                                this.dec_keys.entry(message.id.clone()).or_insert(dec_key);
                                let connection = Connection::open(DATABASE_PATH).unwrap();
                                let db = Database::new(connection).unwrap();
                                let mut k = Vec::new();
                                dec_key.serialize_compressed(&mut k);
                                db.upsert_dec_key(message.id, k);
                            }
                        }
                    }
                }
                RollupProtoMessageKind::Ping => {
                    return Poll::Ready(Some(RollupProtoMessage::pong().encoded()))
                }
                RollupProtoMessageKind::Pong => {}
            }
        }
    }
}

/// The connection handler for the RLPx subprotocol.
pub(crate) struct RollupConnHandler {
    pub(crate) state: ProtocolState,
}

impl ConnectionHandler for RollupConnHandler {
    type Connection = RollupConnection;

    fn protocol(&self) -> Protocol {
        RollupProtoMessage::protocol()
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        let (tx, rx) = mpsc::unbounded_channel();
        self.state
            .events
            .send(ProtocolEvent::Established { direction, peer_id, to_connection: tx })
            .ok();
        RollupConnection {
            conn,
            received: DashMap::new(),
            dec_keys: DashMap::new(),
            initial_ping: direction.is_outgoing().then(RollupProtoMessage::ping),
        }
    }
}
