use super::{
    data::SignedTicker, OracleProtoMessage, OracleProtoMessageKind, ProtocolEvent, ProtocolState,
};
use alloy_rlp::Encodable;
use futures::{Stream, StreamExt};
use reth_eth_wire::{
    capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol,
};
use reth_network::protocol::{ConnectionHandler, OnNotSupported};
use reth_network_api::Direction;
use reth_primitives::{Address, BytesMut};
use reth_rpc_types::PeerId;
use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{BroadcastStream, UnboundedReceiverStream};

/// The commands supported by the OracleConnection.
#[derive(Clone)]
pub(crate) enum OracleCommand {
    /// Sends a signed tick to a peer
    Tick(SignedTicker),
}

/// This struct defines the connection object for the Oracle subprotocol.
pub(crate) struct OracleConnection {
    conn: ProtocolConnection,
    commands: UnboundedReceiverStream<OracleCommand>,
    signed_ticks: BroadcastStream<SignedTicker>,
    initial_ping: Option<OracleProtoMessage>,
    attestations: Vec<Address>,
}

impl Stream for OracleConnection {
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(initial_ping) = this.initial_ping.take() {
            return Poll::Ready(Some(initial_ping.encoded()));
        }

        loop {
            if let Poll::Ready(Some(cmd)) = this.commands.poll_next_unpin(cx) {
                return match cmd {
                    OracleCommand::Tick(tick) => {
                        Poll::Ready(Some(OracleProtoMessage::signed_ticker(tick).encoded()))
                    }
                };
            }

            if let Poll::Ready(Some(Ok(tick))) = this.signed_ticks.poll_next_unpin(cx) {
                return Poll::Ready(Some(OracleProtoMessage::signed_ticker(tick).encoded()));
            }

            let Some(msg) = ready!(this.conn.poll_next_unpin(cx)) else { return Poll::Ready(None) };

            let Some(msg) = OracleProtoMessage::decode_message(&mut &msg[..]) else {
                return Poll::Ready(None);
            };

            match msg.message {
                OracleProtoMessageKind::Ping => {
                    return Poll::Ready(Some(OracleProtoMessage::pong().encoded()))
                }
                OracleProtoMessageKind::Pong => {}
                OracleProtoMessageKind::SignedTicker(signed_data) => {
                    let signer = signed_data.signer;
                    let sig = signed_data.signature;

                    let mut buffer = BytesMut::new();
                    signed_data.ticker.encode(&mut buffer);

                    let addr = sig.recover_address_from_msg(buffer).ok().unwrap();

                    if addr == signer && !this.attestations.contains(&addr) {
                        this.attestations.push(addr);
                    }
                }
            }
        }
    }
}

/// The connection handler for the RLPx subprotocol.
pub(crate) struct OracleConnHandler {
    pub(crate) state: ProtocolState,
}

impl ConnectionHandler for OracleConnHandler {
    type Connection = OracleConnection;

    fn protocol(&self) -> Protocol {
        OracleProtoMessage::protocol()
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
        OracleConnection {
            conn,
            initial_ping: direction.is_outgoing().then(OracleProtoMessage::ping),
            commands: UnboundedReceiverStream::new(rx),
            signed_ticks: BroadcastStream::new(self.state.to_peers.subscribe()),
            attestations: Vec::new(),
        }
    }
}
