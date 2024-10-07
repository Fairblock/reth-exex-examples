#![allow(dead_code)]

use alloy_rlp::{Decodable, Encodable};
use connection::{RollupCommand,RollupConnHandler};
use data::{Message};
use reth_eth_wire::{protocol::Protocol, Capability};
use reth_network::{protocol::ProtocolHandler, Direction};
use reth_network_api::PeerId;
use reth_primitives::{Address, Buf, BufMut, BytesMut};
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub(crate) mod connection;
pub(crate) mod data;
pub(crate) type ProtoEvents = mpsc::UnboundedReceiver<ProtocolEvent>;
/// The events that can be emitted by our custom protocol.
#[derive(Debug, Clone)]
pub(crate) enum ProtocolEvent {
    Established {
        direction: Direction,
        peer_id: PeerId,
        to_connection: mpsc::UnboundedSender<RollupCommand>,
    },
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RollupProtoMessageId {
    Ping = 0x00,
    Pong = 0x01,
    Message = 0x02,

}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RollupProtoMessageKind {
    Ping,
    Pong,
    Message(Box<Message>),

}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RollupProtoMessage {
    pub(crate) message_type: RollupProtoMessageId,
    pub(crate) message: RollupProtoMessageKind,
}

impl RollupProtoMessage {
    /// Returns the capability for the `custom_rlpx` protocol.
    pub(crate) fn capability() -> Capability {
        Capability::new_static("custom_rlpx", 1)
    }

    /// Returns the protocol for the `custom_rlpx` protocol.
    pub(crate) fn protocol() -> Protocol {
        Protocol::new(Self::capability(), 4)
    }



    /// Creates a ping message
    pub(crate) fn ping() -> Self {
        Self { message_type: RollupProtoMessageId::Ping, message: RollupProtoMessageKind::Ping }
    }

    /// Creates a pong message
    pub(crate) fn pong() -> Self {
        Self { message_type: RollupProtoMessageId::Pong, message: RollupProtoMessageKind::Pong }
    }

    /// Creates a new `RollupProtoMessage` with the given message ID and payload.
    pub(crate) fn encoded(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(self.message_type as u8);
        match &self.message {
            RollupProtoMessageKind::Message(message)=>{
                message.encode(&mut buf);
            }
            RollupProtoMessageKind::Ping | RollupProtoMessageKind::Pong => {}
         
        }
        buf
    }

    /// Decodes a `RollupProtoMessage` from the given message buffer.
    pub(crate) fn decode_message(buf: &mut &[u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        let id = buf[0];
        buf.advance(1);
        let message_type = match id {
            0x00 => RollupProtoMessageId::Ping,
            0x01 => RollupProtoMessageId::Pong,
            0x02 => RollupProtoMessageId::Message,

            _ => return None,
        };
        let message = match message_type {
            RollupProtoMessageId::Message => {
                let data = Message::decode(buf).ok()?;
             
                RollupProtoMessageKind::Message(Box::new(data))
            }
            RollupProtoMessageId::Ping => RollupProtoMessageKind::Ping,
            RollupProtoMessageId::Pong => RollupProtoMessageKind::Pong,
     
        };

        Some(Self { message_type, message })
    }
}


pub(crate) type ToPeers = tokio::sync::broadcast::Sender<Message>;
/// This struct is responsible of incoming and outgoing connections.
#[derive(Debug)]
pub(crate) struct RollupProtoHandler {
    pub(crate) state: ProtocolState,
}

/// The size of the broadcast channel.
///
/// This value is based on the estimated message rate and the tolerance for lag.
/// - We assume an average of 10-20 updates per second per symbol.
/// - For 2 symbols (e.g., ETHUSDC and BTCUSDC), this gives approximately 20-40 messages per second.
/// - To allow subscribers to catch up if they fall behind, we provide a lag tolerance of 5 seconds.
///
/// Thus, the buffer size is calculated as:
///
/// `Buffer Size = Message Rate per Second * Lag Tolerance`
///
/// For 2 symbols, we calculate: `40 * 5 = 200`.
const BROADCAST_CHANNEL_SIZE: usize = 200;

impl RollupProtoHandler {
    /// Creates a new `RollupProtoHandler` with the given protocol state.
    pub(crate) fn new() -> (Self, ProtoEvents, ToPeers) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (to_peers, _) = tokio::sync::broadcast::channel(BROADCAST_CHANNEL_SIZE);
        (Self { state: ProtocolState { events: tx, to_peers: to_peers.clone()} }, rx, to_peers)
    }
}

impl ProtocolHandler for RollupProtoHandler {
    type ConnectionHandler = RollupConnHandler;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(RollupConnHandler { state: self.state.clone() })
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(RollupConnHandler { state: self.state.clone() })
    }
}

/// Protocol state is an helper struct to store the protocol events.
#[derive(Clone, Debug)]
pub(crate) struct ProtocolState {
    pub(crate) events: mpsc::UnboundedSender<ProtocolEvent>,
    pub(crate) to_peers: tokio::sync::broadcast::Sender<Message>,
 
}
