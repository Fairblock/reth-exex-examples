#![allow(dead_code)]

use alloy_primitives::{hex::FromHex, FixedBytes};
use dashmap::DashMap;
use discv5::{enr::secp256k1::rand, Enr, Event, ListenConfig};
use futures::StreamExt;
use reth::network::config::SecretKey;
use reth_discv5::{enr::EnrCombinedKeyWrapper, Config, Discv5};
use reth_eth_wire::multiplex::ProtocolConnection;
use reth_network::{protocol::{ConnectionHandler, ProtocolHandler}, Direction};
use reth_network_peers::NodeRecord;
use reth_tracing::tracing::{error, info};
use rusqlite::types::Null;
use tokio_stream::wrappers::BroadcastStream;
use std::{
    char::from_u32, future::Future, net::SocketAddr, pin::Pin, task::{ready, Context, Poll}
};
use tokio::sync::mpsc;
use std::str::FromStr;

use crate::network::proto::{connection::RollupConnection, data::Message, ProtocolEvent, RollupProtoMessage};

use super::proto::RollupProtoHandler;
/// Helper struct to manage a discovery node using discv5.
pub(crate) struct Discovery {
    /// The inner discv5 instance.
   pub(crate)  inner: Discv5,
    /// The node record of the discv5 instance.
    node_record: NodeRecord,
    /// The events stream of the discv5 instance.
    events: mpsc::Receiver<discv5::Event>,
    proto_handler: RollupProtoHandler
}

impl Discovery {
    /// Starts a new discovery node.
    pub(crate) async fn new(
        disc_addr: SocketAddr,
        rlpx_addr: SocketAddr,
        proto_handler: RollupProtoHandler,
        key: String
    ) -> eyre::Result<Discovery> {
        let secret_key = SecretKey::from_str(&key).unwrap();
    
        let config = ListenConfig::from(disc_addr);
        let discv5_config = Config::builder(rlpx_addr)
            .discv5_config(discv5::ConfigBuilder::new(config).disable_enr_update().build())
            .build();

        let (discv5, events, node_record) = Discv5::start(&secret_key, discv5_config).await?;
        println!("-------------------------------------------------: {:?}",discv5.with_discv5(|discv5| discv5.local_enr()).to_string());
        let enr = Enr::from_str("enr:-Iu4QOaolaidTtdJfebaLZ8g_agvN5fpdMEExOmhSfaKO6n6E5XZ9B8mgIVAUbkqLVz2dH54Qo7JUMwTFLPcCVuxbH4BgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQJTh5bTKWX-ZZwoJRQP7byfCDjV5bTV5xE2dHdvdxhWBIN0Y3CCdVKDdWRwgnVT");
       // let reth_enr: enr::Enr<SecretKey> = EnrCombinedKeyWrapper(enr.unwrap().clone()).into();
        let r = discv5.with_discv5(|discv5| discv5.send_ping(enr.unwrap())).await;
        println!("-------------------------------------------------: {:?}",r);
       // discv5.add_node(reth_enr)?;
        Ok(Self { inner: discv5, events, node_record, proto_handler })
    }

    /// Adds a node to the table if its not already present.
    pub(crate) fn add_node(&mut self, enr: Enr) -> eyre::Result<()> {
        let reth_enr: enr::Enr<SecretKey> = EnrCombinedKeyWrapper(enr.clone()).into();
        self.inner.add_node(reth_enr)?;
        Ok(())
    }

    /// Returns the local ENR of the discv5 node.
    pub(crate) fn local_enr(&self) -> Enr {
        self.inner.with_discv5(|discv5| discv5.local_enr())
    }

    /// Returns true if the discv5 node has connected peers.
    pub(crate) fn has_peers(&self) -> bool {
        self.inner.with_discv5(|discv5| discv5.connected_peers() > 0)
    }
}

impl Future for Discovery {
    type Output = eyre::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        info!("discovery started...");
        let mut this = self.as_mut();
        loop {
            match ready!(this.events.poll_recv(cx)) {
                Some(evt) => match evt {
                    Event::Discovered(enr) => {
                        info!(?enr, "Discovered a new node.");
                        this.add_node(enr)?;
                    }
                    Event::SessionEstablished(enr, socket_addr) => {
                        info!(?enr, ?socket_addr, "Session established with a new node.");
                        let direction = Direction::Incoming;
                       let handler =  this.proto_handler.on_incoming(socket_addr).unwrap();
                       let (tx, mut rx) = mpsc::unbounded_channel();
                       handler.state
                           .events
                           .send(ProtocolEvent::Established { direction, peer_id: FixedBytes::from_slice(&[0u8;64]), to_connection: tx })
                           .ok();
                      let mut connection = RollupConnection {
                        //   conn: ProtocolConnection { from_wire: UnboundedReceiverStream::new(rx) },
                           received: DashMap::new(),
                           dec_keys: DashMap::new(),
                           initial_ping: direction.is_outgoing().then(RollupProtoMessage::ping),
                           messages: BroadcastStream::new(handler.state.to_peers.subscribe()),
                       };
                       loop {
                      
                         match connection.poll_next_unpin(cx) {
                             Poll::Ready(m) => {
                                 info!(?m, "Received message.");
                                 // Handle the message.
                             }
                             Poll::Pending => {
                                let m = Message{key_share: vec![1,2,7], id:vec![4,5,8]};
      
                                match handler.state.to_peers.send(m) {
                                    Ok(_) => {
                                        info!("message sent...");
                                    },
                                    Err(e) => {
                                        error!("Error sending message: {:?}", e);
                                       
                                    },
                                }
                             }
                             Poll::Ready(None) => {
                                 info!("Connection closed.");
                                 // Handle the connection closure.
                             }
                         }
                         // Process the connection.
                       }
                        return Poll::Ready(Ok(()));
                    }
                    evt => {
                        info!(?evt, "New discovery event.");
                    }
                },
                None => { info!("nothing...");
                    return Poll::Ready(Ok(()))},
            }
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::network::discovery::Discovery;
//     use reth_tracing::tracing::info;
//     use std::net::SocketAddr;

//     #[tokio::test]
//     async fn can_establish_discv5_session_with_peer() {
//         reth_tracing::init_test_tracing();
//         let discv5_addr: SocketAddr = "127.0.0.1:30301".to_string().parse().unwrap();
//         let rlpx_addr: SocketAddr = "127.0.0.1:30303".to_string().parse().unwrap();
//         let mut node_1 = Discovery::new(discv5_addr, rlpx_addr).await.unwrap();
//         let node_1_enr = node_1.local_enr();

//         let discv5_addr: SocketAddr = "127.0.0.1:30302".to_string().parse().unwrap();
//         let rlpx_addr: SocketAddr = "127.0.0.1:30303".to_string().parse().unwrap();
//         let mut node_2 = Discovery::new(discv5_addr, rlpx_addr).await.unwrap();

//         let node_2_enr = node_2.local_enr();

//         info!(?node_1_enr, ?node_2_enr, "Started discovery nodes.");

//         // add node_2 to node_1 table
//         node_1.add_node(node_2_enr.clone()).unwrap();

//         // verify node_2 is in node_1 table
//         assert!(node_1
//             .inner
//             .with_discv5(|discv5| discv5.table_entries_id().contains(&node_2_enr.node_id())));

//         // send ping from node_1 to node_2
//         node_1.inner.with_discv5(|discv5| discv5.send_ping(node_2_enr.clone())).await.unwrap();

//         // verify they both established a session
//         let event_2_v5 = node_2.events.recv().await.unwrap();
//         let event_1_v5 = node_1.events.recv().await.unwrap();
//         assert!(matches!(
//             event_1_v5,
//             discv5::Event::SessionEstablished(node, socket) if node == node_2_enr && socket == node_2_enr.udp4_socket().unwrap().into()
//         ));
//         assert!(matches!(
//             event_2_v5,
//             discv5::Event::SessionEstablished(node, socket) if node == node_1_enr && socket == node_1_enr.udp4_socket().unwrap().into()
//         ));

//         // verify node_1 is in
//         let event_2_v5 = node_2.events.recv().await.unwrap();
//         assert!(matches!(
//             event_2_v5,
//             discv5::Event::NodeInserted { node_id, replaced } if node_id == node_1_enr.node_id() && replaced.is_none()
//         ));
//     }
// }
