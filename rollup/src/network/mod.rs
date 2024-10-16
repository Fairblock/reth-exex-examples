use discovery::Discovery;
use futures::{ready, FutureExt};
use proto::{data::Message, ProtocolEvent, RollupProtoHandler};
use reth_tracing::tracing::{error, info};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

mod discovery;
pub(crate) mod proto;

/// The Network struct is a long running task that orchestrates discovery of new peers and
/// network gossiping via the RLPx subprotocol.
pub(crate) struct Network {
    /// The discovery task for this node.
  pub(crate)  discovery: Discovery,
    /// The protocol events channel.
    proto_events: proto::ProtoEvents,
}

impl Network {
    pub(crate) async fn new(
        proto_events: proto::ProtoEvents,
        tcp_port: u16,
        udp_port: u16,
        proto_handler : RollupProtoHandler,
        key: String,
    ) -> eyre::Result<Self> {
        let disc_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse()?;
        let rlpx_addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse()?;
        let discovery = Discovery::new(disc_addr, rlpx_addr, proto_handler, key).await?;
        Ok(Self { discovery, proto_events })
    }
}

impl Future for Network {
    type Output = eyre::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut();
        // Poll the discovery future until its drained
        loop {
            match this.discovery.poll_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    info!("Discovery task completed");
                    
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => {
                    error!(?e, "Discovery task encountered an error");
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => break,
            }
        }
        loop {
            match ready!(this.proto_events.poll_recv(cx)) {
                Some(ProtocolEvent::Established { direction, peer_id, to_connection }) => {
                 
                    info!(
                        ?direction,
                        ?peer_id,
                        ?to_connection,
                        "Established connection, will start gossiping"
                    );
                    let (to_peers, _) = tokio::sync::broadcast::channel::<Message>(32);
                    to_peers.send(Message{key_share:vec![1,2,3], id: vec![1,2,3,4]});
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
