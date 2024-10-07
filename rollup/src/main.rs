//! Example of a simple rollup that derives its state from the L1 chain by executing transactions,
//! processing deposits and storing all related data in an SQLite database.
//!
//! The rollup contract accepts blocks of transactions and deposits of ETH and is deployed on
//! Holesky at [ROLLUP_CONTRACT_ADDRESS], see <https://github.com/init4tech/zenith/blob/e0481e930947513166881a83e276b316c2f38502/src/Zenith.sol>.
// use reth_exec_test_utils::TestConsensusBuilder;

use crate::network::proto::data::Message;
use alloy_sol_types::{sol, SolEventInterface, SolInterface};
use config::load_config;
use db::Database;
use execution::execute_block;

use futures::FutureExt;
use futures_util::StreamExt;
use network::{proto::RollupProtoHandler, Network};
use once_cell::sync::Lazy;
use reth_chainspec::{ChainSpec, ChainSpecBuilder};
use reth_execution_types::Chain;
use reth_exex::{ExExContext, ExExEvent};
use reth_network::{protocol::IntoRlpxSubProtocol, NetworkProtocols};
use reth_node_api::FullNodeComponents;
use reth_node_ethereum::EthereumNode;
use reth_primitives::{
    address, ruint::Uint, Address, Genesis, SealedBlockWithSenders, TransactionSigned, U256,
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use std::result::Result::Ok;
use reth_tracing::tracing::{error, info};
use rusqlite::Connection;
use tokio::sync::mpsc;
use std::{env::args, sync::Arc};
mod db;
mod crypto;
mod config;
mod execution;
mod network;
sol!(RollupContract, "rollup_abi.json");
use RollupContract::{RollupContractCalls, RollupContractEvents};
const BROADCAST_CHANNEL_SIZE: usize = 200;
const DATABASE_PATH: &str = "rollup.db";
const ROLLUP_CONTRACT_ADDRESS: Address = address!("A05A8F96173CEbceD36239268bDB80d5005AA8A9");
const ROLLUP_SUBMITTER_ADDRESS: Address = address!("831E49Ec6e86E2de8BFe82a1274f0790758953e6");
const CHAIN_ID: u64 = 17001;
static CHAIN_SPEC: Lazy<Arc<ChainSpec>> = Lazy::new(|| {
    Arc::new(
        ChainSpecBuilder::default()
            .chain(CHAIN_ID.into())
            .genesis(Genesis::clique_genesis(CHAIN_ID, ROLLUP_SUBMITTER_ADDRESS))
            .shanghai_activated()
            .build(),
    )
});

struct Rollup<Node: FullNodeComponents> {
    ctx: ExExContext<Node>,
    db: Database,
    to_peers: tokio::sync::broadcast::Sender<Message>,
    net: Network
}
impl<Node: FullNodeComponents> Future for Rollup<Node> {
    type Output = eyre::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut();
        // Poll the network future until its drained
        loop {
            match this.net.poll_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    info!("Discv5 task completed successfully");
                }
                Poll::Ready(Err(e)) => {
                    error!(?e, "Discv5 task encountered an error");
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    // Exit match and continue to poll exex
                    break;
                }
            }
        }
        return Poll::Ready(Ok(()));
    }
}
impl<Node: FullNodeComponents> Rollup<Node> {
    fn new(ctx: ExExContext<Node>, connection: Connection, net: Network, to_peers: tokio::sync::broadcast::Sender<Message>) -> eyre::Result<Self> {
        let db = Database::new(connection)?;
        
        Ok(Self { ctx, db, to_peers, net})
    }

    async fn start(self) -> eyre::Result<()> {
        tokio::spawn(async move {
            let mut this = self;
            // Process all new chain state notifications
            while let Some(notification) = this.ctx.notifications.next().await {
                if let Some(reverted_chain) = notification.reverted_chain() {
                    this.revert(&reverted_chain)?;
                }
    
                if let Some(committed_chain) = notification.committed_chain() {
                    this.commit(&committed_chain).await?;
                    this.ctx
                        .events
                        .send(ExExEvent::FinishedHeight(committed_chain.tip().number))?;
                }
            }
            Ok::<_, eyre::Report>(())
        });
    
        Ok(())
    }
 
    async fn send_key_share(
        block_number: Uint<256, 4>,
        to_peers: &tokio::sync::broadcast::Sender<Message>,
    ) {
        let config = load_config().unwrap();
        let keyshare = crypto::extract::extract(config.share,block_number.to_be_bytes_vec(), config.index);
        let m = Message{key_share: keyshare.unwrap(), id:block_number.to_be_bytes_vec()};
        to_peers.send(m).unwrap();
        
    }

    /// Process a new chain commit.
    ///
    /// This function decodes all transactions to the rollup contract into events, executes the
    /// corresponding actions and inserts the results into the database.
    async fn commit(&mut self, chain: &Chain) -> eyre::Result<()> {
        let events = decode_chain_into_rollup_events(chain);

        for (_, tx, event) in events {
            match event {
                // A new block is submitted to the rollup contract.
                // The block is executed on top of existing rollup state and committed into the
                // database.
                RollupContractEvents::BlockSubmitted(RollupContract::BlockSubmitted {
                    blockDataHash,
                    ..
                }) => {
                    let call = RollupContractCalls::abi_decode(tx.input(), true)?;

                    if let RollupContractCalls::submitBlock(RollupContract::submitBlockCall {
                        header,
                        blockData,
                        ..
                    }) = call
                    {
                        // Get the decryption key and execute the block.
                        Self::send_key_share(header.sequence.clone(), &self.to_peers).await;
                        let mut dec_key: Vec<u8> = Vec::new();
                        while true{
                            let key =  self.db.get_dec_key(header.sequence.to_be_bytes_vec()).unwrap();
                            if key.is_some() {
                                dec_key = key.unwrap();
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        }
                        match execute_block(
                            &mut self.db,
                            self.ctx.pool(),
                            tx,
                            &header,
                            blockData,
                            blockDataHash,
                            dec_key
                        )
                        .await
                        {
                            Ok((block, bundle, _, _)) => {
                                let block = block.seal_slow();
                                self.db.insert_block_with_bundle(&block, bundle)?;
                                info!(
                                    tx_hash = %tx.recalculate_hash(),
                                    chain_id = %header.rollupChainId,
                                    sequence = %header.sequence,
                                    transactions = block.body.len(),
                                    "Block submitted, executed and inserted into database"
                                );
                            }
                            Err(err) => {
                                error!(
                                    %err,
                                    tx_hash = %tx.recalculate_hash(),
                                    chain_id = %header.rollupChainId,
                                    sequence = %header.sequence,
                                    "Failed to execute block"
                                );
                            }
                        }
                    }
                }
                // A deposit of ETH to the rollup contract. The deposit is added to the recipient's
                // balance and committed into the database.
                RollupContractEvents::Enter(RollupContract::Enter {
                    rollupChainId,
                    token,
                    rollupRecipient,
                    amount,
                }) => {
                    if rollupChainId != U256::from(CHAIN_ID) {
                        error!(tx_hash = %tx.recalculate_hash(), "Invalid rollup chain ID");
                        continue;
                    }
                    if token != Address::ZERO {
                        error!(tx_hash = %tx.recalculate_hash(), "Only ETH deposits are supported");
                        continue;
                    }

                    self.db.upsert_account(rollupRecipient, |account| {
                        let mut account = account.unwrap_or_default();
                        account.balance += amount;
                        Ok(account)
                    })?;

                    info!(
                        tx_hash = %tx.recalculate_hash(),
                        %amount,
                        recipient = %rollupRecipient,
                        "Deposit",
                    );
                }
                _ => (),
            }
        }

        Ok(())
    }

    /// Process a chain revert.
    ///
    /// This function decodes all transactions to the rollup contract into events, reverts the
    /// corresponding actions and updates the database.
    fn revert(&mut self, chain: &Chain) -> eyre::Result<()> {
        let mut events = decode_chain_into_rollup_events(chain);
        // Reverse the order of events to start reverting from the tip
        events.reverse();

        for (_, tx, event) in events {
            match event {
                // The block is reverted from the database.
                RollupContractEvents::BlockSubmitted(_) => {
                    let call = RollupContractCalls::abi_decode(tx.input(), true)?;

                    if let RollupContractCalls::submitBlock(RollupContract::submitBlockCall {
                        header,
                        ..
                    }) = call
                    {
                        self.db.revert_tip_block(header.sequence)?;
                        info!(
                            tx_hash = %tx.recalculate_hash(),
                            chain_id = %header.rollupChainId,
                            sequence = %header.sequence,
                            "Block reverted"
                        );
                    }
                }
                // The deposit is subtracted from the recipient's balance.
                RollupContractEvents::Enter(RollupContract::Enter {
                    rollupChainId,
                    token,
                    rollupRecipient,
                    amount,
                }) => {
                    if rollupChainId != U256::from(CHAIN_ID) {
                        error!(tx_hash = %tx.recalculate_hash(), "Invalid rollup chain ID");
                        continue;
                    }
                    if token != Address::ZERO {
                        error!(tx_hash = %tx.recalculate_hash(), "Only ETH deposits are supported");
                        continue;
                    }

                    self.db.upsert_account(rollupRecipient, |account| {
                        let mut account = account.ok_or(eyre::eyre!("account not found"))?;
                        account.balance -= amount;
                        Ok(account)
                    })?;

                    info!(
                        tx_hash = %tx.recalculate_hash(),
                        %amount,
                        recipient = %rollupRecipient,
                        "Deposit reverted",
                    );
                }
                _ => (),
            }
        }

        Ok(())
    }
}

/// Decode chain of blocks into a flattened list of receipt logs, filter only transactions to the
/// Rollup contract [ROLLUP_CONTRACT_ADDRESS] and extract [RollupContractEvents].
fn decode_chain_into_rollup_events(
    chain: &Chain,
) -> Vec<(&SealedBlockWithSenders, &TransactionSigned, RollupContractEvents)> {
    chain
        // Get all blocks and receipts
        .blocks_and_receipts()
        // Get all receipts
        .flat_map(|(block, receipts)| {
            block
                .body
                .iter()
                .zip(receipts.iter().flatten())
                .map(move |(tx, receipt)| (block, tx, receipt))
        })
        // Get all logs from rollup contract
        .flat_map(|(block, tx, receipt)| {
            receipt
                .logs
                .iter()
                .filter(|log| log.address == ROLLUP_CONTRACT_ADDRESS)
                .map(move |log| (block, tx, log))
        })
        // Decode and filter rollup events
        .filter_map(|(block, tx, log)| {
            RollupContractEvents::decode_raw_log(log.topics(), &log.data.data, true)
                .ok()
                .map(|event| (block, tx, event))
        })
        .collect()
}

fn main() -> eyre::Result<()> {
    
    reth::cli::Cli::parse_args().run(|builder, _| async move {
        let handle = builder
            .node(EthereumNode::default())
            .install_exex("Rollup", move |ctx| async {
                let connection = Connection::open(DATABASE_PATH)?;
                let (subproto, proto_events, to_peers) = RollupProtoHandler::new();
                // add it to the network as a subprotocol
                ctx.network().add_rlpx_sub_protocol(subproto.into_rlpx_sub_protocol());
                let config = load_config()?;
                let tcp_port = config.tcp_port;
                let udp_port = config.udp_port;
                let network = Network::new(proto_events, tcp_port, udp_port).await?;
                Ok(Rollup::new(ctx, connection, network, to_peers)?.start())
            })
            .launch()
            .await?;

        handle.wait_for_node_exit().await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use network::proto::RollupProtoMessage;
    use reth_revm::primitives::bitvec::vec;
    use tokio::sync::broadcast;
    use tokio::runtime::Runtime;
    use futures::StreamExt;
    use std::sync::Arc;

   
    #[tokio::test]
    async fn test_custom_protocol_message_flow() {
       
        let rt = Runtime::new().unwrap();

      
        let (to_peer0, mut from_peer0) = broadcast::channel::<RollupProtoMessage>(10);
        let (to_peer1, mut from_peer1) = broadcast::channel::<RollupProtoMessage>(10);

      
        let mut peer0 = setup_peer(to_peer0);
        let mut peer1 = setup_peer(to_peer1);

  
        let test_message = Message{key_share:vec![1,2,3], id: vec![1,2,3]};
        peer0.send_message(test_message.clone()).expect("Failed to send message");

      
        match from_peer1.recv().await {
            Ok(received_message) => {
                //assert_eq!(test_message, received_message.message, "Message mismatch between peers");
            }
            Err(_) => {
                panic!("Failed to receive message");
            }
        }

     
    }


    fn setup_peer(to_peer: broadcast::Sender<RollupProtoMessage>) -> Peer {
     
        Peer::new(to_peer)
    }

 
    impl RollupProtoMessage {
        pub fn new_ping() -> Self {
         
            Self {
                kind: RollupProtoMessageKind::Ping,
                data: vec![], 
            }
        }
    }
}



// #[cfg(test)]
// mod tests {
//     use crate::RollupContract::{RollupContractCalls, RollupContractEvents};
//     use crate::Zenith::BlockHeader;
//     use crate::{Rollup, RollupContract, ROLLUP_CONTRACT_ADDRESS};
//     use alloy_consensus::TxEip2930;
//     use alloy_rlp::Decodable;
//     use alloy_sol_types::{SolEvent, SolValue};
//     use reth::revm::db::BundleState;
//     use reth_exex_test_utils::{test_exex_context, PollOnce};
//     use reth_primitives::alloy_primitives::FixedBytes;
//     use reth_primitives::constants::ETH_TO_WEI;
//     use reth_primitives::{
//         bytes, keccak256, public_key_to_address, Address, Block, Header, Log, Receipt, Transaction,
//         TransactionSigned, TxKind, TxLegacy, TxType, U256,
//     };
//     use reth_provider::{Chain, ExecutionOutcome};
//     use reth_revm::primitives::AccountInfo;
//     use reth_testing_utils::generators::{
//         self, sign_tx_with_key_pair, sign_tx_with_random_key_pair,
//     };
//     use rusqlite::Connection;
//     use secp256k1::{rand, Keypair, Secp256k1};
//     use std::io::Read;
//     use std::pin::pin;
//     use std::str::FromStr;

//     use alloy_sol_types::SolInterface;

//     fn encode_submit_block_call(
//         header: BlockHeader,
//         block_data: Vec<u8>,
//         block_data_hash: [u8; 32],
//     ) -> Vec<u8> {
//         let submit_block_call = RollupContract::submitBlockCall {
//             header,
//             blockDataHash: FixedBytes(block_data_hash),
//             blockData: block_data.into(),
//             v: 27,
//             r: FixedBytes([0u8; 32]),
//             s: FixedBytes([0u8; 32]),
//         };

//         RollupContractCalls::submitBlock(submit_block_call).abi_encode()
//     }

//     fn construct_tx_and_receipt<E: SolEvent>(
//         to: Address,
//         event: E,
//         tx_data: Vec<u8>,
//     ) -> eyre::Result<(TransactionSigned, Receipt)> {
//         let tx = reth_primitives::TxLegacy {
//             nonce: 0u64,
//             gas_price: 1u128,
//             gas_limit: 100000u128,
//             to: reth_primitives::TxKind::Call(to),
//             value: U256::from(0),
//             input: tx_data.into(),
//             chain_id: Some(1),
//         };

//         let log = Log::new(
//             to,
//             event.encode_topics().into_iter().map(|topic| topic.0).collect(),
//             event.encode_data().into(),
//         )
//         .ok_or_else(|| eyre::eyre!("failed to encode event"))?;

//         let receipt = Receipt {
//             tx_type: reth_primitives::TxType::Legacy,
//             success: true,
//             cumulative_gas_used: 0,
//             logs: vec![log],
//             ..Default::default()
//         };

//         let signed_tx = reth_testing_utils::generators::sign_tx_with_random_key_pair(
//             &mut rand::thread_rng(),
//             reth_primitives::Transaction::from(tx),
//         );

//         Ok((signed_tx, receipt))
//     }

//     #[tokio::test]
//     async fn test_rollup_block_submitted() -> eyre::Result<()> {
//         use crate::{db::Database, RollupContract, Zenith::BlockHeader, CHAIN_ID};
//         use reth_primitives::{
//             keccak256, Address, Block, Bytes, Header, Transaction, TxKind, U256,
//         };
//         use secp256k1::Secp256k1;
//         use std::str::FromStr;

//         reth_tracing::init_test_tracing();

//         ///////////////////////////////////////////// for creating a new tx
//         // let secp = Secp256k1::new();
//         // let key_pair = Keypair::new(&secp, &mut generators::rng());
//         // let sender_address = public_key_to_address(key_pair.public_key());
//         //////////////////////////////////////////

//         let (ctx, handle) = test_exex_context().await?;
//         let connection = Connection::open_in_memory()?;

//         let rollup = Rollup::new(ctx, connection)?;
//         let addr = Address::from_str("0x4fbbaa27fd78f9bf98e8b0bd7588cb370cc3c4b3").unwrap();
//         rollup.db.upsert_account(addr, |_| {
//             Ok(AccountInfo { balance: U256::from(ETH_TO_WEI * 10), nonce: 0, ..Default::default() })
//         })?;

//         ///////////////////////////////////////////// for creating a new tx
//         // let tx = Transaction::Eip2930(TxEip2930 {
//         //     chain_id: CHAIN_ID,
//         //     nonce: 0,
//         //     gas_limit: 1_000_000,
//         //     gas_price: 1_500_000_000,
//         //     to: TxKind::Create,
//         //     value: U256::from(1_000_000_000_000u64),
//         //     ..Default::default()
//         // });

//         // let signed_tx = sign_tx_with_key_pair(key_pair, tx);
//         // let mut tx_encoded = Vec::new();
//         // signed_tx.encode_enveloped(&mut tx_encoded);
//         ///////////////////////////////////////////////////

//         let sequencer = Address::random();
//         let block_header = BlockHeader {
//             rollupChainId: U256::from(CHAIN_ID),
//             sequence: U256::from(1),
//             confirmBy: U256::from(10000u64),
//             gasLimit: U256::from(1_000_000u64),
//             rewardAddress: sequencer,
//         };

//         ////////////////////////////////////////////////// already created and encrypted tx
//         let encrypted_tx_data: Vec<u8> = vec![
//             97, 103, 101, 45, 101, 110, 99, 114, 121, 112, 116, 105, 111, 110, 46, 111, 114, 103,
//             47, 118, 49, 10, 45, 62, 32, 100, 105, 115, 116, 73, 66, 69, 10, 111, 74, 109, 53, 57,
//             53, 119, 119, 80, 117, 120, 78, 53, 56, 117, 67, 88, 54, 119, 54, 74, 57, 88, 49, 112,
//             104, 71, 50, 73, 84, 56, 106, 79, 83, 108, 43, 117, 84, 80, 49, 69, 122, 107, 57, 106,
//             49, 111, 66, 77, 55, 74, 82, 83, 81, 51, 112, 48, 57, 48, 66, 118, 86, 85, 70, 10, 119,
//             49, 115, 52, 103, 49, 77, 51, 85, 80, 70, 105, 119, 80, 101, 98, 80, 84, 90, 55, 73,
//             98, 88, 79, 68, 49, 79, 72, 112, 68, 77, 108, 57, 118, 56, 103, 76, 88, 75, 122, 78,
//             75, 77, 54, 68, 56, 81, 120, 97, 70, 120, 120, 78, 48, 77, 101, 73, 85, 104, 105, 71,
//             111, 85, 50, 10, 72, 116, 53, 65, 57, 98, 77, 88, 49, 69, 85, 119, 66, 122, 81, 109,
//             51, 67, 104, 110, 111, 65, 10, 45, 45, 45, 32, 115, 73, 83, 69, 52, 69, 121, 80, 78,
//             82, 113, 100, 104, 65, 117, 98, 121, 65, 68, 121, 53, 69, 54, 65, 100, 57, 90, 100, 49,
//             72, 67, 65, 122, 56, 114, 56, 55, 74, 73, 120, 105, 51, 85, 10, 164, 31, 64, 174, 230,
//             19, 16, 147, 121, 133, 183, 209, 21, 108, 5, 196, 233, 176, 209, 164, 11, 76, 1, 226,
//             71, 98, 114, 54, 194, 65, 176, 6, 182, 23, 37, 21, 242, 131, 186, 103, 101, 196, 162,
//             168, 237, 242, 32, 66, 117, 45, 27, 15, 155, 63, 196, 208, 89, 132, 212, 236, 43, 130,
//             191, 15, 44, 183, 178, 112, 62, 152, 225, 125, 47, 243, 213, 223, 32, 96, 201, 250,
//             118, 51, 247, 201, 247, 255, 18, 138, 167, 86, 81, 27, 134, 72, 206, 173, 164, 138, 63,
//             210, 219, 125, 124, 138, 102, 110, 68, 212, 87, 237, 123, 91, 223, 56, 204, 125, 9,
//             185, 0, 3, 85, 230, 209, 161,
//         ];
//         /////////////////////////////////////////////////////

//         let encrypted_transactions: Vec<Bytes> = vec![encrypted_tx_data.into()];

//         let block_data: Vec<u8> = alloy_rlp::encode(&encrypted_transactions);
//         let block_data_hash = keccak256(&block_data);

//         let encoded_submit_block_call =
//             encode_submit_block_call(block_header.clone(), block_data, *block_data_hash);
//         let header_bytes = block_header.abi_encode();
//         let header_hash = keccak256(header_bytes);
//         let fixed_header = FixedBytes::from(header_hash);

//         let block_submitted_event = RollupContract::BlockSubmitted {
//             blockDataHash: block_data_hash.into(),
//             sequencer,
//             header: fixed_header,
//         };

//         let (submitted_tx, submitted_tx_receipt) = construct_tx_and_receipt(
//             ROLLUP_CONTRACT_ADDRESS,
//             block_submitted_event,
//             encoded_submit_block_call,
//         )?;

//         let block =
//             Block { header: Header::default(), body: vec![submitted_tx], ..Default::default() }
//                 .seal_slow()
//                 .seal_with_senders()
//                 .ok_or_else(|| eyre::eyre!("failed to recover senders"))?;

//         let chain = Chain::new(
//             vec![block.clone()],
//             ExecutionOutcome::new(
//                 BundleState::default(),
//                 vec![submitted_tx_receipt].into(),
//                 block.number,
//                 vec![block.requests.clone().unwrap_or_default()],
//             ),
//             None,
//         );

//         handle.send_notification_chain_committed(chain.clone()).await?;
//         let mut rollup_future = pin!(rollup.start());
//         rollup_future.poll_once().await?;

//         Ok(())
//     }
// }
