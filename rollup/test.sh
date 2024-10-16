 RUST_LOG=debug cargo run --bin rollup node --port 30404 --discovery.port 30407

 RUST_LOG=debug cargo run --bin rollup node --port 30405 --discovery.port 30408 --authrpc.port 8555  --datadir /home/setareh/.local/share/reth/mainnet/db2