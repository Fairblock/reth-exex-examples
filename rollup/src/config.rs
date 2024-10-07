use std::fs;


use serde::Deserialize;

#[derive(Deserialize)]
pub struct NetworkConfig {
   pub(crate)  tcp_port: u16,
   pub(crate)  udp_port: u16,
   pub(crate) share: Vec<u8>,
   pub(crate) index:u32,
}

pub fn load_config() -> eyre::Result<NetworkConfig> {
    let config_content = fs::read_to_string("config.toml").expect("Failed to read config file");
    // Parse the TOML file.
    let network_config: NetworkConfig = toml::from_str(&config_content).expect("Failed to parse config file");
    Ok(network_config)
}
