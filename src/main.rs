use anyhow::Result;

mod cert;
mod config;

fn main() -> Result<()> {
    let config_manager = config::ConfigManager::try_default()?;
    config_manager.ensure_config_dir_exists()?;
    config_manager.ensure_certificate_and_rsa_private_key_valid()?;
    let config = config_manager.get_or_create_config()?;

    if !config.tcp.enabled && !config.bluetooth.enabled {
        panic!("Neither TCP nor Bluetooth is enabled");
    }

    // TODO: Implement core

    Ok(())
}
