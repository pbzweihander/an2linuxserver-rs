use anyhow::{bail, Context, Result};

mod config;
mod opt;
mod protocol;
mod tcp;
mod tls;
mod utils;

fn main() -> Result<()> {
    // parse command-line arguments
    let opt = opt::Opt::from_args();
    let config_manager = config::ConfigManager::new();
    config_manager
        .ensure_config_dir_exists()
        .context("failed to ensure config dir exists")?;
    config_manager
        .ensure_certificate_and_rsa_private_key_exists()
        .context("failed to ensure certificate and RSA private key exists")?;
    let config = config_manager.get_or_create_config()?;

    if !config.tcp.enabled && !config.bluetooth.enabled {
        panic!("Neither TCP nor Bluetooth is enabled");
    }

    // load tls config
    let certs =
        tls::load_certs(&config_manager.certificate_path()).context("failed to load certs")?;
    let privkey = tls::load_private_key(&config_manager.rsa_private_key_path())
        .context("failed to load RSA private key")?;
    if certs.is_empty() {
        bail!("there are no loaded certificate")
    } else if certs.len() > 1 {
        // TODO: show warning
    }

    // TODO: signal handling
    let tls_info = tls::TlsInfoBuilder::new(certs, privkey);
    if config.tcp.enabled {
        match opt.cmd {
            Some(opt::Subcommand::Pair) => {
                // pairing request
                let authorized_certs_manager = config_manager.authorized_certs_manager();
                let tls_config = tls_info
                    .build()
                    .context("failed to build TLS configuration")?;
                tcp::pairing_tcp_handler(&config.tcp, &authorized_certs_manager, tls_config)
                    .context("failed to handle TCP pairing")?;
            }
            None => {
                simple_logger::SimpleLogger::new()
                    .with_level(log::LevelFilter::Info)
                    .init()
                    .context("failed to initialize logger")?;

                // notification daemon mode
                let authorized_certs = config_manager
                    .authorized_certs_manager()
                    .load()
                    .context("failed to load authorized certs")?;
                let tls_config = tls_info
                    .with_client_auth(utils::hashmap_into_values(authorized_certs))
                    .build()
                    .context("failed to build TLS configuration")?;
                tcp::notification_tcp_handler(&config.tcp, tls_config)
                    .context("failed to handle TCP notification daemon")?;
            }
        }
    }

    // TODO: Implement bluetooth

    Ok(())
}
