use anyhow::{bail, Result};

mod config;
mod opt;
mod protocol;
mod tcp;
mod tls;

fn main() -> Result<()> {
    // parse command-line arguments
    let opt = opt::Opt::from_args();
    let config_manager = config::ConfigManager::try_default(true)?;
    config_manager.ensure_config_dir_exists()?;
    config_manager.ensure_certificate_and_rsa_private_key_exists()?;
    let config = config_manager.get_config().unwrap();

    if !config.tcp.enabled && !config.bluetooth.enabled {
        panic!("Neither TCP nor Bluetooth is enabled");
    }

    // load tls config
    let certs = tls::load_certs(&config_manager.certificate_path())?;
    let privkey = tls::load_private_key(&config_manager.rsa_private_key_path())?;
    if certs.is_empty() {
        bail!("there are no loaded certificate")
    } else if certs.len() > 1 {
        // TODO: show warning
    }

    // TODO: Implement core
    // TODO: signal handling
    let tls_info = tls::TlsInfoBuilder::new(certs, privkey);
    if config.tcp.enabled {
        match opt.cmd {
            Some(opt::Subcommand::Pair) => {
                // pairing request
                let tls_config = tls_info.build_tls_info()?;
                tcp::pairing_tcp_handler(&config_manager, tls_config)?;
            }
            None => {
                // notification daemon mode
                let authorized_certs = config_manager.parse_authorized_cert()?.get_all_der_certs();
                let tls_config = tls_info
                    .with_client_auth(authorized_certs)
                    .build_tls_info()?;
                tcp::notification_tcp_handler(&config_manager, tls_config)?;
            }
        }
    }

    Ok(())
}
