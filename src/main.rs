use anyhow::{Result, bail};
use structopt::StructOpt;

mod tls;
mod config;
mod protocol;
mod tcp;
mod opt;

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
    if config.tcp.enabled {
        match opt.cmd {
            Some(opt::Subcommand::Pair) => {
                // pairing request
                let tls_config = tls::make_tls_server_config_no_client_auth(certs, privkey)?;
                tcp::pairing_tcp_handler(&config_manager, tls_config)?;
            },
            None => {
                let authorized_certs = config_manager.parse_authorized_cert()?.get_all_der_certs();
                let tls_config = tls::make_tls_server_config_with_auth(certs, privkey, authorized_certs)?;
                tcp::notification_tcp_handler(&config_manager, tls_config)?;
            },
        }
    }

    Ok(())
}
