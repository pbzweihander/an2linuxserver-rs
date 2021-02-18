use anyhow::Result;
use std::fs;
use std::io::BufReader;
use std::path::Path;

fn load_certs(filename: &Path) -> Result<Vec<rustls::Certificate>> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    Ok(certs)
}

fn load_private_key(filename: &Path) -> Result<rustls::PrivateKey> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {},
        }
    }

    Err(anyhow::anyhow!("No RSA private keys found in {}", filename.to_string_lossy()))
}

pub fn make_tls_server_config(
    certificate_path: &Path,
    rsa_private_key_path: &Path,
) -> Result<rustls::ServerConfig> {
    let certs = load_certs(certificate_path)?;
    let privkey = load_private_key(rsa_private_key_path)?;

    let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    config.set_single_cert(certs, privkey)?;

    Ok(config)
}
