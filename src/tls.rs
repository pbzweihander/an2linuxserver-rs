use anyhow::Result;
use std::fs;
use std::io::BufReader;
use std::path::Path;

#[derive(Clone)]
pub struct TlsInfo {
    pub certs: Vec<rustls::Certificate>,
    pub config: rustls::ServerConfig,
}

pub fn load_certs(filename: &Path) -> Result<Vec<rustls::Certificate>> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    Ok(certs)
}

pub fn load_private_key(filename: &Path) -> Result<rustls::PrivateKey> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            _ => {},
        }
    }

    Err(anyhow::anyhow!("No RSA private keys found in {}", filename.to_string_lossy()))
}

pub fn make_tls_server_config(
    certs: Vec<rustls::Certificate>,
    privkey: rustls::PrivateKey,
) -> Result<TlsInfo> {
    let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    config.set_single_cert(certs.clone(), privkey)?;

    Ok(TlsInfo{
        certs,
        config,
    })
}
