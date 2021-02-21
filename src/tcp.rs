use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use std::sync::Arc;

use anyhow::{Result, bail};
use rustls;
use ring;

use super::protocol::{ConnType, PairingResponse};
use super::config::Config;
use super::tls::TlsInfo;

pub fn pairing_tcp_handler(config: Config, tls_info: TlsInfo) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:10101")?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // TODO: make this function call asynchronous
                handle_pairing_connection(stream, &tls_info);
            }
            Err(_) => {
                // TODO: log to stderr and continue
            }
        }
    }
    Ok(())
}

fn handle_pairing_connection(mut stream: TcpStream, tls_info: &TlsInfo) -> Result<()> {
    let mut buf = [0; 1];
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.read_exact(&mut buf)?;

    if let Some(conn_type) = ConnType::from(buf[0]) {
        match conn_type {
            ConnType::PairRequest => {
                handle_pair_request(stream, tls_info);
            }
            _ => {
                bail!("invalid connection type")
            }
        }
    } else {
        // invalid conn type byte
        bail!("invalid conn type: {}", buf[0])
    }
    Ok(())
}

const CERT_SIZE_LIMIT: u32 = 10000;

fn handle_pair_request(mut stream: TcpStream, tls_info: &TlsInfo) -> Result<()> {
    let mut session = rustls::ServerSession::new(&Arc::new(tls_info.config.clone()));
    let mut tls_stream = rustls::Stream::new(&mut session, &mut stream);

    // start reading pair request header
    // read cert_size
    let mut buf = [0; 4];
    tls_stream.read_exact(&mut buf)?;
    let cert_size = u32::from_be_bytes(buf);
    if cert_size > CERT_SIZE_LIMIT {
        bail!("certificate size is too large: {} > {}(limit)", cert_size, CERT_SIZE_LIMIT);
    }

    // read certificate
    let mut buf = vec![0; cert_size as usize];
    tls_stream.read_exact(&mut buf)?;
    let server_cert = &tls_info.certs[0];
    let client_cert = buf.clone();
    buf.extend(server_cert.as_ref().to_vec());
    let digest = ring::digest::digest(&ring::digest::SHA256, buf.as_ref());
    // TODO: print digest
    print!(concat![
        "It is very important that you verify that the following hash matches what is viewed on your phone\n",
        "It is a sha256 hash like so: sha256(client_cert + server_cert)\n\n",
        "If the hash don't match there could be a man-in-the-middle attack\n",
        "Or something else is not right, you should abort if they don't match!\n"
    ]);

    // TODO: pretty-print sha256 digest
    println!("{:x?}", digest.as_ref());


    // TODO: asynchronously handle pairing response
    println!("Waiting for client pairing response...");
    let mut buf = [0; 1];
    tls_stream.read_exact(&mut buf)?;
    if let Some(resp) = PairingResponse::from(buf[0]) {
        if let PairingResponse::Deny = resp {
            bail!("client denied pairing")
        }
    } else {
        bail!("invalid client pairing response")
    }

    let mut q = String::new();
    print!("Enter \"yes\" to accept pairing: ");
    std::io::stdin().read_line(&mut q)?;
    if q != "yes" {
        tls_stream.write_all(&mut [PairingResponse::Deny.into()])?;
        bail!("user denied pairing")
    }

    tls_stream.write_all(&mut [PairingResponse::Accept.into()])?;

    // TODO: add authorized_certs

    Ok(())
}
