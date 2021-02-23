use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::time::Duration;
use std::sync::Arc;

use anyhow::{Result, bail};
use rustls;
use ring;
use notify_rust::{Notification, Image};
use image;

use super::protocol::{ConnType, PairingResponse, NotificationFlag};
use super::config::ConfigManager;
use super::tls::TlsInfo;

pub fn pairing_tcp_handler(config_manager: &ConfigManager, tls_info: TlsInfo) -> Result<()> {
    let port = config_manager.get_config().unwrap().tcp.port;
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], port as u16));
    let listener = TcpListener::bind(bind_addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_pairing_connection(stream, config_manager, &tls_info)?;
                println!("successfully paired");
                return Ok(());
            }
            Err(_) => {
                // TODO: log to stderr and continue
            }
        }
    }
    Ok(())
}

fn handle_pairing_connection(mut stream: TcpStream, config_manager: &ConfigManager, tls_info: &TlsInfo) -> Result<()> {
    let mut buf = [0; 1];
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.read_exact(&mut buf)?;

    if let Some(conn_type) = ConnType::from(buf[0]) {
        match conn_type {
            ConnType::PairRequest => {
                handle_pair_request(stream, config_manager, tls_info)?;
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

fn handle_pair_request(mut stream: TcpStream, config_manager: &ConfigManager, tls_info: &TlsInfo) -> Result<()> {
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
    println!("{:02X?}", digest.as_ref());

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
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut q)?;
    let q = q.trim();
    if q != "yes" {
        tls_stream.write_all(&mut [PairingResponse::Deny.into()])?;
        bail!("user denied pairing")
    }

    tls_stream.write_all(&mut [PairingResponse::Accept.into()])?;

    // add to authorized_certs
    config_manager.add_authorized_cert(&client_cert)?;

    Ok(())
}

pub fn notification_tcp_handler(config_manager: &ConfigManager, tls_info: TlsInfo) -> Result<()> {
    let port = config_manager.get_config().unwrap().tcp.port;
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], port as u16));
    let listener = TcpListener::bind(bind_addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_notification_connection(stream, &tls_info) {
                    // TODO: log to stderr
                    println!("error on notification handler: {:?}", e);
                }
            }
            Err(_) => {
                // TODO: log to stderr and continue
            }
        }
    }
    Ok(())
}

fn handle_notification_connection(mut stream: TcpStream, tls_info: &TlsInfo) -> Result<()> {
    let mut buf = [0; 1];
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.read_exact(&mut buf)?;

    if let Some(conn_type) = ConnType::from(buf[0]) {
        match conn_type {
            ConnType::NotifConn => {
                handle_notification_request(stream, tls_info)?;
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

const PAYLOAD_LIMIT: u32 = 10000;

fn handle_notification_request(mut stream: TcpStream, tls_info: &TlsInfo) -> Result<()> {
    let mut session = rustls::ServerSession::new(&Arc::new(tls_info.config.clone()));
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut tls_stream = rustls::Stream::new(&mut session, &mut stream);

    let mut buf = [0; 1];
    tls_stream.read_exact(&mut buf)?;
    let flag = NotificationFlag::from(u8::from_be_bytes(buf));

    let (title, message) = if flag.include_title || flag.include_message {
        let mut buf = [0; 4];
        tls_stream.read_exact(&mut buf)?;
        let size = u32::from_be_bytes(buf);
        if size > PAYLOAD_LIMIT {
            bail!("payload size is too large: {} > {}(limit)", size, PAYLOAD_LIMIT);
        }

        let title: String;
        let message: String;

        let mut buf = vec![0; size as usize];
        tls_stream.read_exact(&mut buf)?;
        let payload = String::from_utf8(buf)?;
        let splitted = payload.split("|||").collect::<Vec<&str>>();
        if flag.include_title {
            title = splitted[0].to_owned();
        } else {
            title = String::new();
        }
        if flag.include_message {
            if splitted.len() < 2 {
                bail!("flag says paylod includes message but actually not")
            }
            message = splitted[1].to_owned();
        } else {
            message = String::new();
        }
        (title, message)
    } else {
        (String::new(), String::new())
    };

    let icon_bytes = if flag.include_icon {
        let mut buf = [0; 4];
        tls_stream.read_exact(&mut buf)?;
        let size = u32::from_be_bytes(buf);
        if size > PAYLOAD_LIMIT {
            bail!("payload size is too large: {} > {}(limit)", size, PAYLOAD_LIMIT);
        }
        let mut buf = vec![0; size as usize];
        tls_stream.read_exact(&mut buf)?;
        buf
    } else {
        vec![]
    };

    // TODO: filter message
    let image = image::load_from_memory(&icon_bytes)?.into_rgba8();
    Notification::new()
        .summary(&title)
        .body(&message)
        .image_data(Image::from_rgba(image.width() as i32, image.height() as i32, image.into_raw())?)
        .show()?;

    Ok(())
}
