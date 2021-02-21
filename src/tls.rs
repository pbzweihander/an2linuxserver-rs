use anyhow::{Result, bail};
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use rustls::{ClientCertVerifier, DistinguishedNames, HandshakeSignatureValid, ClientCertVerified, TLSError};
use rustls::internal::msgs::handshake::DigitallySignedStruct;
use rustls::SignatureScheme as RScheme;
use x509_signature::SignatureScheme as XScheme;
use x509_signature::parse_certificate;

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

pub fn make_tls_server_config_no_client_auth(
    server_certs: Vec<rustls::Certificate>,
    privkey: rustls::PrivateKey,
) -> Result<TlsInfo> {
    let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    config.set_single_cert(server_certs.clone(), privkey)?;

    Ok(TlsInfo{
        certs: server_certs,
        config,
    })
}

pub fn make_tls_server_config_with_auth(
    server_certs: Vec<rustls::Certificate>,
    privkey: rustls::PrivateKey,
    client_certs: Vec<rustls::Certificate>,
) -> Result<TlsInfo> {
    let custom_cert_verifier = Arc::new(CustomClientCertVerifier::new(client_certs)?);
    let mut config = rustls::ServerConfig::new(custom_cert_verifier);
    config.set_single_cert(server_certs.clone(), privkey)?;

    Ok(TlsInfo{
        certs: server_certs,
        config,
    })
}

pub struct CustomClientCertVerifier {
    allowed_certs: Vec<rustls::Certificate>,
    subject_names: DistinguishedNames,
}

impl CustomClientCertVerifier {
    pub fn new(allowed_certs: Vec<rustls::Certificate>) -> Result<Self> {
        let mut subject_names = DistinguishedNames::new();
        for cert in &allowed_certs {
            let cert = parse_certificate(&cert.0);
            if cert.is_err() {
                bail!("error while parsing client cert")
            }
            let cert = cert.unwrap();
            // probably not need to check if self-issued?
            if cert.check_self_issued().is_err() {
                bail!("cert is not self-issued")
            }
            let subject = rustls::internal::msgs::base::PayloadU16::new(cert.subject().to_owned());
            subject_names.push(subject);
        }

        Ok(Self {
            allowed_certs,
            subject_names,
        })
    }
}

// because we are using custom self-issued client certificates,
// we have to verify the client certificate validity.
// but webpki does not permit arbitrary der-formatted certificate parsing,
// so we have to manually check the certificate and signature.
// warning: this is probably not safe method to verify!
impl ClientCertVerifier for CustomClientCertVerifier {
    // provides parsed subject names of allowed_certs
    fn client_auth_root_subjects(&self, _sni: Option<&webpki::DNSName>) -> Option<DistinguishedNames> {
        Some(self.subject_names.clone())
    }

    // check if the certificate is _totally_ same with previously paired certificate.
    fn verify_client_cert(
        &self,
        presented_certs: &[rustls::Certificate],
        _sni: Option<&webpki::DNSName>,
    ) -> Result<ClientCertVerified, TLSError> {
        for presented_cert in presented_certs {
            for allowed_cert in &self.allowed_certs {
                if allowed_cert.0 == presented_cert.0 {
                    return Ok(ClientCertVerified::assertion())
                }
            }
        }
        Err(TLSError::General(String::from("cannot find appropriate client cert")))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TLSError> {
        let cert = parse_certificate(&cert.0);
        if cert.is_err() {
            return Err(TLSError::General(String::from("cannot parse certificate")));
        }
        let cert = cert.unwrap();
        let scheme = match dss.scheme {
            RScheme::RSA_PKCS1_SHA256 => Some(XScheme::RSA_PKCS1_SHA256),
            RScheme::RSA_PKCS1_SHA384 => Some(XScheme::RSA_PKCS1_SHA384),
            RScheme::RSA_PKCS1_SHA512 => Some(XScheme::RSA_PKCS1_SHA512),
            RScheme::RSA_PSS_SHA256 => Some(XScheme::RSA_PSS_SHA256),
            RScheme::RSA_PSS_SHA384 => Some(XScheme::RSA_PSS_SHA384),
            RScheme::RSA_PSS_SHA512 => Some(XScheme::RSA_PSS_SHA512),
            RScheme::ECDSA_NISTP256_SHA256 => Some(XScheme::ECDSA_NISTP256_SHA256),
            RScheme::ECDSA_NISTP384_SHA384 => Some(XScheme::ECDSA_NISTP384_SHA384),
            RScheme::ED25519 => Some(XScheme::ED25519),
            RScheme::ED448 => Some(XScheme::ED448),
            _  => None,
        };
        if scheme.is_none() {
            return Err(TLSError::General(String::from("cannot figure out signature scheme")));
        }
        println!("{:?}", scheme);
        // maybe we should use `check_tls12_signature`, but tlsv1.2 does not permit RSA_PSS.
        // nevertheless, an2linux is using RSA_PSS_SHA256 algorithm. so we have to
        // set restriction to None.
        let res = cert.subject_public_key_info()
            .check_signature(scheme.unwrap(), message, &dss.sig.0, x509_signature::Restrictions::None);
        if res.is_err() {
            println!("{:?}", res);
            return Err(TLSError::General(String::from("failed to verify signature")));
        }
        Ok(HandshakeSignatureValid::assertion())
    }
}
