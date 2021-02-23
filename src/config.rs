use anyhow::{format_err, Error, Result, bail};
use configparser::ini::Ini;
use regex::Regex;
use std::fs;
use std::io::*;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

const DEFAULT_CONFIG_FILE_CONTENT: &str = include_str!("default_config.ini");

#[derive(Debug, Clone)]
pub struct Config {
    pub tcp: TcpServerConfig,
    pub bluetooth: BluetoothConfig,
    pub notification: NotificationConfig,
}

impl Config {
    pub fn create_default_config_to_path(path: &Path) -> Result<()> {
        fs::write(path, DEFAULT_CONFIG_FILE_CONTENT)?;
        Ok(())
    }

    pub fn from_ini(ini: &Ini) -> Result<Self> {
        let tcp = TcpServerConfig::from_ini(ini)?;
        let bluetooth = BluetoothConfig::from_ini(ini)?;
        let notification = NotificationConfig::from_ini(ini)?;
        Ok(Self {
            tcp,
            bluetooth,
            notification,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TcpServerConfig {
    pub enabled: bool,
    pub port: u64,
}

// reimplementation of Ini::getboolcoerce, because of "on"/"off" string handling, which is valid
// for boolean coercion in Python configparser.
fn get_bool_coerce(ini: &Ini, section: &str, key: &str) -> Result<Option<bool>> {
    let bool_str = ini.get(section, key);
    if bool_str.is_none() {
        return Ok(None);
    }
    let bool_str = &bool_str.unwrap().to_lowercase()[..];
    if ["true", "yes", "t", "y", "1", "on"].contains(&bool_str) {
        Ok(Some(true))
    } else if ["false", "no", "f", "n", "0", "off"].contains(&bool_str) {
        Ok(Some(false))
    } else {
        bail!("Unable to parse value into bool at {}:{}", section, key);
    }
}

impl TcpServerConfig {
    fn from_ini(ini: &Ini) -> Result<Self> {
        let enabled = get_bool_coerce(ini, "tcp", "tcp_server")?.unwrap_or(true);
        let port = ini
            .getuint("tcp", "tcp_port")
            .map_err(Error::msg)?
            .unwrap_or(46352);
        Ok(Self { enabled, port })
    }
}

#[derive(Debug, Clone)]
pub struct BluetoothConfig {
    pub enabled: bool,
    pub support_kitkat: bool,
}

impl BluetoothConfig {
    fn from_ini(ini: &Ini) -> Result<Self> {
        let enabled = get_bool_coerce(ini, "bluetooth", "bluetooth_server")?.unwrap_or(false);
        let support_kitkat = get_bool_coerce(ini, "bluetooth", "bluetooth_support_kitkat")?.unwrap_or(false);
        Ok(Self {
            enabled,
            support_kitkat,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NotificationConfig {
    pub timeout: u64,
    pub list_size_duplicates: u64,
    pub ignore_duplicates_list_for_titles: Vec<String>,
    pub keywords_to_ignore: Vec<String>,
    pub regexes_to_ignore_in_title: Vec<Regex>,
    pub regexes_to_ignore_in_content: Vec<Regex>,
}

impl NotificationConfig {
    fn from_ini(ini: &Ini) -> Result<Self> {
        let timeout = ini
            .getuint("notification", "notification_timeout")
            .map_err(Error::msg)?
            .unwrap_or(5);
        let list_size_duplicates = ini
            .getuint("notification", "list_size_duplicates")
            .map_err(Error::msg)?
            .unwrap_or(0);
        let ignore_duplicates_list_for_titles: Vec<String> = ini
            .get("notification", "ignore_duplicates_list_for_titles")
            .map(|list| {
                list.split(',')
                    .map(|item| item.trim().to_string())
                    .collect()
            })
            .unwrap_or_else(Vec::new);
        let keywords_to_ignore: Vec<String> = ini
            .get("notification", "keywords_to_ignore")
            .map(|list| {
                list.split(',')
                    .map(|item| item.trim().to_string())
                    .collect()
            })
            .unwrap_or_else(Vec::new);
        let regexes_to_ignore_in_title: Vec<Regex> = ini
            .get("notification", "regexes_to_ignore_in_title")
            .map(|list| {
                list.split(',')
                    .filter_map(|item| Regex::new(item.trim()).ok())
                    .collect()
            })
            .unwrap_or_else(Vec::new);
        let regexes_to_ignore_in_content: Vec<Regex> = ini
            .get("notification", "regexes_to_ignore_in_content")
            .map(|list| {
                list.split(',')
                    .filter_map(|item| Regex::new(item.trim()).ok())
                    .collect()
            })
            .unwrap_or_else(Vec::new);
        Ok(Self {
            timeout,
            list_size_duplicates,
            ignore_duplicates_list_for_titles,
            keywords_to_ignore,
            regexes_to_ignore_in_title,
            regexes_to_ignore_in_content,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConfigManager {
    config_dir: PathBuf,
    config: Option<Config>,
}

impl ConfigManager {
    pub fn try_default(load_config: bool) -> Result<Self> {
        let config_home_dir =
            dirs::config_dir().ok_or_else(|| format_err!("Unsupported platform"))?;
        let config_dir = config_home_dir.join("an2linux_rs");
        let mut config_manager = Self { config_dir, config: None };
        config_manager.ensure_config_dir_exists()?;
        config_manager.ensure_certificate_and_rsa_private_key_exists()?;

        if load_config {
            let config_file_path = config_manager.config_file_path();
            if !config_file_path.is_file() {
                Config::create_default_config_to_path(&config_file_path)?;
            }
            let config_content = fs::read_to_string(&config_file_path)?;
            let mut ini = Ini::new_cs();
            ini.read(config_content).map_err(Error::msg)?;
            config_manager.config = Some(Config::from_ini(&ini)?);
        }
        Ok(config_manager)
    }

    pub fn config_file_path(&self) -> PathBuf {
        self.config_dir.join("config")
    }

    pub fn certificate_path(&self) -> PathBuf {
        self.config_dir.join("certificate.pem")
    }

    pub fn rsa_private_key_path(&self) -> PathBuf {
        self.config_dir.join("rsakey.pem")
    }

    pub fn authorized_certs_path(&self) -> PathBuf {
        self.config_dir.join("authorized_certs")
    }

    // TODO
    #[allow(dead_code)]
    pub fn dhparam_path(&self) -> PathBuf {
        self.config_dir.join("dhparam.pem")
    }

    pub fn ensure_config_dir_exists(&self) -> Result<()> {
        if !self.config_dir.is_dir() {
            fs::create_dir_all(&self.config_dir)?;
        }
        Ok(())
    }

    pub fn ensure_certificate_and_rsa_private_key_exists(&self) -> Result<()> {
        let certificate_path = self.certificate_path();
        let rsa_private_key_path = self.rsa_private_key_path();
        if !certificate_path.is_file() {
            return Err(format_err!(
                "No certificate file found in {}",
                certificate_path.to_string_lossy()
            ));
        }
        if !rsa_private_key_path.is_file() {
            return Err(format_err!(
                "No RSA private key file found in {}",
                certificate_path.to_string_lossy()
            ));
        }
        Ok(())
    }

    pub fn get_config(&self) -> Option<&Config> {
        if let Some(config) = &self.config {
            Some(&config)
        } else {
            None
        }
    }

    pub fn parse_authorized_cert(&self) -> Result<AuthorizedCerts> {
        let authorized_certs_path = self.authorized_certs_path();
        if !authorized_certs_path.is_file() {
            fs::File::create(authorized_certs_path)?;
            return Ok(AuthorizedCerts::new());
        }
        let mut f = fs::File::open(authorized_certs_path)?;
        let mut buf = String::new();
        f.read_to_string(&mut buf)?;
        AuthorizedCerts::from_str(&buf)
    }

    pub fn add_authorized_cert(&self, cert_der: &dyn AsRef<[u8]>) -> Result<()> {
        let cert_der = cert_der.as_ref();
        let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
        let digest_hex_formatted =
            digest.as_ref().iter()
            .map(|x| format!("{:02X}", x))
            .collect::<Vec<String>>()
            .join(":");
        let authorized_certs = self.parse_authorized_cert()?;
        if authorized_certs.certs.get(&digest_hex_formatted).is_some() {
            bail!("client certificate already exists")
        }

        let digest_hex_formatted = format!("SHA256:{}", digest_hex_formatted);
        let base64_str = base64::encode(cert_der);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(self.authorized_certs_path())?;
        let s = format!("{} {}\n", digest_hex_formatted, base64_str);
        f.write_all(&s.into_bytes())?;
        Ok(())
    }
}

// data structure that holds `authorized_certs` file content
pub struct AuthorizedCerts {
    // Fingerprint -> Certificate map
    certs: HashMap<String, Vec<u8>>
}

impl AuthorizedCerts {
    fn new() -> Self {
        Self {
            certs: HashMap::new(),
        }
    }

    fn from_str(content: &dyn AsRef<str>) -> Result<Self> {
        let content = content.as_ref();
        let mut hashmap: HashMap<String, Vec<u8>> = HashMap::new();
        for line in content.lines() {
            let s = line.split_whitespace().collect::<Vec<&str>>();
            if s.len() != 2 {
                continue;
            }
            let fingerprint = {
                let splitted = s[0].splitn(2, ':').collect::<Vec<&str>>();
                if splitted.len() < 2 {
                    ""
                } else {
                    splitted[0]
                }
            };
            if fingerprint.is_empty() {
                continue;
            }
            let cert_der = base64::decode(s[1]).unwrap_or_default();
            if cert_der.is_empty() {
                continue;
            }
            hashmap.insert(fingerprint.to_owned(), cert_der);
        }
        Ok(Self {
            certs: hashmap,
        })
    }

    pub fn get_all_der_certs(&self) -> Vec<rustls::Certificate> {
        self.certs.values().map(|cert| rustls::Certificate(cert.clone())).collect()
    }
}
