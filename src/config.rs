use anyhow::{format_err, Error, Result};
use configparser::ini::Ini;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

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

impl TcpServerConfig {
    fn from_ini(ini: &Ini) -> Result<Self> {
        let enabled = ini
            .getboolcoerce("tcp", "tcp_server")
            .map_err(Error::msg)?
            .unwrap_or(true);
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
        let enabled = ini
            .getboolcoerce("bluetooth", "bluetooth_server")
            .map_err(Error::msg)?
            .unwrap_or(false);
        let support_kitkat = ini
            .getboolcoerce("bluetooth", "bluetooth_support_kitkat")
            .map_err(Error::msg)?
            .unwrap_or(false);
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
}

impl ConfigManager {
    pub fn try_default() -> Result<Self> {
        let config_home_dir =
            dirs::config_dir().ok_or_else(|| format_err!("Unsupported platform"))?;
        let config_dir = config_home_dir.join("an2linux");
        Ok(Self { config_dir })
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
        if certificate_path.is_file() {
            return Err(format_err!(
                "No certificate file found in {}",
                certificate_path.to_string_lossy()
            ));
        }
        if rsa_private_key_path.is_file() {
            return Err(format_err!(
                "No RSA private key file found in {}",
                certificate_path.to_string_lossy()
            ));
        }
        Ok(())
    }

    pub fn get_or_create_config(&self) -> Result<Config> {
        let config_file_path = self.config_file_path();
        if !config_file_path.is_file() {
            Config::create_default_config_to_path(&config_file_path)?;
        }
        let config_content = fs::read_to_string(&config_file_path)?;
        let mut ini = Ini::new_cs();
        ini.read(config_content).map_err(Error::msg)?;
        Config::from_ini(&ini)
    }
}
