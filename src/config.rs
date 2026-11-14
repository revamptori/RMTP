//! Configuration loading for RMTP.
//!
//! Reads a TOML configuration file, applies environment-variable overrides,
//! and validates security-sensitive settings (e.g. auth without TLS).

use serde::Deserialize;
use std::error::Error;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Top-level configuration.
#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub queue: QueueConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub hostname: String,
    pub bind: String,
    pub port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub required: bool,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct RelayConfig {
    #[serde(default)]
    pub enabled: bool,
    pub host: Option<String>,
    #[serde(default = "default_relay_port")]
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "default_relay_tls")]
    pub tls: String, // "starttls", "implicit", "none"
}

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct QueueConfig {
    #[serde(default = "default_queue_dir")]
    pub directory: PathBuf,
    #[serde(default = "default_retry_interval")]
    pub retry_interval: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_max_connections() -> usize { 500 }
fn default_max_message_size() -> usize { 26_214_400 }
fn default_relay_port() -> u16 { 587 }
fn default_relay_tls() -> String { "starttls".into() }
fn default_queue_dir() -> PathBuf { PathBuf::from("./data/queue") }
fn default_retry_interval() -> u64 { 60 }
fn default_max_retries() -> u32 { 10 }
fn default_log_level() -> String { "info".into() }

impl Config {
    /// Load configuration from a TOML file path.
    pub fn from_file(path: &str) -> Result<Config, ConfigError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(format!("reading config {path}: {e}")))?;
        let mut config: Config = toml::from_str(&contents)
            .map_err(ConfigError::Toml)?;

        // Apply environment-variable overrides for secrets (never hardcode secrets).
        if let Ok(pw) = std::env::var("RMTP_AUTH_PASSWORD") {
            config.auth.password = Some(pw);
        }
        if let Ok(user) = std::env::var("RMTP_AUTH_USERNAME") {
            config.auth.username = Some(user);
        }
        if let Ok(pw) = std::env::var("RMTP_RELAY_PASSWORD") {
            config.relay.password = Some(pw);
        }
        if let Ok(host) = std::env::var("RMTP_RELAY_HOST") {
            config.relay.host = Some(host);
        }
        if let Ok(port) = std::env::var("RMTP_RELAY_PORT").and_then(|s| s.parse::<u16>()) {
            config.relay.port = port;
        }
        if let Ok(bind) = std::env::var("RMTP_BIND") {
            config.server.bind = bind;
        }
        if let Ok(port) = std::env::var("RMTP_PORT").and_then(|s| s.parse::<u16>()) {
            config.server.port = port;
        }

        Ok(config)
    }

    /// Resolve the listen address.
    pub fn addr(&self) -> SocketAddr {
        let bind = self.server.bind.as_str();
        let port = self.server.port;
        format!("{bind}:{port}")
            .parse()
            .unwrap_or_else(|_| {
                eprintln!("warning: invalid bind {bind}:{port}, using 0.0.0.0:{port}");
                format!("0.0.0.0:{port}").parse().unwrap()
            })
    }

    /// Validate security-sensitive settings.
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Auth enabled without TLS is insecure unless explicitly overridden.
        if self.auth.enabled && !self.tls.enabled && !Self::allow_auth_without_tls() {
            return Err(ValidationError::AuthWithoutTls);
        }
        if self.auth.required && !self.tls.enabled {
            return Err(ValidationError::AuthRequiredWithoutTls);
        }
        // If TLS enabled, cert and key must be present.
        if self.tls.enabled {
            if self.tls.certificate.is_none() {
                return Err(ValidationError::TlsMissingCertificate);
            }
            if self.tls.private_key.is_none() {
                return Err(ValidationError::TlsMissingPrivateKey);
            }
        }
        // Relay with auth needs credentials and a host.
        if self.relay.enabled {
            if self.relay.host.is_none() {
                return Err(ValidationError::RelayMissingHost);
            }
        }
        self.validate_paths()
    }

    fn validate_paths(&self) -> Result<(), ValidationError> {
        let display = self.queue.directory.to_string_lossy();
        // Reject obvious traversal attempts.
        if display.starts_with("..") || display.contains("../") {
            return Err(ValidationError::QueuePathTraversal);
        }
        Ok(())
    }

    pub fn allow_auth_without_tls() -> bool {
        std::env::var("RMTP_INSECURE_ALLOW_AUTH_WITHOUT_TLS")
            .map(|v| v == "1")
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Toml(toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(s) => write!(f, "IO error: {s}"),
            ConfigError::Toml(e) => write!(f, "TOML parse error: {e}"),
        }
    }
}

impl Error for ConfigError {}

#[derive(Debug)]
pub enum ValidationError {
    AuthWithoutTls,
    AuthRequiredWithoutTls,
    TlsMissingCertificate,
    TlsMissingPrivateKey,
    RelayMissingHost,
    QueuePathTraversal,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::AuthWithoutTls => {
                write!(f, "SMTP AUTH is enabled but TLS is not configured. Refusing insecure \
                         configuration. Set RMTP_INSECURE_ALLOW_AUTH_WITHOUT_TLS=1 to override.")
            }
            ValidationError::AuthRequiredWithoutTls => {
                write!(f, "SMTP AUTH is required but TLS is not enabled")
            }
            ValidationError::TlsMissingCertificate => {
                write!(f, "TLS is enabled but no certificate file was configured")
            }
            ValidationError::TlsMissingPrivateKey => {
                write!(f, "TLS is enabled but no private key file was configured")
            }
            ValidationError::RelayMissingHost => {
                write!(f, "relay is enabled but no upstream host was configured")
            }
            ValidationError::QueuePathTraversal => {
                write!(f, "queue directory path may escape the working directory (traversal)")
            }
        }
    }
}

impl Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let toml_str = r#"
[server]
hostname = "smtp.example.com"
bind = "0.0.0.0"
port = 587
max_connections = 500
max_message_size = 26214400

[tls]
enabled = true
certificate = "./certs/cert.pem"
private_key = "./certs/key.pem"

[auth]
enabled = true
username = "user"
password = "change-me"

[relay]
host = "smtp.upstream.com"
port = 587
username = "upstream-user"
password = "upstream-password"
tls = "starttls"

[queue]
directory = "./data/queue"
retry_interval = 60
max_retries = 10

[logging]
level = "info"
"#;
        let config: Config = toml::from_str(toml_str).expect("valid config");
        assert_eq!(config.server.hostname, "smtp.example.com");
        assert_eq!(config.server.port, 587);
        assert!(config.tls.enabled);
        assert!(config.auth.enabled);
        assert_eq!(config.relay.tls, "starttls");
    }

    #[test]
    fn rejects_auth_without_tls() {
        let toml_str = r#"
[server]
hostname = "localhost"
bind = "127.0.0.1"
port = 2525
[auth]
enabled = true
username = "user"
password = "pass"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_queue_traversal() {
        let toml_str = r#"
[server]
hostname = "localhost"
bind = "127.0.0.1"
port = 2525
[queue]
directory = "../../etc"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(matches!(
            config.validate(),
            Err(ValidationError::QueuePathTraversal)
        ));
    }
}
