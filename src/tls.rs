//! TLS support using rustls.
//!
//! Provides STARTTLS upgrading of an established connection and implicit TLS
//! for relay connections.

use std::fs;
use std::io::{self, Read};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig as RustlsServerConfig;

/// Build a rustls server config from certificate and private key PEM files.
pub fn server_config(cert_path: &std::path::Path, key_path: &std::path::Path) -> io::Result<Arc<RustlsServerConfig>> {
    let certs = load_certs(cert_path)?;
    let keys = load_private_keys(key_path)?;
    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no certificates found"));
    }
    if keys.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no private keys found"));
    }
    let mut config = RustlsServerConfig::builder()
        .with_cipher_suites(rustls::cipher_suite::TLS13_CIPHER_SUITES.to_vec())
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    config.max_fragment_size = Some(16384);
    Ok(Arc::new(config))
}

/// Build a `TlsAcceptor` from a server config.
pub fn acceptor(config: Arc<RustlsServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

fn load_certs(path: &std::path::Path) -> io::Result<Vec<rustls::Certificate>> {
    let mut file = fs::File::open(path)?;
    rustls_pemfile::certs(&mut file).collect()
}

fn load_private_keys(path: &std::path::Path) -> io::Result<Vec<rustls::PrivateKey>> {
    let mut file = fs::File::open(path)?;
    rustls_pemfile::pkcs8_private_keys(&mut file).collect()
}

/// Upgrade a plain TCP stream to TLS (server-side STARTTLS).
pub async fn accept_tls<IO>(
    io: IO,
    acceptor: &TlsAcceptor,
) -> io::Result<tokio_rustls::TlsServerStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    acceptor.accept(io).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// Client-side TLS config for connecting to an upstream relay.
pub fn client_config() -> io::Result<Arc<rustls::ClientConfig>> {
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots()
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_builds() {
        assert!(client_config().is_ok());
    }
}
