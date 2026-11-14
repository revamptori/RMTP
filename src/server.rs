//! Async TCP server accepting SMTP connections.
//!
//! Bounded concurrency, per-connection command timeouts, graceful shutdown.

use crate::config::Config;
use crate::security::{ConnectionMetrics, RateLimiter};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use log::{error, info, warn};

/// Number of concurrent connections currently active.
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub struct Server {
    config: Arc<Config>,
    listener: Option<TcpListener>,
    rate_limiter: Arc<RateLimiter>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            listener: None,
            rate_limiter: Arc::new(RateLimiter::new(100, 60)),
        }
    }

    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Bind and listen.
    pub async fn bind(&mut self) -> io::Result<SocketAddr> {
        let addr = self.config.addr();
        let listener = TcpListener::bind(addr).await?;
        info!(target: "rmtp::server", "listening on {}", listener.local_addr()?);
        self.listener = Some(listener);
        Ok(self.config.addr())
    }

    /// Accept loop. Runs until `shutdown` receiver is triggered.
    pub async fn run(&mut self, mut shutdown: tokio::sync::broadcast::Receiver<()>) {
        let listener = self.listener.take().expect("server not bound");
        let config = self.config.clone();
        let rate_limiter = self.rate_limiter.clone();
        let max_conn = config.server.max_connections;

        loop {
            tokio::select! {
                biased;
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            if ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= max_conn {
                                warn!(target: "rmtp::server", "connection limit reached, rejecting {peer}");
                                let _ = stream.shutdown().await;
                                continue;
                            }
                            ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                            let cfg = config.clone();
                            let rl = rate_limiter.clone();
                            tokio::spawn(async move {
                                let result = handle_connection(stream, cfg, rl).await;
                                ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                                if let Err(e) = result {
                                    warn!(target: "rmtp::server", "connection error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            error!(target: "rmtp::server", "accept error: {e}");
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!(target: "rmtp::server", "shutdown signal received, stopping acceptor");
                    break;
                }
            }
        }
        info!(target: "rmtp::server", "acceptor stopped");
    }
}

/// Handle a single SMTP connection with timeouts.
async fn handle_connection(
    stream: TcpStream,
    config: Arc<Config>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), std::io::Error> {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let key = format!("conn:{peer}");

    // Greeting banner (220).
    let banner = format!("220 {} ESMTP RMTP ready\r\n", config.server.hostname);

    let (read_half, write_half) = tokio::io::split(stream);
    let mut buf_reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Send greeting.
    let _ = writer.write_all(banner.as_bytes()).await;
    let _ = writer.flush().await;

    // Per-connection command timeout (300s per RFC 5321 recommendation).
    let timeout_secs: u64 = 300;

    loop {
        let mut line = String::new();
        let read_result = timeout(Duration::from_secs(timeout_secs), buf_reader.read_line(&mut line)).await;
        match read_result {
            Ok(Ok(0)) => break, // client disconnected cleanly
            Ok(Ok(_)) => {
                if !rate_limiter.check(&key) {
                    let _ = writer.write_all(b"421 Too many commands. Try again later.\r\n").await;
                    break;
                }
                let response = process_line(&line, &config);
                let _ = writer.write_all(response.as_bytes()).await;
                let _ = writer.flush().await;
                if response.starts_with("221 ") {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                let _ = writer.write_all(b"421 Idle timeout, closing transmission channel\r\n").await;
                break;
            }
        }
    }
    let _ = writer.flush().await;
    Ok(())
}

/// Process one client line and produce the SMTP response.
fn process_line(line: &str, config: &Config) -> String {
    let line = line.trim_end_matches(&['\r', '\n'][..]);
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("EHLO") {
        let domain = line[4..].trim();
        format!(
            "250-{domain} Hello\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n",
            config.server.max_message_size
        )
    } else if upper.starts_with("HELO") {
        format!("250 Hello {}\r\n", line[4..].trim())
    } else if upper.starts_with("MAIL FROM") {
        "250 OK\r\n".into()
    } else if upper.starts_with("RCPT TO") {
        "250 OK\r\n".into()
    } else if upper == "DATA" {
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n".into()
    } else if upper == "RSET" {
        "250 OK\r\n".into()
    } else if upper == "NOOP" {
        "250 OK\r\n".into()
    } else if upper == "QUIT" {
        "221 Service closing transmission channel\r\n".into()
    } else if upper.starts_with("AUTH") {
        "503 Authentication not configured\r\n".into()
    } else {
        "500 Syntax error, command unrecognized\r\n".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            server: crate::config::ServerConfig {
                hostname: "smtp.example.com".into(),
                bind: "0.0.0.0".into(),
                port: 587,
                max_connections: 10,
                max_message_size: 1024,
            },
            tls: Default::default(),
            auth: Default::default(),
            relay: Default::default(),
            queue: Default::default(),
            logging: Default::default(),
        }
    }

    #[test]
    fn process_line_ehlo() {
        let config = test_config();
        let resp = process_line("EHLO client.example.com", &config);
        assert!(resp.starts_with("250-smtp.example.com Hello"));
        assert!(resp.contains("250-STARTTLS"));
        assert!(resp.contains("250-AUTH PLAIN LOGIN"));
        assert!(resp.ends_with("250 HELP\r\n"));
    }

    #[test]
    fn process_line_quit() {
        let config = test_config();
        assert_eq!(process_line("QUIT", &config), "221 Service closing transmission channel\r\n");
    }
}
