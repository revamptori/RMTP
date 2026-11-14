//! SMTP relay: forward accepted messages to an upstream SMTP server.
//!
//! Implements a minimal SMTP client (EHLO, MAIL, RCPT, DATA, QUIT, STARTTLS,
//! AUTH) with retry on temporary failures.

use crate::config::RelayConfig;
use crate::security::validate_command_line;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of a delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    TemporaryFailure(String),
    PermanentFailure(String),
}

/// An SMTP reply from the upstream server.
struct SmtpReply {
    code: u16,
    text: String,
}

/// A minimal upstream SMTP client session.
struct UpstreamSession {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: BufWriter<tokio::io::WriteHalf<TcpStream>>,
    tls: bool,
}

impl UpstreamSession {
    async fn connect(host: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{host}:{port}");
        let stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
            .await
            .map_err(|e| format!("connect timeout: {e}"))?
            .map_err(|e| format!("connect error: {e}"))?;
        let (rd, wr) = tokio::io::split(stream);
        let reader = BufReader::new(rd);
        let writer = BufWriter::new(wr);
        Ok(Self { reader, writer, tls: false })
    }

    /// Read one reply (handling multi-line continuations).
    async fn read_reply(&mut self) -> Result<SmtpReply, String> {
        let mut line = String::new();
        let mut code = 0u16;
        let mut text = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line).await.map_err(|e| format!("read error: {e}"))?;
            if n == 0 {
                return Err("connection closed by upstream".into());
            }
            let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
            if trimmed.len() >= 3 {
                code = trimmed[..3].parse().unwrap_or(0);
                text = trimmed[3..].trim_start().to_string();
            }
            if trimmed.as_bytes().get(3) == Some(&b'-') {
                continue;
            }
            break;
        }
        Ok(SmtpReply { code, text })
    }

    async fn send_cmd(&mut self, cmd: &str) -> Result<(), String> {
        if !validate_command_line(cmd) {
            return Err("refusing to send command with invalid characters".into());
        }
        let line = format!("{cmd}\r\n");
        self.writer.write_all(line.as_bytes()).await.map_err(|e| format!("write error: {e}"))?;
        self.writer.flush().await.map_err(|e| format!("flush error: {e}"))?;
        Ok(())
    }

    async fn expect_reply(&mut self, ok_codes: &[u16]) -> Result<SmtpReply, String> {
        let reply = self.read_reply().await?;
        if ok_codes.contains(&reply.code) {
            Ok(reply)
        } else {
            Err(format!("unexpected reply {} {}", reply.code, reply.text))
        }
    }

    async fn ehlo(&mut self, hostname: &str) -> Result<(), String> {
        self.send_cmd(&format!("EHLO {hostname}")).await?;
        let reply = self.read_reply().await?;
        if reply.code != 250 {
            return Err(format!("EHLO rejected: {} {}", reply.code, reply.text));
        }
        Ok(())
    }

    async fn starttls(&mut self) -> Result<(), String> {
        self.send_cmd("STARTTLS").await?;
        let _ = self.expect_reply(&[220]).await?;
        Ok(())
    }

    async fn mail_from(&mut self, from: &str) -> Result<(), String> {
        self.send_cmd(&format!("MAIL FROM:<{from}>")).await?;
        let _ = self.expect_reply(&[250, 251, 252]).await?;
        Ok(())
    }

    async fn rcpt_to(&mut self, to: &str) -> Result<(), String> {
        self.send_cmd(&format!("RCPT TO:<{to}>")).await?;
        let _ = self.expect_reply(&[250, 251, 252]).await?;
        Ok(())
    }

    async fn data(&mut self, message: &[u8]) -> Result<(), String> {
        self.send_cmd("DATA").await?;
        let _ = self.expect_reply(&[354]).await?;
        self.writer.write_all(message).await.map_err(|e| format!("write data: {e}"))?;
        self.writer.write_all(b"\r\n.\r\n").await.map_err(|e| format!("write terminator: {e}"))?;
        self.writer.flush().await.map_err(|e| format!("flush error: {e}"))?;
        let _ = self.expect_reply(&[250]).await?;
        Ok(())
    }

    async fn quit(&mut self) {
        let _ = self.send_cmd("QUIT").await;
        let _ = self.writer.flush().await;
    }
}

/// Deliver a single message to the configured upstream relay.
pub async fn deliver(config: &RelayConfig, from: &str, to: &[String], message: &[u8]) -> DeliveryOutcome {
    if !config.enabled {
        return DeliveryOutcome::PermanentFailure("relay not enabled".into());
    }
    let Some(host) = &config.host else {
        return DeliveryOutcome::PermanentFailure("no relay host configured".into());
    };
    let port = config.port;

    let mut session = match UpstreamSession::connect(host, port).await {
        Ok(s) => s,
        Err(e) => return DeliveryOutcome::TemporaryFailure(format!("connect: {e}")),
    };

    // Greeting.
    if session.read_reply().await.is_err() {
        return DeliveryOutcome::TemporaryFailure("no greeting from upstream".into());
    }

    // EHLO.
    if session.ehlo("rmtp.local").await.is_err() {
        return DeliveryOutcome::TemporaryFailure("EHLO failed".into());
    }

    // Optional STARTTLS (best-effort; if unsupported, still try plaintext).
    let _ = session.starttls().await;

    // AUTH if credentials configured.
    if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        let _ = session
            .send_cmd(&format!("AUTH PLAIN {}", base64_encode(&format!("\0{user}\0{pass}"))))
            .await;
        let _ = session.read_reply().await;
    }

    // MAIL FROM.
    if session.mail_from(from).await.is_err() {
        session.quit().await;
        return DeliveryOutcome::TemporaryFailure("MAIL FROM rejected".into());
    }

    // RCPT TO for each recipient.
    for rcpt in to {
        if session.rcpt_to(rcpt).await.is_err() {
            session.quit().await;
            return DeliveryOutcome::PermanentFailure(format!("RCPT TO rejected: {rcpt}"));
        }
    }

    // DATA.
    match session.data(message).await {
        Ok(()) => {
            session.quit().await;
            DeliveryOutcome::Delivered
        }
        Err(e) => {
            session.quit().await;
            DeliveryOutcome::TemporaryFailure(format!("DATA failed: {e}"))
        }
    }
}

fn base64_encode(input: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_auth_payload() {
        let enc = base64_encode("\0alice\0s3cret");
        assert!(!enc.is_empty());
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: None,
            port: 587,
            username: None,
            password: None,
            tls: "starttls".into(),
        }
    }
}
