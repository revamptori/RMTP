//! Security helpers: rate limiting, constant-time comparison, input validation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Constant-time comparison of two byte slices to avoid timing leaks.
/// Never returns early on first mismatch.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    subtle::ConstantTimeEq::ct_eq(a, b).into()
}

/// Sliding-window rate limiter per connection key.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_commands: usize,
    window: Duration,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    /// key -> (window_start, count)
    counts: HashMap<String, (Instant, usize)>,
}

impl RateLimiter {
    pub fn new(max_commands: usize, window_secs: u64) -> Self {
        Self {
            max_commands,
            window: Duration::from_secs(window_secs),
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Returns `true` if the command is allowed, `false` if the peer is rate-limited.
    pub fn check(&self, key: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        // Evict expired windows.
        inner.counts.retain(|_, (start, _)| now.duration_since(*start) < self.window);

        let entry = inner.counts.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max_commands
    }
}

/// Validates an SMTP command line for injection/control characters.
pub fn validate_command_line(line: &str) -> bool {
    // Reject CR/LF inside a command (SMTP injection) and NUL bytes.
    !line.is_empty()
        && !line.contains('\n')
        && !line.contains('\r')
        && !line.contains('\0')
        && line.is_ascii()
}

/// Validates a dot-stuffed line per RFC 5321 §4.5.2 (returns the destuffed line).
/// Returns None if the line is malformed (e.g. contains NUL).
pub fn destuff_line(line: &str) -> Option<String> {
    if line.contains('\0') {
        return None;
    }
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'.' && i + 1 < bytes.len() && bytes[i + 1] == b'.' {
            // Dot-stuffing: ".." -> "."
            out.push('.');
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Some(out)
}

/// Validates an SMTP address token for basic syntax (no spaces, no angle-bracket abuse).
pub fn validate_address_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && !token.contains(' ')
        && !token.contains('\t')
        && !token.contains('<')
        && !token.contains('>')
        && !token.contains(',')
        && !token.contains(';')
        && !token.contains(':')
        && token.is_ascii()
}

#[derive(Debug)]
pub struct ConnectionMetrics {
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub commands_seen: AtomicU64,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            commands_seen: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_same_and_diff() {
        assert!(constant_time_eq(b"password", b"password"));
        assert!(!constant_time_eq(b"password", b"passworD"));
        assert!(!constant_time_eq(b"short", b"muchlongerpassword"));
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let rl = RateLimiter::new(2, 1);
        let k = "peer";
        assert!(rl.check(k));
        assert!(rl.check(k));
        assert!(!rl.check(k)); // 3rd exceeds limit of 2
    }

    #[test]
    fn validate_command_line_rejects_injection() {
        assert!(validate_command_line("EHLO example.com"));
        assert!(!validate_command_line("EHLO example.com\r\nQUIT"));
        assert!(!validate_command_line("EHLO example.com\nQUIT"));
        assert!(!validate_command_line(""));
    }

    #[test]
    fn destuff_roundtrip() {
        assert_eq!(destuff_line("Hello..world").unwrap(), "Hello.world");
        assert_eq!(destuff_line("..leading").unwrap(), ".leading");
        assert_eq!(destuff_line("normal").unwrap(), "normal");
        assert!(destuff_line("with\0nul").is_none());
    }

    #[test]
    fn validate_address_token() {
        assert!(validate_address_token("user@example.com"));
        assert!(!validate_address_token("user@x\r\nQUIT"));
        assert!(!validate_address_token("user@x<"));
    }
}
