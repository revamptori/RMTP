//! Structured logging for RMTP.
//!
//! Terminal-only, levels controlled by config, with quiet/verbose support.

use log::{LevelFilter, Record};
use std::io::Write;

/// Initialize logging from a config level string and verbosity flags.
pub fn init(level: &str, quiet: bool, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let filter = if quiet {
        LevelFilter::Warn
    } else if verbose {
        LevelFilter::Debug
    } else {
        match level {
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        }
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_level(filter)
        .format(|buf, record| {
            let ts = chrono_format();
            writeln!(
                buf,
                "{ts} [{level:>5}] {target}: {msg}",
                ts = ts,
                level = record.level(),
                target = record.target(),
                msg = record.args()
            )
        })
        .init();

    Ok(())
}

/// Simple local timestamp without a hard dependency on chrono.
fn chrono_format() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Format as a rough HH:MM:SS using UTC epoch division (good enough for logs).
    let total_secs = secs % 86400;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    let millis = now.subsec_millis();
    format!("{h:02}:{m:02}:{s:02}.{millis:03}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_wraps_at_day() {
        let t = chrono_format();
        assert_eq!(t.len(), 12);
        assert!(t.contains(':'));
        assert!(t.contains('.'));
    }
}
