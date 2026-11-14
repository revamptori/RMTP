//! Terminal CLI built with clap.
//!
//! Commands:
//!   rustsmtp init          - generate a default config file
//!   rustsmtp start         - start the SMTP relay
//!   rustsmtp stop          - stop a running instance
//!   rustsmtp status        - show whether the relay is running
//!   rustsmtp test          - run a self-test SMTP session
//!   rustsmtp queue list    - list queued messages
//!   rustsmtp queue retry   - retry queued deliveries now
//!   rustsmtp queue flush   - drop all queued messages
//!   rustsmtp config validate - validate the configuration file

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "rustsmtp", about = "RMTP - lightweight SMTP server/relay", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Path to the TOML configuration file.
    #[arg(long, global = true, default_value = "rmtp.toml")]
    pub config: PathBuf,

    /// Quiet mode: only warnings and errors.
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    /// Verbose mode: debug logging.
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a default configuration file.
    Init {
        /// Path to write the default config.
        #[arg(default_value = "rmtp.toml")]
        path: PathBuf,
    },
    /// Start the SMTP relay.
    Start {
        /// Run in the foreground (do not daemonize).
        #[arg(long)]
        foreground: bool,
    },
    /// Stop a running relay instance (by PID file).
    Stop {
        /// Path to the PID file.
        #[arg(default_value = "rmtp.pid")]
        pid_file: PathBuf,
    },
    /// Print the running status.
    Status {
        /// Path to the PID file.
        #[arg(default_value = "rmtp.pid")]
        pid_file: PathBuf,
    },
    /// Run a self-test SMTP session against a local listener.
    Test {
        /// Port of the test listener.
        #[arg(default_value = "2525")]
        port: u16,
    },
    /// Queue subcommands.
    #[command(subcommand)]
    Queue(QueueSub),
    /// Validate the configuration file.
    ConfigValidate {
        /// Path to the config file.
        #[arg(default_value = "rmtp.toml")]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum QueueSub {
    /// List queued messages.
    List,
    /// Retry all queued deliveries now.
    Retry,
    /// Drop all queued messages.
    Flush,
}

impl Cli {
    pub fn log_level(&self) -> &str {
        // level comes from config; CLI flags override quiet/verbose only.
        "info"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parse_start() {
        let cli = Cli::parse_from(["rustsmtp", "start", "--config", "cfg.toml", "--verbose"]);
        assert!(matches!(cli.command, Commands::Start { .. }));
        assert_eq!(cli.config, PathBuf::from("cfg.toml"));
        assert!(cli.verbose);
        assert!(!cli.quiet);
    }

    #[test]
    fn cli_parse_queue_list() {
        let cli = Cli::parse_from(["rustsmtp", "queue", "list"]);
        assert!(matches!(cli.command, Commands::Queue(QueueSub::List)));
    }

    #[test]
    fn cli_parse_config_validate() {
        let cli = Cli::parse_from(["rustsmtp", "config", "validate", "--path", "/etc/rmtp.toml"]);
        match &cli.command {
            Commands::ConfigValidate { path } => assert_eq!(path, PathBuf::from("/etc/rmtp.toml")),
            other => panic!("unexpected {other:?}"),
        }
    }
}
