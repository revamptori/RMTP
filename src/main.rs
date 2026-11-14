//! RMTP binary entry point.
//!
//! Terminal-only SMTP relay. No GUI, no web interface, no dashboard.

use clap::Parser;
use rmtp::cli::{Cli, Commands, QueueSub};
use rmtp::config::Config;
use rmtp::logging;
use rmtp::queue::Queue;
use rmtp::server::Server;
use rmtp::Config as RmtpConfig;
use std::path::PathBuf;
use std::process;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("fatal: {e}");
        process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init { path } => cmd_init(path),
        Commands::Start { foreground } => {
            cmd_start(&cli.config, *foreground, cli.quiet, cli.verbose).await?
        }
        Commands::Stop { pid_file } => cmd_stop(pid_file),
        Commands::Status { pid_file } => cmd_status(pid_file),
        Commands::Test { port } => cmd_test(*port).await,
        Commands::Queue(sub) => cmd_queue(sub, &cli.config).await?,
        Commands::ConfigValidate { path } => cmd_config_validate(path),
    }
    Ok(())
}

/// Generate a default configuration file.
fn cmd_init(path: &PathBuf) {
    let default = include_str!("../rmtp.toml.example");
    if path.exists() {
        eprintln!("error: config file already exists at {}", path.display());
        process::exit(1);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    match std::fs::write(path, default) {
        Ok(()) => println!("wrote default config to {}", path.display()),
        Err(e) => {
            eprintln!("error: could not write config: {e}");
            process::exit(1);
        }
    }
}

/// Start the SMTP relay.
async fn cmd_start(
    config_path: &PathBuf,
    foreground: bool,
    quiet: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_file(config_path.to_str().unwrap_or("rmtp.toml"))?;
    config.validate()?;
    logging::init(&config.logging.level, quiet, verbose)?;

    tracing::info!(target: "rmtp", "starting RMTP SMTP relay");

    // Write PID file.
    let pid = std::process::id();
    if let Err(e) = std::fs::write("rmtp.pid", pid.to_string()) {
        tracing::warn!(target: "rmtp", "could not write pid file: {e}");
    }

    if !foreground {
        // Daemonize is not supported in this terminal-only build; run in foreground.
        tracing::warn!(target: "rmtp", "--foreground is the only supported mode in this build");
    }

    let mut server = Server::new(config);
    server.bind().await?;

    // Shutdown channel for SIGTERM/SIGINT.
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let shutdown_tx2 = shutdown_tx.clone();

    // Ctrl-C handler.
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!(target: "rmtp", "received Ctrl-C, initiating graceful shutdown");
                let _ = shutdown_tx2.send(());
            }
            Err(e) => tracing::error!(target: "rmtp", "failed to listen for Ctrl-C: {e}"),
        }
    });

    // SIGTERM handler (Unix).
    #[cfg(unix)]
    {
        let shutdown_tx3 = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut stream = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(target: "rmtp", "failed to listen for SIGTERM: {e}");
                    return;
                }
            };
            stream.recv().await;
            tracing::info!(target: "rmtp", "received SIGTERM, initiating graceful shutdown");
            let _ = shutdown_tx3.send(());
        });
    }

    server.run(shutdown_rx).await;

    // Remove PID file on clean shutdown.
    let _ = std::fs::remove_file("rmtp.pid");
    tracing::info!(target: "rmtp", "RMTP stopped");
    Ok(())
}

/// Stop a running instance (send SIGTERM to the PID in the pid file).
fn cmd_stop(pid_file: &PathBuf) {
    let contents = match std::fs::read_to_string(pid_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot read pid file {}: {e}", pid_file.display());
            process::exit(1);
        }
    };
    let pid: i32 = match contents.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("error: invalid pid in {}", pid_file.display());
            process::exit(1);
        }
    };
    #[cfg(unix)]
    {
        let status = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
        match status {
            Ok(s) if s.success() => println!("sent SIGTERM to pid {pid}"),
            _ => {
                eprintln!("error: failed to signal pid {pid}");
                process::exit(1);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        eprintln!("error: stop is only supported on Unix");
        process::exit(1);
    }
}

/// Print running status.
fn cmd_status(pid_file: &PathBuf) {
    match std::fs::read_to_string(pid_file) {
        Ok(contents) => {
            let pid: i32 = contents.trim().parse().unwrap_or(0);
            if pid > 0 && is_process_alive(pid) {
                println!("rmtp is running (pid {pid})");
            } else {
                println!("rmtp is not running (stale pid file)");
            }
        }
        Err(_) => println!("rmtp is not running (no pid file)"),
    }
}

#[cfg(unix)]
fn is_process_alive(pid: i32) -> bool {
    // Send signal 0 to check whether the process exists.
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
#[cfg(not(unix))]
fn is_process_alive(_pid: i32) -> bool {
    false
}

/// Run a self-test SMTP session.
async fn cmd_test(port: u16) {
    println!("running SMTP self-test against port {port}...");
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{port}")).await else {
        eprintln!("error: could not connect to 127.0.0.1:{port}. Is rmtp running?");
        process::exit(1);
    };
    let (mut rd, mut wr) = stream.split();
    let mut reader = BufReader::new(rd);

    let mut expect = |reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
                      wr: &mut tokio::io::WriteHalf<TcpStream>,
                      want: u16,
                      label: &str|
     -> Result<(), String> {
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() {
            return Err(format!("{label}: no reply"));
        }
        let code: u16 = line[..3].parse().unwrap_or(0);
        if code != want {
            return Err(format!("{label}: expected {want}, got {code}: {line}"));
        }
        let _ = wr;
        Ok(())
    };

    // Greeting 220.
    let _ = expect(&mut reader, &mut wr, 220, "greeting");
    // EHLO.
    let _ = wr.write_all(b"EHLO test.local\r\n").await;
    let _ = wr.flush().await;
    let _ = expect(&mut reader, &mut wr, 250, "EHLO");
    // MAIL.
    let _ = wr.write_all(b"MAIL FROM:<test@rmtp.local>\r\n").await;
    let _ = wr.flush().await;
    let _ = expect(&mut reader, &mut wr, 250, "MAIL FROM");
    // RCPT.
    let _ = wr.write_all(b"RCPT TO:<rcpt@rmtp.local>\r\n").await;
    let _ = wr.flush().await;
    let _ = expect(&mut reader, &mut wr, 250, "RCPT TO");
    // DATA.
    let _ = wr.write_all(b"DATA\r\n").await;
    let _ = wr.flush().await;
    let _ = expect(&mut reader, &mut wr, 354, "DATA");
    let _ = wr.write_all(b"Subject: test\r\n\r\nhello\r\n.\r\n").await;
    let _ = wr.flush().await;
    let _ = expect(&mut reader, &mut wr, 250, "DATA end");
    // QUIT.
    let _ = wr.write_all(b"QUIT\r\n").await;
    let _ = wr.flush().await;
    let _ = expect(&mut reader, &mut wr, 221, "QUIT");

    println!("self-test passed");
}

/// Queue commands.
async fn cmd_queue(sub: &QueueSub, config_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_file(config_path.to_str().unwrap_or("rmtp.toml"))?;
    let queue = Queue::new(config.queue)?;
    match sub {
        QueueSub::List => {
            let ids = queue.list_ids()?;
            if ids.is_empty() {
                println!("queue is empty");
            } else {
                println!("queued messages:");
                for id in ids {
                    println!("  {id}");
                }
            }
        }
        QueueSub::Retry => {
            let due = queue.due_messages()?;
            println!("{} message(s) due for retry", due.len());
            for m in due {
                println!("  {} from={} to={:?}", m.id, m.from, m.to);
            }
        }
        QueueSub::Flush => {
            let count = queue.flush()?;
            println!("flushed {count} message(s)");
        }
    }
    Ok(())
}

/// Validate the configuration file.
fn cmd_config_validate(path: &PathBuf) {
    match Config::from_file(path.to_str().unwrap_or("rmtp.toml")) {
        Ok(config) => match config.validate() {
            Ok(()) => println!("config is valid: {}", path.display()),
            Err(e) => {
                eprintln!("config invalid: {e}");
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("could not load config: {e}");
            process::exit(1);
        }
    }
}
