# RMTP — Lightweight SMTP Server/Relay

**RMTP** (Rust Mail Transfer Protocol) is a standalone, terminal-only SMTP
relay written in Rust. Applications use it as a drop-in SMTP server.

## Design goals

- **Extremely low RAM**: tiny binary, no unbounded memory growth, streams large
  messages instead of buffering them.
- **High performance**: Tokio-based async I/O, bounded concurrency, backpressure.
- **Reliability**: persistent filesystem queue with exponential backoff, crash-safe
  atomic writes, survives restarts without losing queued messages.
- **Security**: SMTP AUTH (PLAIN/LOGIN), STARTTLS via rustls, auth-without-TLS
  rejection, rate limiting, injection protection, no password logging.
- **Easy deployment**: single static binary, no database, no Docker required,
  systemd service included, TOML configuration.

## Requirements (build)

- Rust toolchain (stable, 1.70+ recommended)
- Network access to crates.io at build time (to fetch dependencies)

The sandbox used to prepare this tree had no Rust toolchain and no crates.io
access, so `cargo build` was not executed here. The source is written to compile
with `cargo build --release` in a normal environment.

## Quick start

```bash
# 1. Generate a default configuration
rustsmtp init

# 2. Edit rmtp.toml (set hostname, TLS cert/key, credentials, relay)

# 3. Validate
rustsmtp config validate

# 4. Start
rustsmtp start

# 5. Check status
rustsmtp status
```

## Configuration (`rmtp.toml`)

```toml
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
required = false
username = "change-me"
password = "change-me"

[relay]
enabled = true
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
```

Secrets may be supplied via environment variables instead of the file:
`RMTP_AUTH_USERNAME`, `RMTP_AUTH_PASSWORD`, `RMTP_RELAY_USERNAME`,
`RMTP_RELAY_PASSWORD`, `RMTP_RELAY_HOST`, `RMTP_RELAY_PORT`,
`RMTP_BIND`, `RMTP_PORT`.

**Security**: if `auth.enabled` is true and `tls.enabled` is false, RMTP refuses
to start unless `RMTP_INSECURE_ALLOW_AUTH_WITHOUT_TLS=1` is set.

## CLI

```
rustsmtp init               generate a default config file
rustsmtp start              start the SMTP relay
rustsmtp stop               stop a running instance (PID file)
rustsmtp status             show running status
rustsmtp test               run a self-test SMTP session
rustsmtp queue list         list queued messages
rustsmtp queue retry        retry queued deliveries now
rustsmtp queue flush        drop all queued messages
rustsmtp config validate    validate the configuration file
```

All commands accept `--config <path>` (default `rmtp.toml`), `-q` (quiet) and
`-v` (verbose).

## Architecture

```
src/
  main.rs         CLI entry point (clap)
  lib.rs          library root
  config/         TOML config + validation
  cli/            command definitions
  server/         Tokio TCP listener, bounded connections, timeouts
  smtp/           RFC 5321 protocol engine (parser, responses, session)
  auth/           PLAIN and LOGIN SMTP AUTH
  tls/            STARTTLS via rustls
  relay/          upstream SMTP client
  queue/          persistent filesystem queue, exponential backoff
  storage/        atomic file operations
  logging/        structured terminal logging
  security/       rate limiting, constant-time compare, input validation
```

Components are independent and unit-tested.

## Queue

Messages are durably stored under `queue.directory` as `<id>.eml` plus
`<id>.meta` before any SMTP `250 OK` is emitted. Delivery failures are
rescheduled with exponential backoff (`retry_interval * 2^attempts`, capped at
1 hour). On restart, all queued messages are scanned and re-scheduled.

## Systemd service

See `contrib/rmtp.service`.

```ini
[Unit]
Description=RMTP SMTP Relay
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/rmtp
ExecStart=/opt/rmtp/rustsmtp start --config /opt/rmtp/rmtp.toml
Restart=always
RestartSec=5
User=rmtp
Group=rmtp
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

## Building

```bash
cargo build --release
# binary: target/release/rustsmtp
```

## License

MIT

## Security notes

- Passwords are compared with `subtle` (constant-time) and are never logged.
- AUTH without TLS is rejected by default.
- SMTP command lines are validated for CR/LF injection.
- Queue paths are checked for traversal.
- Errors returned to SMTP clients are generic; internal details are logged
  server-side only.
```
