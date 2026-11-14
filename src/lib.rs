//! RMTP - an extremely lightweight SMTP server/relay.
//!
//! Production-oriented, terminal-only SMTP relay written in Rust.
//!
//! Modules:
//!   config   - TOML configuration loading & validation
//!   logging  - structured terminal logging
//!   security - rate limiting, constant-time compare, input validation
//!   smtp     - SMTP protocol engine (RFC 5321)
//!   auth     - SMTP AUTH (PLAIN, LOGIN)
//!   tls      - STARTTLS via rustls
//!   server   - async TCP server with bounded concurrency
//!   relay    - upstream SMTP relay client
//!   queue    - persistent filesystem queue with exponential backoff
//!   storage  - atomic filesystem operations

pub mod auth;
pub mod config;
pub mod logging;
pub mod queue;
pub mod relay;
pub mod security;
pub mod server;
pub mod smtp;
pub mod storage;
pub mod tls;

pub use config::Config;
