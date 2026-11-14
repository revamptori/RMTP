//! SMTP protocol engine (RFC 5321).
//!
//! Command parsing, response codes, and session state machine.
//! This module is protocol-only: it knows nothing about the network transport.

use crate::security::{validate_address_token, validate_command_line, destuff_line};
use crate::auth::{AuthMechanism, AuthState};
use std::collections::HashMap;

/// SMTP response codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCode {
    /// 220 Service ready.
    ServiceReady,
    /// 221 Service closing transmission channel.
    ServiceClosing,
    /// 250 Requested mail action okay, completed.
    Ok,
    /// 251 User not local; will forward.
    UserNotLocal,
    /// 252 Cannot VRFY user.
    CannotVrfy,
    /// 354 Start mail input.
    StartMailInput,
    /// 421 Service not available, closing channel.
    ServiceNotAvailable,
    /// 450 Requested mail action not taken.
    MailboxUnavailable,
    /// 451 Requested action aborted.
    LocalError,
    /// 452 Insufficient system storage.
    InsufficientStorage,
    /// 454 TLS required.
    TlsRequired,
    /// 500 Syntax error.
    SyntaxError,
    /// 501 Syntax error in parameters.
    SyntaxErrorParameters,
    /// 502 Command not implemented.
    NotImplemented,
    /// 503 Bad sequence of commands.
    BadSequence,
    /// 504 Command parameter not implemented.
    ParameterNotImplemented,
    /// 550 Requested action not taken.
    MailboxNotAvailable,
    /// 551 User not local.
    UserNotLocalPerm,
    /// 552 Exceeded storage allocation.
    ExceededStorage,
    /// 553 Mailbox name not allowed.
    MailboxNameNotAllowed,
    /// 554 Transaction failed.
    TransactionFailed,
    /// 535 Auth credentials invalid.
    AuthCredentialsInvalid,
    /// 538 Encryption required for requested authentication mechanism.
    EncryptionRequired,
}

impl ReplyCode {
    pub fn code(self) -> u16 {
        match self {
            ReplyCode::ServiceReady => 220,
            ReplyCode::ServiceClosing => 221,
            ReplyCode::Ok => 250,
            ReplyCode::UserNotLocal => 251,
            ReplyCode::CannotVrfy => 252,
            ReplyCode::StartMailInput => 354,
            ReplyCode::ServiceNotAvailable => 421,
            ReplyCode::MailboxUnavailable => 450,
            ReplyCode::LocalError => 451,
            ReplyCode::InsufficientStorage => 452,
            ReplyCode::TlsRequired => 454,
            ReplyCode::SyntaxError => 500,
            ReplyCode::SyntaxErrorParameters => 501,
            ReplyCode::NotImplemented => 502,
            ReplyCode::BadSequence => 503,
            ReplyCode::ParameterNotImplemented => 504,
            ReplyCode::MailboxNotAvailable => 550,
            ReplyCode::UserNotLocalPerm => 551,
            ReplyCode::ExceededStorage => 552,
            ReplyCode::MailboxNameNotAllowed => 553,
            ReplyCode::TransactionFailed => 554,
            ReplyCode::AuthCredentialsInvalid => 535,
            ReplyCode::EncryptionRequired => 538,
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            ReplyCode::ServiceReady => "Service ready",
            ReplyCode::ServiceClosing => "Service closing transmission channel",
            ReplyCode::Ok => "OK",
            ReplyCode::UserNotLocal => "User not local; will forward",
            ReplyCode::CannotVrfy => "Cannot VRFY user",
            ReplyCode::StartMailInput => "Start mail input; end with <CRLF>.<CRLF>",
            ReplyCode::ServiceNotAvailable => "Service not available, closing channel",
            ReplyCode::MailboxUnavailable => "Mailbox unavailable",
            ReplyCode::LocalError => "Requested action aborted: local error",
            ReplyCode::InsufficientStorage => "Insufficient system storage",
            ReplyCode::TlsRequired => "TLS required",
            ReplyCode::SyntaxError => "Syntax error, command unrecognized",
            ReplyCode::SyntaxErrorParameters => "Syntax error in parameters or arguments",
            ReplyCode::NotImplemented => "Command not implemented",
            ReplyCode::BadSequence => "Bad sequence of commands",
            ReplyCode::ParameterNotImplemented => "Command parameter not implemented",
            ReplyCode::MailboxNotAvailable => "Requested action not taken: mailbox unavailable",
            ReplyCode::UserNotLocalPerm => "User not local; please try <forward-path>",
            ReplyCode::ExceededStorage => "Requested action aborted: exceeded storage allocation",
            ReplyCode::MailboxNameNotAllowed => "Mailbox name not allowed",
            ReplyCode::TransactionFailed => "Transaction failed",
            ReplyCode::AuthCredentialsInvalid => "Authentication credentials invalid",
            ReplyCode::EncryptionRequired => "Encryption required for requested authentication mechanism",
        }
    }

    /// Format as a full SMTP reply line.
    pub fn format(self) -> String {
        format!("{} {}", self.code(), self.text())
    }
}

/// An SMTP command parsed from a client line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    Ehlo(String),
    Helo(String),
    MailFrom {
        path: String,
        size: Option<usize>,
        body: Option<String>,
        ret: Option<String>,
    },
    RcptTo {
        path: String,
        notify: Option<String>,
    },
    Data,
    Rset,
    Noop,
    Quit,
    Auth {
        mechanism: AuthMechanism,
        initial: Option<String>,
    },
    Vrfy(String),
    Expn(String),
    Help(Option<String>),
    Unknown(String),
}

/// Parse a single SMTP command line into a command.
///
/// Returns `None` for blank/malformed lines (caller should send 500).
pub fn parse_command(line: &str) -> Option<SmtpCommand> {
    let line = line.trim_end();
    if line.is_empty() {
        return None;
    }
    if !validate_command_line(line) {
        return Some(SmtpCommand::Unknown(line.to_string()));
    }

    // Split into command and argument at the first whitespace.
    let (cmd, arg) = split_command_arg(line);
    let cmd = cmd.to_ascii_uppercase();

    match cmd.as_str() {
        "EHLO" => {
            let domain = arg.trim();
            if domain.is_empty() {
                Some(SmtpCommand::Ehlo("localhost".into()))
            } else {
                Some(SmtpCommand::Ehlo(domain.to_string()))
            }
        }
        "HELO" => {
            let domain = arg.trim();
            if domain.is_empty() {
                Some(SmtpCommand::Helo("localhost".into()))
            } else {
                Some(SmtpCommand::Helo(domain.to_string()))
            }
        }
        "MAIL" => parse_mail_from(arg),
        "RCPT" => parse_rcpt_to(arg),
        "DATA" => Some(SmtpCommand::Data),
        "RSET" => Some(SmtpCommand::Rset),
        "NOOP" => Some(SmtpCommand::Noop),
        "QUIT" => Some(SmtpCommand::Quit),
        "AUTH" => parse_auth(arg),
        "VRFY" => Some(SmtpCommand::Vrfy(arg.trim().to_string())),
        "EXPN" => Some(SmtpCommand::Expn(arg.trim().to_string())),
        "HELP" => {
            let arg = arg.trim();
            Some(SmtpCommand::Help(if arg.is_empty() { None } else { Some(arg.to_string()) }))
        }
        _ => Some(SmtpCommand::Unknown(cmd)),
    }
}

fn split_command_arg(line: &str) -> (&str, &str) {
    match line.find(|c: char| c.is_whitespace()) {
        Some(i) => (&line[..i], &line[i + 1..]),
        None => (line, ""),
    }
}

fn parse_mail_from(arg: &str) -> Option<SmtpCommand> {
    let arg = arg.trim();
    // FROM:<path>
    let rest = arg.strip_prefix("FROM:").or_else(|| arg.strip_prefix("from:"))?;
    let rest = rest.trim();
    let (path, params) = split_params(rest);
    if !validate_address_token(path) {
        return Some(SmtpCommand::Unknown("MAIL".into()));
    }
    let mut size = None;
    let mut body = None;
    let mut ret = None;
    for p in params {
        let p = p.trim();
        if let Some(v) = p.strip_prefix("SIZE=") {
            size = v.parse().ok();
        } else if let Some(v) = p.strip_prefix("BODY=") {
            body = Some(v.to_string());
        } else if let Some(v) = p.strip_prefix("RET=") {
            ret = Some(v.to_string());
        }
    }
    Some(SmtpCommand::MailFrom { path: path.to_string(), size, body, ret })
}

fn parse_rcpt_to(arg: &str) -> Option<SmtpCommand> {
    let arg = arg.trim();
    let rest = arg.strip_prefix("TO:").or_else(|| arg.strip_prefix("to:"))?;
    let rest = rest.trim();
    let (path, params) = split_params(rest);
    if !validate_address_token(path) {
        return Some(SmtpCommand::Unknown("RCPT".into()));
    }
    let mut notify = None;
    for p in params {
        let p = p.trim();
        if let Some(v) = p.strip_prefix("NOTIFY=") {
            notify = Some(v.to_string());
        }
    }
    Some(SmtpCommand::RcptTo { path: path.to_string(), notify })
}

fn split_params(s: &str) -> (&str, Vec<&str>) {
    // Split on whitespace; first token is the path, rest are key=value params.
    let mut tokens = s.split_whitespace();
    let path = tokens.next().unwrap_or("");
    let params = tokens.collect();
    (path, params)
}

fn parse_auth(arg: &str) -> Option<SmtpCommand> {
    let arg = arg.trim();
    let mut tokens = arg.split_whitespace();
    let mech = tokens.next()?;
    let mechanism = AuthMechanism::from_name(mech)?;
    let initial = tokens.next().map(|s| s.to_string());
    Some(SmtpCommand::Auth { mechanism, initial })
}

/// State of an SMTP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStage {
    Greeting,          // waiting for EHLO/HELO
    Ehlo,              // identified, awaiting MAIL
    Mail,              // MAIL received, awaiting RCPT
    Rcpt,              // at least one RCPT, awaiting DATA
    Data,              // in DATA
    Auth,              // authenticating
    Closed,
}

impl Default for SessionStage {
    fn default() -> Self {
        SessionStage::Greeting
    }
}

/// An SMTP session's state.
#[derive(Debug, Default, Clone)]
pub struct SmtpSession {
    pub stage: SessionStage,
    pub helo_domain: Option<String>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    pub data: Vec<u8>,
    pub size: Option<usize>,
    pub authenticated: bool,
    pub auth_state: AuthState,
    pub auth_mechanism: Option<AuthMechanism>,
    pub tls_active: bool,
    pub esmtp_extensions: HashMap<String, String>,
}

impl SmtpSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_recipient(&self) -> bool {
        !self.rcpt_to.is_empty()
    }
}

/// A complete client command plus the response to generate.
/// The session is updated by the handler outside this module.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub code: ReplyCode,
    /// Multi-line response (each element is a line, first line includes code).
    pub lines: Vec<String>,
    /// Whether the session should transition to DATA after this.
    pub enter_data: bool,
    /// Whether to close the connection after sending.
    pub close: bool,
}

impl CommandResult {
    pub fn single(code: ReplyCode) -> Self {
        Self { code, lines: vec![code.format()], enter_data: false, close: false }
    }
    pub fn multi(code: ReplyCode, lines: Vec<String>) -> Self {
        Self { code, lines, enter_data: false, close: false }
    }
}

/// Build an EHLO/HELO response.
pub fn handle_hello(cmd: &SmtpCommand, session: &mut SmtpSession, tls_available: bool, auth_enabled: bool) -> CommandResult {
    let domain = match cmd {
        SmtpCommand::Ehlo(d) | SmtpCommand::Helo(d) => d.clone(),
        _ => unreachable!(),
    };
    session.helo_domain = Some(domain.clone());
    session.stage = SessionStage::Ehlo;

    if matches!(cmd, SmtpCommand::Ehlo(_)) {
        let mut lines = vec![format!("250-{domain} Hello")];
        lines.push("250-SIZE 26214400".into());
        lines.push("250-8BITMIME".into());
        lines.push("250-STARTTLS".into());
        if auth_enabled {
            lines.push("250-AUTH PLAIN LOGIN".into());
        }
        lines.push("250 HELP".into());
        CommandResult::multi(ReplyCode::Ok, lines)
    } else {
        session.esmtp_extensions.clear();
        CommandResult::single(ReplyCode::Ok)
    }
}

/// Build a MAIL FROM response.
pub fn handle_mail_from(cmd: &SmtpCommand, session: &mut SmtpSession, max_size: usize) -> CommandResult {
    if !matches!(session.stage, SessionStage::Ehlo) {
        return CommandResult::single(ReplyCode::BadSequence);
    }
    let SmtpCommand::MailFrom { path, size, .. } = cmd else {
        return CommandResult::single(ReplyCode::SyntaxError);
    };

    // Size check.
    if let Some(s) = size {
        if *s > max_size {
            return CommandResult::single(ReplyCode::ExceededStorage);
        }
        session.size = Some(*s);
    }

    session.mail_from = Some(path.clone());
    session.stage = SessionStage::Mail;
    CommandResult::single(ReplyCode::Ok)
}

/// Build an RCPT TO response.
pub fn handle_rcpt_to(cmd: &SmtpCommand, session: &mut SmtpSession) -> CommandResult {
    if !matches!(session.stage, SessionStage::Mail | SessionStage::Rcpt) {
        return CommandResult::single(ReplyCode::BadSequence);
    }
    let SmtpCommand::RcptTo { path, .. } = cmd else {
        return CommandResult::single(ReplyCode::SyntaxError);
    };
    session.rcpt_to.push(path.clone());
    session.stage = SessionStage::Rcpt;
    CommandResult::single(ReplyCode::Ok)
}

/// Build a DATA response.
pub fn handle_data(session: &SmtpSession) -> CommandResult {
    if !matches!(session.stage, SessionStage::Rcpt) {
        return CommandResult::single(ReplyCode::BadSequence);
    }
    if session.rcpt_to.is_empty() {
        return CommandResult::single(ReplyCode::BadSequence);
    }
    CommandResult {
        code: ReplyCode::StartMailInput,
        lines: vec![ReplyCode::StartMailInput.format()],
        enter_data: true,
        close: false,
    }
}

/// Build a RSET response.
pub fn handle_rset(session: &mut SmtpSession) -> CommandResult {
    session.mail_from = None;
    session.rcpt_to.clear();
    session.data.clear();
    session.size = None;
    session.stage = SessionStage::Ehlo;
    CommandResult::single(ReplyCode::Ok)
}

/// Build a NOOP response.
pub fn handle_noop() -> CommandResult {
    CommandResult::single(ReplyCode::Ok)
}

/// Build a QUIT response.
pub fn handle_quit() -> CommandResult {
    CommandResult { code: ReplyCode::ServiceClosing, lines: vec![ReplyCode::ServiceClosing.format()], enter_data: false, close: true }
}

/// Process received DATA: store, enforce size limit, mark complete.
pub fn finalize_data(session: &mut SmtpSession, max_size: usize) -> CommandResult {
    if session.data.len() > max_size {
        session.stage = SessionStage::Ehlo;
        session.mail_from = None;
        session.rcpt_to.clear();
        session.data.clear();
        return CommandResult::single(ReplyCode::ExceededStorage);
    }
    session.stage = SessionStage::Ehlo;
    session.mail_from = None;
    session.rcpt_to.clear();
    session.size = None;
    // data is intentionally preserved for the caller to consume before reset.
    CommandResult::single(ReplyCode::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ehlo_helo() {
        assert!(matches!(parse_command("EHLO example.com").unwrap(), SmtpCommand::Ehlo(d) if d == "example.com"));
        assert!(matches!(parse_command("HELO client").unwrap(), SmtpCommand::Helo(d) if d == "client"));
        assert!(matches!(parse_command("EHLO").unwrap(), SmtpCommand::Ehlo(d) if d == "localhost"));
    }

    #[test]
    fn parse_mail_from() {
        let c = parse_command("MAIL FROM:<alice@example.com> SIZE=100").unwrap();
        match c {
            SmtpCommand::MailFrom { path, size, .. } => {
                assert_eq!(path, "<alice@example.com>");
                assert_eq!(size, Some(100));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_rcpt_to() {
        let c = parse_command("RCPT TO:<bob@example.com>").unwrap();
        match c {
            SmtpCommand::RcptTo { path, .. } => assert_eq!(path, "<bob@example.com>"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_auth_plain() {
        let c = parse_command("AUTH PLAIN").unwrap();
        match c {
            SmtpCommand::Auth { mechanism, initial } => {
                assert_eq!(mechanism, AuthMechanism::Plain);
                assert_eq!(initial, None);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn reject_injection() {
        assert!(parse_command("EHLO host\r\nQUIT").is_some());
        match parse_command("EHLO host\r\nQUIT").unwrap() {
            SmtpCommand::Unknown(_) => {}
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn reply_codes() {
        assert_eq!(ReplyCode::ServiceReady.code(), 220);
        assert_eq!(ReplyCode::Ok.code(), 250);
        assert_eq!(ReplyCode::StartMailInput.code(), 354);
        assert_eq!(ReplyCode::SyntaxError.code(), 500);
        assert_eq!(ReplyCode::ServiceReady.format(), "220 Service ready");
    }

    #[test]
    fn session_flow() {
        let mut session = SmtpSession::new();
        let mut tls = false;
        let auth = true;
        let r = handle_hello(&parse_command("EHLO example.com").unwrap(), &mut session, tls, auth);
        assert_eq!(r.code, ReplyCode::Ok);
        assert!(matches!(session.stage, SessionStage::Ehlo));

        let r = handle_mail_from(&parse_command("MAIL FROM:<a@b.c>").unwrap(), &mut session, 10_000);
        assert_eq!(r.code, ReplyCode::Ok);
        assert!(matches!(session.stage, SessionStage::Mail));

        let r = handle_rcpt_to(&parse_command("RCPT TO:<c@d.e>").unwrap(), &mut session);
        assert_eq!(r.code, ReplyCode::Ok);
        assert!(matches!(session.stage, SessionStage::Rcpt));

        let r = handle_data(&session);
        assert_eq!(r.code, ReplyCode::StartMailInput);
        assert!(r.enter_data);

        let mut s2 = session.clone();
        let r = finalize_data(&mut s2, 10_000);
        assert_eq!(r.code, ReplyCode::Ok);
    }

    #[test]
    fn size_limit_enforced() {
        let mut session = SmtpSession::new();
        let r = handle_hello(&parse_command("EHLO example.com").unwrap(), &mut session, false, false);
        assert_eq!(r.code, ReplyCode::Ok);
        let r = handle_mail_from(&parse_command("MAIL FROM:<a@b.c> SIZE=999999").unwrap(), &mut session, 100);
        assert_eq!(r.code, ReplyCode::ExceededStorage);
    }
}
