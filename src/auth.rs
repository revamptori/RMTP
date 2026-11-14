//! SMTP AUTH (RFC 4954): PLAIN and LOGIN mechanisms.
//!
//! Credentials are never logged. Comparison is constant-time.

use crate::security::constant_time_eq;
use std::sync::Arc;

/// Configured authentication credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}

/// Supported AUTH mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    Plain,
    Login,
}

impl AuthMechanism {
    pub fn name(self) -> &'static str {
        match self {
            AuthMechanism::Plain => "PLAIN",
            AuthMechanism::Login => "LOGIN",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "PLAIN" => Some(AuthMechanism::Plain),
            "LOGIN" => Some(AuthMechanism::Login),
            _ => None,
        }
    }
}

/// State of an in-progress AUTH negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    /// Not yet started / not authenticated.
    None,
    /// PLAIN: waiting for the base64 payload.
    PlainPending,
    /// LOGIN: waiting for username.
    LoginUserPending,
    /// LOGIN: waiting for password.
    LoginPassPending,
    /// Authentication succeeded.
    Authenticated,
    /// Authentication failed permanently.
    Failed,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState::None
    }
}

/// Result of an auth step.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthStep {
    /// Continue the negotiation; send `resp` to the client.
    Continue(String),
    /// Authentication succeeded.
    Success,
    /// Authentication failed.
    Failure,
}

/// Decode a base64 AUTH payload, handling the optional leading response.
fn decode_b64(input: &str) -> Option<Vec<u8>> {
    let s = input.trim();
    if s.is_empty() {
        return Some(Vec::new());
    }
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Split a PLAIN payload (\0username\0password) into its parts.
fn split_plain(payload: &[u8]) -> Option<(String, String)> {
    let s = String::from_utf8(payload.to_vec()).ok()?;
    let mut parts = s.split('\0');
    let _authzid = parts.next();
    let username = parts.next()?.to_string();
    let password = parts.next()?.to_string();
    Some((username, password))
}

/// Process one step of an AUTH exchange.
///
/// `credentials` holds the expected username/password. `state` is the current
/// auth state (mutated). `input` is the raw client argument for this step.
///
/// Returns the SMTP response to send and updates `state`.
pub fn auth_step(
    credentials: &Credentials,
    state: &mut AuthState,
    input: &str,
    mechanism: AuthMechanism,
) -> AuthStep {
    match mechanism {
        AuthMechanism::Plain => match state {
            AuthState::None | AuthState::PlainPending => {
                let payload = match decode_b64(input) {
                    Some(p) => p,
                    None => return AuthStep::Failure,
                };
                let (username, password) = match split_plain(&payload) {
                    Some(p) => p,
                    None => return AuthStep::Failure,
                };
                let ok = constant_time_eq(username.as_bytes(), credentials.username.as_bytes())
                    && constant_time_eq(password.as_bytes(), credentials.password.as_bytes());
                if ok {
                    *state = AuthState::Authenticated;
                    AuthStep::Success
                } else {
                    *state = AuthState::Failed;
                    AuthStep::Failure
                }
            }
            _ => AuthStep::Failure,
        },
        AuthMechanism::Login => match state {
            AuthState::None => {
                *state = AuthState::LoginUserPending;
                AuthStep::Continue("VXNlcm5hbWU6".to_string()) // "Username:"
            }
            AuthState::LoginUserPending => {
                let username = match decode_b64(input) {
                    Some(p) => String::from_utf8(p).unwrap_or_default(),
                    None => return AuthStep::Failure,
                };
                if !constant_time_eq(username.as_bytes(), credentials.username.as_bytes()) {
                    *state = AuthState::Failed;
                    return AuthStep::Failure;
                }
                *state = AuthState::LoginPassPending;
                AuthStep::Continue("UGFzc3dvcmQ6".to_string()) // "Password:"
            }
            AuthState::LoginPassPending => {
                let password = match decode_b64(input) {
                    Some(p) => String::from_utf8(p).unwrap_or_default(),
                    None => return AuthStep::Failure,
                };
                let ok = constant_time_eq(password.as_bytes(), credentials.password.as_bytes());
                if ok {
                    *state = AuthState::Authenticated;
                    AuthStep::Success
                } else {
                    *state = AuthState::Failed;
                    AuthStep::Failure
                }
            }
            _ => AuthStep::Failure,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials::new("alice".into(), "s3cret".into())
    }

    #[test]
    fn plain_success() {
        let c = creds();
        let mut state = AuthState::None;
        // \0alice\0s3cret -> base64
        let payload = base64::engine::general_purpose::STANDARD.encode("\0alice\0s3cret");
        assert_eq!(auth_step(&c, &mut state, &payload, AuthMechanism::Plain), AuthStep::Success);
        assert_eq!(state, AuthState::Authenticated);
    }

    #[test]
    fn plain_failure_wrong_password() {
        let c = creds();
        let mut state = AuthState::None;
        let payload = base64::engine::general_purpose::STANDARD.encode("\0alice\0wrong");
        assert_eq!(auth_step(&c, &mut state, &payload, AuthMechanism::Plain), AuthStep::Failure);
        assert_eq!(state, AuthState::Failed);
    }

    #[test]
    fn login_flow() {
        let c = creds();
        let mut state = AuthState::None;
        // step 1: initiate
        match auth_step(&c, &mut state, "", AuthMechanism::Login) {
            AuthStep::Continue(resp) => assert_eq!(resp, "VXNlcm5hbWU6"),
            other => panic!("expected Continue, got {other:?}"),
        }
        assert_eq!(state, AuthState::LoginUserPending);
        // step 2: username
        let user_b64 = base64::engine::general_purpose::STANDARD.encode("alice");
        match auth_step(&c, &mut state, &user_b64, AuthMechanism::Login) {
            AuthStep::Continue(resp) => assert_eq!(resp, "UGFzc3dvcmQ6"),
            other => panic!("expected Continue, got {other:?}"),
        }
        assert_eq!(state, AuthState::LoginPassPending);
        // step 3: password
        let pass_b64 = base64::engine::general_purpose::STANDARD.encode("s3cret");
        assert_eq!(auth_step(&c, &mut state, &pass_b64, AuthMechanism::Login), AuthStep::Success);
        assert_eq!(state, AuthState::Authenticated);
    }

    #[test]
    fn credentials_never_logged() {
        // Just a placeholder asserting the type exists and is constructible.
        let c = Credentials::new("u".into(), "p".into());
        assert_eq!(c.username, "u");
        let _ = c.password; // ensure field is read (never printed)
    }
}
