//! ZMTP PLAIN security mechanism — HELLO and WELCOME commands (RFC 27).
//!
//! # Security warning
//! PLAIN transmits usernames and passwords in clear text. Only use this
//! mechanism over transports that are already confidential and authenticated
//! (TLS, IPC, trusted LAN segments). Do **not** use PLAIN over untrusted
//! networks without an outer encryption layer.

#[cfg(feature = "plain")]
impl<A: Authenticator> crate::auth::AuthCheck for A {
    fn check(&self, username: &[u8], password: &[u8]) -> bool {
        self.authenticate(username, password)
    }
}

/// Validates credentials presented by a connecting peer.
///
/// Implementations should use constant-time comparison to avoid timing side-channels.
#[cfg(feature = "plain")]
pub trait Authenticator {
    fn authenticate(&self, username: &[u8], password: &[u8]) -> bool;
}

/// Errors from PLAIN mechanism encode/parse operations.
#[derive(Debug, PartialEq)]
pub enum PlainError {
    /// Output buffer is too small for the encoded frame.
    BufferTooSmall,
    /// Flags byte has the COMMAND bit clear — this is a message, not a command.
    NotACommand,
    /// Command name is neither "HELLO" nor "ERROR".
    UnknownCommand,
    /// HELLO frame is structurally malformed.
    MalformedHello,
    /// Credentials were rejected by the authenticator.
    /// The caller should call `write_error` and then drop the connection.
    AuthFailed,
    /// Peer sent an ERROR command.
    PeerError,
}

/// Length of the WELCOME command frame.
pub const WELCOME_LEN: usize = 10;

// 0x04 | body_len=0x08 | name_len=0x07 | "WELCOME"
const WELCOME_FRAME: [u8; WELCOME_LEN] =
    [0x04, 0x08, 0x07, b'W', b'E', b'L', b'C', b'O', b'M', b'E'];

/// Encode a WELCOME command into `buf`.
/// Returns the number of bytes written (`WELCOME_LEN`) or `PlainError::BufferTooSmall`.
///
/// # Errors
/// Returns `PlainError::BufferTooSmall` if `buf` is smaller than `WELCOME_LEN`.
pub fn encode_welcome(buf: &mut [u8]) -> Result<usize, PlainError> {
    if buf.len() < WELCOME_LEN {
        return Err(PlainError::BufferTooSmall);
    }
    buf[..WELCOME_LEN].copy_from_slice(&WELCOME_FRAME);
    Ok(WELCOME_LEN)
}

/// Parse a HELLO command from structured frame data.
/// Returns `(username, password)` slices into `body` on success.
///
/// HELLO body layout: `name_len(1)` + "HELLO"(5) + `username_len(1)` + username + `password_len(1)` + password
///
/// # Errors
/// Returns `PlainError::NotACommand` if `is_command` is false.
/// Returns `PlainError::MalformedHello` if the body is structurally invalid.
/// Returns `PlainError::PeerError` if the command name is "ERROR".
/// Returns `PlainError::UnknownCommand` if the command name is not "HELLO" or "ERROR".
pub fn parse_hello_from(is_command: bool, body: &[u8]) -> Result<(&[u8], &[u8]), PlainError> {
    if !is_command {
        return Err(PlainError::NotACommand);
    }
    if body.is_empty() {
        return Err(PlainError::MalformedHello);
    }
    let name_len = body[0] as usize;
    if body.len() < 1 + name_len {
        return Err(PlainError::MalformedHello);
    }
    let name = &body[1..=name_len];
    if name == b"ERROR" {
        return Err(PlainError::PeerError);
    }
    if name != b"HELLO" {
        return Err(PlainError::UnknownCommand);
    }
    let mut pos = 1 + name_len;

    if pos >= body.len() {
        return Err(PlainError::MalformedHello);
    }
    let username_len = body[pos] as usize;
    pos += 1;
    if pos + username_len > body.len() {
        return Err(PlainError::MalformedHello);
    }
    let username = &body[pos..pos + username_len];
    pos += username_len;

    if pos >= body.len() {
        return Err(PlainError::MalformedHello);
    }
    let password_len = body[pos] as usize;
    pos += 1;
    if pos + password_len > body.len() {
        return Err(PlainError::MalformedHello);
    }
    let password = &body[pos..pos + password_len];

    Ok((username, password))
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn hello_body(username: &[u8], password: &[u8]) -> heapless::Vec<u8, 64> {
        let name = b"HELLO";
        let mut v: heapless::Vec<u8, 64> = heapless::Vec::new();
        v.push(name.len() as u8).unwrap();
        v.extend_from_slice(name).unwrap();
        v.push(username.len() as u8).unwrap();
        v.extend_from_slice(username).unwrap();
        v.push(password.len() as u8).unwrap();
        v.extend_from_slice(password).unwrap();
        v
    }

    // Test 1: encode_welcome emits correct 10-byte frame
    #[test]
    fn encode_welcome_emits_correct_frame() {
        let mut buf = [0u8; 16];
        let n = encode_welcome(&mut buf).unwrap();
        assert_eq!(n, WELCOME_LEN);
        assert_eq!(buf[0], 0x04); // COMMAND flag
        assert_eq!(buf[1], 0x08); // body size = 8
        assert_eq!(buf[2], 0x07); // name_len = 7
        assert_eq!(&buf[3..10], b"WELCOME");
    }

    // Test 2: encode_welcome returns BufferTooSmall for undersized buffer
    #[test]
    fn encode_welcome_buffer_too_small() {
        let mut buf = [0u8; 5];
        assert_eq!(encode_welcome(&mut buf), Err(PlainError::BufferTooSmall));
    }

    // Test 3: parse_hello_from succeeds with valid username and password
    #[test]
    fn parse_hello_from_valid() {
        let body = hello_body(b"alice", b"secret");
        let (user, pass) = parse_hello_from(true, &body).unwrap();
        assert_eq!(user, b"alice");
        assert_eq!(pass, b"secret");
    }

    // Test 4: parse_hello_from accepts empty username and password
    #[test]
    fn parse_hello_from_empty_credentials() {
        let body = hello_body(b"", b"");
        let (user, pass) = parse_hello_from(true, &body).unwrap();
        assert_eq!(user, b"");
        assert_eq!(pass, b"");
    }

    // Test 5: parse_hello_from returns NotACommand when command flag is clear
    #[test]
    fn parse_hello_from_not_a_command() {
        let body = hello_body(b"u", b"p");
        assert_eq!(parse_hello_from(false, &body), Err(PlainError::NotACommand));
    }

    // Test 6: parse_hello_from returns PeerError for ERROR command
    #[test]
    fn parse_hello_from_error_command() {
        // body with name="ERROR"
        let mut body: heapless::Vec<u8, 16> = heapless::Vec::new();
        body.push(5).unwrap();
        body.extend_from_slice(b"ERROR").unwrap();
        body.extend_from_slice(b"\x00something").unwrap();
        assert_eq!(parse_hello_from(true, &body), Err(PlainError::PeerError));
    }

    // Test 7: parse_hello_from returns UnknownCommand for unexpected command name
    #[test]
    fn parse_hello_from_unknown_command() {
        let mut body: heapless::Vec<u8, 16> = heapless::Vec::new();
        body.push(5).unwrap();
        body.extend_from_slice(b"READY").unwrap();
        assert_eq!(
            parse_hello_from(true, &body),
            Err(PlainError::UnknownCommand)
        );
    }

    // Test 8: parse_hello_from returns MalformedHello when body is empty
    #[test]
    fn parse_hello_from_empty_body() {
        assert_eq!(parse_hello_from(true, &[]), Err(PlainError::MalformedHello));
    }

    // Test 9: parse_hello_from returns MalformedHello when body is truncated mid-username
    #[test]
    fn parse_hello_from_truncated_username() {
        // name_len=5, "HELLO", username_len=5, then only 2 bytes of username
        let mut body: heapless::Vec<u8, 16> = heapless::Vec::new();
        body.push(5).unwrap();
        body.extend_from_slice(b"HELLO").unwrap();
        body.push(5).unwrap(); // claim 5 bytes username
        body.extend_from_slice(b"ab").unwrap(); // only 2 bytes
        assert_eq!(
            parse_hello_from(true, &body),
            Err(PlainError::MalformedHello)
        );
    }

    // Test 10: parse_hello_from returns MalformedHello when password_len field is missing
    #[test]
    fn parse_hello_from_missing_password_len() {
        // valid username, but no password_len byte
        let mut body: heapless::Vec<u8, 16> = heapless::Vec::new();
        body.push(5).unwrap();
        body.extend_from_slice(b"HELLO").unwrap();
        body.push(0).unwrap(); // empty username
        // no password_len byte at all
        assert_eq!(
            parse_hello_from(true, &body),
            Err(PlainError::MalformedHello)
        );
    }
}
