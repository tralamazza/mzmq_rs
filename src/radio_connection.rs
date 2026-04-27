//! ZMTP 3.1 RADIO connection state machine (RFC 48).

use crate::auth::{AuthCheck, Mechanism};
use crate::frame::decode_error::DecodeError;
use crate::frame::{FrameDecoder, FrameError, MAX_FRAME_HEADER, encode_message_frame};
use crate::greeting::{
    GREETING_LEN, GREETING_PARTIAL_LEN, GreetingError, encode_greeting, parse_greeting,
    parse_partial_greeting,
};
#[cfg(feature = "plain")]
use crate::greeting::{encode_plain_greeting, parse_plain_greeting};
use crate::group_table::GroupTable;
use crate::null::{
    NullError, RADIO_READY_LEN, encode_error, encode_ready_radio, parse_ready_radio_from,
};
#[cfg(feature = "plain")]
use crate::plain::{PlainError, WELCOME_LEN, encode_welcome, parse_hello_from};

/// Headers returned by [`RadioConnection::publish_headers`]:
/// `(group_hdr, group_hdr_len, body_hdr, body_hdr_len)`.
pub type PublishHeaders = ([u8; MAX_FRAME_HEADER], usize, [u8; MAX_FRAME_HEADER], usize);

/// State of the RADIO connection.
#[derive(Debug, PartialEq)]
pub enum State {
    /// Waiting to send our greeting (or awaiting peer greeting bytes).
    Greeting,
    /// Greeting exchanged; awaiting READY command from peer (NULL mechanism).
    Ready,
    /// PLAIN: greeting exchanged; awaiting HELLO command from peer.
    #[cfg(feature = "plain")]
    PlainHello,
    /// PLAIN: HELLO validated; caller must send WELCOME then READY, then await peer READY.
    #[cfg(feature = "plain")]
    PlainReady,
    /// Handshake complete; can publish messages.
    Established,
    /// Unrecoverable error; connection must be dropped.
    Failed,
}

/// Sans-IO ZMTP 3.1 RADIO connection.
/// `GROUP_CAP` = max simultaneous group memberships per peer.
/// `GROUP_LEN_CAP` = max bytes per group name.
/// `FRAME_CAP` = max body bytes buffered in the internal frame decoder.
/// `A` = authenticator type; use the default `()` for the NULL mechanism,
#[cfg_attr(
    feature = "plain",
    doc = "      or supply an [`Authenticator`](crate::plain::Authenticator) and construct via"
)]
#[cfg_attr(
    feature = "plain",
    doc = "      [`RadioConnection::new_plain`] for the PLAIN mechanism."
)]
#[cfg_attr(
    not(feature = "plain"),
    doc = "      or construct via [`RadioConnection::new`]."
)]
#[allow(clippy::struct_excessive_bools)]
pub struct RadioConnection<
    const GROUP_CAP: usize,
    const GROUP_LEN_CAP: usize,
    const FRAME_CAP: usize,
    A: AuthCheck = (),
> {
    state: State,
    our_greeting_sent: bool,
    peer_greeting_received: bool,
    peer_version_minor: u8,
    our_ready_sent: bool,
    #[cfg_attr(not(feature = "plain"), allow(dead_code))]
    our_welcome_sent: bool,
    mechanism: Mechanism,
    greeting_buf: [u8; 64],
    greeting_pos: usize,
    frame_decoder: FrameDecoder<FRAME_CAP>,
    group_table: GroupTable<GROUP_CAP, GROUP_LEN_CAP>,
    pending_pong: Option<([u8; 16], usize)>,
    #[cfg_attr(not(feature = "plain"), allow(dead_code))]
    auth: A,
}

impl<const GROUP_CAP: usize, const GROUP_LEN_CAP: usize, const FRAME_CAP: usize>
    RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP, ()>
{
    /// Create a new NULL-mechanism connection in the `Greeting` state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Greeting,
            our_greeting_sent: false,
            peer_greeting_received: false,
            peer_version_minor: 0,
            our_ready_sent: false,
            our_welcome_sent: false,
            mechanism: Mechanism::Null,
            greeting_buf: [0u8; 64],
            greeting_pos: 0,
            frame_decoder: FrameDecoder::new(),
            group_table: GroupTable::new(),
            pending_pong: None,
            auth: (),
        }
    }
}

impl<const GROUP_CAP: usize, const GROUP_LEN_CAP: usize, const FRAME_CAP: usize> Default
    for RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP, ()>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "plain")]
impl<const GROUP_CAP: usize, const GROUP_LEN_CAP: usize, const FRAME_CAP: usize, A>
    RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP, A>
where
    A: crate::plain::Authenticator,
{
    /// Create a new PLAIN-mechanism connection in the `Greeting` state.
    /// The `auth` value is called to validate credentials from each connecting peer.
    /// On authentication failure `feed` returns `ConnError::PlainError(PlainError::AuthFailed)`;
    /// call `write_error` and drop the connection.
    pub fn new_plain(auth: A) -> Self {
        Self {
            state: State::Greeting,
            our_greeting_sent: false,
            peer_greeting_received: false,
            peer_version_minor: 0,
            our_ready_sent: false,
            our_welcome_sent: false,
            mechanism: Mechanism::Plain,
            greeting_buf: [0u8; 64],
            greeting_pos: 0,
            frame_decoder: FrameDecoder::new(),
            group_table: GroupTable::new(),
            pending_pong: None,
            auth,
        }
    }
}

impl<const GROUP_CAP: usize, const GROUP_LEN_CAP: usize, const FRAME_CAP: usize, A: AuthCheck>
    RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP, A>
{
    /// Current handshake [`State`] of the connection.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Returns the peer's ZMTP version as (major, minor).
    #[must_use]
    pub fn peer_version(&self) -> (u8, u8) {
        (3, self.peer_version_minor)
    }

    /// Write our full 64-byte greeting into `out`. Call once after creating the connection.
    /// Returns `Ok(GREETING_LEN)` or Err if not in Greeting state or buf too small.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Greeting` state or already sent.
    /// Returns `ConnError::BufferTooSmall` if `out` is smaller than `GREETING_LEN`.
    pub fn write_greeting(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        if self.state != State::Greeting || self.our_greeting_sent {
            return Err(ConnError::WrongState);
        }
        if out.len() < GREETING_LEN {
            return Err(ConnError::BufferTooSmall);
        }
        let mut arr = [0u8; GREETING_LEN];
        match self.mechanism {
            Mechanism::Null => encode_greeting(&mut arr),
            #[cfg(feature = "plain")]
            Mechanism::Plain => encode_plain_greeting(&mut arr),
        }
        out[..GREETING_LEN].copy_from_slice(&arr);
        self.our_greeting_sent = true;
        Ok(GREETING_LEN)
    }

    /// Write our RADIO READY command into `out`. Call after receiving a valid peer greeting.
    /// For PLAIN, `write_welcome` must be called first.
    /// Returns `Ok(RADIO_READY_LEN)` or Err.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Ready` state (or `PlainReady` for PLAIN).
    /// Returns `ConnError::BufferTooSmall` if `out` is smaller than `RADIO_READY_LEN`.
    pub fn write_ready(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        let in_ready_state = match self.mechanism {
            Mechanism::Null => self.state == State::Ready,
            #[cfg(feature = "plain")]
            Mechanism::Plain => {
                self.state == State::Ready
                    || (self.state == State::PlainReady && self.our_welcome_sent)
            }
        };
        if !in_ready_state {
            return Err(ConnError::WrongState);
        }
        if self.our_ready_sent {
            return Err(ConnError::WrongState);
        }
        if out.len() < RADIO_READY_LEN {
            return Err(ConnError::BufferTooSmall);
        }
        encode_ready_radio(out).map_err(ConnError::NullError)?;
        self.our_ready_sent = true;
        Ok(RADIO_READY_LEN)
    }

    /// Feed incoming bytes from the peer into the connection.
    /// Drives the handshake and, once established, processes incoming group frames.
    /// Returns Ok(consumed) — may be less than `input.len()` if a frame boundary was hit.
    ///
    /// # Errors
    /// Returns `ConnError::GreetingError` if the peer greeting is invalid.
    /// Returns `ConnError::NullError` if the READY/ERROR handshake fails.
    /// Returns `ConnError::PlainError` if PLAIN authentication fails.
    /// Returns `ConnError::DecodeError` if an inbound frame is malformed.
    /// Returns `ConnError::WrongState` if the connection is in `Failed` state.
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        match self.state {
            State::Greeting => self.feed_greeting(input),
            State::Ready => self.feed_ready(input),
            #[cfg(feature = "plain")]
            State::PlainHello => self.feed_plain_hello(input),
            #[cfg(feature = "plain")]
            State::PlainReady => self.feed_plain_ready(input),
            State::Established => self.feed_established(input),
            State::Failed => Err(ConnError::WrongState),
        }
    }

    fn feed_greeting(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        let needed = GREETING_LEN - self.greeting_pos;
        let to_copy = input.len().min(needed);
        let prev_pos = self.greeting_pos;
        self.greeting_buf[self.greeting_pos..self.greeting_pos + to_copy]
            .copy_from_slice(&input[..to_copy]);
        self.greeting_pos += to_copy;

        if prev_pos < GREETING_PARTIAL_LEN && self.greeting_pos >= GREETING_PARTIAL_LEN {
            let partial: &[u8; GREETING_PARTIAL_LEN] = self.greeting_buf[..GREETING_PARTIAL_LEN]
                .try_into()
                .unwrap();
            parse_partial_greeting(partial).map_err(ConnError::GreetingError)?;
        }

        if self.greeting_pos == GREETING_LEN {
            let peer_greeting = match self.mechanism {
                Mechanism::Null => {
                    parse_greeting(&self.greeting_buf).map_err(ConnError::GreetingError)?
                }
                #[cfg(feature = "plain")]
                Mechanism::Plain => {
                    parse_plain_greeting(&self.greeting_buf).map_err(ConnError::GreetingError)?
                }
            };
            self.peer_version_minor = peer_greeting.version_minor;
            self.peer_greeting_received = true;
            if self.our_greeting_sent {
                self.state = match self.mechanism {
                    Mechanism::Null => State::Ready,
                    #[cfg(feature = "plain")]
                    Mechanism::Plain => State::PlainHello,
                };
            }
        }

        Ok(to_copy)
    }

    fn feed_ready(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        if !self.our_ready_sent {
            return Err(ConnError::WrongState);
        }
        self.feed_ready_inner(input)
    }

    /// Shared logic for processing a peer READY command frame (NULL and PLAIN).
    fn feed_ready_inner(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        let (consumed, maybe_frame) = self
            .frame_decoder
            .feed(input)
            .map_err(ConnError::DecodeError)?;

        if let Some(frame) = maybe_frame {
            let body = frame.body;
            if body.len() > 255 {
                self.state = State::Failed;
                return Err(ConnError::NullError(NullError::MalformedMetadata));
            }

            match parse_ready_radio_from(frame.is_command, body) {
                Ok(_) => {
                    self.state = State::Established;
                }
                Err(e) => {
                    self.state = State::Failed;
                    return Err(ConnError::NullError(e));
                }
            }
        }

        Ok(consumed)
    }

    fn feed_established(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        let (consumed, maybe_frame) = self
            .frame_decoder
            .feed(input)
            .map_err(ConnError::DecodeError)?;

        if let Some(frame) = maybe_frame {
            let body = frame.body;
            if frame.is_command {
                // ZMTP 3.1 command: [name_len: 1][name: name_len bytes][payload...]
                if body.is_empty() {
                    return Ok(consumed);
                }
                let name_len = body[0] as usize;
                if body.len() < 1 + name_len {
                    return Ok(consumed);
                }
                let name = &body[1..=name_len];
                let payload = &body[1 + name_len..];

                if name == b"JOIN" {
                    // JOIN is best-effort per ZMTP spec; ignore TableFull/GroupTooLong.
                    let _ = self.group_table.join(payload);
                } else if name == b"LEAVE" {
                    self.group_table.leave(payload);
                } else if name == b"PING" && self.peer_version_minor >= 1 {
                    let ctx_bytes = payload.get(2..).unwrap_or(&[]);
                    let ctx_len = ctx_bytes.len().min(16);
                    let mut ctx = [0u8; 16];
                    ctx[..ctx_len].copy_from_slice(&ctx_bytes[..ctx_len]);
                    self.pending_pong = Some((ctx, ctx_len));
                }
            }
            // RADIO does not accept ZMTP 3.0-style subscription messages (0x01/0x00).
        }

        Ok(consumed)
    }

    /// Encode the two ZMTP frame headers for a publish, after checking group membership.
    /// Returns `Ok(None)` if no peer has joined `group`; `Ok(Some(...))` otherwise.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub fn publish_headers(
        &mut self,
        group: &[u8],
        body: &[u8],
    ) -> Result<Option<PublishHeaders>, ConnError> {
        if self.state != State::Established {
            return Err(ConnError::WrongState);
        }
        if !self.group_table.matches(group) {
            return Ok(None);
        }
        let mut gh = [0u8; MAX_FRAME_HEADER];
        let gh_n =
            encode_message_frame(&mut gh, group.len(), true).map_err(ConnError::FrameError)?;
        let mut bh = [0u8; MAX_FRAME_HEADER];
        let bh_n =
            encode_message_frame(&mut bh, body.len(), false).map_err(ConnError::FrameError)?;
        Ok(Some((gh, gh_n, bh, bh_n)))
    }

    /// Publish a message to the peer. Only valid in Established state.
    /// Encodes a multipart message (MORE frame for group, LAST frame for body).
    /// Returns Ok(0) if the peer has not joined `group`.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::BufferTooSmall` if `out` cannot hold the encoded message.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub fn publish(
        &mut self,
        group: &[u8],
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ConnError> {
        let Some((gh, gh_n, bh, bh_n)) = self.publish_headers(group, body)? else {
            return Ok(0);
        };
        let total = gh_n + group.len() + bh_n + body.len();
        if out.len() < total {
            return Err(ConnError::BufferTooSmall);
        }
        let mut written = 0;
        out[written..written + gh_n].copy_from_slice(&gh[..gh_n]);
        written += gh_n;
        out[written..written + group.len()].copy_from_slice(group);
        written += group.len();
        out[written..written + bh_n].copy_from_slice(&bh[..bh_n]);
        written += bh_n;
        out[written..written + body.len()].copy_from_slice(body);
        written += body.len();
        Ok(written)
    }

    /// Encode an ERROR command into `out`. Can be called after transitioning to Failed.
    ///
    /// # Errors
    /// Returns `ConnError::NullError` if the ERROR frame cannot be encoded.
    pub fn write_error(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        encode_error(out, b"Invalid socket type").map_err(ConnError::NullError)
    }

    /// Encode and clear a pending PONG command (queued by a received PING).
    /// Returns `Ok(None)` when no PONG is pending, `Ok(Some(n))` on success.
    ///
    /// # Errors
    /// Returns `ConnError::BufferTooSmall` if `out` cannot hold the encoded PONG frame.
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_pong(&mut self, out: &mut [u8]) -> Result<Option<usize>, ConnError> {
        let Some((ctx, ctx_len)) = self.pending_pong else {
            return Ok(None);
        };
        let body_len = 1 + 4 + ctx_len;
        let total = 2 + body_len;
        if out.len() < total {
            return Err(ConnError::BufferTooSmall);
        }
        self.pending_pong = None;
        out[0] = 0x04; // COMMAND, SHORT, MORE=0
        out[1] = body_len as u8;
        out[2] = 4; // name-size "PONG"
        out[3..7].copy_from_slice(b"PONG");
        out[7..7 + ctx_len].copy_from_slice(&ctx[..ctx_len]);
        Ok(Some(total))
    }

    /// Encode a WELCOME command into `out`. Must be called after `feed` transitions to
    /// `PlainReady`, and before `write_ready`.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `PlainReady` state or already sent.
    /// Returns `ConnError::PlainError` if the WELCOME frame cannot be encoded.
    #[cfg(feature = "plain")]
    pub fn write_welcome(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        if self.state != State::PlainReady || self.our_welcome_sent {
            return Err(ConnError::WrongState);
        }
        encode_welcome(out).map_err(ConnError::PlainError)?;
        self.our_welcome_sent = true;
        Ok(WELCOME_LEN)
    }

    #[cfg(feature = "plain")]
    fn feed_plain_hello(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        let (consumed, maybe_frame) = self
            .frame_decoder
            .feed(input)
            .map_err(ConnError::DecodeError)?;

        if let Some(frame) = maybe_frame {
            let body = frame.body;
            match parse_hello_from(frame.is_command, body) {
                Ok((username, password)) => {
                    if self.auth.check(username, password) {
                        self.state = State::PlainReady;
                    } else {
                        self.state = State::Failed;
                        return Err(ConnError::PlainError(PlainError::AuthFailed));
                    }
                }
                Err(e) => {
                    self.state = State::Failed;
                    return Err(ConnError::PlainError(e));
                }
            }
        }
        Ok(consumed)
    }

    #[cfg(feature = "plain")]
    fn feed_plain_ready(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        if !self.our_welcome_sent || !self.our_ready_sent {
            return Err(ConnError::WrongState);
        }
        self.feed_ready_inner(input)
    }
}

/// Errors returned by [`RadioConnection`] operations.
#[derive(Debug, PartialEq)]
pub enum ConnError {
    /// Operation is not valid in the current [`State`].
    WrongState,
    /// Caller-provided output buffer is too small for the encoded frame.
    BufferTooSmall,
    /// Transport I/O error. The payload is `embedded_io::ErrorKind as usize`.
    IoError(usize),
    /// Peer greeting was malformed or unsupported.
    GreetingError(GreetingError),
    /// NULL mechanism error (READY/ERROR handshake).
    NullError(NullError),
    /// PLAIN mechanism error (HELLO/WELCOME handshake).
    #[cfg(feature = "plain")]
    PlainError(PlainError),
    /// Outbound frame could not be encoded.
    FrameError(FrameError),
    /// Inbound frame could not be decoded.
    DecodeError(DecodeError),
}

impl ConnError {
    /// Returns `true` if the error originated from the transport.
    #[must_use]
    pub fn is_io_error(&self) -> bool {
        matches!(self, ConnError::IoError(_))
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::null::{NullError, RADIO_READY_LEN};
    use crate::test_helpers::{dish_greeting, dish_ready};

    // SUB READY frame (should be rejected by RADIO)
    fn sub_ready() -> [u8; 27] {
        [
            0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x53, 0x55, 0x42,
        ]
    }

    // Perform a full RADIO/DISH handshake
    fn do_handshake(conn: &mut RadioConnection<8, 32, 512>) {
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&dish_greeting()).unwrap();
        let mut ready_out = [0u8; 32];
        conn.write_ready(&mut ready_out).unwrap();
        conn.feed(&dish_ready()).unwrap();
    }

    // Build a ZMTP 3.1 JOIN command frame
    fn build_join_frame(group: &[u8]) -> heapless::Vec<u8, 64> {
        let name = b"JOIN";
        let body_len = 1 + name.len() + group.len();
        let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
        frame.push(0x04).unwrap();
        frame.push(body_len as u8).unwrap();
        frame.push(name.len() as u8).unwrap();
        frame.extend_from_slice(name).unwrap();
        frame.extend_from_slice(group).unwrap();
        frame
    }

    // Build a ZMTP 3.1 LEAVE command frame
    fn build_leave_frame(group: &[u8]) -> heapless::Vec<u8, 64> {
        let name = b"LEAVE";
        let body_len = 1 + name.len() + group.len();
        let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
        frame.push(0x04).unwrap();
        frame.push(body_len as u8).unwrap();
        frame.push(name.len() as u8).unwrap();
        frame.extend_from_slice(name).unwrap();
        frame.extend_from_slice(group).unwrap();
        frame
    }

    // Test 1: initial state is Greeting
    #[test]
    fn initial_state_is_greeting() {
        let conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        assert_eq!(conn.state(), &State::Greeting);
    }

    // Test 2: write_greeting writes 64 bytes (full greeting)
    #[test]
    fn write_greeting_succeeds() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut out = [0u8; 64];
        let n = conn.write_greeting(&mut out).unwrap();
        assert_eq!(n, GREETING_LEN);
        assert_eq!(out[0], 0xFF);
        assert_eq!(out[9], 0x7F);
        assert_eq!(out[10], 0x03);
    }

    // Test 3: calling write_greeting twice returns WrongState
    #[test]
    fn write_greeting_wrong_state_fails() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        let result = conn.write_greeting(&mut out);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 4: feed(DISH_GREETING) after write_greeting advances to Ready
    #[test]
    fn feed_peer_greeting_advances_to_ready() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&dish_greeting()).unwrap();
        assert_eq!(conn.state(), &State::Ready);
    }

    // Test 5: write_ready after greeting returns Ok(RADIO_READY_LEN)
    #[test]
    fn write_ready_after_greeting_succeeds() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&dish_greeting()).unwrap();
        let mut ready_out = [0u8; 32];
        let n = conn.write_ready(&mut ready_out).unwrap();
        assert_eq!(n, RADIO_READY_LEN);
    }

    // Test 6: full handshake -> state == Established
    #[test]
    fn feed_dish_ready_advances_to_established() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        do_handshake(&mut conn);
        assert_eq!(conn.state(), &State::Established);
    }

    // Test 7: feed a SUB READY -> WrongSocketType error, state == Failed
    #[test]
    fn feed_sub_ready_returns_wrong_socket_type() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&dish_greeting()).unwrap();
        let mut ready_out = [0u8; 32];
        conn.write_ready(&mut ready_out).unwrap();
        let result = conn.feed(&sub_ready());
        assert_eq!(
            result,
            Err(ConnError::NullError(NullError::WrongSocketType))
        );
        assert_eq!(conn.state(), &State::Failed);
    }

    // Test 8: publish without group membership returns Ok(0)
    #[test]
    fn publish_without_membership_returns_zero() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        do_handshake(&mut conn);
        let mut buf = [0u8; 256];
        let n = conn.publish(b"foo", b"bar", &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    // Test 9: publish after JOIN command writes wire bytes
    #[test]
    fn publish_with_matching_group_writes_frames() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        do_handshake(&mut conn);

        let join_frame = build_join_frame(b"foo");
        conn.feed(join_frame.as_slice()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.publish(b"foo", b"bar", &mut buf).unwrap();
        assert!(n > 0);

        // Verify wire format
        assert_eq!(buf[0], 0x01); // MORE flag
        assert_eq!(buf[1], 0x03); // group length = 3
        assert_eq!(&buf[2..5], b"foo");
        assert_eq!(buf[5], 0x00); // no MORE flag
        assert_eq!(buf[6], 0x03); // body length = 3
        assert_eq!(&buf[7..10], b"bar");
        assert_eq!(n, 10);
    }

    // Test 10: publish requires exact match (no prefix matching)
    #[test]
    fn publish_requires_exact_match() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        do_handshake(&mut conn);

        let join_frame = build_join_frame(b"foo");
        conn.feed(join_frame.as_slice()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.publish(b"foobar", b"payload", &mut buf).unwrap();
        assert_eq!(n, 0);

        let n = conn.publish(b"foo", b"payload", &mut buf).unwrap();
        assert!(n > 0);
    }

    // Test 11: LEAVE removes group membership
    #[test]
    fn leave_removes_membership() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        do_handshake(&mut conn);

        let join_frame = build_join_frame(b"foo");
        conn.feed(join_frame.as_slice()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.publish(b"foo", b"x", &mut buf).unwrap();
        assert!(n > 0);

        let leave_frame = build_leave_frame(b"foo");
        conn.feed(leave_frame.as_slice()).unwrap();

        let n = conn.publish(b"foo", b"x", &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    // Test 12: publish in wrong state (Greeting) returns WrongState
    #[test]
    fn publish_in_wrong_state_fails() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut buf = [0u8; 256];
        let result = conn.publish(b"foo", b"bar", &mut buf);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 13: PING command queues a PONG with the echoed context
    #[test]
    fn ping_command_queues_pong_with_context() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        do_handshake(&mut conn);

        let ping: &[u8] = &[
            0x04, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        conn.feed(ping).unwrap();

        let mut pong_buf = [0u8; 23];
        let n = conn
            .write_pong(&mut pong_buf)
            .unwrap()
            .expect("pong pending");
        assert_eq!(n, 9);
        assert_eq!(pong_buf[0], 0x04); // COMMAND
        assert_eq!(pong_buf[1], 7); // body len
        assert_eq!(pong_buf[2], 4); // name-size "PONG"
        assert_eq!(&pong_buf[3..7], b"PONG");
        assert_eq!(&pong_buf[7..9], b"hi");
        assert_eq!(conn.write_pong(&mut pong_buf).unwrap(), None);
    }

    // Test 14: write_error after Failed state returns a valid ERROR frame
    #[test]
    fn write_error_returns_error_frame() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&dish_greeting()).unwrap();
        let mut ready_out = [0u8; 32];
        conn.write_ready(&mut ready_out).unwrap();
        let _ = conn.feed(&sub_ready());
        assert_eq!(conn.state(), &State::Failed);

        let mut err_out = [0u8; 64];
        let n = conn.write_error(&mut err_out).unwrap();
        assert!(n > 0);
        assert_eq!(err_out[0], 0x04);
        assert_eq!(&err_out[3..8], b"ERROR");
    }

    // Test 15: peer_version returns (3, 1) after handshake with 3.1 peer
    #[test]
    fn peer_version_returns_3_1() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        assert_eq!(conn.peer_version(), (3, 0));

        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&dish_greeting()).unwrap();
        assert_eq!(conn.peer_version(), (3, 1));
    }

    // Test 16: calling write_greeting twice fails
    #[test]
    fn write_greeting_twice_fails() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        let result = conn.write_greeting(&mut out);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 17: write_greeting produces the canonical 64-byte greeting
    #[test]
    fn write_greeting_matches_encode_greeting() {
        let mut conn: RadioConnection<8, 32, 512> = RadioConnection::new();
        let mut combined = [0u8; GREETING_LEN];
        let n = conn.write_greeting(&mut combined).unwrap();
        assert_eq!(n, GREETING_LEN);

        let mut expected = [0u8; GREETING_LEN];
        encode_greeting(&mut expected);
        assert_eq!(combined, expected);
    }

    // ---------------------------------------------------------------------------
    // PLAIN mechanism tests
    // ---------------------------------------------------------------------------

    #[cfg(feature = "plain")]
    mod plain_tests {
        use super::*;
        use crate::greeting::{GREETING_LEN, encode_plain_greeting};
        use crate::plain::{Authenticator, WELCOME_LEN};

        struct AcceptAll;
        impl Authenticator for AcceptAll {
            fn authenticate(&self, _username: &[u8], _password: &[u8]) -> bool {
                true
            }
        }

        struct RejectAll;
        impl Authenticator for RejectAll {
            fn authenticate(&self, _username: &[u8], _password: &[u8]) -> bool {
                false
            }
        }

        struct RequireCredentials {
            user: &'static [u8],
            pass: &'static [u8],
        }
        impl Authenticator for RequireCredentials {
            fn authenticate(&self, username: &[u8], password: &[u8]) -> bool {
                username == self.user && password == self.pass
            }
        }

        fn plain_dish_greeting() -> [u8; GREETING_LEN] {
            let mut g = [0u8; GREETING_LEN];
            g[0] = 0xFF;
            g[9] = 0x7F;
            g[10] = 0x03;
            g[11] = 0x01;
            g[12] = b'P';
            g[13] = b'L';
            g[14] = b'A';
            g[15] = b'I';
            g[16] = b'N';
            // as_server = 0 (client role)
            g
        }

        fn hello_frame(username: &[u8], password: &[u8]) -> heapless::Vec<u8, 64> {
            let body_len: u8 = (1 + 5 + 1 + username.len() + 1 + password.len()) as u8;
            let mut f: heapless::Vec<u8, 64> = heapless::Vec::new();
            f.push(0x04).unwrap(); // COMMAND flag
            f.push(body_len).unwrap();
            f.push(5).unwrap(); // name_len
            f.extend_from_slice(b"HELLO").unwrap();
            f.push(username.len() as u8).unwrap();
            f.extend_from_slice(username).unwrap();
            f.push(password.len() as u8).unwrap();
            f.extend_from_slice(password).unwrap();
            f
        }

        fn do_plain_handshake(conn: &mut RadioConnection<8, 32, 512, AcceptAll>) {
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_dish_greeting()).unwrap();
            let hello = hello_frame(b"user", b"pass");
            conn.feed(hello.as_slice()).unwrap();
            let mut welcome_buf = [0u8; 16];
            conn.write_welcome(&mut welcome_buf).unwrap();
            let mut ready_out = [0u8; 32];
            conn.write_ready(&mut ready_out).unwrap();
            conn.feed(&dish_ready()).unwrap();
        }

        // Test RP1: write_greeting for PLAIN encodes "PLAIN" and as_server=1
        #[test]
        fn plain_write_greeting_uses_plain_greeting() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            let mut combined = [0u8; GREETING_LEN];
            let n = conn.write_greeting(&mut combined).unwrap();
            assert_eq!(n, GREETING_LEN);

            let mut expected = [0u8; GREETING_LEN];
            encode_plain_greeting(&mut expected);
            assert_eq!(combined, expected);
        }

        // Test RP2: after greeting exchange, state advances to PlainHello (not Ready)
        #[test]
        fn plain_greeting_exchange_transitions_to_plain_hello() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_dish_greeting()).unwrap();
            assert_eq!(conn.state(), &State::PlainHello);
        }

        // Test RP3: feeding valid HELLO with correct credentials transitions to PlainReady
        #[test]
        fn plain_valid_hello_transitions_to_plain_ready() {
            let mut conn: RadioConnection<8, 32, 512, RequireCredentials> =
                RadioConnection::new_plain(RequireCredentials {
                    user: b"alice",
                    pass: b"secret",
                });
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_dish_greeting()).unwrap();

            let hello = hello_frame(b"alice", b"secret");
            conn.feed(hello.as_slice()).unwrap();
            assert_eq!(conn.state(), &State::PlainReady);
        }

        // Test RP4: wrong credentials transition to Failed and return AuthFailed
        #[test]
        fn plain_wrong_credentials_returns_auth_failed() {
            let mut conn: RadioConnection<8, 32, 512, RejectAll> =
                RadioConnection::new_plain(RejectAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_dish_greeting()).unwrap();

            let hello = hello_frame(b"user", b"wrong");
            let result = conn.feed(hello.as_slice());
            assert_eq!(
                result,
                Err(ConnError::PlainError(crate::plain::PlainError::AuthFailed))
            );
            assert_eq!(conn.state(), &State::Failed);
        }

        // Test RP5: write_welcome in PlainReady state writes a 10-byte WELCOME frame
        #[test]
        fn plain_write_welcome_writes_correct_frame() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_dish_greeting()).unwrap();
            let hello = hello_frame(b"u", b"p");
            conn.feed(hello.as_slice()).unwrap();

            let mut welcome_buf = [0u8; 16];
            let n = conn.write_welcome(&mut welcome_buf).unwrap();
            assert_eq!(n, WELCOME_LEN);
            assert_eq!(welcome_buf[0], 0x04);
            assert_eq!(welcome_buf[1], 0x08);
            assert_eq!(&welcome_buf[3..10], b"WELCOME");
        }

        // Test RP6: full PLAIN handshake reaches Established
        #[test]
        fn plain_full_handshake_reaches_established() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            do_plain_handshake(&mut conn);
            assert_eq!(conn.state(), &State::Established);
        }

        // Test RP7: write_ready before write_welcome returns WrongState
        #[test]
        fn plain_write_ready_before_welcome_fails() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_dish_greeting()).unwrap();
            let hello = hello_frame(b"u", b"p");
            conn.feed(hello.as_slice()).unwrap();
            assert_eq!(conn.state(), &State::PlainReady);

            let mut ready_out = [0u8; 32];
            assert_eq!(conn.write_ready(&mut ready_out), Err(ConnError::WrongState));
        }

        // Test RP8: write_welcome in wrong state returns WrongState
        #[test]
        fn plain_write_welcome_in_wrong_state_fails() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            let mut out = [0u8; 16];
            assert_eq!(conn.write_welcome(&mut out), Err(ConnError::WrongState));
        }

        // Test RP9: PLAIN connection rejects peer greeting with NULL mechanism
        #[test]
        fn plain_rejects_null_peer_greeting() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            let result = conn.feed(&dish_greeting()); // NULL greeting
            assert!(result.is_err());
        }

        // Test RP10: after PLAIN handshake, publish works normally
        #[test]
        fn plain_publish_after_handshake_works() {
            let mut conn: RadioConnection<8, 32, 512, AcceptAll> =
                RadioConnection::new_plain(AcceptAll);
            do_plain_handshake(&mut conn);

            let join_frame = {
                let name = b"JOIN";
                let body_len = 1 + name.len();
                let mut f: heapless::Vec<u8, 32> = heapless::Vec::new();
                f.push(0x04).unwrap();
                f.push(body_len as u8).unwrap();
                f.push(name.len() as u8).unwrap();
                f.extend_from_slice(name).unwrap();
                f
            };
            conn.feed(join_frame.as_slice()).unwrap();

            let mut buf = [0u8; 256];
            let n = conn.publish(b"", b"hello", &mut buf).unwrap();
            assert!(n > 0);
        }
    }
}
