use crate::frame::decode_error::DecodeError;
use crate::frame::{FrameDecoder, FrameError, MAX_FRAME_HEADER, encode_message_frame};
use crate::greeting::{
    GREETING_LEN, GREETING_PARTIAL_LEN, GreetingError, encode_greeting, parse_greeting,
    parse_partial_greeting,
};
#[cfg(feature = "plain")]
use crate::greeting::{encode_plain_greeting, parse_plain_greeting};
use crate::null::{NullError, READY_LEN, encode_error, encode_ready, parse_ready_from};
use crate::plain::AuthCheck;
#[cfg(feature = "plain")]
use crate::plain::{PlainError, WELCOME_LEN, encode_welcome, parse_hello_from};
use crate::sub_table::SubTable;

/// Headers returned by [`Connection::publish_headers`]:
/// `(topic_hdr, topic_hdr_len, payload_hdr, payload_hdr_len)`.
pub type PublishHeaders = ([u8; MAX_FRAME_HEADER], usize, [u8; MAX_FRAME_HEADER], usize);

/// State of the connection.
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

/// Sans-IO ZMTP 3.1 PUB connection.
/// `SUB_CAP` = max simultaneous subscriptions per peer.
/// `PREFIX_CAP` = max bytes per subscription prefix.
/// `FRAME_CAP` = max body bytes buffered in the internal frame decoder.
/// `A` = authenticator type; use the default `()` for the NULL mechanism,
///       or supply an [`Authenticator`](crate::plain::Authenticator) and construct via
///       [`Connection::new_plain`] for the PLAIN mechanism (requires the `plain` feature).
#[allow(clippy::struct_excessive_bools)]
pub struct Connection<
    const SUB_CAP: usize,
    const PREFIX_CAP: usize,
    const FRAME_CAP: usize,
    A: AuthCheck = (),
> {
    state: State,
    our_greeting_partial_sent: bool,
    our_greeting_sent: bool,
    peer_greeting_received: bool,
    peer_version_minor: u8,
    our_ready_sent: bool,
    #[cfg(feature = "plain")]
    our_welcome_sent: bool,
    #[cfg(feature = "plain")]
    is_plain: bool,
    greeting_buf: [u8; 64],
    greeting_pos: usize,
    frame_decoder: FrameDecoder<FRAME_CAP>,
    sub_table: SubTable<SUB_CAP, PREFIX_CAP>,
    pending_pong: Option<([u8; 16], usize)>,
    #[cfg(feature = "plain")]
    auth: A,
    #[cfg(not(feature = "plain"))]
    _auth: core::marker::PhantomData<A>,
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize>
    Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, ()>
{
    /// Create a new NULL-mechanism connection in the `Greeting` state.
    pub fn new() -> Self {
        Self {
            state: State::Greeting,
            our_greeting_partial_sent: false,
            our_greeting_sent: false,
            peer_greeting_received: false,
            peer_version_minor: 0,
            our_ready_sent: false,
            #[cfg(feature = "plain")]
            our_welcome_sent: false,
            #[cfg(feature = "plain")]
            is_plain: false,
            greeting_buf: [0u8; 64],
            greeting_pos: 0,
            frame_decoder: FrameDecoder::new(),
            sub_table: SubTable::new(),
            pending_pong: None,
            #[cfg(feature = "plain")]
            auth: (),
            #[cfg(not(feature = "plain"))]
            _auth: core::marker::PhantomData,
        }
    }
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize> Default
    for Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, ()>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "plain")]
impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, A>
    Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>
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
            our_greeting_partial_sent: false,
            our_greeting_sent: false,
            peer_greeting_received: false,
            peer_version_minor: 0,
            our_ready_sent: false,
            our_welcome_sent: false,
            is_plain: true,
            greeting_buf: [0u8; 64],
            greeting_pos: 0,
            frame_decoder: FrameDecoder::new(),
            sub_table: SubTable::new(),
            pending_pong: None,
            auth, // only compiled when plain feature is enabled
        }
    }
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, A: AuthCheck>
    Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>
{
    /// Current handshake [`State`] of the connection.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Returns the peer's ZMTP version as (major, minor).
    pub fn peer_version(&self) -> (u8, u8) {
        (3, self.peer_version_minor)
    }

    /// Write the first 11 bytes of our greeting (signature + version major) into `out`.
    /// Call once after creating the connection.
    /// Returns `Ok(GREETING_PARTIAL_LEN)` or Err if not in Greeting state or buf too small.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Greeting` state or already sent.
    /// Returns `ConnError::BufferTooSmall` if `out` is smaller than `GREETING_PARTIAL_LEN`.
    pub fn write_greeting(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        if self.state != State::Greeting || self.our_greeting_partial_sent {
            return Err(ConnError::WrongState);
        }
        if out.len() < GREETING_PARTIAL_LEN {
            return Err(ConnError::BufferTooSmall);
        }
        let mut arr = [0u8; GREETING_LEN];
        encode_greeting(&mut arr);
        out[..GREETING_PARTIAL_LEN].copy_from_slice(&arr[..GREETING_PARTIAL_LEN]);
        self.our_greeting_partial_sent = true;
        Ok(GREETING_PARTIAL_LEN)
    }

    /// Write the remaining 53 bytes of our greeting into `out`.
    /// Call after receiving the peer's partial greeting (11 bytes).
    /// If the peer's full greeting is already received, transitions state to Ready (NULL)
    /// or `PlainHello` (PLAIN).
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in the correct handshake state.
    /// Returns `ConnError::BufferTooSmall` if `out` is smaller than the remaining greeting bytes.
    pub fn write_greeting_rest(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        if self.state != State::Greeting
            || !self.our_greeting_partial_sent
            || self.our_greeting_sent
        {
            return Err(ConnError::WrongState);
        }
        let rest_len = GREETING_LEN - GREETING_PARTIAL_LEN;
        if out.len() < rest_len {
            return Err(ConnError::BufferTooSmall);
        }
        let mut arr = [0u8; GREETING_LEN];
        #[cfg(not(feature = "plain"))]
        encode_greeting(&mut arr);
        #[cfg(feature = "plain")]
        if self.is_plain {
            encode_plain_greeting(&mut arr);
        } else {
            encode_greeting(&mut arr);
        }
        out[..rest_len].copy_from_slice(&arr[GREETING_PARTIAL_LEN..]);
        self.our_greeting_sent = true;
        if self.peer_greeting_received {
            #[cfg(not(feature = "plain"))]
            {
                self.state = State::Ready;
            }
            #[cfg(feature = "plain")]
            {
                self.state = if self.is_plain {
                    State::PlainHello
                } else {
                    State::Ready
                };
            }
        }
        Ok(rest_len)
    }

    /// Returns `true` if we have sent our partial greeting, received the peer's partial greeting,
    /// but have not yet sent the remaining 53 bytes.
    pub fn greeting_rest_pending(&self) -> bool {
        self.state == State::Greeting
            && self.our_greeting_partial_sent
            && !self.our_greeting_sent
            && self.greeting_pos >= GREETING_PARTIAL_LEN
    }

    /// Write our READY command into `out`. Call after receiving a valid peer greeting.
    /// For PLAIN, `write_welcome` must be called first.
    /// Returns `Ok(READY_LEN)` or Err.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Ready` state (or `PlainReady` for PLAIN).
    /// Returns `ConnError::BufferTooSmall` if `out` is smaller than `READY_LEN`.
    pub fn write_ready(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        #[cfg(not(feature = "plain"))]
        let in_ready_state = self.state == State::Ready;
        #[cfg(feature = "plain")]
        let in_ready_state = self.state == State::Ready
            || (self.state == State::PlainReady && self.our_welcome_sent);
        if !in_ready_state {
            return Err(ConnError::WrongState);
        }
        if self.our_ready_sent {
            return Err(ConnError::WrongState);
        }
        if out.len() < READY_LEN {
            return Err(ConnError::BufferTooSmall);
        }
        encode_ready(out).map_err(ConnError::NullError)?;
        self.our_ready_sent = true;
        Ok(READY_LEN)
    }

    /// Feed incoming bytes from the peer into the connection.
    /// Drives the handshake and, once established, processes incoming subscription frames.
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
            #[cfg(not(feature = "plain"))]
            let peer_greeting =
                parse_greeting(&self.greeting_buf).map_err(ConnError::GreetingError)?;
            #[cfg(feature = "plain")]
            let peer_greeting = if self.is_plain {
                parse_plain_greeting(&self.greeting_buf).map_err(ConnError::GreetingError)?
            } else {
                parse_greeting(&self.greeting_buf).map_err(ConnError::GreetingError)?
            };
            self.peer_version_minor = peer_greeting.version_minor;
            self.peer_greeting_received = true;
            if self.our_greeting_sent {
                #[cfg(not(feature = "plain"))]
                {
                    self.state = State::Ready;
                }
                #[cfg(feature = "plain")]
                {
                    self.state = if self.is_plain {
                        State::PlainHello
                    } else {
                        State::Ready
                    };
                }
            }
        }

        Ok(to_copy)
    }

    fn feed_ready(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        if !self.our_ready_sent {
            return Err(ConnError::WrongState);
        }

        let (consumed, maybe_frame) = self
            .frame_decoder
            .feed(input)
            .map_err(ConnError::DecodeError)?;

        if let Some(frame) = maybe_frame {
            let body = frame.body;
            // RFC 23: handshake commands must be short frames (body ≤ 255 bytes).
            // Enforced here rather than via FRAME_CAP, which may be larger.
            if body.len() > 255 {
                self.state = State::Failed;
                return Err(ConnError::NullError(NullError::MalformedMetadata));
            }

            match parse_ready_from(frame.is_command, body) {
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

                if name == b"SUBSCRIBE" {
                    let _ = self.sub_table.subscribe(payload);
                } else if name == b"CANCEL" {
                    self.sub_table.cancel(payload);
                } else if name == b"PING" && self.peer_version_minor >= 1 {
                    // PING/PONG are ZMTP 3.1 features (RFC 37)
                    let ctx_bytes = payload.get(2..).unwrap_or(&[]);
                    let ctx_len = ctx_bytes.len().min(16);
                    let mut ctx = [0u8; 16];
                    ctx[..ctx_len].copy_from_slice(&ctx_bytes[..ctx_len]);
                    self.pending_pong = Some((ctx, ctx_len));
                }
            } else {
                // ZMTP 3.0 message-based subscription
                if body.is_empty() {
                    return Ok(consumed);
                }
                match body[0] {
                    0x01 => {
                        let _ = self.sub_table.subscribe(&body[1..]);
                    }
                    0x00 => {
                        self.sub_table.cancel(&body[1..]);
                    }
                    _ => {}
                }
            }
        }

        Ok(consumed)
    }

    /// Encode the two ZMTP frame headers for a publish, after checking subscriptions.
    /// Returns `Ok(None)` if no subscription matches; `Ok(Some(...))` with
    /// `(topic_hdr, th_len, payload_hdr, ph_len)` otherwise.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub fn publish_headers(
        &mut self,
        topic: &[u8],
        payload: &[u8],
    ) -> Result<Option<PublishHeaders>, ConnError> {
        if self.state != State::Established {
            return Err(ConnError::WrongState);
        }
        if !self.sub_table.matches(topic) {
            return Ok(None);
        }
        let mut th = [0u8; MAX_FRAME_HEADER];
        let th_n =
            encode_message_frame(&mut th, topic.len(), true).map_err(ConnError::FrameError)?;
        let mut ph = [0u8; MAX_FRAME_HEADER];
        let ph_n =
            encode_message_frame(&mut ph, payload.len(), false).map_err(ConnError::FrameError)?;
        Ok(Some((th, th_n, ph, ph_n)))
    }

    /// Publish a message to the peer. Only valid in Established state.
    /// Encodes a multipart message (MORE frame for topic, LAST frame for payload).
    /// Returns Ok(0) if the peer has no matching subscription.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::BufferTooSmall` if `out` cannot hold the encoded message.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub fn publish(
        &mut self,
        topic: &[u8],
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ConnError> {
        let Some((th, th_n, ph, ph_n)) = self.publish_headers(topic, payload)? else {
            return Ok(0);
        };
        let total = th_n + topic.len() + ph_n + payload.len();
        if out.len() < total {
            return Err(ConnError::BufferTooSmall);
        }
        let mut written = 0;
        out[written..written + th_n].copy_from_slice(&th[..th_n]);
        written += th_n;
        out[written..written + topic.len()].copy_from_slice(topic);
        written += topic.len();
        out[written..written + ph_n].copy_from_slice(&ph[..ph_n]);
        written += ph_n;
        out[written..written + payload.len()].copy_from_slice(payload);
        written += payload.len();
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
        // body = name-size(1) + "PONG"(4) + context(0-16) — always fits a short frame
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
            match parse_ready_from(frame.is_command, body) {
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
}

/// Errors returned by [`Connection`] operations.
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
    pub fn is_io_error(&self) -> bool {
        matches!(self, ConnError::IoError(_))
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::null::{NullError, READY_LEN};
    use crate::test_helpers::{sub_greeting, sub_ready};

    // PUSH READY frame (should be rejected)
    fn push_ready() -> [u8; 28] {
        [
            0x04, 0x1A, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x04, 0x50, 0x55, 0x53, 0x48,
        ]
    }

    // Perform a full handshake
    fn do_handshake(conn: &mut Connection<8, 32, 512>) {
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap();
        conn.write_greeting_rest(&mut out).unwrap();
        let mut ready_out = [0u8; 32];
        conn.write_ready(&mut ready_out).unwrap();
        conn.feed(&sub_ready()).unwrap();
    }

    // Build a ZMTP 3.1 SUBSCRIBE command frame
    fn build_subscribe_frame(prefix: &[u8]) -> heapless::Vec<u8, 64> {
        let name = b"SUBSCRIBE";
        let body_len = 1 + name.len() + prefix.len();
        let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
        frame.push(0x04).unwrap();
        frame.push(body_len as u8).unwrap();
        frame.push(name.len() as u8).unwrap();
        frame.extend_from_slice(name).unwrap();
        frame.extend_from_slice(prefix).unwrap();
        frame
    }

    // Build a ZMTP 3.0 subscribe message frame
    fn build_zmtp30_subscribe(prefix: &[u8]) -> heapless::Vec<u8, 64> {
        let body_len = 1 + prefix.len();
        let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
        frame.push(0x00).unwrap();
        frame.push(body_len as u8).unwrap();
        frame.push(0x01).unwrap();
        frame.extend_from_slice(prefix).unwrap();
        frame
    }

    // Build a ZMTP 3.0 cancel message frame
    fn build_zmtp30_cancel(prefix: &[u8]) -> heapless::Vec<u8, 64> {
        let body_len = 1 + prefix.len();
        let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
        frame.push(0x00).unwrap();
        frame.push(body_len as u8).unwrap();
        frame.push(0x00).unwrap();
        frame.extend_from_slice(prefix).unwrap();
        frame
    }

    // Test 1: initial state is Greeting
    #[test]
    fn initial_state_is_greeting() {
        let conn: Connection<8, 32, 512> = Connection::new();
        assert_eq!(conn.state(), &State::Greeting);
    }

    // Test 2: write_greeting writes 11 bytes (partial greeting)
    #[test]
    fn write_greeting_succeeds() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        let n = conn.write_greeting(&mut out).unwrap();
        assert_eq!(n, GREETING_PARTIAL_LEN);
        assert_eq!(out[0], 0xFF);
        assert_eq!(out[9], 0x7F);
        assert_eq!(out[10], 0x03);
        // The rest of the greeting should not have been written
        assert!(out[11..].iter().all(|&b| b == 0));
    }

    // Test 3: calling write_greeting twice returns WrongState
    #[test]
    fn write_greeting_wrong_state_fails() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        let result = conn.write_greeting(&mut out);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 4: feed(SUB_GREETING) after write_greeting + write_greeting_rest advances to Ready
    #[test]
    fn feed_peer_greeting_advances_to_ready() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap();
        assert_eq!(conn.state(), &State::Greeting); // still waiting for our greeting rest
        conn.write_greeting_rest(&mut out).unwrap();
        assert_eq!(conn.state(), &State::Ready);
    }

    // Test 5: write_ready after greeting returns Ok(27)
    #[test]
    fn write_ready_after_greeting_succeeds() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap();
        conn.write_greeting_rest(&mut out).unwrap();
        let mut ready_out = [0u8; 32];
        let n = conn.write_ready(&mut ready_out).unwrap();
        assert_eq!(n, READY_LEN);
    }

    // Test 6: full handshake → state == Established
    #[test]
    fn feed_sub_ready_advances_to_established() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);
        assert_eq!(conn.state(), &State::Established);
    }

    // Test 7: feed a PUSH READY → WrongSocketType error, state == Failed
    #[test]
    fn feed_push_ready_returns_wrong_socket_type() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap();
        conn.write_greeting_rest(&mut out).unwrap();
        let mut ready_out = [0u8; 32];
        conn.write_ready(&mut ready_out).unwrap();
        let result = conn.feed(&push_ready());
        assert_eq!(
            result,
            Err(ConnError::NullError(NullError::WrongSocketType))
        );
        assert_eq!(conn.state(), &State::Failed);
    }

    // Test 8: publish without subscription returns Ok(0)
    #[test]
    fn publish_without_subscription_returns_zero() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);
        let mut buf = [0u8; 256];
        let n = conn.publish(b"foo", b"bar", &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    // Test 9: publish after SUBSCRIBE command writes wire bytes
    #[test]
    fn publish_with_matching_subscription_writes_frames() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);

        let sub_frame = build_subscribe_frame(b"foo");
        conn.feed(sub_frame.as_slice()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.publish(b"foo", b"bar", &mut buf).unwrap();
        assert!(n > 0);

        // Verify wire format
        assert_eq!(buf[0], 0x01); // MORE flag
        assert_eq!(buf[1], 0x03); // topic length = 3
        assert_eq!(&buf[2..5], b"foo");
        assert_eq!(buf[5], 0x00); // no MORE flag
        assert_eq!(buf[6], 0x03); // payload length = 3
        assert_eq!(&buf[7..10], b"bar");
        assert_eq!(n, 10);
    }

    // Test 10: publish filtered by prefix
    #[test]
    fn publish_filtered_by_prefix() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);

        let sub_frame = build_subscribe_frame(b"foo");
        conn.feed(sub_frame.as_slice()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.publish(b"bar", b"payload", &mut buf).unwrap();
        assert_eq!(n, 0);

        let n = conn.publish(b"fooX", b"payload", &mut buf).unwrap();
        assert!(n > 0);
    }

    // Test 11: ZMTP 3.0 subscribe message accepted
    #[test]
    fn zmtp_30_subscribe_message_accepted() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);

        let msg_frame = build_zmtp30_subscribe(b"foo");
        conn.feed(msg_frame.as_slice()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.publish(b"foo", b"data", &mut buf).unwrap();
        assert!(n > 0);
    }

    // Test 12: ZMTP 3.0 cancel removes subscription
    #[test]
    fn zmtp_30_cancel_message_accepted() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);

        let sub_frame = build_zmtp30_subscribe(b"foo");
        conn.feed(sub_frame.as_slice()).unwrap();

        let mut buf = [0u8; 256];
        let n = conn.publish(b"foo", b"x", &mut buf).unwrap();
        assert!(n > 0);

        let cancel_frame = build_zmtp30_cancel(b"foo");
        conn.feed(cancel_frame.as_slice()).unwrap();

        let n = conn.publish(b"foo", b"x", &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    // Test 13: publish in wrong state (Greeting) returns WrongState
    #[test]
    fn publish_in_wrong_state_fails() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut buf = [0u8; 256];
        let result = conn.publish(b"foo", b"bar", &mut buf);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 14: PING command queues a PONG with the echoed context
    #[test]
    fn ping_command_queues_pong_with_context() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);

        // PING: flags=0x04, body-size=0x09, name-size=0x04, "PING", ttl=0x00,0x00, ctx=b"hi"
        let ping: &[u8] = &[
            0x04, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        conn.feed(ping).unwrap();

        let mut pong_buf = [0u8; 23];
        let n = conn
            .write_pong(&mut pong_buf)
            .unwrap()
            .expect("pong pending");
        // body = name-size(1) + "PONG"(4) + "hi"(2) = 7
        assert_eq!(n, 9);
        assert_eq!(pong_buf[0], 0x04); // COMMAND
        assert_eq!(pong_buf[1], 7); // body len
        assert_eq!(pong_buf[2], 4); // name-size "PONG"
        assert_eq!(&pong_buf[3..7], b"PONG");
        assert_eq!(&pong_buf[7..9], b"hi");
        // second call returns None
        assert_eq!(conn.write_pong(&mut pong_buf).unwrap(), None);
    }

    // Test 15: write_error after Failed state returns a valid ERROR frame
    #[test]
    fn write_error_returns_error_frame() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap();
        conn.write_greeting_rest(&mut out).unwrap();
        let mut ready_out = [0u8; 32];
        conn.write_ready(&mut ready_out).unwrap();
        let _ = conn.feed(&push_ready());
        assert_eq!(conn.state(), &State::Failed);

        let mut err_out = [0u8; 64];
        let n = conn.write_error(&mut err_out).unwrap();
        assert!(n > 0);
        assert_eq!(err_out[0], 0x04);
        assert_eq!(&err_out[3..8], b"ERROR");
    }

    // Test 16: peer_version returns (3, 1) after handshake with 3.1 peer
    #[test]
    fn peer_version_returns_3_1() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        assert_eq!(conn.peer_version(), (3, 0)); // default before handshake

        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap(); // sub_greeting is 3.1
        assert_eq!(conn.peer_version(), (3, 1));
    }

    // Test 17: peer_version returns (3, 0) after handshake with 3.0 peer
    #[test]
    fn peer_version_returns_3_0() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();

        // Build a 3.0 greeting (version_minor = 0x00)
        let mut greeting_30 = sub_greeting();
        greeting_30[11] = 0x00; // ZMTP 3.0
        conn.feed(&greeting_30).unwrap();

        assert_eq!(conn.peer_version(), (3, 0));
    }

    // Test 18: PING from 3.0 peer is ignored (no pending_pong)
    #[test]
    fn ping_from_30_peer_ignored() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();

        // Feed 3.0 greeting
        let mut greeting_30 = sub_greeting();
        greeting_30[11] = 0x00;
        conn.feed(&greeting_30).unwrap();
        conn.write_greeting_rest(&mut out).unwrap();

        // Complete handshake
        let mut ready_out = [0u8; 32];
        conn.write_ready(&mut ready_out).unwrap();
        conn.feed(&sub_ready()).unwrap();
        assert_eq!(conn.state(), &State::Established);

        // Send PING - should be ignored for 3.0 peer
        let ping: &[u8] = &[
            0x04, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        conn.feed(ping).unwrap();

        // No PONG should be pending
        let mut pong_buf = [0u8; 23];
        assert_eq!(conn.write_pong(&mut pong_buf).unwrap(), None);
    }

    // Test 19: PING from 3.1 peer queues PONG
    #[test]
    fn ping_from_31_peer_queues_pong() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        do_handshake(&mut conn);
        assert_eq!(conn.peer_version(), (3, 1));

        let ping: &[u8] = &[
            0x04, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        conn.feed(ping).unwrap();

        let mut pong_buf = [0u8; 23];
        assert!(conn.write_pong(&mut pong_buf).unwrap().is_some());
    }

    // Test 20: write_greeting_rest writes remaining 53 bytes
    #[test]
    fn write_greeting_rest_succeeds() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        let n = conn.write_greeting_rest(&mut out).unwrap();
        assert_eq!(n, GREETING_LEN - GREETING_PARTIAL_LEN);
        assert_eq!(out[0], 0x01); // version minor
        assert_eq!(&out[1..5], b"NULL");
        assert!(out[5..].iter().all(|&b| b == 0));
    }

    // Test 21: calling write_greeting_rest before write_greeting fails
    #[test]
    fn write_greeting_rest_before_write_greeting_fails() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        let result = conn.write_greeting_rest(&mut out);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 22: calling write_greeting twice fails
    #[test]
    fn write_greeting_twice_fails() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        let result = conn.write_greeting(&mut out);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 23: calling write_greeting_rest twice fails
    #[test]
    fn write_greeting_rest_twice_fails() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.write_greeting_rest(&mut out).unwrap();
        let result = conn.write_greeting_rest(&mut out);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 24: greeting_rest_pending is true after receiving peer partial
    #[test]
    fn greeting_rest_pending_after_peer_partial() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        assert!(!conn.greeting_rest_pending());

        let partial = &sub_greeting()[..GREETING_PARTIAL_LEN];
        conn.feed(partial).unwrap();
        assert!(conn.greeting_rest_pending());

        conn.write_greeting_rest(&mut out).unwrap();
        assert!(!conn.greeting_rest_pending());
    }

    // Test 25: invalid signature in partial greeting fails fast
    #[test]
    fn feed_invalid_signature_in_partial_greeting_fails_fast() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();

        let mut partial = [0u8; GREETING_PARTIAL_LEN];
        partial[0] = 0xFE; // bad SIG0
        partial[9] = 0x7F;
        partial[10] = 0x03;
        let result = conn.feed(&partial);
        assert_eq!(
            result,
            Err(ConnError::GreetingError(GreetingError::InvalidSignature)),
        );
    }

    // Test 26: bad version major in partial greeting fails fast, split across two feeds
    #[test]
    fn feed_unsupported_version_major_in_partial_greeting_fails_fast() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();

        let mut g = [0u8; 64];
        g[0] = 0xFF;
        g[9] = 0x7F;
        g[10] = 0x02; // ZMTP 2.x

        conn.feed(&g[..5]).unwrap(); // before boundary — no check yet
        let result = conn.feed(&g[5..11]); // crosses boundary — check fires
        assert_eq!(
            result,
            Err(ConnError::GreetingError(
                GreetingError::UnsupportedVersionMajor
            )),
        );
    }

    // Test 27: partial check fires exactly once; valid greeting split at the boundary
    #[test]
    fn feed_partial_check_fires_only_once_across_multiple_calls() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();

        let g = sub_greeting();
        conn.feed(&g[..GREETING_PARTIAL_LEN]).unwrap();
        conn.feed(&g[GREETING_PARTIAL_LEN..]).unwrap();
        conn.write_greeting_rest(&mut out).unwrap();
        assert_eq!(conn.state(), &State::Ready);
    }

    // Test 28: write_greeting + write_greeting_rest produces the canonical 64-byte greeting
    #[test]
    fn write_greeting_concat_matches_encode_greeting() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut combined = [0u8; GREETING_LEN];
        let n1 = conn.write_greeting(&mut combined).unwrap();
        let n2 = conn.write_greeting_rest(&mut combined[n1..]).unwrap();
        assert_eq!(n1 + n2, GREETING_LEN);

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

        fn plain_client_greeting() -> [u8; GREETING_LEN] {
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
            f.push(body_len).unwrap(); // body size
            f.push(5).unwrap(); // name_len
            f.extend_from_slice(b"HELLO").unwrap();
            f.push(username.len() as u8).unwrap();
            f.extend_from_slice(username).unwrap();
            f.push(password.len() as u8).unwrap();
            f.extend_from_slice(password).unwrap();
            f
        }

        fn plain_sub_ready() -> [u8; 27] {
            sub_ready()
        }

        fn do_plain_handshake(conn: &mut Connection<8, 32, 512, AcceptAll>) {
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_client_greeting()).unwrap();
            conn.write_greeting_rest(&mut out).unwrap();
            let hello = hello_frame(b"user", b"pass");
            conn.feed(hello.as_slice()).unwrap();
            let mut welcome_buf = [0u8; 16];
            conn.write_welcome(&mut welcome_buf).unwrap();
            let mut ready_out = [0u8; 32];
            conn.write_ready(&mut ready_out).unwrap();
            conn.feed(&plain_sub_ready()).unwrap();
        }

        // Test P1: write_greeting_rest for PLAIN encodes "PLAIN" and as_server=1
        #[test]
        fn plain_write_greeting_rest_uses_plain_greeting() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            let mut combined = [0u8; GREETING_LEN];
            let n1 = conn.write_greeting(&mut combined).unwrap();
            let n2 = conn.write_greeting_rest(&mut combined[n1..]).unwrap();
            assert_eq!(n1 + n2, GREETING_LEN);

            let mut expected = [0u8; GREETING_LEN];
            encode_plain_greeting(&mut expected);
            assert_eq!(combined, expected);
        }

        // Test P2: after greeting exchange, state advances to PlainHello (not Ready)
        #[test]
        fn plain_greeting_exchange_transitions_to_plain_hello() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_client_greeting()).unwrap();
            conn.write_greeting_rest(&mut out).unwrap();
            assert_eq!(conn.state(), &State::PlainHello);
        }

        // Test P3: feeding valid HELLO with correct credentials transitions to PlainReady
        #[test]
        fn plain_valid_hello_transitions_to_plain_ready() {
            let mut conn: Connection<8, 32, 512, RequireCredentials> =
                Connection::new_plain(RequireCredentials {
                    user: b"alice",
                    pass: b"secret",
                });
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_client_greeting()).unwrap();
            conn.write_greeting_rest(&mut out).unwrap();

            let hello = hello_frame(b"alice", b"secret");
            conn.feed(hello.as_slice()).unwrap();
            assert_eq!(conn.state(), &State::PlainReady);
        }

        // Test P4: wrong credentials transition to Failed and return AuthFailed
        #[test]
        fn plain_wrong_credentials_returns_auth_failed() {
            let mut conn: Connection<8, 32, 512, RejectAll> = Connection::new_plain(RejectAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_client_greeting()).unwrap();
            conn.write_greeting_rest(&mut out).unwrap();

            let hello = hello_frame(b"user", b"wrong");
            let result = conn.feed(hello.as_slice());
            assert_eq!(
                result,
                Err(ConnError::PlainError(crate::plain::PlainError::AuthFailed))
            );
            assert_eq!(conn.state(), &State::Failed);
        }

        // Test P5: write_welcome in PlainReady state writes a 10-byte WELCOME frame
        #[test]
        fn plain_write_welcome_writes_correct_frame() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_client_greeting()).unwrap();
            conn.write_greeting_rest(&mut out).unwrap();
            let hello = hello_frame(b"u", b"p");
            conn.feed(hello.as_slice()).unwrap();

            let mut welcome_buf = [0u8; 16];
            let n = conn.write_welcome(&mut welcome_buf).unwrap();
            assert_eq!(n, WELCOME_LEN);
            assert_eq!(welcome_buf[0], 0x04);
            assert_eq!(welcome_buf[1], 0x08);
            assert_eq!(&welcome_buf[3..10], b"WELCOME");
        }

        // Test P6: full PLAIN handshake reaches Established
        #[test]
        fn plain_full_handshake_reaches_established() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            do_plain_handshake(&mut conn);
            assert_eq!(conn.state(), &State::Established);
        }

        // Test P7: write_ready before write_welcome returns WrongState
        #[test]
        fn plain_write_ready_before_welcome_fails() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            conn.feed(&plain_client_greeting()).unwrap();
            conn.write_greeting_rest(&mut out).unwrap();
            let hello = hello_frame(b"u", b"p");
            conn.feed(hello.as_slice()).unwrap();
            assert_eq!(conn.state(), &State::PlainReady);

            let mut ready_out = [0u8; 32];
            assert_eq!(conn.write_ready(&mut ready_out), Err(ConnError::WrongState));
        }

        // Test P8: write_welcome in wrong state returns WrongState
        #[test]
        fn plain_write_welcome_in_wrong_state_fails() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            let mut out = [0u8; 16];
            assert_eq!(conn.write_welcome(&mut out), Err(ConnError::WrongState));
        }

        // Test P9: PLAIN connection rejects peer greeting with NULL mechanism
        #[test]
        fn plain_rejects_null_peer_greeting() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            let mut out = [0u8; 64];
            conn.write_greeting(&mut out).unwrap();
            let result = conn.feed(&sub_greeting()); // NULL greeting
            assert!(result.is_err());
        }

        // Test P10: after PLAIN handshake, publish works normally
        #[test]
        fn plain_publish_after_handshake_works() {
            let mut conn: Connection<8, 32, 512, AcceptAll> = Connection::new_plain(AcceptAll);
            do_plain_handshake(&mut conn);

            let sub_frame = {
                let name = b"SUBSCRIBE";
                let body_len = 1 + name.len();
                let mut f: heapless::Vec<u8, 32> = heapless::Vec::new();
                f.push(0x04).unwrap();
                f.push(body_len as u8).unwrap();
                f.push(name.len() as u8).unwrap();
                f.extend_from_slice(name).unwrap();
                f
            };
            conn.feed(sub_frame.as_slice()).unwrap();

            let mut buf = [0u8; 256];
            let n = conn.publish(b"", b"hello", &mut buf).unwrap();
            assert!(n > 0);
        }
    }
}
