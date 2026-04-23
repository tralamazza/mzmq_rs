use crate::frame::decode_error::DecodeError;
use crate::frame::{FrameDecoder, FrameError, MAX_FRAME_HEADER, encode_message_frame};
use crate::greeting::{GREETING_LEN, GreetingError, encode_greeting, parse_greeting};
use crate::null::{NullError, READY_LEN, encode_error, encode_ready, parse_ready_from};
use crate::sub_table::SubTable;

/// Headers returned by [`Connection::publish_headers`]:
/// `(topic_hdr, topic_hdr_len, payload_hdr, payload_hdr_len)`.
pub type PublishHeaders = ([u8; MAX_FRAME_HEADER], usize, [u8; MAX_FRAME_HEADER], usize);

/// State of the connection.
#[derive(Debug, PartialEq)]
pub enum State {
    /// Waiting to send our greeting (or awaiting peer greeting bytes).
    Greeting,
    /// Greeting exchanged; awaiting READY command from peer.
    Ready,
    /// Handshake complete; can publish messages.
    Established,
    /// Unrecoverable error; connection must be dropped.
    Failed,
}

/// Sans-IO ZMTP 3.1 PUB connection.
/// `SUB_CAP` = max simultaneous subscriptions per peer.
/// `PREFIX_CAP` = max bytes per subscription prefix.
/// `FRAME_CAP` = max body bytes buffered in the internal frame decoder.
pub struct Connection<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize> {
    state: State,
    our_greeting_sent: bool,
    peer_greeting_received: bool,
    our_ready_sent: bool,
    greeting_buf: [u8; 64],
    greeting_pos: usize,
    frame_decoder: FrameDecoder<FRAME_CAP>,
    sub_table: SubTable<SUB_CAP, PREFIX_CAP>,
    pending_pong: Option<([u8; 16], usize)>,
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize>
    Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP>
{
    /// Create a new connection in the `Greeting` state.
    pub fn new() -> Self {
        Self {
            state: State::Greeting,
            our_greeting_sent: false,
            peer_greeting_received: false,
            our_ready_sent: false,
            greeting_buf: [0u8; 64],
            greeting_pos: 0,
            frame_decoder: FrameDecoder::new(),
            sub_table: SubTable::new(),
            pending_pong: None,
        }
    }

    /// Current handshake [`State`] of the connection.
    pub fn state(&self) -> &State {
        &self.state
    }
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize> Default
    for Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize>
    Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP>
{
    /// Write our greeting into `out`. Call once after creating the connection.
    /// Returns Ok(GREETING_LEN) or Err if not in Greeting state or buf too small.
    pub fn write_greeting(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        if self.state != State::Greeting || self.our_greeting_sent {
            return Err(ConnError::WrongState);
        }
        if out.len() < GREETING_LEN {
            return Err(ConnError::BufferTooSmall);
        }
        let mut arr = [0u8; GREETING_LEN];
        encode_greeting(&mut arr);
        out[..GREETING_LEN].copy_from_slice(&arr);
        self.our_greeting_sent = true;
        Ok(GREETING_LEN)
    }

    /// Write our READY command into `out`. Call after receiving a valid peer greeting.
    /// Returns Ok(READY_LEN) or Err.
    pub fn write_ready(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        if self.state != State::Ready {
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
    /// Returns Ok(consumed) — may be less than input.len() if a frame boundary was hit.
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        match self.state {
            State::Greeting => self.feed_greeting(input),
            State::Ready => self.feed_ready(input),
            State::Established => self.feed_established(input),
            State::Failed => Err(ConnError::WrongState),
        }
    }

    fn feed_greeting(&mut self, input: &[u8]) -> Result<usize, ConnError> {
        let needed = GREETING_LEN - self.greeting_pos;
        let to_copy = input.len().min(needed);
        self.greeting_buf[self.greeting_pos..self.greeting_pos + to_copy]
            .copy_from_slice(&input[..to_copy]);
        self.greeting_pos += to_copy;

        if self.greeting_pos == GREETING_LEN {
            let arr_ref: &[u8; 64] = &self.greeting_buf;
            parse_greeting(arr_ref).map_err(ConnError::GreetingError)?;
            self.peer_greeting_received = true;
            if self.our_greeting_sent && self.peer_greeting_received {
                self.state = State::Ready;
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
                let name = &body[1..1 + name_len];
                let payload = &body[1 + name_len..];

                if name == b"SUBSCRIBE" {
                    let _ = self.sub_table.subscribe(payload);
                } else if name == b"CANCEL" {
                    self.sub_table.cancel(payload);
                } else if name == b"PING" {
                    // payload = ping-ttl(2) + ping-context(0-16); echo context in PONG
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
    pub fn write_error(&mut self, out: &mut [u8]) -> Result<usize, ConnError> {
        encode_error(out, b"Invalid socket type").map_err(ConnError::NullError)
    }

    /// Encode and clear a pending PONG command (queued by a received PING).
    /// Returns `Ok(None)` when no PONG is pending, `Ok(Some(n))` on success.
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

    // Test 2: write_greeting writes 64 bytes
    #[test]
    fn write_greeting_succeeds() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
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
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        let result = conn.write_greeting(&mut out);
        assert_eq!(result, Err(ConnError::WrongState));
    }

    // Test 4: feed(SUB_GREETING) after write_greeting advances to Ready
    #[test]
    fn feed_peer_greeting_advances_to_ready() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap();
        assert_eq!(conn.state(), &State::Ready);
    }

    // Test 5: write_ready after greeting returns Ok(27)
    #[test]
    fn write_ready_after_greeting_succeeds() {
        let mut conn: Connection<8, 32, 512> = Connection::new();
        let mut out = [0u8; 64];
        conn.write_greeting(&mut out).unwrap();
        conn.feed(&sub_greeting()).unwrap();
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
        let ping: &[u8] = &[0x04, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i'];
        conn.feed(ping).unwrap();

        let mut pong_buf = [0u8; 23];
        let n = conn.write_pong(&mut pong_buf).unwrap().expect("pong pending");
        // body = name-size(1) + "PONG"(4) + "hi"(2) = 7
        assert_eq!(n, 9);
        assert_eq!(pong_buf[0], 0x04); // COMMAND
        assert_eq!(pong_buf[1], 7);    // body len
        assert_eq!(pong_buf[2], 4);    // name-size "PONG"
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
}
