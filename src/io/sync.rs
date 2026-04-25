//! Synchronous (blocking) IO adapter for `Connection`.
//!
//! `Driver` wraps a `Connection` and a transport implementing
//! `embedded_io::Read + Write`, drives the handshake, and exposes a
//! `publish` method.

use crate::auth::AuthCheck;
use crate::connection::{ConnError, Connection, State};
#[cfg(feature = "plain")]
use crate::plain::WELCOME_LEN;
use embedded_io::{Error, Read, Write};

/// Blocking driver for a ZMTP 3.1 PUB [`Connection`].
///
/// Generic parameters mirror [`Connection`]:
/// - `SUB_CAP`    — maximum simultaneous peer subscriptions
/// - `PREFIX_CAP` — maximum bytes per subscription prefix
/// - `FRAME_CAP`  — frame-decoder body buffer size
/// - `T`          — transport implementing `embedded_io::Read + Write`
///
/// Internal buffers (not configurable):
/// - `rx_buf` is 512 bytes — holds handshake bytes and a single inbound
///   SUBSCRIBE/CANCEL frame, which fit comfortably at that size.
pub struct Driver<
    const SUB_CAP: usize,
    const PREFIX_CAP: usize,
    const FRAME_CAP: usize,
    T,
    A: AuthCheck = (),
> {
    conn: Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>,
    transport: T,
    rx_buf: [u8; 512],
    rx_len: usize,
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, T>
    Driver<SUB_CAP, PREFIX_CAP, FRAME_CAP, T, ()>
where
    T: Read + Write,
{
    /// Create a new NULL-mechanism driver. Sends our greeting immediately.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if the connection cannot write the greeting.
    /// Returns `ConnError::IoError` if the transport write fails.
    pub fn new(mut transport: T) -> Result<Self, ConnError> {
        let mut conn = Connection::new();

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .map_err(|e| ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            conn,
            transport,
            rx_buf: [0u8; 512],
            rx_len: 0,
        })
    }
}

#[cfg(feature = "plain")]
impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, T, A>
    Driver<SUB_CAP, PREFIX_CAP, FRAME_CAP, T, A>
where
    T: Read + Write,
    A: crate::plain::Authenticator,
{
    /// Create a new PLAIN-mechanism driver (server role). Sends our greeting immediately.
    ///
    /// `auth` must implement [`crate::plain::Authenticator`]. For the NULL mechanism use
    /// [`Driver::new`] instead — `()` satisfies [`AuthCheck`] but not [`crate::plain::Authenticator`].
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if the connection cannot write the greeting.
    /// Returns `ConnError::IoError` if the transport write fails.
    pub fn new_plain(mut transport: T, auth: A) -> Result<Self, ConnError> {
        let mut conn = Connection::new_plain(auth);

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .map_err(|e| ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            conn,
            transport,
            rx_buf: [0u8; 512],
            rx_len: 0,
        })
    }
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, T, A: AuthCheck>
    Driver<SUB_CAP, PREFIX_CAP, FRAME_CAP, T, A>
where
    T: Read + Write,
{
    /// Drive the connection one step. Blocks on `transport.read` when there is
    /// no buffered data left to process. Returns `Ok(true)` when the connection
    /// is `Established`.
    ///
    /// # Errors
    /// Returns `ConnError::IoError` if the transport read/write fails or EOF is reached.
    /// Returns `ConnError::WrongState` if the connection is in an invalid state.
    /// Returns other `ConnError` variants if the handshake or frame processing fails.
    pub fn poll(&mut self) -> Result<bool, ConnError> {
        if *self.conn.state() == State::Ready {
            let mut ready = [0u8; 32];
            match self.conn.write_ready(&mut ready) {
                Ok(n) => {
                    self.transport
                        .write_all(&ready[..n])
                        .map_err(|e| ConnError::IoError(e.kind() as usize))?;
                    // Don't process peer's READY in the same poll — defer to
                    // the next call so our READY is on the wire first
                    // (NULL mechanism deadlock rule).
                    return Ok(false);
                }
                Err(ConnError::WrongState) => {}
                Err(e) => return Err(e),
            }
        }

        if self.rx_len > 0 {
            let prev_rx_len = self.rx_len;
            self.drain_buffer()?;
            if self.rx_len < prev_rx_len {
                return Ok(*self.conn.state() == State::Established);
            }
            // Nothing consumed — the parser needs more bytes; fall through to read.
        }

        match self.transport.read(&mut self.rx_buf[self.rx_len..]) {
            Ok(0) => Err(ConnError::IoError(0)),
            Ok(n) => {
                self.rx_len += n;
                self.drain_buffer()?;
                Ok(*self.conn.state() == State::Established)
            }
            Err(e) => Err(ConnError::IoError(e.kind() as usize)),
        }
    }

    fn drain_buffer(&mut self) -> Result<(), ConnError> {
        let io_err =
            |e: <T as embedded_io::ErrorType>::Error| ConnError::IoError(e.kind() as usize);
        let mut total_consumed = 0;
        while total_consumed < self.rx_len {
            let prev_state = *self.conn.state();
            match self.conn.feed(&self.rx_buf[total_consumed..self.rx_len]) {
                Ok(consumed) => {
                    total_consumed += consumed;

                    if self.conn.greeting_rest_pending() {
                        let mut rest = [0u8; 64];
                        let n = self.conn.write_greeting_rest(&mut rest)?;
                        self.transport.write_all(&rest[..n]).map_err(io_err)?;
                    }

                    match (prev_state, self.conn.state()) {
                        (State::Greeting, State::Ready) => {
                            let mut ready = [0u8; 32];
                            let n = self.conn.write_ready(&mut ready)?;
                            self.transport.write_all(&ready[..n]).map_err(io_err)?;
                            break;
                        }
                        #[cfg(feature = "plain")]
                        (State::PlainHello, State::PlainReady) => {
                            let mut welcome = [0u8; WELCOME_LEN];
                            let n = self.conn.write_welcome(&mut welcome)?;
                            self.transport.write_all(&welcome[..n]).map_err(io_err)?;
                            let mut ready = [0u8; 32];
                            let n = self.conn.write_ready(&mut ready)?;
                            self.transport.write_all(&ready[..n]).map_err(io_err)?;
                            break;
                        }
                        _ => {}
                    }

                    let mut pong_buf = [0u8; 23];
                    if let Some(n) = self.conn.write_pong(&mut pong_buf)? {
                        self.transport.write_all(&pong_buf[..n]).map_err(io_err)?;
                    }

                    if consumed == 0 {
                        break;
                    }
                }
                Err(e) => {
                    if *self.conn.state() == State::Failed {
                        let mut err_buf = [0u8; 32];
                        if let Ok(n) = self.conn.write_error(&mut err_buf) {
                            let _ = self.transport.write_all(&err_buf[..n]);
                        }
                    }
                    return Err(e);
                }
            }
        }

        if total_consumed > 0 {
            self.rx_buf.copy_within(total_consumed..self.rx_len, 0);
            self.rx_len -= total_consumed;
        }
        Ok(())
    }

    /// Publish a message. Returns 0 if no peer subscription matches.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::IoError` if the transport write fails.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub fn publish(&mut self, topic: &[u8], payload: &[u8]) -> Result<usize, ConnError> {
        let Some((th, th_n, ph, ph_n)) = self.conn.publish_headers(topic, payload)? else {
            return Ok(0);
        };
        let io_err =
            |e: <T as embedded_io::ErrorType>::Error| ConnError::IoError(e.kind() as usize);
        self.transport.write_all(&th[..th_n]).map_err(io_err)?;
        self.transport.write_all(topic).map_err(io_err)?;
        self.transport.write_all(&ph[..ph_n]).map_err(io_err)?;
        self.transport.write_all(payload).map_err(io_err)?;
        Ok(th_n + topic.len() + ph_n + payload.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        pub_ready, sub_greeting, sub_ready, sub_subscribe, sync_mock::MockTransport,
    };
    use embedded_io::{ErrorKind, Read, Write};

    extern crate alloc;

    struct ReadErrorTransport;
    impl embedded_io::ErrorType for ReadErrorTransport {
        type Error = ErrorKind;
    }
    impl Read for ReadErrorTransport {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Err(ErrorKind::BrokenPipe)
        }
    }
    impl Write for ReadErrorTransport {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn make_established(prefix: Option<&[u8]>) -> Driver<8, 32, 512, MockTransport> {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&sub_ready());
        if let Some(p) = prefix {
            peer.extend_from_slice(&sub_subscribe(p));
        }
        let mut driver = Driver::<8, 32, 512, _>::new(MockTransport::new(peer)).unwrap();
        while !driver.poll().unwrap() {}
        driver
    }

    #[test]
    fn driver_sends_partial_greeting_first() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&sub_greeting());
        peer_bytes.extend_from_slice(&sub_ready());

        let transport = MockTransport::new(peer_bytes);
        let driver = Driver::<8, 32, 512, _>::new(transport).unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 11);
        assert_eq!(written[0], 0xFF);
        assert_eq!(written[9], 0x7F);
        assert_eq!(written[10], 0x03);
    }

    #[test]
    fn driver_respects_deadlock_rule() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&sub_greeting());
        peer_bytes.extend_from_slice(&sub_ready());

        let transport = MockTransport::new(peer_bytes);
        let mut driver = Driver::<8, 32, 512, _>::new(transport).unwrap();

        let mut established = false;
        for _ in 0..10 {
            match driver.poll() {
                Ok(true) => {
                    established = true;
                    break;
                }
                Ok(false) => {}
                Err(e) => panic!("poll failed: {e:?}"),
            }
        }

        assert!(established);
        assert_eq!(*driver.conn.state(), State::Established);

        let written = driver.transport.written();
        assert!(written.len() >= 64 + 27);
        assert_eq!(&written[64..64 + 27], &pub_ready());
    }

    #[test]
    fn driver_publish_returns_zero_without_subscription() {
        let mut driver = make_established(None);
        assert_eq!(driver.publish(b"topic", b"payload").unwrap(), 0);
    }

    #[test]
    fn driver_publish_writes_correct_wire_bytes() {
        let mut driver = make_established(Some(b"foo"));
        let n = driver.publish(b"foo", b"bar").unwrap();
        assert_eq!(n, 10); // 2+3+2+3
        // greeting (64) + pub_ready (27) = 91 bytes before publish output
        let pub_out = &driver.transport.written()[91..];
        assert_eq!(
            pub_out,
            &[0x01, 0x03, b'f', b'o', b'o', 0x00, 0x03, b'b', b'a', b'r']
        );
    }

    #[test]
    fn driver_publish_filtered_by_prefix() {
        let mut driver = make_established(Some(b"foo"));
        assert_eq!(driver.publish(b"bar", b"payload").unwrap(), 0);
        assert!(driver.publish(b"fooX", b"payload").unwrap() > 0);
    }

    #[test]
    fn driver_poll_eof_returns_error() {
        let transport = MockTransport::new(alloc::vec::Vec::new());
        let mut driver = Driver::<8, 32, 512, _>::new(transport).unwrap();
        assert!(matches!(driver.poll(), Err(ConnError::IoError(0))));
    }

    #[test]
    fn driver_poll_transport_read_error_propagates() {
        let mut driver = Driver::<8, 32, 512, _>::new(ReadErrorTransport).unwrap();
        assert!(matches!(driver.poll(), Err(ConnError::IoError(_))));
    }

    #[test]
    fn driver_ping_triggers_pong_response() {
        // PING: flags=0x04, body=9, name-size=4, "PING", ttl=0x00,0x00, ctx=b"hi"
        let ping = [
            0x04u8, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&sub_ready());
        peer.extend_from_slice(&ping);

        let transport = MockTransport::new(peer);
        let mut driver = Driver::<8, 32, 512, _>::new(transport).unwrap();
        while !driver.poll().unwrap() {}

        // partial(11) + rest(53) + pub_ready(27) = 91 bytes, then PONG(9)
        let written = driver.transport.written();
        assert!(written.len() >= 100);
        let pong_frame = &written[91..100];
        assert_eq!(pong_frame[0], 0x04); // COMMAND
        assert_eq!(pong_frame[1], 7); // body len = 1+4+2
        assert_eq!(&pong_frame[2..7], &[0x04, b'P', b'O', b'N', b'G']);
        assert_eq!(&pong_frame[7..9], b"hi");
    }

    #[test]
    fn driver_feed_error_writes_error_frame_and_returns_err() {
        // PUSH READY: wrong socket type for a PUB connection
        let push_ready = [
            0x04u8, 0x1A, 0x05, b'R', b'E', b'A', b'D', b'Y', 0x0B, b'S', b'o', b'c', b'k', b'e',
            b't', b'-', b'T', b'y', b'p', b'e', 0x00, 0x00, 0x00, 0x04, b'P', b'U', b'S', b'H',
        ];
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&push_ready);

        let transport = MockTransport::new(peer);
        let mut driver = Driver::<8, 32, 512, _>::new(transport).unwrap();
        assert!(!driver.poll().unwrap()); // processes greeting
        assert!(driver.poll().is_err()); // PUSH READY → WrongSocketType → Failed

        // ERROR command frame written after partial(11)+rest(53)+ready(27)=91 bytes
        let written = driver.transport.written();
        assert!(written.len() > 91);
        assert_eq!(written[91], 0x04); // COMMAND flag
    }
}

// ---------------------------------------------------------------------------
// RADIO driver (parallel to the PUB Driver above)
// ---------------------------------------------------------------------------

/// Blocking driver for a ZMTP 3.1 RADIO [`RadioConnection`].
///
/// Generic parameters mirror [`RadioConnection`]:
/// - `GROUP_CAP`    — maximum simultaneous peer group memberships
/// - `GROUP_LEN_CAP` — maximum bytes per group name
/// - `FRAME_CAP`  — frame-decoder body buffer size
/// - `T`          — transport implementing `embedded_io::Read + Write`
pub struct RadioDriver<
    const GROUP_CAP: usize,
    const GROUP_LEN_CAP: usize,
    const FRAME_CAP: usize,
    T,
> {
    conn: crate::radio_connection::RadioConnection<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP>,
    transport: T,
    rx_buf: [u8; 512],
    rx_len: usize,
}

impl<const GROUP_CAP: usize, const GROUP_LEN_CAP: usize, const FRAME_CAP: usize, T>
    RadioDriver<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP, T>
where
    T: Read + Write,
{
    /// Create a new RADIO driver. Sends our greeting immediately.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if the connection cannot write the greeting.
    /// Returns `ConnError::IoError` if the transport write fails.
    pub fn new(mut transport: T) -> Result<Self, crate::radio_connection::ConnError> {
        let mut conn = crate::radio_connection::RadioConnection::new();

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .map_err(|e| crate::radio_connection::ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            conn,
            transport,
            rx_buf: [0u8; 512],
            rx_len: 0,
        })
    }

    /// Drive the connection one step. Blocks on `transport.read` when there is
    /// no buffered data left to process. Returns `Ok(true)` when the connection
    /// is `Established`.
    ///
    /// # Errors
    /// Returns `ConnError::IoError` if the transport read/write fails or EOF is reached.
    /// Returns `ConnError::WrongState` if the connection is in an invalid state.
    /// Returns other `ConnError` variants if the handshake or frame processing fails.
    pub fn poll(&mut self) -> Result<bool, crate::radio_connection::ConnError> {
        use crate::radio_connection::State;

        if *self.conn.state() == State::Ready {
            let mut ready = [0u8; 32];
            match self.conn.write_ready(&mut ready) {
                Ok(n) => {
                    self.transport.write_all(&ready[..n]).map_err(|e| {
                        crate::radio_connection::ConnError::IoError(e.kind() as usize)
                    })?;
                    return Ok(false);
                }
                Err(crate::radio_connection::ConnError::WrongState) => {}
                Err(e) => return Err(e),
            }
        }

        if self.rx_len > 0 {
            let prev_rx_len = self.rx_len;
            self.drain_buffer()?;
            if self.rx_len < prev_rx_len {
                return Ok(*self.conn.state() == State::Established);
            }
            // Nothing consumed — the parser needs more bytes; fall through to read.
        }

        match self.transport.read(&mut self.rx_buf[self.rx_len..]) {
            Ok(0) => Err(crate::radio_connection::ConnError::IoError(0)),
            Ok(n) => {
                self.rx_len += n;
                self.drain_buffer()?;
                Ok(*self.conn.state() == State::Established)
            }
            Err(e) => Err(crate::radio_connection::ConnError::IoError(
                e.kind() as usize
            )),
        }
    }

    fn drain_buffer(&mut self) -> Result<(), crate::radio_connection::ConnError> {
        use crate::radio_connection::State;

        let mut total_consumed = 0;
        while total_consumed < self.rx_len {
            let was_ready_before = *self.conn.state() == State::Ready;
            match self.conn.feed(&self.rx_buf[total_consumed..self.rx_len]) {
                Ok(consumed) => {
                    total_consumed += consumed;

                    if self.conn.greeting_rest_pending() {
                        let mut rest = [0u8; 64];
                        match self.conn.write_greeting_rest(&mut rest) {
                            Ok(n) => {
                                self.transport.write_all(&rest[..n]).map_err(|e| {
                                    crate::radio_connection::ConnError::IoError(e.kind() as usize)
                                })?;
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    if *self.conn.state() == State::Ready && !was_ready_before {
                        let mut ready = [0u8; 32];
                        match self.conn.write_ready(&mut ready) {
                            Ok(n) => {
                                self.transport.write_all(&ready[..n]).map_err(|e| {
                                    crate::radio_connection::ConnError::IoError(e.kind() as usize)
                                })?;
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    let mut pong_buf = [0u8; 23];
                    if let Some(n) = self.conn.write_pong(&mut pong_buf)? {
                        self.transport.write_all(&pong_buf[..n]).map_err(|e| {
                            crate::radio_connection::ConnError::IoError(e.kind() as usize)
                        })?;
                    }

                    if consumed == 0 {
                        break;
                    }
                }
                Err(e) => {
                    if *self.conn.state() == State::Failed {
                        let mut err_buf = [0u8; 32];
                        if let Ok(n) = self.conn.write_error(&mut err_buf) {
                            let _ = self.transport.write_all(&err_buf[..n]);
                        }
                    }
                    return Err(e);
                }
            }
        }

        if total_consumed > 0 {
            self.rx_buf.copy_within(total_consumed..self.rx_len, 0);
            self.rx_len -= total_consumed;
        }
        Ok(())
    }

    /// Publish a message to the group. Returns 0 if the peer has not joined the group.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::IoError` if the transport write fails.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub fn publish(
        &mut self,
        group: &[u8],
        body: &[u8],
    ) -> Result<usize, crate::radio_connection::ConnError> {
        let Some((gh, gh_n, bh, bh_n)) = self.conn.publish_headers(group, body)? else {
            return Ok(0);
        };
        let io_err = |e: <T as embedded_io::ErrorType>::Error| {
            crate::radio_connection::ConnError::IoError(e.kind() as usize)
        };
        self.transport.write_all(&gh[..gh_n]).map_err(io_err)?;
        self.transport.write_all(group).map_err(io_err)?;
        self.transport.write_all(&bh[..bh_n]).map_err(io_err)?;
        self.transport.write_all(body).map_err(io_err)?;
        Ok(gh_n + group.len() + bh_n + body.len())
    }
}

#[cfg(test)]
mod radio_tests {
    use super::*;
    use crate::test_helpers::{
        dish_greeting, dish_join, dish_ready, radio_ready, sync_mock::MockTransport,
    };
    use embedded_io::{ErrorKind, Read, Write};

    extern crate alloc;

    struct ReadErrorTransport;
    impl embedded_io::ErrorType for ReadErrorTransport {
        type Error = ErrorKind;
    }
    impl Read for ReadErrorTransport {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Err(ErrorKind::BrokenPipe)
        }
    }
    impl Write for ReadErrorTransport {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn make_established(group: Option<&[u8]>) -> RadioDriver<8, 32, 512, MockTransport> {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&dish_greeting());
        peer.extend_from_slice(&dish_ready());
        if let Some(g) = group {
            peer.extend_from_slice(&dish_join(g));
        }
        let mut driver = RadioDriver::<8, 32, 512, _>::new(MockTransport::new(peer)).unwrap();
        while !driver.poll().unwrap() {}
        driver
    }

    #[test]
    fn radio_driver_sends_partial_greeting_first() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&dish_greeting());
        peer_bytes.extend_from_slice(&dish_ready());

        let transport = MockTransport::new(peer_bytes);
        let driver = RadioDriver::<8, 32, 512, _>::new(transport).unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 11);
        assert_eq!(written[0], 0xFF);
        assert_eq!(written[9], 0x7F);
        assert_eq!(written[10], 0x03);
    }

    #[test]
    fn radio_driver_respects_deadlock_rule() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&dish_greeting());
        peer_bytes.extend_from_slice(&dish_ready());

        let transport = MockTransport::new(peer_bytes);
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).unwrap();

        let mut established = false;
        for _ in 0..10 {
            match driver.poll() {
                Ok(true) => {
                    established = true;
                    break;
                }
                Ok(false) => {}
                Err(e) => panic!("poll failed: {e:?}"),
            }
        }

        assert!(established);
        assert_eq!(
            *driver.conn.state(),
            crate::radio_connection::State::Established
        );

        let written = driver.transport.written();
        assert!(written.len() >= 64 + 29);
        assert_eq!(&written[64..64 + 29], &radio_ready());
    }

    #[test]
    fn radio_driver_publish_returns_zero_without_membership() {
        let mut driver = make_established(None);
        assert_eq!(driver.publish(b"topic", b"payload").unwrap(), 0);
    }

    #[test]
    fn radio_driver_publish_writes_correct_wire_bytes() {
        let mut driver = make_established(Some(b"foo"));
        let n = driver.publish(b"foo", b"bar").unwrap();
        assert_eq!(n, 10); // 2+3+2+3
        // greeting (64) + radio_ready (29) = 93 bytes before publish output
        let pub_out = &driver.transport.written()[93..];
        assert_eq!(
            pub_out,
            &[0x01, 0x03, b'f', b'o', b'o', 0x00, 0x03, b'b', b'a', b'r']
        );
    }

    #[test]
    fn radio_driver_publish_requires_exact_match() {
        let mut driver = make_established(Some(b"foo"));
        assert_eq!(driver.publish(b"foobar", b"payload").unwrap(), 0);
        assert!(driver.publish(b"foo", b"payload").unwrap() > 0);
    }

    #[test]
    fn radio_driver_poll_eof_returns_error() {
        let transport = MockTransport::new(alloc::vec::Vec::new());
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).unwrap();
        assert!(driver.poll().is_err());
    }

    #[test]
    fn radio_driver_poll_transport_read_error_propagates() {
        let mut driver = RadioDriver::<8, 32, 512, _>::new(ReadErrorTransport).unwrap();
        assert!(driver.poll().is_err());
    }

    #[test]
    fn radio_driver_ping_triggers_pong_response() {
        // PING: flags=0x04, body=9, name-size=4, "PING", ttl=0x00,0x00, ctx=b"hi"
        let ping = [
            0x04u8, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&dish_greeting());
        peer.extend_from_slice(&dish_ready());
        peer.extend_from_slice(&ping);

        let transport = MockTransport::new(peer);
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).unwrap();
        while !driver.poll().unwrap() {}

        // partial(11) + rest(53) + radio_ready(29) = 93 bytes, then PONG(9)
        let written = driver.transport.written();
        assert!(written.len() >= 102);
        let pong_frame = &written[93..102];
        assert_eq!(pong_frame[0], 0x04); // COMMAND
        assert_eq!(pong_frame[1], 7); // body len = 1+4+2
        assert_eq!(&pong_frame[2..7], &[0x04, b'P', b'O', b'N', b'G']);
        assert_eq!(&pong_frame[7..9], b"hi");
    }

    #[test]
    fn radio_driver_feed_error_writes_error_frame_and_returns_err() {
        // SUB READY: wrong socket type for a RADIO connection (expects DISH)
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&dish_greeting());
        peer.extend_from_slice(&crate::test_helpers::sub_ready());

        let transport = MockTransport::new(peer);
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).unwrap();
        assert!(!driver.poll().unwrap()); // processes greeting
        assert!(driver.poll().is_err()); // SUB READY → WrongSocketType → Failed

        // ERROR command frame written after partial(11)+rest(53)+radio_ready(29)=93 bytes
        let written = driver.transport.written();
        assert!(written.len() > 93);
        assert_eq!(written[93], 0x04); // COMMAND flag
    }
}

#[cfg(all(test, feature = "plain"))]
mod plain_driver_tests {
    use super::*;
    use crate::test_helpers::{
        plain_hello, plain_sub_greeting, pub_ready, sub_ready, sub_subscribe,
        sync_mock::MockTransport,
    };

    extern crate alloc;

    struct AcceptAll;
    impl crate::plain::Authenticator for AcceptAll {
        fn authenticate(&self, _username: &[u8], _password: &[u8]) -> bool {
            true
        }
    }

    struct RejectAll;
    impl crate::plain::Authenticator for RejectAll {
        fn authenticate(&self, _username: &[u8], _password: &[u8]) -> bool {
            false
        }
    }

    fn make_plain_established(
        prefix: Option<&[u8]>,
    ) -> Driver<8, 32, 512, MockTransport, AcceptAll> {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&plain_sub_greeting());
        peer.extend_from_slice(&plain_hello(b"user", b"pass"));
        peer.extend_from_slice(&sub_ready());
        if let Some(p) = prefix {
            peer.extend_from_slice(&sub_subscribe(p));
        }
        let mut driver =
            Driver::<8, 32, 512, _, _>::new_plain(MockTransport::new(peer), AcceptAll).unwrap();
        while !driver.poll().unwrap() {}
        driver
    }

    #[test]
    fn plain_driver_writes_partial_greeting_on_construction() {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&plain_sub_greeting());
        peer.extend_from_slice(&plain_hello(b"u", b"p"));
        peer.extend_from_slice(&sub_ready());

        let driver =
            Driver::<8, 32, 512, _, _>::new_plain(MockTransport::new(peer), AcceptAll).unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 11);
        assert_eq!(written[0], 0xFF);
        assert_eq!(written[9], 0x7F);
        assert_eq!(written[10], 0x03);
    }

    #[test]
    fn plain_driver_completes_handshake() {
        let driver = make_plain_established(None);
        assert_eq!(*driver.conn.state(), State::Established);
    }

    #[test]
    fn plain_driver_emits_welcome_then_ready() {
        let driver = make_plain_established(None);
        let written = driver.transport.written();
        // partial(11) + rest(53) = 64 bytes (our PLAIN server greeting)
        // welcome(10) at offset 64, pub_ready(27) at offset 74
        assert!(written.len() >= 101);
        // PLAIN server greeting: mechanism="PLAIN" at bytes 12–16, as_server=1 at byte 32
        assert_eq!(&written[12..17], b"PLAIN");
        assert_eq!(written[32], 0x01);
        // WELCOME frame
        assert_eq!(written[64], 0x04);
        assert_eq!(written[65], 0x08);
        assert_eq!(written[66], 0x07);
        assert_eq!(&written[67..74], b"WELCOME");
        // PUB READY frame
        assert_eq!(&written[74..101], &pub_ready());
    }

    #[test]
    fn plain_driver_publish_returns_zero_without_subscription() {
        let mut driver = make_plain_established(None);
        assert_eq!(driver.publish(b"topic", b"payload").unwrap(), 0);
    }

    #[test]
    fn plain_driver_publish_writes_correct_wire_bytes() {
        let mut driver = make_plain_established(Some(b"foo"));
        let n = driver.publish(b"foo", b"bar").unwrap();
        assert_eq!(n, 10); // 2+3+2+3
        // greeting(64) + welcome(10) + pub_ready(27) = 101 bytes before publish
        let pub_out = &driver.transport.written()[101..];
        assert_eq!(
            pub_out,
            &[0x01, 0x03, b'f', b'o', b'o', 0x00, 0x03, b'b', b'a', b'r']
        );
    }

    #[test]
    fn plain_driver_rejects_bad_credentials() {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&plain_sub_greeting());
        peer.extend_from_slice(&plain_hello(b"wrong", b"creds"));

        let mut driver =
            Driver::<8, 32, 512, _, _>::new_plain(MockTransport::new(peer), RejectAll).unwrap();

        let found_err = loop {
            match driver.poll() {
                Err(_) => break true,
                Ok(true) => break false,
                Ok(false) => {}
            }
        };
        assert!(found_err, "Bad credentials should produce an error");
    }
}
