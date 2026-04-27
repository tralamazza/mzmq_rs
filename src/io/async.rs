use crate::auth::AuthCheck;
use crate::connection::{ConnError, Connection};
use crate::io::core::{Action, DriverCore, RadioDriverCore};
use embedded_io_async::{Error, Read, Write};

/// Async driver for a ZMTP 3.1 PUB [`Connection`].
///
/// Generic parameters mirror [`Connection`]:
/// - `SUB_CAP`    — maximum simultaneous peer subscriptions
/// - `PREFIX_CAP` — maximum bytes per subscription prefix
/// - `FRAME_CAP`  — frame-decoder body buffer size
/// - `T`          — transport implementing `embedded_io_async::Read + Write`
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
    core: DriverCore<SUB_CAP, PREFIX_CAP, FRAME_CAP, A>,
    transport: T,
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
    pub async fn new(mut transport: T) -> Result<Self, ConnError> {
        let mut conn = Connection::new();

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .await
            .map_err(|e| ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            core: DriverCore::new_null(conn),
            transport,
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
    /// [`Driver::new`] instead — `()` satisfies [`AuthCheck`] but not
    /// [`crate::plain::Authenticator`].
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if the connection cannot write the greeting.
    /// Returns `ConnError::IoError` if the transport write fails.
    pub async fn new_plain(mut transport: T, auth: A) -> Result<Self, ConnError> {
        let mut conn = Connection::new_plain(auth);

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .await
            .map_err(|e| ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            core: DriverCore::new_plain(conn),
            transport,
        })
    }
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, T, A: AuthCheck>
    Driver<SUB_CAP, PREFIX_CAP, FRAME_CAP, T, A>
where
    T: Read + Write,
{
    /// Drive the connection one step. Returns `Ok(true)` when the connection
    /// is `Established`.
    ///
    /// # Errors
    /// Returns `ConnError::IoError` if the transport read/write fails or EOF is reached.
    /// Returns `ConnError::WrongState` if the connection is in an invalid state.
    /// Returns other `ConnError` variants if the handshake or frame processing fails.
    pub async fn poll(&mut self) -> Result<bool, ConnError> {
        let io_err =
            |e: <T as embedded_io_async::ErrorType>::Error| ConnError::IoError(e.kind() as usize);
        loop {
            match self.core.step()? {
                Action::Write(bytes) => {
                    self.transport.write_all(bytes).await.map_err(io_err)?;
                }
                Action::Read => {
                    let n = self
                        .transport
                        .read(self.core.rx_slot())
                        .await
                        .map_err(io_err)?;
                    if n == 0 {
                        return Err(ConnError::IoError(0));
                    }
                    self.core.advance_rx(n);
                    return Ok(self.core.is_established());
                }
                Action::Parked => return Ok(false),
                Action::Established => return Ok(true),
            }
        }
    }

    /// Publish a message. Returns 0 if no peer subscription matches.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::IoError` if the transport write fails.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub async fn publish(&mut self, topic: &[u8], payload: &[u8]) -> Result<usize, ConnError> {
        let Some((th, th_n, ph, ph_n)) = self.core.publish_headers(topic, payload)? else {
            return Ok(0);
        };
        let io_err =
            |e: <T as embedded_io_async::ErrorType>::Error| ConnError::IoError(e.kind() as usize);
        self.transport
            .write_all(&th[..th_n])
            .await
            .map_err(io_err)?;
        self.transport.write_all(topic).await.map_err(io_err)?;
        self.transport
            .write_all(&ph[..ph_n])
            .await
            .map_err(io_err)?;
        self.transport.write_all(payload).await.map_err(io_err)?;
        Ok(th_n + topic.len() + ph_n + payload.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::State;
    use crate::test_helpers::{
        async_mock::MockTransport, pub_ready, sub_greeting, sub_ready, sub_subscribe,
    };

    extern crate alloc;

    struct ReadErrorTransport;
    impl embedded_io_async::ErrorType for ReadErrorTransport {
        type Error = embedded_io_async::ErrorKind;
    }
    impl embedded_io_async::Read for ReadErrorTransport {
        async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Err(embedded_io_async::ErrorKind::BrokenPipe)
        }
    }
    impl embedded_io_async::Write for ReadErrorTransport {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    async fn make_established(prefix: Option<&[u8]>) -> Driver<8, 32, 512, MockTransport> {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&sub_ready());
        if let Some(p) = prefix {
            peer.extend_from_slice(&sub_subscribe(p));
        }
        let mut driver = Driver::<8, 32, 512, _>::new(MockTransport::new(peer))
            .await
            .unwrap();
        while !driver.poll().await.unwrap() {}
        driver
    }

    #[tokio::test]
    async fn driver_sends_full_greeting_first() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&sub_greeting());
        peer_bytes.extend_from_slice(&sub_ready());

        let transport = MockTransport::new(peer_bytes);
        let driver = Driver::<8, 32, 512, _>::new(transport).await.unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 64);
        assert_eq!(written[0], 0xFF);
        assert_eq!(written[9], 0x7F);
        assert_eq!(written[10], 0x03);
    }

    #[tokio::test]
    async fn driver_respects_deadlock_rule() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&sub_greeting());
        peer_bytes.extend_from_slice(&sub_ready());

        let transport = MockTransport::new(peer_bytes);
        let mut driver = Driver::<8, 32, 512, _>::new(transport).await.unwrap();

        let mut established = false;
        for _ in 0..10 {
            match driver.poll().await {
                Ok(true) => {
                    established = true;
                    break;
                }
                Ok(false) => {}
                Err(e) => panic!("poll failed: {e:?}"),
            }
        }

        assert!(established);
        assert_eq!(*driver.core.conn().state(), State::Established);

        let written = driver.transport.written();
        assert!(written.len() >= 64 + 27);
        assert_eq!(&written[64..64 + 27], &pub_ready());
    }

    #[tokio::test]
    async fn driver_publish_returns_zero_without_subscription() {
        let mut driver = make_established(None).await;
        assert_eq!(driver.publish(b"topic", b"payload").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn driver_publish_writes_correct_wire_bytes() {
        let mut driver = make_established(Some(b"foo")).await;
        let n = driver.publish(b"foo", b"bar").await.unwrap();
        assert_eq!(n, 10);
        let pub_out = &driver.transport.written()[91..];
        assert_eq!(
            pub_out,
            &[0x01, 0x03, b'f', b'o', b'o', 0x00, 0x03, b'b', b'a', b'r']
        );
    }

    #[tokio::test]
    async fn driver_publish_filtered_by_prefix() {
        let mut driver = make_established(Some(b"foo")).await;
        assert_eq!(driver.publish(b"bar", b"payload").await.unwrap(), 0);
        assert!(driver.publish(b"fooX", b"payload").await.unwrap() > 0);
    }

    #[tokio::test]
    async fn driver_poll_eof_returns_error() {
        let transport = MockTransport::new(alloc::vec::Vec::new());
        let mut driver = Driver::<8, 32, 512, _>::new(transport).await.unwrap();
        assert!(matches!(driver.poll().await, Err(ConnError::IoError(0))));
    }

    #[tokio::test]
    async fn driver_poll_transport_read_error_propagates() {
        let mut driver = Driver::<8, 32, 512, _>::new(ReadErrorTransport)
            .await
            .unwrap();
        assert!(matches!(driver.poll().await, Err(ConnError::IoError(_))));
    }

    #[tokio::test]
    async fn driver_ping_triggers_pong_response() {
        let ping = [
            0x04u8, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&sub_ready());
        peer.extend_from_slice(&ping);

        let transport = MockTransport::new(peer);
        let mut driver = Driver::<8, 32, 512, _>::new(transport).await.unwrap();
        while !driver.poll().await.unwrap() {}

        let written = driver.transport.written();
        assert!(written.len() >= 100);
        let pong_frame = &written[91..100];
        assert_eq!(pong_frame[0], 0x04);
        assert_eq!(pong_frame[1], 7);
        assert_eq!(&pong_frame[2..7], &[0x04, b'P', b'O', b'N', b'G']);
        assert_eq!(&pong_frame[7..9], b"hi");
    }

    #[tokio::test]
    async fn driver_feed_error_writes_error_frame_and_returns_err() {
        let push_ready = [
            0x04u8, 0x1A, 0x05, b'R', b'E', b'A', b'D', b'Y', 0x0B, b'S', b'o', b'c', b'k', b'e',
            b't', b'-', b'T', b'y', b'p', b'e', 0x00, 0x00, 0x00, 0x04, b'P', b'U', b'S', b'H',
        ];
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&sub_greeting());
        peer.extend_from_slice(&push_ready);

        let transport = MockTransport::new(peer);
        let mut driver = Driver::<8, 32, 512, _>::new(transport).await.unwrap();
        assert!(!driver.poll().await.unwrap());
        assert!(driver.poll().await.is_err());

        let written = driver.transport.written();
        assert!(written.len() > 91);
        assert_eq!(written[91], 0x04);
    }

    struct ChunkedReadTransport {
        data: alloc::vec::Vec<u8>,
        pos: usize,
    }

    impl embedded_io_async::ErrorType for ChunkedReadTransport {
        type Error = embedded_io_async::ErrorKind;
    }
    impl embedded_io_async::Read for ChunkedReadTransport {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }
    impl embedded_io_async::Write for ChunkedReadTransport {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn driver_chunked_read_completes_handshake() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&sub_greeting());
        peer_bytes.extend_from_slice(&sub_ready());

        let mut driver = Driver::<8, 32, 512, _>::new(ChunkedReadTransport {
            data: peer_bytes,
            pos: 0,
        })
        .await
        .unwrap();
        while !driver.poll().await.unwrap() {}
        assert_eq!(*driver.core.conn().state(), State::Established);
    }
}

#[cfg(all(test, feature = "plain"))]
mod plain_driver_tests {
    use super::*;
    use crate::connection::State;
    use crate::test_helpers::{
        async_mock::MockTransport, plain_hello, plain_sub_greeting, pub_ready, sub_ready,
        sub_subscribe,
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

    async fn make_plain_established(
        prefix: Option<&[u8]>,
    ) -> Driver<8, 32, 512, MockTransport, AcceptAll> {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&plain_sub_greeting());
        peer.extend_from_slice(&plain_hello(b"user", b"pass"));
        peer.extend_from_slice(&sub_ready());
        if let Some(p) = prefix {
            peer.extend_from_slice(&sub_subscribe(p));
        }
        let mut driver = Driver::<8, 32, 512, _, _>::new_plain(MockTransport::new(peer), AcceptAll)
            .await
            .unwrap();
        while !driver.poll().await.unwrap() {}
        driver
    }

    #[tokio::test]
    async fn plain_driver_writes_full_greeting_on_construction() {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&plain_sub_greeting());
        peer.extend_from_slice(&plain_hello(b"u", b"p"));
        peer.extend_from_slice(&sub_ready());

        let driver = Driver::<8, 32, 512, _, _>::new_plain(MockTransport::new(peer), AcceptAll)
            .await
            .unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 64);
        assert_eq!(written[0], 0xFF);
        assert_eq!(written[9], 0x7F);
        assert_eq!(written[10], 0x03);
    }

    #[tokio::test]
    async fn plain_driver_completes_handshake() {
        let driver = make_plain_established(None).await;
        assert_eq!(*driver.core.conn().state(), State::Established);
    }

    #[tokio::test]
    async fn plain_driver_emits_welcome_then_ready() {
        let driver = make_plain_established(None).await;
        let written = driver.transport.written();
        assert!(written.len() >= 101);
        assert_eq!(&written[12..17], b"PLAIN");
        assert_eq!(written[32], 0x01);
        assert_eq!(written[64], 0x04);
        assert_eq!(written[65], 0x08);
        assert_eq!(written[66], 0x07);
        assert_eq!(&written[67..74], b"WELCOME");
        assert_eq!(&written[74..101], &pub_ready());
    }

    #[tokio::test]
    async fn plain_driver_publish_returns_zero_without_subscription() {
        let mut driver = make_plain_established(None).await;
        assert_eq!(driver.publish(b"topic", b"payload").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn plain_driver_publish_writes_correct_wire_bytes() {
        let mut driver = make_plain_established(Some(b"foo")).await;
        let n = driver.publish(b"foo", b"bar").await.unwrap();
        assert_eq!(n, 10);
        let pub_out = &driver.transport.written()[101..];
        assert_eq!(
            pub_out,
            &[0x01, 0x03, b'f', b'o', b'o', 0x00, 0x03, b'b', b'a', b'r']
        );
    }

    #[tokio::test]
    async fn plain_driver_rejects_bad_credentials() {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&plain_sub_greeting());
        peer.extend_from_slice(&plain_hello(b"wrong", b"creds"));

        let mut driver = Driver::<8, 32, 512, _, _>::new_plain(MockTransport::new(peer), RejectAll)
            .await
            .unwrap();

        let found_err = loop {
            match driver.poll().await {
                Err(_) => break true,
                Ok(true) => break false,
                Ok(false) => {}
            }
        };
        assert!(found_err, "Bad credentials should produce an error");
    }
}

// ---------------------------------------------------------------------------
// Async RADIO driver
// ---------------------------------------------------------------------------

/// Async driver for a ZMTP 3.1 RADIO [`crate::radio_connection::RadioConnection`].
///
/// Generic parameters mirror [`crate::radio_connection::RadioConnection`]:
/// - `GROUP_CAP`    — maximum simultaneous peer group memberships
/// - `GROUP_LEN_CAP` — maximum bytes per group name
/// - `FRAME_CAP`  — frame-decoder body buffer size
/// - `T`          — transport implementing `embedded_io_async::Read + Write`
pub struct RadioDriver<
    const GROUP_CAP: usize,
    const GROUP_LEN_CAP: usize,
    const FRAME_CAP: usize,
    T,
> {
    core: RadioDriverCore<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP>,
    transport: T,
}

impl<const GROUP_CAP: usize, const GROUP_LEN_CAP: usize, const FRAME_CAP: usize, T>
    RadioDriver<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP, T>
where
    T: Read + Write,
{
    /// Create a new async RADIO driver. Sends our greeting immediately.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if the connection cannot write the greeting.
    /// Returns `ConnError::IoError` if the transport write fails.
    pub async fn new(mut transport: T) -> Result<Self, crate::radio_connection::ConnError> {
        let mut conn = crate::radio_connection::RadioConnection::new();

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .await
            .map_err(|e| crate::radio_connection::ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            core: RadioDriverCore::new(conn),
            transport,
        })
    }

    /// Drive the connection one step. Returns `Ok(true)` when the connection
    /// is `Established`.
    ///
    /// # Errors
    /// Returns `ConnError::IoError` if the transport read/write fails or EOF is reached.
    /// Returns `ConnError::WrongState` if the connection is in an invalid state.
    /// Returns other `ConnError` variants if the handshake or frame processing fails.
    pub async fn poll(&mut self) -> Result<bool, crate::radio_connection::ConnError> {
        let io_err = |e: <T as embedded_io_async::ErrorType>::Error| {
            crate::radio_connection::ConnError::IoError(e.kind() as usize)
        };
        loop {
            match self.core.step()? {
                Action::Write(bytes) => {
                    self.transport.write_all(bytes).await.map_err(io_err)?;
                }
                Action::Read => {
                    let n = self
                        .transport
                        .read(self.core.rx_slot())
                        .await
                        .map_err(io_err)?;
                    if n == 0 {
                        return Err(crate::radio_connection::ConnError::IoError(0));
                    }
                    self.core.advance_rx(n);
                    return Ok(self.core.is_established());
                }
                Action::Parked => return Ok(false),
                Action::Established => return Ok(true),
            }
        }
    }

    /// Publish a message to the group. Returns 0 if the peer has not joined the group.
    ///
    /// # Errors
    /// Returns `ConnError::WrongState` if not in `Established` state.
    /// Returns `ConnError::IoError` if the transport write fails.
    /// Returns `ConnError::FrameError` if the frame headers cannot be encoded.
    pub async fn publish(
        &mut self,
        group: &[u8],
        body: &[u8],
    ) -> Result<usize, crate::radio_connection::ConnError> {
        let Some((gh, gh_n, bh, bh_n)) = self.core.publish_headers(group, body)? else {
            return Ok(0);
        };
        let io_err = |e: <T as embedded_io_async::ErrorType>::Error| {
            crate::radio_connection::ConnError::IoError(e.kind() as usize)
        };
        self.transport
            .write_all(&gh[..gh_n])
            .await
            .map_err(io_err)?;
        self.transport.write_all(group).await.map_err(io_err)?;
        self.transport
            .write_all(&bh[..bh_n])
            .await
            .map_err(io_err)?;
        self.transport.write_all(body).await.map_err(io_err)?;
        Ok(gh_n + group.len() + bh_n + body.len())
    }
}

#[cfg(test)]
mod radio_tests {
    use super::*;
    use crate::test_helpers::{
        async_mock::MockTransport, dish_greeting, dish_join, dish_ready, radio_ready,
    };

    extern crate alloc;

    struct ReadErrorTransport;
    impl embedded_io_async::ErrorType for ReadErrorTransport {
        type Error = embedded_io_async::ErrorKind;
    }
    impl embedded_io_async::Read for ReadErrorTransport {
        async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Err(embedded_io_async::ErrorKind::BrokenPipe)
        }
    }
    impl embedded_io_async::Write for ReadErrorTransport {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct ChunkedReadTransport {
        data: alloc::vec::Vec<u8>,
        pos: usize,
    }

    impl embedded_io_async::ErrorType for ChunkedReadTransport {
        type Error = embedded_io_async::ErrorKind;
    }
    impl embedded_io_async::Read for ChunkedReadTransport {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }
    impl embedded_io_async::Write for ChunkedReadTransport {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    async fn make_established(group: Option<&[u8]>) -> RadioDriver<8, 32, 512, MockTransport> {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&dish_greeting());
        peer.extend_from_slice(&dish_ready());
        if let Some(g) = group {
            peer.extend_from_slice(&dish_join(g));
        }
        let mut driver = RadioDriver::<8, 32, 512, _>::new(MockTransport::new(peer))
            .await
            .unwrap();
        while !driver.poll().await.unwrap() {}
        driver
    }

    #[tokio::test]
    async fn radio_driver_sends_full_greeting_first() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&dish_greeting());
        peer_bytes.extend_from_slice(&dish_ready());

        let transport = MockTransport::new(peer_bytes);
        let driver = RadioDriver::<8, 32, 512, _>::new(transport).await.unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 64);
        assert_eq!(written[0], 0xFF);
        assert_eq!(written[9], 0x7F);
        assert_eq!(written[10], 0x03);
    }

    #[tokio::test]
    async fn radio_driver_respects_deadlock_rule() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&dish_greeting());
        peer_bytes.extend_from_slice(&dish_ready());

        let transport = MockTransport::new(peer_bytes);
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).await.unwrap();

        let mut established = false;
        for _ in 0..10 {
            match driver.poll().await {
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
            *driver.core.conn().state(),
            crate::radio_connection::State::Established
        );

        let written = driver.transport.written();
        assert!(written.len() >= 64 + 29);
        assert_eq!(&written[64..64 + 29], &radio_ready());
    }

    #[tokio::test]
    async fn radio_driver_publish_returns_zero_without_membership() {
        let mut driver = make_established(None).await;
        assert_eq!(driver.publish(b"topic", b"payload").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn radio_driver_publish_writes_correct_wire_bytes() {
        let mut driver = make_established(Some(b"foo")).await;
        let n = driver.publish(b"foo", b"bar").await.unwrap();
        assert_eq!(n, 10);
        let pub_out = &driver.transport.written()[93..];
        assert_eq!(
            pub_out,
            &[0x01, 0x03, b'f', b'o', b'o', 0x00, 0x03, b'b', b'a', b'r']
        );
    }

    #[tokio::test]
    async fn radio_driver_publish_requires_exact_match() {
        let mut driver = make_established(Some(b"foo")).await;
        assert_eq!(driver.publish(b"foobar", b"payload").await.unwrap(), 0);
        assert!(driver.publish(b"foo", b"payload").await.unwrap() > 0);
    }

    #[tokio::test]
    async fn radio_driver_poll_eof_returns_error() {
        let transport = MockTransport::new(alloc::vec::Vec::new());
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).await.unwrap();
        assert!(driver.poll().await.is_err());
    }

    #[tokio::test]
    async fn radio_driver_poll_transport_read_error_propagates() {
        let mut driver = RadioDriver::<8, 32, 512, _>::new(ReadErrorTransport)
            .await
            .unwrap();
        assert!(driver.poll().await.is_err());
    }

    #[tokio::test]
    async fn radio_driver_ping_triggers_pong_response() {
        let ping = [
            0x04u8, 0x09, 0x04, b'P', b'I', b'N', b'G', 0x00, 0x00, b'h', b'i',
        ];
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&dish_greeting());
        peer.extend_from_slice(&dish_ready());
        peer.extend_from_slice(&ping);

        let transport = MockTransport::new(peer);
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).await.unwrap();
        while !driver.poll().await.unwrap() {}

        let written = driver.transport.written();
        assert!(written.len() >= 102);
        let pong_frame = &written[93..102];
        assert_eq!(pong_frame[0], 0x04);
        assert_eq!(pong_frame[1], 7);
        assert_eq!(&pong_frame[2..7], &[0x04, b'P', b'O', b'N', b'G']);
        assert_eq!(&pong_frame[7..9], b"hi");
    }

    #[tokio::test]
    async fn radio_driver_feed_error_writes_error_frame_and_returns_err() {
        let mut peer = alloc::vec::Vec::new();
        peer.extend_from_slice(&dish_greeting());
        peer.extend_from_slice(&crate::test_helpers::sub_ready());

        let transport = MockTransport::new(peer);
        let mut driver = RadioDriver::<8, 32, 512, _>::new(transport).await.unwrap();
        assert!(!driver.poll().await.unwrap());
        assert!(driver.poll().await.is_err());

        let written = driver.transport.written();
        assert!(written.len() > 93);
        assert_eq!(written[93], 0x04);
    }

    #[tokio::test]
    async fn radio_driver_chunked_read_completes_handshake() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&dish_greeting());
        peer_bytes.extend_from_slice(&dish_ready());

        let mut driver = RadioDriver::<8, 32, 512, _>::new(ChunkedReadTransport {
            data: peer_bytes,
            pos: 0,
        })
        .await
        .unwrap();
        while !driver.poll().await.unwrap() {}
        assert_eq!(
            *driver.core.conn().state(),
            crate::radio_connection::State::Established
        );
    }
}
