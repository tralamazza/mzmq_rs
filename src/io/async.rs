//! Asynchronous IO adapter for `Connection`.
//!
//! `Driver` wraps a `Connection` and a transport implementing
//! `embedded_io_async::Read + Write`, drives the handshake, and exposes
//! an async `publish` method.

use crate::connection::{ConnError, Connection, State};
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
pub struct Driver<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, T> {
    conn: Connection<SUB_CAP, PREFIX_CAP, FRAME_CAP>,
    transport: T,
    rx_buf: [u8; 512],
    rx_len: usize,
}

impl<const SUB_CAP: usize, const PREFIX_CAP: usize, const FRAME_CAP: usize, T>
    Driver<SUB_CAP, PREFIX_CAP, FRAME_CAP, T>
where
    T: Read + Write,
{
    /// Create a new driver. Sends our greeting immediately.
    pub async fn new(mut transport: T) -> Result<Self, ConnError> {
        let mut conn = Connection::new();

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .await
            .map_err(|e| ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            conn,
            transport,
            rx_buf: [0u8; 512],
            rx_len: 0,
        })
    }

    /// Drive the connection one step. Returns `Ok(true)` when the connection
    /// is `Established`.
    pub async fn poll(&mut self) -> Result<bool, ConnError> {
        if *self.conn.state() == State::Ready {
            let mut ready = [0u8; 32];
            match self.conn.write_ready(&mut ready) {
                Ok(n) => {
                    self.transport
                        .write_all(&ready[..n])
                        .await
                        .map_err(|e| ConnError::IoError(e.kind() as usize))?;
                    // Don't process peer's READY in the same poll — defer to
                    // the next call so our READY is on the wire first
                    // (NULL mechanism deadlock rule).
                    return Ok(false);
                }
                Err(ConnError::WrongState) => {
                    // Already sent.
                }
                Err(e) => return Err(e),
            }
        }

        if self.rx_len > 0 {
            self.drain_buffer().await?;
            return Ok(*self.conn.state() == State::Established);
        }

        match self.transport.read(&mut self.rx_buf[self.rx_len..]).await {
            Ok(0) => Err(ConnError::IoError(0)),
            Ok(n) => {
                self.rx_len += n;
                self.drain_buffer().await?;
                Ok(*self.conn.state() == State::Established)
            }
            Err(e) => Err(ConnError::IoError(e.kind() as usize)),
        }
    }

    async fn drain_buffer(&mut self) -> Result<(), ConnError> {
        let mut total_consumed = 0;
        while total_consumed < self.rx_len {
            let was_ready_before = *self.conn.state() == State::Ready;
            match self.conn.feed(&self.rx_buf[total_consumed..self.rx_len]) {
                Ok(consumed) => {
                    total_consumed += consumed;

                    // Send greeting rest if we received peer's partial but haven't sent ours
                    if self.conn.greeting_rest_pending() {
                        let mut rest = [0u8; 64];
                        match self.conn.write_greeting_rest(&mut rest) {
                            Ok(n) => {
                                self.transport
                                    .write_all(&rest[..n])
                                    .await
                                    .map_err(|e| ConnError::IoError(e.kind() as usize))?;
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    if *self.conn.state() == State::Ready && !was_ready_before {
                        let mut ready = [0u8; 32];
                        match self.conn.write_ready(&mut ready) {
                            Ok(n) => {
                                self.transport
                                    .write_all(&ready[..n])
                                    .await
                                    .map_err(|e| ConnError::IoError(e.kind() as usize))?;
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    // Send PONG if PING was received
                    let mut pong_buf = [0u8; 23];
                    if let Some(n) = self.conn.write_pong(&mut pong_buf)? {
                        self.transport
                            .write_all(&pong_buf[..n])
                            .await
                            .map_err(|e| ConnError::IoError(e.kind() as usize))?;
                    }

                    if consumed == 0 {
                        break;
                    }
                }
                Err(e) => {
                    if *self.conn.state() == State::Failed {
                        let mut err_buf = [0u8; 32];
                        if let Ok(n) = self.conn.write_error(&mut err_buf) {
                            let _ = self.transport.write_all(&err_buf[..n]).await;
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
    pub async fn publish(&mut self, topic: &[u8], payload: &[u8]) -> Result<usize, ConnError> {
        let Some((th, th_n, ph, ph_n)) = self.conn.publish_headers(topic, payload)? else {
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
    use crate::test_helpers::{
        async_mock::MockTransport, pub_ready, sub_greeting, sub_ready, sub_subscribe,
    };

    extern crate alloc;

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
    async fn driver_sends_partial_greeting_first() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&sub_greeting());
        peer_bytes.extend_from_slice(&sub_ready());

        let transport = MockTransport::new(peer_bytes);
        let driver = Driver::<8, 32, 512, _>::new(transport).await.unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 11);
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
                Err(e) => panic!("poll failed: {:?}", e),
            }
        }

        assert!(established);
        assert_eq!(*driver.conn.state(), State::Established);

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
}

// ---------------------------------------------------------------------------
// Async RADIO driver (parallel to the PUB Driver above)
// ---------------------------------------------------------------------------

/// Async driver for a ZMTP 3.1 RADIO [`RadioConnection`].
///
/// Generic parameters mirror [`RadioConnection`]:
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
    /// Create a new async RADIO driver. Sends our greeting immediately.
    pub async fn new(mut transport: T) -> Result<Self, crate::radio_connection::ConnError> {
        let mut conn = crate::radio_connection::RadioConnection::new();

        let mut greeting = [0u8; 64];
        let n = conn.write_greeting(&mut greeting)?;
        transport
            .write_all(&greeting[..n])
            .await
            .map_err(|e| crate::radio_connection::ConnError::IoError(e.kind() as usize))?;

        Ok(Self {
            conn,
            transport,
            rx_buf: [0u8; 512],
            rx_len: 0,
        })
    }

    /// Drive the connection one step. Returns `Ok(true)` when the connection
    /// is `Established`.
    pub async fn poll(&mut self) -> Result<bool, crate::radio_connection::ConnError> {
        use crate::radio_connection::State;

        if *self.conn.state() == State::Ready {
            let mut ready = [0u8; 32];
            match self.conn.write_ready(&mut ready) {
                Ok(n) => {
                    self.transport.write_all(&ready[..n]).await.map_err(|e| {
                        crate::radio_connection::ConnError::IoError(e.kind() as usize)
                    })?;
                    return Ok(false);
                }
                Err(crate::radio_connection::ConnError::WrongState) => {}
                Err(e) => return Err(e),
            }
        }

        if self.rx_len > 0 {
            self.drain_buffer().await?;
            return Ok(*self.conn.state() == State::Established);
        }

        match self.transport.read(&mut self.rx_buf[self.rx_len..]).await {
            Ok(0) => Err(crate::radio_connection::ConnError::IoError(0)),
            Ok(n) => {
                self.rx_len += n;
                self.drain_buffer().await?;
                Ok(*self.conn.state() == State::Established)
            }
            Err(e) => Err(crate::radio_connection::ConnError::IoError(
                e.kind() as usize
            )),
        }
    }

    async fn drain_buffer(&mut self) -> Result<(), crate::radio_connection::ConnError> {
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
                                self.transport.write_all(&rest[..n]).await.map_err(|e| {
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
                                self.transport.write_all(&ready[..n]).await.map_err(|e| {
                                    crate::radio_connection::ConnError::IoError(e.kind() as usize)
                                })?;
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }

                    let mut pong_buf = [0u8; 23];
                    if let Some(n) = self.conn.write_pong(&mut pong_buf)? {
                        self.transport
                            .write_all(&pong_buf[..n])
                            .await
                            .map_err(|e| {
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
                            let _ = self.transport.write_all(&err_buf[..n]).await;
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
    pub async fn publish(
        &mut self,
        group: &[u8],
        body: &[u8],
    ) -> Result<usize, crate::radio_connection::ConnError> {
        let Some((gh, gh_n, bh, bh_n)) = self.conn.publish_headers(group, body)? else {
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
    async fn radio_driver_sends_partial_greeting_first() {
        let mut peer_bytes = alloc::vec::Vec::new();
        peer_bytes.extend_from_slice(&dish_greeting());
        peer_bytes.extend_from_slice(&dish_ready());

        let transport = MockTransport::new(peer_bytes);
        let driver = RadioDriver::<8, 32, 512, _>::new(transport).await.unwrap();

        let written = driver.transport.written();
        assert_eq!(written.len(), 11);
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
                Err(e) => panic!("poll failed: {:?}", e),
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
}
