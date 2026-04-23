//! Synchronous (blocking) IO adapter for `Connection`.
//!
//! `Driver` wraps a `Connection` and a transport implementing
//! `embedded_io::Read + Write`, drives the handshake, and exposes a
//! `publish` method.

use crate::connection::{ConnError, Connection, State};
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

    /// Drive the connection one step. Blocks on `transport.read` when there is
    /// no buffered data left to process. Returns `Ok(true)` when the connection
    /// is `Established`.
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
                Err(ConnError::WrongState) => {
                    // Already sent.
                }
                Err(e) => return Err(e),
            }
        }

        if self.rx_len > 0 {
            self.drain_buffer()?;
            return Ok(*self.conn.state() == State::Established);
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
        let mut total_consumed = 0;
        while total_consumed < self.rx_len {
            let was_ready_before = *self.conn.state() == State::Ready;
            match self.conn.feed(&self.rx_buf[total_consumed..self.rx_len]) {
                Ok(consumed) => {
                    total_consumed += consumed;

                    if *self.conn.state() == State::Ready && !was_ready_before {
                        let mut ready = [0u8; 32];
                        match self.conn.write_ready(&mut ready) {
                            Ok(n) => {
                                self.transport
                                    .write_all(&ready[..n])
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
                            .map_err(|e| ConnError::IoError(e.kind() as usize))?;
                    }

                    if consumed == 0 {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if total_consumed > 0 {
            self.rx_buf.copy_within(total_consumed..self.rx_len, 0);
            self.rx_len -= total_consumed;
        }
        Ok(())
    }

    /// Publish a message. Returns 0 if no peer subscription matches.
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
    use crate::test_helpers::{pub_ready, sub_greeting, sub_ready};
    use embedded_io::ErrorKind;

    /// Minimal in-memory transport implementing `embedded_io::Read + Write`.
    /// Returns `Ok(0)` when peer bytes are exhausted (treated as EOF by the driver).
    struct MockTransport {
        peer_bytes: alloc::vec::Vec<u8>,
        peer_pos: usize,
        our_bytes: alloc::vec::Vec<u8>,
    }

    extern crate alloc;

    impl MockTransport {
        fn new(peer_bytes: alloc::vec::Vec<u8>) -> Self {
            Self {
                peer_bytes,
                peer_pos: 0,
                our_bytes: alloc::vec::Vec::new(),
            }
        }

        fn written(&self) -> &[u8] {
            &self.our_bytes
        }
    }

    impl embedded_io::ErrorType for MockTransport {
        type Error = ErrorKind;
    }

    impl Read for MockTransport {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.peer_pos >= self.peer_bytes.len() {
                return Ok(0);
            }
            let to_copy = core::cmp::min(buf.len(), self.peer_bytes.len() - self.peer_pos);
            buf[..to_copy]
                .copy_from_slice(&self.peer_bytes[self.peer_pos..self.peer_pos + to_copy]);
            self.peer_pos += to_copy;
            Ok(to_copy)
        }
    }

    impl Write for MockTransport {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.our_bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    // ZMTP 3.1 SUBSCRIBE command frame for the given prefix.
    fn sub_subscribe(prefix: &[u8]) -> alloc::vec::Vec<u8> {
        let name = b"SUBSCRIBE";
        let body_len = 1 + name.len() + prefix.len();
        let mut f = alloc::vec::Vec::new();
        f.push(0x04);
        f.push(body_len as u8);
        f.push(name.len() as u8);
        f.extend_from_slice(name);
        f.extend_from_slice(prefix);
        f
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
                Err(e) => panic!("poll failed: {:?}", e),
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
}
