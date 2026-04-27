//! Adapter to use a [`smoltcp::socket::tcp::Socket`] as an [`embedded_io`]
//! transport.
//!
//! Enable the `smoltcp` feature to use this module:
//!
//! ```toml
//! [dependencies]
//! mzmq = { version = "0.1", features = ["smoltcp"] }
//! ```
//!
//! The [`TcpAdapter`] wraps a borrowed smoltcp TCP socket and implements
//! `embedded_io::Read + Write`. Because smoltcp sockets are managed through a
//! [`SocketSet`](smoltcp::iface::SocketSet), the adapter borrows the socket
//! mutably. The caller is responsible for calling
//! [`Interface::poll`](smoltcp::iface::Interface::poll) regularly to drive the
//! TCP state machine and drain socket buffers.
//!
//! When the transmit buffer is full,
//! [`write`](embedded_io::Write::write) returns `Ok(0)`. Call
//! `Interface::poll` to drain the buffer before retrying.

use embedded_io::{ErrorKind, ErrorType, Read, Write};

/// Wraps a borrowed smoltcp TCP socket to implement `embedded_io::Read + Write`.
///
/// See the [module-level documentation](self) for usage notes.
pub struct TcpAdapter<'a>(pub &'a mut smoltcp::socket::tcp::Socket<'a>);

/// Error type for [`TcpAdapter`].
#[derive(Debug)]
pub enum Error {
    /// Transmit error from the underlying TCP socket.
    Send(smoltcp::socket::tcp::SendError),
    /// Receive error from the underlying TCP socket.
    Recv(smoltcp::socket::tcp::RecvError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Send(e) => write!(f, "smoltcp send error: {e}"),
            Self::Recv(e) => write!(f, "smoltcp recv error: {e}"),
        }
    }
}

impl core::error::Error for Error {}

impl embedded_io::Error for Error {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Send(_) => ErrorKind::Other,
            Self::Recv(e) => match e {
                smoltcp::socket::tcp::RecvError::Finished => ErrorKind::BrokenPipe,
                smoltcp::socket::tcp::RecvError::InvalidState => ErrorKind::NotConnected,
            },
        }
    }
}

impl ErrorType for TcpAdapter<'_> {
    type Error = Error;
}

impl Read for TcpAdapter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.recv_slice(buf).map_err(Error::Recv)
    }
}

impl Write for TcpAdapter<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.send_slice(buf).map_err(Error::Send)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(all(test, feature = "smoltcp"))]
mod tests {
    use super::*;
    use embedded_io::Error as _;

    extern crate alloc;

    #[test]
    fn error_send_kind_is_other() {
        let e = Error::Send(smoltcp::socket::tcp::SendError::InvalidState);
        assert_eq!(e.kind(), ErrorKind::Other);
    }

    #[test]
    fn error_recv_invalid_state_kind_is_not_connected() {
        let e = Error::Recv(smoltcp::socket::tcp::RecvError::InvalidState);
        assert_eq!(e.kind(), ErrorKind::NotConnected);
    }

    #[test]
    fn error_recv_finished_kind_is_broken_pipe() {
        let e = Error::Recv(smoltcp::socket::tcp::RecvError::Finished);
        assert_eq!(e.kind(), ErrorKind::BrokenPipe);
    }

    #[test]
    fn error_display_is_non_empty() {
        let e = Error::Send(smoltcp::socket::tcp::SendError::InvalidState);
        assert!(!alloc::format!("{e}").is_empty());
        let e = Error::Recv(smoltcp::socket::tcp::RecvError::InvalidState);
        assert!(!alloc::format!("{e}").is_empty());
    }

    #[test]
    fn read_on_fresh_socket_returns_invalid_state() {
        let mut rx_storage = [0u8; 64];
        let mut tx_storage = [0u8; 64];
        let mut socket = smoltcp::socket::tcp::Socket::new(
            smoltcp::storage::RingBuffer::new(&mut rx_storage[..]),
            smoltcp::storage::RingBuffer::new(&mut tx_storage[..]),
        );
        let mut adapter = TcpAdapter(&mut socket);
        let mut buf = [0u8; 32];
        let result = adapter.read(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotConnected);
    }

    #[test]
    fn write_on_fresh_socket_returns_invalid_state() {
        let mut rx_storage = [0u8; 64];
        let mut tx_storage = [0u8; 64];
        let mut socket = smoltcp::socket::tcp::Socket::new(
            smoltcp::storage::RingBuffer::new(&mut rx_storage[..]),
            smoltcp::storage::RingBuffer::new(&mut tx_storage[..]),
        );
        let mut adapter = TcpAdapter(&mut socket);
        let result = adapter.write(b"hello");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Other);
    }

    #[test]
    fn flush_succeeds() {
        let mut rx_storage = [0u8; 64];
        let mut tx_storage = [0u8; 64];
        let mut socket = smoltcp::socket::tcp::Socket::new(
            smoltcp::storage::RingBuffer::new(&mut rx_storage[..]),
            smoltcp::storage::RingBuffer::new(&mut tx_storage[..]),
        );
        let mut adapter = TcpAdapter(&mut socket);
        assert!(adapter.flush().is_ok());
    }
}
