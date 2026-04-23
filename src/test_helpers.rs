//! Shared byte-level fixtures for unit tests across modules.

/// 64-byte ZMTP 3.1 NULL greeting as a SUB peer would send it.
pub(crate) fn sub_greeting() -> [u8; 64] {
    let mut g = [0u8; 64];
    g[0] = 0xFF;
    g[9] = 0x7F;
    g[10] = 0x03;
    g[11] = 0x01;
    g[12] = b'N';
    g[13] = b'U';
    g[14] = b'L';
    g[15] = b'L';
    g
}

/// 27-byte READY command frame with `Socket-Type = SUB`.
pub(crate) fn sub_ready() -> [u8; 27] {
    [
        0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65, 0x74,
        0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x53, 0x55, 0x42,
    ]
}

/// 27-byte READY command frame with `Socket-Type = PUB` (what this library emits).
pub(crate) fn pub_ready() -> [u8; 27] {
    [
        0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65, 0x74,
        0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x50, 0x55, 0x42,
    ]
}

/// 64-byte ZMTP 3.1 NULL greeting as a DISH peer would send it.
pub(crate) fn dish_greeting() -> [u8; 64] {
    let mut g = [0u8; 64];
    g[0] = 0xFF;
    g[9] = 0x7F;
    g[10] = 0x03;
    g[11] = 0x01;
    g[12] = b'N';
    g[13] = b'U';
    g[14] = b'L';
    g[15] = b'L';
    g
}

/// 28-byte READY command frame with `Socket-Type = DISH`.
pub(crate) fn dish_ready() -> [u8; 28] {
    [
        0x04, 0x1A, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65, 0x74,
        0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x04, 0x44, 0x49, 0x53, 0x48,
    ]
}

/// 29-byte READY command frame with `Socket-Type = RADIO` (what the RADIO library emits).
pub(crate) fn radio_ready() -> [u8; 29] {
    [
        0x04, 0x1B, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65, 0x74,
        0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x05, 0x52, 0x41, 0x44, 0x49, 0x4F,
    ]
}

// ---------------------------------------------------------------------------
// ZMTP command frame builders (used by both sync and async IO tests)
// ---------------------------------------------------------------------------

extern crate alloc;

/// Build a ZMTP 3.1 SUBSCRIBE command frame for the given prefix.
pub(crate) fn sub_subscribe(prefix: &[u8]) -> alloc::vec::Vec<u8> {
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

/// Build a ZMTP 3.1 JOIN command frame for the given group.
pub(crate) fn dish_join(group: &[u8]) -> alloc::vec::Vec<u8> {
    let name = b"JOIN";
    let body_len = 1 + name.len() + group.len();
    let mut f = alloc::vec::Vec::new();
    f.push(0x04);
    f.push(body_len as u8);
    f.push(name.len() as u8);
    f.extend_from_slice(name);
    f.extend_from_slice(group);
    f
}

// ---------------------------------------------------------------------------
// Mock transports (sync / async) shared by IO driver tests
// ---------------------------------------------------------------------------

#[cfg(feature = "sync")]
pub(crate) mod sync_mock {
    use embedded_io::{ErrorKind, Read, Write};
    extern crate alloc;

    pub struct MockTransport {
        peer_bytes: alloc::vec::Vec<u8>,
        peer_pos: usize,
        our_bytes: alloc::vec::Vec<u8>,
    }

    impl MockTransport {
        pub fn new(peer_bytes: alloc::vec::Vec<u8>) -> Self {
            Self {
                peer_bytes,
                peer_pos: 0,
                our_bytes: alloc::vec::Vec::new(),
            }
        }

        pub fn written(&self) -> &[u8] {
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
}

#[cfg(feature = "async")]
pub(crate) mod async_mock {
    use embedded_io_async::{ErrorKind, Read, Write};
    extern crate alloc;

    pub struct MockTransport {
        peer_bytes: alloc::vec::Vec<u8>,
        peer_pos: usize,
        our_bytes: alloc::vec::Vec<u8>,
    }

    impl MockTransport {
        pub fn new(peer_bytes: alloc::vec::Vec<u8>) -> Self {
            Self {
                peer_bytes,
                peer_pos: 0,
                our_bytes: alloc::vec::Vec::new(),
            }
        }

        pub fn written(&self) -> &[u8] {
            &self.our_bytes
        }
    }

    impl embedded_io_async::ErrorType for MockTransport {
        type Error = ErrorKind;
    }

    impl Read for MockTransport {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
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
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.our_bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
