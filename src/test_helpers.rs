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
#[cfg(any(feature = "sync", feature = "async"))]
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
#[cfg(any(feature = "sync", feature = "async"))]
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
#[cfg(any(feature = "sync", feature = "async"))]
#[allow(clippy::cast_possible_truncation)]
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
#[cfg(any(feature = "sync", feature = "async"))]
#[allow(clippy::cast_possible_truncation)]
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

/// 64-byte ZMTP 3.1 PLAIN greeting as a SUB peer (client role, `as_server=0`) would send it.
#[cfg(feature = "plain")]
pub(crate) fn plain_sub_greeting() -> [u8; 64] {
    let mut g = [0u8; 64];
    g[0] = 0xFF;
    g[9] = 0x7F;
    g[10] = 0x03;
    g[11] = 0x01;
    g[12] = b'P';
    g[13] = b'L';
    g[14] = b'A';
    g[15] = b'I';
    g[16] = b'N';
    // bytes 17–31: mechanism padding = 0x00
    // byte 32: as_server = 0x00 (client role)
    g
}

/// Build a ZMTP 3.1 PLAIN HELLO command frame with the given credentials.
#[cfg(feature = "plain")]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn plain_hello(username: &[u8], password: &[u8]) -> alloc::vec::Vec<u8> {
    // name_len(1) + "HELLO"(5) + ulen(1) + username + plen(1) + password
    let body_len = 1 + 5 + 1 + username.len() + 1 + password.len();
    let mut f = alloc::vec::Vec::new();
    f.push(0x04u8);
    f.push(body_len as u8);
    f.push(5u8);
    f.extend_from_slice(b"HELLO");
    f.push(username.len() as u8);
    f.extend_from_slice(username);
    f.push(password.len() as u8);
    f.extend_from_slice(password);
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

    /// Delivers peer bytes one at a time for testing partial-read drain-buffer
    /// paths (consumed==0, buffer management).
    pub struct ChunkedReadTransport {
        peer_bytes: alloc::vec::Vec<u8>,
        peer_pos: usize,
    }

    impl ChunkedReadTransport {
        pub fn new(peer_bytes: alloc::vec::Vec<u8>) -> Self {
            Self {
                peer_bytes,
                peer_pos: 0,
            }
        }
    }

    impl embedded_io::ErrorType for ChunkedReadTransport {
        type Error = ErrorKind;
    }

    impl Read for ChunkedReadTransport {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.peer_pos >= self.peer_bytes.len() {
                return Ok(0);
            }
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.peer_bytes[self.peer_pos];
            self.peer_pos += 1;
            Ok(1)
        }
    }

    impl Write for ChunkedReadTransport {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Succeeds for `fail_after` writes, then returns `BrokenPipe` on writes.
    /// Used to test transport write-error propagation.
    pub struct WriteFailTransport {
        peer_bytes: alloc::vec::Vec<u8>,
        peer_pos: usize,
        our_bytes: alloc::vec::Vec<u8>,
        write_count: usize,
        fail_after: usize,
    }

    impl WriteFailTransport {
        pub fn new(peer_bytes: alloc::vec::Vec<u8>, fail_after: usize) -> Self {
            Self {
                peer_bytes,
                peer_pos: 0,
                our_bytes: alloc::vec::Vec::new(),
                write_count: 0,
                fail_after,
            }
        }
    }

    impl embedded_io::ErrorType for WriteFailTransport {
        type Error = ErrorKind;
    }

    impl Read for WriteFailTransport {
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

    impl Write for WriteFailTransport {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.write_count += 1;
            if self.write_count > self.fail_after {
                return Err(ErrorKind::BrokenPipe);
            }
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
