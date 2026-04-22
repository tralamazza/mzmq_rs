/// Maximum header overhead: 9 bytes (long frame)
pub const MAX_FRAME_HEADER: usize = 9;

#[derive(Debug, PartialEq)]
pub enum FrameError {
    BufferTooSmall,
    ReservedFlagBits,
}

/// Writes a MESSAGE frame header into `buf[..header_len]`.
/// Returns Ok(header_len) on success, Err if buf too small or flags are invalid.
pub fn encode_message_frame(
    buf: &mut [u8],
    body_len: usize,
    more: bool,
) -> Result<usize, FrameError> {
    let more_bit: u8 = if more { 0x01 } else { 0x00 };
    if body_len <= 255 {
        if buf.len() < 2 {
            return Err(FrameError::BufferTooSmall);
        }
        buf[0] = more_bit; // flags: LONG=0, COMMAND=0
        buf[1] = body_len as u8;
        Ok(2)
    } else {
        if buf.len() < 9 {
            return Err(FrameError::BufferTooSmall);
        }
        buf[0] = 0x02 | more_bit; // flags: LONG=1, COMMAND=0
        let size_bytes = (body_len as u64).to_be_bytes();
        buf[1..9].copy_from_slice(&size_bytes);
        Ok(9)
    }
}

/// Writes a COMMAND frame header into `buf[..header_len]`.
/// Returns Ok(header_len). Body must be written by the caller after the header.
pub fn encode_command_frame(buf: &mut [u8], body_len: usize) -> Result<usize, FrameError> {
    if body_len <= 255 {
        if buf.len() < 2 {
            return Err(FrameError::BufferTooSmall);
        }
        buf[0] = 0x04; // flags: LONG=0, COMMAND=1, MORE=0
        buf[1] = body_len as u8;
        Ok(2)
    } else {
        if buf.len() < 9 {
            return Err(FrameError::BufferTooSmall);
        }
        buf[0] = 0x06; // flags: LONG=1, COMMAND=1, MORE=0
        let size_bytes = (body_len as u64).to_be_bytes();
        buf[1..9].copy_from_slice(&size_bytes);
        Ok(9)
    }
}

/// Errors returned by [`FrameDecoder::feed`].
pub mod decode_error {
    #[derive(Debug, PartialEq)]
    pub enum DecodeError {
        /// Flags byte had reserved bits (3-7) set.
        ReservedFlagBits,
        /// Decoded body length exceeds the decoder's fixed capacity `CAP`.
        BodyTooLarge,
        /// Frame ended mid-header (reserved for future use).
        Truncated,
    }
}

use decode_error::DecodeError;

/// A fully decoded frame. The body borrows from the decoder's internal buffer.
#[derive(Debug, PartialEq)]
pub struct DecodedFrame<'a> {
    pub more: bool,
    pub is_command: bool,
    pub body: &'a [u8],
}

/// Internal state machine stages.
enum State {
    /// Waiting for the flags byte.
    NeedFlags,
    /// Flags received. `long` indicates whether we need 1 or 8 size bytes.
    /// `size_buf` accumulates the size bytes; `size_pos` is how many have arrived.
    NeedSize {
        more: bool,
        is_command: bool,
        long: bool,
        size_buf: [u8; 8],
        size_pos: usize,
    },
    /// Size known; accumulating body bytes. `remaining` is how many are still needed.
    NeedBody {
        more: bool,
        is_command: bool,
        remaining: usize,
    },
    /// A decode error has occurred; the decoder is poisoned.
    Poisoned,
}

/// Streaming ZMTP frame decoder. Generic over a fixed body-buffer capacity `CAP`.
///
/// Call [`feed`](FrameDecoder::feed) repeatedly with incoming bytes; it returns a
/// [`DecodedFrame`] once a complete frame has been received, then resets itself.
pub struct FrameDecoder<const CAP: usize> {
    state: State,
    buf: [u8; CAP],
    buf_pos: usize,
}

impl<const CAP: usize> FrameDecoder<CAP> {
    /// Create a new decoder in its initial state.
    pub const fn new() -> Self {
        Self {
            state: State::NeedFlags,
            buf: [0u8; CAP],
            buf_pos: 0,
        }
    }
}

impl<const CAP: usize> Default for FrameDecoder<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> FrameDecoder<CAP> {
    /// Reset to initial state, ready to decode a new frame.
    pub fn reset(&mut self) {
        self.state = State::NeedFlags;
        self.buf_pos = 0;
    }

    /// Feed bytes into the decoder.
    ///
    /// Returns:
    /// - `Ok((consumed, Some(frame)))` — frame is complete; `consumed` bytes were used.
    /// - `Ok((consumed, None))` — more bytes needed; all `input` bytes were consumed.
    /// - `Err(DecodeError)` — invalid frame; decoder is now poisoned.
    pub fn feed<'a>(
        &'a mut self,
        input: &[u8],
    ) -> Result<(usize, Option<DecodedFrame<'a>>), DecodeError> {
        let mut pos = 0usize;

        loop {
            if pos >= input.len() {
                return Ok((pos, None));
            }

            match &mut self.state {
                State::Poisoned => {
                    // Propagate the last error type — but we don't store the original error.
                    // Callers are supposed to discard the decoder after an error; returning
                    // ReservedFlagBits is a safe sentinel.
                    return Err(DecodeError::ReservedFlagBits);
                }

                State::NeedFlags => {
                    let flags = input[pos];
                    pos += 1;
                    if flags & 0xF8 != 0 {
                        self.state = State::Poisoned;
                        return Err(DecodeError::ReservedFlagBits);
                    }
                    let more = (flags & 0x01) != 0;
                    let long = (flags & 0x02) != 0;
                    let is_command = (flags & 0x04) != 0;
                    self.state = State::NeedSize {
                        more,
                        is_command,
                        long,
                        size_buf: [0u8; 8],
                        size_pos: 0,
                    };
                }

                State::NeedSize {
                    more,
                    is_command,
                    long,
                    size_buf,
                    size_pos,
                } => {
                    let size_needed = if *long { 8 } else { 1 };
                    while *size_pos < size_needed && pos < input.len() {
                        size_buf[*size_pos] = input[pos];
                        *size_pos += 1;
                        pos += 1;
                    }
                    if *size_pos < size_needed {
                        return Ok((pos, None));
                    }
                    // All size bytes have arrived.
                    let body_len = if *long {
                        u64::from_be_bytes(*size_buf) as usize
                    } else {
                        size_buf[0] as usize
                    };
                    if body_len > CAP {
                        self.state = State::Poisoned;
                        return Err(DecodeError::BodyTooLarge);
                    }
                    let more = *more;
                    let is_command = *is_command;
                    if body_len == 0 {
                        // Zero-length body — frame is immediately complete.
                        self.buf_pos = 0;
                        self.state = State::NeedFlags;
                        return Ok((
                            pos,
                            Some(DecodedFrame {
                                more,
                                is_command,
                                body: &self.buf[..0],
                            }),
                        ));
                    }
                    self.buf_pos = 0;
                    self.state = State::NeedBody {
                        more,
                        is_command,
                        remaining: body_len,
                    };
                }

                State::NeedBody {
                    more,
                    is_command,
                    remaining,
                } => {
                    let available = input.len() - pos;
                    let to_copy = available.min(*remaining);
                    self.buf[self.buf_pos..self.buf_pos + to_copy]
                        .copy_from_slice(&input[pos..pos + to_copy]);
                    self.buf_pos += to_copy;
                    *remaining -= to_copy;
                    pos += to_copy;

                    if *remaining == 0 {
                        let body_end = self.buf_pos;
                        let more = *more;
                        let is_command = *is_command;
                        self.state = State::NeedFlags;
                        self.buf_pos = 0;
                        return Ok((
                            pos,
                            Some(DecodedFrame {
                                more,
                                is_command,
                                body: &self.buf[..body_end],
                            }),
                        ));
                    }
                    // Still waiting for more body bytes.
                    return Ok((pos, None));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DecodedFrame, FrameDecoder, FrameError, decode_error::DecodeError, encode_command_frame,
        encode_message_frame,
    };

    #[test]
    fn short_message_last_frame_header() {
        let mut buf = [0u8; 9];
        let result = encode_message_frame(&mut buf, 6, false);
        assert_eq!(result, Ok(2));
        assert_eq!(&buf[..2], &[0x00, 0x06]);
    }

    #[test]
    fn short_message_more_frame_header() {
        let mut buf = [0u8; 9];
        let result = encode_message_frame(&mut buf, 3, true);
        assert_eq!(result, Ok(2));
        assert_eq!(&buf[..2], &[0x01, 0x03]);
    }

    #[test]
    fn short_frame_max_body_255() {
        let mut buf = [0u8; 9];
        let result = encode_message_frame(&mut buf, 255, false);
        assert_eq!(result, Ok(2));
        assert_eq!(&buf[..2], &[0x00, 0xFF]);
    }

    #[test]
    fn long_frame_body_256_switches_to_long() {
        let mut buf = [0u8; 9];
        let result = encode_message_frame(&mut buf, 256, false);
        assert_eq!(result, Ok(9));
        assert_eq!(buf[0], 0x02);
        assert_eq!(&buf[1..9], &[0, 0, 0, 0, 0, 0, 1, 0]);
    }

    #[test]
    fn long_frame_body_65536() {
        let mut buf = [0u8; 9];
        let result = encode_message_frame(&mut buf, 65536, false);
        assert_eq!(result, Ok(9));
        assert_eq!(buf[0], 0x02);
        let size = u64::from_be_bytes(buf[1..9].try_into().unwrap());
        assert_eq!(size, 65536u64);
    }

    #[test]
    fn long_frame_more_flag() {
        let mut buf = [0u8; 9];
        let result = encode_message_frame(&mut buf, 300, true);
        assert_eq!(result, Ok(9));
        assert_eq!(buf[0], 0x03);
    }

    #[test]
    fn command_frame_short() {
        let mut buf = [0u8; 9];
        let result = encode_command_frame(&mut buf, 25);
        assert_eq!(result, Ok(2));
        assert_eq!(&buf[..2], &[0x04, 0x19]);
    }

    #[test]
    fn command_frame_long() {
        let mut buf = [0u8; 9];
        let result = encode_command_frame(&mut buf, 300);
        assert_eq!(result, Ok(9));
        assert_eq!(buf[0], 0x06);
        let size = u64::from_be_bytes(buf[1..9].try_into().unwrap());
        assert_eq!(size, 300u64);
    }

    #[test]
    fn message_frame_buffer_too_small_short() {
        let mut buf = [0u8; 1];
        let result = encode_message_frame(&mut buf, 10, false);
        assert_eq!(result, Err(FrameError::BufferTooSmall));
    }

    #[test]
    fn message_frame_buffer_too_small_long() {
        let mut buf = [0u8; 8];
        let result = encode_message_frame(&mut buf, 256, false);
        assert_eq!(result, Err(FrameError::BufferTooSmall));
    }

    #[test]
    fn encode_pub_message_topic_and_payload() {
        let mut buf = [0u8; 9];

        // First frame: topic "foo", more=true
        let r1 = encode_message_frame(&mut buf, b"foo".len(), true);
        assert_eq!(r1, Ok(2));
        assert_eq!(&buf[..2], &[0x01, 0x03]);

        // Second frame: payload "bar", more=false
        let r2 = encode_message_frame(&mut buf, b"bar".len(), false);
        assert_eq!(r2, Ok(2));
        assert_eq!(&buf[..2], &[0x00, 0x03]);
    }

    // ---- FrameDecoder tests (M4) ----

    #[test]
    fn decode_short_message_frame_all_at_once() {
        let mut dec: FrameDecoder<64> = FrameDecoder::new();
        let input = [0x00u8, 0x06, b'f', b'o', b'o', b'b', b'a', b'r'];
        let result = dec.feed(&input);
        assert_eq!(
            result,
            Ok((
                8,
                Some(DecodedFrame {
                    more: false,
                    is_command: false,
                    body: b"foobar"
                })
            ))
        );
    }

    #[test]
    fn decode_short_command_frame_all_at_once() {
        // READY command: flags=0x04, size=0x19 (25), body = [0x05, 'R','E','A','D','Y', ...metadata...]
        // Full 27-byte READY frame as produced by M2 greeting/null handshake
        let mut frame = [0u8; 27];
        frame[0] = 0x04; // flags: COMMAND=1
        frame[1] = 0x19; // size = 25
        // body: name-len(1)=5, "READY"(5), no properties = 6 bytes... but size=25 means 25 body bytes
        // Construct: 0x05 'R' 'E' 'A' 'D' 'Y' followed by 19 zero bytes (empty metadata)
        frame[2] = 0x05; // name length
        frame[3] = b'R';
        frame[4] = b'E';
        frame[5] = b'A';
        frame[6] = b'D';
        frame[7] = b'Y';
        // remaining 19 bytes of body are 0x00 (already zeroed)
        let mut dec: FrameDecoder<64> = FrameDecoder::new();
        let result = dec.feed(&frame);
        let expected_body: &[u8] = &frame[2..27];
        assert_eq!(
            result,
            Ok((
                27,
                Some(DecodedFrame {
                    more: false,
                    is_command: true,
                    body: expected_body
                })
            ))
        );
    }

    #[test]
    fn decode_short_message_byte_by_byte() {
        let mut dec: FrameDecoder<64> = FrameDecoder::new();
        let input = [0x00u8, 0x06, b'f', b'o', b'o', b'b', b'a', b'r'];
        for &byte in &input[..input.len() - 1] {
            let result = dec.feed(core::slice::from_ref(&byte));
            assert_eq!(result, Ok((1, None)));
        }
        // last byte should complete the frame
        let last = dec.feed(&input[input.len() - 1..]);
        assert_eq!(
            last,
            Ok((
                1,
                Some(DecodedFrame {
                    more: false,
                    is_command: false,
                    body: b"foobar"
                })
            ))
        );
    }

    #[test]
    fn decode_long_frame_header_then_body() {
        let body_len: usize = 256;
        let mut buf = [0u8; 9 + 256];
        buf[0] = 0x02; // flags: LONG=1, COMMAND=0, MORE=0
        let size_bytes = (body_len as u64).to_be_bytes();
        buf[1..9].copy_from_slice(&size_bytes);
        for i in 0..body_len {
            buf[9 + i] = (i & 0xFF) as u8;
        }
        let mut dec: FrameDecoder<512> = FrameDecoder::new();
        let result = dec.feed(&buf);
        match result {
            Ok((consumed, Some(frame))) => {
                assert_eq!(consumed, 9 + body_len);
                assert!(!frame.more);
                assert!(!frame.is_command);
                assert_eq!(frame.body.len(), body_len);
                for i in 0..body_len {
                    assert_eq!(frame.body[i], (i & 0xFF) as u8);
                }
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn decode_more_flag_set() {
        let mut dec: FrameDecoder<64> = FrameDecoder::new();
        let input = [0x01u8, 0x03, b'f', b'o', b'o'];
        let result = dec.feed(&input);
        assert_eq!(
            result,
            Ok((
                5,
                Some(DecodedFrame {
                    more: true,
                    is_command: false,
                    body: b"foo"
                })
            ))
        );
    }

    #[test]
    fn decode_rejects_reserved_flag_bits() {
        let mut dec: FrameDecoder<64> = FrameDecoder::new();
        let input = [0x08u8, 0x01, 0x00]; // bit 3 set in flags
        let result = dec.feed(&input);
        assert_eq!(result, Err(DecodeError::ReservedFlagBits));
    }

    #[test]
    fn decode_rejects_body_exceeding_capacity() {
        let mut dec: FrameDecoder<4> = FrameDecoder::new();
        // short frame with body_len=5, exceeds CAP=4
        let input = [0x00u8, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let result = dec.feed(&input);
        assert_eq!(result, Err(DecodeError::BodyTooLarge));
    }

    #[test]
    fn decode_two_frames_sequential() {
        let mut dec: FrameDecoder<64> = FrameDecoder::new();
        let frame1 = [0x00u8, 0x03, b'o', b'n', b'e'];
        let frame2 = [0x00u8, 0x03, b't', b'w', b'o'];
        let r1 = dec.feed(&frame1);
        assert_eq!(
            r1,
            Ok((
                5,
                Some(DecodedFrame {
                    more: false,
                    is_command: false,
                    body: b"one"
                })
            ))
        );
        let r2 = dec.feed(&frame2);
        assert_eq!(
            r2,
            Ok((
                5,
                Some(DecodedFrame {
                    more: false,
                    is_command: false,
                    body: b"two"
                })
            ))
        );
    }

    #[test]
    fn decode_partial_then_complete() {
        let mut dec: FrameDecoder<64> = FrameDecoder::new();
        // header only (flags + size), no body
        let header = [0x00u8, 0x04];
        let r1 = dec.feed(&header);
        assert_eq!(r1, Ok((2, None)));
        // now feed body
        let body = [b'd', b'a', b't', b'a'];
        let r2 = dec.feed(&body);
        assert_eq!(
            r2,
            Ok((
                4,
                Some(DecodedFrame {
                    more: false,
                    is_command: false,
                    body: b"data"
                })
            ))
        );
    }
}
