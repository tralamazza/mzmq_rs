// ZMTP NULL security mechanism — READY and ERROR commands (RFC 23)

/// Length of the PUB READY command frame.
pub const READY_LEN: usize = 27;

/// Pre-computed PUB READY frame:
/// flags=0x04, size=0x19, name-size=0x05, "READY",
/// prop name-size=0x0B, "Socket-Type", value-size=0x00000003, "PUB"
pub const READY_FRAME: [u8; READY_LEN] = [
    0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65, 0x74, 0x2D,
    0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x50, 0x55, 0x42,
];

/// Length of the RADIO READY command frame.
pub const RADIO_READY_LEN: usize = 29;

/// Pre-computed RADIO READY frame:
/// flags=0x04, size=0x1B (27), name-size=0x05, "READY",
/// prop name-size=0x0B, "Socket-Type", value-size=0x00000005, "RADIO"
pub const RADIO_READY_FRAME: [u8; RADIO_READY_LEN] = [
    0x04, 0x1B, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65, 0x74, 0x2D,
    0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x05, 0x52, 0x41, 0x44, 0x49, 0x4F,
];

/// Peer socket types we accept as subscribers.
#[derive(Debug, PartialEq)]
pub enum PeerSocketType {
    /// Standard SUB peer.
    Sub,
    /// XSUB (extended SUB, forwards subscriptions upstream).
    Xsub,
    /// DISH peer (RADIO-DISH pattern, RFC 48).
    Dish,
}

/// Errors from NULL mechanism encode/parse operations.
#[derive(Debug, PartialEq)]
pub enum NullError {
    /// Output buffer is too small for the encoded frame.
    BufferTooSmall,
    /// Flags byte has the COMMAND bit (bit 2) clear — this is a message, not a command.
    NotACommand,
    /// Command name is neither "READY" nor "ERROR".
    UnknownCommand,
    /// Peer sent an ERROR command rejecting the handshake.
    PeerError,
    /// Socket-Type property value is not "SUB" or "XSUB".
    WrongSocketType,
    /// Could not parse the Socket-Type metadata property.
    MalformedMetadata,
    /// ERROR `reason` exceeds the 255-byte short-frame body limit.
    ReasonTooLong,
}

/// Encode our PUB READY frame into `buf`.
/// Returns the number of bytes written (`READY_LEN`) or `NullError::BufferTooSmall`.
pub fn encode_ready(buf: &mut [u8]) -> Result<usize, NullError> {
    if buf.len() < READY_LEN {
        return Err(NullError::BufferTooSmall);
    }
    buf[..READY_LEN].copy_from_slice(&READY_FRAME);
    Ok(READY_LEN)
}

/// Encode our RADIO READY frame into `buf`.
/// Returns the number of bytes written (`RADIO_READY_LEN`) or `NullError::BufferTooSmall`.
pub fn encode_ready_radio(buf: &mut [u8]) -> Result<usize, NullError> {
    if buf.len() < RADIO_READY_LEN {
        return Err(NullError::BufferTooSmall);
    }
    buf[..RADIO_READY_LEN].copy_from_slice(&RADIO_READY_FRAME);
    Ok(RADIO_READY_LEN)
}

/// Parse a READY (or ERROR) command frame from raw wire bytes.
/// Returns the peer's socket type if the frame is a valid READY for SUB or XSUB.
pub fn parse_ready(buf: &[u8]) -> Result<PeerSocketType, NullError> {
    if buf.len() < 3 {
        return Err(NullError::MalformedMetadata);
    }

    let is_command = (buf[0] & 0x04) != 0;
    let body_size = buf[1] as usize;
    if buf.len() < 2 + body_size {
        return Err(NullError::MalformedMetadata);
    }
    let body = &buf[2..2 + body_size];

    parse_ready_from(is_command, body)
}

/// Parse a RADIO/DISH READY (or ERROR) command frame from raw wire bytes.
/// Returns the peer's socket type if the frame is a valid READY for DISH.
pub fn parse_ready_radio(buf: &[u8]) -> Result<PeerSocketType, NullError> {
    if buf.len() < 3 {
        return Err(NullError::MalformedMetadata);
    }

    let is_command = (buf[0] & 0x04) != 0;
    let body_size = buf[1] as usize;
    if buf.len() < 2 + body_size {
        return Err(NullError::MalformedMetadata);
    }
    let body = &buf[2..2 + body_size];

    parse_ready_radio_from(is_command, body)
}

/// Parse a READY (or ERROR) command from structured frame data.
/// `is_command` must be true (COMMAND flag bit set). `body` is the frame body.
pub fn parse_ready_from(is_command: bool, body: &[u8]) -> Result<PeerSocketType, NullError> {
    if !is_command {
        return Err(NullError::NotACommand);
    }

    // Parse command name: name-size (1 byte) + name bytes
    if body.is_empty() {
        return Err(NullError::MalformedMetadata);
    }
    let name_len = body[0] as usize;
    if body.len() < 1 + name_len {
        return Err(NullError::MalformedMetadata);
    }
    let name = &body[1..1 + name_len];

    if name == b"ERROR" {
        return Err(NullError::PeerError);
    }
    if name != b"READY" {
        return Err(NullError::UnknownCommand);
    }

    // Parse metadata: sequence of (name-size, name, value-size-4BE, value)
    let mut pos = 1 + name_len;
    while pos < body.len() {
        // prop name-size
        if pos >= body.len() {
            break;
        }
        let prop_name_len = body[pos] as usize;
        pos += 1;
        if pos + prop_name_len > body.len() {
            return Err(NullError::MalformedMetadata);
        }
        let prop_name = &body[pos..pos + prop_name_len];
        pos += prop_name_len;

        // value-size (4 bytes BE)
        if pos + 4 > body.len() {
            return Err(NullError::MalformedMetadata);
        }
        let val_len =
            u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + val_len > body.len() {
            return Err(NullError::MalformedMetadata);
        }
        let val = &body[pos..pos + val_len];
        pos += val_len;

        // Case-insensitive compare for "Socket-Type" (RFC 23 §7.3)
        if prop_name_len == 11 && prop_name.eq_ignore_ascii_case(b"Socket-Type") {
            if val == b"SUB" {
                return Ok(PeerSocketType::Sub);
            } else if val == b"XSUB" {
                return Ok(PeerSocketType::Xsub);
            } else {
                return Err(NullError::WrongSocketType);
            }
        }
    }

    // RFC 37: Socket-Type SHOULD be specified. Absent = unrecognised peer type.
    Err(NullError::WrongSocketType)
}

/// Parse a RADIO/DISH READY (or ERROR) command from structured frame data.
/// `is_command` must be true. `body` is the frame body.
pub fn parse_ready_radio_from(is_command: bool, body: &[u8]) -> Result<PeerSocketType, NullError> {
    if !is_command {
        return Err(NullError::NotACommand);
    }

    if body.is_empty() {
        return Err(NullError::MalformedMetadata);
    }
    let name_len = body[0] as usize;
    if body.len() < 1 + name_len {
        return Err(NullError::MalformedMetadata);
    }
    let name = &body[1..1 + name_len];

    if name == b"ERROR" {
        return Err(NullError::PeerError);
    }
    if name != b"READY" {
        return Err(NullError::UnknownCommand);
    }

    let mut pos = 1 + name_len;
    while pos < body.len() {
        if pos >= body.len() {
            break;
        }
        let prop_name_len = body[pos] as usize;
        pos += 1;
        if pos + prop_name_len > body.len() {
            return Err(NullError::MalformedMetadata);
        }
        let prop_name = &body[pos..pos + prop_name_len];
        pos += prop_name_len;

        if pos + 4 > body.len() {
            return Err(NullError::MalformedMetadata);
        }
        let val_len =
            u32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + val_len > body.len() {
            return Err(NullError::MalformedMetadata);
        }
        let val = &body[pos..pos + val_len];
        pos += val_len;

        if prop_name_len == 11 && prop_name.eq_ignore_ascii_case(b"Socket-Type") {
            if val == b"DISH" {
                return Ok(PeerSocketType::Dish);
            } else {
                return Err(NullError::WrongSocketType);
            }
        }
    }

    Err(NullError::WrongSocketType)
}

/// Encode an ERROR command frame into `buf`.
/// Frame: flags(0x04) + body-size(1) + name-size(0x05) + "ERROR" + reason-len(1) + reason.
/// Returns number of bytes written or `NullError::BufferTooSmall`.
pub fn encode_error(buf: &mut [u8], reason: &[u8]) -> Result<usize, NullError> {
    // body = name-size(1) + "ERROR"(5) + reason-len(1) + reason  [RFC 37: short-size = OCTET]
    let body_size = 1 + 5 + 1 + reason.len();
    if body_size > u8::MAX as usize {
        return Err(NullError::ReasonTooLong);
    }
    let total = 2 + body_size;
    if buf.len() < total {
        return Err(NullError::BufferTooSmall);
    }
    buf[0] = 0x04; // flags: COMMAND
    buf[1] = body_size as u8;
    buf[2] = 0x05; // name-size
    buf[3..8].copy_from_slice(b"ERROR");
    buf[8] = reason.len() as u8;
    buf[9..9 + reason.len()].copy_from_slice(reason);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::{
        NullError, PeerSocketType, RADIO_READY_FRAME, READY_FRAME, encode_error, encode_ready,
        encode_ready_radio, parse_ready, parse_ready_radio,
    };

    // Test 1: READY_FRAME constant matches exact 27-byte PUB sequence
    #[test]
    fn ready_frame_constant_matches_expected_bytes() {
        let expected: [u8; 27] = [
            0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x50, 0x55, 0x42,
        ];
        assert_eq!(READY_FRAME, expected);
    }

    // Test 2: encode_ready writes correct bytes into buffer
    #[test]
    fn encode_ready_writes_correct_bytes() {
        let mut buf = [0u8; 27];
        let n = encode_ready(&mut buf).unwrap();
        assert_eq!(n, 27);
        assert_eq!(buf, READY_FRAME);
    }

    // Test 3: encode_ready returns Err on buffer smaller than 27 bytes
    #[test]
    fn encode_ready_returns_err_on_small_buffer() {
        let mut buf = [0u8; 26];
        assert_eq!(encode_ready(&mut buf), Err(NullError::BufferTooSmall));
    }

    // Test 4: parse_ready with a valid SUB READY frame returns PeerSocketType::Sub
    #[test]
    fn parse_ready_sub_returns_sub_socket_type() {
        // flags=0x04, size=0x19 (25), name-size=0x05, "READY",
        // prop name-size=0x0B, "Socket-Type", value-size=0x00000003, "SUB"
        let frame: [u8; 27] = [
            0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x53, 0x55, 0x42,
        ];
        assert_eq!(parse_ready(&frame), Ok(PeerSocketType::Sub));
    }

    // Test 5: parse_ready with XSUB READY frame returns PeerSocketType::Xsub
    #[test]
    fn parse_ready_xsub_returns_xsub_socket_type() {
        // size=0x1A (26), value-size=0x00000004, "XSUB" — total frame 30 bytes
        let frame: [u8; 30] = [
            0x04, 0x1A, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x04, 0x58, 0x53, 0x55, 0x42,
            // 2 trailing zeroes to pad to 30 for array syntax (frame is 28 bytes actual)
            // Actually frame is 2+26=28 bytes — let's use 28
            0x00, 0x00,
        ];
        // Only pass the valid 28 bytes
        assert_eq!(parse_ready(&frame[..28]), Ok(PeerSocketType::Xsub));
    }

    // Test 6: parse_ready with wrong socket type returns WrongSocketType
    #[test]
    fn parse_ready_wrong_socket_type_returns_err() {
        // Same structure but Socket-Type = "PUSH" (4 bytes)
        let frame: [u8; 28] = [
            0x04, 0x1A, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x04, 0x50, 0x55, 0x53,
            0x48, // "PUSH"
        ];
        assert_eq!(parse_ready(&frame), Err(NullError::WrongSocketType));
    }

    // Test 7: parse_ready with flags=0x00 (message frame) returns NotACommand
    #[test]
    fn parse_ready_not_a_command_returns_err() {
        let mut frame = [0u8; 27];
        frame[0] = 0x00; // flags: not a command
        frame[1] = 0x19;
        // rest doesn't matter
        assert_eq!(parse_ready(&frame), Err(NullError::NotACommand));
    }

    // Test 8: parse_ready with unknown command name returns UnknownCommand
    #[test]
    fn parse_ready_unknown_command_returns_err() {
        // Replace "READY" with "HELLO\0" (6 chars to keep same body size region)
        // Actually use "HELLO" (5 chars same length) — name-size=0x05, "HELLO"
        let frame: [u8; 27] = [
            0x04, 0x19, 0x05, 0x48, 0x45, 0x4C, 0x4C, 0x4F, // "HELLO"
            0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00,
            0x00, 0x03, 0x50, 0x55, 0x42,
        ];
        assert_eq!(parse_ready(&frame), Err(NullError::UnknownCommand));
    }

    // Peer "ERROR" command is reported as PeerError, not UnknownCommand
    #[test]
    fn parse_ready_peer_error_command_returns_peer_error() {
        // name-size=0x05, "ERROR", plus a short reason byte to satisfy body parsing
        let frame: [u8; 10] = [
            0x04, 0x08, 0x05, 0x45, 0x52, 0x52, 0x4F, 0x52, // "ERROR"
            0x00, 0x00,
        ];
        assert_eq!(parse_ready(&frame[..10]), Err(NullError::PeerError));
    }

    // encode_error rejects reasons that would overflow the 1-byte body size
    #[test]
    fn encode_error_reason_too_long_returns_err() {
        let reason = [b'x'; 249]; // body_size = 7 + 249 = 256, just over u8::MAX
        let mut buf = [0u8; 512];
        assert_eq!(
            encode_error(&mut buf, &reason),
            Err(NullError::ReasonTooLong)
        );
    }

    // boundary: 248-byte reason fits (body_size == 255)
    #[test]
    fn encode_error_reason_at_boundary_succeeds() {
        let reason = [b'x'; 248];
        let mut buf = [0u8; 512];
        let n = encode_error(&mut buf, &reason).unwrap();
        assert_eq!(buf[1], 0xFF); // body_size = 255
        assert_eq!(n, 2 + 255);
    }

    // READY with no Socket-Type metadata returns WrongSocketType (not MalformedMetadata)
    #[test]
    fn parse_ready_missing_socket_type_returns_wrong_socket_type() {
        // flags=0x04, size=0x06, name-size=0x05, "READY" (no metadata)
        let frame: [u8; 8] = [0x04, 0x06, 0x05, b'R', b'E', b'A', b'D', b'Y'];
        assert_eq!(parse_ready(&frame), Err(NullError::WrongSocketType));
    }

    // Test 9: encode_error writes correct framing for "Invalid socket type" reason
    #[test]
    fn encode_error_writes_invalid_socket_type_message() {
        // flags=0x04, size=1+5+1+19=26=0x1A, body: name-size=0x05, "ERROR",
        // reason-len(1)=0x13 (19), "Invalid socket type"
        let reason = b"Invalid socket type";
        let mut buf = [0u8; 64];
        let n = encode_error(&mut buf, reason).unwrap();
        // frame = 2 + 1 + 5 + 1 + 19 = 28 bytes
        assert_eq!(n, 28);
        assert_eq!(buf[0], 0x04); // flags: COMMAND
        assert_eq!(buf[1], 0x1A); // size = 26 = 1+5+1+19
        assert_eq!(buf[2], 0x05); // name-size
        assert_eq!(&buf[3..8], b"ERROR"); // command name
        assert_eq!(buf[8], 0x13); // reason-len = 19
        assert_eq!(&buf[9..28], reason); // reason string
    }

    // RADIO tests

    #[test]
    fn radio_ready_frame_constant_matches_expected_bytes() {
        let expected: [u8; 29] = [
            0x04, 0x1B, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x05, 0x52, 0x41, 0x44, 0x49,
            0x4F,
        ];
        assert_eq!(RADIO_READY_FRAME, expected);
    }

    #[test]
    fn encode_ready_radio_writes_correct_bytes() {
        let mut buf = [0u8; 29];
        let n = encode_ready_radio(&mut buf).unwrap();
        assert_eq!(n, 29);
        assert_eq!(buf, RADIO_READY_FRAME);
    }

    #[test]
    fn encode_ready_radio_returns_err_on_small_buffer() {
        let mut buf = [0u8; 28];
        assert_eq!(encode_ready_radio(&mut buf), Err(NullError::BufferTooSmall));
    }

    #[test]
    fn parse_ready_radio_with_dish_returns_dish_socket_type() {
        // DISH READY: flags=0x04, size=0x1A (26), name-size=0x05, "READY",
        // prop name-size=0x0B, "Socket-Type", value-size=0x00000004, "DISH"
        let frame: [u8; 28] = [
            0x04, 0x1A, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x04, 0x44, 0x49, 0x53, 0x48,
        ];
        assert_eq!(parse_ready_radio(&frame), Ok(PeerSocketType::Dish));
    }

    #[test]
    fn parse_ready_radio_with_sub_returns_wrong_socket_type() {
        // Same as parse_ready_sub but through the radio parser
        let frame: [u8; 27] = [
            0x04, 0x19, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x0B, 0x53, 0x6F, 0x63, 0x6B, 0x65,
            0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x03, 0x53, 0x55, 0x42,
        ];
        assert_eq!(parse_ready_radio(&frame), Err(NullError::WrongSocketType));
    }
}
