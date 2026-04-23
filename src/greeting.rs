/// Fixed size of a ZMTP 3.1 greeting frame in bytes.
pub const GREETING_LEN: usize = 64;
/// Number of bytes in the partial greeting (signature + version major).
/// VERSION_MAJOR is the index of that byte, so +1 gives the length.
pub const GREETING_PARTIAL_LEN: usize = VERSION_MAJOR + 1;

const SIG0: usize = 0;
const SIG9: usize = 9;
const VERSION_MAJOR: usize = 10;
const VERSION_MINOR: usize = 11;
const MECHANISM: usize = 12;
const AS_SERVER: usize = 32;

/// Decoded peer greeting (subset relevant to this library).
#[derive(Debug, PartialEq)]
pub struct PeerGreeting {
    /// Peer's ZMTP minor version (e.g. `0` for 3.0, `1` for 3.1).
    pub version_minor: u8,
}

/// Errors returned when parsing a peer greeting.
#[derive(Debug, PartialEq)]
pub enum GreetingError {
    InvalidSignature,
    UnsupportedVersionMajor,
    UnsupportedMechanism,
    InvalidAsServer,
}

/// Writes the 64-byte ZMTP 3.1 NULL greeting for a PUB socket into `buf`.
pub fn encode_greeting(buf: &mut [u8; GREETING_LEN]) {
    *buf = [0u8; GREETING_LEN];
    buf[SIG0] = 0xFF;
    buf[SIG9] = 0x7F;
    buf[VERSION_MAJOR] = 0x03;
    buf[VERSION_MINOR] = 0x01; // ZMTP 3.1
    buf[MECHANISM..MECHANISM + 4].copy_from_slice(b"NULL");
    // AS_SERVER and 31-byte filler remain 0x00
}

/// Validates the first 11 bytes of a ZMTP greeting (signature + version major).
/// Call this as soon as GREETING_PARTIAL_LEN bytes are buffered to fail fast on bad peers.
pub fn parse_partial_greeting(buf: &[u8; GREETING_PARTIAL_LEN]) -> Result<(), GreetingError> {
    if buf[SIG0] != 0xFF || buf[SIG9] != 0x7F {
        return Err(GreetingError::InvalidSignature);
    }
    if buf[VERSION_MAJOR] != 0x03 {
        return Err(GreetingError::UnsupportedVersionMajor);
    }
    Ok(())
}

/// Parses a 64-byte greeting from a peer. Returns the peer's version minor.
pub fn parse_greeting(buf: &[u8; GREETING_LEN]) -> Result<PeerGreeting, GreetingError> {
    if buf[SIG0] != 0xFF || buf[SIG9] != 0x7F {
        return Err(GreetingError::InvalidSignature);
    }
    if buf[VERSION_MAJOR] != 0x03 {
        return Err(GreetingError::UnsupportedVersionMajor);
    }
    // Mechanism is a 20-byte field: "NULL" padded with zero bytes.
    // Check all 20 bytes to avoid accepting "NULLCURVE..." as NULL.
    if !buf[MECHANISM..MECHANISM + 4].eq(b"NULL")
        || buf[MECHANISM + 4..MECHANISM + 20].iter().any(|&b| b != 0)
    {
        return Err(GreetingError::UnsupportedMechanism);
    }
    if buf[AS_SERVER] != 0x00 {
        return Err(GreetingError::InvalidAsServer);
    }
    Ok(PeerGreeting {
        version_minor: buf[VERSION_MINOR],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_sub_greeting() -> [u8; GREETING_LEN] {
        let mut g = [0u8; GREETING_LEN];
        g[SIG0] = 0xFF;
        g[SIG9] = 0x7F;
        g[VERSION_MAJOR] = 0x03;
        g[VERSION_MINOR] = 0x01; // ZMTP 3.1
        g[MECHANISM] = b'N';
        g[MECHANISM + 1] = b'U';
        g[MECHANISM + 2] = b'L';
        g[MECHANISM + 3] = b'L';
        g
    }

    #[test]
    fn emits_64_byte_null_pub_greeting() {
        let mut buf = [0u8; GREETING_LEN];
        encode_greeting(&mut buf);
        assert_eq!(buf[SIG0], 0xFF);
        assert_eq!(buf[1..9], [0u8; 8]); // padding
        assert_eq!(buf[SIG9], 0x7F);
        assert_eq!(buf[VERSION_MAJOR], 0x03); // major
        assert_eq!(buf[VERSION_MINOR], 0x01); // minor = ZMTP 3.1
        assert_eq!(&buf[MECHANISM..MECHANISM + 4], b"NULL");
        assert!(buf[MECHANISM + 4..AS_SERVER].iter().all(|&b| b == 0)); // mechanism padding
        assert_eq!(buf[AS_SERVER], 0x00); // as-server
        assert!(buf[AS_SERVER..GREETING_LEN].iter().all(|&b| b == 0)); // filler
    }

    #[test]
    fn accepts_valid_greeting_version_minor_1() {
        let g = valid_sub_greeting();
        assert_eq!(
            parse_greeting(&g),
            Ok(PeerGreeting {
                version_minor: 0x01
            })
        );
    }

    #[test]
    fn accepts_version_minor_0() {
        let mut g = valid_sub_greeting();
        g[VERSION_MINOR] = 0x00;
        assert_eq!(
            parse_greeting(&g),
            Ok(PeerGreeting {
                version_minor: 0x00
            })
        );
    }

    #[test]
    fn rejects_wrong_signature_first_byte() {
        let mut g = valid_sub_greeting();
        g[SIG0] = 0xFE;
        assert_eq!(parse_greeting(&g), Err(GreetingError::InvalidSignature));
    }

    #[test]
    fn rejects_wrong_signature_tenth_byte() {
        let mut g = valid_sub_greeting();
        g[SIG9] = 0x00;
        assert_eq!(parse_greeting(&g), Err(GreetingError::InvalidSignature));
    }

    #[test]
    fn rejects_wrong_version_major() {
        let mut g = valid_sub_greeting();
        g[VERSION_MAJOR] = 0x02;
        assert_eq!(
            parse_greeting(&g),
            Err(GreetingError::UnsupportedVersionMajor)
        );
    }

    #[test]
    fn rejects_unknown_mechanism() {
        let mut g = valid_sub_greeting();
        g[MECHANISM] = b'C'; // "CURVE..."
        assert_eq!(parse_greeting(&g), Err(GreetingError::UnsupportedMechanism));
    }

    #[test]
    fn rejects_mechanism_null_with_nonzero_padding() {
        // "NULL" in bytes 12-15 but non-zero padding in the remaining 16 bytes
        // — must not be accepted as the NULL mechanism.
        let mut g = valid_sub_greeting();
        g[MECHANISM + 4] = b'X';
        assert_eq!(parse_greeting(&g), Err(GreetingError::UnsupportedMechanism));
    }

    #[test]
    fn rejects_nonzero_as_server() {
        let mut g = valid_sub_greeting();
        g[AS_SERVER] = 0x01;
        assert_eq!(parse_greeting(&g), Err(GreetingError::InvalidAsServer));
    }

    #[test]
    fn partial_greeting_accepts_valid_first_11_bytes() {
        let mut buf = [0u8; GREETING_PARTIAL_LEN];
        buf[SIG0] = 0xFF;
        buf[SIG9] = 0x7F;
        buf[VERSION_MAJOR] = 0x03;
        assert_eq!(parse_partial_greeting(&buf), Ok(()));
    }

    #[test]
    fn partial_greeting_rejects_wrong_signature() {
        let mut buf = [0u8; GREETING_PARTIAL_LEN];
        buf[SIG0] = 0xFE;
        buf[SIG9] = 0x7F;
        buf[VERSION_MAJOR] = 0x03;
        assert_eq!(
            parse_partial_greeting(&buf),
            Err(GreetingError::InvalidSignature),
        );
    }

    #[test]
    fn partial_greeting_rejects_wrong_version_major() {
        let mut buf = [0u8; GREETING_PARTIAL_LEN];
        buf[SIG0] = 0xFF;
        buf[SIG9] = 0x7F;
        buf[VERSION_MAJOR] = 0x02;
        assert_eq!(
            parse_partial_greeting(&buf),
            Err(GreetingError::UnsupportedVersionMajor),
        );
    }
}
