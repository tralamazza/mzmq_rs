#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::radio_connection::RadioConnection;

fuzz_target!(|data: &[u8]| {
    let mut conn = RadioConnection::<8, 64, 4096>::new();
    let mut out = [0u8; 256];

    let _ = conn.write_greeting(&mut out);

    let mut remaining = data;
    loop {
        if remaining.is_empty() {
            break;
        }
        match conn.feed(remaining) {
            Ok(n) if n > 0 => {
                remaining = &remaining[n..];
                let _ = conn.write_ready(&mut out);
            }
            _ => break,
        }
    }
});
