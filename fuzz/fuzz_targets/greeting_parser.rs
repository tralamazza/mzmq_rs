#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::greeting::{GREETING_LEN, GREETING_PARTIAL_LEN, parse_greeting, parse_partial_greeting};

fuzz_target!(|data: &[u8]| {
    if data.len() >= GREETING_PARTIAL_LEN {
        let arr: &[u8; GREETING_PARTIAL_LEN] = data[..GREETING_PARTIAL_LEN].try_into().unwrap();
        let _ = parse_partial_greeting(arr);
    }
    if data.len() >= GREETING_LEN {
        let arr: &[u8; GREETING_LEN] = data[..GREETING_LEN].try_into().unwrap();
        let _ = parse_greeting(arr);
    }
});
