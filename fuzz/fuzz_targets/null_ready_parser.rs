#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::null::{parse_ready, parse_ready_radio};

fuzz_target!(|data: &[u8]| {
    let _ = parse_ready(data);
    let _ = parse_ready_radio(data);
});
