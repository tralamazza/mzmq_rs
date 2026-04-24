#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::plain::parse_hello_from;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let is_command = (data[0] & 1) != 0;
    let body = &data[1..];
    let _ = parse_hello_from(is_command, body);
});
