#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::frame::FrameDecoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = FrameDecoder::<4096>::new();
    let _ = decoder.feed(data);
});
