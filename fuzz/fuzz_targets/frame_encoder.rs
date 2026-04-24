#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::frame::{FrameDecoder, encode_command_frame, encode_message_frame};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    let body_len = usize::from(data[0]) | (usize::from(data[1]) << 8);
    let more = (data[2] & 1) != 0;

    let mut enc_buf = [0u8; 9];

    if let Ok(hl) = encode_message_frame(&mut enc_buf, body_len, more) {
        let mut frame = [0u8; 4096];
        let total = hl + body_len.min(4096 - hl);
        if total <= 4096 {
            frame[..hl].copy_from_slice(&enc_buf[..hl]);
            if data.len() > 3 {
                let copy_len = body_len.min(data.len() - 3).min(4096 - hl);
                frame[hl..hl + copy_len]
                    .copy_from_slice(&data[3..3 + copy_len]);
            }
            let mut decoder = FrameDecoder::<4096>::new();
            let _ = decoder.feed(&frame[..total]);
        }
    }

    if let Ok(hl) = encode_command_frame(&mut enc_buf, body_len) {
        let mut frame = [0u8; 4096];
        let total = hl + body_len.min(4096 - hl);
        if total <= 4096 {
            frame[..hl].copy_from_slice(&enc_buf[..hl]);
            if data.len() > 3 {
                let copy_len = body_len.min(data.len() - 3).min(4096 - hl);
                frame[hl..hl + copy_len]
                    .copy_from_slice(&data[3..3 + copy_len]);
            }
            let mut decoder = FrameDecoder::<4096>::new();
            let _ = decoder.feed(&frame[..total]);
        }
    }
});
