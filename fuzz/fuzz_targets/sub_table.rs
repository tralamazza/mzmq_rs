#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::sub_table::SubTable;

fuzz_target!(|data: &[u8]| {
    let mut table: SubTable<8, 64> = SubTable::new();
    for chunk in data.chunks(64) {
        let op = chunk[0] % 3;
        let payload = &chunk[1..];
        match op {
            0 => {
                let _ = table.subscribe(payload);
            }
            1 => {
                table.cancel(payload);
            }
            2 => {
                let _ = table.matches(payload);
            }
            _ => unreachable!(),
        }
    }
});
