#![no_main]
use libfuzzer_sys::fuzz_target;
use mzmq::group_table::GroupTable;

fuzz_target!(|data: &[u8]| {
    let mut table: GroupTable<8, 64> = GroupTable::new();
    for chunk in data.chunks(64) {
        let op = chunk[0] % 3;
        let payload = &chunk[1..];
        match op {
            0 => {
                let _ = table.join(payload);
            }
            1 => {
                table.leave(payload);
            }
            2 => {
                let _ = table.matches(payload);
            }
            _ => unreachable!(),
        }
    }
});
