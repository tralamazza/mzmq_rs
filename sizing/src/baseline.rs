// Minimum runnable binary for each target — measures non-mzmq overhead
// (startup, panic handler, rt boilerplate) so scripts/measure_size.sh can
// subtract it from the probe to isolate mzmq's contribution.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

#[cfg(target_os = "none")]
#[cortex_m_rt::entry]
fn entry() -> ! {
    loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {}
