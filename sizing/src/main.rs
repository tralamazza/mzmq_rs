// Bare-metal binary that references every public mzmq API enabled by the
// current feature set. Built by scripts/measure_size.sh as:
//   cargo build --release --manifest-path sizing/Cargo.toml
//              --target=thumbv7em-none-eabihf --features=<combo>
// and the resulting ELF's .text + .rodata is measured with `llvm-size`.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::hint::black_box;

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
    probe();
    loop {}
}

#[cfg(not(target_os = "none"))]
fn main() {
    probe();
}

use mzmq::connection::Connection;
use mzmq::frame::{FrameDecoder, encode_command_frame, encode_message_frame};
use mzmq::group_table::GroupTable;
use mzmq::null::{encode_error, encode_ready, encode_ready_radio, parse_ready, parse_ready_radio};
use mzmq::radio_connection::RadioConnection;
use mzmq::sub_table::SubTable;

#[cfg(feature = "plain")]
use mzmq::plain::{encode_welcome, parse_hello_from};

fn probe() {
    let mut buf = [0u8; 256];

    let mut conn: Connection<8, 32, 512> = Connection::new();
    let _ = black_box(conn.write_greeting(&mut buf));
    let _ = black_box(conn.feed(black_box(&buf)));
    let _ = black_box(conn.write_ready(&mut buf));
    let _ = black_box(conn.publish(black_box(b"t"), black_box(b"p"), &mut buf));
    let _ = black_box(conn.write_error(&mut buf));
    let _ = black_box(conn.write_pong(&mut buf));

    let mut radio: RadioConnection<8, 32, 512> = RadioConnection::new();
    let _ = black_box(radio.write_greeting(&mut buf));
    let _ = black_box(radio.feed(black_box(&buf)));
    let _ = black_box(radio.write_ready(&mut buf));
    let _ = black_box(radio.publish(black_box(b"g"), black_box(b"p"), &mut buf));

    let mut sub: SubTable<16, 64> = SubTable::new();
    let _ = sub.subscribe(black_box(b"a"));
    let _ = black_box(sub.matches(black_box(b"abc")));
    sub.cancel(black_box(b"a"));

    let mut group: GroupTable<16, 64> = GroupTable::new();
    let _ = group.join(black_box(b"g"));
    let _ = black_box(group.matches(black_box(b"g")));
    group.leave(black_box(b"g"));

    let mut dec: FrameDecoder<512> = FrameDecoder::new();
    let _ = black_box(dec.feed(black_box(&buf)));
    let _ = black_box(encode_message_frame(&mut buf, 10, false));
    let _ = black_box(encode_command_frame(&mut buf, 10));

    let _ = black_box(encode_ready(&mut buf));
    let _ = black_box(encode_ready_radio(&mut buf));
    let _ = black_box(parse_ready(black_box(&buf)));
    let _ = black_box(parse_ready_radio(black_box(&buf)));
    let _ = black_box(encode_error(&mut buf, black_box(b"nope")));

    #[cfg(feature = "plain")]
    {
        let _ = black_box(encode_welcome(&mut buf));
        let _ = black_box(parse_hello_from(true, black_box(&buf)));
    }

    #[cfg(feature = "sync")]
    sync_probe();

    #[cfg(feature = "async")]
    async_probe();
}

#[cfg(feature = "sync")]
fn sync_probe() {
    use embedded_io::{ErrorKind, ErrorType, Read, Write};
    use mzmq::io::sync::{Driver, RadioDriver};

    struct NullIo;
    impl ErrorType for NullIo {
        type Error = ErrorKind;
    }
    impl Read for NullIo {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Err(ErrorKind::BrokenPipe)
        }
    }
    impl Write for NullIo {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    if let Ok(mut d) = Driver::<8, 32, 512, _>::new(NullIo) {
        let _ = black_box(d.poll());
        let _ = black_box(d.publish(black_box(b"t"), black_box(b"p")));
    }
    if let Ok(mut d) = RadioDriver::<8, 32, 512, _>::new(NullIo) {
        let _ = black_box(d.poll());
        let _ = black_box(d.publish(black_box(b"g"), black_box(b"p")));
    }

    #[cfg(feature = "plain")]
    {
        use mzmq::plain::Authenticator;
        struct AcceptAll;
        impl Authenticator for AcceptAll {
            fn authenticate(&self, _u: &[u8], _p: &[u8]) -> bool {
                true
            }
        }
        if let Ok(mut d) = Driver::<8, 32, 512, _, _>::new_plain(NullIo, AcceptAll) {
            let _ = black_box(d.poll());
        }
    }
}

#[cfg(feature = "async")]
fn async_probe() {
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
    use mzmq::io::r#async::{Driver, RadioDriver};

    struct NullIo;
    impl ErrorType for NullIo {
        type Error = ErrorKind;
    }
    impl Read for NullIo {
        async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Err(ErrorKind::BrokenPipe)
        }
    }
    impl Write for NullIo {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }
        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    const VT: RawWakerVTable =
        RawWakerVTable::new(|_| RawWaker::new(core::ptr::null(), &VT), |_| {}, |_| {}, |_| {});
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);

    {
        let fut = Driver::<8, 32, 512, _>::new(NullIo);
        let mut fut = pin!(fut);
        if let Poll::Ready(Ok(mut d)) = fut.as_mut().poll(&mut cx) {
            {
                let mut p = pin!(d.poll());
                let _ = black_box(p.as_mut().poll(&mut cx));
            }
            {
                let mut p = pin!(d.publish(b"t", b"p"));
                let _ = black_box(p.as_mut().poll(&mut cx));
            }
        }
    }

    {
        let fut = RadioDriver::<8, 32, 512, _>::new(NullIo);
        let mut fut = pin!(fut);
        if let Poll::Ready(Ok(mut d)) = fut.as_mut().poll(&mut cx) {
            let mut p = pin!(d.poll());
            let _ = black_box(p.as_mut().poll(&mut cx));
        }
    }

    #[cfg(feature = "plain")]
    {
        use mzmq::plain::Authenticator;
        struct AcceptAll;
        impl Authenticator for AcceptAll {
            fn authenticate(&self, _u: &[u8], _p: &[u8]) -> bool {
                true
            }
        }
        let fut = Driver::<8, 32, 512, _, _>::new_plain(NullIo, AcceptAll);
        let mut fut = pin!(fut);
        let _ = black_box(fut.as_mut().poll(&mut cx));
    }
}
