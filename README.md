# mzmq

Minimal `no_std` ZMQ (ZMTP 3.1) PUB transport for embedded Rust.

[![Rust CI](https://github.com/tralamazza/mzmq_rs/actions/workflows/ci.yml/badge.svg)](https://github.com/tralamazza/mzmq_rs/actions/workflows/ci.yml)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-blue)](https://github.com/rust-lang/rust/releases/tag/1.88.0)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Purpose

A tiny, `no_std`, `no_alloc` Rust library that speaks ZMTP 3.1 as a PUB endpoint.
Designed for embedded Cortex-M-class targets that need to publish telemetry
to ZMQ-based tooling (dashboards, log collectors, control planes) without
linking libzmq or pulling in `tokio`.

## Features

| Feature | Description |
|---------|-------------|
| `std` | Opts out of `no_std`; required when building on hosted targets |
| `sync` | Blocking driver over `embedded-io` (default) |
| `async` | Async driver over `embedded-io-async` |
| `python-tests` | Integration tests against real `pyzmq` |

Default: `default = ["sync"]`

## Usage

```rust
use embedded_io_adapters::std::FromStd;
use mzmq::io::sync::Driver;
use std::net::TcpStream;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect("127.0.0.1:5556")?;
    stream.set_nonblocking(true)?;

    // Driver::<SUB_CAP, PREFIX_CAP, FRAME_CAP, Transport>
    //   SUB_CAP    = max simultaneous subscriptions
    //   PREFIX_CAP = max bytes per subscription prefix
    //   FRAME_CAP  = internal frame decoder buffer size
    let mut driver = Driver::<8, 32, 1024, _>::new(FromStd::new(stream))?;

    // Drive the ZMTP handshake until Established.
    while !driver.poll()? {}

    // Publish. Returns 0 if no peer subscription matches `b"hello"`.
    driver.publish(b"hello", b"world")?;
    Ok(())
}
```

See [`examples/pub_hello.rs`](examples/pub_hello.rs) for a runnable version with
timeouts and error handling.

## RFC 37 (ZMTP 3.1)

This implementation follows the [ZMTP 3.1 specification](https://rfc.zeromq.org/spec/37/).

- **Role**: PUB only (publishes to SUB/XSUB peers)
- **Security**: NULL mechanism only
- **Framing**: Short (≤255 bytes) + long (>255 bytes) frames
- **Subscriptions**: Parses SUBSCRIBE/CANCEL (3.1) and 0x01/0x00 prefix (3.0)

## no_std Operation

The sans-IO core compiles with `--no-default-features`:

```bash
cargo test --no-default-features
cargo build --no-default-features --target thumbv7em-none-eabihf
```

## Interop Testing

Real ZMQ interop tests against `pyzmq>=26`:

```bash
uv sync
cargo test --features python-tests -- --test-threads=1
```
