# mzmq

[![Rust CI](https://github.com/tralamazza/mzmq_rs/actions/workflows/ci.yml/badge.svg)](https://github.com/tralamazza/mzmq_rs/actions/workflows/ci.yml)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-blue)](https://github.com/rust-lang/rust/releases/tag/1.88.0)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A `no_std`, `no_alloc` Rust library that speaks [ZMTP 3.1](https://rfc.zeromq.org/spec/37/) as a **PUB** or **RADIO** endpoint. Built for Cortex-M-class targets that need to publish telemetry to ZMQ-based tooling without linking libzmq or pulling in `tokio`.

## When to use this

- You have an embedded device (or any `no_std` target) that needs to push data to a ZMQ subscriber
- You want to use the standard PUB-SUB or RADIO-DISH wire protocol with zero heap allocation
- You do **not** need to receive messages or act as a broker

## Getting started

Add to `Cargo.toml`:

```toml
[dependencies]
mzmq = "0.1"
```

### PUB-SUB

```rust
use embedded_io_adapters::std::FromStd;
use mzmq::io::sync::Driver;
use std::net::TcpStream;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect("127.0.0.1:5556")?;
    stream.set_nonblocking(true)?;

    // Driver::<SUB_CAP, PREFIX_CAP, FRAME_CAP, Transport>
    //   SUB_CAP    — max simultaneous subscriptions
    //   PREFIX_CAP — max bytes per subscription prefix
    //   FRAME_CAP  — internal frame buffer size
    let mut driver = Driver::<8, 32, 1024, _>::new(FromStd::new(stream))?;

    while !driver.poll()? {}                      // drive the ZMTP handshake

    driver.publish(b"hello", b"world")?;          // returns 0 if no subscriber matches
    Ok(())
}
```

### RADIO-DISH (RFC 48)

Groups are matched by **exact byte equality**, unlike the prefix matching of PUB-SUB.

```rust
use embedded_io_adapters::std::FromStd;
use mzmq::io::sync::RadioDriver;
use std::net::TcpStream;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect("127.0.0.1:5556")?;
    stream.set_nonblocking(true)?;

    // RadioDriver::<GROUP_CAP, GROUP_LEN_CAP, FRAME_CAP, Transport>
    let mut driver = RadioDriver::<8, 32, 1024, _>::new(FromStd::new(stream))?;

    while !driver.poll()? {}

    driver.publish(b"alerts", b"temperature critical")?;
    Ok(())
}
```

See [`examples/pub_hello.rs`](examples/pub_hello.rs) for a runnable version with timeouts and error handling.

### PLAIN security (optional)

Enable the `plain` feature and use `Driver::new_plain(transport, authenticator)` instead of
`Driver::new(transport)` to authenticate peers with a username/password pair. The authenticator
must implement `mzmq::plain::Authenticator`. PLAIN transmits credentials in clear text — only
use over trusted or encrypted transports.

```rust
use mzmq::io::sync::Driver;
use mzmq::plain::Authenticator;

struct MyAuth { user: &'static [u8], pass: &'static [u8] }
impl Authenticator for MyAuth {
    fn authenticate(&self, username: &[u8], password: &[u8]) -> bool {
        username == self.user && password == self.pass
    }
}

let auth = MyAuth { user: b"admin", pass: b"secret" };
let mut driver = Driver::<8, 32, 1024, _, _>::new_plain(transport, auth)?;
```

## Features

| Feature | Default | Description |
|---------|:-------:|-------------|
| `sync` | yes | Blocking driver over `embedded-io` |
| `async` | no | Async driver over `embedded-io-async` |
| `std` | no | Opt out of `no_std`; required on hosted targets |
| `plain` | no | ZMTP PLAIN security mechanism (RFC 27) — server role |
| `python-tests` | no | Integration tests against a real `pyzmq` process |

## no_std / embedded targets

The sans-IO core compiles with no default features:

```bash
cargo build --no-default-features --target thumbv7em-none-eabihf
```

All capacity bounds (`SUB_CAP`, `PREFIX_CAP`, `FRAME_CAP`, …) are const generics resolved at compile time. The library uses [`heapless`](https://docs.rs/heapless) internally — no allocator required.

## Protocol scope

- **Transport**: ZMTP 3.1 (RFC 37), NULL and PLAIN (RFC 27, optional feature) security mechanisms
- **Roles**: PUB (to SUB/XSUB peers) and RADIO (to DISH peers)
- **Framing**: short frames (≤ 255 bytes) and long frames (> 255 bytes)
- **Subscriptions**: SUBSCRIBE/CANCEL (3.1) and legacy 0x01/0x00 prefix (3.0)
- **Groups**: JOIN/LEAVE (RFC 48) with exact matching

## Interop tests

Run the integration tests against a live `pyzmq >= 26` process:

```bash
uv sync
cargo test --features python-tests -- --test-threads=1
```

## Releasing

Releases are automated via [`cargo-release`](https://github.com/crate-ci/cargo-release).

```bash
cargo install cargo-release
cargo release patch --execute   # or: minor / major / <x.y.z>
```

This bumps the version in `Cargo.toml`, commits, tags `vX.Y.Z`, and pushes. The
`Release` workflow then publishes to crates.io and creates a GitHub Release.

Required secret on the repo: `CARGO_REGISTRY_TOKEN` (crates.io API token with
publish scope).

## Development

Install git hooks:

```bash
git config core.hooksPath .githooks
```
