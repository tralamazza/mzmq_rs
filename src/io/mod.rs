//! IO adapters for the sans-IO ZMTP 3.1 PUB and RADIO connections.
//!
//! - `sync`: blocking drivers over `embedded_io::Read + Write`
//! - `async`: future-based drivers over `embedded_io_async::Read + Write`
//! - `smoltcp`: embedded-io adapter for [`smoltcp::socket::tcp::Socket`]

/// Synchronous (blocking) IO adapter for `Connection` and `RadioConnection`.
#[cfg(feature = "sync")]
pub mod sync;

/// Asynchronous IO adapter for `Connection` and `RadioConnection`.
#[cfg(feature = "async")]
pub mod r#async;

/// [`embedded_io::Read`] + [`embedded_io::Write`] adapter for smoltcp TCP sockets.
#[cfg(feature = "smoltcp")]
pub mod smoltcp;
