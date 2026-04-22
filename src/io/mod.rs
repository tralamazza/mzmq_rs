//! IO adapters for the sans-IO ZMTP 3.1 PUB connection.
//!
//! - `sync`: blocking driver over `embedded_io::Read + Write`
//! - `async`: future-based driver over `embedded_io_async::Read + Write`

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(feature = "async")]
pub mod r#async;
