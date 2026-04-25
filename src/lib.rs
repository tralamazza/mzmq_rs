#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod auth;
pub mod connection;
pub mod frame;
pub mod greeting;
pub mod group_table;
pub mod null;
#[cfg(feature = "plain")]
pub mod plain;
pub mod radio_connection;
pub mod sub_table;

#[cfg(any(feature = "sync", feature = "async"))]
pub mod io;

#[cfg(test)]
pub(crate) mod test_helpers;
