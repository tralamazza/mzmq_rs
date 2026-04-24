#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod connection;
pub mod frame;
pub mod greeting;
pub mod group_table;
pub mod null;
pub mod plain;
pub mod radio_connection;
pub mod sub_table;

#[cfg(any(feature = "sync", feature = "async"))]
pub mod io;

#[cfg(test)]
pub(crate) mod test_helpers;
