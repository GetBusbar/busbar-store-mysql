// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MySQL/MariaDB native primitive persistence over the host connector.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

/// The package name stated by both linked and loadable doors.
pub const NAME: &str = "busbar-store-mysql";
/// Maximum retained host connections.
pub(crate) const KEPT_CONNECTIONS: usize = 8;
/// MySQL duplicate-key error, interpreted by the physical transport.
pub(crate) const ER_DUP_ENTRY: u16 = 1062;

mod credentials;
pub(crate) mod legacy;
pub(crate) mod mysqlwire;
/// Native primitive persistence door and implementation.
pub(crate) mod v4;
pub use v4::{door, MACRO_DOOR};

#[cfg(test)]
mod settings_schema_tests;
#[cfg(test)]
#[path = "../tests-support/mysql_io.rs"]
mod test_mysql_io;

mod source_interpretation;

#[cfg(test)]
#[path = "../tests-support/rsa_key.rs"]
mod test_rsa_key;
