// SPDX-License-Identifier: Apache-2.0
//! Compile the exact production codec module and its focused regressions.
//!
//! The official crate's unrelated decimal unit tests require a C++ MySQL source
//! build. This harness uses the official exported constants and production codec
//! module directly, while keeping the dependency in its ordinary library mode.
pub use mysql_common::constants;

#[path = "../../vendor/mysql_common/src/proto/codec/mod.rs"]
pub mod codec;
