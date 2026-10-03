// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **MySQL/MariaDB store as a droppable busbar plugin** — the `cdylib` a signed tarball of the
//! store carries (`kind: store`, alias `mysql`). Drop it into the engine's plugins folder and set
//! `store: { module: mysql, settings: { url: "mysql://..." } }`; the engine loads it in-process at
//! boot. One MySQL/MariaDB behind a fleet of busbar nodes means shared virtual keys, budgets, and
//! usage across the cluster.
//!
//! All the store lives in the `busbar-store-mysql` crate, including its door
//! (`busbar_store_mysql::door`, `store_door!`). This crate re-exports the logic crate and exports
//! that door as the image's ONE symbol, `busbar_plugin_door` (`export_door!`, behind the `dropped-in` feature),
//! so the library carries exactly the code a busbar build that links the store runs
//! — one source, both doors (DECISIONS #2 rule (1)).
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one
//! reviewed exemption (a `forbid` cannot be lifted for it). No other `unsafe` exists here.

#![deny(unsafe_code)]

pub use busbar_store_mysql::*;

/// The exported door, behind `dropped-in` (the cdylib build only): the macro's `#[no_mangle]` symbol is
/// the one exemption.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_mysql::door);
}
