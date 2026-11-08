// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **MySQL/MariaDB store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store carries (`kind: store`, alias `mysql`).

#![deny(unsafe_code)]

pub use busbar_store_mysql::{door, MACRO_DOOR};

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_mysql::door);
}
