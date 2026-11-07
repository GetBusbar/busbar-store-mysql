// SPDX-License-Identifier: Apache-2.0
//! Normal native primitive persistence. Opening never invokes the legacy migrator.

pub(crate) mod backend;
mod bootstrap;
mod empty_origin;
mod native;
mod schema;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::sdk::door::abi_str;

const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The store's one need: the server, dialled over `tcp` at the URL's `host:port` (or its `socket=` path as `unix:<path>`; the store names the target per connection), in the `operator-infrastructure` egress class (private, loopback and plaintext allowed; pinned; cloud metadata hosts refused).
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
    transport: abi_str("tcp"),
    auth: NO_TEXT,
    target_from: NO_TEXT,
    trust_from: NO_TEXT,
    details: Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    },
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

const MAX_INFLIGHT: u32 = 64;
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

busbar_contract::store_v4_door!(
    backend::MysqlV4,
    crate::NAME,
    env!("CARGO_PKG_VERSION"),
    MAX_INFLIGHT,
    needs: NEEDS,
    extensions: EXTENSIONS,
    settings_schema: busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json"))
);

#[cfg(test)]
mod bootstrap_native_tests;
#[cfg(test)]
mod native_tests;
