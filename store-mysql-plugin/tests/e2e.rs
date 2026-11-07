// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invalid native settings fail at the actual loaded image before any connection.
mod common;
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};

#[test]
fn load_and_exercise_mysql_plugin_bad_config_fails_over_abi() {
    let library = common::plugin_path();
    for settings in [
        b"{}".as_slice(),
        b"null",
        b"[]",
        br#"{"url":"postgres://localhost/nope","input_budget":100}"#,
        br#"{"url":"mysql://localhost/db","input_budget":0}"#,
    ] {
        let (plugin, dispatcher) = common::native_plugin(Some(&library)).unwrap();
        let result = common::block(LoadedPersistence::open(
            plugin,
            dispatcher,
            settings,
            Limits {
                descriptor_bytes: 1048576,
                output_items: 64,
                output_bytes: 1048576,
                decode_bytes: 1048576,
            },
        ));
        assert!(result.is_err());
    }
}
