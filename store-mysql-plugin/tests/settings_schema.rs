// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn settings_schema_is_carried_by_statement() {
    let bytes = busbar_plugin_loader::dispatch::rendering_of(busbar_store_mysql::door)
        .expect("actual linked door renders");
    let statement = busbar_contract::abi::mechanism::rendering::read(&bytes)
        .expect("Statement rendering reads");
    assert_eq!(
        statement.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    assert_eq!(
        statement.settings_schema.bytes,
        include_bytes!("../../store-mysql/src/settings.schema.json")
    );
}
