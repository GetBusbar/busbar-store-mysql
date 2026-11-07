// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::v4::backend::MysqlV4;
use busbar_contract::abi::sdk::store::v4::backend::Backend;

#[test]
fn settings_schema_matches_lifecycle_shapes() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("v4/settings.schema.json")).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid settings schema");
    let cases: &[(&str, bool)] = &[
        (
            r#"{"url":"mysql://localhost/busbar","input_budget":1048576}"#,
            true,
        ),
        (r#"{}"#, false),
        (r#"null"#, false),
        (r#"[]"#, false),
        (r#"{"url":null}"#, false),
        (r#"{"url":1}"#, false),
        (r#"{"url":""}"#, false),
        (r#"{"url":"mysql://localhost/busbar","unknown":0}"#, false),
    ];
    for &(text, accepted) in cases {
        let value: serde_json::Value = serde_json::from_str(text).expect("case JSON");
        assert_eq!(validator.is_valid(&value), accepted, "schema: {text}");
        assert_eq!(
            MysqlV4::validate(text.as_bytes()).is_ok(),
            accepted,
            "lifecycle: {text}"
        );
    }
    assert!(!MysqlV4::validate(b"").is_ok());
    // Semantic URL checks remain with the lifecycle parser.
    assert!(MysqlV4::validate(br#"{"url":"postgres://localhost/busbar"}"#).is_err());
}

#[test]
fn settings_schema_has_no_connection_defaults() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("v4/settings.schema.json")).unwrap();
    let field = &schema["properties"]["url"];
    assert_eq!(field["type"], "string");
    assert!(field.get("default").is_none());
}
