// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `url` is reference-capable rather than a declared secret field; literal 1.5.5 URLs remain accepted.

use std::sync::Arc;

use busbar_contract::secret_fields::resolve_declared_fields;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};

const URL: &str = "mysql://busbar@db.internal:3306/busbar";

fn linked() -> (Plugin<StoreV4>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("reference-url"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of_kind::<StoreV4>(
        busbar_store_mysql::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .expect("the row renders");
    (
        load_linked::<StoreV4>(&row, bind).expect("the door loads"),
        d,
    )
}

#[test]
fn the_url_is_not_declared_secret() {
    let (p, _d) = linked();
    assert!(
        !p.secret_refs().iter().any(|f| f == "url"),
        "{:?}",
        p.secret_refs()
    );
}

#[test]
fn a_reference_at_the_url_resolves_as_the_kernel_resolves_it() {
    let (p, _d) = linked();
    let mut v: serde_json::Value =
        serde_json::from_slice(br#"{"url":{"env":"REFCAP_URL_FOR_TEST"}}"#).unwrap();
    resolve_declared_fields(
        &mut v,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        |_, _| Ok(URL.to_string()),
    )
    .expect("a reference at the URL resolves");
    assert_eq!(v["url"], URL);
}

#[test]
fn a_literal_url_passes_as_written() {
    let (p, _d) = linked();
    let settings = format!(r#"{{"url":"{URL}"}}"#);
    let mut v: serde_json::Value = serde_json::from_slice(settings.as_bytes()).unwrap();
    resolve_declared_fields(
        &mut v,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        |_, _| Err("a literal url resolves nothing".to_string()),
    )
    .expect("a literal URL passes as written");
    assert_eq!(v["url"], URL);
}
