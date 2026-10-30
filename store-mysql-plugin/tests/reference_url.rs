// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `url` IS REFERENCE-CAPABLE, NOT SECRET (busbar lead ruling item 7a): a 1.5.5 config that
//! writes the mysql store's `url` as `{env: VAR}` keeps booting (the reference resolves in place, as the
//! kernel resolves it), and a literal url keeps working (it passes as written, never refused as a
//! secret literal). The linked door is loaded the way the host binds it.

use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};
use busbar_test_kit::conformance::settings_as_the_kernel_resolves;

const URL: &str = "mysql://busbar@db.internal:3306/busbar";

fn linked() -> (Plugin<Store>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("reference-url"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of(busbar_store_mysql::door).expect("the row renders");
    (load_linked::<Store>(&row, bind).expect("the door loads"), d)
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
    let out =
        settings_as_the_kernel_resolves(&p, br#"{"url":{"env":"REFCAP_URL_FOR_TEST"}}"#, |_, _| {
            Ok(URL.to_string())
        })
        .expect("a reference at the url resolves");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["url"], URL);
}

#[test]
fn a_literal_url_passes_as_written() {
    let (p, _d) = linked();
    let settings = format!(r#"{{"url":"{URL}"}}"#);
    let out = settings_as_the_kernel_resolves(&p, settings.as_bytes(), |_, _| {
        Err("a literal url resolves nothing".to_string())
    })
    .expect("a literal url passes as written");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["url"], URL);
}
