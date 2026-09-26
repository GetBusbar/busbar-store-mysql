// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE STORE, BOTH DOORS, ONE ROW** — the MySQL store's linked + dropped-in conformance, run
//! against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (its `linked::STORE` statement and boundary, the row a
//! busbar build that compiles it in registers) and DROPPED IN (this crate's built cdylib, signed
//! first-party under the SAME statement into a temp `plugins/` directory and found by the loader's
//! scan). Each arm is opened by the one `open_store` and gives one transcript: the row's statement,
//! whether it is first-party, the refusals the store's own `open` answers for bad configurations,
//! and — against a live MySQL — a scenario of reads and writes through the `RecordStore` verbs. The
//! two transcripts must agree byte for byte.
//!
//! The RED arms are in the same test: the same cdylib signed as another KIND is refused at the kind
//! handshake naming both kinds, and the same bytes dropped in under another statement (alias) do not
//! give the linked transcript (the comparison covers the row, so it cannot pass vacuously).
//!
//! The live scenario follows this repo's `BUSBAR_TEST_MYSQL_URL` gate (set: runs; unset under CI: a
//! failure; unset locally: skipped with a line saying so). Everything else in this test needs no
//! database and always runs.

use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, VirtualKey};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// The version both arms state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The live MySQL, under this repo's gate.
fn mysql_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(u) => Some(u),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!("BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql service container must provision it")
        }
        Err(_) => {
            eprintln!("skip (live scenario only): set BUSBAR_TEST_MYSQL_URL to run it");
            None
        }
    }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_store_mysql_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-store-mysql-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// The statement both arms make, as `kind` at the newest payload schema the loader speaks for it.
fn statement(kind: &str) -> Manifest {
    let (name, alias, _) = busbar_store_mysql::linked::STORE;
    let abi = busbar_plugin_loader::supported_abi(kind)
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// The LINKED row: exactly what a busbar build that links this store registers.
fn linked_registry() -> PluginRegistry {
    let (_, _, entry) = busbar_store_mysql::linked::STORE;
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::boundary(statement("store"), entry)])
        .expect("the linked row registers")
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("store-mysql-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libstore.so", lib).unwrap();
    std::fs::write(dir.join("store.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed store scans")
}

/// The ids the live scenario writes; removed before and after each arm, so both arms start from the
/// same database state.
const KEY_ID: &str = "vk_conformance_doors";
const TASK_ID: &str = "conformance-doors-task";
const PARENT: &str = "conformance-doors-parent";
const TOKEN: &str = "conformance-doors-nonce";

fn clear(url: &str) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(mysql::Opts::from_url(url).unwrap()).expect("connect");
    for (sql, v) in [
        ("DELETE FROM api_keys WHERE id = ?", KEY_ID),
        ("DELETE FROM plane_records WHERE ident = ?", TASK_ID),
        ("DELETE FROM plane_records WHERE parent = ?", PARENT),
        ("DELETE FROM plane_tokens WHERE token = ?", TOKEN),
    ] {
        conn.exec_drop(sql, (v,))
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
}

/// What one door does as `alias` with `url`, as one comparable transcript.
fn transcript(registry: &PluginRegistry, alias: &str, url: Option<&str>) -> serde_json::Value {
    let p = registry.resolve(alias).expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    // The store's own `open`, refusing configurations it cannot run.
    let refusals = [
        "",
        "{ not json",
        r#"{"url": "  "}"#,
        r#"{"url": "mysql://nobody:none@127.0.0.1:9/nowhere"}"#,
    ]
    .map(|cfg| match registry.open_store(alias, cfg) {
        Ok(_) => "opened".to_string(),
        Err(e) => e,
    });

    let live = url.map(|url| {
        clear(url);
        let cfg = serde_json::json!({ "url": url }).to_string();
        let store = registry.open_store(alias, &cfg).expect("the store opens");
        let key = VirtualKey {
            id: KEY_ID.into(),
            generation_hash: format!("binding:{KEY_ID}:g1"),
            name: "conformance doors".into(),
            enabled: true,
            created_at: 1_700_000_000,
            ..Default::default()
        };
        store.put_key(&key).expect("put_key");
        let got = store
            .get_key(KEY_ID)
            .expect("get_key")
            .map(|k| serde_json::json!([k.id, k.generation_hash, k.name, k.enabled, k.created_at]));
        let task = PlaneRecord {
            kind: "task".into(),
            id: TASK_ID.into(),
            parent: None,
            seq: 0,
            ts: 1_700_000_100,
            disposition: PlaneDisposition::Active,
            body: b"{\"state\":\"working\"}".to_vec(),
        };
        store.upsert_plane_record(&task).expect("upsert");
        let task_body = store.get_plane_record("task", TASK_ID).expect("get");
        for seq in 1..=3u64 {
            store
                .append_plane_record(&PlaneRecord {
                    kind: "task_event".into(),
                    id: format!("{TASK_ID}-e{seq}"),
                    parent: Some(PARENT.into()),
                    seq,
                    ts: 1_700_000_100 + seq,
                    disposition: PlaneDisposition::Terminal,
                    body: format!("event {seq}").into_bytes(),
                })
                .expect("append");
        }
        let chain: Vec<_> = store
            .list_plane_records("task_event", &PlaneSelector::Parent(PARENT.into()))
            .expect("list")
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect();
        let redeemed = [
            store
                .redeem_plane_token("ask", TOKEN, 1_700_009_000, 1_700_000_000)
                .expect("redeem"),
            store
                .redeem_plane_token("ask", TOKEN, 1_700_009_000, 1_700_000_001)
                .expect("redeem again"),
        ];
        store.delete_key(KEY_ID).expect("delete_key");
        let after_delete = store.get_key(KEY_ID).expect("get_key").map(|k| k.enabled);
        drop(store);
        clear(url);
        serde_json::json!({
            "key": got,
            "task": task_body.map(|b| String::from_utf8_lossy(&b).into_owned()),
            "chain": chain,
            "redeemed": redeemed,
            "after_delete": after_delete,
        })
    });
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "refusals": refusals,
        "live": live,
    })
}

/// The MySQL store registers ONE row and behaves as ONE store through either door — and the same
/// bytes as another kind, or under another statement, do not (the RED arms).
#[test]
fn the_linked_and_the_dropped_in_mysql_store_are_one_store() {
    let url = mysql_url();
    let url = url.as_deref();
    let (name, alias, _) = busbar_store_mysql::linked::STORE;
    assert_eq!(name, "busbar-store-mysql-plugin");
    assert_eq!(alias, "mysql");
    let lib = cdylib();

    let linked = transcript(&linked_registry(), alias, url);
    let dropped_registry = dropped("dropped", statement("store"), &lib);
    let dropped_in = transcript(&dropped_registry, alias, url);
    assert_eq!(linked, dropped_in, "the two doors are not one store");

    // The transcript holds the store's own words, not the loader's.
    assert_eq!(linked["first_party"], true);
    let refusals = linked["refusals"].as_array().unwrap();
    assert!(
        refusals[0]
            .as_str()
            .unwrap()
            .contains("mysql plugin config requires a \"url\""),
        "{refusals:?}"
    );
    assert!(
        refusals[1]
            .as_str()
            .unwrap()
            .contains("invalid mysql plugin config"),
        "{refusals:?}"
    );
    if url.is_some() {
        let live = &linked["live"];
        assert_eq!(live["key"][0], KEY_ID, "{live}");
        assert_eq!(live["task"], "{\"state\":\"working\"}", "{live}");
        assert_eq!(live["chain"].as_array().unwrap().len(), 3, "{live}");
        assert_eq!(live["redeemed"], serde_json::json!([true, false]), "{live}");
    }

    // RED ARM 1: the same bytes signed as another kind are refused at the kind handshake, naming
    // both kinds.
    let wrong = dropped("wrong-kind", statement("secret"), &lib);
    let e = match wrong.open_secret(alias, "{}") {
        Ok(_) => panic!("a store library signed as secret opened"),
        Err(e) => e,
    };
    assert!(
        e.contains(&format!(
            "plugin '{name}' exports kind 'store' but is being loaded as 'secret'"
        )),
        "{e}"
    );

    // RED ARM 2: the same bytes dropped in under a statement that is not the linked row (another
    // alias) are not the linked store's transcript — the comparison above covers the row itself,
    // not only what the store answers.
    let shadow = Manifest {
        alias: "mysql-shadow".into(),
        ..statement("store")
    };
    let red_registry = dropped("red", shadow, &lib);
    let red = transcript(&red_registry, "mysql-shadow", url);
    assert_ne!(
        red, linked,
        "a different statement must not read as the same row"
    );
    assert_eq!(
        red["refusals"], linked["refusals"],
        "the store's own answers are the same bytes' answers"
    );
}
