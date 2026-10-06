// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE STORE, BOTH DOORS, ONE TABLE** — the MySQL store's linked + dropped-in conformance on the
//! store kind's memory ABI (store v3), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (the logic crate's `door`, as a busbar build that
//! compiles it in registers it: `LinkedRow::of(door)` through the loader's `load_linked`) and
//! DROPPED IN (this crate's built cdylib, its Statement rendered the way `busbar-plugin-pack`
//! renders it into the signed manifest, then `dlopen`ed by the loader's `load_dropped`). Each is
//! bound to its own dispatcher and opened the way the host opens a store (`LoadedStore`), and gives
//! one transcript: the Statement facts, the refusals the store's own `open` answers for bad
//! settings, and — against a live MySQL — a scenario through the 1.5.5 op set and the v3 slots
//! (window caps, a whole-cell reserve, its replay, a release, the journal, sessions and records).
//! The two transcripts must agree line for line.
//!
//! THE RED ARMS, each its own test: the library asked for as another kind is refused before `dlopen`; a
//! manifest rendering that is not the library's own Statement is refused; and the comparison is
//! not vacuous (the live scenario reads back what it wrote).
//!
//! The live scenario follows this repo's `BUSBAR_TEST_MYSQL_URL` gate (set: runs; unset under CI: a
//! failure; unset locally: skipped with a line saying so). Everything else needs no database and
//! always runs. A missing cdylib PANICS: this test IS the dropped-in door's proof.

// THE PUBLISHED SUITE (busbar-plugin-loader's `conformance` feature, at the pin): the linked door and
// the built cdylib, each through the one loader, driven by the store kind's script over the live
// MySQL `conformance.json` names; exact crossing counts, the two folds equal, its RED arms.
//
// THE HOST: the store's one `tcp` need is served by busbar's own connector, composed as the root
// composes it (`conformance_host`, rendered by the fleet template). No `tls:`: the store has no TLS
// option (its URL names none, and one that does is refused, as 1.5.5's was).
//
// Each fold opens over a DATABASE of its own: conformance.json's url names `{fold}` as its database,
// and the hooks below create that database before the fold and drop it after, on an independent
// connection of the `mysql` driver. The service's store user may not create a database, so the hooks
// connect as the server's root (a test-only account: `BUSBAR_TEST_MYSQL_ROOT_PASSWORD`, the service
// container's `busbar` when unset) and grant the settings' user the fold's database. The store never
// creates a database; nothing in its behaviour changes.
//
// THE KEY IDS: this store's `usage_metering.key_id` is a FOREIGN KEY to `api_keys` (a metering row
// names a key that exists), and the store kind's script meters keys `a` and `z` without putting
// them; so conformance.json's `keys.grouped` and `keys.plain` ARE `a` and `z`, put (and tombstoned,
// never removed) before the script meters them.
#[path = "support/conformance_host.rs"]
mod conformance_host;

busbar_plugin_loader::conformance_suite! {
    door: busbar_store_mysql::door,
    cdylib: "busbar_store_mysql_plugin",
    inputs: include_str!("conformance.json"),
    host: conformance_host::host,
    namespace: (create_fold_database, drop_fold_database),
}

/// The live server a fold's filled settings name, as the server's root on a connection of the
/// `mysql` driver's own, and the settings' user (the one the store connects as).
fn fold_root(settings: &[u8]) -> (mysql::Conn, String) {
    let v: serde_json::Value =
        serde_json::from_slice(settings).expect("conformance.json's settings are JSON");
    let url = v["url"]
        .as_str()
        .expect("conformance.json's settings name a url");
    let opts = mysql::Opts::from_url(url).expect("conformance.json's url is a mysql url");
    let user = opts.get_user().unwrap_or_default().to_owned();
    let password =
        std::env::var("BUSBAR_TEST_MYSQL_ROOT_PASSWORD").unwrap_or_else(|_| "busbar".to_owned());
    let root = mysql::OptsBuilder::from_opts(opts)
        .user(Some("root"))
        .pass(Some(password))
        .db_name(None::<String>);
    let conn = mysql::Conn::new(root).expect("the live MySQL accepts the test client as root");
    (conn, user)
}

/// The suite's namespace hook: the fold's database, made before its open, its whole use granted to
/// the user the store connects as.
fn create_fold_database(namespace: &str, settings: &[u8]) {
    use mysql::prelude::Queryable;
    let (mut root, user) = fold_root(settings);
    root.query_drop(format!("CREATE DATABASE IF NOT EXISTS `{namespace}`"))
        .expect("the fold's database is created");
    root.query_drop(format!(
        "GRANT ALL PRIVILEGES ON `{namespace}`.* TO '{user}'@'%'"
    ))
    .expect("the fold's database is granted to the store's user");
}

/// The suite's namespace hook: the fold's database and everything the store made in it, dropped
/// after the fold, and its grant revoked.
fn drop_fold_database(namespace: &str, settings: &[u8]) {
    use mysql::prelude::Queryable;
    let (mut root, user) = fold_root(settings);
    root.query_drop(format!("DROP DATABASE IF EXISTS `{namespace}`"))
        .expect("the fold's database is dropped");
    root.query_drop(format!(
        "REVOKE ALL PRIVILEGES ON `{namespace}`.* FROM '{user}'@'%'"
    ))
    .expect("the fold's grant is revoked");
}

use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::sdk::store::{Cap, Cell, CellKey, Dimension};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, VirtualKey,
};
use busbar_contract::store_calls::StoreCalls;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::store_v3::LoadedStore;

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
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_store_mysql_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-store-mysql-plugin cdylib ({file}) is not built"))
}

/// What a door is bound to: its own dispatcher's adopter, no envelope sink, and the loader's test
/// connection table (plain TCP, the host's connector path) for the one `tcp` need the store states.
fn bind(d: &Dispatcher) -> Bind {
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> = Arc::new(
        busbar_plugin_loader::tcp_conns::TcpConns::new(d.conn_waker()),
    );
    Bind {
        instance: Arc::from("store-mysql-conformance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(conns),
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

/// The library's Statement as `busbar-plugin-pack` renders it into the signed manifest.
fn packed_rendering(lib: &std::path::Path) -> Vec<u8> {
    rendering_of_library(lib)
        .expect("the library's door renders")
        .expect("the library exports a door")
}

/// One door, loaded one way: a plugin and the dispatcher that adopted it.
type Loaded = (Plugin<Store>, Arc<Dispatcher>);

/// THE LINKED DOOR: the row a busbar build that compiles this store in registers.
fn linked() -> Loaded {
    let d = dispatcher();
    let row = LinkedRow::of(busbar_store_mysql::door).expect("the door states its Statement");
    let p = load_linked::<Store>(&row, bind(&d)).expect("the linked door loads");
    (p, d)
}

/// THE DROPPED-IN DOOR: the built cdylib against the rendering its manifest would carry.
fn dropped(lib: &std::path::Path, stated: &[u8]) -> Loaded {
    let d = dispatcher();
    let p = load_dropped::<Store>(lib, stated, bind(&d)).expect("the dropped-in door loads");
    (p, d)
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// The ids the live scenario writes; removed before and after each arm, so both arms start from the
/// same database state.
const KEY_ID: &str = "vk_conformance_doors";
const TASK_ID: &str = "conformance-doors-task";
const PARENT: &str = "conformance-doors-parent";
const TOKEN: &str = "conformance-doors-nonce";
const BUCKET: &str = "conformance-doors-bucket";
const STREAM: &str = "conformance-doors-stream";
const SCHEMA: &str = "conformance-doors-schema";
const PRINCIPAL: &str = "conformance-doors-principal";
/// The epoch the scenario draws at: the fence is one row of the shared database, so every draw
/// against it states the same high epoch (see `store-mysql`'s slots tests).
const EPOCH: u64 = 1 << 62;

fn clear(url: &str) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(mysql::Opts::from_url(url).unwrap()).expect("connect");
    for (sql, v) in [
        ("DELETE FROM api_keys WHERE id = ?", KEY_ID),
        ("DELETE FROM plane_records WHERE ident = ?", TASK_ID),
        ("DELETE FROM plane_records WHERE parent = ?", PARENT),
        ("DELETE FROM plane_tokens WHERE token = ?", TOKEN),
        ("DELETE FROM store_caps WHERE bucket = ?", BUCKET),
        ("DELETE FROM store_slices WHERE bucket = ?", BUCKET),
        ("DELETE FROM store_journal WHERE stream = ?", STREAM),
        ("DELETE FROM store_records WHERE schema_id = ?", SCHEMA),
        ("DELETE FROM store_sessions WHERE principal = ?", PRINCIPAL),
    ] {
        conn.exec_drop(sql, (v,))
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
}

/// A node id no earlier run or instance used, for `LoadedStore::open`: its bridge mints each op id
/// as `(node, counter from 0)`, and this store's dedupe is DURABLE, so two instances sharing a node
/// would replay each other's op ids (the kernel draws the node from the OS CSPRNG per process).
fn node() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (t ^ (u64::from(std::process::id()) << 32))
        .wrapping_add(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) << 48)
        | 1
}

/// The node's one `op_id` allocator (`LoadedStore::open` mints the bridge's writes from it): a node
/// half no earlier run used (the dedupe is durable) and one counter.
fn mint() -> OpId {
    static NODE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(node);
    OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// A fresh op id (the dedupe is durable: an op id from an earlier run would replay).
fn op(counter: u64) -> OpId {
    OpId::from_parts(node(), counter * 2 + 1)
}

/// What one door does with `url`, as one comparable transcript. `load` loads the door afresh: a
/// refused `open` consumes the instance it was offered.
fn transcript(load: impl Fn() -> Loaded, url: Option<&str>) -> Vec<String> {
    let mut t = vec![format!("name = {}", load().0.name())];
    // The store's own `open`, refusing settings it cannot run, in its own words.
    for cfg in [
        "",
        "{ not json",
        r#"{"url": "  "}"#,
        r#"{"url": "mysql://nobody:none@127.0.0.1:9/nowhere"}"#,
    ] {
        let (plugin, dispatcher) = load();
        let answer = LoadedStore::open(plugin, dispatcher, cfg.as_bytes(), mint).map(|_| ());
        t.push(format!("open {cfg:?} = {answer:?}"));
    }
    let Some(url) = url else {
        return t;
    };
    let (plugin, dispatcher) = load();
    clear(url);
    let settings = serde_json::json!({ "url": url }).to_string();
    let s =
        LoadedStore::open(plugin, dispatcher, settings.as_bytes(), mint).expect("the store opens");
    t.push(format!("facts = {:?}", s.facts()));

    // The 1.5.5 op set.
    let key = VirtualKey {
        id: KEY_ID.into(),
        generation_hash: format!("binding:{KEY_ID}:g1"),
        name: "conformance doors".into(),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    };
    t.push(format!("put_key = {:?}", s.put_key(&key)));
    t.push(format!(
        "get_key = {:?}",
        s.get_key(KEY_ID)
            .map(|k| k.map(|k| (k.id, k.name, k.enabled, k.created_at)))
    ));
    let task = PlaneRecord {
        kind: "task".into(),
        id: TASK_ID.into(),
        parent: None,
        seq: 0,
        ts: 1_700_000_100,
        disposition: PlaneDisposition::Active,
        body: b"{\"state\":\"working\"}".to_vec(),
    };
    t.push(format!(
        "upsert = {:?}",
        RecordStore::upsert_plane_record(&s, task.view())
    ));
    t.push(format!(
        "get task = {:?}",
        RecordStore::get_plane_record(&s, "task", TASK_ID)
            .map(|b| b.map(|b| String::from_utf8_lossy(&b).into_owned()))
    ));
    for seq in 1..=3u64 {
        let ev = PlaneRecord {
            kind: "task_event".into(),
            id: format!("{TASK_ID}-e{seq}"),
            parent: Some(PARENT.into()),
            seq,
            ts: 1_700_000_100 + seq,
            disposition: PlaneDisposition::Terminal,
            body: format!("event {seq}").into_bytes(),
        };
        t.push(format!(
            "append {seq} = {:?}",
            RecordStore::append_plane_record(&s, ev.view())
        ));
    }
    t.push(format!(
        "chain = {:?}",
        RecordStore::list_plane_records(&s, "task_event", &PlaneSelector::Parent(PARENT.into()))
            .map(|v| v
                .into_iter()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .collect::<Vec<_>>())
    ));
    t.push(format!(
        "redeem = {:?} then {:?}",
        RecordStore::redeem_plane_token(&s, "ask", TOKEN, 1_700_009_000, 1_700_000_000),
        RecordStore::redeem_plane_token(&s, "ask", TOKEN, 1_700_009_000, 1_700_000_001)
    ));
    t.push(format!("delete_key = {:?}", s.delete_key(KEY_ID)));
    t.push(format!(
        "after delete = {:?}",
        s.get_key(KEY_ID).map(|k| k.map(|k| k.enabled))
    ));

    // The v3 slots.
    let k = CellKey {
        bucket: BUCKET,
        pool: None,
        dimension: Dimension::Requests,
        window_start: 60,
    };
    let cells = [Cell { key: k, amount: 2 }, Cell { key: k, amount: 1 }];
    block(async {
        t.push(format!(
            "reserve, no cap = {:?}",
            StoreCalls::reserve(&s, op(1), EPOCH, &cells).await
        ));
        let caps = [Cap {
            key: k,
            cap: 3,
            config_gen: 1,
        }];
        t.push(format!(
            "window_caps = {:?}",
            StoreCalls::window_caps(&s, op(2), &caps).await
        ));
        let id = op(3);
        let grants = StoreCalls::reserve(&s, id, EPOCH, &cells).await;
        t.push(format!(
            "reserve = {:?}",
            grants
                .as_ref()
                .map(|g| g.iter().map(|g| g.granted).collect::<Vec<_>>())
        ));
        let replay = StoreCalls::reserve(&s, id, EPOCH, &cells).await;
        t.push(format!(
            "replay answers the original grants = {}",
            replay.as_ref().ok() == grants.as_ref().ok()
        ));
        t.push(format!(
            "reserve past the cap = {:?}",
            StoreCalls::reserve(&s, op(4), EPOCH, &cells[1..]).await
        ));
        if let Ok(g) = &grants {
            let items = [(g[0].slice_id, 5)];
            t.push(format!(
                "release = {:?}",
                StoreCalls::slice_release(&s, op(5), EPOCH, &items).await
            ));
        }
        let r = |b: &[u8]| RecordBytes::new(b.to_vec()).unwrap();
        t.push(format!(
            "append_batch = {:?}",
            StoreCalls::append_batch(&s, op(6), STREAM, &[r(b"one"), r(b"two")]).await
        ));
        t.push(format!(
            "record_put = {:?}",
            StoreCalls::record_put(&s, SCHEMA, b"k", &r(b"v")).await
        ));
        t.push(format!(
            "record_get = {:?}",
            StoreCalls::record_get(&s, SCHEMA, b"k")
                .await
                .map(|v| v.map(|v| String::from_utf8_lossy(v.as_slice()).into_owned()))
        ));
        t.push(format!(
            "session_put = {:?}",
            StoreCalls::session_put(&s, 42_424_242, "node-a", PRINCIPAL).await
        ));
        t.push(format!(
            "sessions_for = {:?}",
            StoreCalls::sessions_for(&s, PRINCIPAL).await
        ));
        t.push(format!(
            "session_remove = {:?}",
            StoreCalls::session_remove(&s, 42_424_242).await
        ));
    });
    drop(s);
    clear(url);
    t
}

/// The two transcripts are equal, line for line; a divergence names its first line.
fn same(linked: &[String], dropped: &[String]) {
    for (i, (a, b)) in linked.iter().zip(dropped).enumerate() {
        assert_eq!(
            a, b,
            "the two doors diverge at line {i}:\n linked:     {a}\n dropped in: {b}"
        );
    }
    assert_eq!(
        linked.len(),
        dropped.len(),
        "the two doors ran different scripts"
    );
}

/// The MySQL store behaves as ONE store through either door (the RED arms below: the library asked
/// for as another kind, or under a Statement that is not its own, is refused).
#[test]
fn the_linked_and_the_dropped_in_mysql_store_are_one_store() {
    let url = mysql_url();
    let url = url.as_deref();
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    assert_eq!(
        stated,
        LinkedRow::of(busbar_store_mysql::door)
            .expect("the linked row")
            .statement,
        "the dropped-in library states the linked door's Statement byte for byte"
    );

    let linked = transcript(linked, url);
    let dropped_in = transcript(|| dropped(&lib, &stated), url);
    same(&linked, &dropped_in);
    assert_eq!(linked[0], format!("name = {}", busbar_store_mysql::NAME));

    if url.is_some() {
        // The comparison is not vacuous: the scenario read back what it wrote.
        let find = |p: &str| {
            linked
                .iter()
                .find(|l| l.starts_with(p))
                .unwrap_or_else(|| panic!("no {p} line in {linked:#?}"))
                .clone()
        };
        assert!(find("facts").contains("ephemeral: false"), "{linked:#?}");
        assert!(find("get_key").contains("conformance doors"), "{linked:#?}");
        assert!(find("get task").contains("working"), "{linked:#?}");
        assert!(find("chain").contains("event 3"), "{linked:#?}");
        assert!(
            find("redeem").contains("Ok(true) then Ok(false)"),
            "{linked:#?}"
        );
        assert!(find("reserve, no cap").contains("NoCap"), "{linked:#?}");
        assert_eq!(find("reserve ="), "reserve = Ok([2, 1])");
        assert!(find("replay").ends_with("true"), "{linked:#?}");
        assert!(find("reserve past").contains("Exhausted"), "{linked:#?}");
        assert_eq!(find("release"), "release = Ok([2])");
        assert!(find("append_batch").contains("seq: 2"), "{linked:#?}");
        assert_eq!(find("record_get"), "record_get = Ok(Some(\"v\"))");
        assert!(find("sessions_for").contains("node-a"), "{linked:#?}");
    }
    // The store's own words reach the host through either door.
    assert!(linked[1].contains("requires a \\\"url\\\""), "{linked:#?}");
    assert!(
        linked[2].contains("invalid mysql plugin config"),
        "{linked:#?}"
    );
    assert!(linked[3].contains("requires a \\\"url\\\""), "{linked:#?}");
    assert!(
        linked[4].starts_with("open") && linked[4].contains("Err("),
        "{linked:#?}"
    );
}

/// RED ARM 1: the library asked for as another kind is refused before it is opened. No database
/// needed.
#[test]
fn a_store_library_loaded_as_another_kind_is_refused() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let d = dispatcher();
    let e = match load_dropped::<Secret>(&lib, &stated, bind(&d)) {
        Ok(_) => panic!("a store library loaded as secret"),
        Err(e) => e.to_string(),
    };
    assert!(
        e.contains("the manifest states kind Store, not Secret"),
        "{e}"
    );
}

/// RED ARM 2: a manifest whose Statement is not the library's own is refused. No database needed.
#[test]
fn a_statement_that_is_not_the_librarys_own_is_refused() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let mut other = stated.clone();
    other.push(0);
    let d = dispatcher();
    let e = match load_dropped::<Store>(&lib, &other, bind(&d)) {
        Ok(_) => panic!("a library loaded under a Statement that is not its own"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("repack the plugin"), "{e}");
}
