// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-mysql-plugin` cdylib, loaded the way a REAL operator
//! actually loads a plugin — not via a direct in-process `load()` call
//! (that mechanism no end user ever uses: nobody imports `busbar-plugin-loader` and calls its
//! internal function). Converted from the prior direct-call test to mirror store-postgres's proven
//! file-drop pattern exactly.
//!
//! `load_and_exercise_mysql_plugin_via_file_drop` packs the built cdylib into a real tarball (the
//! same `busbar-plugin-pack` tool CI's own SIGNOFF step uses), drops it into a real `plugins.dir`,
//! and boots the REAL `busbar` binary against a config naming `store: { module: mysql }` — the
//! documented file-drop install path, on a fresh private database. Validation alone does not open
//! the store. A raw database connection observes the child's schema/version before any linked
//! store is opened, and the child must also reach its serving listener.
//!
//! Persistence is then proven the same two independent ways the prior direct-call test used:
//!   1. The child's boot (via the plugin's `open()` and its connect step) runs the real schema
//!      migration — confirmed through raw SQL scoped to the private database.
//!   2. A second, independent store through the COMPILED-IN door (never the cdylib) confirms real
//!      MySQL was actually touched, not an in-process fake.
//!
//! The ABI-contract tests below load the cdylib DIRECTLY through the loader's dropped-in door
//! ([`load`]: the Statement rendered as `busbar-plugin-pack` renders it, `load_dropped`, then
//! `LoadedStore::open`, the way the host opens a store) — they test the store table's own contract
//! in isolation ("does a bad config produce a clean Err across the ABI, never a panic"; "does
//! every verb relay"), a different question from "does a real end-user install work".

mod common;

use busbar_contract::records::RecordStore;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use common::{build_real_binaries, cleanup, mint, plugin_path, ScratchDb, E2E_RELEASE_PRIVKEY};
use mysql::params;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A dispatcher and a bind over the loader's test connection table (plain TCP, the host's connector path): every connection the store makes is one the "host" dials.
fn host(instance: &str) -> (Arc<Dispatcher>, Bind) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> =
        common::mysql_io::host(dispatcher.conn_waker(), Default::default());
    let bind = Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Host(conns),
    };
    (dispatcher, bind)
}

/// Load the store library at `path` through the DROPPED-IN DOOR and open it on `cfg`, the way the host opens a store: its Statement rendered as `busbar-plugin-pack` signs it into the manifest, `load_dropped` (dlopen, `busbar_plugin_door`, the Statement compared byte for byte), then `LoadedStore::open`.
fn load(path: &Path, cfg: &str) -> Result<Box<dyn RecordStore>, String> {
    let stated = rendering_of_library(path)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the library exports no busbar_plugin_door".to_string())?;
    let (dispatcher, bind) = host("store-mysql-e2e");
    let plugin = load_dropped::<Store>(path, &stated, bind).map_err(|e| e.to_string())?;
    let store = LoadedStore::open(plugin, dispatcher, cfg.as_bytes(), mint)?;
    Ok(Box::new(store))
}

/// The store through its COMPILED-IN door (`busbar_store_mysql::door`, never the cdylib): the independent leg the dropped-in store's writes are migrated, read back and cleaned up through.
struct MysqlStore;

impl MysqlStore {
    fn connect(url: &str) -> Result<LoadedStore, String> {
        let (dispatcher, bind) = host("store-mysql-e2e-direct");
        let row = busbar_plugin_loader::dispatch::LinkedRow::of(busbar_store_mysql::door)
            .map_err(|e| e.to_string())?;
        let plugin = busbar_plugin_loader::dispatch::load_linked::<Store>(&row, bind)
            .map_err(|e| e.to_string())?;
        let cfg = serde_json::json!({ "url": url }).to_string();
        LoadedStore::open(plugin, dispatcher, cfg.as_bytes(), mint)
    }
}

fn mysql_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql:8 service container must \
                 provision it (see .github/workflows/ci.yml). Refusing to silently skip the only \
                 real-install-path coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_MYSQL_URL to run the live-MySQL e2e tests");
            None
        }
    }
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// Every `env:` secret-ref name a config text references, in first-seen order, de-duplicated.
fn referenced_env_vars(text: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for (i, _) in text.match_indices("env:") {
        let rest = &text[i + 4..];
        let name: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !v.contains(&name) {
            v.push(name);
        }
    }
    v
}

/// THE REAL END-TO-END INSTALL PROOF: pack the plugin, drop it in a real `plugins.dir`, run the real `busbar` boot against a config naming `store: { module: mysql }`, and confirm real MySQL was actually touched — via the documented file-drop mechanism, never a direct `load()` call.
#[test]
fn load_and_exercise_mysql_plugin_via_file_drop() {
    use mysql::prelude::*;
    let Some(server) = mysql_url() else { return };
    let db = ScratchDb::new(&server);
    let url = &db.url;
    let mut raw =
        mysql::Conn::new(mysql::Opts::from_url(&crate::common::raw_mysql_url(url)).unwrap())
            .unwrap();
    let initial_tables: u64 = raw
        .query_first("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()")
        .unwrap()
        .unwrap();
    assert_eq!(
        initial_tables, 0,
        "the child receives a fresh private database"
    );
    let so_path = plugin_path();

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-mysql-filedrop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    let tarball = work.join("store-mysql.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-mysql",
            "--alias",
            "mysql",
            "--kind",
            "store",
            "--version",
            env!("CARGO_PKG_VERSION"),
            "--publisher",
            "busbar",
            "--description",
            "e2e file-drop proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", E2E_RELEASE_PRIVKEY)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    std::fs::copy(&tarball, plugins_dir.join("store-mysql.tar.gz")).unwrap();
    let retained = std::fs::read(plugins_dir.join("store-mysql.tar.gz")).unwrap();
    assert_eq!(
        retained,
        std::fs::read(&tarball).unwrap(),
        "the file drop retains the exact packed signed archive"
    );
    let archive_pin = busbar_contract::redacted::sha256_hex(&retained);

    let config = work.join("config.yaml");
    let providers = work.join("providers.yaml");
    let data_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    let config_text = format!(
        "listen: \"127.0.0.1:{data_port}\"\n\
         admin_listen: \"127.0.0.1:0\"\n\
         store:\n  module: mysql\n  settings: {{ url: \"{url}\" }}\n\
         plugins:\n  enabled: true\n  dir: {}\n  fetch:\n    - url: \"https://plugins.example/store-mysql.tar.gz\"\n      sha256: \"{archive_pin}\"\n  trust:\n    allow_unsigned: true\n\
         auth:\n  chain: []\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );
    std::fs::write(&config, &config_text).unwrap();

    let mut boot = Command::new(&busbar_bin);
    boot.env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_STATE_FILE", "");
    for name in referenced_env_vars(&config_text) {
        boot.env(
            name,
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
    }
    let log_path = work.join("boot.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = ChildGuard(
        boot.stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("boot the real file-drop process"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let expected_schema = busbar_store_mysql::SCHEMA_VERSION.to_string();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "file-drop boot exited: {status}\n{}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            );
        }
        let tables: u64 = raw
            .query_first(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() \
             AND table_name IN ('api_keys','credentials','store_meta','store_sequence')",
            )
            .unwrap()
            .unwrap();
        if tables == 4 {
            let version: Option<String> = raw
                .query_first("SELECT v FROM store_meta WHERE k='schema_version'")
                .unwrap();
            let migrating: Option<String> = raw
                .query_first("SELECT v FROM store_meta WHERE k='migrating_to'")
                .unwrap();
            let sequence: u64 = raw
                .query_first("SELECT COUNT(*) FROM store_sequence WHERE id=1")
                .unwrap()
                .unwrap();
            if version.as_deref() == Some(expected_schema.as_str())
                && migrating.is_none()
                && sequence == 1
                && std::net::TcpStream::connect(("127.0.0.1", data_port)).is_ok()
            {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "file-drop boot never completed its own schema and listener\n{}",
            std::fs::read_to_string(&log_path).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    drop(child);
    drop(MysqlStore::connect(url).expect("the independently witnessed schema also opens linked"));

    let _ = std::fs::remove_dir_all(&work);
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct `load()` call): an `open()` config that cannot produce a usable store surfaces back across the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_mysql_plugin_bad_config_fails_over_abi() {
    let path = plugin_path();

    let err = load(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid mysql plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = load(&path, "{}")
        .err()
        .expect("a config missing url must fail to load");
    assert!(
        err.contains("requires a \"url\""),
        "expected the plugin's own missing-url message, got: {err}"
    );

    let err = load(
        &path,
        &cfg("mysql://u:CANARYpw9@127.0.0.1:1/definitely_not_a_real_db"),
    )
    .err()
    .expect("an unreachable mysql target must fail to load");
    eprintln!("connect failure: {err}");
    assert!(
        err.contains("Could not connect") && err.contains("127.0.0.1:1"),
        "expected the driver's own connect-failure text to survive the ABI crossing, got: {err}"
    );
    assert!(
        !err.contains("CANARYpw9"),
        "the URL password must never reach the refusal: {err}"
    );
}

/// A non-plugin library (or a missing file) is refused with a clear error, never a crash.
#[test]
fn refuses_non_plugin() {
    let err = match load(std::path::Path::new("/definitely/not/a/plugin.so"), "{}") {
        Err(e) => e,
        Ok(_) => panic!("a missing library must not load"),
    };
    assert!(err.contains("did not load"), "got: {err}");
}

/// Wipe the durable plane-record tables so this run's exact counts mean something.
fn wipe_task_and_call_rows(url: &str) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(
        mysql::Opts::from_url(&crate::common::raw_mysql_url(url)).expect("test url must parse"),
    )
    .expect("connect to wipe the durable task/call-log rows");
    conn.query_drop("DELETE FROM plane_records WHERE kind IN ('task', 'task_event', 'call')")
        .unwrap_or_else(|e| panic!("wipe the task/call plane rows: {e}"));
}

fn body(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("serialize a test body")
}

fn decode(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).expect("a body this test wrote decodes")
}

/// THE DURABILITY PROOF FOR THE PLANE-RECORD VERBS, OVER THE REAL PLUGIN PATH.
#[test]
fn tasks_and_call_log_survive_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};

    let path = plugin_path();
    let Some(url) = mysql_url() else {
        return;
    };
    let config = cfg(&url);

    let direct =
        MysqlStore::connect(&url).expect("connect directly to migrate, clean up and verify");
    wipe_task_and_call_rows(&url);

    let task =
        |id: &str, state: &str, updated_at: u64, disposition: PlaneDisposition| PlaneRecord {
            kind: "task".into(),
            id: id.into(),
            parent: None,
            seq: 0,
            ts: updated_at,
            disposition,
            body: body(serde_json::json!({
                "task_id": id, "context_id": format!("ctx-{id}"), "principal": "vk_abi",
                "direction": "inbound", "state": state, "agent_id": "planner",
                "artifact_cursor": 7, "push_callback": "https://example.test/push",
                "created_at": 1_000, "updated_at": updated_at,
            })),
        };
    let event = |task_id: &str, seq: u64, prev: &str, hash: &str| PlaneRecord {
        kind: "task_event".into(),
        id: task_id.into(),
        parent: Some(task_id.into()),
        seq,
        ts: 1_000 + seq,
        disposition: PlaneDisposition::Active,
        body: body(serde_json::json!({
            "task_id": task_id, "seq": seq, "ts": 1_000 + seq, "kind": "task.working",
            "prev_hash": prev, "hash": hash,
        })),
    };
    let call = |principal: &str, seq: u64, prev: &str, hash: &str| PlaneRecord {
        kind: "call".into(),
        id: principal.into(),
        parent: Some(principal.into()),
        seq,
        ts: 2_000 + seq,
        disposition: PlaneDisposition::Active,
        body: body(serde_json::json!({
            "seq": seq, "prev_hash": prev, "hash": hash,
            "content": format!("srv|srv_read_file|dispatched|sha256:tool{seq}|3"),
        })),
    };
    let ids_of = |bodies: Vec<Vec<u8>>| -> Vec<String> {
        let mut v: Vec<String> = bodies
            .iter()
            .map(|b| decode(b)["task_id"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    };
    let seqs_of = |bodies: &[Vec<u8>]| -> Vec<u64> {
        bodies
            .iter()
            .map(|b| decode(b)["seq"].as_u64().unwrap())
            .collect()
    };

    {
        let store = load(&path, &config).expect("the mysql plugin must load over the real ABI");
        for (id, state, updated, d) in [
            ("t_alpha", "working", 10_u64, PlaneDisposition::Active),
            ("t_beta", "input-required", 20, PlaneDisposition::Active),
            ("t_gamma", "completed", 30, PlaneDisposition::Terminal),
        ] {
            store
                .upsert_plane_record(task(id, state, updated, d).view())
                .expect("upsert a task");
        }

        for (seq, prev, hash) in [(2_u64, "e1", "e2"), (1, "", "e1"), (3, "e2", "e3")] {
            store
                .append_plane_record(event("t_alpha", seq, prev, hash).view())
                .expect("append a task event");
        }
        store
            .append_plane_record(event("t_beta", 1, "", "b1").view())
            .expect("append a task event");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_plane_record(call("vk_abi", seq, prev, hash).view())
                .expect("append a call");
        }
        store
            .append_plane_record(call("vk_other", 1, "", "o1").view())
            .expect("append a call");

        drop(store);
    }

    let store = load(&path, &config).expect("the mysql plugin must load again over the real ABI");

    let tasks = store
        .list_plane_records("task", &PlaneSelector::All)
        .expect("list tasks");
    assert_eq!(
        ids_of(tasks),
        vec!["t_alpha", "t_beta", "t_gamma"],
        "all three tasks must survive the unload/reload over the plugin ABI — an empty answer is \
         the accept-and-keep-nothing shape of the trait default an unrelayed seam substitutes"
    );
    let beta = store
        .get_plane_record("task", "t_beta")
        .expect("get a task")
        .expect("the interrupted task must be readable by id after a reload");
    assert_eq!(
        beta,
        task("t_beta", "input-required", 20, PlaneDisposition::Active).body,
        "the opaque body must round-trip the ABI byte-for-byte"
    );

    let events = store
        .list_plane_records("task_event", &PlaneSelector::Parent("t_alpha".into()))
        .expect("list task events");
    assert_eq!(
        seqs_of(&events),
        vec![1, 2, 3],
        "the per-task provenance chain must come back oldest-first and complete"
    );
    for w in events.windows(2) {
        assert_eq!(decode(&w[1])["prev_hash"], decode(&w[0])["hash"]);
    }
    assert_eq!(
        store
            .list_plane_records("task_event", &PlaneSelector::Parent("t_beta".into()))
            .expect("list task events")
            .len(),
        1,
        "one task's events must not leak into another's chain"
    );

    let calls = store
        .list_plane_records("call", &PlaneSelector::Parent("vk_abi".into()))
        .expect("list calls");
    assert_eq!(seqs_of(&calls), vec![1, 2, 3]);
    assert_eq!(calls[2], call("vk_abi", 3, "h2", "h3").body);
    assert_eq!(
        store
            .list_plane_record_parents("call")
            .expect("list call parents"),
        vec!["vk_abi".to_string(), "vk_other".to_string()],
        "the boot enumeration must name every principal holding records, exactly once each"
    );

    assert!(
        store
            .append_plane_record(call("vk_abi", 1, "", "FORKED").view())
            .is_err(),
        "a different record at an occupied chain position must be refused across the ABI"
    );

    assert_eq!(
        store
            .purge_plane_records_before("call", 2_002)
            .expect("purge calls"),
        2,
        "both records at ts 2001 go (one per principal); the one exactly at the cutoff stays"
    );
    assert_eq!(
        store
            .purge_plane_records("task", 25, busbar_contract::records::Retention::TerminalOnly)
            .expect("purge tasks"),
        0,
        "no TERMINAL task is older than the cutoff: t_alpha and t_beta are active and must never be \
         swept no matter how old"
    );
    assert_eq!(
        store
            .purge_plane_records(
                "task",
                31,
                busbar_contract::records::Retention::TerminalOnly
            )
            .expect("purge tasks"),
        1,
        "the one terminal task at ts 30 is the only row retention may drop"
    );
    drop(store);

    assert_eq!(
        ids_of(
            RecordStore::list_plane_records(&direct, "task", &PlaneSelector::All)
                .expect("list tasks via the direct connection")
        ),
        vec!["t_alpha", "t_beta"],
        "the tasks must be physically present in MySQL, not just cached in-process by the plugin"
    );
    let direct_events = RecordStore::list_plane_records(
        &direct,
        "task_event",
        &PlaneSelector::Parent("t_alpha".into()),
    )
    .expect("list task events via the direct connection");
    assert_eq!(seqs_of(&direct_events), vec![1, 2, 3]);
    let direct_calls =
        RecordStore::list_plane_records(&direct, "call", &PlaneSelector::Parent("vk_abi".into()))
            .expect("list calls via the direct connection");
    assert_eq!(seqs_of(&direct_calls), vec![2, 3]);
    assert!(RecordStore::list_plane_records(
        &direct,
        "call",
        &PlaneSelector::Parent("vk_other".into())
    )
    .expect("list calls")
    .is_empty());

    wipe_task_and_call_rows(&url);
}

/// Drop exactly this run's own trust-state rows.
fn clear_trust_rows(url: &str, servers: &[&str], nonces: &[&str]) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(
        mysql::Opts::from_url(&crate::common::raw_mysql_url(url)).expect("test url must parse"),
    )
    .expect("connect to clear this run's trust-state rows");
    for s in servers {
        conn.exec_drop(
            "DELETE FROM plane_records WHERE kind = 'demotion' AND ident = :s",
            params! { "s" => *s },
        )
        .unwrap_or_else(|e| panic!("clear demotion {s}: {e}"));
    }
    for n in nonces {
        conn.exec_drop(
            "DELETE FROM plane_tokens WHERE kind = 'ask' AND token = :n",
            params! { "n" => *n },
        )
        .unwrap_or_else(|e| panic!("clear ledger row {n}: {e}"));
    }
}

/// THE DURABILITY PROOF FOR THE TRUST STATE, OVER THE REAL PLUGIN PATH: the `demotion` kind (upsert / list / delete) and the `ask` single-use token (`redeem_plane_token`).
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};

    let path = plugin_path();
    let url = std::env::var("BUSBAR_TEST_MYSQL_URL").unwrap_or_else(|_| {
        panic!(
            "BUSBAR_TEST_MYSQL_URL is unset, and this case must not skip: it is the only \
             over-the-ABI proof that a demotion and a spent approval survive a restart on this \
             backend, and both fail SILENTLY when unrelayed"
        )
    });
    let config = cfg(&url);
    let direct =
        MysqlStore::connect(&url).expect("connect directly to migrate, clean up and verify");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let srv_demoted = format!("srv_abi_demoted_{stamp}");
    let srv_cleared = format!("srv_abi_cleared_{stamp}");
    let nonce_restart = format!("nonce_abi_restart_{stamp}");
    let nonce_fleet = format!("nonce_abi_fleet_{stamp}");
    let nonce_fresh = format!("nonce_abi_fresh_{stamp}");
    const NOW: u64 = 4_000_000_000;

    clear_trust_rows(
        &url,
        &[&srv_demoted, &srv_cleared],
        &[&nonce_restart, &nonce_fleet, &nonce_fresh],
    );

    let demotion = |server: &str, reason: &str, at: u64| PlaneRecord {
        kind: "demotion".into(),
        id: server.into(),
        parent: None,
        seq: 0,
        ts: at,
        disposition: PlaneDisposition::Active,
        body: body(serde_json::json!({ "server": server, "reason": reason, "recorded_at": at })),
    };
    let mine = |store: &dyn RecordStore| -> Vec<serde_json::Value> {
        store
            .list_plane_records("demotion", &PlaneSelector::All)
            .expect("list demotions")
            .iter()
            .map(|b| decode(b))
            .filter(|d| d["server"] == srv_demoted.as_str() || d["server"] == srv_cleared.as_str())
            .collect()
    };

    {
        let store = load(&path, &config).expect("the mysql plugin must load over the real ABI");
        store
            .upsert_plane_record(demotion(&srv_demoted, "tool-drift", NOW).view())
            .expect("upsert a demotion");

        store
            .upsert_plane_record(demotion(&srv_demoted, "digest-mismatch", NOW + 10).view())
            .expect("upsert a demotion");
        store
            .upsert_plane_record(demotion(&srv_cleared, "tool-drift", NOW + 20).view())
            .expect("upsert a demotion");
        store
            .delete_plane_record("demotion", &srv_cleared)
            .expect("a later agreeing observation clears the quarantine");
        assert!(
            store
                .redeem_plane_token("ask", &nonce_restart, u64::MAX, NOW)
                .expect("redeem"),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        drop(store);
    }

    let store = load(&path, &config).expect("the mysql plugin must load again over the real ABI");
    assert_eq!(
        mine(store.as_ref()),
        vec![decode(
            &demotion(&srv_demoted, "digest-mismatch", NOW + 10).body
        )],
        "the boot read must put the recorded quarantine back in force — at its LATEST reason, and \
         without the one a later agreeing observation cleared"
    );
    assert!(
        !store
            .redeem_plane_token("ask", &nonce_restart, u64::MAX, NOW + 1)
            .expect("redeem"),
        "a restart handed a spent approval back over the plugin ABI"
    );

    let node_b = load(&path, &config)
        .expect("a second node loads the same plugin against the same database");
    assert!(store
        .redeem_plane_token("ask", &nonce_fleet, u64::MAX, NOW + 2)
        .expect("redeem"));
    assert!(
        !node_b
            .redeem_plane_token("ask", &nonce_fleet, u64::MAX, NOW + 3)
            .expect("redeem"),
        "a second node redeemed an approval the first already spent"
    );

    assert!(
        node_b
            .redeem_plane_token("ask", &nonce_fresh, u64::MAX, NOW + 4)
            .expect("redeem"),
        "a freshly minted approval is not the one that was spent"
    );

    assert_eq!(
        mine(&direct),
        vec![decode(
            &demotion(&srv_demoted, "digest-mismatch", NOW + 10).body
        )],
        "the demotion must be physically present in MySQL, not merely cached in the plugin"
    );
    assert!(
        !RecordStore::redeem_plane_token(&direct, "ask", &nonce_restart, u64::MAX, NOW + 5)
            .expect("redeem via the direct connection"),
        "the spent-approval row must be physically present in MySQL"
    );

    clear_trust_rows(
        &url,
        &[&srv_demoted, &srv_cleared],
        &[&nonce_restart, &nonce_fleet, &nonce_fresh],
    );
}

/// A key granting a NON-`pool` scope kind round-trips ACROSS THE PLUGIN ABI.
#[test]
fn a_non_pool_scope_grant_crosses_the_plugin_abi() {
    use busbar_contract::records::{ScopeRef, VirtualKey};

    let path = plugin_path();
    let Some(url) = mysql_url() else {
        return;
    };
    let id = "vk_abi_scope_kinds";
    let _direct = MysqlStore::connect(&url).expect("migrate");
    cleanup(&url, id);
    let store = load(&path, &cfg(&url)).expect("the mysql plugin must load over the real ABI");
    let key = VirtualKey {
        id: id.into(),
        generation_hash: "g".into(),
        name: "scopes".into(),
        allowed_scopes: Some(vec![
            ScopeRef::pool("fast"),
            ScopeRef {
                kind: "mcp_server".into(),
                value: "payments".into(),
            },
        ]),
        enabled: true,
        created_at: 1_000,
        ..Default::default()
    };
    store
        .put_key(&key)
        .expect("put a key with an mcp_server grant");
    let back = store
        .get_key(id)
        .expect("a non-pool grant must be readable back over the ABI")
        .expect("the key exists");
    assert!(back.scope_allowed("mcp_server", "payments"));
    assert!(back.scope_allowed("pool", "fast"));
    assert!(
        !back.scope_allowed("pool", "payments"),
        "an mcp_server grant must never come back as a pool grant"
    );
    let listed = store
        .list_keys()
        .expect("list_keys over the ABI with a non-pool grant");
    let listed = listed
        .iter()
        .find(|candidate| candidate.id == id)
        .expect("the key is listed");
    assert_eq!(
        listed.allowed_scopes, key.allowed_scopes,
        "list_keys preserves every scope kind and value"
    );
    drop(store);
    cleanup(&url, id);
}
