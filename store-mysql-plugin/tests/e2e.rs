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
//! and runs the REAL `busbar --validate` binary against a config naming `store: { module: mysql }` —
//! the documented file-drop install path. `--validate` genuinely exercises the trust gate + ABI
//! dlopen + `RecordStore::connect` (real schema migration against real MySQL), so a successful validate is
//! real proof the plugin loads and initializes through busbar's own boot path, not a proxy for it.
//!
//! Persistence is then proven the same two independent ways the prior direct-call test used:
//!   1. `--validate` itself (via the plugin's `open()` and its connect step) runs the real schema
//!      migration — confirmed by checking the schema now exists.
//!   2. A second, independent store through the COMPILED-IN door (never the cdylib) confirms real
//!      MySQL was actually touched, not an in-process fake.
//!
//! The ABI-contract tests below load the cdylib DIRECTLY through the loader's dropped-in door
//! ([`load`]: the Statement rendered as `busbar-plugin-pack` renders it, `load_dropped`, then
//! `LoadedStore::open`, the way the host opens a store) — they test the store table's own contract
//! in isolation ("does a bad config produce a clean Err across the ABI, never a panic"; "does
//! every verb relay"), a different question from "does a real end-user install work".

use busbar_contract::records::RecordStore;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use mysql::params;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

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
fn mint() -> busbar_contract::abi::store::OpId {
    static NODE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(node);
    busbar_contract::abi::store::OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// A dispatcher and a bind over the loader's test connection table (plain TCP, the host's
/// connector path): every connection the store makes is one the "host" dials.
fn host(instance: &str) -> (Arc<Dispatcher>, Bind) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> = Arc::new(
        busbar_plugin_loader::tcp_conns::TcpConns::new(dispatcher.conn_waker()),
    );
    let bind = Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: Some(conns),
    };
    (dispatcher, bind)
}

/// Load the store library at `path` through the DROPPED-IN DOOR and open it on `cfg`, the way the
/// host opens a store: its Statement rendered as `busbar-plugin-pack` signs it into the manifest,
/// `load_dropped` (dlopen, `busbar_plugin_door`, the Statement compared byte for byte), then
/// `LoadedStore::open`. Dropping the handle closes the instance and unloads the library.
fn load(path: &Path, cfg: &str) -> Result<Box<dyn RecordStore>, String> {
    let stated = rendering_of_library(path)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the library exports no busbar_plugin_door".to_string())?;
    let (dispatcher, bind) = host("store-mysql-e2e");
    let plugin = load_dropped::<Store>(path, &stated, bind).map_err(|e| e.to_string())?;
    let store = LoadedStore::open(plugin, dispatcher, cfg.as_bytes(), mint)?;
    Ok(Box::new(store))
}

/// The store through its COMPILED-IN door (`busbar_store_mysql::door`, never the cdylib): the
/// independent leg the dropped-in store's writes are migrated, read back and cleaned up through.
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

/// Locate the cdylib THIS `cargo test` invocation just built — never a leftover artifact.
///
/// This looks ONLY in `target/<profile>/deps/`, never `target/<profile>/`, and that distinction is
/// the whole point of this function.
///
/// `cargo` emits the lib target's cdylib into `deps/` as part of the very build graph that produces
/// this test binary (this package's lib unit is compiled with BOTH declared crate-types — see
/// `[lib] crate-type = ["cdylib", "rlib"]` in Cargo.toml), so `deps/libbusbar_store_mysql_plugin.dylib` is by construction up to
/// date with the source tree under test. Cargo only *uplifts* a copy to `target/<profile>/` for
/// `cargo build`, NEVER for `cargo test`. A lookup in `target/<profile>/` therefore reads an
/// artifact that nothing in this test's dependency graph refreshes: whatever some earlier `cargo
/// build` left there, from any commit — or nothing at all.
///
/// Both outcomes of that are lies about durability, and the second is the dangerous one:
///   * NOTHING there  -> the old code `return`ed with a "skip:" line and reported GREEN. That is how
///     `cargo test` can pass with ZERO over-the-ABI coverage of the durable store path.
///   * STALE artifact -> a cdylib built before an ABI change answers every write `Ok(())` and every
///     read empty, which is BYTE-FOR-BYTE the signature of the unrelayed-seam defect this file
///     exists to catch (that defect was real: `DynStore`'s `impl Store` overrode 24 methods, none of
///     them the task/call-log methods, so `put_task` took the accept-and-keep-nothing trait
///     default). RED on a stale artifact is indistinguishable from RED on the real bug — and an
///     artifact NEWER than a regression reports GREEN while the shipped ABI is broken. Proven, not
///     theorised: with a regressed plugin in the tree and a good cdylib in `target/debug/`, the old
///     lookup passed and this one fails.
///
/// Same hazard, and the same reasoning, as the engine's `crates/busbar/Cargo.toml` dev-dependency on
/// `busbar-store-example-plugin`: keep the cdylib in the build graph so no test can judge a stale
/// one. Here the plugin's lib IS this package, so that graph edge already exists — what was missing
/// was reading the artifact that edge actually produces.
///
/// Panics rather than skipping: a missing cdylib under `cargo test` means the build graph changed
/// shape, and the only honest report of that is a failure, not a silent pass.
/// The newest mtime across every workspace crate's `src/` — "how fresh must a cdylib be to be the
/// one this source tree describes".
///
/// Deliberately ONLY `src/**/*.rs` of each workspace member: editing a `tests/` file or a
/// `[dev-dependencies]` line recompiles the test binary but NOT the lib, so including those would
/// fail a perfectly current cdylib.
fn newest_source_mtime() -> std::time::SystemTime {
    fn walk(dir: &std::path::Path, newest: &mut std::time::SystemTime) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, newest);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                    if m > *newest {
                        *newest = m;
                    }
                }
            }
        }
    }
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the plugin crate always sits under the workspace root");
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for e in std::fs::read_dir(ws_root).into_iter().flatten().flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(&src, &mut newest);
        }
    }
    newest
}

fn plugin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe"); // .../target/<profile>/deps/<test>-<hash>
    let deps_dir = exe.parent().expect("the test binary always lives in deps/");
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_mysql_plugin");
    let fresh = deps_dir.join(&name);
    assert!(
        fresh.exists(),
        "the store-mysql-plugin cdylib is not at {}, where cargo emits it for the same build that produced \
         this test binary. Refusing to fall back to target/<profile>/ (an artifact only `cargo \
         build` refreshes) or to skip: judging a stale cdylib is exactly how an unrelayed plugin \
         ABI reads as green.",
        fresh.display()
    );
    // FRESHNESS, ASSERTED — not assumed. Under `cargo test` the artifact above is rebuilt by the
    // same graph that built this binary (proven: delete it, re-run, cargo re-emits it). But this
    // test binary can also be executed DIRECTLY out of `deps/`, where nothing rebuilds anything,
    // and a stale cdylib there produces empty reads — indistinguishable from the unrelayed-ABI
    // defect. So compare it against the sources and fail with a message that says STALE ARTIFACT,
    // explicitly NOT a durability verdict.
    let built = std::fs::metadata(&fresh)
        .and_then(|m| m.modified())
        .expect("cdylib mtime");
    let newest_src = newest_source_mtime();
    assert!(
        built >= newest_src,
        "STALE ARTIFACT — THIS IS NOT A DURABILITY FAILURE. {} predates this workspace's sources, \
         so it cannot answer for the code in the tree; a pre-change cdylib returns empty for every \
         read, which reads exactly like an unrelayed plugin ABI. Run `cargo build -p {}` (or just \
         `cargo test`, which rebuilds it) and re-run.",
        fresh.display(),
        "busbar-store-mysql-plugin"
    );
    fresh
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// Every `env:` secret-ref name a config text references, in first-seen order, de-duplicated.
///
/// busbar 1.5.3 made `--validate` RESOLVE built-in (`env`/`file`) secret references and exit 1 when
/// one cannot resolve, rather than only checking the reference's SHAPE. A fixture config that names
/// a real-looking env var (here, `MOCK_KEY`) then fails `--validate` on any machine that doesn't
/// happen to have that var set -- which is every CI runner and most dev machines. Hardcoding
/// `MOCK_KEY` here would fix today's failure but rot the moment this fixture, or a future one, names
/// a different variable. Extracting the names generically (same approach as the core repo's
/// `crates/busbar/tests/docs_examples.rs` and `tests/migration_corpus.rs`) keeps the harness working
/// no matter what the fixture references.
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

fn cleanup(url: &str, id: &str) {
    if let Ok(mut conn) = mysql::Conn::new(mysql::Opts::from_url(url).unwrap()) {
        use mysql::prelude::*;
        let _: Result<(), _> = conn.exec_drop(
            "DELETE FROM credentials WHERE key_id=:id",
            params! { "id" => id },
        );
        let _: Result<(), _> =
            conn.exec_drop("DELETE FROM api_keys WHERE id=:id", params! { "id" => id });
    }
}

/// The busbar checkout the real binaries are built from: `$BUSBAR_CHECKOUT`, else a sibling
/// `busbar/` beside this repo (ci.yml checks GetBusbar/busbar out there at the `.busbar-ref` pin).
/// It must be AT the pin (`.busbar-ref` field 1): an end-to-end proof against any other busbar is a
/// proof about a binary this repo does not build against.
fn busbar_root() -> PathBuf {
    let root = std::env::var_os("BUSBAR_CHECKOUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../busbar"));
    let root = root.canonicalize().unwrap_or_else(|e| {
        panic!(
            "no busbar checkout at {} ({e}): set BUSBAR_CHECKOUT to a GetBusbar/busbar checkout at \
             the .busbar-ref pin, or check it out beside this repo",
            root.display()
        )
    });
    let pin = include_str!("../../.busbar-ref")
        .split_whitespace()
        .next()
        .expect(".busbar-ref field 1 is the pinned busbar sha")
        .to_string();
    let head = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse the busbar checkout");
    let head = String::from_utf8_lossy(&head.stdout).trim().to_string();
    assert_eq!(
        head,
        pin,
        "the busbar checkout at {} is not at the .busbar-ref pin",
        root.display()
    );
    root
}

/// Build (once, cached by cargo) and return the path to the real `busbar` binary and the real
/// `busbar-plugin-pack` binary, both from the sibling busbar checkout — never a fixture, never a
/// stub, the exact binaries a real release ships.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbar_root();
    let status = Command::new("cargo")
        // `busbar-plugin-pack` is a feature-gated `[[bin]]` of `busbar-plugin-loader` in busbar 1.6.0
        // (roster def 14), built the way busbar's own release workflow does.
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "busbar-plugin-loader/pack",
            "--bin",
            "busbar",
            "--bin",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(
        status.success(),
        "building the real busbar + busbar-plugin-pack binaries must succeed"
    );
    // The child `cargo` inherits CARGO_TARGET_DIR when one is set, so the binaries land THERE, not
    // under the checkout's own `target/` — look where they were actually built.
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    (
        target.join("release/busbar"),
        target.join("release/busbar-plugin-pack"),
    )
}

/// THE REAL END-TO-END INSTALL PROOF: pack the plugin, drop it in a real `plugins.dir`, run the real
/// `busbar --validate` against a config naming `store: { module: mysql }`, and confirm real MySQL was
/// actually touched — via the documented file-drop mechanism, never a direct `load()` call.
#[test]
fn load_and_exercise_mysql_plugin_via_file_drop() {
    let Some(url) = mysql_url() else { return };
    let so_path = plugin_path();
    let key_id = "vk_mysql_filedrop_e2e";
    cleanup(&url, key_id);

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

    // Pack the real cdylib into a real signed-shape tarball via the same tool CI's SIGNOFF step
    // uses, --allow-unsigned locally exactly like CI's own unsigned-key fallback.
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
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "e2e file-drop proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    // FILE-DROP: the real boot-time discovery mechanism extracts/reads whatever is in plugins.dir --
    // dropping the packed tarball here, uninstalled via any admin call, is the documented mechanism.
    std::fs::copy(&tarball, plugins_dir.join("store-mysql.tar.gz")).unwrap();

    let config = work.join("config.yaml");
    let providers = work.join("providers.yaml");
    // providers.yaml is the flat CATALOG (provider name at the document root, no wrapping key) --
    // config.yaml separately has its OWN `providers:`/`models:` blocks naming which catalog
    // entries are enabled. Mirrors the known-good fixture in
    // crates/busbar/tests/cli_validate.rs::write_configs, not invented here.
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let config_text = format!(
        "listen: \"127.0.0.1:0\"\n\
         store:\n  module: mysql\n  settings: {{ url: \"{url}\" }}\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         auth:\n  chain: []\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );
    std::fs::write(&config, &config_text).unwrap();

    // `--validate` RESOLVES built-in `env:` secret references (busbar 1.5.3); give every one this
    // fixture names a placeholder so the gate tests the config's SHAPE, not this machine's
    // environment. See `referenced_env_vars`'s doc comment for why this is generic, not hardcoded.
    let mut validate_cmd = Command::new(&busbar_bin);
    validate_cmd
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers);
    for name in referenced_env_vars(&config_text) {
        // 64 hex chars: valid for `auth.signing_key`, and harmless as any other secret's value.
        validate_cmd.env(
            name,
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
    }
    let out = validate_cmd.output().expect("run busbar --validate");
    assert!(
        out.status.success(),
        "busbar --validate must succeed with the file-dropped mysql plugin: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // PROOF real MySQL was touched by the REAL busbar process, through the REAL file-drop path: an
    // independent connection (bypassing the plugin/ABI/loader entirely) confirms the schema now
    // exists -- --validate's own plugin-open call ran RecordStore::connect, which runs init_schema(). Also
    // exercises MysqlStore::connect itself as the second independent-verification leg the prior
    // direct-call test used.
    let _direct = MysqlStore::connect(&url)
        .expect("connect directly, bypassing the plugin entirely, to confirm real schema init");
    let mut raw = mysql::Conn::new(mysql::Opts::from_url(&url).unwrap()).unwrap();
    use mysql::prelude::*;
    let exists: bool = raw
        .exec_first(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='api_keys')",
            (),
        )
        .unwrap()
        .unwrap();
    assert!(
        exists,
        "the api_keys table must exist after busbar --validate loaded the plugin via file-drop -- \
         proof the real boot path actually called RecordStore::connect/init_schema, not a no-op"
    );

    let _ = std::fs::remove_dir_all(&work);
    cleanup(&url, key_id);
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct
/// `load()` call): an `open()` config that cannot produce a usable store surfaces back across
/// the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
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
        &cfg("mysql://u:p@127.0.0.1:1/definitely_not_a_real_db"),
    )
    .err()
    .expect("an unreachable mysql target must fail to load");
    assert!(
        !err.is_empty(),
        "expected the underlying mysql crate's own connect-failure message to survive the ABI \
         crossing, got an empty error"
    );
}

/// A non-plugin library (or a missing file) is refused with a clear error, never a crash. Same
/// ABI-contract-unit-test rationale as above.
#[test]
fn refuses_non_plugin() {
    let err = match load(std::path::Path::new("/definitely/not/a/plugin.so"), "{}") {
        Err(e) => e,
        Ok(_) => panic!("a missing library must not load"),
    };
    assert!(err.contains("did not load"), "got: {err}");
}

/// Wipe the durable plane-record tables so this run's exact counts mean something.
///
/// Task listing, the call-parent enumeration and both kind-wide purges are GLOBAL, not scoped to a
/// principal, so against a re-used database a leftover row from an earlier run makes every exact
/// assertion in the ABI durability test below meaningless. The contract-level purge cannot do this
/// on its own — the `task` kind only drops TERMINAL rows by design, so an abandoned `working` task
/// would survive it forever — hence raw SQL, scoped to the three kinds this test writes. No other
/// test in this file touches them.
fn wipe_task_and_call_rows(url: &str) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(mysql::Opts::from_url(url).expect("test url must parse"))
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
///
/// busbar 1.6.0 carries the A2A task store and the MCP call log through the neutral kind-tagged
/// verbs (`upsert_plane_record`, `append_plane_record`, `list_plane_records`,
/// `list_plane_record_parents`, `purge_plane_records_before`, …) — kinds `task`, `task_event` and
/// `call`. Every in-crate test of them calls `MysqlStore` DIRECTLY, in-process, and NONE of them can
/// see the failure that actually matters in production, because in production this backend is ONLY
/// ever reached as a plugin.
///
/// `busbar_contract::records::Store` DEFAULTS every one of these verbs to accept-and-keep-nothing. A plugin seam
/// that does not RELAY them silently substitutes those defaults: every write returns `Ok`, every
/// read answers empty, and a deployment loses every in-flight A2A task and every tool-call record
/// while reporting success. That is not hypothetical — the ABI once carried four store methods while
/// the trait carried ten, so a task write took the trait default and reported success.
///
/// So it goes through [`load`]: a REAL `dlopen` of the built cdylib, the
/// store v3 table, the real `LoadedStore`. It writes AT ARITY > 1 (three tasks across two dispositions,
/// three events on one task and one on another, three call records for one principal and one for a
/// second), DROPS the handle — which runs `close` and UNLOADS the library — then `dlopen`s
/// AGAIN over the same file and reads everything back. A third leg reads the same rows through the
/// plain `MysqlStore`, never touching the cdylib, the C ABI or the loader — so a plugin that
/// answered from its own in-process cache still fails here.
#[test]
fn tasks_and_call_log_survive_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};

    let path = plugin_path();
    let Some(url) = mysql_url() else {
        return;
    };
    let config = cfg(&url);

    // `MysqlStore::connect` runs the real schema migration, so the tables exist before the wipe —
    // and this same handle is leg 3's independent reader.
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
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
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
        // Out of order, so the read has to sort by seq, not by insertion.
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
        // Dropping the boxed store drops the loader's `Library` handle: the instance closes and the
        // dylib is UNLOADED. Nothing this process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file.
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
    // A fork is refused over the ABI too — the error has to survive the crossing as an Err.
    assert!(
        store
            .append_plane_record(call("vk_abi", 1, "", "FORKED").view())
            .is_err(),
        "a different record at an occupied chain position must be refused across the ABI"
    );

    // Retention crosses the ABI too, COUNT AND ALL — a relay that dropped the return value would
    // read as 0.
    assert_eq!(
        store
            .purge_plane_records_before("call", 2_002)
            .expect("purge calls"),
        2,
        "both records at ts 2001 go (one per principal); the one exactly at the cutoff stays"
    );
    assert_eq!(
        store
            .purge_plane_records_before("task", 25)
            .expect("purge tasks"),
        0,
        "no TERMINAL task is older than the cutoff: t_alpha and t_beta are active and must never be \
         swept no matter how old"
    );
    assert_eq!(
        store
            .purge_plane_records_before("task", 31)
            .expect("purge tasks"),
        1,
        "the one terminal task at ts 30 is the only row retention may drop"
    );
    drop(store);

    // LEG 3 — the surviving rows through the plain `MysqlStore`, never the cdylib / ABI / loader.
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

/// Drop exactly this run's own trust-state rows. Scoped by id rather than a blanket delete: the
/// single-use ledger is the one table where wiping another concurrently-running node's rows would
/// hand a spent approval straight back — which is the defect it exists to prevent, so the test rig
/// must not model it.
fn clear_trust_rows(url: &str, servers: &[&str], nonces: &[&str]) {
    use mysql::prelude::*;
    let mut conn = mysql::Conn::new(mysql::Opts::from_url(url).expect("test url must parse"))
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

/// THE DURABILITY PROOF FOR THE TRUST STATE, OVER THE REAL PLUGIN PATH: the `demotion` kind
/// (upsert / list / delete) and the `ask` single-use token (`redeem_plane_token`).
///
/// A seam that does not RELAY them substitutes two security failures, both silent and both green:
/// a demotion written, reported successful and DISCARDED, so a restart hands a quarantined upstream
/// the operator's approval back; and a single-use approval redeemable once per node and once per
/// restart. Two simultaneous loads are the fleet; a drop and a reload is the restart; and a third
/// leg reads through the plain `MysqlStore`, never touching the cdylib.
///
/// PANICS rather than skipping when no MySQL is configured: this is the only over-the-ABI coverage
/// of two properties whose unimplemented form is silently green.
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
        // The UPSERT path crosses the ABI too: a second demotion of one upstream replaces the row.
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
                .redeem_plane_token("ask", &nonce_restart, NOW + 900, NOW)
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
            .redeem_plane_token("ask", &nonce_restart, NOW + 900, NOW + 1)
            .expect("redeem"),
        "a restart handed a spent approval back over the plugin ABI"
    );

    // THE FLEET: a second, simultaneous dlopen against the same database.
    let node_b = load(&path, &config)
        .expect("a second node loads the same plugin against the same database");
    assert!(store
        .redeem_plane_token("ask", &nonce_fleet, NOW + 900, NOW + 2)
        .expect("redeem"));
    assert!(
        !node_b
            .redeem_plane_token("ask", &nonce_fleet, NOW + 900, NOW + 3)
            .expect("redeem"),
        "a second node redeemed an approval the first already spent"
    );
    // THE CONTROL: a ledger that refused everything would satisfy both cases above.
    assert!(
        node_b
            .redeem_plane_token("ask", &nonce_fresh, NOW + 900, NOW + 4)
            .expect("redeem"),
        "a freshly minted approval is not the one that was spent"
    );

    // LEG 3 — the plain `MysqlStore`, never the cdylib.
    assert_eq!(
        mine(&direct),
        vec![decode(
            &demotion(&srv_demoted, "digest-mismatch", NOW + 10).body
        )],
        "the demotion must be physically present in MySQL, not merely cached in the plugin"
    );
    assert!(
        !RecordStore::redeem_plane_token(&direct, "ask", &nonce_restart, NOW + 900, NOW + 5)
            .expect("redeem via the direct connection"),
        "the spent-approval row must be physically present in MySQL"
    );

    clear_trust_rows(
        &url,
        &[&srv_demoted, &srv_cleared],
        &[&nonce_restart, &nonce_fleet, &nonce_fresh],
    );
}

/// A key granting a NON-`pool` scope kind round-trips ACROSS THE PLUGIN ABI. The store response is
/// serialized INSIDE the cdylib, whose scope-kind wire registry the engine's boot registration never
/// reaches; before the store registered the kinds it reads, `get_key`/`list_keys` on such a key
/// failed with "scope kind 'mcp_server' has no registered wire field" — and the engine's governance
/// boot, which lists every key, refused to start against this backend.
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
    busbar_contract::records::register_scope_kind("mcp_server"); // the engine side registers it at boot
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
    assert!(store
        .list_keys()
        .expect("list_keys over the ABI with a non-pool grant in the table")
        .iter()
        .any(|k| k.id == id));
    drop(store);
    cleanup(&url, id);
}
