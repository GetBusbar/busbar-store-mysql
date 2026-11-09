// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Helpers shared by this crate's live-MySQL test binaries (`e2e.rs`, `admin_api_e2e.rs`, `conformance.rs`): one copy of each, so a fix lands once.

#![allow(dead_code)]

#[path = "../../../store-mysql/tests-support/mysql_io.rs"]
pub mod mysql_io;

use std::path::PathBuf;
use std::process::Command;

/// A unique fixture identity for instances and disposable databases.
pub fn node() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (t ^ (u64::from(std::process::id()) << 32))
        .wrapping_add(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) << 48)
        | 1
}

/// The newest mtime across every workspace crate's `src/` — "how fresh must a cdylib be to be the one this source tree describes".
pub fn newest_source_mtime() -> std::time::SystemTime {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the plugin crate always sits under the workspace root");
    newest_source_mtime_under(ws_root)
}

/// [`newest_source_mtime`] for the workspace rooted at `ws_root`.
pub fn newest_source_mtime_under(ws_root: &std::path::Path) -> std::time::SystemTime {
    fn is_cfg_test_file(p: &std::path::Path) -> bool {
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        stem == "tests" || stem.starts_with("tests_") || stem.ends_with("_tests")
    }
    fn walk(dir: &std::path::Path, newest: &mut std::time::SystemTime) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if is_cfg_test_file(&p) {
                continue;
            }
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
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for e in std::fs::read_dir(ws_root).into_iter().flatten().flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(&src, &mut newest);
        }
    }
    newest
}

/// The actual fresh MySQL cdylib. CI supplies BUSBAR_PLUGIN_CDYLIB as an absolute path;
/// direct cargo test runs use the deterministic artifact beside their own test binary.
/// Missing or stale artifacts fail, without searching old hashed outputs or substituting a linked door.
pub fn plugin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let deps_dir = exe.parent().expect("the test binary always lives in deps/");
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_mysql_plugin");
    let fresh = match std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
            path
        }
        None if std::env::var_os("CI").is_some() => {
            panic!("CI must set BUSBAR_PLUGIN_CDYLIB to the freshly built actual MySQL cdylib")
        }
        None => deps_dir.join(&name),
    };
    assert!(
        fresh.exists(),
        "the store-mysql-plugin cdylib is not at {}, where cargo emits it for the same build that produced \
         this test binary. Refusing to fall back to target/<profile>/ (an artifact only `cargo \
         build` refreshes) or to skip: judging a stale cdylib is exactly how an unrelayed plugin \
         ABI reads as green.",
        fresh.display()
    );

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

/// The exact assembled host checkout; `.busbar-ref` selects its independently pinned SDK.
pub fn busbar_root() -> PathBuf {
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
    let pin = include_str!("../../../.busbar-ref")
        .split_whitespace()
        .next()
        .expect(".busbar-ref field 1 is the pinned busbar sha")
        .to_string();
    let host_revision = std::env::var("BUSBAR_ADMISSION_CORE_REVISION")
        .expect("BUSBAR_ADMISSION_CORE_REVISION must select the exact assembled host");
    assert!(
        host_revision.len() == 40 && host_revision.bytes().all(|b| b.is_ascii_hexdigit()),
        "BUSBAR_ADMISSION_CORE_REVISION must be a full SHA"
    );
    let head = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse the busbar checkout");
    assert!(head.status.success(), "resolve the assembled host revision");
    let head = String::from_utf8_lossy(&head.stdout).trim().to_string();
    assert_eq!(
        head,
        host_revision,
        "the busbar checkout at {} is not at the admitted host revision",
        root.display()
    );
    let dirty = Command::new("git")
        .args([
            "-C",
            root.to_str().unwrap(),
            "status",
            "--porcelain",
            "--untracked-files=no",
        ])
        .output()
        .expect("inspect assembled host source");
    assert!(
        dirty.status.success() && dirty.stdout.is_empty(),
        "assembled host has modified source"
    );
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("scripts/ci-product-pins.json"))
            .expect("read assembled host SDK vector"),
    )
    .expect("parse assembled host SDK vector");
    assert_eq!(
        vector["sdk"].as_str(),
        Some(pin.as_str()),
        "assembled host and plugin SDK differ; qualify a coherent cohort"
    );
    root
}

/// Build (once, cached by cargo) and return the path to the real `busbar` binary and the real `busbar-plugin-pack` binary, both from the sibling busbar checkout — never a fixture, never a stub, the exact binaries a real release ships.
pub fn build_real_binaries() -> (PathBuf, PathBuf) {
    if let Some(binary) = std::env::var_os("BUSBAR_TEST_HOST_BINARY") {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must build the admitted host source"
        );
        let binary = PathBuf::from(binary);
        let pack = PathBuf::from(
            std::env::var_os("BUSBAR_TEST_PACK_BINARY")
                .expect("local host override also requires BUSBAR_TEST_PACK_BINARY"),
        );
        assert!(
            binary.is_absolute() && binary.is_file() && pack.is_absolute() && pack.is_file(),
            "local binary overrides must be existing absolute paths"
        );
        return (binary, pack);
    }
    let root = busbar_root();

    for args in [
        &[
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--bin",
            "busbar",
        ][..],
        &[
            "build",
            "--release",
            "--locked",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = Command::new("cargo")
            .env(
                "RUSTUP_TOOLCHAIN",
                std::env::var_os("RUSTUP_TOOLCHAIN").unwrap_or_else(|| "1.98".into()),
            )
            .args(args)
            .arg("--target-dir")
            .arg(root.join("target"))
            .env("BUSBAR_RELEASE_PUBKEY", E2E_RELEASE_PUBKEY)
            .env_remove("CARGO_TARGET_DIR")
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar + busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    let target = root.join("target");
    (
        target.join("release/busbar"),
        target.join("release/busbar-plugin-pack"),
    )
}

/// THE TEST-ONLY FIRST-PARTY KEYPAIR (ed25519, `busbar-plugin-pack keygen`), never the release key.
pub const E2E_RELEASE_PUBKEY: &str =
    "9209607c315f66473c8cca8bf9a7b8031115d01bb47341613cebf57f0e4f271c";
pub const E2E_RELEASE_PRIVKEY: &str =
    "290f2453f236650ab21b85a95d49b9dab088518e829e4d524b01e441636ab327";

/// Open the store through its COMPILED-IN door (`busbar_store_mysql::door`) on `url`, the way the host opens a store: the connect step creates the schema on an empty database.
pub fn connect_linked(
    url: &str,
) -> Result<busbar_plugin_loader::store_v4::LoadedPersistence, String> {
    let (plugin, dispatcher) = native_plugin(None)?;
    open_native(plugin, dispatcher, url)
}

pub fn block<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}
pub fn native_plugin(
    library: Option<&std::path::Path>,
) -> Result<
    (
        busbar_plugin_loader::dispatch::Plugin<
            busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4,
        >,
        std::sync::Arc<busbar_plugin_loader::dispatch::Dispatcher>,
    ),
    String,
> {
    use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
    use busbar_plugin_loader::dispatch::{
        load_dropped, load_linked, rendering_of_library, Bind, ConnTable, DispatchConfig,
        Dispatcher, LinkedRow, NoSink,
    };
    use std::sync::Arc;
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let bind = Bind {
        instance: Arc::from(format!("mysql-native-image-{}", node())),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Host(mysql_io::host(dispatcher.conn_waker(), Default::default())),
    };
    let plugin = if let Some(library) = library {
        let stated = rendering_of_library(library)
            .map_err(|e| e.to_string())?
            .ok_or("missing door")?;
        load_dropped::<StoreV4>(library, &stated, bind)
    } else {
        let row = LinkedRow::of_kind::<StoreV4>(
            busbar_store_mysql::door as busbar_contract::abi::mechanism::door::DoorFn,
        )
        .map_err(|e| e.to_string())?;
        load_linked::<StoreV4>(&row, bind)
    }
    .map_err(|e| e.to_string())?;
    Ok((plugin, dispatcher))
}
pub fn open_native(
    plugin: busbar_plugin_loader::dispatch::Plugin<
        busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4,
    >,
    dispatcher: std::sync::Arc<busbar_plugin_loader::dispatch::Dispatcher>,
    url: &str,
) -> Result<busbar_plugin_loader::store_v4::LoadedPersistence, String> {
    use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
    let settings = serde_json::json!({"url":url,"input_budget":67108864}).to_string();
    block(LoadedPersistence::open(
        plugin,
        dispatcher,
        settings.as_bytes(),
        Limits {
            descriptor_bytes: 67108864,
            output_items: 1024,
            output_bytes: 67108864,
            decode_bytes: 67108864,
        },
    ))
    .map_err(|e| e.to_string())
}

/// A private database for real child-boot proofs; no production constructor creates its schema.
pub struct ScratchDb {
    root: mysql::Conn,
    name: String,
    user: String,
    pub url: String,
}

impl ScratchDb {
    pub fn new(server: &str) -> Self {
        use mysql::prelude::Queryable;
        let opts = mysql::Opts::from_url(&crate::common::raw_mysql_url(server)).unwrap();
        let user = opts.get_user().unwrap_or("busbar").replace('\'', "''");
        let password =
            std::env::var("BUSBAR_TEST_MYSQL_ROOT_PASSWORD").unwrap_or_else(|_| "busbar".into());
        let root = mysql::OptsBuilder::from_opts(opts)
            .user(Some("root"))
            .pass(Some(password))
            .db_name(None::<String>);
        let mut root = mysql::Conn::new(root).unwrap();
        let name = format!("busbar_filedrop_{}", node());
        root.query_drop(format!("CREATE DATABASE {name}")).unwrap();
        root.query_drop(format!("GRANT ALL PRIVILEGES ON {name}.* TO '{user}'@'%'"))
            .unwrap();
        let (scheme, rest) = server
            .split_once("://")
            .expect("the MySQL URL names its scheme");
        let (authority, tail) = rest
            .split_once('/')
            .expect("the MySQL URL names a database");
        let query = tail.find('?').map_or("", |at| &tail[at..]);
        let url = format!("{scheme}://{authority}/{name}{query}");
        Self {
            root,
            name,
            user,
            url,
        }
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        use mysql::prelude::Queryable;
        let _ = self.root.query_drop(format!("DROP DATABASE {}", self.name));
        let _ = self.root.query_drop(format!(
            "REVOKE ALL PRIVILEGES ON {}.* FROM '{}'@'%'",
            self.name, self.user
        ));
    }
}

/// Strip the SDK-only pin option solely for the independent fixture SQL client.
pub fn raw_mysql_url(value: &str) -> String {
    let Some((base, query)) = value.split_once('?') else {
        return value.to_owned();
    };
    let query = query
        .split('&')
        .filter(|pair| pair.split('=').next() != Some("server_public_key_sha256"))
        .collect::<Vec<_>>()
        .join("&");
    if query.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{query}")
    }
}
