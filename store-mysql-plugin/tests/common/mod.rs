// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Helpers shared by this crate's live-MySQL test binaries (`e2e.rs`, `admin_api_e2e.rs`,
//! `conformance.rs`): one copy of each, so a fix lands once.

#![allow(dead_code)]

use mysql::params;
use std::path::PathBuf;
use std::process::Command;

/// A node id no earlier run or instance used, for `LoadedStore::open`: its bridge mints each op id
/// as `(node, counter from 0)`, and this store's dedupe is DURABLE, so two instances sharing a node
/// would replay each other's op ids (the kernel draws the node from the OS CSPRNG per process).
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

/// The node's one `op_id` allocator (`LoadedStore::open` mints the bridge's writes from it): a node
/// half no earlier run used (the dedupe is durable) and one counter.
pub fn mint() -> busbar_contract::abi::store::OpId {
    static NODE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(node);
    busbar_contract::abi::store::OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
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
/// fail a perfectly current cdylib. The same holds for the `cfg(test)` files under `src/` (`tests.rs`,
/// `tests/`, `tests_*.rs`): the cdylib is built without `cfg(test)`, so editing one never refreshes it.
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
        stem == "tests" || stem.starts_with("tests_")
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

pub fn plugin_path() -> PathBuf {
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

pub fn cleanup(url: &str, id: &str) {
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
pub fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbar_root();
    // Two builds: the busbar binary is the DEFAULT DISTRIBUTION's (`dist/default`: core plus the
    // standard plugins, the llm plane included, as busbar's signing gate builds it; a bare `-p busbar`
    // links no plugin), and `busbar-plugin-pack` is a feature-gated `[[bin]]` of `busbar-plugin-loader`
    // in busbar 1.6.0. Both land in `<checkout>/target`.
    for args in [
        &[
            "build",
            "--release",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--target-dir",
            "target",
            "--bin",
            "busbar",
        ][..],
        &[
            "build",
            "--release",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = Command::new("cargo")
            .args(args)
            .env("BUSBAR_RELEASE_PUBKEY", E2E_RELEASE_PUBKEY)
            // Both binaries are read back from `<checkout>/target/release` below.
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
/// busbar grants the `operator-infrastructure` egress class this store's `tcp` need declares to a
/// FIRST-PARTY plugin only (`busbar_plugin_loader::sign::egress_grant`): the busbar built here
/// embeds the public half (`BUSBAR_RELEASE_PUBKEY`, compile time, as busbar's signing gate builds
/// it) and the tarball is signed with the private half, so the plugin under test is first-party.
/// Fixed, so the cached busbar build is reused across runs.
pub const E2E_RELEASE_PUBKEY: &str =
    "9209607c315f66473c8cca8bf9a7b8031115d01bb47341613cebf57f0e4f271c";
pub const E2E_RELEASE_PRIVKEY: &str =
    "290f2453f236650ab21b85a95d49b9dab088518e829e4d524b01e441636ab327";
