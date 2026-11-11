// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Installs the actual plugin over HTTP, restarts with a fresh native target,
//! mints a key and credential, then checks the HTTP result and physical records
//! and receipts independently through MySQL.

mod common;

use base64::Engine as _;
use common::{build_real_binaries, plugin_path, E2E_RELEASE_PRIVKEY, E2E_RELEASE_PUBKEY};
use mysql::prelude::*;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct ChildGuard(Child, PathBuf);

impl ChildGuard {
    /// The child's captured output, formatted for a panic message.
    fn output(&self) -> String {
        match std::fs::read_to_string(&self.1) {
            Ok(s) if s.trim().is_empty() => "  (the child produced no output)".to_string(),
            Ok(s) => s
                .lines()
                .map(|l| format!("  | {l}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(e) => format!("  (could not read {}: {e})", self.1.display()),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `busbar` with stdout+stderr captured to `log`, wrapped in a guard that knows where to find them.
fn spawn_busbar(cmd: &mut Command, log: PathBuf, what: &str) -> ChildGuard {
    let out = std::fs::File::create(&log)
        .unwrap_or_else(|e| panic!("create the {what} log at {}: {e}", log.display()));
    let err = out
        .try_clone()
        .unwrap_or_else(|e| panic!("dup the {what} log handle: {e}"));
    let child = cmd
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn the real busbar for {what}: {e}"));
    ChildGuard(child, log)
}

fn mysql_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql:8 service container must \
                 provision it. Refusing to silently skip the only real-admin-API-install coverage \
                 in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_MYSQL_URL to run the live-MySQL e2e tests");
            None
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn diagnose_stalled_boot(child: u32, database: &mut mysql::Conn, what: &str) {
    let tasks = std::fs::read_dir(format!("/proc/{child}/task"));
    if let Ok(tasks) = tasks {
        let mut waits = tasks
            .flatten()
            .filter_map(|task| {
                let id = task.file_name().to_str()?.parse::<u32>().ok()?;
                let name = std::fs::read_to_string(task.path().join("comm")).ok()?;
                let wait = std::fs::read_to_string(task.path().join("wchan")).ok()?;
                Some((id, name.trim().to_owned(), wait.trim().to_owned()))
            })
            .take(64)
            .collect::<Vec<_>>();
        waits.sort_by_key(|row| row.0);
        eprintln!("{what} child thread wait channels: {waits:?}");
    }
    // DIGEST_TEXT normalizes SQL literals. Never emit raw statements, lock data,
    // record values, credentials, configuration or connection strings.
    type Statement = (u64, String, String, String, String, u64);
    let statements: mysql::Result<Vec<Statement>> = database.query(
        "SELECT /*+ MAX_EXECUTION_TIME(500) */ t.PROCESSLIST_ID,COALESCE(t.PROCESSLIST_STATE,''),LEFT(COALESCE(s.DIGEST_TEXT,''),512),COALESCE(i.TRX_STATE,''),COALESCE(i.TRX_OPERATION_STATE,''),COALESCE(i.TRX_ROWS_LOCKED,0) FROM performance_schema.threads t LEFT JOIN performance_schema.events_statements_current s ON s.THREAD_ID=t.THREAD_ID LEFT JOIN information_schema.INNODB_TRX i ON i.TRX_MYSQL_THREAD_ID=t.PROCESSLIST_ID WHERE t.PROCESSLIST_DB=DATABASE() LIMIT 16",
    );
    eprintln!("{what} fixture normalized statements and transaction states: {statements:?}");
    type WaitEdge = (u64, u64, u64, String, Option<String>, String, String);
    let waits: mysql::Result<Vec<WaitEdge>> = database.query(
        "SELECT /*+ MAX_EXECUTION_TIME(500) */ w.REQUESTING_ENGINE_TRANSACTION_ID,w.BLOCKING_ENGINE_TRANSACTION_ID,COALESCE(i.TRX_MYSQL_THREAD_ID,0),l.OBJECT_NAME,l.INDEX_NAME,l.LOCK_MODE,l.LOCK_STATUS FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID LEFT JOIN information_schema.INNODB_TRX i ON i.TRX_ID=w.REQUESTING_ENGINE_TRANSACTION_ID WHERE l.OBJECT_SCHEMA=DATABASE() LIMIT 16",
    );
    eprintln!("{what} fixture lock wait edges: {waits:?}");
}

fn wait_for_admin_listener(
    client: &reqwest::blocking::Client,
    admin_base: &str,
    token: &str,
    guard: &mut ChildGuard,
    what: &str,
    mut diagnostic_options: Option<mysql::Opts>,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let diagnostic_at = Instant::now() + Duration::from_secs(12);
    let mut diagnosed = false;
    loop {
        if client
            .get(format!("{admin_base}/plugins"))
            .header("x-admin-token", token)
            .send()
            .is_ok()
        {
            return;
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!(
                "{what} exited before its admin listener came up (status: {status})\n\
                 --- {what} output ---\n{}",
                guard.output()
            );
        }
        if !diagnosed && Instant::now() >= diagnostic_at {
            diagnosed = true;
            if let Some(options) = diagnostic_options.take() {
                let child = guard.0.id();
                let what = what.to_owned();
                // Never pause the listener poll or join across its original deadline.
                // This test-process-owned thread has bounded I/O and server queries.
                let _diagnostic = std::thread::spawn(move || match mysql::Conn::new(options) {
                    Ok(mut database) => diagnose_stalled_boot(child, &mut database, &what),
                    Err(error) => {
                        eprintln!("{what} fixture diagnostic observer unavailable: {error:?}")
                    }
                });
            }
        }
        assert!(
            Instant::now() < deadline,
            "{what}'s admin listener never came up within 15s\n--- {what} output ---\n{}",
            guard.output()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE REAL END-TO-END PROOF: install the real cdylib over the real admin API, restart onto it, mint a virtual key and AWS credential through the running instance over the same admin API, and independently confirm both rows landed in real MySQL.
#[test]
fn install_over_admin_api_then_mint_a_key_and_verify_mysql_directly() {
    let Some(server_url) = mysql_url() else {
        return;
    };
    let database = common::ScratchDb::new(&server_url);
    let url = database.url.clone();
    let mut schema_observer =
        mysql::Conn::new(mysql::Opts::from_url(&crate::common::raw_mysql_url(&url)).unwrap())
            .unwrap();
    let initial_tables: u64 = schema_observer
        .query_first("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()")
        .unwrap()
        .unwrap();
    assert_eq!(
        initial_tables, 0,
        "only boot #2 may initialize this private schema"
    );
    let so_path = plugin_path();

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-mysql-adminapi-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    let tarball_path = work.join("store-mysql.tar.gz");
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
            "admin-api e2e proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball_path.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", E2E_RELEASE_PRIVKEY)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");
    let tarball_bytes = std::fs::read(&tarball_path).unwrap();
    let file = "store-mysql.tar.gz";

    let admin_port = free_port();
    let admin_token = "smysql-adminapi-e2e-token";
    let admin_base = format!("http://127.0.0.1:{admin_port}/api/v1/admin");
    let client = reqwest::blocking::Client::new();

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    let providers_and_common = format!(
        "listen: \"127.0.0.1:0\"\n\
         admin_listen: \"127.0.0.1:{admin_port}\"\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         auth:\n  chain: [keys]\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
             credentials:\n  at_rest:\n    key: {{ env: BUSBAR_SIGNING_KEY }}\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );

    let config1 = work.join("config1.yaml");
    std::fs::write(
        &config1,
        format!("{providers_and_common}store:\n  module: memory\n"),
    )
    .unwrap();

    let mut guard1 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY", E2E_RELEASE_PUBKEY)
            .env("BUSBAR_CONFIG", &config1)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("MOCK_KEY", "e2e-placeholder-not-a-real-key")
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot1.log"),
        "boot #1 (memory store, admin listener up)",
    );
    wait_for_admin_listener(
        &client,
        &admin_base,
        admin_token,
        &mut guard1,
        "boot #1",
        None,
    );

    let install_body = serde_json::json!({
        "file": file,
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball_bytes),
    });
    let install_resp = client
        .post(format!("{admin_base}/plugins"))
        .header("x-admin-token", admin_token)
        .json(&install_body)
        .send()
        .unwrap();
    let install_status = install_resp.status();
    let install_body_text = install_resp.text().unwrap_or_default();
    assert_eq!(
        install_status.as_u16(),
        201,
        "plugin install must succeed over the real admin API: {install_body_text}"
    );
    assert!(
        plugins_dir.join(file).exists(),
        "the admin API's own install handler must have written the tarball to plugins.dir"
    );

    let unauth = client
        .post(format!("{admin_base}/plugins"))
        .json(&install_body)
        .send()
        .expect("the unauthenticated request must reach the running admin listener");
    assert_eq!(
        unauth.status().as_u16(),
        401,
        "plugin install without x-admin-token must be refused by HTTP, not a transport failure"
    );

    let list: serde_json::Value = client
        .get(format!("{admin_base}/plugins?type=store"))
        .header("x-admin-token", admin_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let items = list["items"].as_array().expect("plugins list has items");
    assert!(
        items
            .iter()
            .any(|p| p["target"] == file && p["name"] == "busbar-store-mysql"),
        "the installed mysql plugin must be listed in the real catalog: {items:?}"
    );

    drop(guard1);

    let retained = std::fs::read(plugins_dir.join(file)).expect("read the admin-installed archive");
    assert_eq!(
        retained, tarball_bytes,
        "the admin install retains the exact uploaded signed archive"
    );
    let archive_pin = busbar_contract::redacted::sha256_hex(&retained);
    let pinned_common = providers_and_common.replacen(
        "  trust:\n",
        &format!("  fetch:\n    - url: \"https://plugins.example/{file}\"\n      sha256: \"{archive_pin}\"\n  trust:\n"),
        1,
    );

    let config2 = work.join("config2.yaml");
    std::fs::write(
        &config2,
        format!("{pinned_common}store:\n  module: mysql\n  settings: {{ url: \"{url}\", input_budget: 67108864 }}\n"),
    )
    .unwrap();

    let mut guard2 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY", E2E_RELEASE_PUBKEY)
            .env("BUSBAR_CONFIG", &config2)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("MOCK_KEY", "e2e-placeholder-not-a-real-key")
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot2.log"),
        "boot #2 (mysql store, the admin-installed plugin)",
    );

    let deadline = Instant::now() + Duration::from_secs(15);
    let booted = loop {
        let tables: u64 = schema_observer
            .query_first(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()
             AND table_name IN ('busbar_v4_meta','busbar_v4_records','busbar_v4_receipts')",
            )
            .unwrap()
            .unwrap();
        if tables == 3 {
            let ready: Option<Vec<u8>> = schema_observer
                .query_first("SELECT ready FROM busbar_v4_meta")
                .unwrap();
            if ready.as_deref() == Some(&[1]) {
                break true;
            }
        }
        if let Ok(Some(status)) = guard2.0.try_wait() {
            panic!("boot #2 exited before creating the mysql schema (status: {status})");
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        booted,
        "boot #2, restarted onto the admin-installed mysql plugin, must admit the native primitive \
         table within 15s -- proof the real dlopen+connect path executed"
    );
    wait_for_admin_listener(
        &client,
        &admin_base,
        admin_token,
        &mut guard2,
        "boot #2",
        Some(database.diagnostic_options()),
    );

    let records_before: u64 = schema_observer
        .query_first("SELECT COUNT(*) FROM busbar_v4_records")
        .unwrap()
        .unwrap();
    let receipts_before: u64 = schema_observer
        .query_first("SELECT COUNT(*) FROM busbar_v4_receipts")
        .unwrap()
        .unwrap();

    let mint_body = serde_json::json!({
        "name": "smysql-adminapi-e2e-key",
        "labels": {},
        "issue_aws_credential": true,
    });
    let mint_resp = client
        .post(format!("{admin_base}/keys"))
        .header("x-admin-token", admin_token)
        .json(&mint_body)
        .send()
        .unwrap();
    let mint_status = mint_resp.status();
    let mint_json: serde_json::Value = mint_resp.json().unwrap();

    let mut redacted_mint_json = mint_json.clone();
    if let Some(obj) = redacted_mint_json.as_object_mut() {
        if obj.contains_key("aws_secret_access_key") {
            obj.insert(
                "aws_secret_access_key".into(),
                serde_json::json!("<redacted>"),
            );
        }
    }
    assert_eq!(
        mint_status.as_u16(),
        201,
        "minting a key over the real admin API must succeed: {redacted_mint_json}"
    );
    let minted_id = mint_json["id"]
        .as_str()
        .expect("minted key response has an id")
        .to_string();

    let access_key_id = mint_json["aws_access_key_id"]
        .as_str()
        .expect("issue_aws_credential:true must return an aws_access_key_id")
        .to_string();
    assert!(
        mint_json["aws_secret_access_key"].is_string(),
        "issue_aws_credential:true must also return an aws_secret_access_key: {redacted_mint_json}"
    );

    let observed: serde_json::Value = client
        .get(format!("{admin_base}/keys/{minted_id}"))
        .header("x-admin-token", admin_token)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(observed["name"], "smysql-adminapi-e2e-key");
    assert_eq!(observed["enabled"], true);
    assert!(!access_key_id.is_empty());
    // Inspect physical persistence without decoding core-owned identity records.
    let records: u64 = schema_observer
        .query_first("SELECT COUNT(*) FROM busbar_v4_records")
        .unwrap()
        .unwrap();
    let receipts: u64 = schema_observer
        .query_first("SELECT COUNT(*) FROM busbar_v4_receipts")
        .unwrap()
        .unwrap();
    assert!(
        records > records_before && receipts > receipts_before,
        "confirmed identity publication has native records and receipts"
    );

    drop(guard2);
    drop(schema_observer);
    let _ = std::fs::remove_dir_all(&work);
}
