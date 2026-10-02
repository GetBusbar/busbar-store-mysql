// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::ModelTokensDelta;
use std::collections::BTreeMap;

/// A name-keyed `usage_units` map from literal pairs — the 1.6.0 shape of what used to be the four
/// `TierTokens`/`TierTokensDelta` fields.
fn units<V: Copy>(pairs: &[(&str, V)]) -> BTreeMap<String, V> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn test_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(u) => Some(u),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!("BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql service container must provision it");
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_MYSQL_URL to run these tests, e.g. mysql://busbar:busbar@127.0.0.1:3307/busbar_test");
            None
        }
    }
}

/// Connects against the same live server every test shares. Deliberately does NOT truncate/reset
/// per TEST (tests run in PARALLEL by default, and a per-test `TRUNCATE` against shared tables races
/// with every other concurrently-running test — tried, and it produced exactly the connection-
/// exhaustion/deadlock/cross-test-corruption chaos you'd expect from concurrent DDL and concurrent
/// global-state resets against one database). Instead: truncate exactly ONCE per BINARY run (guarded
/// by `Once`, so the many parallel test threads calling this all block on the first one, which does
/// the reset, then proceed against a genuinely clean slate) — this is what makes RE-RUNNING the suite
/// against a server with leftover rows from a prior run safe, while leaving true test-to-test
/// concurrency within one run intact (every test below already uses a uniquely-named key id, so
/// concurrent tests never touch each other's rows once the shared starting state is clean).
fn fresh_store() -> Option<MysqlStore> {
    let url = test_url()?;
    let store = MysqlStore::connect(&url).expect("connect+schema");

    ensure_reset(&store);
    Some(store)
}

/// The one-time table wipe, as its own barrier so a test can join it WITHOUT paying for another
/// `MysqlStore::connect`.
///
/// It TRUNCATEs `audit_log`, `api_keys`, `usage_windows` and friends, and `Once` fires it at whatever
/// moment the FIRST caller arrives. Under parallel tests that moment can land in the middle of
/// another test's run — so a test that writes rows without having joined this barrier can have them
/// wiped underneath it. That is exactly what happened: tests reaching the store through
/// `MysqlStore::connect` directly never participated, and lost rows mid-run
/// (`concurrent_appends_of_distinct_seqs_never_deadlock` 10/16, plus `add_usage_...` and a
/// conformance check).
///
/// `Once::call_once` also BLOCKS concurrent callers until the wipe completes, which is the property
/// that makes joining it sufficient: every participant either does the truncate or waits for it, and
/// none of them has written anything yet.
fn ensure_reset(store: &MysqlStore) {
    static RESET_ONCE: std::sync::Once = std::sync::Once::new();
    RESET_ONCE.call_once(|| {
        let mut conn = store.pool.get_conn().unwrap();
        for t in [
            "credentials",
            "api_keys",
            "denylist",
            "usage_windows",
            "usage_window_units",
            "usage_metering",
            "usage_metering_units",
            "audit_log",
        ] {
            conn.query_drop("SET FOREIGN_KEY_CHECKS=0").unwrap();
            conn.query_drop(format!("TRUNCATE TABLE {t}")).unwrap();
            conn.query_drop("SET FOREIGN_KEY_CHECKS=1").unwrap();
        }
        conn.query_drop("UPDATE store_sequence SET revision = 0 WHERE id = 1")
            .unwrap();
    });
}

/// `purge_windows_before` is UNSCOPED by contract: it deletes every window below the cutoff, across
/// every bucket. That is correct for a retention sweep and incompatible with this suite's usual
/// isolation-by-unique-id, so the purge test and the tests that read a window back must not run at
/// the same time. They cannot be isolated by a throwaway database either: the CI user has no
/// CREATE DATABASE privilege (see the note above the backfill tests). One shared lock, held only by
/// the handful of tests that care, keeps the rest of the suite parallel.
static USAGE_WINDOWS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The two tests that build a WHOLE schema from nothing against their own throwaway database (the
/// v2 real-wiring test and the v4->v5 task-store migration) run ~25 DDL statements apiece. MySQL 8's
/// data dictionary is shared ACROSS databases, so that DDL contends even though the two databases do
/// not — and `init_schema`'s deadlock retry, which exists for exactly this, was observed exhausting
/// all five attempts (`ERROR 1213` on `CREATE INDEX idx_api_keys_revision`) when both ran at once on
/// a loaded machine. Serialising just these two keeps the DDL burst from overlapping without costing
/// the rest of the suite any parallelism.
static FRESH_DATABASE_DDL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_fresh_database_ddl() -> std::sync::MutexGuard<'static, ()> {
    FRESH_DATABASE_DDL_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn lock_usage_windows() -> std::sync::MutexGuard<'static, ()> {
    USAGE_WINDOWS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn sample_key(id: &str, generation: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: generation.to_string(),
        name: "test".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 1000,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        idp_subject: None,
        binding_mode: None,
        minted_by: None,
    }
}

fn sample_credential(key_id: &str, public_id: &str, slot: u8) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: format!("cred_{public_id}"),
            key_id: key_id.to_string(),
            kind: "sigv4".to_string(),
            slot,
            public_id: public_id.to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 1000,
            updated_at: 1000,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:shhh".to_string(),
    }
}

#[test]
fn put_get_roundtrips_a_key() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_1", "binding:vk_1:g1");
    s.put_key(&k).unwrap();
    let back = s.get_key("vk_1").unwrap().unwrap();
    assert_eq!(back.generation_hash, "binding:vk_1:g1");
    assert!(back.deleted_at.is_none());
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");
}

/// Regression for a real bug found in this session's final CI verification: every prior test in
/// this file uses short synthetic ids (`"vk_1"`, `"vk_all"`, ...), all well under the schema's old
/// `CHAR(26)` column width -- so the suite never caught that the REAL id format busbar's core mint
/// path generates (`vk_` + 32 hex chars from `hex::encode([u8; 16])`, `governance/state.rs::mint_signed`)
/// is 35 characters, wider than `CHAR(26)` (sized, incorrectly, for a 26-char ULID). A real mint
/// against this schema failed with `MySqlError 1406: Data too long for column 'id'` -- reproduced
/// directly against a live MySQL 8 container outside this crate's own suite before the fix. Widened
/// `id`/`key_id`/`sub` to `VARCHAR(64)` for headroom against any future id-format change, not just
/// today's 35 chars.
#[test]
fn put_get_roundtrips_a_key_with_the_real_35_char_mint_format() {
    let Some(s) = fresh_store() else { return };
    let id = format!("vk_{}", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");
    assert_eq!(
        id.len(),
        35,
        "sanity: matches the real mint_signed id length"
    );
    let k = sample_key(&id, "binding:real-format:g1");
    s.put_key(&k).unwrap();
    let back = s.get_key(&id).unwrap().unwrap();
    assert_eq!(back.id, id);
    assert_eq!(back.generation_hash, "binding:real-format:g1");
}

#[test]
fn allowed_pools_none_vs_empty_round_trip_distinctly() {
    let Some(s) = fresh_store() else { return };
    let mut all_pools = sample_key("vk_all", "g");
    all_pools.allowed_scopes = None;
    let mut no_pools = sample_key("vk_none", "g");
    no_pools.allowed_scopes = Some(vec![]);
    s.put_key(&all_pools).unwrap();
    s.put_key(&no_pools).unwrap();
    assert_eq!(s.get_key("vk_all").unwrap().unwrap().allowed_scopes, None);
    assert_eq!(
        s.get_key("vk_none").unwrap().unwrap().allowed_scopes,
        Some(vec![])
    );
}

#[test]
fn list_keys_since_only_returns_keys_past_watermark() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_wm_a", "g")).unwrap();
    let watermark = s.get_key("vk_wm_a").unwrap().unwrap().revision;
    s.put_key(&sample_key("vk_wm_b", "g")).unwrap();
    let delta = s.list_keys_since(watermark).unwrap();
    // `revision` is a store-GLOBAL counter shared by every concurrently-running test (this test
    // suite deliberately does NOT serialize tests -- see fresh_store's doc), so other tests' keys
    // can legitimately also land past this watermark. Assert OUR key is present and vk_wm_a (minted
    // before the watermark) is absent, not an exact delta size.
    assert!(
        delta.iter().any(|k| k.id == "vk_wm_b"),
        "vk_wm_b must appear in the delta"
    );
    assert!(
        !delta.iter().any(|k| k.id == "vk_wm_a"),
        "vk_wm_a predates the watermark, must not appear"
    );
}

// ── Tombstone delete: the central behavior change, and the hard-delete-invisible-to-hydration fix ──

#[test]
fn delete_key_tombstones_not_removes() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_del", "g")).unwrap();
    s.delete_key("vk_del").unwrap();
    let row = s
        .get_key("vk_del")
        .unwrap()
        .expect("tombstoned row must still be readable");
    assert!(!row.enabled);
    assert!(row.deleted_at.is_some());
}

#[test]
fn delete_key_destroys_credentials() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_cred", "g");
    let cred = sample_credential("vk_cred", "AKIA_TEST", 0);
    s.put_key_with_credential(&k, &cred).unwrap();
    assert_eq!(s.list_credentials("vk_cred").unwrap().len(), 1);
    s.delete_key("vk_cred").unwrap();
    assert!(s.list_credentials("vk_cred").unwrap().is_empty());
    assert!(s
        .lookup_credential_secret("sigv4", "AKIA_TEST")
        .unwrap()
        .is_none());
}

#[test]
fn delete_key_is_idempotent() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_x", "g")).unwrap();
    s.delete_key("vk_x").unwrap();
    let rev_after_first = s.get_key("vk_x").unwrap().unwrap().revision;
    s.delete_key("vk_x").unwrap();
    let rev_after_second = s.get_key("vk_x").unwrap().unwrap().revision;
    assert_eq!(
        rev_after_first, rev_after_second,
        "a no-op re-delete must not stamp a new revision"
    );
}

/// The hard-delete-invisible-to-hydration fix: a hydrator reading `list_keys_since` and
/// `list_credentials_since` in that ORDER must see the tombstone (deleted_at set) before or exactly
/// when the credential deltas stop appearing — proving the tombstone and the credential destruction
/// happened in the SAME transaction / same revision, not a window where one is visible without the
/// other.
#[test]
fn tombstone_and_credential_destruction_share_one_transaction() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_hyd", "g");
    let cred = sample_credential("vk_hyd", "AKIA_HYD", 0);
    s.put_key_with_credential(&k, &cred).unwrap();
    let watermark = s.get_key("vk_hyd").unwrap().unwrap().revision;

    s.delete_key("vk_hyd").unwrap();

    // `revision` is store-GLOBAL and shared across concurrently-running tests -- assert OUR key's
    // tombstone is present in the delta, not an exact delta size (see the sibling watermark test's
    // comment for why an exact count would be racy against the rest of the suite).
    let key_delta = s.list_keys_since(watermark).unwrap();
    let ours = key_delta
        .iter()
        .find(|k| k.id == "vk_hyd")
        .expect("vk_hyd must appear in the delta");
    assert!(
        ours.deleted_at.is_some(),
        "the delta must show the tombstone"
    );

    // The credential row is HARD-deleted (not tombstoned) -- it produces NO further delta for THIS
    // key. A hydrator must rely on the key's deleted_at, never wait for a credential-row delta that
    // will never come. Other concurrent tests' credentials may legitimately appear in this delta too
    // (global revision counter), so assert absence of ours specifically, not overall emptiness.
    let cred_delta = s.list_credentials_since(watermark).unwrap();
    assert!(
        !cred_delta.iter().any(|c| c.meta.key_id == "vk_hyd"),
        "a hard-deleted credential produces no delta -- this is the trap the contract warns about"
    );
}

#[test]
fn scrub_key_requires_tombstone_first() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_scrub", "g")).unwrap();
    assert!(
        s.scrub_key("vk_scrub").is_err(),
        "scrub on a LIVE key must error"
    );
    s.delete_key("vk_scrub").unwrap();
    s.scrub_key("vk_scrub").unwrap();
    let row = s.get_key("vk_scrub").unwrap().unwrap();
    assert_eq!(row.name, "");
}

// ── Credentials: slot bounds, revoke, secret isolation ──────────────────────────────────────────

#[test]
fn credential_slot_occupied_by_live_cred_rejects_overwrite() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_slot", "g");
    s.put_key(&k).unwrap();
    s.put_credential(&sample_credential("vk_slot", "AKIA_A", 0))
        .unwrap();
    let result = s.put_credential(&sample_credential("vk_slot", "AKIA_B", 0));
    assert!(
        result.is_err(),
        "minting into a slot holding a LIVE credential must fail loudly"
    );
}

#[test]
fn credential_slot_reusable_after_revoke() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_rot", "g");
    s.put_key(&k).unwrap();
    let cred1 = sample_credential("vk_rot", "AKIA_OLD", 0);
    s.put_credential(&cred1).unwrap();
    s.revoke_credential(&cred1.meta.id, "rotated").unwrap();
    // Now the slot should be reusable.
    s.put_credential(&sample_credential("vk_rot", "AKIA_NEW", 0))
        .unwrap();
    let live: Vec<_> = s
        .list_credentials("vk_rot")
        .unwrap()
        .into_iter()
        .filter(|c| c.revoked_at.is_none())
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].public_id, "AKIA_NEW");
}

#[test]
fn lookup_credential_secret_returns_the_secret_and_meta_never_leaks_it_via_list() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_sec", "g");
    let cred = sample_credential("vk_sec", "AKIA_SEC", 0);
    s.put_key_with_credential(&k, &cred).unwrap();

    let looked_up = s
        .lookup_credential_secret("sigv4", "AKIA_SEC")
        .unwrap()
        .unwrap();
    assert_eq!(looked_up.secret, "v1:plain:shhh");

    // list_credentials returns CredentialMeta, which has no `secret` field at all -- the type
    // system, not discipline, makes this leak-proof. This assertion just confirms the metadata is
    // otherwise correct.
    let meta = &s.list_credentials("vk_sec").unwrap()[0];
    assert_eq!(meta.public_id, "AKIA_SEC");
}

/// The `ascii_bin` collation is what makes credential lookups case-SENSITIVE, matching Postgres/
/// SQLite's default behavior -- MySQL's default collation is case-insensitive, which would let
/// "AKIA_SEC" and "akia_sec" collide as the same credential (a real security property, not a
/// cosmetic one).
#[test]
fn public_id_lookup_is_case_sensitive() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_case", "g");
    let cred = sample_credential("vk_case", "AKIA_CASE", 0);
    s.put_key_with_credential(&k, &cred).unwrap();

    assert!(s
        .lookup_credential_secret("sigv4", "AKIA_CASE")
        .unwrap()
        .is_some());
    assert!(
        s.lookup_credential_secret("sigv4", "akia_case")
            .unwrap()
            .is_none(),
        "a case-different public_id must NOT resolve to the same credential"
    );
}

// ── Usage ledgers ────────────────────────────────────────────────────────────────────────────────

#[test]
fn put_and_get_usage_roundtrips() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    let ledger = UsageLedger {
        requests: 5,
        billable_requests: 4,
        models: vec![ModelTokens {
            model: "gpt-x".to_string(),
            usage_units: units(&[(UNIT_INPUT, 100), (UNIT_OUTPUT, 50)]),
        }],
    };
    s.put_usage("vk_u", 1000, &ledger).unwrap();
    let back = s.get_usage("vk_u", 1000).unwrap();
    assert_eq!(back.requests, 5);
    assert_eq!(back.billable_requests, 4);
    assert_eq!(back.models[0].tier(UNIT_INPUT), 100);
}

/// The request counters are per-WINDOW, not per-model, and must round-trip as themselves whatever
/// the model breakdown looks like.
///
/// The existing round-trip test uses exactly one model, which is the one arity where a per-model
/// duplication is invisible: `SUM` over a single row returns the value unchanged. With N models,
/// writing the whole `ledger.requests` onto each row and summing them back returns N times the real
/// count, and budget hydration reads the window as N times its real usage.
#[test]
fn usage_request_counters_do_not_multiply_with_the_model_count() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    let model = |name: &str| ModelTokens {
        model: name.to_string(),
        usage_units: units(&[(UNIT_INPUT, 10), (UNIT_OUTPUT, 5)]),
    };
    let ledger = UsageLedger {
        requests: 7,
        billable_requests: 3,
        models: vec![model("gpt-x"), model("gpt-y"), model("gpt-z")],
    };
    s.put_usage("vk_multimodel", 1_000_101, &ledger).unwrap();

    let back = s.get_usage("vk_multimodel", 1_000_101).unwrap();
    assert_eq!(
        back.requests, 7,
        "requests is a per-window counter: three models in one window is still seven requests"
    );
    assert_eq!(back.billable_requests, 3, "same for billable_requests");
    assert_eq!(back.models.len(), 3, "every model must still round-trip");

    // add_usage accumulates against the same window, and must add the delta ONCE, not once per
    // model. This is the fleet flush primitive, so an N-times error here compounds permanently.
    s.add_usage(
        "vk_multimodel",
        1_000_101,
        &busbar_contract::records::UsageDelta {
            requests: 2,
            billable_requests: 1,
            models: vec![
                busbar_contract::records::ModelTokensDelta {
                    model: "gpt-x".to_string(),
                    usage_units: units(&[(UNIT_INPUT, 1), (UNIT_OUTPUT, 1)]),
                },
                busbar_contract::records::ModelTokensDelta {
                    model: "gpt-y".to_string(),
                    usage_units: units(&[(UNIT_INPUT, 1), (UNIT_OUTPUT, 1)]),
                },
            ],
        },
    )
    .unwrap();
    let after = s.get_usage("vk_multimodel", 1_000_101).unwrap();
    assert_eq!(
        after.requests, 9,
        "one delta of two requests must add two, not two per model"
    );
    assert_eq!(after.billable_requests, 4);
}

/// A ledger carrying request counters but NO per-model breakdown must still record those counters.
/// The write path deletes the window first and then inserts one row per model, so an empty model
/// list erased the window and reported success, discarding the requests with it. That shape is
/// real: a window whose requests were all refunded to zero tokens still has a request count.
#[test]
fn usage_with_no_model_breakdown_still_records_its_request_counters() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    let ledger = UsageLedger {
        requests: 4,
        billable_requests: 2,
        models: vec![],
    };
    s.put_usage("vk_nomodels", 1_000_102, &ledger).unwrap();
    let back = s.get_usage("vk_nomodels", 1_000_102).unwrap();
    assert_eq!(
        back.requests, 4,
        "a ledger with no model breakdown still carries request counters, and they must persist"
    );
    assert_eq!(back.billable_requests, 2);
}

/// `purge_metering_before` must match the rows `add_metering` actually wrote. The bucket column is
/// `CHAR(10)` and both the write and the read zero-pad into it; only the purge compared the caller's
/// raw string, so a caller passing the unpadded form matched nothing and got a successful purge of
/// zero rows. A retention sweep that reports success having deleted nothing is the shape this whole
/// release has been chasing.
#[test]
fn purge_metering_before_matches_the_padding_the_write_path_uses() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_purge_meter", "g")).unwrap();
    let bucket = 20_260_731u64;
    s.add_metering(&MeteringDelta {
        key_id: "vk_purge_meter".to_string(),
        bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: BTreeMap::new(),
    })
    .unwrap();
    assert!(
        s.list_metering(bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == "vk_purge_meter"),
        "precondition: the metering row must exist"
    );

    // The caller has a u64 bucket and renders it the obvious way. That is the form the trait's
    // `&str` parameter invites, and it must reach the padded rows.
    let purged = s.purge_metering_before(&bucket.to_string()).unwrap();
    assert!(
        purged >= 1,
        "the purge must actually match the stored rows, got {purged} deleted"
    );
    assert!(
        !s.list_metering(bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == "vk_purge_meter"),
        "the named bucket must be gone after the purge"
    );
}

/// `purge_windows_before` must purge EVERY window below the cutoff, not one capped batch. The
/// contract is "purge every window whose window_start < before"; a single `LIMIT 5000` statement
/// leaves a backlog larger than the cap permanently un-swept while returning a nonzero count each
/// tick that looks like progress.
#[test]
fn purge_windows_before_sweeps_past_a_single_batch() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    // Well clear of every other test's windows, and above the batch size so one capped statement
    // cannot finish the job.
    let base = 7_000_000u64;
    let n = 5_200u64;
    {
        let mut conn = s.pool.get_conn().unwrap();
        let mut sql = String::from(
            "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests) VALUES ",
        );
        for i in 0..n {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("({}, 'key', 'vk_purge_sweep', '', 1)", base + i));
        }
        conn.query_drop(sql).unwrap();
    }

    let purged = s.purge_windows_before(base + n).unwrap();
    assert!(
        purged >= n,
        "every window below the cutoff must be purged and counted, not just one capped batch: \
         expected at least {n}, got {purged}"
    );
    let left: u64 = {
        let mut conn = s.pool.get_conn().unwrap();
        conn.query_first("SELECT COUNT(*) FROM usage_windows WHERE bucket_id = 'vk_purge_sweep'")
            .unwrap()
            .unwrap_or(0)
    };
    assert_eq!(left, 0, "no window below the cutoff may survive the purge");
}

#[test]
fn get_usage_on_an_empty_window_returns_zeroes_not_a_panic() {
    // Regression test: `SUM(x)` with no GROUP BY always returns exactly one row even when zero
    // rows match the WHERE clause — it hands back SQL NULL, not an empty result set. Converting
    // that NULL directly into a `u64` panics (see the `COALESCE` fix in `get_usage`). This exact
    // bug crashed a freshly-restarted busbar process during governance boot's budget hydration
    // against a brand-new store (confirmed in CI: "budget hydration failed ... plugin panicked").
    let Some(s) = fresh_store() else { return };
    let back = s.get_usage("vk_never_used", 999).unwrap();
    assert_eq!(back.requests, 0);
    assert_eq!(back.billable_requests, 0);
    assert!(back.models.is_empty());
}

#[test]
fn add_usage_accumulates_and_floors_at_zero() {
    // Reads a usage window back, so it has to be serialised against the UNSCOPED
    // `purge_windows_before` like the other window-reading tests. It was missed when that lock was
    // introduced, which left it losing its rows to a concurrent purge about 1 run in 18.
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 3,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: units(&[(UNIT_INPUT, 10), (UNIT_OUTPUT, 5)]),
        }],
    };
    s.add_usage("vk_add", 2000, &delta).unwrap();
    s.add_usage("vk_add", 2000, &delta).unwrap();
    let ledger = s.get_usage("vk_add", 2000).unwrap();
    assert_eq!(ledger.requests, 6);
    assert_eq!(ledger.models[0].tier(UNIT_INPUT), 20);

    // A large negative refund must floor at 0, never wrap/go negative.
    let refund = UsageDelta {
        requests: -100,
        billable_requests: -100,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: units(&[(UNIT_INPUT, -1000), (UNIT_OUTPUT, 0)]),
        }],
    };
    s.add_usage("vk_add", 2000, &refund).unwrap();
    let ledger = s.get_usage("vk_add", 2000).unwrap();
    assert_eq!(
        ledger.requests, 0,
        "requests must floor at 0, never underflow"
    );
    assert_eq!(ledger.models[0].tier(UNIT_INPUT), 0);
}

#[test]
fn add_metering_upserts_and_accumulates() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_meter", "g")).unwrap();
    let d = MeteringDelta {
        key_id: "vk_meter".to_string(),
        bucket: 20260731,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "team-a".to_string(),
        pricing_version: "v1".to_string(),
        priced_from_ms: 0,
        usage_units: BTreeMap::new(),
    };
    s.add_metering(&d).unwrap();
    s.add_metering(&d).unwrap();
    let rows = s.list_metering(20260731).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requests, 2);
    assert_eq!(rows[0].tokens_input, 20);
    assert_eq!(rows[0].key_group_at_use, "team-a");
}

// ── Denylist ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn denylist_add_and_list_roundtrips_and_never_shortens_the_window() {
    let Some(s) = fresh_store() else { return };
    s.add_denylist("sub1", "revoked").unwrap();
    assert!(s.list_denylist().unwrap().contains(&"sub1".to_string()));
    // Re-adding must not error (idempotent upsert path).
    s.add_denylist("sub1", "revoked again").unwrap();
}

// ── Boot-time invariant probes ───────────────────────────────────────────────────────────────────

/// Proves the CHECK-enforcement functional probe actually detects a real violation attempt and
/// would refuse to boot if the server didn't enforce it (this test can't easily simulate a real
/// pre-8.0.16 server, so it proves the probe's DETECTION half by confirming a live server currently
/// running under CI/local docker actually enforces the constraint it probes).
#[test]
fn boot_probe_confirms_check_enforcement_on_a_real_server() {
    let Some(url) = test_url() else { return };
    // connect() itself runs the probe internally and would have returned Err if enforcement were
    // missing -- reaching this line at all is the proof for a real MySQL 8 server.
    let store = MysqlStore::connect(&url).unwrap();
    drop(store);
}

#[test]
fn boot_probe_rejects_a_permissive_sql_mode() {
    let Some(url) = test_url() else { return };
    let opts = Opts::from_url(&url).unwrap();
    let pool = Pool::new(opts).unwrap();
    let mut conn = pool.get_conn().unwrap();
    let original: String = conn.query_first("SELECT @@sql_mode").unwrap().unwrap();
    conn.query_drop("SET SESSION sql_mode = ''").unwrap();
    // The probe reads the SESSION-visible sql_mode on ITS OWN connection from the pool, which for a
    // single-connection-pool-in-test scenario should reflect this session's setting; if the pool
    // hands back a different pooled connection this assertion may not trigger -- acceptable for a
    // probe-logic proof rather than a strict guarantee across pool internals.
    let result = MysqlStore::probe_invariants(&mut conn);
    assert!(
        result.is_err(),
        "an empty sql_mode (no STRICT_ALL_TABLES) must be rejected"
    );
    conn.query_drop(format!("SET SESSION sql_mode = '{original}'"))
        .unwrap();
}

/// Treating ANY error from the probe INSERT as proof CHECK constraints are enforced (`.is_err()`
/// on the whole `Result`, with no inspection of WHICH error) would pass for the wrong reason. This
/// is deterministic and needs no live DB: it proves the discrimination logic itself, not that a
/// live server happens to answer one way today.
#[test]
fn is_check_constraint_violation_accepts_only_the_two_real_engine_codes() {
    let mysql_check = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "HY000".to_string(),
        message: "Check constraint 'ck_seq_singleton' is violated.".to_string(),
        code: 3819,
    });
    let mariadb_check = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "23000".to_string(),
        message: "CONSTRAINT `ck_seq_singleton` failed for `busbar_test`.`store_sequence`"
            .to_string(),
        code: 4025,
    });
    let unrelated_lock_timeout = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "HY000".to_string(),
        message: "Lock wait timeout exceeded; try restarting transaction".to_string(),
        code: 1205,
    });
    let unrelated_duplicate_key = mysql::Error::MySqlError(mysql::error::MySqlError {
        state: "23000".to_string(),
        message: "Duplicate entry '1' for key 'PRIMARY'".to_string(),
        code: 1062,
    });

    assert!(
        MysqlStore::is_check_constraint_violation(&mysql_check),
        "MySQL 8.0.16+'s real CHECK-violation code (3819) must be recognized"
    );
    assert!(
        MysqlStore::is_check_constraint_violation(&mariadb_check),
        "MariaDB's real CHECK-violation code (4025) must be recognized -- this store's README \
         names MariaDB as a co-equal supported target"
    );
    assert!(
        !MysqlStore::is_check_constraint_violation(&unrelated_lock_timeout),
        "a lock-wait-timeout must NOT be silently read as proof of CHECK enforcement"
    );
    assert!(
        !MysqlStore::is_check_constraint_violation(&unrelated_duplicate_key),
        "an unrelated duplicate-key error must NOT be silently read as proof of CHECK enforcement"
    );
}

// NOTE: a test proving `connect()` ITSELF (not just `probe_invariants` in isolation) refuses to
// boot on a permissive server was attempted here and reverted. The only way to make a genuinely
// FRESH connection (the kind `connect()`'s own `Pool::new` creates) inherit a permissive sql_mode
// is to flip the server's GLOBAL default -- `mysql::Opts::from_url` has no per-connection `init`
// hook, and `connect()`'s public signature takes only a URL, giving no way to inject session state
// into the specific connection it creates. Tried exactly that (flip GLOBAL, call connect(), restore
// immediately) and it broke 6 OTHER concurrently-running tests in a normal (non-`--test-threads=1`)
// `cargo test` run -- a real, reproduced collateral failure, not a theoretical risk. This suite has
// no serialization mechanism for tests touching global server state (unlike the `store_sequence`
// revision counter, which every test already tolerates as shared, this would be actively breaking
// unrelated tests' boot). Reverted rather than land something that destabilizes the suite. The
// wiring gap (a regression breaking connect()->probe_invariants would ship undetected by the two
// existing direct-call tests above) remains open pending either a `connect()` variant testable with
// injectable Opts, or the mysql crate exposing a per-connection init hook through URL parsing.

/// `connect()` now ESTABLISHES strict sql_mode on every connection via `OptsBuilder::init(...)`
/// (appended, not just verified once at boot) rather than trusting every future pooled/reconnected
/// connection inherits the same session posture the one boot-time probe happened to see. Proves the
/// exact init statement `connect()` uses actually WORKS even when the underlying default would be
/// permissive -- self-contained (a throwaway pool this test builds itself, never the shared server
/// global default), so no cross-test interference risk like the reverted GLOBAL-flip attempt above.
#[test]
fn connect_establishes_strict_sql_mode_via_init_even_when_the_default_would_be_permissive() {
    let Some(url) = test_url() else { return };
    let opts = Opts::from_url(&url).unwrap();
    let opts = mysql::OptsBuilder::from_opts(opts).init(vec![
        // Simulates a permissive starting session (as if the server's own default were empty) --
        // then the SAME append statement connect() itself uses. Both run, in order, on THIS
        // pool's own connections only; never touches the real shared server default.
        "SET SESSION sql_mode = ''",
        "SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')",
    ]);
    let pool = Pool::new(opts).unwrap();
    let mut conn = pool.get_conn().unwrap();
    let sql_mode: String = conn.query_first("SELECT @@sql_mode").unwrap().unwrap();
    assert!(
        sql_mode.contains("STRICT_ALL_TABLES"),
        "the init-time append must land even starting from an empty sql_mode: got '{sql_mode}'"
    );
}

// ── Lock ordering ─────────────────────────────────────────────────────────────────────────────────

/// `delete_key`/`scrub_key` must lock `store_sequence` (via `bump_revision`) BEFORE locking the
/// `api_keys` row, matching every other control-plane transaction (`put_key`, `put_credential`,
/// `revoke_credential`) — that fixed order is what the module doc claims makes deadlock across the
/// admin plane structurally impossible. Proves it by racing a tight loop of `put_key` against a tight
/// loop of `delete_key`+re-`put_key` (to keep the key alive for the next iteration) on the SAME row
/// from concurrent threads: if the two lock acquisitions ever ran in opposite order, MySQL's deadlock
/// detector would abort one side with a real "Deadlock found" error under this contention.
///
/// The deleter used to keep the row alive by re-`put_key`ing a LIVE key straight over the tombstone
/// it had just written. That is the resurrection `RecordStore::put_key` now refuses, so the loop clears the
/// tombstone with a raw hard DELETE instead — test scaffolding, not a store operation, and
/// deliberately not `delete_key`, whose lock ordering is the thing under test and must keep running
/// against a real live row every iteration.
///
/// The putter now tolerates the tombstone refusal, because it races: whether its live write lands or
/// is refused depends on which side holds the row, and both outcomes are correct. What it does NOT
/// tolerate is a deadlock, which is the entire point of the test, so the error is matched rather than
/// swallowed. Unwrapping unconditionally would have made a lock-order regression indistinguishable
/// from an ordinary lost race.
#[test]
fn delete_and_put_on_the_same_key_never_deadlock_under_concurrency() {
    let Some(s) = fresh_store() else { return };
    let id = "vk_lock_order_race";
    let _ = s.delete_key(id);
    {
        let mut c = s.conn().expect("conn");
        let _ = c.exec_drop(
            "DELETE FROM api_keys WHERE id = :id",
            params! { "id" => id },
        );
    }
    s.put_key(&sample_key(id, "g0")).unwrap();

    let put_store = MysqlStore::connect(&test_url().unwrap()).unwrap();
    let del_store = MysqlStore::connect(&test_url().unwrap()).unwrap();
    let raw_url = test_url().unwrap();

    let putter = std::thread::spawn(move || {
        for i in 0..150 {
            if let Err(e) = put_store.put_key(&sample_key(id, &format!("g{i}"))) {
                let msg = e.to_string();
                assert!(
                    msg.contains("is tombstoned"),
                    "the only acceptable loss of this race is the tombstone refusal; a deadlock \
                     means the fixed lock order broke: {msg}"
                );
            }
        }
    });
    let deleter = std::thread::spawn(move || {
        let clear = MysqlStore::connect(&raw_url).unwrap();
        for _ in 0..150 {
            // `delete_key` is what this test exists to exercise: it must take store_sequence before
            // the api_keys row, every iteration, against a genuinely live row.
            if let Err(e) = del_store.delete_key(id) {
                let msg = e.to_string();
                assert!(
                    msg.contains("unknown id"),
                    "delete_key must only ever lose this race by finding the row already cleared: \
                     {msg}"
                );
            }
            // Scaffolding: drop the tombstone so the next iteration races a live row again.
            let mut c = clear.conn().expect("conn");
            let _ = c.exec_drop(
                "DELETE FROM api_keys WHERE id = :id",
                params! { "id" => id },
            );
            let _ = del_store.put_key(&sample_key(id, "g_relive"));
        }
    });

    putter.join().expect("put_key thread must not panic/error");
    deleter
        .join()
        .expect("delete_key thread must not panic/error");
}

// ── Schema v2 migration: hydrate_budgets billing-bug backfill ──────────────────────────────────────
//
// Both tests below run the backfill against a PRIVATE, uniquely-named scratch table, never the real
// shared `usage_windows` every other concurrently-running test also writes to. Two approaches were
// tried and rejected first:
//   1. Mutate the real `store_meta.schema_version` row and reconnect via `MysqlStore::connect()` —
//      that row is a single GLOBAL singleton shared by the whole test binary (unlike every other row
//      in this suite, which is scoped by a unique key id and so never collides even under
//      `fresh_store()`'s documented parallel execution); any OTHER concurrently-running test's own
//      `connect()` unconditionally overwrites it back to the current `SCHEMA_VERSION`, racing a
//      deliberately-lowered test marker in both directions (reproduced: one run backfilled a row
//      that should have been left alone, another failed to backfill one that should have been
//      touched).
//   2. Call `run_v2_backfill_if_needed` directly against the real `usage_windows` table — the
//      production UPDATE is correctly UNSCOPED (a real one-time boot migration touches the whole
//      table, matching store-postgres/store-sqlite exactly), so calling it directly during a
//      concurrently-running suite corrupts OTHER tests' legitimate `billable_requests=0` rows,
//      which shows up as unrelated failures in tests like `put_and_get_usage_roundtrips`.
// Unlike store-postgres's own equivalent test (which isolates via a throwaway DATABASE per test),
// the `busbar` CI user has no `CREATE DATABASE` privilege (confirmed: `ERROR 1044 Access denied for
// user 'busbar'@'%'`) — only table-level DDL within the one shared database, which is what
// `run_v2_backfill_if_needed`'s `table` parameter exists to target here.

fn unique_scratch_table(name: &str) -> String {
    format!(
        "scratch_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// A row created before v2 (`billable_requests = 0` purely because this store didn't track the
/// split yet, not because of a genuine refund) must be backfilled to `billable_requests = requests`
/// when the database predates v2 (`prior_version` 1..2).
#[test]
fn migrate_v2_backfills_billable_requests_for_a_pre_migration_row() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("premigration");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            bucket_id VARCHAR(64) NOT NULL,
            window_start BIGINT NOT NULL,
            requests BIGINT NOT NULL DEFAULT 0,
            billable_requests BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_id, window_start)
        ) ENGINE=InnoDB"
    ))
    .unwrap();
    conn.query_drop(format!(
        "INSERT INTO {table} (bucket_id, window_start, requests, billable_requests) \
         VALUES ('vk_premigration_v2', 5000, 7, 0)"
    ))
    .unwrap();

    MysqlStore::run_v2_backfill_if_needed(&mut conn, 1, &table)
        .expect("the v2 backfill must succeed against a prior_version=1 database");

    let (requests, billable): (u64, u64) = conn
        .query_first(format!(
            "SELECT requests, billable_requests FROM {table} \
             WHERE bucket_id='vk_premigration_v2' AND window_start=5000"
        ))
        .unwrap()
        .unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(requests, 7, "the backfill must never touch `requests`");
    assert_eq!(
        billable, 7,
        "a pre-v2 row's billable_requests must be backfilled to equal requests"
    );
}

/// A row with `billable_requests = 0` that already lives on an at-or-past-v2 database (i.e. a
/// genuine full refund/discount, not a pre-v2 artifact) must NOT be touched — gated on
/// `prior_version >= 2` (already migrated) as well as `prior_version == 0` (a brand-new database
/// with no pre-migration rows to backfill in the first place).
#[test]
fn migrate_v2_does_not_touch_a_row_when_the_database_is_not_pre_v2() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("norerun");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            bucket_id VARCHAR(64) NOT NULL,
            window_start BIGINT NOT NULL,
            requests BIGINT NOT NULL DEFAULT 0,
            billable_requests BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_id, window_start)
        ) ENGINE=InnoDB"
    ))
    .unwrap();
    conn.query_drop(format!(
        "INSERT INTO {table} (bucket_id, window_start, requests, billable_requests) \
         VALUES ('vk_already_v2_refund', 6000, 9, 0)"
    ))
    .unwrap();

    MysqlStore::run_v2_backfill_if_needed(&mut conn, 2, &table)
        .expect("a no-op call at prior_version=2 must still succeed");
    MysqlStore::run_v2_backfill_if_needed(&mut conn, 0, &table)
        .expect("a no-op call at prior_version=0 (fresh database) must still succeed");

    let (requests, billable): (u64, u64) = conn
        .query_first(format!(
            "SELECT requests, billable_requests FROM {table} \
             WHERE bucket_id='vk_already_v2_refund' AND window_start=6000"
        ))
        .unwrap()
        .unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(requests, 9);
    assert_eq!(
        billable, 0,
        "a genuine billable_requests=0 row must survive both no-op calls untouched"
    );
}

fn scratch_collation(conn: &mut PooledConn, table: &str, column: &str) -> String {
    conn.query_first(format!(
        "SELECT COLLATION_NAME FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{table}' AND COLUMN_NAME = '{column}'"
    ))
    .unwrap()
    .expect("column exists")
}

/// A `usage_metering`-shaped table created before v3 (v1.0.0 shipped `key_group_at_use` without
/// `ascii_bin`, inheriting MySQL's case-insensitive default) must have its collation corrected to
/// `ascii_bin` when the database predates v3 (`prior_version` 1..3).
#[test]
fn migrate_v3_fixes_key_group_at_use_collation_for_a_pre_migration_table() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("premigration_v3");

    let mut conn = s.pool.get_conn().unwrap();
    // The pre-v3 shape: no explicit collation, so it inherits the database default (utf8mb4_*, NOT
    // ascii_bin) -- exactly what a real v1.0.0-created `usage_metering` table has today.
    conn.query_drop(format!(
        "CREATE TABLE {table} (key_group_at_use VARCHAR(128) NOT NULL DEFAULT '') ENGINE=InnoDB"
    ))
    .unwrap();
    let before = scratch_collation(&mut conn, &table, "key_group_at_use");
    assert_ne!(
        before, "ascii_bin",
        "the scratch table must start on a non-ascii_bin collation, or this test proves nothing"
    );

    MysqlStore::run_v3_ascii_bin_fix_if_needed(&mut conn, 1, &table)
        .expect("the v3 ascii_bin fix must succeed against a prior_version=1 database");

    let after = scratch_collation(&mut conn, &table, "key_group_at_use");
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(
        after, "ascii_bin",
        "a pre-v3 table's key_group_at_use collation must be corrected to ascii_bin"
    );
}

/// A table already at-or-past v3 (already `ascii_bin`, or a fresh v3+ install) must not have the
/// migration re-run pointlessly — gated on `prior_version >= 3` as well as `prior_version == 0`.
#[test]
fn migrate_v3_does_not_touch_a_table_when_the_database_is_not_pre_v3() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("norerun_v3");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            key_group_at_use VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT ''
        ) ENGINE=InnoDB"
    ))
    .unwrap();

    MysqlStore::run_v3_ascii_bin_fix_if_needed(&mut conn, 3, &table)
        .expect("a no-op call at prior_version=3 must still succeed");
    MysqlStore::run_v3_ascii_bin_fix_if_needed(&mut conn, 0, &table)
        .expect("a no-op call at prior_version=0 (fresh database) must still succeed");

    let after = scratch_collation(&mut conn, &table, "key_group_at_use");
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(
        after, "ascii_bin",
        "both no-op calls must leave the collation untouched"
    );
}

/// KNOWN, DOCUMENTED, NOT-YET-CLOSED GAP -- see `run_v2_backfill_if_needed`'s own doc comment for
/// the full writeup, including why a `GET_LOCK` does not close it. Characterizes the exact
/// rolling-upgrade race as a
/// deterministic ORDER-of-operations reproduction (no real thread timing needed -- the race is
/// about which write reaches the row first, which a single-threaded test can fully control): a
/// pre-v2 row that receives ONE legitimate real v2 write (simulating an already-live node
/// elsewhere in the fleet) BEFORE this node's own backfill runs permanently loses its pre-v2
/// history from ever being counted as billable.
///
/// `#[ignore]`d: it documents real, CURRENT behavior rather than guarding a regression, so it
/// fails today by design. Un-ignore once the provenance-based redesign
/// `run_v2_backfill_if_needed` describes lands, at which point the assertion starts passing.
#[test]
#[ignore = "characterizes a known, documented, not-yet-fixed gap -- see run_v2_backfill_if_needed's doc comment"]
fn characterize_v2_backfill_loses_a_row_to_a_racing_live_write() {
    let Some(s) = fresh_store() else { return };
    let table = unique_scratch_table("racecharacterize");

    let mut conn = s.pool.get_conn().unwrap();
    conn.query_drop(format!(
        "CREATE TABLE {table} (
            bucket_id VARCHAR(64) NOT NULL,
            window_start BIGINT NOT NULL,
            requests BIGINT NOT NULL DEFAULT 0,
            billable_requests BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_id, window_start)
        ) ENGINE=InnoDB"
    ))
    .unwrap();
    // Pre-v2 history: 10 real requests, never tracked as billable (this store didn't split the
    // counters before v2).
    conn.query_drop(format!(
        "INSERT INTO {table} (bucket_id, window_start, requests, billable_requests) \
         VALUES ('vk_race', 7000, 10, 0)"
    ))
    .unwrap();

    // A live, already-upgraded node's REAL v2 write lands FIRST -- legitimate: 2 new billable
    // requests arrive after the upgrade, correctly tracked in lockstep by v2-aware code.
    conn.query_drop(format!(
        "UPDATE {table} SET requests = requests + 2, billable_requests = billable_requests + 2 \
         WHERE bucket_id = 'vk_race' AND window_start = 7000"
    ))
    .unwrap();

    // THEN this (still-booting) node's backfill runs.
    MysqlStore::run_v2_backfill_if_needed(&mut conn, 1, &table).unwrap();

    let (requests, billable): (u64, u64) = conn
        .query_first(format!(
            "SELECT requests, billable_requests FROM {table} \
             WHERE bucket_id='vk_race' AND window_start=7000"
        ))
        .unwrap()
        .unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();

    assert_eq!(requests, 12, "sanity: 10 pre-v2 + 2 live v2 requests");
    assert_eq!(
        billable, 12,
        "the pre-v2 10 requests should be reclassified as billable too -- if this fails, \
         billable_requests stayed at 2 (only the live write's own delta) because the backfill's \
         predicate (billable_requests = 0) no longer matched once the live write touched the row \
         first. This is the documented, known gap in run_v2_backfill_if_needed's doc comment."
    );
}

/// The two tests above prove `run_v2_backfill_if_needed` works correctly called DIRECTLY with a
/// hand-supplied `prior_version`/`table` -- neither ever goes through `try_init_schema`'s REAL
/// wiring: reading `prior_version` from the actual `store_meta.schema_version` row and calling the
/// backfill with the real hardcoded table name `"usage_windows"`. A regression that reordered that
/// real read (e.g. moved it after the SCHEMA loop / the `schema_version` write) or typo'd the real
/// table name would ship undetected by either test above.
///
/// Exercises the REAL public `MysqlStore::connect()` entry point (which internally calls the real,
/// unparameterized `try_init_schema`) against a DEDICATED, throwaway database -- not the shared
/// `busbar_test` every other test in this suite uses -- so this can safely pre-seed a real pre-v2
/// `store_meta.schema_version='1'` row without racing any other concurrently-running test's own
/// `connect()` calls (the documented reason `run_v2_backfill_if_needed` takes an explicit
/// `prior_version` instead of reading the shared row itself). Needs `root` to `CREATE DATABASE`
/// (same constraint as the app-level `busbar` CI user lacking that privilege, documented on the
/// migration tests above) -- real CI has `root`/`busbar` available with matching credentials (see
/// `plugin-ci.yml`'s own "set strict sql_mode" step, which already connects as root).
#[test]
fn try_init_schema_real_wiring_backfills_a_genuinely_pre_v2_database() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(url) = test_url() else { return };
    let db_name = format!(
        "busbar_wiring_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let root_url = url.replacen("busbar:busbar@", "root:busbar@", 1);
    let root_opts = Opts::from_url(&root_url).unwrap();
    let root_pool = Pool::new(root_opts).unwrap();
    let mut root_conn = root_pool.get_conn().unwrap();
    root_conn
        .query_drop(format!("CREATE DATABASE {db_name}"))
        .unwrap();
    root_conn
        .query_drop(format!(
            "GRANT ALL PRIVILEGES ON {db_name}.* TO 'busbar'@'%'"
        ))
        .unwrap();

    // Point the app-level busbar user at the fresh dedicated database (swap the path component of
    // the URL, keep the same host/port/credentials). `url` is only a transitive dep (via `mysql`),
    // so plain string surgery on the last path segment instead of a proper URL crate.
    let dedicated_url = {
        let cut = url
            .rfind('/')
            .expect("test_url() must be a mysql:// URL with a /database path");
        format!("{}/{db_name}", &url[..cut])
    };

    // Boot ONCE to create the real schema for real via try_init_schema, then hand-seed a genuine
    // pre-v2 marker directly in the real store_meta row (safe here -- this database has no other
    // concurrent user) and a pre-v2-shaped row in the real usage_windows table.
    let store1 = MysqlStore::connect(&dedicated_url).expect("first boot must create the schema");
    {
        let mut conn = store1.pool.get_conn().unwrap();
        conn.query_drop("UPDATE store_meta SET v = '1' WHERE k = 'schema_version'")
            .unwrap();
        conn.query_drop(
            "INSERT INTO usage_windows \
             (window_start, bucket_scope, bucket_id, model, requests, billable_requests) \
             VALUES (9000, 'key', 'vk_wiring', 'gpt', 5, 0)",
        )
        .unwrap();
    }
    drop(store1);

    // Reconnect -- THIS is the real try_init_schema call under test: it must read prior_version=1
    // from the real store_meta row (not a hand-supplied one) and run the backfill against the
    // real, hardcoded "usage_windows" table name (not a scratch table a test pointed it at).
    let store2 = MysqlStore::connect(&dedicated_url).expect("second boot (the real migration)");
    let mut conn = store2.pool.get_conn().unwrap();
    let (requests, billable): (u64, u64) = conn
        .query_first(
            "SELECT requests, billable_requests FROM usage_windows \
             WHERE bucket_id = 'vk_wiring' AND window_start = 9000",
        )
        .unwrap()
        .unwrap();
    drop(store2);

    root_conn
        .query_drop(format!("DROP DATABASE {db_name}"))
        .unwrap();

    assert_eq!(requests, 5);
    assert_eq!(
        billable, 5,
        "try_init_schema's REAL wiring (real store_meta read, real \"usage_windows\" table name) \
         must have backfilled this pre-v2 row -- a regression to either would leave billable_requests \
         at 0, undetected by the two tests above that bypass this wiring entirely"
    );
}

// ── read_prior_version: real query errors must not collapse into "fresh install" ───────────────────

fn scratch_meta_table(conn: &mut PooledConn, name: &str) -> String {
    let table = unique_scratch_table(name);
    conn.query_drop(format!(
        "CREATE TABLE {table} (k VARCHAR(191) PRIMARY KEY, v TEXT NOT NULL) ENGINE=InnoDB"
    ))
    .unwrap();
    table
}

#[test]
fn read_prior_version_is_zero_when_no_row_exists_yet() {
    let Some(s) = fresh_store() else { return };
    let mut conn = s.pool.get_conn().unwrap();
    let table = scratch_meta_table(&mut conn, "noversion");
    let v = MysqlStore::read_prior_version(&mut conn, &table).unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(
        v, 0,
        "no schema_version row yet must read as version 0, not an error"
    );
}

#[test]
fn read_prior_version_parses_a_real_stored_value() {
    let Some(s) = fresh_store() else { return };
    let mut conn = s.pool.get_conn().unwrap();
    let table = scratch_meta_table(&mut conn, "realversion");
    conn.query_drop(format!(
        "INSERT INTO {table} (k, v) VALUES ('schema_version', '1')"
    ))
    .unwrap();
    let v = MysqlStore::read_prior_version(&mut conn, &table).unwrap();
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert_eq!(v, 1);
}

/// A `.and_then(|v| v.parse().ok()).unwrap_or(0)` read would silently turn a corrupt, non-numeric
/// stored value into version 0, indistinguishable from "fresh install" -- the same
/// "looks already migrated but isn't" failure mode the module doc warns about, reached via a
/// corrupt marker instead of a query error. A corrupt marker must hard-fail, not silently
/// default.
#[test]
fn read_prior_version_hard_fails_on_a_corrupt_stored_value() {
    let Some(s) = fresh_store() else { return };
    let mut conn = s.pool.get_conn().unwrap();
    let table = scratch_meta_table(&mut conn, "corruptversion");
    conn.query_drop(format!(
        "INSERT INTO {table} (k, v) VALUES ('schema_version', 'not-a-number')"
    ))
    .unwrap();
    let result = MysqlStore::read_prior_version(&mut conn, &table);
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    assert!(
        result.is_err(),
        "a corrupt (non-numeric) schema_version value must hard-fail, not silently read as 0"
    );
}

/// `revoke_credential` must reject an unknown/typo'd id loudly, not silently return `Ok(())`.
/// An unconditional `UPDATE ... WHERE id=:id` that never checks for a matched row cannot produce
/// the `Err` this asserts.
#[test]
fn revoke_credential_rejects_an_unknown_id() {
    let Some(s) = fresh_store() else { return };
    let err = s
        .revoke_credential("cred_does_not_exist_anywhere", "cleanup")
        .unwrap_err();
    assert!(
        err.to_string().contains("unknown credential id"),
        "must name the real reason: {err}"
    );
}

/// `put_credential` must reject a `public_id` collision against a DIFFERENT credential's id, not
/// silently corrupt the unrelated row via `ON DUPLICATE KEY UPDATE`, which would overwrite that
/// row's `id`/`secret` and leave its `key_id`/`slot` untouched.
#[test]
fn put_credential_rejects_a_public_id_collision_against_a_different_credential() {
    let Some(s) = fresh_store() else { return };
    let k1 = sample_key("vk_pubcol_a", "g");
    let k2 = sample_key("vk_pubcol_b", "g");
    s.put_key(&k1).unwrap();
    s.put_key(&k2).unwrap();
    s.put_credential(&sample_credential("vk_pubcol_a", "AKIA_SHARED_PUBID", 0))
        .unwrap();

    // A genuinely NEW credential (different id, different key_id/slot) reusing the SAME
    // public_id must be rejected, not silently take over the first credential's identity.
    // (sample_credential derives `id` from `public_id`, so force a DIFFERENT id explicitly --
    // otherwise this would collide on the PRIMARY KEY too and test the wrong path.)
    let mut colliding = sample_credential("vk_pubcol_b", "AKIA_SHARED_PUBID", 0);
    colliding.meta.id = "cred_genuinely_different_id".to_string();
    let err = s.put_credential(&colliding).unwrap_err();
    // A real MySQL duplicate-key rejection on `uq_cred_public` -- dropping the blanket
    // `ON DUPLICATE KEY UPDATE` (see put_credential's own comment) means MySQL's own constraint
    // now catches this collision directly, same as the PRIMARY KEY case below.
    assert!(
        (err.to_string().contains("Duplicate entry") || err.to_string().contains("1062"))
            && err.to_string().contains("uq_cred_public"),
        "must be a real duplicate-key rejection on the public_id unique key: {err}"
    );

    // The FIRST credential must be completely untouched by the rejected attempt.
    let untouched = s
        .lookup_credential_secret("sigv4", "AKIA_SHARED_PUBID")
        .unwrap()
        .unwrap();
    assert_eq!(untouched.meta.key_id, "vk_pubcol_a");
}

/// `put_credential` must also reject a PRIMARY KEY (`id`) collision against a row that belongs to
/// a DIFFERENT `key_id`/`slot` -- the third of the table's 3 unique keys, and the one a
/// public_id-only guard does not cover. `ON DUPLICATE KEY UPDATE`'s SET list never touches
/// `key_id`/`slot`, so without this guard the statement silently overwrites the existing row's
/// secret material while leaving it attached to the WRONG key/slot.
#[test]
fn put_credential_rejects_an_id_collision_against_a_different_key_or_slot() {
    let Some(s) = fresh_store() else { return };
    let k1 = sample_key("vk_idcol_a", "g");
    let k2 = sample_key("vk_idcol_b", "g");
    s.put_key(&k1).unwrap();
    s.put_key(&k2).unwrap();
    let original = sample_credential("vk_idcol_a", "AKIA_IDCOL_ORIG", 0);
    s.put_credential(&original).unwrap();

    // Same `id` as `original` (sample_credential derives id from public_id, so force a real
    // collision by reusing original's id directly), but a DIFFERENT key_id/slot/public_id.
    let mut colliding = sample_credential("vk_idcol_b", "AKIA_IDCOL_NEW", 1);
    colliding.meta.id = original.meta.id.clone();
    let err = s.put_credential(&colliding).unwrap_err();
    // MySQL's own PRIMARY KEY constraint surfaces this now (a real 1062 duplicate-entry error),
    // since the INSERT path no longer silently upserts across an id collision.
    assert!(
        err.to_string().contains("Duplicate entry") || err.to_string().contains("1062"),
        "must be a real duplicate-key rejection, not a silent corruption: {err}"
    );

    // The ORIGINAL credential must be completely untouched.
    let untouched = s
        .lookup_credential_secret("sigv4", "AKIA_IDCOL_ORIG")
        .unwrap()
        .unwrap();
    assert_eq!(untouched.meta.key_id, "vk_idcol_a");
    assert_eq!(untouched.meta.slot, 0);
}

/// Real proof that `delete_key`'s tombstone-write and credential-destroy are ONE atomic
/// transaction, not two: a concurrent connection contends for the SAME row lock `delete_key`
/// holds for its whole transaction. InnoDB row locks are held for the full transaction, not
/// released between statements, so a racer that observes the row after finding it locked can
/// only ever see the FULLY-before or FULLY-after state -- never a window with one half done and
/// not the other. If `delete_key` were split into two transactions, the row lock would release
/// after the first commits, letting a racer that lands in that gap observe the broken
/// intermediate state, which the assertion below would then catch.
#[test]
fn tombstone_and_credential_destruction_are_never_observed_apart() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_atomicrace", "g");
    let cred = sample_credential("vk_atomicrace", "AKIA_ATOMICRACE", 0);
    s.put_key_with_credential(&k, &cred).unwrap();

    let pool = s.pool.clone();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let observed2 = observed.clone();

    let racer = std::thread::spawn(move || {
        let mut conn = pool.get_conn().unwrap();
        // Bias toward the interesting (contended) case: repeatedly probe with a near-zero lock
        // wait until we find the row genuinely locked (proof delete_key's transaction is
        // mid-flight), then switch to a normal blocking wait so we observe the state EXACTLY as
        // the lock releases -- never a state from before delete_key started.
        for _ in 0..500 {
            let mut probe = conn.start_transaction(mysql::TxOpts::default()).unwrap();
            // NOWAIT (MySQL 8.0.1+) errors instantly instead of blocking -- a real non-blocking
            // probe, unlike innodb_lock_wait_timeout (whose minimum valid value is 1 second).
            let busy = probe
                .exec_first::<Option<u64>, _, _>(
                    "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE NOWAIT",
                    params! { "id" => "vk_atomicrace" },
                )
                .is_err();
            let _ = probe.rollback();
            if busy {
                break;
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        conn.query_drop("SET innodb_lock_wait_timeout = 50")
            .unwrap();
        let mut tx = conn.start_transaction(mysql::TxOpts::default()).unwrap();
        let tombstoned: Option<u64> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => "vk_atomicrace" },
            )
            .unwrap()
            .flatten();
        let cred_count: i64 = tx
            .exec_first(
                "SELECT COUNT(*) FROM credentials WHERE key_id = :id",
                params! { "id" => "vk_atomicrace" },
            )
            .unwrap()
            .unwrap();
        let _ = tx.rollback();
        *observed2.lock().unwrap() = Some((tombstoned.is_some(), cred_count));
    });

    s.delete_key("vk_atomicrace").unwrap();
    racer.join().unwrap();

    let (tombstoned, cred_count) = observed.lock().unwrap().unwrap();
    assert!(
        (tombstoned && cred_count == 0) || (!tombstoned && cred_count == 1),
        "observed tombstoned={tombstoned} cred_count={cred_count} -- a window where one half of \
         delete_key committed without the other means it is NOT one atomic transaction"
    );
}

/// The `Store` contract conformance suite — THIS crate's own copy, at `src/tests/store_conformance.rs`.
/// It used to arrive as `busbar-plugin-testkit`; the owner ruled that crate deleted on 2026-09-22 and
/// #2/#31 forbid a shared test util between plugins, so every backend owns its copy. See that file's
/// module doc for the full provenance and for what the shared crate was buying: a new ruling no
/// longer reaches this backend on a dependency bump, it has to be written in here by hand.
mod store_conformance;

/// The cross-backend `Store` conformance checks, answered by this backend — EVERY check the suite
/// offers, including the plane-record battery and the two interleaved-run regressions busbar's own
/// reference backend runs.
///
/// Fixtures are namespaced per process AND per check, and hard-reset first. Per-process because this
/// suite runs against a SHARED live database that is not reset between tests and CI can point more
/// than one binary at it; per-check because these run in parallel and `reset` clears every id in the
/// namespace it is given, so one shared namespace would have each check deleting the others' rows
/// mid-run.
mod conformance {
    use super::store_conformance as conf;
    use super::{lock_plane_purge, test_url, MysqlStore};
    use mysql::params;
    use mysql::prelude::Queryable;

    fn ns(check: &str) -> String {
        format!("vk_c{}{}", std::process::id(), check)
    }

    fn reset(store: &MysqlStore, ns: &str, seq: u64) {
        let mut conn = store.conn().expect("conn");
        for id in conf::key_ids(ns) {
            let _ = conn.exec_drop(
                "DELETE FROM credentials WHERE key_id = :id",
                params! { "id" => &id },
            );
            let _ = conn.exec_drop(
                "DELETE FROM api_keys WHERE id = :id",
                params! { "id" => &id },
            );
        }
        for id in conf::credential_ids(ns) {
            let _ = conn.exec_drop(
                "DELETE FROM credentials WHERE id = :id",
                params! { "id" => &id },
            );
        }
        let _ = conn.exec_drop(
            "DELETE FROM audit_log WHERE seq = :seq",
            params! { "seq" => seq },
        );
        // Every plane record and token the battery derives from `ns` (`{ns}_ptask_*`, `{ns}_pchain`,
        // `{ns}_prinA`, `{ns}_srvA`, `{ns}_asknonce`, ...). A prefix test rather than LIKE, because
        // `ns` itself contains `_`, which LIKE would read as a wildcard.
        let prefix = format!("{ns}_");
        let _ = conn.exec_drop(
            "DELETE FROM plane_records WHERE LEFT(ident, CHAR_LENGTH(:p)) = :p",
            params! { "p" => &prefix },
        );
        let _ = conn.exec_drop(
            "DELETE FROM plane_tokens WHERE LEFT(token, CHAR_LENGTH(:p)) = :p",
            params! { "p" => &prefix },
        );
    }

    /// ONE store shared by every check.
    ///
    /// `MysqlStore::connect` re-runs the schema DDL and the invariant probes on EVERY call, and this
    /// module's checks run in parallel with sibling tests that hold `SELECT ... FOR UPDATE`
    /// transactions open. Connecting once per check mid-suite made those siblings fail with
    /// `ERROR 1412 (Table definition has changed, please retry transaction)` about one run in six.
    /// Connecting once, behind a `OnceLock`, removes the extra DDL entirely; the checks stay
    /// isolated from each other through their per-check namespaces, not through separate
    /// connections.
    fn shared_store() -> Option<&'static MysqlStore> {
        static STORE: std::sync::OnceLock<Option<MysqlStore>> = std::sync::OnceLock::new();
        STORE
            .get_or_init(|| {
                let url = test_url()?;
                let s = MysqlStore::connect(&url).expect("connect");
                // Same barrier as every other test: without it the one-time TRUNCATE can land in
                // the middle of a conformance check and delete the rows it just wrote.
                super::ensure_reset(&s);
                Some(s)
            })
            .as_ref()
    }

    fn setup(check: &str, seq: u64) -> Option<(&'static MysqlStore, String)> {
        let store = shared_store()?;
        let ns = ns(check);
        reset(store, &ns, seq);
        Some((store, ns))
    }

    #[test]
    fn put_key_does_not_resurrect_a_tombstone() {
        let Some((store, ns)) = setup("put", 0) else {
            return;
        };
        conf::assert_put_key_does_not_resurrect_a_tombstone(store, &ns);
    }

    #[test]
    fn delete_key_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("del", 0) else {
            return;
        };
        conf::assert_delete_key_unknown_id_is_an_error(store, &ns);
    }

    #[test]
    fn revoke_credential_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("rev", 0) else {
            return;
        };
        conf::assert_revoke_credential_unknown_id_is_an_error(store, &ns);
    }

    #[test]
    fn put_credential_requires_a_live_key() {
        let Some((store, ns)) = setup("pcl", 0) else {
            return;
        };
        conf::assert_put_credential_requires_a_live_key(store, &ns);
    }

    #[test]
    fn put_key_with_credential_is_atomic() {
        let Some((store, ns)) = setup("pkc", 0) else {
            return;
        };
        conf::assert_put_key_with_credential_is_atomic(store, &ns);
    }

    #[test]
    fn append_audit_duplicate_seq_is_ok_when_identical_and_an_error_when_different() {
        let seq = 910_000_000u64 + (std::process::id() as u64 % 1_000_000);
        let Some((store, _ns)) = setup("aud", seq) else {
            return;
        };
        conf::assert_append_audit_duplicate_seq(store, seq);
    }

    #[test]
    fn plane_task_upsert_get_list() {
        let Some((store, ns)) = setup("ptk", 0) else {
            return;
        };
        conf::assert_plane_task_upsert_get_list(store, &ns);
    }

    #[test]
    fn plane_event_chain_is_ordered_by_seq() {
        let Some((store, ns)) = setup("pev", 0) else {
            return;
        };
        conf::assert_plane_event_chain_is_ordered_by_seq(store, &ns);
    }

    #[test]
    fn plane_call_parents_enumerated() {
        let Some((store, ns)) = setup("pcp", 0) else {
            return;
        };
        conf::assert_plane_call_parents_enumerated(store, &ns);
    }

    #[test]
    fn plane_demotion_upsert_list_delete() {
        let Some((store, ns)) = setup("pdm", 0) else {
            return;
        };
        conf::assert_plane_demotion_upsert_list_delete(store, &ns);
    }

    // The two purge checks sweep a KIND-WIDE cutoff. The suite's own `ns_purge_window` keeps two
    // conformance runs out of each other's way, but this binary's own exact-count purge tests
    // (`purge_calls_*`, `purge_tasks_*`) sweep wider cutoffs over the same kinds, so every purge in
    // the binary takes the one `PLANE_PURGE_LOCK`.

    #[test]
    fn plane_purge_honours_the_cutoff() {
        let _guard = lock_plane_purge();
        let Some((store, ns)) = setup("ppc", 0) else {
            return;
        };
        conf::assert_plane_purge_honours_the_cutoff(store, &ns);
    }

    #[test]
    fn plane_purge_task_keeps_active_rows() {
        let _guard = lock_plane_purge();
        let Some((store, ns)) = setup("ppt", 0) else {
            return;
        };
        conf::assert_plane_purge_task_keeps_active_rows(store, &ns);
    }

    #[test]
    fn plane_token_is_single_use() {
        let Some((store, ns)) = setup("ptu", 0) else {
            return;
        };
        conf::assert_plane_token_is_single_use(store, &ns);
    }

    // The suite's kind-wide purge-collision regression, the same one busbar's reference backend runs:
    // two conformance runs against ONE live database, each sweeping the other's kind while it works.
    // Here that is literal — two namespaces, two threads, one shared MySQL.

    #[test]
    fn plane_purge_honours_the_cutoff_survives_two_interleaved_runs() {
        let _guard = lock_plane_purge();
        let Some((store, ns_a)) = setup("ppcA", 0) else {
            return;
        };
        let ns_b = ns("ppcB");
        reset(store, &ns_b, 0);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(store, &ns_a));
            let b = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(store, &ns_b));
            a.join().expect("run A must not panic");
            b.join().expect("run B must not panic");
        });
    }

    #[test]
    fn plane_purge_task_keeps_active_rows_survives_two_interleaved_runs() {
        let _guard = lock_plane_purge();
        let Some((store, ns_a)) = setup("pptA", 0) else {
            return;
        };
        let ns_b = ns("pptB");
        reset(store, &ns_b, 0);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(store, &ns_a));
            let b = scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(store, &ns_b));
            a.join().expect("run A must not panic");
            b.join().expect("run B must not panic");
        });
    }
}

/// Concurrent appends of DIFFERENT seqs must not deadlock.
///
/// The duplicate-seq comparison was first written as `SELECT ... FOR UPDATE` then INSERT. Under
/// REPEATABLE READ (what `TxOpts::default()` leaves the server on) a `FOR UPDATE` on a MISSING row
/// takes a next-key/gap lock; two appends of different, both-new seqs land in the same gap, and each
/// side's following INSERT needs an insert-intention lock that conflicts with the other's gap lock.
/// Four threads over 200 distinct seqs each produced 39 `ERROR 1213` deadlocks that way, against 0
/// for the plain insert it replaced. `append_audit` is also the one control-plane path that does not
/// call `bump_revision`, so it sits outside the `store_sequence` serialization that keeps every other
/// admin-plane transaction deadlock-free.
///
/// A durable audit write-through failing under ordinary multi-node load defeats the whole point of
/// the durable sink, so this pins it.
#[test]
fn concurrent_appends_of_distinct_seqs_never_deadlock() {
    // ONE store, shared by every thread, instead of one `connect()` per worker.
    //
    // `MysqlStore::connect` re-runs the whole schema DDL on every call (`init_schema`), and doing
    // that mid-suite makes sibling tests holding `SELECT ... FOR UPDATE` fail with
    // `ERROR 1412 (Table definition has changed, please retry transaction)`. An earlier version of
    // this test connected six extra times and took a suite that was 20/20 clean to 3/20 failing --
    // while the commit adding it claimed to have REMOVED mid-suite connects. The pool inside one
    // store is what provides the concurrency here; extra stores only bought extra DDL.
    let Some(url) = test_url() else { return };
    let base = 940_000_000u64 + (std::process::id() as u64 % 100_000) * 1_000;
    let shared = std::sync::Arc::new(MysqlStore::connect(&url).expect("connect"));
    // Join the one-time wipe barrier before writing anything, or it can fire mid-run and truncate
    // `audit_log` underneath these 200 appends.
    ensure_reset(&shared);
    {
        let store = std::sync::Arc::clone(&shared);
        let mut conn = store.conn().expect("conn");
        let _ = conn.exec_drop(
            "DELETE FROM audit_log WHERE seq >= :lo AND seq < :hi",
            params! { "lo" => base, "hi" => base + 1_000 },
        );
    }

    let threads: Vec<_> = (0..4u64)
        .map(|t| {
            let store = std::sync::Arc::clone(&shared);
            std::thread::spawn(move || {
                for i in 0..50u64 {
                    let seq = base + t * 100 + i;
                    let rec = AuditRecord {
                        seq,
                        ts: 1_700_000_000,
                        action: "key.mint".into(),
                        resource: format!("key:vk_{seq}"),
                        outcome: "applied".into(),
                        principal: "admin".into(),
                        prev_hash: String::new(),
                        hash: format!("h{seq}"),
                    };
                    if let Err(e) = store.append_audit(&rec) {
                        let msg = e.to_string();
                        assert!(
                            !msg.contains("Deadlock") && !msg.contains("1213"),
                            "concurrent appends of DISTINCT seqs deadlocked: {msg}"
                        );
                        panic!("append_audit failed unexpectedly: {msg}");
                    }
                }
            })
        })
        .collect();
    for h in threads {
        h.join().expect("no append thread may fail");
    }

    let mut conn = shared.conn().expect("conn");
    let n: Option<u64> = conn
        .exec_first(
            "SELECT COUNT(*) FROM audit_log WHERE seq >= :lo AND seq < :hi",
            params! { "lo" => base, "hi" => base + 1_000 },
        )
        .unwrap();
    assert_eq!(n, Some(200), "every distinct append must be durably stored");
    let _ = conn.exec_drop(
        "DELETE FROM audit_log WHERE seq >= :lo AND seq < :hi",
        params! { "lo" => base, "hi" => base + 1_000 },
    );
}

// ── THE NEUTRAL PLANE-RECORD STORE (busbar 1.6.0) ─────────────────────────────────────────────
//
// busbar 1.6.0 replaced the per-protocol durable methods (`append_mcp_call`, `put_task`,
// `put_mcp_demotion`, `redeem_ask_state`, ...) with eight kind-tagged verbs over an opaque
// `PlaneRecord` envelope. Every property the per-protocol tests below used to pin is still owed —
// durability through a reconnect, ordering, enumeration, retention with a real count, fork refusal,
// byte-exact identity, the full u64 range — so each is re-pinned here through the verb that now
// carries it, with the kind string that used to be a method name.
//
// The property under test is never "the write returned Ok": the trait DEFAULTS every one of these
// verbs to accept-and-keep-nothing, so a write's return value is worthless as evidence of
// durability. The only honest proof is to READ IT BACK, and the only honest proof that it survives
// a deploy is to read it back on a NEW CONNECTION after the writing store is gone.

/// Every plane-record purge in this binary takes this ONE lock. `purge_plane_records_before` is
/// KIND-WIDE by contract (no namespace), so a purge test's cutoff sweeps every other test's rows of
/// that kind below it — including the conformance battery's. Only the purge tests and the two
/// conformance purge checks hold it; everything else writes above every cutoff used here and stays
/// parallel.
static PLANE_PURGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_plane_purge() -> std::sync::MutexGuard<'static, ()> {
    PLANE_PURGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Delete every row of `kind` under each identity (a `call` principal, a `task` id, a
/// `task_event`'s task, a `demotion` server) — this test's own rows and no one else's.
fn reset_plane(store: &MysqlStore, kind: &str, idents: &[&str]) {
    let mut conn = store.conn().expect("conn");
    for i in idents {
        conn.exec_drop(
            "DELETE FROM plane_records WHERE kind = :k AND ident = :i",
            params! { "k" => kind, "i" => *i },
        )
        .expect("clear this test's own plane rows");
    }
}

fn json_body(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("serialize a test body")
}

fn decode(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).expect("a body this suite wrote decodes")
}

// ── the `call` kind: the durable MCP tool-call log ─────────────────────────────────────────────

/// A `call` record in the envelope the engine writes: parent = the principal, keyed by `seq`, the
/// body a neutral journal body. Its `content` stands in for the plane's pre-framed digest suffix —
/// opaque to this store either way.
fn call_rec(principal: &str, seq: u64, ts: u64, prev_hash: &str, hash: &str) -> PlaneRecord {
    PlaneRecord {
        kind: "call".into(),
        id: principal.into(),
        parent: Some(principal.into()),
        seq,
        ts,
        disposition: PlaneDisposition::Active,
        body: json_body(serde_json::json!({
            "seq": seq,
            "prev_hash": prev_hash,
            "hash": hash,
            "content": format!("srv|srv_read_file|dispatched|sha256:tool{seq}|3"),
        })),
    }
}

fn calls_of(store: &MysqlStore, principal: &str) -> Vec<serde_json::Value> {
    store
        .list_plane_records("call", &PlaneSelector::Parent(principal.into()))
        .unwrap()
        .iter()
        .map(|b| decode(b))
        .collect()
}

/// THE TEST THAT MATTERS. A round-trip on one live handle cannot distinguish a backend that wrote
/// to the server from one holding a HashMap behind the same trait. So this DROPS the store —
/// closing its pool entirely — then connects a genuinely new one and verifies the per-principal
/// hash chain still links from the rows the server hands back.
#[test]
fn a_call_chain_survives_dropping_the_store_and_reconnecting() {
    let Some(url) = test_url() else { return };
    let p = "vk_mcp_restart";
    let written = [
        call_rec(p, 1, 2_000_000_100, "", "h1"),
        call_rec(p, 2, 2_000_000_200, "h1", "h2"),
        call_rec(p, 3, 2_000_000_300, "h2", "h3"),
    ];
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_plane(&store, "call", &[p]);
        for r in &written {
            store.append_plane_record(r.view()).unwrap();
        }
        drop(store);
    }

    // A genuinely new store and pool — nothing carried over in this process.
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let raw = reopened
        .list_plane_records("call", &PlaneSelector::Parent(p.into()))
        .unwrap();
    assert_eq!(
        raw.len(),
        3,
        "the call log must survive a reconnect; got {} records back, which is the \
         accept-and-keep-nothing behaviour this backend exists to replace",
        raw.len()
    );
    // The body is OPAQUE: it must come back BYTE-FOR-BYTE, not merely decode to the same value.
    for (got, want) in raw.iter().zip(written.iter()) {
        assert_eq!(got, &want.body, "a plane body must round-trip verbatim");
    }
    let got = calls_of(&reopened, p);
    assert_eq!(got[0]["prev_hash"], "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1]["prev_hash"], w[0]["hash"],
            "the per-principal chain must still link after a reconnect"
        );
    }
    assert_eq!(
        got.iter()
            .map(|r| r["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    reset_plane(&reopened, "call", &[p]);
}

/// The boot enumeration: a restart has to resume a chain for a principal this process has not yet
/// seen, so the store must be able to name every principal holding records.
#[test]
fn call_principals_are_enumerable_after_a_reconnect() {
    let Some(url) = test_url() else { return };
    let (a, b) = ("vk_mcp_enum_a", "vk_mcp_enum_b");
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_plane(&store, "call", &[a, b]);
        store
            .append_plane_record(call_rec(a, 1, 2_000_000_100, "", "a1").view())
            .unwrap();
        store
            .append_plane_record(call_rec(b, 1, 2_000_000_100, "", "b1").view())
            .unwrap();
        store
            .append_plane_record(call_rec(a, 2, 2_000_000_101, "a1", "a2").view())
            .unwrap();
        drop(store);
    }
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let principals = reopened.list_plane_record_parents("call").unwrap();
    for want in [a, b] {
        assert_eq!(
            principals.iter().filter(|p| p.as_str() == want).count(),
            1,
            "{want} must be enumerable after a reconnect, exactly once"
        );
    }
    // The chain scope is the principal: a scoped read returns only its own.
    assert_eq!(calls_of(&reopened, a).len(), 2);
    assert_eq!(calls_of(&reopened, b).len(), 1);
    assert!(
        calls_of(&reopened, "vk_mcp_nonexistent").is_empty(),
        "a principal with no records reads back empty, not an error"
    );
    // A kind is its own namespace: the call principals are not `task_event` parents.
    assert!(!reopened
        .list_plane_record_parents("task_event")
        .unwrap()
        .iter()
        .any(|p| p == a || p == b));
    reset_plane(&reopened, "call", &[a, b]);
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did
/// not perform is worse than one that reports nothing purged. The `call` kind drops ALL rows older
/// than the cutoff (no terminal-only rule), strictly less-than.
#[test]
fn purge_calls_before_deletes_and_returns_a_real_count() {
    let Some(url) = test_url() else { return };
    let _guard = lock_plane_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    let p = "vk_mcp_purge";
    reset_plane(&store, "call", &[p]);
    // Retention is KIND-WIDE by `ts`, so this test owns the low band under `PLANE_PURGE_LOCK` and
    // every other call test sits ABOVE the highest cutoff used here.
    store
        .append_plane_record(call_rec(p, 1, 1_000_000_100, "", "h1").view())
        .unwrap();
    store
        .append_plane_record(call_rec(p, 2, 1_000_000_200, "h1", "h2").view())
        .unwrap();
    store
        .append_plane_record(call_rec(p, 3, 1_000_000_300, "h2", "h3").view())
        .unwrap();

    let purged = store
        .purge_plane_records_before("call", 1_000_000_200)
        .unwrap();
    assert!(
        purged >= 1,
        "purge must report rows it actually removed; got {purged}"
    );
    assert_eq!(
        calls_of(&store, p)
            .iter()
            .map(|r| r["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![2, 3],
        "rows at or after the cutoff must remain — `before` is strictly less-than, so the row \
         exactly at the cutoff is kept"
    );
    let rest = store
        .purge_plane_records_before("call", 1_000_001_000)
        .unwrap();
    assert!(
        rest >= 2,
        "the remaining two rows must actually be removed; got {rest}"
    );
    assert!(calls_of(&store, p).is_empty());
}

/// A purge of one kind never touches another kind's rows, however old — retention is part of each
/// kind's contract, not a table-wide sweep.
#[test]
fn a_purge_is_confined_to_its_own_kind() {
    let Some(url) = test_url() else { return };
    let _guard = lock_plane_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    let (p, s) = ("vk_kind_confined", "srv_kind_confined");
    reset_plane(&store, "call", &[p]);
    reset_plane(&store, "demotion", &[s]);
    let mut demotion = demotion_rec(s, "tool-drift", 5);
    demotion.ts = 5;
    store.upsert_plane_record(demotion.view()).unwrap();
    store
        .append_plane_record(call_rec(p, 1, 5, "", "h1").view())
        .unwrap();
    store
        .purge_plane_records_before("call", 1_000_000_000)
        .unwrap();
    assert!(calls_of(&store, p).is_empty(), "the old call row is swept");
    assert!(
        demotion_servers(&store).contains(&s.to_string()),
        "a `call` purge must not reach a `demotion` row, however old"
    );
    reset_plane(&store, "demotion", &[s]);
}

/// A record arriving on a `(principal, seq)` that already has one is settled the way the contract
/// settles it: IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and is an
/// error. Overwriting would destroy the second case instead of reporting it.
#[test]
fn a_replayed_call_is_idempotent_but_a_forked_one_is_refused() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let p = "vk_mcp_replay";
    reset_plane(&store, "call", &[p]);

    let rec = call_rec(p, 1, 2_000_000_100, "", "h1");
    store.append_plane_record(rec.view()).unwrap();
    store
        .append_plane_record(rec.view())
        .expect("an identical replay is the at-least-once retry and must succeed");
    assert_eq!(
        calls_of(&store, p).len(),
        1,
        "a replay must not duplicate the row"
    );

    let forked = call_rec(p, 1, 2_000_000_100, "", "DIFFERENT");
    let err = store
        .append_plane_record(forked.view())
        .expect_err("a different record at an occupied (principal, seq) is a fork and must error");
    assert!(
        !format!("{err}").contains("DIFFERENT"),
        "the error must not echo stored or caller content back"
    );
    assert_eq!(
        calls_of(&store, p)[0]["hash"],
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    // Identical body, different envelope: a different `ts` at the same position is a fork too.
    let mut moved = rec.clone();
    moved.ts += 1;
    store
        .append_plane_record(moved.view())
        .expect_err("a record that differs only in its envelope is still a fork and must error");
    reset_plane(&store, "call", &[p]);
}

/// THE CROSS-PRINCIPAL READ. The identity column is half of the PRIMARY KEY and the only predicate
/// a scoped read filters on, and this schema's default collation is `utf8mb4_0900_ai_ci` — case- AND
/// accent-insensitive. Under that collation two key ids differing only in case are the SAME key: one
/// principal's read hands back another principal's tool-call evidence, and the second principal's
/// first append collides and is reported as a "fork" of a chain it never wrote. `utf8mb4_bin` on the
/// key columns is what stops it.
#[test]
fn principals_differing_only_in_case_are_distinct_chains() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let (lower, upper) = ("vk_mcp_case_variant", "VK_MCP_CASE_VARIANT");
    reset_plane(&store, "call", &[lower, upper]);

    store
        .append_plane_record(call_rec(lower, 1, 2_000_000_100, "", "lower1").view())
        .unwrap();
    store
        .append_plane_record(call_rec(upper, 1, 2_000_000_100, "", "upper1").view())
        .expect(
            "a case-different principal is a DIFFERENT caller opening its own chain, never a fork \
             of the first caller's",
        );

    let a = calls_of(&store, lower);
    let b = calls_of(&store, upper);
    assert_eq!(
        a.len(),
        1,
        "a scoped read returns this principal's records and no other's"
    );
    assert_eq!(b.len(), 1);
    assert_eq!(
        a[0]["hash"], "lower1",
        "an exact-match read must not case-fold"
    );
    assert_eq!(b[0]["hash"], "upper1");

    let principals = store.list_plane_record_parents("call").unwrap();
    for want in [lower, upper] {
        assert_eq!(
            principals.iter().filter(|p| p.as_str() == want).count(),
            1,
            "{want} must be enumerated in its own right, not collapsed into its case variant"
        );
    }
    reset_plane(&store, "call", &[lower, upper]);
}

// ── the `task` / `task_event` kinds: the durable A2A task store ────────────────────────────────
//
// A2A is async by design: a task spans turns, can sit interrupted waiting on a human, and can
// outlive the process that started it. The only honest proof of a durable task store is to READ
// THE TASK BACK THROUGH A RESTART.

/// Timestamps are BANDED. Retention is KIND-WIDE, so everything below the top of this band belongs
/// to the purge tests (under `PLANE_PURGE_LOCK`) and every other task test writes ABOVE it.
const TASK_PURGE_BAND_TOP: u64 = 1_000_100_000;
const TASK_LIVE_TS: u64 = 2_000_000_000;

/// A `task` record in the envelope the engine writes: upsert by id, `ts` = the task's `updated_at`,
/// the terminal/active verdict on the typed `disposition` — the ENGINE decides it; the store only
/// reads the column.
fn task_rec(
    task_id: &str,
    state: &str,
    updated_at: u64,
    disposition: PlaneDisposition,
) -> PlaneRecord {
    PlaneRecord {
        kind: "task".into(),
        id: task_id.into(),
        parent: None,
        seq: 0,
        ts: updated_at,
        disposition,
        body: json_body(serde_json::json!({
            "task_id": task_id,
            "context_id": format!("ctx-{task_id}"),
            "principal": "vk_a",
            "direction": "inbound",
            "state": state,
            "agent_id": "planner",
            "artifact_cursor": 7,
            "push_callback": "https://example.test/push",
            "created_at": 100,
            "updated_at": updated_at,
        })),
    }
}

fn active_task(task_id: &str, state: &str, updated_at: u64) -> PlaneRecord {
    task_rec(task_id, state, updated_at, PlaneDisposition::Active)
}

fn terminal_task(task_id: &str, state: &str, updated_at: u64) -> PlaneRecord {
    task_rec(task_id, state, updated_at, PlaneDisposition::Terminal)
}

fn event_rec(task_id: &str, seq: u64, kind: &str, prev_hash: &str, hash: &str) -> PlaneRecord {
    // Saturating: the full-range test deliberately passes `u64::MAX` as `seq`.
    let ts = seq.saturating_add(TASK_LIVE_TS);
    PlaneRecord {
        kind: "task_event".into(),
        id: task_id.into(),
        parent: Some(task_id.into()),
        seq,
        ts,
        disposition: PlaneDisposition::Active,
        body: json_body(serde_json::json!({
            "task_id": task_id,
            "seq": seq,
            "ts": ts,
            "kind": kind,
            "context_id": format!("ctx-{task_id}"),
            "principal": "vk_a",
            "agent_id": "planner",
            "state": "working",
            "request_id": format!("req-{seq}"),
            "prev_hash": prev_hash,
            "hash": hash,
        })),
    }
}

fn get_task(store: &MysqlStore, id: &str) -> Option<serde_json::Value> {
    store
        .get_plane_record("task", id)
        .unwrap()
        .map(|b| decode(&b))
}

fn events_of(store: &MysqlStore, task_id: &str) -> Vec<serde_json::Value> {
    store
        .list_plane_records("task_event", &PlaneSelector::Parent(task_id.into()))
        .unwrap()
        .iter()
        .map(|b| decode(b))
        .collect()
}

fn all_task_ids(store: &MysqlStore) -> Vec<String> {
    store
        .list_plane_records("task", &PlaneSelector::All)
        .unwrap()
        .iter()
        .filter_map(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .filter_map(|v| v["task_id"].as_str().map(str::to_string))
        .collect()
}

fn reset_tasks(store: &MysqlStore, task_ids: &[&str]) {
    reset_plane(store, "task_event", task_ids);
    reset_plane(store, "task", task_ids);
}

#[test]
fn an_in_flight_task_survives_dropping_the_store_and_reconnecting() {
    let Some(url) = test_url() else { return };
    let (t1, t2) = ("t_restart_1", "t_restart_2");
    let interrupted = active_task(t1, "input-required", TASK_LIVE_TS + 300);
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tasks(&store, &[t1, t2]);
        store
            .upsert_plane_record(active_task(t1, "working", TASK_LIVE_TS + 200).view())
            .unwrap();
        // The write-through on a state transition REPLACES the row rather than appending a second
        // one — an interrupted task waiting on a human is what a restart has to find.
        store.upsert_plane_record(interrupted.view()).unwrap();
        store
            .upsert_plane_record(active_task(t2, "submitted", TASK_LIVE_TS + 210).view())
            .unwrap();
        drop(store);
    }

    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let got = reopened.get_plane_record("task", t1).unwrap().expect(
        "an in-flight task must survive a restart; got None back after reconnecting, which is the \
         accept-and-keep-nothing default this backend exists to replace",
    );
    assert_eq!(
        got, interrupted.body,
        "the LAST write must win, and its body must come back byte-for-byte"
    );

    // UPSERT, not append: two writes for one id leave ONE row.
    let mine: Vec<String> = all_task_ids(&reopened)
        .into_iter()
        .filter(|id| id == t1 || id == t2)
        .collect();
    assert_eq!(
        mine.iter().filter(|id| id.as_str() == t1).count(),
        1,
        "an upsert replaces; a second write for the same id must never append: {mine:?}"
    );
    assert!(mine.iter().any(|id| id == t2));

    assert!(
        reopened
            .get_plane_record("task", "t_nonexistent_task")
            .unwrap()
            .is_none(),
        "an unknown task id reads back None, not an error"
    );
    // A kind is its own namespace: the same id under another kind is not this task.
    assert!(reopened.get_plane_record("demotion", t1).unwrap().is_none());
    reset_tasks(&reopened, &[t1, t2]);
}

/// `list_plane_records(All)` is deliberately UNFILTERED. The boot rehydrate wants the active rows,
/// the retention sweep wants the terminal ones and the scoped listing wants one principal's; a store
/// that pre-filtered for any one of those would break the other two.
#[test]
fn listing_tasks_returns_every_row_including_terminal_ones_after_a_reconnect() {
    let Some(url) = test_url() else { return };
    let ids = [
        "t_list_active",
        "t_list_waiting",
        "t_list_done",
        "t_list_failed",
    ];
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tasks(&store, &ids);
        store
            .upsert_plane_record(active_task(ids[0], "working", TASK_LIVE_TS + 200).view())
            .unwrap();
        store
            .upsert_plane_record(active_task(ids[1], "input-required", TASK_LIVE_TS + 201).view())
            .unwrap();
        store
            .upsert_plane_record(terminal_task(ids[2], "completed", TASK_LIVE_TS + 202).view())
            .unwrap();
        store
            .upsert_plane_record(terminal_task(ids[3], "failed", TASK_LIVE_TS + 203).view())
            .unwrap();
        drop(store);
    }
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let mut mine: Vec<String> = all_task_ids(&reopened)
        .into_iter()
        .filter(|id| ids.contains(&id.as_str()))
        .collect();
    mine.sort();
    let mut want: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(
        mine, want,
        "the task listing is unfiltered: terminal rows are returned too, and every row survives a \
         reconnect"
    );
    reset_tasks(&reopened, &ids);
}

/// The per-task provenance chain, read back off the server after a reconnect. Per-TASK rather than
/// one global chain, so the scope of a read is one task and the links have to hold within it.
///
/// It never writes the task itself, deliberately: a `task.submitted` event and the first task upsert
/// are two independent write-throughs with no stated order, so appending an event for a task with
/// no row yet has to WORK — which is why the schema carries no foreign key between them.
#[test]
fn a_task_event_chain_survives_a_reconnect_and_still_links() {
    let Some(url) = test_url() else { return };
    let (t1, t2) = ("t_chain_1", "t_chain_2");
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tasks(&store, &[t1, t2]);
        // Appended OUT of order: the read must come back by `seq`, not by insertion.
        store
            .append_plane_record(event_rec(t1, 2, "task.working", "e1", "e2").view())
            .unwrap();
        store
            .append_plane_record(event_rec(t1, 1, "task.submitted", "", "e1").view())
            .unwrap();
        store
            .append_plane_record(event_rec(t1, 3, "task.interrupted", "e2", "e3").view())
            .unwrap();
        // A second task's chain is independent — it must not leak into the first one's read.
        store
            .append_plane_record(event_rec(t2, 1, "task.submitted", "", "f1").view())
            .unwrap();
        drop(store);
    }
    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let got = events_of(&reopened, t1);
    assert_eq!(
        got.len(),
        3,
        "the provenance chain must survive a reconnect; got {} events back",
        got.len()
    );
    assert_eq!(
        got.iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "oldest-first by seq, which is the order the chain verifier reads"
    );
    assert_eq!(got[0]["prev_hash"], "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1]["prev_hash"], w[0]["hash"],
            "the per-task chain must still link"
        );
    }
    assert_eq!(got[2]["kind"], "task.interrupted");
    assert_eq!(got[2]["request_id"], "req-3");
    assert_eq!(
        events_of(&reopened, t2).len(),
        1,
        "the scope of a read is one task"
    );
    assert!(
        events_of(&reopened, "t_unknown_chain").is_empty(),
        "a task with no events reads back empty, not an error"
    );
    reset_tasks(&reopened, &[t1, t2]);
}

/// A replayed `(task_id, seq)` is settled like every other append: IDENTICAL is the at-least-once
/// retry and succeeds without duplicating the row; DIFFERENT is refused as a fork and the stored
/// record stands.
///
/// BEHAVIOUR CHANGE from the pre-1.6.0 `append_task_event`, which UPSERTED a rewritten event over
/// the stored one. busbar 1.6.0 carries task events through the one neutral `append_plane_record`,
/// whose contract is an APPEND that "never recomputes any digest", and busbar's reference stores
/// (store-memory, store-example-plugin) refuse a DIFFERENT record at an occupied position for every
/// appended kind. Silently replacing a sealed chain link is the tamper shape the chain exists to
/// expose, so this backend now refuses it too.
#[test]
fn a_replayed_task_event_is_idempotent_but_a_rewritten_one_is_refused() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let t = "t_replay_event";
    reset_tasks(&store, &[t]);

    let e = event_rec(t, 1, "task.submitted", "", "e1");
    store.append_plane_record(e.view()).unwrap();
    store
        .append_plane_record(e.view())
        .expect("an identical replay must succeed, not be rejected as a fork");
    assert_eq!(
        events_of(&store, t).len(),
        1,
        "a replay must not duplicate the row"
    );

    let rewritten = event_rec(t, 1, "task.submitted", "", "e1-rewritten");
    store
        .append_plane_record(rewritten.view())
        .expect_err("a DIFFERENT event at an occupied (task, seq) is a fork and must be refused");
    let got = events_of(&store, t);
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0]["hash"], "e1",
        "the refused rewrite must not replace the stored link"
    );
    reset_tasks(&store, &[t]);
}

/// The band the purge tests own, cleared wholesale. Safe only under `PLANE_PURGE_LOCK`, and correct
/// only because every non-purge task test writes above `TASK_PURGE_BAND_TOP`.
fn clear_purge_band(store: &MysqlStore) {
    let mut conn = store.conn().expect("conn");
    conn.exec_drop(
        "DELETE ev FROM plane_records ev JOIN plane_records t \
           ON ev.kind = 'task_event' AND ev.ident = t.ident \
         WHERE t.kind = 'task' AND t.ts < :top",
        params! { "top" => TASK_PURGE_BAND_TOP },
    )
    .expect("clear the purge band's events");
    conn.exec_drop(
        "DELETE FROM plane_records WHERE kind = 'task' AND ts < :top",
        params! { "top" => TASK_PURGE_BAND_TOP },
    )
    .expect("clear the purge band");
}

/// Retention drops TERMINAL rows only, strictly older than the cutoff, and returns a count it
/// actually performed. An interrupted task waiting on a human is exactly the row that legitimately
/// sits still for a long time; compacting it is losing the work, not reclaiming space.
///
/// Terminality is the envelope's typed `disposition`, decided by the engine. The store reads THAT
/// COLUMN and never the body: the `t_purge_old_body_says_completed` row carries a body whose state
/// reads `completed` under an ACTIVE disposition, and it must survive — a backend that decoded the
/// body to decide would sweep it.
#[test]
fn purge_tasks_before_drops_only_terminal_rows_and_returns_a_real_count() {
    let Some(url) = test_url() else { return };
    let _guard = lock_plane_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    clear_purge_band(&store);

    let old = 1_000_000_100;
    for state in ["completed", "failed", "canceled", "rejected"] {
        store
            .upsert_plane_record(terminal_task(&format!("t_purge_old_{state}"), state, old).view())
            .unwrap();
    }
    for state in ["input-required", "auth-required", "working", "submitted"] {
        store
            .upsert_plane_record(active_task(&format!("t_purge_old_{state}"), state, old).view())
            .unwrap();
    }
    store
        .upsert_plane_record(
            active_task("t_purge_old_body_says_completed", "completed", old).view(),
        )
        .unwrap();
    // Terminal but at the cutoff exactly, and terminal but newer — both kept.
    store
        .upsert_plane_record(terminal_task("t_purge_at_cutoff", "completed", 1_000_000_200).view())
        .unwrap();
    store
        .upsert_plane_record(terminal_task("t_purge_newer", "completed", 1_000_000_300).view())
        .unwrap();

    let purged = store
        .purge_plane_records_before("task", 1_000_000_200)
        .unwrap();
    assert_eq!(
        purged, 4,
        "only the four TERMINAL rows strictly older than the cutoff go, and the count must be one \
         actually performed rather than a guess"
    );
    let mut left: Vec<String> = all_task_ids(&store)
        .into_iter()
        .filter(|id| id.starts_with("t_purge_"))
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec![
            "t_purge_at_cutoff",
            "t_purge_newer",
            "t_purge_old_auth-required",
            "t_purge_old_body_says_completed",
            "t_purge_old_input-required",
            "t_purge_old_submitted",
            "t_purge_old_working",
        ],
        "an active or interrupted task is never dropped by retention, the store decides by the \
         typed disposition and never by decoding the body, and `before` is strictly less-than so a \
         row exactly at the cutoff is kept"
    );
    assert_eq!(
        store
            .purge_plane_records_before("task", 1_000_000_200)
            .unwrap(),
        0,
        "re-running the same purge removes nothing"
    );
    clear_purge_band(&store);
}

/// Retention has to bound the EVENT chain too. Nothing else ever purges a `task_event` row, so if
/// purging a task left its provenance behind the chains would grow without any bound the contract
/// provides a way to apply. Dropping a task therefore drops the chain that belongs to it — and
/// drops nothing belonging to any other task.
#[test]
fn purging_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let Some(url) = test_url() else { return };
    let _guard = lock_plane_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    clear_purge_band(&store);

    let (gone, stays) = ("t_cascade_gone", "t_cascade_stays");
    reset_tasks(&store, &[gone, stays]);
    store
        .upsert_plane_record(terminal_task(gone, "completed", 1_000_000_100).view())
        .unwrap();
    store
        .upsert_plane_record(active_task(stays, "working", 1_000_000_100).view())
        .unwrap();
    store
        .append_plane_record(event_rec(gone, 1, "task.submitted", "", "g1").view())
        .unwrap();
    store
        .append_plane_record(event_rec(gone, 2, "task.completed", "g1", "g2").view())
        .unwrap();
    store
        .append_plane_record(event_rec(stays, 1, "task.submitted", "", "s1").view())
        .unwrap();

    assert_eq!(
        store
            .purge_plane_records_before("task", 1_000_000_200)
            .unwrap(),
        1,
        "exactly the one terminal task in this band is swept, and the count must be one actually \
         performed — 0 here is the accept-and-keep-nothing default this backend exists to replace"
    );
    assert!(
        events_of(&store, gone).is_empty(),
        "the purged task's events go with it; otherwise the chain grows unbounded"
    );
    assert_eq!(
        events_of(&store, stays).len(),
        1,
        "another task's chain must be untouched by that purge"
    );
    reset_tasks(&store, &[gone, stays]);
    clear_purge_band(&store);
}

/// Every `u64` of the envelope round-trips at the FULL range, `u64::MAX` included — `seq` and `ts`
/// are BIGINT UNSIGNED like every other u64 in this store, so there is no value the contract can
/// hand this backend that it has to refuse or silently mangle.
#[test]
fn the_plane_store_round_trips_the_full_u64_range() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let t = "t_full_range";
    reset_tasks(&store, &[t]);

    let task = active_task(t, "working", u64::MAX);
    store
        .upsert_plane_record(task.view())
        .expect("BIGINT UNSIGNED holds the whole u64 range; nothing here needs refusing");
    let got = get_task(&store, t).expect("the task must read back at all");
    assert_eq!(got["updated_at"].as_u64(), Some(u64::MAX));
    assert!(
        all_task_ids(&store).contains(&t.to_string()),
        "a u64::MAX ts must not break the listing"
    );

    let mut ev = event_rec(t, u64::MAX, "task.submitted", "", "e1");
    ev.ts = u64::MAX;
    store
        .append_plane_record(ev.view())
        .expect("seq/ts hold u64::MAX");
    let events = events_of(&store, t);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["seq"].as_u64(), Some(u64::MAX));
    // And the identical replay at that position is still recognised as identical — a column that
    // wrapped would read back as a different `ts` and report a fork.
    store
        .append_plane_record(ev.view())
        .expect("the replay at u64::MAX must compare identical");
    reset_tasks(&store, &[t]);
}

/// Two task ids differing only in CASE are two different tasks, and the primary key has to agree.
/// Under this schema's default collation they compare EQUAL, so the second upsert would land on the
/// first one's row and one of the two tasks would simply be gone — silently, with the write
/// reporting success.
#[test]
fn task_ids_differing_only_in_case_are_distinct_tasks() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let (lower, upper) = ("t_case_variant", "T_CASE_VARIANT");
    reset_tasks(&store, &[lower, upper]);

    store
        .upsert_plane_record(active_task(lower, "working", TASK_LIVE_TS + 1).view())
        .unwrap();
    store
        .upsert_plane_record(terminal_task(upper, "completed", TASK_LIVE_TS + 2).view())
        .expect("a case-different id is a different task, not an upsert onto the first");
    let a = get_task(&store, lower).expect("the lower-case task");
    let b = get_task(&store, upper).expect("the upper-case task");
    assert_eq!(
        a["task_id"], lower,
        "an exact-match lookup must not case-fold"
    );
    assert_eq!(b["task_id"], upper);
    assert_eq!(
        a["state"], "working",
        "the second upsert must not have overwritten the first task's row"
    );

    store
        .append_plane_record(event_rec(lower, 1, "task.submitted", "", "l1").view())
        .unwrap();
    store
        .append_plane_record(event_rec(upper, 1, "task.submitted", "", "u1").view())
        .unwrap();
    assert_eq!(events_of(&store, lower)[0]["hash"], "l1");
    assert_eq!(
        events_of(&store, upper)[0]["hash"],
        "u1",
        "a case-different task id is a different chain, not the same (task, seq) slot"
    );
    reset_tasks(&store, &[lower, upper]);
}

// ── the `demotion` kind and the single-use token ledger ────────────────────────────────────────
//
// Both are security state, and both arrived with the same hole: the trait defaults the neutral
// verbs to accept-and-keep-nothing, so a backend that implements neither compiles, ships and reports
// every write successful while discarding it. What that costs is a quarantined upstream that gets
// the operator's approval back at the next restart, and a single-use human approval that a second
// node of the fleet redeems again.

/// THE LIVE URL, OR A FAILURE. Deliberately NOT `test_url()`, whose `None` arm lets a case return
/// green having tested nothing: an unimplemented ledger and a test that never ran produce the same
/// green, and these are exactly the two properties where that costs an operator something.
fn require_test_url() -> String {
    std::env::var("BUSBAR_TEST_MYSQL_URL").unwrap_or_else(|_| {
        panic!(
            "BUSBAR_TEST_MYSQL_URL is unset. These cases are the ONLY coverage of the durable MCP \
             demotion record and the single-use token ledger on this backend, and both fail \
             SILENTLY when unimplemented — the trait defaults accept a demotion and keep nothing. \
             Skipping them reports green over a quarantined upstream that comes back approved and \
             an approval that is redeemable once per node. Point this at a live MySQL, e.g. \
             mysql://busbar:busbar@127.0.0.1:3307/busbar_test"
        )
    })
}

/// Per-process namespacing. This suite runs against a SHARED MySQL, so a fixed key would have two
/// concurrent runs redeeming each other's approvals and reading each other's demotions.
fn trust_ns(tag: &str) -> String {
    format!("{}_{}", tag, std::process::id())
}

/// The ledger's eviction sweep is GLOBAL (`expires_at < now`, every kind), so the redemptions in
/// this binary are placed where no sweep reaches another test's live token: every `now` below stays
/// under `TRUST_NOW + 11`, and every token this file keeps live expires at or after `TRUST_NOW + 900`
/// — both below the conformance battery's own expiry (`2_000_000_000`) and above its `now`
/// (`1_700_000_000`), so the battery and these cases can never sweep each other's rows mid-check.
const TRUST_NOW: u64 = 1_999_990_000;

fn demotion_rec(server: &str, reason: &str, recorded_at: u64) -> PlaneRecord {
    PlaneRecord {
        kind: "demotion".into(),
        id: server.into(),
        parent: None,
        seq: 0,
        ts: recorded_at,
        disposition: PlaneDisposition::Active,
        body: json_body(serde_json::json!({
            "server": server, "reason": reason, "recorded_at": recorded_at,
        })),
    }
}

fn demotions(store: &MysqlStore) -> Vec<serde_json::Value> {
    store
        .list_plane_records("demotion", &PlaneSelector::All)
        .unwrap()
        .iter()
        .map(|b| decode(b))
        .collect()
}

fn demotion_servers(store: &MysqlStore) -> Vec<String> {
    demotions(store)
        .iter()
        .filter_map(|d| d["server"].as_str().map(str::to_string))
        .collect()
}

fn reset_tokens(store: &MysqlStore, kind: &str, tokens: &[&str]) {
    let mut conn = store.conn().expect("conn");
    for t in tokens {
        conn.exec_drop(
            "DELETE FROM plane_tokens WHERE kind = :k AND token = :t",
            params! { "k" => kind, "t" => *t },
        )
        .expect("clear this test's own ledger rows");
    }
}

/// A DEMOTION OUTLIVES THE PROCESS THAT RECORDED IT. Without this row on the server, a restart
/// hands a quarantined upstream its approval back.
#[test]
fn a_demotion_survives_dropping_the_store_and_reconnecting() {
    let url = require_test_url();
    let (a, b, c) = (
        trust_ns("srv_payments"),
        trust_ns("srv_search"),
        trust_ns("srv_mail"),
    );
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_plane(&store, "demotion", &[&a, &b, &c]);
        store
            .upsert_plane_record(demotion_rec(&a, "tool-drift", TRUST_NOW).view())
            .unwrap();
        // UPSERT by server: a second demotion of one upstream REPLACES the row rather than standing
        // a rival one beside it, so the boot read cannot hold two answers about one server.
        store
            .upsert_plane_record(demotion_rec(&a, "digest-mismatch", TRUST_NOW + 10).view())
            .unwrap();
        store
            .upsert_plane_record(demotion_rec(&b, "tool-drift", TRUST_NOW + 20).view())
            .unwrap();
        store
            .upsert_plane_record(demotion_rec(&c, "tool-drift", TRUST_NOW + 30).view())
            .unwrap();
        store
            .delete_plane_record("demotion", &c)
            .expect("a later observation that agrees with the approval clears the quarantine");
        store
            .delete_plane_record("demotion", &trust_ns("srv_never_demoted"))
            .expect("clearing a row that is not there is a no-op, not an error");
        drop(store);
    }

    let reopened = MysqlStore::connect(&url).expect("reconnect");
    let mut mine: Vec<serde_json::Value> = demotions(&reopened)
        .into_iter()
        .filter(|d| {
            d["server"] == a.as_str() || d["server"] == b.as_str() || d["server"] == c.as_str()
        })
        .collect();
    mine.sort_by(|x, y| x["server"].as_str().cmp(&y["server"].as_str()));
    let mut expect = vec![
        decode(&demotion_rec(&a, "digest-mismatch", TRUST_NOW + 10).body),
        decode(&demotion_rec(&b, "tool-drift", TRUST_NOW + 20).body),
    ];
    expect.sort_by(|x, y| x["server"].as_str().cmp(&y["server"].as_str()));
    assert_eq!(
        mine, expect,
        "the boot read must put every recorded quarantine back in force — upserted to the LATEST \
         reason, and WITHOUT the one a later agreeing observation cleared"
    );
    reset_plane(&reopened, "demotion", &[&a, &b, &c]);
}

/// SERVER IDS DIFFERING ONLY IN CASE ARE DISTINCT UPSTREAMS: quarantining one must not overwrite
/// the other's record, and clearing one must not clear both.
#[test]
fn servers_differing_only_in_case_are_distinct_demotions() {
    let url = require_test_url();
    let (lower, upper) = (trust_ns("srv_case"), trust_ns("srv_CASE"));
    let store = MysqlStore::connect(&url).expect("connect");
    reset_plane(&store, "demotion", &[&lower, &upper]);

    store
        .upsert_plane_record(demotion_rec(&lower, "tool-drift", TRUST_NOW).view())
        .unwrap();
    store
        .upsert_plane_record(demotion_rec(&upper, "digest-mismatch", TRUST_NOW + 1).view())
        .unwrap();
    let servers = demotion_servers(&store);
    assert_eq!(
        servers
            .iter()
            .filter(|s| **s == lower || **s == upper)
            .count(),
        2,
        "two upstreams whose ids differ only in case are two upstreams"
    );
    store.delete_plane_record("demotion", &lower).unwrap();
    assert!(
        demotion_servers(&store).contains(&upper),
        "clearing one upstream's quarantine must not lift another's"
    );
    reset_plane(&store, "demotion", &[&lower, &upper]);
}

/// THE SPENT-APPROVAL LEDGER ACROSS A RESTART. The seal that carries a single-use approval is valid
/// bytes on its second presentation exactly as on its first; only a record that the first happened
/// tells them apart.
#[test]
fn a_reconnected_store_refuses_a_second_redemption_of_the_same_approval() {
    let url = require_test_url();
    let (spent, fresh) = (trust_ns("nonce_restart"), trust_ns("nonce_restart_other"));
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tokens(&store, "ask", &[&spent, &fresh]);
        assert!(
            store
                .redeem_plane_token("ask", &spent, TRUST_NOW + 900, TRUST_NOW)
                .unwrap(),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        drop(store);
    }

    let reopened = MysqlStore::connect(&url).expect("reconnect");
    assert!(
        !reopened
            .redeem_plane_token("ask", &spent, TRUST_NOW + 900, TRUST_NOW + 1)
            .unwrap(),
        "a restart handed a spent approval back. The approval has not lapsed, so the only thing \
         that changed is that the process which recorded the redemption is gone"
    );
    // THE CONTROL: a ledger that refused everything would satisfy the case above.
    assert!(
        reopened
            .redeem_plane_token("ask", &fresh, TRUST_NOW + 900, TRUST_NOW + 2)
            .unwrap(),
        "a different approval is not the one that was spent"
    );
    // The ledger is keyed by KIND as well: the same token string under another single-use kind is a
    // different capability, never one another kind already spent.
    assert!(
        reopened
            .redeem_plane_token("ask_other_kind", &spent, TRUST_NOW + 900, TRUST_NOW + 2)
            .unwrap(),
        "a token spent under one kind must not read as spent under another"
    );
    reset_tokens(&reopened, "ask", &[&spent, &fresh]);
    reset_tokens(&reopened, "ask_other_kind", &[&spent]);
}

/// TWO CONNECTIONS ARE TWO NODES OF A FLEET, and this is the arrangement the durable ledger exists
/// for: the second redemption needs no timing skill at all, only a load balancer.
#[test]
fn a_second_node_cannot_redeem_an_approval_the_first_already_spent() {
    let url = require_test_url();
    let nonce = trust_ns("nonce_fleet");
    let node_a = MysqlStore::connect(&url).expect("node A connects");
    let node_b = MysqlStore::connect(&url).expect("node B connects");
    reset_tokens(&node_a, "ask", &[&nonce]);

    assert!(node_a
        .redeem_plane_token("ask", &nonce, TRUST_NOW + 900, TRUST_NOW)
        .unwrap());
    assert!(
        !node_b
            .redeem_plane_token("ask", &nonce, TRUST_NOW + 900, TRUST_NOW)
            .unwrap(),
        "a second node of the same deployment redeemed an approval the first already spent"
    );
    reset_tokens(&node_a, "ask", &[&nonce]);
}

/// NONCES DIFFERING ONLY IN CASE ARE DISTINCT APPROVALS — the sharpest instance of the collation
/// hazard: under a case-insensitive key a fresh approval would be REFUSED.
#[test]
fn nonces_differing_only_in_case_are_distinct_approvals() {
    let url = require_test_url();
    let (lower, upper) = (trust_ns("nonce_case_ab"), trust_ns("nonce_case_AB"));
    let store = MysqlStore::connect(&url).expect("connect");
    reset_tokens(&store, "ask", &[&lower, &upper]);

    assert!(store
        .redeem_plane_token("ask", &lower, TRUST_NOW + 900, TRUST_NOW)
        .unwrap());
    assert!(
        store
            .redeem_plane_token("ask", &upper, TRUST_NOW + 900, TRUST_NOW)
            .unwrap(),
        "an approval whose nonce differs only in case from a spent one is a DIFFERENT approval"
    );
    reset_tokens(&store, "ask", &[&lower, &upper]);
}

/// CONCURRENT REDEMPTION IS THE ATTACK, not the corner case. Eight independent CONNECTIONS race on
/// one approval through a barrier — the arrangement a read-then-write implementation answers
/// "first" to eight times. Exactly one may win.
#[test]
fn exactly_one_of_many_racing_nodes_wins_the_redemption() {
    let url = require_test_url();
    let nonce = trust_ns("nonce_race");
    let cleanup = MysqlStore::connect(&url).expect("connect");
    reset_tokens(&cleanup, "ask", &[&nonce]);
    drop(cleanup);

    let n = 8usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let winners: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let url = url.clone();
                let nonce = nonce.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    let node = MysqlStore::connect(&url).expect("a racing node connects");
                    barrier.wait();
                    node.redeem_plane_token("ask", &nonce, TRUST_NOW + 900, TRUST_NOW)
                        .expect("redeem_plane_token") as usize
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });

    assert_eq!(
        winners, 1,
        "exactly one redemption of one approval may be the first; {winners} nodes were each told \
         they were"
    );
    let cleanup = MysqlStore::connect(&url).expect("connect");
    reset_tokens(&cleanup, "ask", &[&nonce]);
}

/// THE LEDGER IS BOUNDED BY ONE VALIDITY WINDOW: `now` is handed to every redemption so the backend
/// drops what has lapsed in the same call.
#[test]
fn redeeming_evicts_entries_whose_token_can_no_longer_be_presented() {
    let url = require_test_url();
    let (short, long, other) = (
        trust_ns("nonce_short"),
        trust_ns("nonce_long"),
        trust_ns("nonce_sweeper"),
    );
    let store = MysqlStore::connect(&url).expect("connect");
    reset_tokens(&store, "ask", &[&short, &long, &other]);

    assert!(store
        .redeem_plane_token("ask", &short, TRUST_NOW + 10, TRUST_NOW)
        .unwrap());
    assert!(store
        .redeem_plane_token("ask", &long, TRUST_NOW + 10_000, TRUST_NOW)
        .unwrap());

    let later = TRUST_NOW + 11;
    assert!(store
        .redeem_plane_token("ask", &other, later + 900, later)
        .unwrap());

    let present = |nonce: &str| -> bool {
        let mut conn = store.conn().expect("conn");
        let n: Option<u64> = conn
            .exec_first(
                "SELECT COUNT(*) FROM plane_tokens WHERE kind = 'ask' AND token = :n",
                params! { "n" => nonce },
            )
            .expect("count the ledger row");
        n.unwrap_or(0) > 0
    };
    assert!(
        !present(&short),
        "the entry whose token can no longer be presented must be evicted by the sweep"
    );
    assert!(
        present(&long),
        "a token still inside its window must NOT be swept — evicting it early is exactly the \
         double redemption this ledger exists to refuse"
    );
    reset_tokens(&store, "ask", &[&short, &long, &other]);
}

/// THE FULL u64 RANGE STORES FAITHFULLY. A clamped or wrapped `now` would be a security bug rather
/// than a rounding one: clamped high it sweeps the ENTIRE ledger and reports a replay as first.
#[test]
fn the_trust_state_stores_the_full_unsigned_range() {
    let url = require_test_url();
    let (server, nonce) = (trust_ns("srv_range"), trust_ns("nonce_range"));
    let store = MysqlStore::connect(&url).expect("connect");
    reset_plane(&store, "demotion", &[&server]);
    reset_tokens(&store, "ask", &[&nonce]);

    store
        .upsert_plane_record(demotion_rec(&server, "tool-drift", u64::MAX).view())
        .expect("BIGINT UNSIGNED holds the whole u64 range");
    assert_eq!(
        demotions(&store)
            .into_iter()
            .find(|d| d["server"] == server.as_str())
            .expect("the row must be there")["recorded_at"]
            .as_u64(),
        Some(u64::MAX)
    );
    assert!(
        store
            .redeem_plane_token("ask", &nonce, u64::MAX, TRUST_NOW)
            .unwrap(),
        "an expires_at at the top of the range is storable here and must redeem normally"
    );
    assert!(
        !store
            .redeem_plane_token("ask", &nonce, u64::MAX, TRUST_NOW + 1)
            .unwrap(),
        "and the row it wrote must still be found on the replay"
    );
    reset_plane(&store, "demotion", &[&server]);
    reset_tokens(&store, "ask", &[&nonce]);
}

// ── plane_token_live: the multi-use capability (kind `push_config`) ─────────────────────────────

fn push_config(id: &str, disposition: PlaneDisposition) -> PlaneRecord {
    PlaneRecord {
        kind: "push_config".into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts: TASK_LIVE_TS,
        disposition,
        body: json_body(serde_json::json!({ "task_id": id, "url": "https://example.test/cb" })),
    }
}

/// LIVE means all three: present, still ACTIVE, and inside its deadline. It SPENDS NOTHING — asking
/// twice answers the same twice, which is what makes it usable for the several callbacks one task
/// legitimately receives — and it dies the moment the write that made the task terminal flips the
/// row, or the deadline passes. Every failing leg answers `false`: fail-closed.
#[test]
fn plane_token_live_carries_a_task_and_dies_with_it() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let id = &trust_ns("push_live");
    reset_plane(&store, "push_config", &[id]);
    let deadline = TASK_LIVE_TS + 1_000;

    assert!(
        !store
            .plane_token_live("push_config", id, deadline, TASK_LIVE_TS)
            .unwrap(),
        "an unknown token holds no capability"
    );
    store
        .upsert_plane_record(push_config(id, PlaneDisposition::Active).view())
        .unwrap();
    for _ in 0..2 {
        assert!(
            store
                .plane_token_live("push_config", id, deadline, TASK_LIVE_TS)
                .unwrap(),
            "a present, active token inside its deadline is live — and asking again spends nothing"
        );
    }
    assert!(
        store
            .plane_token_live("push_config", id, deadline, deadline)
            .unwrap(),
        "`now` AT the deadline has not passed it"
    );
    assert!(
        !store
            .plane_token_live("push_config", id, deadline, deadline + 1)
            .unwrap(),
        "a lapsed token is not live even though nothing finished"
    );
    assert!(
        !store
            .plane_token_live("some_other_kind", id, deadline, TASK_LIVE_TS)
            .unwrap(),
        "the capability is scoped to its kind"
    );
    store
        .upsert_plane_record(push_config(id, PlaneDisposition::Terminal).view())
        .unwrap();
    assert!(
        !store
            .plane_token_live("push_config", id, deadline, TASK_LIVE_TS)
            .unwrap(),
        "the write that made the task terminal revokes the token"
    );
    store.delete_plane_record("push_config", id).unwrap();
    assert!(!store
        .plane_token_live("push_config", id, deadline, TASK_LIVE_TS)
        .unwrap());
}

// ── 1.6.0 record shapes: VirtualKey, ModelTokens, MeteringRow ───────────────────────────────────

/// Every scope KIND round-trips as itself. The pre-1.6.0 write path stored only each scope's
/// VALUE into `allowed_pools`, so an `mcp_server` grant came back as a POOL grant — the MCP grant
/// lost AND a pool the key was never given admitted. busbar 1.6.0 ships non-`pool` kinds, so this
/// is the escalation that write path would now hand out.
#[test]
fn every_scope_kind_round_trips_and_none_becomes_a_pool() {
    let Some(s) = fresh_store() else { return };
    let mut k = sample_key("vk_scopes", "g");
    k.allowed_scopes = Some(vec![
        ScopeRef::pool("fast"),
        ScopeRef {
            kind: "mcp_server".into(),
            value: "payments".into(),
        },
        ScopeRef {
            kind: "agent".into(),
            value: "planner".into(),
        },
    ]);
    s.put_key(&k).unwrap();
    let back = s.get_key("vk_scopes").unwrap().unwrap();
    assert!(back.scope_allowed("pool", "fast"));
    assert!(back.scope_allowed("mcp_server", "payments"));
    assert!(back.scope_allowed("agent", "planner"));
    assert!(
        !back.scope_allowed("pool", "payments"),
        "an mcp_server grant must never come back as a POOL grant"
    );
    assert!(!back.scope_allowed("pool", "planner"));
    let mut want = k.allowed_scopes.clone().unwrap();
    let mut got = back.allowed_scopes.clone().unwrap();
    want.sort_by(|a, b| (&a.kind, &a.value).cmp(&(&b.kind, &b.value)));
    got.sort_by(|a, b| (&a.kind, &a.value).cmp(&(&b.kind, &b.value)));
    assert_eq!(got, want, "the grant round-trips exactly, every kind");

    // A grant of ONLY non-pool kinds is an explicit list, fail-closed for pools — never widened to
    // the omitted-list wildcard.
    let mut only_mcp = sample_key("vk_scopes_mcp_only", "g");
    only_mcp.allowed_scopes = Some(vec![ScopeRef {
        kind: "mcp_server".into(),
        value: "search".into(),
    }]);
    s.put_key_with_credential(
        &only_mcp,
        &sample_credential("vk_scopes_mcp_only", "AKIA_SCOPES_MCP", 0),
    )
    .unwrap();
    let back = s.get_key("vk_scopes_mcp_only").unwrap().unwrap();
    assert!(back.scope_allowed("mcp_server", "search"));
    assert!(
        !back.scope_allowed("pool", "anything"),
        "a key granted only an MCP server grants no pool"
    );
    assert!(back.allowed_scopes.is_some(), "never the wildcard");
    // And the pool column a 1.5.x node would read is the empty (fail-closed) grant, not NULL.
    let mut conn = s.conn().unwrap();
    let pools: Option<Option<String>> = conn
        .query_first("SELECT allowed_pools FROM api_keys WHERE id = 'vk_scopes_mcp_only'")
        .unwrap();
    assert_eq!(
        pools.flatten().map(|p| p.replace(' ', "")),
        Some("[]".to_string())
    );
}

/// The three 1.6.0 `VirtualKey` fields persist through both write paths and a tombstone.
#[test]
fn the_1_6_0_key_fields_round_trip() {
    let Some(s) = fresh_store() else { return };
    let mut k = sample_key("vk_bound", "g");
    k.idp_subject = Some("user|abc-123".into());
    k.binding_mode = Some("user-bound".into());
    k.minted_by = Some("vk_app_admin".into());
    s.put_key(&k).unwrap();
    let back = s.get_key("vk_bound").unwrap().unwrap();
    assert_eq!(back.idp_subject.as_deref(), Some("user|abc-123"));
    assert_eq!(back.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(back.minted_by.as_deref(), Some("vk_app_admin"));

    let mut minted = sample_key("vk_bound_minted", "g");
    minted.binding_mode = Some("time-bound".into());
    minted.minted_by = Some("vk_app_admin".into());
    s.put_key_with_credential(
        &minted,
        &sample_credential("vk_bound_minted", "AKIA_BOUND", 0),
    )
    .unwrap();
    let back = s.get_key("vk_bound_minted").unwrap().unwrap();
    assert_eq!(back.binding_mode.as_deref(), Some("time-bound"));
    assert_eq!(back.minted_by.as_deref(), Some("vk_app_admin"));
    assert_eq!(back.idp_subject, None, "an unset field reads back None");

    s.delete_key("vk_bound").unwrap();
    let tomb = s.get_key("vk_bound").unwrap().unwrap();
    assert_eq!(
        tomb.minted_by.as_deref(),
        Some("vk_app_admin"),
        "provenance survives the tombstone, like every other attribution field"
    );
}

/// OPEN usage units (everything but the reserved four) round-trip through `put_usage`, accumulate
/// through `add_usage` with the same floor-at-zero rule, and are replaced — not merged — by an
/// absolute `put_usage`.
#[test]
fn open_usage_units_round_trip_accumulate_and_floor_at_zero() {
    let _guard = lock_usage_windows();
    let Some(s) = fresh_store() else { return };
    let ledger = UsageLedger {
        requests: 2,
        billable_requests: 2,
        models: vec![ModelTokens {
            model: "rerank-x".into(),
            usage_units: units(&[(UNIT_INPUT, 7), ("search_units", 3), ("tool_calls", 1)]),
        }],
    };
    s.put_usage("vk_open_units", 1_000_201, &ledger).unwrap();
    let back = s.get_usage("vk_open_units", 1_000_201).unwrap();
    assert_eq!(
        back, ledger,
        "the whole ledger, open units included, round-trips"
    );

    s.add_usage(
        "vk_open_units",
        1_000_201,
        &UsageDelta {
            requests: 1,
            billable_requests: 1,
            models: vec![ModelTokensDelta {
                model: "rerank-x".into(),
                usage_units: units(&[("search_units", 4), ("tool_calls", -10), ("bytes", 5)]),
            }],
        },
    )
    .unwrap();
    let after = s.get_usage("vk_open_units", 1_000_201).unwrap();
    let m = &after.models[0];
    assert_eq!(m.tier("search_units"), 7, "an open unit accumulates");
    assert_eq!(
        m.tier("tool_calls"),
        0,
        "an open unit floors at 0, never wraps"
    );
    assert_eq!(
        m.tier("bytes"),
        5,
        "a unit first seen in a delta is created"
    );
    assert_eq!(m.tier(UNIT_INPUT), 7, "the reserved units are untouched");

    // An absolute set REPLACES the window: a unit the new ledger does not carry is gone.
    let replaced = UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            model: "rerank-x".into(),
            usage_units: units(&[("search_units", 1)]),
        }],
    };
    s.put_usage("vk_open_units", 1_000_201, &replaced).unwrap();
    assert_eq!(s.get_usage("vk_open_units", 1_000_201).unwrap(), replaced);

    // And the retention sweep takes a window's open units with it.
    s.purge_windows_before(1_000_202).unwrap();
    let mut conn = s.conn().unwrap();
    let left: Option<u64> = conn
        .query_first("SELECT COUNT(*) FROM usage_window_units WHERE bucket_id = 'vk_open_units'")
        .unwrap();
    assert_eq!(
        left,
        Some(0),
        "a purged window leaves no open-unit rows behind"
    );
}

fn metering_delta(key: &str, bucket: u64, priced_from_ms: u64) -> MeteringDelta {
    MeteringDelta {
        key_id: key.into(),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "team-a".into(),
        pricing_version: "v1".into(),
        priced_from_ms,
        usage_units: units(&[("tool_calls", 2)]),
    }
}

/// DECISION #79: `priced_from_ms` JOINS THE ACCRUAL KEY. A rate-card edit inside the UTC day opens
/// a SECOND cell for that day, so each half keeps the card it was earned under; the same instant
/// accumulates into one cell. Open units accumulate per cell, and the purge takes them with it.
#[test]
fn metering_cells_split_on_priced_from_ms_and_carry_open_units() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_meter79", "g")).unwrap();
    let bucket = 20_260_801u64;
    s.add_metering(&metering_delta("vk_meter79", bucket, 0))
        .unwrap();
    s.add_metering(&metering_delta("vk_meter79", bucket, 0))
        .unwrap();
    s.add_metering(&metering_delta("vk_meter79", bucket, 1_780_000_000_000))
        .unwrap();

    let mut rows: Vec<MeteringRow> = s
        .list_metering(bucket)
        .unwrap()
        .into_iter()
        .filter(|r| r.key_id == "vk_meter79")
        .collect();
    rows.sort_by_key(|r| r.priced_from_ms);
    assert_eq!(rows.len(), 2, "a card edit splits the day's cell in two");
    assert_eq!(rows[0].priced_from_ms, 0);
    assert_eq!(
        rows[0].requests, 2,
        "the same instant accumulates into one cell"
    );
    assert_eq!(rows[0].tokens_input, 20);
    assert_eq!(rows[0].usage_units, units(&[("tool_calls", 4)]));
    assert_eq!(rows[1].priced_from_ms, 1_780_000_000_000);
    assert_eq!(rows[1].requests, 1);
    assert_eq!(rows[1].usage_units, units(&[("tool_calls", 2)]));

    assert!(s.purge_metering_before(&bucket.to_string()).unwrap() >= 2);
    assert!(s
        .list_metering(bucket)
        .unwrap()
        .iter()
        .all(|r| r.key_id != "vk_meter79"));
    let mut conn = s.conn().unwrap();
    let left: Option<u64> = conn
        .query_first("SELECT COUNT(*) FROM usage_metering_units WHERE key_id = 'vk_meter79'")
        .unwrap();
    assert_eq!(
        left,
        Some(0),
        "a purged cell leaves no open-unit rows behind"
    );
}

// ── The store v3 slots (the door's additions to the 1.5.5 op set) ─────────────────────────────

mod slots_tests;

// ── Upgrading an existing database IN PLACE ─────────────────────────────────────────────────────

mod schema_fixtures;

/// A throwaway database, dropped on scope exit. Migration tests need a whole schema of their own:
/// seeding an old `schema_version` in the shared `busbar_test` would race every other test's
/// `connect()`, and the CI `busbar` user cannot CREATE DATABASE, so `root` does it.
struct ScratchDb {
    root: Pool,
    name: String,
    url: String,
}

impl ScratchDb {
    fn new(tag: &str) -> Option<Self> {
        let url = test_url()?;
        let name = format!(
            "busbar_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root_url = url.replacen("busbar:busbar@", "root:busbar@", 1);
        let root = Pool::new(Opts::from_url(&root_url).unwrap()).unwrap();
        let mut c = root.get_conn().unwrap();
        c.query_drop(format!("CREATE DATABASE {name}")).unwrap();
        c.query_drop(format!("GRANT ALL PRIVILEGES ON {name}.* TO 'busbar'@'%'"))
            .unwrap();
        let cut = url
            .rfind('/')
            .expect("test_url() must be a mysql:// URL with a /database path");
        let db_url = format!("{}/{name}", &url[..cut]);
        Some(Self {
            root,
            name,
            url: db_url,
        })
    }

    fn conn(&self) -> PooledConn {
        let pool = Pool::new(Opts::from_url(&self.url).unwrap()).unwrap();
        pool.get_conn().unwrap()
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        if let Ok(mut c) = self.root.get_conn() {
            let _ = c.query_drop(format!("DROP DATABASE {}", self.name));
        }
    }
}

/// THE UPGRADE THAT MUST NOT BREAK: a database written by the RELEASED 1.5.x plugin (v1.0.6, schema
/// v3 — its DDL is reproduced verbatim in `schema_fixtures`) upgrades IN PLACE on the first 1.6.0
/// boot. Every row it held reads back unchanged, the new columns and the re-keyed metering table are
/// in place, the new tables work, and a second boot is a no-op.
#[test]
fn a_released_1_5_database_upgrades_in_place() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("up15") else {
        return;
    };
    {
        let mut c = db.conn();
        c.query_drop("SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')")
            .unwrap();
        for stmt in schema_fixtures::V1_0_6_SCHEMA {
            c.query_drop(*stmt).unwrap();
        }
        for stmt in [
            "INSERT INTO store_meta (k, v) VALUES ('schema_version', '3')",
            "INSERT INTO store_sequence (id, revision) VALUES (1, 41)",
            "INSERT INTO api_keys (id, name, key_group, allowed_pools, labels, enabled, \
             generation_hash, created_at, updated_at, expires_at, deleted_at, revision) VALUES \
             ('vk_old_pools', 'old', 'team-a', '[\"fast\", \"slow\"]', '{\"env\": \"prod\"}', 1, \
              'binding:vk_old_pools:g1', 1000, 1000, NULL, NULL, 40), \
             ('vk_old_all', 'all', '', NULL, '{}', 1, 'g', 1000, 1000, NULL, NULL, 39), \
             ('vk_old_none', 'none', '', '[]', '{}', 1, 'g', 1000, 1000, NULL, NULL, 38), \
             ('vk_old_dead', '', '', NULL, '{}', 0, 'g', 1000, 1000, NULL, 2000, 41)",
            "INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form, \
             created_at, updated_at, revision) VALUES ('cred_old', 'vk_old_pools', 'sigv4', 0, \
             'AKIA_OLD15', 'v1:plain:old', 'recoverable', 1000, 1000, 40)",
            "INSERT INTO denylist (sub, reason, revoked_at, expires_at, revision) \
             VALUES ('vk_old_dead', 'revoked', 2000, 9000000000, 41)",
            "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests, \
             billable_requests) VALUES (3000, 'key', 'vk_old_pools', '', 9, 8)",
            "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, \
             tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) \
             VALUES (3000, 'key', 'vk_old_pools', 'gpt-x', 100, 50, 7, 3)",
            "INSERT INTO usage_metering (bucket, key_id, provider, model, key_group_at_use, \
             pricing_version, requests, billable_requests, tokens_input, tokens_output, \
             tokens_cache_read, tokens_cache_write) VALUES ('0020260731', 'vk_old_pools', 'p', \
             'm', 'team-a', 'v1', 4, 3, 40, 20, 0, 0)",
            "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash) \
             VALUES (1, 1000, 'key.mint', 'key:vk_old_pools', 'applied', 'admin', '', 'h1')",
        ] {
            c.query_drop(stmt).unwrap();
        }
    }

    let store = MysqlStore::connect(&db.url).expect("a released 1.5.x database must upgrade");

    // Every existing row reads back as it was.
    let k = store
        .get_key("vk_old_pools")
        .unwrap()
        .expect("the 1.5 key survives");
    assert_eq!(
        k.allowed_scopes,
        Some(vec![ScopeRef::pool("fast"), ScopeRef::pool("slow")])
    );
    assert_eq!(k.group.as_deref(), Some("team-a"));
    assert_eq!(k.labels.get("env").map(String::as_str), Some("prod"));
    assert_eq!(k.revision, 40);
    assert_eq!(
        (
            k.idp_subject.clone(),
            k.binding_mode.clone(),
            k.minted_by.clone()
        ),
        (None, None, None),
        "a pre-field key reads the new fields as None"
    );
    assert_eq!(
        store.get_key("vk_old_all").unwrap().unwrap().allowed_scopes,
        None
    );
    assert_eq!(
        store
            .get_key("vk_old_none")
            .unwrap()
            .unwrap()
            .allowed_scopes,
        Some(vec![])
    );
    assert!(store
        .get_key("vk_old_dead")
        .unwrap()
        .unwrap()
        .deleted_at
        .is_some());
    assert_eq!(store.list_keys().unwrap().len(), 4);
    let cred = store
        .lookup_credential_secret("sigv4", "AKIA_OLD15")
        .unwrap()
        .expect("the 1.5 credential survives");
    assert_eq!(cred.secret, "v1:plain:old");
    assert_eq!(
        store.list_denylist().unwrap(),
        vec!["vk_old_dead".to_string()]
    );
    let usage = store.get_usage("vk_old_pools", 3000).unwrap();
    assert_eq!((usage.requests, usage.billable_requests), (9, 8));
    assert_eq!(usage.models.len(), 1);
    assert_eq!(
        usage.models[0].usage_units,
        units(&[
            (UNIT_INPUT, 100),
            (UNIT_OUTPUT, 50),
            (UNIT_CACHE_READ, 7),
            (UNIT_CACHE_WRITE, 3)
        ]),
        "the four token columns ARE the reserved units — no data migration, nothing lost"
    );
    let meter = store.list_metering(20_260_731).unwrap();
    assert_eq!(meter.len(), 1);
    assert_eq!(
        (
            meter[0].requests,
            meter[0].tokens_input,
            meter[0].priced_from_ms
        ),
        (4, 40, 0),
        "a 1.5 metering cell reads back unchanged, dated at the opening card (0)"
    );
    assert_eq!(store.list_audit().unwrap().len(), 1);

    // The revision counter carried over: a new write stamps PAST every 1.5 revision.
    store.put_key(&sample_key("vk_new16", "g")).unwrap();
    assert!(store.get_key("vk_new16").unwrap().unwrap().revision > 41);

    // The re-keyed metering table accepts a second cell for the same day on a later card, and the
    // 1.5 cell keeps accumulating under priced_from_ms = 0.
    store
        .add_metering(&metering_delta("vk_old_pools", 20_260_731, 0))
        .unwrap();
    store
        .add_metering(&metering_delta(
            "vk_old_pools",
            20_260_731,
            1_780_000_000_000,
        ))
        .unwrap();
    let mut meter = store.list_metering(20_260_731).unwrap();
    meter.sort_by_key(|r| r.priced_from_ms);
    assert_eq!(meter.len(), 2);
    assert_eq!(meter[0].requests, 5, "the 1.5 cell accumulates in place");
    // The new tables are live.
    store
        .upsert_plane_record(active_task("t_after_upgrade", "working", TASK_LIVE_TS).view())
        .unwrap();
    assert!(store
        .get_plane_record("task", "t_after_upgrade")
        .unwrap()
        .is_some());
    assert!(store
        .redeem_plane_token("ask", "n_after_upgrade", TRUST_NOW + 900, TRUST_NOW)
        .unwrap());

    let mut c = db.conn();
    let version: Option<String> = c
        .query_first("SELECT v FROM store_meta WHERE k = 'schema_version'")
        .unwrap();
    assert_eq!(
        version.as_deref(),
        Some(SCHEMA_VERSION.to_string().as_str())
    );
    drop(store);

    // A second boot is a no-op: nothing re-runs destructively, every row is still there.
    let again = MysqlStore::connect(&db.url).expect("a second boot of an upgraded database");
    assert_eq!(again.list_keys().unwrap().len(), 5);
    assert_eq!(again.list_metering(20_260_731).unwrap().len(), 2);
    assert!(again
        .get_plane_record("task", "t_after_upgrade")
        .unwrap()
        .is_some());
}

/// A pre-release 1.6.0 development database (v4..v6) carried plane state in per-protocol tables.
/// The v7 crossing carries tasks, their event chains, demotions and spent approvals into the neutral
/// tables in the envelope the engine reads, ONCE; it drops nothing; and a later boot does not
/// re-copy (which would resurrect a demotion the engine has since cleared).
#[test]
fn a_v6_development_database_carries_its_plane_state_across_once() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("up6") else {
        return;
    };
    {
        let mut c = db.conn();
        for stmt in schema_fixtures::V1_0_6_SCHEMA
            .iter()
            .chain(schema_fixtures::V6_PLANE_TABLES)
        {
            c.query_drop(*stmt).unwrap();
        }
        for stmt in [
            "INSERT INTO store_meta (k, v) VALUES ('schema_version', '6')",
            "INSERT INTO store_sequence (id, revision) VALUES (1, 0)",
            "INSERT INTO tasks (task_id, context_id, principal, direction, state, agent_id, \
             artifact_cursor, push_callback, created_at, updated_at) VALUES \
             ('t_v6_live', 'ctx', 'vk_a', 'inbound', 'input-required', 'planner', 18446744073709551615, \
              'https://example.test/push', 100, 200), \
             ('t_v6_done', 'ctx', 'vk_a', 'inbound', 'completed', 'planner', 0, '', 100, 150), \
             ('t_v6_Done', 'ctx', 'vk_a', 'inbound', 'Completed', 'planner', 0, '', 100, 150)",
            "INSERT INTO task_events (task_id, seq, ts, kind, context_id, principal, agent_id, \
             state, request_id, prev_hash, hash) VALUES \
             ('t_v6_live', 1, 101, 'task.submitted', 'ctx', 'vk_a', 'planner', 'submitted', 'r1', '', 'e1'), \
             ('t_v6_live', 2, 102, 'task.working', 'ctx', 'vk_a', 'planner', 'working', 'r2', 'e1', 'e2')",
            "INSERT INTO mcp_demotions (server, reason, recorded_at) VALUES ('srv_v6', 'tool-drift', 300)",
            "INSERT INTO spent_ask_states (nonce, expires_at) VALUES ('nonce_v6', 18446744073709551615)",
            "INSERT INTO mcp_calls (principal, seq, ts, prev_hash, hash, body) \
             VALUES ('vk_a', 1, 400, '', 'c1', '{}')",
        ] {
            c.query_drop(stmt).unwrap();
        }
    }

    let store = MysqlStore::connect(&db.url).expect("a v6 database must upgrade");

    let live = get_task(&store, "t_v6_live").expect("the in-flight task crosses the upgrade");
    assert_eq!(live["state"], "input-required");
    assert_eq!(
        live["artifact_cursor"].as_u64(),
        Some(u64::MAX),
        "a u64 column copies into the body without wrapping"
    );
    assert_eq!(live["push_callback"], "https://example.test/push");
    assert_eq!(live["updated_at"].as_u64(), Some(200));
    let events = events_of(&store, "t_v6_live");
    assert_eq!(
        events
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(events[1]["prev_hash"], "e1");
    assert!(
        events[0].get("digest_version").is_none(),
        "no digest_version is invented: the engine reads these as the framing they were sealed under"
    );
    // Terminality came across on the typed column: a purge takes the terminal task only — and
    // `Completed` (not a recognised terminal token) is kept, the closed-set rule the v5 sweep had.
    let _guard = lock_plane_purge();
    assert_eq!(store.purge_plane_records_before("task", 1_000).unwrap(), 1);
    let ids = all_task_ids(&store);
    assert!(ids.contains(&"t_v6_live".to_string()));
    assert!(ids.contains(&"t_v6_Done".to_string()));
    assert!(!ids.contains(&"t_v6_done".to_string()));
    drop(_guard);

    assert_eq!(
        demotions(&store),
        vec![serde_json::json!({ "server": "srv_v6", "reason": "tool-drift", "recorded_at": 300 })],
        "a quarantine outlives the upgrade"
    );
    assert!(
        !store
            .redeem_plane_token("ask", "nonce_v6", u64::MAX, 1_000)
            .unwrap(),
        "an approval spent before the upgrade stays spent"
    );
    // The call log is NOT copied (the engine has no decode for the pre-1.6 typed body), and NOTHING
    // legacy is dropped.
    assert!(store.list_plane_record_parents("call").unwrap().is_empty());
    let mut c = db.conn();
    for t in [
        "tasks",
        "task_events",
        "mcp_demotions",
        "spent_ask_states",
        "mcp_calls",
    ] {
        let n: Option<u64> = c.query_first(format!("SELECT COUNT(*) FROM {t}")).unwrap();
        assert!(
            n.unwrap_or(0) > 0,
            "legacy table {t} must be left as it was"
        );
    }

    // The engine clears the demotion; a later boot must NOT resurrect it from the legacy table.
    store.delete_plane_record("demotion", "srv_v6").unwrap();
    drop(store);
    let again = MysqlStore::connect(&db.url).expect("second boot");
    assert!(
        demotions(&again).is_empty(),
        "the one-time copy must not re-run and resurrect a cleared quarantine"
    );
}
