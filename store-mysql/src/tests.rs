// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{ModelTokensDelta, RecordStore};
use mysql::prelude::*;
use mysql::{params, Opts, Pool, PooledConn};
use std::collections::BTreeMap;

mod conditional_records;
#[path = "tests/credential_rewrap.rs"]
mod credential_rewrap;
/// The store under test, opened through the real loader over the host's connection path; raw SQL on an independent `mysql` driver connection.
mod harness;
mod rewrap_faults;
mod usage_correction;
use harness::MysqlStore;

/// The verify path's read, which is no longer a store op: a credential's secret by `(kind, public_id)`, read back through the revision delta (which carries every row, revoked or not).
trait Lookup {
    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>>;
}

impl Lookup for MysqlStore {
    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        Ok(self
            .list_credentials_since(0)?
            .into_iter()
            .find(|c| c.meta.kind == kind && c.meta.public_id == public_id))
    }
}

/// A name-keyed `usage_units` map from literal pairs — the 1.6.0 shape of what used to be the four `TierTokens`/`TierTokensDelta` fields.
fn units<V: Copy>(pairs: &[(&str, V)]) -> BTreeMap<String, V> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn test_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(u) => Some(u),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_MYSQL_URL is unset under CI: the mysql service container must provision it"
            );
        }
        Err(_) => {
            eprintln!(
                "skip: set BUSBAR_TEST_MYSQL_URL to run these tests, e.g. mysql://busbar:busbar@127.0.0.1:3307/busbar_test"
            );
            None
        }
    }
}

/// Connects against the same live server every test shares.
fn fresh_store() -> Option<MysqlStore> {
    let url = test_url()?;
    let store = MysqlStore::connect(&url).expect("connect+schema");

    ensure_reset(&store);
    Some(store)
}

/// The one-time table wipe, as its own barrier so a test can join it WITHOUT paying for another `MysqlStore::connect`.
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

// The independent SQL fixture client does not implement the SDK's RSA-pin URL option.
fn raw_mysql_url(value: &str) -> String {
    let mut url = url::Url::parse(value).expect("fixture MySQL URL");
    let pairs: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key != "server_public_key_sha256")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    if !pairs.is_empty() {
        url.query_pairs_mut().extend_pairs(pairs);
    }
    url.to_string()
}

/// The server's `root` on the test URL's host, for the DDL the `busbar` user may not run (CREATE DATABASE).
fn root_url(url: &str) -> String {
    let password =
        std::env::var("BUSBAR_TEST_MYSQL_ROOT_PASSWORD").unwrap_or_else(|_| "busbar".into());
    url.replacen("busbar:busbar@", &format!("root:{password}@"), 1)
}

/// The two tests that build a WHOLE schema from nothing against their own throwaway database (the v2 real-wiring test and the v4->v5 task-store migration) run ~25 DDL statements apiece.
static FRESH_DATABASE_DDL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_fresh_database_ddl() -> std::sync::MutexGuard<'static, ()> {
    FRESH_DATABASE_DDL_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
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
        idp_provider: None,
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

/// A second `put_key` on the same id replaces every field it carries: name, group, labels, scopes, expiry, enabled, generation hash and the IdP fields all read back as the second write, and the creation time stays the first's.
#[test]
fn put_key_over_an_existing_key_replaces_every_field() {
    let Some(s) = fresh_store() else { return };
    let mut first = sample_key("vk_reput", "gen-1");
    first.name = "first".into();
    first.group = Some("g1".into());
    first.labels = BTreeMap::from([("a".to_owned(), "1".to_owned())]);
    first.allowed_scopes = Some(vec![ScopeRef::pool("p1")]);
    first.expires_at = Some(5_000);
    first.idp_subject = Some("sub-1".into());
    first.binding_mode = Some("bound".into());
    first.minted_by = Some("admin-1".into());
    first.idp_provider = Some("idp-1".into());
    s.put_key(&first).unwrap();

    let mut second = sample_key("vk_reput", "gen-2");
    second.name = "second".into();
    second.group = Some("g2".into());
    second.labels = BTreeMap::from([("b".to_owned(), "2".to_owned())]);
    second.allowed_scopes = Some(vec![ScopeRef::pool("p2"), ScopeRef::pool("p3")]);
    second.expires_at = Some(9_000);
    second.enabled = false;
    second.created_at = 2_000;
    second.idp_subject = Some("sub-2".into());
    second.binding_mode = Some("unbound".into());
    second.minted_by = Some("admin-2".into());
    second.idp_provider = Some("idp-2".into());
    s.put_key(&second).unwrap();

    let got = s.get_key("vk_reput").unwrap().unwrap();
    assert_eq!(got.name, "second");
    assert_eq!(got.generation_hash, "gen-2");
    assert_eq!(got.group.as_deref(), Some("g2"));
    assert_eq!(got.labels, second.labels);
    assert_eq!(got.allowed_scopes, second.allowed_scopes);
    assert_eq!(got.expires_at, Some(9_000));
    assert!(!got.enabled);
    assert_eq!(got.idp_subject.as_deref(), Some("sub-2"));
    assert_eq!(got.binding_mode.as_deref(), Some("unbound"));
    assert_eq!(got.minted_by.as_deref(), Some("admin-2"));
    assert_eq!(got.idp_provider.as_deref(), Some("idp-2"));
    assert_eq!(
        got.created_at, 1000,
        "the creation time is the first write's"
    );

    let mut cleared = sample_key("vk_reput", "gen-3");
    cleared.created_at = 3_000;
    s.put_key(&cleared).unwrap();
    let got = s.get_key("vk_reput").unwrap().unwrap();
    assert_eq!(got.group, None);
    assert_eq!(got.expires_at, None);
    assert_eq!(got.allowed_scopes, None);
    assert!(got.labels.is_empty());
    assert_eq!(got.idp_subject, None);
    assert!(got.enabled);
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

/// Regression for a real bug found in this session's final CI verification: every prior test in this file uses short synthetic ids (`"vk_1"`, `"vk_all"`, ...), all well under the schema's old `CHAR(26)` column width -- so the suite never caught that the REAL id format busbar's core mint path generates (`vk_` + 32 hex chars from `hex::encode([u8; 16])`, `governance/state.rs::mint_signed`) is 35 characters, wider than `CHAR(26)` (sized, incorrectly, for a 26-char ULID).
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

    assert!(
        delta.iter().any(|k| k.id == "vk_wm_b"),
        "vk_wm_b must appear in the delta"
    );
    assert!(
        !delta.iter().any(|k| k.id == "vk_wm_a"),
        "vk_wm_a predates the watermark, must not appear"
    );
}

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

/// Delta and full hydration observe the tombstone and physical credential destruction.
/// That both halves commit atomically is independently guarded by
/// `delete_key_shows_nothing_of_itself_until_it_commits_both_halves`.
#[test]
fn tombstone_delta_and_full_hydration_observe_credential_destruction() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_hyd", "g");
    let cred = sample_credential("vk_hyd", "AKIA_HYD", 0);
    s.put_key_with_credential(&k, &cred).unwrap();
    let watermark = s.get_key("vk_hyd").unwrap().unwrap().revision;
    let before = s.list_credentials_since(0).unwrap();
    assert!(
        before.iter().any(|row| row.meta.id == cred.meta.id),
        "the credential must really exist before deletion"
    );

    s.delete_key("vk_hyd").unwrap();
    assert!(
        !s.list_credentials_since(0)
            .unwrap()
            .iter()
            .any(|row| row.meta.id == cred.meta.id),
        "full hydration must independently confirm physical credential destruction"
    );

    let key_delta = s.list_keys_since(watermark).unwrap();
    let ours = key_delta
        .iter()
        .find(|k| k.id == "vk_hyd")
        .expect("vk_hyd must appear in the delta");
    assert!(
        ours.deleted_at.is_some(),
        "the delta must show the tombstone"
    );

    let cred_delta = s.list_credentials_since(watermark).unwrap();
    assert!(
        !cred_delta.iter().any(|c| c.meta.key_id == "vk_hyd"),
        "a hard-deleted credential produces no delta -- this is the trap the contract warns about"
    );
}

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

    let meta = &s.list_credentials("vk_sec").unwrap()[0];
    assert_eq!(meta.public_id, "AKIA_SEC");
    assert!(!format!("{meta:?}").contains("shhh"));
    assert!(!serde_json::to_string(meta).unwrap().contains("shhh"));
}

/// Credential lookups are case-SENSITIVE (the key columns are byte-exact `VARBINARY`), matching Postgres/SQLite's default behavior.
#[test]
fn public_id_lookup_is_case_sensitive() {
    let Some(s) = fresh_store() else { return };
    let k = sample_key("vk_case", "g");
    let cred = sample_credential("vk_case", "AKIA_CASE", 0);
    s.put_key_with_credential(&k, &cred).unwrap();

    let mut conn = s.conn().unwrap();
    let lookup = |conn: &mut PooledConn, public_id: &str| -> Option<String> {
        conn.exec_first(
            "SELECT id FROM credentials WHERE kind = 'sigv4' AND public_id = :p",
            params! { "p" => public_id },
        )
        .unwrap()
    };
    assert_eq!(lookup(&mut conn, "AKIA_CASE"), Some(cred.meta.id.clone()));
    assert_eq!(
        lookup(&mut conn, "akia_case"),
        None,
        "a case-different public_id must NOT resolve to the same credential"
    );
    assert!(s
        .lookup_credential_secret("sigv4", "AKIA_CASE")
        .unwrap()
        .is_some());
    assert!(s
        .lookup_credential_secret("sigv4", "akia_case")
        .unwrap()
        .is_none());

    let k2 = sample_key("vk_case2", "g");
    let cred2 = sample_credential("vk_case2", "akia_case", 0);
    s.put_key_with_credential(&k2, &cred2)
        .expect("a public_id differing only in case is its own credential");
    assert_eq!(lookup(&mut conn, "akia_case"), Some(cred2.meta.id.clone()));
}

#[test]
fn put_and_get_usage_roundtrips() {
    let Some(s) = fresh_store() else { return };
    let ledger = UsageLedger {
        requests: 5,
        billable_requests: 4,
        models: vec![ModelTokens {
            scale: 6,
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

/// The request counters are per-WINDOW, not per-model, and must round-trip as themselves whatever the model breakdown looks like.
#[test]
fn usage_request_counters_do_not_multiply_with_the_model_count() {
    let Some(s) = fresh_store() else { return };
    let model = |name: &str| ModelTokens {
        scale: 6,
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

    s.add_usage(
        "vk_multimodel",
        1_000_101,
        &busbar_contract::records::UsageDelta {
            requests: 2,
            billable_requests: 1,
            models: vec![
                busbar_contract::records::ModelTokensDelta {
                    scale: 6,
                    model: "gpt-x".to_string(),
                    usage_units: units(&[(UNIT_INPUT, 1), (UNIT_OUTPUT, 1)]),
                },
                busbar_contract::records::ModelTokensDelta {
                    scale: 6,
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
#[test]
fn usage_with_no_model_breakdown_still_records_its_request_counters() {
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

/// THE SPLIT FLUSH (busbar ADV-1.6.0-2).
#[test]
fn a_request_split_across_two_flushes_keeps_its_count_across_a_reconnect() {
    let Some(s) = fresh_store() else { return };
    let admission = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![],
    };
    let completion = UsageDelta {
        requests: 0,
        billable_requests: 0,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: "m-split".to_string(),
            usage_units: units(&[(UNIT_INPUT, 11), (UNIT_OUTPUT, 7)]),
        }],
    };
    s.add_usage("vk_split_flush", 1_000_103, &admission)
        .unwrap();
    s.add_usage("vk_split_flush", 1_000_103, &completion)
        .unwrap();
    drop(s);
    let reopened = MysqlStore::connect(&test_url().unwrap()).expect("reconnect");
    let back = reopened.get_usage("vk_split_flush", 1_000_103).unwrap();
    assert_eq!(
        (back.requests, back.billable_requests),
        (1, 1),
        "the admission flush's request count was dropped; the completion's tokens alone survived: {back:?}"
    );
    assert_eq!(back.models.len(), 1, "{back:?}");
    assert_eq!(back.models[0].tier(UNIT_INPUT), 11, "{back:?}");
    assert_eq!(back.models[0].tier(UNIT_OUTPUT), 7, "{back:?}");
}

#[test]
fn get_usage_on_an_empty_window_returns_zeroes_not_a_panic() {
    let Some(s) = fresh_store() else { return };
    let back = s.get_usage("vk_never_used", 999).unwrap();
    assert_eq!(back.requests, 0);
    assert_eq!(back.billable_requests, 0);
    assert!(back.models.is_empty());
}

#[test]
fn add_usage_accumulates_and_floors_at_zero() {
    let Some(s) = fresh_store() else { return };
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 3,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: "m".to_string(),
            usage_units: units(&[(UNIT_INPUT, 10), (UNIT_OUTPUT, 5)]),
        }],
    };
    s.add_usage("vk_add", 2000, &delta).unwrap();
    s.add_usage("vk_add", 2000, &delta).unwrap();
    let ledger = s.get_usage("vk_add", 2000).unwrap();
    assert_eq!(ledger.requests, 6);
    assert_eq!(ledger.models[0].tier(UNIT_INPUT), 20);

    let refund = UsageDelta {
        requests: -100,
        billable_requests: -100,
        models: vec![ModelTokensDelta {
            scale: 6,
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
    assert_eq!(
        ledger.billable_requests, 0,
        "billable_requests must floor at 0"
    );
}

#[test]
fn add_metering_upserts_and_accumulates() {
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key("vk_meter", "g")).unwrap();
    let d = MeteringDelta {
        scale: 6,
        key_id: "vk_meter".to_string(),

        bucket: 20260915,
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
    let rows: Vec<_> = s
        .list_metering(20260915)
        .unwrap()
        .into_iter()
        .filter(|r| r.key_id == "vk_meter")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requests, 2);
    assert_eq!(rows[0].tokens_input, 20);
    assert_eq!(rows[0].key_group_at_use, "team-a");
}

#[test]
fn denylist_repeat_refreshes_reason_and_revision_without_shortening_expiry() {
    let Some(s) = fresh_store() else { return };
    s.add_denylist("sub_window", "revoked").unwrap();
    assert!(s
        .list_denylist()
        .unwrap()
        .contains(&"sub_window".to_string()));

    let far = 4_000_000_000_000u64;
    let row = |conn: &mut PooledConn| -> (u64, u64) {
        conn.query_first("SELECT expires_at, revision FROM denylist WHERE sub = 'sub_window'")
            .unwrap()
            .unwrap()
    };
    let mut conn = s.pool.get_conn().unwrap();
    conn.exec_drop(
        "UPDATE denylist SET expires_at = :far WHERE sub = 'sub_window'",
        params! { "far" => far },
    )
    .unwrap();
    let before = row(&mut conn);
    assert_eq!(before.0, far);

    s.add_denylist("sub_window", "revoked again").unwrap();
    let after = row(&mut conn);
    assert_eq!(
        after.0, far,
        "a renewed denial never shortens a longer deadline"
    );
    assert!(after.1 > before.1, "renewal is published to delta readers");
    let reason: String = conn
        .query_first("SELECT reason FROM denylist WHERE sub='sub_window'")
        .unwrap()
        .unwrap();
    assert_eq!(reason, "revoked again");
    conn.query_drop("UPDATE denylist SET expires_at=1 WHERE sub='sub_window'")
        .unwrap();
    s.add_denylist("sub_window", "renewed").unwrap();
    assert!(row(&mut conn).0 > crate_now().unwrap());
}

#[test]
fn boot_probe_rejects_a_permissive_sql_mode() {
    let Some(url) = test_url() else { return };
    let opts = Opts::from_url(&raw_mysql_url(&url)).unwrap();
    let pool = Pool::new(opts).unwrap();
    let mut conn = pool.get_conn().unwrap();
    let original: String = conn.query_first("SELECT @@sql_mode").unwrap().unwrap();
    conn.query_drop("SET SESSION sql_mode = ''").unwrap();

    let err = MysqlStore::probe_invariants(&mut conn)
        .expect_err("an empty sql_mode (no STRICT_ALL_TABLES) must be rejected");
    let text = err.to_string();
    assert!(
        text.contains("sql_mode") && text.contains("STRICT"),
        "the refusal must name sql_mode and STRICT, not fail for another reason: {text}"
    );

    conn.query_drop("SET SESSION sql_mode = 'STRICT_ALL_TABLES'")
        .unwrap();
    MysqlStore::probe_invariants(&mut conn).expect("a strict session passes the probe");
    conn.query_drop(format!("SET SESSION sql_mode = '{original}'"))
        .unwrap();
}

/// Treating ANY error from the probe INSERT as proof CHECK constraints are enforced (`.is_err()` on the whole `Result`, with no inspection of WHICH error) would pass for the wrong reason.
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

/// The store ESTABLISHES strict sql_mode on every connection it opens (`INIT`, appended and not just verified once at boot).
#[test]
fn the_stores_own_connection_establishes_strict_sql_mode_from_a_permissive_start() {
    let Some(url) = test_url() else { return };
    let opts = std::sync::Arc::new(mysqlwire::Opts::from_url(&url).unwrap());
    let mut init = vec!["SET SESSION sql_mode = ''"];
    init.extend(crate::INIT.iter().copied());
    let mut conn = harness::block_on(mysqlwire::Conn::open_tcp(&opts, &init)).expect("open");
    let sql_mode: Option<String> =
        harness::block_on(conn.query_first("SELECT @@SESSION.sql_mode")).expect("read");
    let sql_mode = sql_mode.expect("a row");
    assert!(
        sql_mode.contains("STRICT_ALL_TABLES"),
        "the init-time append must land even starting from an empty sql_mode: got '{sql_mode}'"
    );
}

/// `delete_key` must lock `store_sequence` (via `bump_revision`) BEFORE locking the `api_keys` row, matching every other control-plane transaction (`put_key`, `put_credential`, `revoke_credential`) — that fixed order is what the module doc claims makes deadlock across the admin plane structurally impossible.
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
            if let Err(e) = del_store.delete_key(id) {
                let msg = e.to_string();
                assert!(
                    msg.contains("unknown id"),
                    "delete_key must only ever lose this race by finding the row already cleared: \
                     {msg}"
                );
            }

            let mut c = clear.conn().expect("conn");
            c.exec_drop(
                "DELETE FROM api_keys WHERE id = :id",
                params! { "id" => id },
            )
            .expect("race scaffolding must not swallow a deadlock or delete failure");
            del_store
                .put_key(&sample_key(id, "g_relive"))
                .expect("the restoring put must not swallow a deadlock");
        }
    });

    putter.join().expect("put_key thread must not panic/error");
    deleter
        .join()
        .expect("delete_key thread must not panic/error");
}

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

/// A `.and_then(|v| v.parse().ok()).unwrap_or(0)` read would silently turn a corrupt, non-numeric stored value into version 0, indistinguishable from "fresh install" -- the same "looks already migrated but isn't" failure mode the module doc warns about, reached via a corrupt marker instead of a query error.
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

/// The `usage_windows` reads must pin `bucket_scope = 'key'`: it sits inside the primary key, and a row of another scope for the same bucket id and window is not this bucket's usage.
#[test]
fn get_usage_ignores_usage_windows_rows_of_another_scope() {
    let Some(s) = fresh_store() else { return };
    let bucket = "vk_scope_pin_unique";
    let window = 7_700_000_000_123u64;
    s.add_usage(
        bucket,
        window,
        &UsageDelta {
            requests: 2,
            billable_requests: 1,
            models: vec![ModelTokensDelta {
                scale: 6,
                model: "m-key-scope".to_string(),
                usage_units: units(&[(UNIT_INPUT, 10), (UNIT_OUTPUT, 5), ("images", 4)]),
            }],
        },
    )
    .unwrap();
    let mut conn = s.pool.get_conn().unwrap();
    conn.exec_drop(
        "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests, \
         billable_requests, tokens_input, tokens_output) VALUES (:w, 'group', :b, 'm-group-scope', 40, 30, 900, 800)",
        params! { "w" => window, "b" => bucket },
    )
    .unwrap();

    conn.exec_drop(
        "INSERT INTO usage_window_units (window_start, bucket_scope, bucket_id, model, unit, count) \
         VALUES (:w, 'group', :b, 'm-key-scope', 'images', 99), \
                (:w, 'group', :b, 'm-group-scope', 'images', 77)",
        params! { "w" => window, "b" => bucket },
    )
    .unwrap();
    let back = s.get_usage(bucket, window).unwrap();
    conn.exec_drop(
        "DELETE FROM usage_windows WHERE window_start = :w AND bucket_id = :b",
        params! { "w" => window, "b" => bucket },
    )
    .unwrap();
    conn.exec_drop(
        "DELETE FROM usage_window_units WHERE window_start = :w AND bucket_id = :b",
        params! { "w" => window, "b" => bucket },
    )
    .unwrap();
    assert_eq!((back.requests, back.billable_requests), (2, 1), "{back:?}");
    assert_eq!(back.models.len(), 1, "{back:?}");
    assert_eq!(back.models[0].model, "m-key-scope", "{back:?}");
    assert_eq!(back.models[0].tier(UNIT_INPUT), 10, "{back:?}");
    assert_eq!(
        back.models[0].usage_units.get("images"),
        Some(&4),
        "{back:?}"
    );
}

/// `model`/`provider` in the metering tables are byte-exact keys (v11, D19), as in every other store: `GPT-4o` and `gpt-4o` are two cells, and each cell's units land on it and only on it.
#[test]
fn list_metering_keeps_model_spellings_apart_and_units_on_their_cell() {
    let Some(s) = fresh_store() else { return };
    let key = "vk_meter_collation_unique";
    s.put_key(&sample_key(key, "g")).unwrap();
    let bucket = 20_991_231u64;
    let mut conn = s.pool.get_conn().unwrap();
    let clean = |conn: &mut PooledConn| {
        for t in ["usage_metering_units", "usage_metering"] {
            conn.exec_drop(
                format!("DELETE FROM {t} WHERE key_id = :k AND bucket = :b"),
                params! { "k" => key, "b" => format!("{bucket:010}") },
            )
            .unwrap();
        }
    };
    clean(&mut conn);
    let delta = |model: &str, usage_units: BTreeMap<String, u64>| MeteringDelta {
        scale: 6,
        key_id: key.to_string(),
        bucket,
        model: model.to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: "v1".to_string(),
        priced_from_ms: 0,
        usage_units,
    };
    s.add_metering(&delta("GPT-4o", BTreeMap::new())).unwrap();
    s.add_metering(&delta("gpt-4o", units(&[("tool_calls", 5)])))
        .unwrap();
    let rows: Vec<_> = s
        .list_metering(bucket)
        .unwrap()
        .into_iter()
        .filter(|r| r.key_id == key)
        .collect();
    clean(&mut conn);
    assert_eq!(rows.len(), 2, "two spellings, two cells: {rows:?}");
    let cell = |model: &str| {
        rows.iter()
            .find(|r| r.model == model)
            .unwrap_or_else(|| panic!("no {model} cell: {rows:?}"))
    };
    assert_eq!(
        cell("gpt-4o").usage_units.get("tool_calls"),
        Some(&5),
        "{rows:?}"
    );
    assert_eq!(cell("gpt-4o").requests, 1, "{rows:?}");
    assert!(cell("GPT-4o").usage_units.is_empty(), "{rows:?}");
    assert_eq!(cell("GPT-4o").requests, 1, "{rows:?}");
}

#[test]
fn stamp_schema_version_never_lowers_a_newer_marker() {
    let Some(s) = fresh_store() else { return };
    let mut conn = s.pool.get_conn().unwrap();
    let table = scratch_meta_table(&mut conn, "stampversion");
    let read = |conn: &mut PooledConn| -> Option<String> {
        conn.query_first(format!("SELECT v FROM {table} WHERE k = 'schema_version'"))
            .unwrap()
    };
    let mut results = Vec::new();

    MysqlStore::stamp_schema_version(&mut conn, &table).unwrap();
    results.push(read(&mut conn));

    conn.query_drop(format!(
        "UPDATE {table} SET v = '3' WHERE k = 'schema_version'"
    ))
    .unwrap();
    MysqlStore::stamp_schema_version(&mut conn, &table).unwrap();
    results.push(read(&mut conn));

    let newer = (SCHEMA_VERSION + 1).to_string();
    conn.query_drop(format!(
        "UPDATE {table} SET v = '{newer}' WHERE k = 'schema_version'"
    ))
    .unwrap();
    MysqlStore::stamp_schema_version(&mut conn, &table).unwrap();
    results.push(read(&mut conn));
    conn.query_drop(format!("DROP TABLE {table}")).unwrap();
    let current = Some(SCHEMA_VERSION.to_string());
    assert_eq!(results[0], current, "no row -> stamped");
    assert_eq!(results[1], current, "older marker -> raised");
    assert_eq!(
        results[2].as_deref(),
        Some(newer.as_str()),
        "a newer marker must not be lowered"
    );
}

fn server_error(code: u16, state: &str, message: &str) -> crate::mysqlwire::Error {
    crate::mysqlwire::Error::MySqlError(crate::mysqlwire::MySqlError {
        code,
        state: state.into(),
        message: message.into(),
    })
}

/// Boot DDL races are recognised by server error code, not by English message text.
#[test]
fn ddl_race_is_recognised_by_code_not_by_english_text() {
    assert!(crate::MysqlStore::is_ddl_race(&server_error(
        1061,
        "42000",
        "Doppelter Schlüsselname 'idx'"
    )));
    assert!(crate::MysqlStore::is_ddl_race(&server_error(
        1050,
        "42S01",
        "Tabelle 't' existiert bereits"
    )));
    assert!(
        !crate::MysqlStore::is_ddl_race(&server_error(
            1146,
            "42S02",
            "Table 'x.y' already exists in some other sense"
        )),
        "an unrelated error whose text says 'already exists' is not a race"
    );
}

#[test]
fn deadlock_is_recognised_by_code_not_by_english_text() {
    let e = server_error(
        1213,
        "40001",
        "Verklemmung beim Versuch, eine Sperre zu bekommen",
    );
    assert!(crate::MysqlStore::is_deadlock(&format!(
        "schema init failed: {e}\nstatement: CREATE INDEX x"
    )));
    assert!(!crate::MysqlStore::is_deadlock(
        "schema init failed: ERROR 1146 (42S02): Deadlock found in a message"
    ));
}

/// `revoke_credential` must reject an unknown/typo'd id loudly, not silently return `Ok(())`.
#[test]
fn revoke_credential_rejects_an_unknown_id() {
    let Some(s) = fresh_store() else { return };
    let err = s
        .revoke_credential("cred_does_not_exist_anywhere", "cleanup")
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("revoke_credential: unknown id 'cred_does_not_exist_anywhere'"),
        "must name the real reason: {err}"
    );
}

/// `put_credential` must reject a `public_id` collision against a DIFFERENT credential's id, not silently corrupt the unrelated row via `ON DUPLICATE KEY UPDATE`, which would overwrite that row's `id`/`secret` and leave its `key_id`/`slot` untouched.
#[test]
fn put_credential_rejects_a_public_id_collision_against_a_different_credential() {
    let Some(s) = fresh_store() else { return };
    let k1 = sample_key("vk_pubcol_a", "g");
    let k2 = sample_key("vk_pubcol_b", "g");
    s.put_key(&k1).unwrap();
    s.put_key(&k2).unwrap();
    s.put_credential(&sample_credential("vk_pubcol_a", "AKIA_SHARED_PUBID", 0))
        .unwrap();

    let mut colliding = sample_credential("vk_pubcol_b", "AKIA_SHARED_PUBID", 0);
    colliding.meta.id = "cred_genuinely_different_id".to_string();
    let err = s.put_credential(&colliding).unwrap_err();
    assert!(
        err.to_string().contains(
            "put_credential: public_id 'AKIA_SHARED_PUBID' is already in use for kind 'sigv4'"
        ),
        "must name the public_id clash in the family's words: {err}"
    );

    let untouched = s
        .lookup_credential_secret("sigv4", "AKIA_SHARED_PUBID")
        .unwrap()
        .unwrap();
    assert_eq!(untouched.meta.key_id, "vk_pubcol_a");
}

/// `put_credential` must also reject a PRIMARY KEY (`id`) collision against a row that belongs to a DIFFERENT `key_id`/`slot` -- the third of the table's 3 unique keys, and the one a public_id-only guard does not cover.
#[test]
fn put_credential_rejects_an_id_collision_against_a_different_key_or_slot() {
    let Some(s) = fresh_store() else { return };
    let k1 = sample_key("vk_idcol_a", "g");
    let k2 = sample_key("vk_idcol_b", "g");
    s.put_key(&k1).unwrap();
    s.put_key(&k2).unwrap();
    let original = sample_credential("vk_idcol_a", "AKIA_IDCOL_ORIG", 0);
    s.put_credential(&original).unwrap();

    let mut colliding = sample_credential("vk_idcol_b", "AKIA_IDCOL_NEW", 1);
    colliding.meta.id = original.meta.id.clone();
    let err = s.put_credential(&colliding).unwrap_err();

    assert!(
        err.to_string().contains("put_credential: duplicate ")
            && err.to_string().contains("PRIMARY")
            && !err.to_string().contains(&original.meta.id),
        "must be a duplicate-key rejection naming the constraint, not the value: {err}"
    );

    let untouched = s
        .lookup_credential_secret("sigv4", "AKIA_IDCOL_ORIG")
        .unwrap()
        .unwrap();
    assert_eq!(untouched.meta.key_id, "vk_idcol_a");
    assert_eq!(untouched.meta.slot, 0);
}

/// DETERMINISTIC: `delete_key` is held mid-transaction by a lock on the key's credential row (it takes the `api_keys` row lock first and reaches the credential delete second), and a third connection reads while it waits.
#[test]
fn delete_key_shows_nothing_of_itself_until_it_commits_both_halves() {
    let Some(s) = fresh_store() else { return };
    let (key, public_id) = (
        format!("vk_pause_{}", std::process::id()),
        format!("AKIA_PAUSE_{}", std::process::id()),
    );
    s.put_key_with_credential(
        &sample_key(&key, "g"),
        &sample_credential(&key, &public_id, 0),
    )
    .unwrap();

    let mut holder = s.conn().unwrap();
    holder.query_drop("START TRANSACTION").unwrap();
    holder
        .exec_drop(
            "SELECT id FROM credentials WHERE key_id = :k FOR UPDATE",
            params! { "k" => &key },
        )
        .unwrap();

    let mut reader = s.conn().unwrap();
    let state = |reader: &mut PooledConn| -> (Option<u64>, i64) {
        let tombstone: Option<Option<u64>> = reader
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :k",
                params! { "k" => &key },
            )
            .unwrap();
        let creds: i64 = reader
            .exec_first(
                "SELECT COUNT(*) FROM credentials WHERE key_id = :k",
                params! { "k" => &key },
            )
            .unwrap()
            .unwrap();
        (tombstone.unwrap(), creds)
    };
    std::thread::scope(|sc| {
        let deleter = sc.spawn(|| s.delete_key(&key));

        let mut probe = s.conn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let mut tx = probe.start_transaction(mysql::TxOpts::default()).unwrap();
            let busy = tx
                .exec_first::<Option<u64>, _, _>(
                    "SELECT deleted_at FROM api_keys WHERE id = :k FOR UPDATE NOWAIT",
                    params! { "k" => &key },
                )
                .is_err();
            let _ = tx.rollback();
            if busy {
                break;
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            state(&mut reader),
            (None, 1),
            "while delete_key waits, none of it is visible"
        );
        holder.query_drop("COMMIT").unwrap();
        deleter.join().unwrap().unwrap();
    });
    let (tombstone, creds) = state(&mut reader);
    assert!(tombstone.is_some() && creds == 0, "{tombstone:?} {creds}");
}

/// Real proof that `delete_key`'s tombstone-write and credential-destroy are ONE atomic transaction, not two: a concurrent connection contends for the SAME row lock `delete_key` holds for its whole transaction.
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

        for _ in 0..500 {
            let mut probe = conn.start_transaction(mysql::TxOpts::default()).unwrap();

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
mod store_conformance;

/// The cross-backend `Store` conformance checks, answered by this backend — EVERY check the suite offers, including the plane-record battery and the two interleaved-run regressions busbar's own reference backend runs.
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
    fn shared_store() -> Option<&'static MysqlStore> {
        static STORE: std::sync::OnceLock<Option<MysqlStore>> = std::sync::OnceLock::new();
        STORE
            .get_or_init(|| {
                let url = test_url()?;
                let s = MysqlStore::connect(&url).expect("connect");

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
        conf::assert_put_key_does_not_resurrect_a_tombstone(&**store, &ns);
    }

    #[test]
    fn delete_key_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("del", 0) else {
            return;
        };
        conf::assert_delete_key_unknown_id_is_an_error(&**store, &ns);
    }

    #[test]
    fn revoke_credential_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("rev", 0) else {
            return;
        };
        conf::assert_revoke_credential_unknown_id_is_an_error(&**store, &ns);
    }

    #[test]
    fn put_credential_requires_a_live_key() {
        let Some((store, ns)) = setup("pcl", 0) else {
            return;
        };
        conf::assert_put_credential_requires_a_live_key(&**store, &ns);
    }

    #[test]
    fn put_key_with_credential_is_atomic() {
        let Some((store, ns)) = setup("pkc", 0) else {
            return;
        };
        conf::assert_put_key_with_credential_is_atomic(&**store, &ns);
    }

    #[test]
    fn plane_task_upsert_get_list() {
        let Some((store, ns)) = setup("ptk", 0) else {
            return;
        };
        conf::assert_plane_task_upsert_get_list(&**store, &ns);
    }

    #[test]
    fn plane_event_chain_is_ordered_by_seq() {
        let Some((store, ns)) = setup("pev", 0) else {
            return;
        };
        conf::assert_plane_event_chain_is_ordered_by_seq(&**store, &ns);
    }

    #[test]
    fn plane_call_parents_enumerated() {
        let Some((store, ns)) = setup("pcp", 0) else {
            return;
        };
        conf::assert_plane_call_parents_enumerated(&**store, &ns);
    }

    #[test]
    fn plane_demotion_upsert_list_delete() {
        let Some((store, ns)) = setup("pdm", 0) else {
            return;
        };
        conf::assert_plane_demotion_upsert_list_delete(&**store, &ns);
    }

    #[test]
    fn plane_purge_honours_the_cutoff() {
        let _guard = lock_plane_purge();
        let Some((store, ns)) = setup("ppc", 0) else {
            return;
        };
        conf::assert_plane_purge_honours_the_cutoff(&**store, &ns);
    }

    #[test]
    fn plane_purge_task_keeps_active_rows() {
        let _guard = lock_plane_purge();
        let Some((store, ns)) = setup("ppt", 0) else {
            return;
        };
        conf::assert_plane_purge_task_keeps_active_rows(&**store, &ns);
    }

    #[test]
    fn plane_token_is_single_use() {
        let Some((store, ns)) = setup("ptu", 0) else {
            return;
        };
        conf::assert_plane_token_is_single_use(&**store, &ns);
    }

    #[test]
    fn plane_purge_honours_the_cutoff_survives_two_interleaved_runs() {
        let _guard = lock_plane_purge();
        let Some((store, ns_a)) = setup("ppcA", 0) else {
            return;
        };
        let ns_b = ns("ppcB");
        reset(store, &ns_b, 0);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&**store, &ns_a));
            let b = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&**store, &ns_b));
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
            let a =
                scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&**store, &ns_a));
            let b =
                scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&**store, &ns_b));
            a.join().expect("run A must not panic");
            b.join().expect("run B must not panic");
        });
    }
}

/// Every plane-record purge in this binary takes this ONE lock.
static PLANE_PURGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_plane_purge() -> std::sync::MutexGuard<'static, ()> {
    PLANE_PURGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Delete every row of `kind` under each identity (a `call` principal, a `task` id, a `task_event`'s task, a `demotion` server) — this test's own rows and no one else's.
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

/// A `call` record in the envelope the engine writes: parent = the principal, keyed by `seq`, the body a neutral journal body.
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

/// THE TEST THAT MATTERS.
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

/// The boot enumeration: a restart has to resume a chain for a principal this process has not yet seen, so the store must be able to name every principal holding records.
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

    assert_eq!(calls_of(&reopened, a).len(), 2);
    assert_eq!(calls_of(&reopened, b).len(), 1);
    assert!(
        calls_of(&reopened, "vk_mcp_nonexistent").is_empty(),
        "a principal with no records reads back empty, not an error"
    );

    assert!(!reopened
        .list_plane_record_parents("task_event")
        .unwrap()
        .iter()
        .any(|p| p == a || p == b));
    reset_plane(&reopened, "call", &[a, b]);
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did not perform is worse than one that reports nothing purged.
#[test]
fn purge_calls_before_deletes_and_returns_a_real_count() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("purge_exact") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).expect("connect");
    let p = "vk_mcp_purge";
    reset_plane(&store, "call", &[p]);

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
    assert_eq!(
        purged, 1,
        "exactly the row strictly before the cutoff is removed"
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
    assert_eq!(rest, 2, "the remaining two rows must actually be removed");
    assert!(calls_of(&store, p).is_empty());
}

/// A purge of one kind never touches another kind's rows, however old — retention is part of each kind's contract, not a table-wide sweep.
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

/// A record arriving on a `(principal, seq)` that already has one is settled the way the contract settles it: IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and is an error.
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

    let forked = call_rec(p, 1, 2_000_000_100, "", "h2-second-writer");
    let err = store
        .append_plane_record(forked.view())
        .expect_err("a different record at an occupied (principal, seq) is a fork and must error");
    assert_eq!(
        err.0,
        busbar_contract::abi::sdk::store::fork::chain_fork("call", p, 1).0,
        "the refusal is the SDK's chain_fork text"
    );
    for echoed in ["h1", "h2-second-writer", "srv_read_file"] {
        assert!(
            !err.0.contains(echoed),
            "the error must not echo stored or caller content back: {echoed}"
        );
    }
    assert_eq!(
        calls_of(&store, p)[0]["hash"],
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    let mut moved = rec.clone();
    moved.ts += 1;
    store
        .append_plane_record(moved.view())
        .expect_err("a record that differs only in its envelope is still a fork and must error");
    reset_plane(&store, "call", &[p]);
}

/// THE CROSS-PRINCIPAL READ.
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

/// Timestamps are BANDED.
const TASK_PURGE_BAND_TOP: u64 = 1_000_100_000;
const TASK_LIVE_TS: u64 = 2_000_000_000;

/// A `task` record in the envelope the engine writes: upsert by id, `ts` = the task's `updated_at`, the terminal/active verdict on the typed `disposition` — the ENGINE decides it; the store only reads the column.
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

    assert!(reopened.get_plane_record("demotion", t1).unwrap().is_none());
    reset_tasks(&reopened, &[t1, t2]);
}

/// `list_plane_records(All)` is deliberately UNFILTERED.
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

/// The per-task provenance chain, read back off the server after a reconnect.
#[test]
fn a_task_event_chain_survives_a_reconnect_and_still_links() {
    let Some(url) = test_url() else { return };
    let (t1, t2) = ("t_chain_1", "t_chain_2");
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tasks(&store, &[t1, t2]);

        store
            .append_plane_record(event_rec(t1, 2, "task.working", "e1", "e2").view())
            .unwrap();
        store
            .append_plane_record(event_rec(t1, 1, "task.submitted", "", "e1").view())
            .unwrap();
        store
            .append_plane_record(event_rec(t1, 3, "task.interrupted", "e2", "e3").view())
            .unwrap();

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

/// A replayed `(task_id, seq)` is settled like every other append: IDENTICAL is the at-least-once retry and succeeds without duplicating the row; DIFFERENT is refused as a fork and the stored record stands.
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
    let err = store
        .append_plane_record(rewritten.view())
        .expect_err("a DIFFERENT event at an occupied (task, seq) is a fork and must be refused");
    assert_eq!(
        err.0,
        busbar_contract::abi::sdk::store::fork::chain_fork("task_event", t, 1).0,
        "the refusal is the SDK's chain_fork text"
    );
    for echoed in ["e1", "e1-rewritten", "task.submitted"] {
        assert!(
            !err.0.contains(echoed),
            "the error must not echo stored or caller content back: {echoed}"
        );
    }
    let got = events_of(&store, t);
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0]["hash"], "e1",
        "the refused rewrite must not replace the stored link"
    );
    reset_tasks(&store, &[t]);
}

/// The band the purge tests own, cleared wholesale.
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

/// Retention drops TERMINAL rows only, strictly older than the cutoff, and returns a count it actually performed.
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

    store
        .upsert_plane_record(terminal_task("t_purge_at_cutoff", "completed", 1_000_000_200).view())
        .unwrap();
    store
        .upsert_plane_record(terminal_task("t_purge_newer", "completed", 1_000_000_300).view())
        .unwrap();

    let purged = store
        .purge_plane_records(
            "task",
            1_000_000_200,
            busbar_contract::records::Retention::TerminalOnly,
        )
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
            .purge_plane_records(
                "task",
                1_000_000_200,
                busbar_contract::records::Retention::TerminalOnly
            )
            .unwrap(),
        0,
        "re-running the same purge removes nothing"
    );
    clear_purge_band(&store);
}

/// Retention has to bound the EVENT chain too.
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
            .purge_plane_records(
                "task",
                1_000_000_200,
                busbar_contract::records::Retention::TerminalOnly
            )
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

/// The envelope's `seq` and `ts` round-trip up to `i64::MAX`, the largest value every store of the family can hold (R16); one above is refused, not stored.
#[test]
fn the_plane_store_round_trips_up_to_i64_max_and_refuses_above() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let t = "t_full_range";
    reset_tasks(&store, &[t]);
    let top = i64::MAX as u64;

    let task = active_task(t, "working", top);
    store
        .upsert_plane_record(task.view())
        .expect("i64::MAX is storable");
    let got = get_task(&store, t).expect("the task must read back at all");
    assert_eq!(got["updated_at"].as_u64(), Some(top));
    assert!(
        all_task_ids(&store).contains(&t.to_string()),
        "an i64::MAX ts must not break the listing"
    );
    let too_big = active_task(t, "working", top + 1);
    let err = store.upsert_plane_record(too_big.view()).unwrap_err();
    assert!(
        err.to_string().contains("exceeds the storable range"),
        "{err}"
    );

    let mut ev = event_rec(t, top, "task.submitted", "", "e1");
    ev.ts = top;
    store
        .append_plane_record(ev.view())
        .expect("seq/ts hold i64::MAX");
    let events = events_of(&store, t);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["seq"].as_u64(), Some(top));
    store
        .append_plane_record(ev.view())
        .expect("the replay at i64::MAX must compare identical");
    reset_tasks(&store, &[t]);
}

/// Two task ids differing only in CASE are two different tasks, and the primary key has to agree.
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

/// THE LIVE URL, OR A FAILURE.
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

/// Per-process namespacing.
fn trust_ns(tag: &str) -> String {
    format!("{}_{}", tag, std::process::id())
}

/// Synthetic caller time for records; replay expiry is governed by the database clock.
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

/// A DEMOTION OUTLIVES THE PROCESS THAT RECORDED IT.
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

/// SERVER IDS DIFFERING ONLY IN CASE ARE DISTINCT UPSTREAMS: quarantining one must not overwrite the other's record, and clearing one must not clear both.
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

/// THE SPENT-APPROVAL LEDGER ACROSS A RESTART.
#[test]
fn a_reconnected_store_refuses_a_second_redemption_of_the_same_approval() {
    let url = require_test_url();
    let (spent, fresh) = (trust_ns("nonce_restart"), trust_ns("nonce_restart_other"));
    {
        let store = MysqlStore::connect(&url).expect("connect");
        reset_tokens(&store, "ask", &[&spent, &fresh]);
        assert!(
            store
                .redeem_plane_token("ask", &spent, u64::MAX, TRUST_NOW)
                .unwrap(),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        drop(store);
    }

    let reopened = MysqlStore::connect(&url).expect("reconnect");
    assert!(
        !reopened
            .redeem_plane_token("ask", &spent, u64::MAX, TRUST_NOW + 1)
            .unwrap(),
        "a restart handed a spent approval back. The approval has not lapsed, so the only thing \
         that changed is that the process which recorded the redemption is gone"
    );

    assert!(
        reopened
            .redeem_plane_token("ask", &fresh, u64::MAX, TRUST_NOW + 2)
            .unwrap(),
        "a different approval is not the one that was spent"
    );

    assert!(
        reopened
            .redeem_plane_token("ask_other_kind", &spent, u64::MAX, TRUST_NOW + 2)
            .unwrap(),
        "a token spent under one kind must not read as spent under another"
    );
    reset_tokens(&reopened, "ask", &[&spent, &fresh]);
    reset_tokens(&reopened, "ask_other_kind", &[&spent]);
}

/// TWO CONNECTIONS ARE TWO NODES OF A FLEET, and this is the arrangement the durable ledger exists for: the second redemption needs no timing skill at all, only a load balancer.
#[test]
fn a_second_node_cannot_redeem_an_approval_the_first_already_spent() {
    let url = require_test_url();
    let nonce = trust_ns("nonce_fleet");
    let node_a = MysqlStore::connect(&url).expect("node A connects");
    let node_b = MysqlStore::connect(&url).expect("node B connects");
    reset_tokens(&node_a, "ask", &[&nonce]);

    assert!(node_a
        .redeem_plane_token("ask", &nonce, u64::MAX, TRUST_NOW)
        .unwrap());
    assert!(
        !node_b
            .redeem_plane_token("ask", &nonce, u64::MAX, TRUST_NOW)
            .unwrap(),
        "a second node of the same deployment redeemed an approval the first already spent"
    );
    reset_tokens(&node_a, "ask", &[&nonce]);
}

/// NONCES DIFFERING ONLY IN CASE ARE DISTINCT APPROVALS — the sharpest instance of the collation hazard: under a case-insensitive key a fresh approval would be REFUSED.
#[test]
fn nonces_differing_only_in_case_are_distinct_approvals() {
    let url = require_test_url();
    let (lower, upper) = (trust_ns("nonce_case_ab"), trust_ns("nonce_case_AB"));
    let store = MysqlStore::connect(&url).expect("connect");
    reset_tokens(&store, "ask", &[&lower, &upper]);

    assert!(store
        .redeem_plane_token("ask", &lower, u64::MAX, TRUST_NOW)
        .unwrap());
    assert!(
        store
            .redeem_plane_token("ask", &upper, u64::MAX, TRUST_NOW)
            .unwrap(),
        "an approval whose nonce differs only in case from a spent one is a DIFFERENT approval"
    );
    reset_tokens(&store, "ask", &[&lower, &upper]);
}

/// CONCURRENT REDEMPTION IS THE ATTACK, not the corner case.
#[test]
fn exactly_one_of_many_racing_nodes_wins_the_redemption() {
    let url = require_test_url();
    let nonce = trust_ns("nonce_race");
    let cleanup = MysqlStore::connect(&url).expect("connect");
    reset_tokens(&cleanup, "ask", &[&nonce]);
    drop(cleanup);

    let n = 8usize;
    let nodes: Vec<_> = (0..n)
        .map(|_| MysqlStore::connect(&url).expect("a racing node connects"))
        .collect();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let winners: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = nodes
            .into_iter()
            .map(|node| {
                let nonce = nonce.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    node.redeem_plane_token("ask", &nonce, u64::MAX, TRUST_NOW)
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

/// A live redemption removes old rows using database time and retains still-live rows.
#[test]
fn redeeming_evicts_entries_whose_token_can_no_longer_be_presented() {
    const EXPIRED_AT_EPOCH: u64 = u64::MIN;
    let url = require_test_url();
    let kind = trust_ns("expiry_sweep");
    let (short, long, other) = (
        trust_ns("nonce_short"),
        trust_ns("nonce_long"),
        trust_ns("nonce_sweeper"),
    );
    let store = MysqlStore::connect(&url).expect("connect");
    reset_tokens(&store, &kind, &[&short, &long, &other]);

    store
        .conn()
        .unwrap()
        .exec_drop(
            "INSERT INTO plane_tokens(kind,token,expires_at) VALUES (:kind,:token,:expiry)",
            params! {"kind"=>&kind,"token"=>&short,"expiry"=>EXPIRED_AT_EPOCH},
        )
        .unwrap();
    assert!(store
        .redeem_plane_token(&kind, &long, u64::MAX, TRUST_NOW)
        .unwrap());

    let later = TRUST_NOW + 11;
    assert!(store
        .redeem_plane_token(&kind, &other, u64::MAX, later)
        .unwrap());

    let present = |nonce: &str| -> bool {
        let mut conn = store.conn().expect("conn");
        let n: Option<u64> = conn
            .exec_first(
                "SELECT COUNT(*) FROM plane_tokens WHERE kind = :kind AND token = :n",
                params! { "kind" => &kind, "n" => nonce },
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
    reset_tokens(&store, &kind, &[&short, &long, &other]);
}

/// The strict boundary is checked against the database clock, not the caller clock.
#[test]
fn the_sweep_keeps_an_entry_expiring_exactly_at_now() {
    token_clock::assert_strict_boundary();
}

#[test]
fn a_private_token_kind_preserves_a_replay_across_caller_clock_changes() {
    let url = require_test_url();
    let (edge, other) = (trust_ns("nonce_edge"), trust_ns("nonce_edge_sweeper"));
    let store = MysqlStore::connect(&url).expect("connect");
    // Preserve the audit's private-kind replay witness independently of caller clock values.
    let kind = trust_ns("ask_edge");
    reset_tokens(&store, &kind, &[&edge, &other]);
    let expires = TRUST_NOW + 10;
    assert!(store
        .redeem_plane_token(&kind, &edge, expires, TRUST_NOW)
        .unwrap());
    // The caller's expiry boundary must not make this live token redeemable twice.
    assert!(store
        .redeem_plane_token(&kind, &other, expires + 900, expires)
        .unwrap());
    assert!(
        !store
            .redeem_plane_token(&kind, &edge, expires, expires)
            .unwrap(),
        "a replay remains refused when the caller reports the entry's expiry"
    );
    reset_tokens(&store, &kind, &[&edge, &other]);
}

/// THE TOP OF THE SIGNED RANGE STORES FAITHFULLY: `i64::MAX` is storable and readable back, both as
/// a plane record `ts` and as a token expiry (redeemed at the ordinary `TRUST_NOW`). This does NOT
/// cover the range above `i64::MAX` or a clamped-high `now`: token expiries are `BIGINT UNSIGNED`
/// and accepted up to `u64::MAX`, and that range, with the `now` boundaries, is pinned by
/// `token_redemption_preserves_unsigned_expiry_and_clock_boundaries`.
#[test]
fn the_trust_state_stores_the_full_signed_range() {
    let url = require_test_url();
    let (server, nonce) = (trust_ns("srv_range"), trust_ns("nonce_range"));
    let store = MysqlStore::connect(&url).expect("connect");
    reset_plane(&store, "demotion", &[&server]);
    reset_tokens(&store, "ask", &[&nonce]);

    let top = i64::MAX as u64;
    store
        .upsert_plane_record(demotion_rec(&server, "tool-drift", top).view())
        .expect("i64::MAX is storable");
    assert_eq!(
        demotions(&store)
            .into_iter()
            .find(|d| d["server"] == server.as_str())
            .expect("the row must be there")["recorded_at"]
            .as_u64(),
        Some(top)
    );
    assert!(
        store
            .redeem_plane_token("ask", &nonce, top, TRUST_NOW)
            .unwrap(),
        "an expires_at at the top of the range is storable here and must redeem normally"
    );
    assert!(
        !store
            .redeem_plane_token("ask", &nonce, top, TRUST_NOW + 1)
            .unwrap(),
        "and the row it wrote must still be found on the replay"
    );
    reset_plane(&store, "demotion", &[&server]);
    reset_tokens(&store, "ask", &[&nonce]);
}

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

/// LIVE means all three: present, still ACTIVE, and inside its deadline.
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

/// Every scope KIND round-trips as itself.
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

    let mut conn = s.conn().unwrap();
    let pools: Option<Option<String>> = conn
        .query_first("SELECT allowed_pools FROM api_keys WHERE id = 'vk_scopes_mcp_only'")
        .unwrap();
    assert_eq!(
        pools.flatten().map(|p| p.replace(' ', "")),
        Some("[]".to_string())
    );
}

/// `idp_provider` is persisted with the row and read back.
#[test]
fn idp_provider_round_trips() {
    let Some(s) = fresh_store() else { return };
    let mut k = sample_key("vk_idp", "g");
    k.idp_provider = Some("github".into());
    s.put_key(&k).unwrap();
    let back = s.get_key("vk_idp").unwrap().unwrap();
    assert_eq!(back.idp_provider.as_deref(), Some("github"));
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

/// OPEN usage units (everything but the reserved four) round-trip through `put_usage`, accumulate through `add_usage` with the same floor-at-zero rule, and are replaced — not merged — by an absolute `put_usage`.
#[test]
fn open_usage_units_round_trip_accumulate_and_floor_at_zero() {
    let Some(s) = fresh_store() else { return };
    let ledger = UsageLedger {
        requests: 2,
        billable_requests: 2,
        models: vec![ModelTokens {
            scale: 6,
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
                scale: 6,
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

    let replaced = UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            scale: 6,
            model: "rerank-x".into(),
            usage_units: units(&[("search_units", 1)]),
        }],
    };
    s.put_usage("vk_open_units", 1_000_201, &replaced).unwrap();
    assert_eq!(s.get_usage("vk_open_units", 1_000_201).unwrap(), replaced);
}

fn metering_delta(key: &str, bucket: u64, priced_from_ms: u64) -> MeteringDelta {
    MeteringDelta {
        scale: 6,
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

/// DECISION #79: `priced_from_ms` JOINS THE ACCRUAL KEY.
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
}

mod slots_tests;
mod task_age_retention;

#[path = "tests/migration_ownership.rs"]
mod migration_ownership;
#[path = "tests/migration_revoked_revisions.rs"]
mod migration_revoked_revisions;
mod schema_fixtures;

/// A throwaway database, dropped on scope exit. Migration tests need a whole schema of their own:
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
        let root_url = root_url(&url);
        let root = Pool::new(Opts::from_url(&raw_mysql_url(&root_url)).unwrap()).unwrap();
        let mut c = root.get_conn().unwrap();
        c.query_drop(format!("CREATE DATABASE {name}")).unwrap();
        c.query_drop(format!("GRANT ALL PRIVILEGES ON {name}.* TO 'busbar'@'%'"))
            .unwrap();
        let mut db_url = url::Url::parse(&url).expect("fixture MySQL URL");
        db_url.set_path(&format!("/{name}"));
        let db_url = db_url.to_string();
        Some(Self {
            root,
            name,
            url: db_url,
        })
    }

    /// Fault-injection triggers require the fixture administrator when binary logging is enabled.
    /// Product connections continue to use the unprivileged database URL.
    fn admin_conn(&self) -> PooledConn {
        let mut conn = self.root.get_conn().unwrap();
        conn.query_drop(format!("USE `{}`", self.name)).unwrap();
        conn
    }

    fn conn(&self) -> PooledConn {
        let pool = Pool::new(Opts::from_url(&raw_mysql_url(&self.url)).unwrap()).unwrap();
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

/// THE UPGRADE THAT MUST NOT BREAK: a database written by the RELEASED 1.5.x plugin (v1.0.6, schema v3 — its DDL is reproduced verbatim in `schema_fixtures`) upgrades IN PLACE on the first 1.6.0 boot.
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

    store.put_key(&sample_key("vk_new16", "g")).unwrap();
    assert!(store.get_key("vk_new16").unwrap().unwrap().revision > 41);

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

    store
        .upsert_plane_record(active_task("t_after_upgrade", "working", TASK_LIVE_TS).view())
        .unwrap();
    assert!(store
        .get_plane_record("task", "t_after_upgrade")
        .unwrap()
        .is_some());
    assert!(store
        .redeem_plane_token("ask", "n_after_upgrade", u64::MAX, TRUST_NOW)
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

    let again = MysqlStore::connect(&db.url).expect("a second boot of an upgraded database");
    assert_eq!(again.list_keys().unwrap().len(), 5);
    assert_eq!(again.list_metering(20_260_731).unwrap().len(), 2);
    assert!(again
        .get_plane_record("task", "t_after_upgrade")
        .unwrap()
        .is_some());
}

/// A pre-release 1.6.0 development database (v4..v6) carried plane state in per-protocol tables.
#[test]
fn unsupported_v6_development_database_is_refused_without_changing_plane_state() {
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

    let snapshot = || {
        let mut conn = db.conn();
        [
            "tasks",
            "task_events",
            "mcp_demotions",
            "spent_ask_states",
            "mcp_calls",
        ]
        .into_iter()
        .map(|table| {
            let rows: Vec<mysql::Row> = conn.query(format!("SELECT * FROM {table}")).unwrap();
            let mut rows: Vec<String> = rows.into_iter().map(|row| format!("{row:?}")).collect();
            rows.sort();
            assert!(!rows.is_empty(), "the fixture has data in {table}");
            (table, rows)
        })
        .collect::<Vec<_>>()
    };
    let before = snapshot();
    let shape = schema_shape(&db);
    for _ in 0..2 {
        let error = MysqlStore::connect(&db.url)
            .err()
            .expect("unsupported schema 6 is refused");
        assert!(error.contains("newer than this build"), "{error}");
        assert_eq!(schema_version_of(&db), "6", "not restamped");
        assert_eq!(schema_shape(&db), shape, "no schema mutation");
        assert_eq!(
            snapshot(),
            before,
            "all legacy plane state remains unchanged"
        );
    }
}

const FIXTURE_DUMP_1_5_5: &str = include_str!("../tests/fixtures/1.5.5/dump.sql");
const FIXTURE_ROWS_1_5_5: &str = include_str!("../tests/fixtures/1.5.5/rows.json");

fn fixture_rows(table: &str) -> Vec<serde_json::Value> {
    let all: serde_json::Value = serde_json::from_str(FIXTURE_ROWS_1_5_5).unwrap();
    all[table]
        .as_array()
        .unwrap_or_else(|| panic!("rows.json has no table {table}"))
        .clone()
}

fn fx_u64(row: &serde_json::Value, col: &str) -> u64 {
    row[col]
        .as_u64()
        .unwrap_or_else(|| panic!("{col} is not an unsigned integer in {row}"))
}

fn fx_str<'a>(row: &'a serde_json::Value, col: &str) -> &'a str {
    row[col]
        .as_str()
        .unwrap_or_else(|| panic!("{col} is not a string in {row}"))
}

/// A fresh database holding exactly what the 1.5.5 binary left.
fn restore_1_5_5(db: &ScratchDb) {
    let mut c = db.conn();
    let mut stmt = String::new();
    for line in FIXTURE_DUMP_1_5_5.lines() {
        if stmt.is_empty() && line.trim().is_empty() {
            continue;
        }
        stmt.push_str(line);
        stmt.push('\n');
        if line.ends_with(';') {
            c.query_drop(stmt.as_str())
                .unwrap_or_else(|e| panic!("the 1.5.5 dump restores: {e}\n{stmt}"));
            stmt.clear();
        }
    }
    assert!(stmt.trim().is_empty(), "the dump ends on a statement");
}

/// Recreate released whole-unit storage before downgrading a generated migration fixture.
/// The current store writes micro-units even when the offered delta has historical scale 0.
fn restore_historical_whole_unit_seed(raw: &mut mysql::PooledConn) {
    for (table, columns) in [
        (
            "usage_windows",
            &[
                "tokens_input",
                "tokens_output",
                "tokens_cache_read",
                "tokens_cache_write",
            ][..],
        ),
        ("usage_window_units", &["count"][..]),
        (
            "usage_metering",
            &[
                "tokens_input",
                "tokens_output",
                "tokens_cache_read",
                "tokens_cache_write",
            ][..],
        ),
        ("usage_metering_units", &["count"][..]),
    ] {
        let inexact = columns
            .iter()
            .map(|column| format!("{column} % 1000000 <> 0"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let found: Option<u64> = raw
            .query_first(format!(
                "SELECT EXISTS(SELECT 1 FROM {table} WHERE {inexact})"
            ))
            .unwrap();
        assert_eq!(
            found,
            Some(0),
            "historical seed {table} must contain whole units"
        );
        let assignments = columns
            .iter()
            .map(|column| format!("{column} = {column} DIV 1000000"))
            .collect::<Vec<_>>()
            .join(", ");
        raw.query_drop(format!("UPDATE {table} SET {assignments}"))
            .unwrap();
    }
}

fn schema_version_of(db: &ScratchDb) -> String {
    let mut c = db.conn();
    c.query_first("SELECT v FROM store_meta WHERE k = 'schema_version'")
        .unwrap()
        .expect("a schema_version row")
}

/// Recorded admin counts must survive independently of the raw-row comparison below.
fn assert_recorded_1_5_5_admin_counts(store: &MysqlStore) {
    let usage: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/1.5.5/readback/usage.json")).unwrap();
    let metering = store
        .list_metering(usage["window"]["start"].as_u64().unwrap())
        .unwrap();
    for expected in usage["by_key"].as_array().unwrap() {
        let rows: Vec<_> = metering
            .iter()
            .filter(|row| row.key_id == expected["id"].as_str().unwrap())
            .collect();
        assert!(rows.iter().all(|row| row.scale == 6));
        let actual = [
            rows.iter().map(|row| row.requests).sum::<u64>(),
            rows.iter().map(|row| row.tokens_input).sum(),
            rows.iter().map(|row| row.tokens_output).sum(),
            rows.iter().map(|row| row.tokens_cache_read).sum(),
            rows.iter().map(|row| row.tokens_cache_write).sum(),
        ];
        let expected = [
            "requests",
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_creation",
        ]
        .map(|field| {
            expected[field].as_u64().unwrap() * if field == "requests" { 1 } else { 1_000_000 }
        });
        assert_eq!(
            actual, expected,
            "migrated metering preserves the recorded fleet usage counts"
        );
    }
    for text in [
        include_str!("../tests/fixtures/1.5.5/readback/key-fixture-grouped.json"),
        include_str!("../tests/fixtures/1.5.5/readback/key-fixture-ungrouped.json"),
    ] {
        let expected: serde_json::Value = serde_json::from_str(text).unwrap();
        let id = expected["id"].as_str().unwrap();
        let got = store
            .get_usage(id, expected["window_start"].as_u64().unwrap())
            .unwrap();
        assert_eq!(
            got.requests,
            expected["requests"].as_u64().unwrap(),
            "preserve the independently recorded key-window count, including historical differences from metering"
        );
        assert!(got.models.iter().all(|model| model.scale == 6));
        let tokens: u64 = got
            .models
            .iter()
            .map(|model| {
                [UNIT_INPUT, UNIT_OUTPUT, UNIT_CACHE_READ, UNIT_CACHE_WRITE]
                    .iter()
                    .map(|unit| model.usage_units.get(*unit).copied().unwrap_or(0))
                    .sum::<u64>()
            })
            .sum();
        assert_eq!(tokens, expected["tokens"].as_u64().unwrap() * 1_000_000);
    }
}

/// Every row of `rows.json` read back through the 1.6.0 surface, and no extra rows.
fn assert_1_5_5_rows_read_back(store: &MysqlStore) {
    assert_recorded_1_5_5_admin_counts(store);
    assert!(
        store.list_credentials_since(0).unwrap().is_empty(),
        "migration must not invent credentials absent from this recording"
    );
    assert!(
        store.list_denylist().unwrap().is_empty(),
        "migration must not invent denylist rows absent from this recording"
    );
    let expected_revision = fixture_rows("store_sequence")[0]["revision"]
        .as_u64()
        .unwrap();
    let actual_revision: u64 = store
        .conn()
        .unwrap()
        .query_first("SELECT revision FROM store_sequence WHERE id=1")
        .unwrap()
        .unwrap();
    assert_eq!(
        actual_revision, expected_revision,
        "migration preserves the recorded global revision"
    );

    let metering = fixture_rows("usage_metering");
    assert!(!metering.is_empty(), "the fixture carries metering rows");
    let bucket_of = |r: &serde_json::Value| -> u64 { fx_str(r, "bucket").parse().unwrap() };
    let buckets: std::collections::BTreeSet<u64> = metering.iter().map(bucket_of).collect();
    let mut seen = 0;
    for bucket in &buckets {
        let got = store.list_metering(*bucket).unwrap();
        let want: Vec<&serde_json::Value> = metering
            .iter()
            .filter(|r| bucket_of(r) == *bucket)
            .collect();
        assert_eq!(got.len(), want.len(), "metering rows in bucket {bucket}");
        for w in want {
            let row = got
                .iter()
                .find(|g| {
                    g.key_id == fx_str(w, "key_id")
                        && g.model == fx_str(w, "model")
                        && g.provider == fx_str(w, "provider")
                })
                .unwrap_or_else(|| panic!("metering row missing after migrate: {w}"));
            assert_eq!(row.scale, 6, "{w}");
            assert_eq!(row.requests, fx_u64(w, "requests"), "{w}");
            assert_eq!(row.billable_requests, fx_u64(w, "billable_requests"), "{w}");
            assert_eq!(row.key_group_at_use, fx_str(w, "key_group_at_use"), "{w}");
            assert_eq!(row.pricing_version, fx_str(w, "pricing_version"), "{w}");
            assert_eq!(
                row.tokens_input,
                fx_u64(w, "tokens_input") * 1_000_000,
                "{w}"
            );
            assert_eq!(
                row.tokens_output,
                fx_u64(w, "tokens_output") * 1_000_000,
                "{w}"
            );
            assert_eq!(
                row.tokens_cache_read,
                fx_u64(w, "tokens_cache_read") * 1_000_000,
                "{w}"
            );
            assert_eq!(
                row.tokens_cache_write,
                fx_u64(w, "tokens_cache_write") * 1_000_000,
                "{w}"
            );
            assert_eq!(row.priced_from_ms, 0, "a 1.5.5 row is undated: {w}");
            assert!(row.usage_units.is_empty(), "{w}");
            seen += 1;
        }
    }
    assert_eq!(seen, metering.len());

    let windows = fixture_rows("usage_windows");
    assert!(!windows.is_empty(), "the fixture carries usage windows");
    let cells: std::collections::BTreeSet<(String, u64)> = windows
        .iter()
        .map(|w| {
            (
                fx_str(w, "bucket_id").to_string(),
                fx_u64(w, "window_start"),
            )
        })
        .collect();
    for (bucket, start) in cells {
        let rows: Vec<&serde_json::Value> = windows
            .iter()
            .filter(|w| fx_str(w, "bucket_id") == bucket && fx_u64(w, "window_start") == start)
            .collect();
        let got = store.get_usage(&bucket, start).unwrap();
        assert_eq!(
            got.requests,
            rows.iter().map(|w| fx_u64(w, "requests")).sum::<u64>(),
            "requests of {bucket}@{start}"
        );
        assert_eq!(
            got.billable_requests,
            rows.iter()
                .map(|w| fx_u64(w, "billable_requests"))
                .sum::<u64>(),
            "billable requests of {bucket}@{start}"
        );
        let mut want: Vec<(String, BTreeMap<String, u64>)> = rows
            .iter()
            .filter(|w| !fx_str(w, "model").is_empty())
            .map(|w| {
                let mut m = BTreeMap::new();
                for (unit, col) in [
                    (UNIT_INPUT, "tokens_input"),
                    (UNIT_OUTPUT, "tokens_output"),
                    (UNIT_CACHE_READ, "tokens_cache_read"),
                    (UNIT_CACHE_WRITE, "tokens_cache_write"),
                ] {
                    let v = fx_u64(w, col) * 1_000_000;
                    if v != 0 {
                        m.insert(unit.to_string(), v);
                    }
                }
                (fx_str(w, "model").to_string(), m)
            })
            .collect();
        assert!(got.models.iter().all(|model| model.scale == 6));
        let mut have: Vec<(String, BTreeMap<String, u64>)> = got
            .models
            .iter()
            .map(|m| (m.model.clone(), m.usage_units.clone()))
            .collect();
        want.sort();
        have.sort();
        assert_eq!(have, want, "models of {bucket}@{start}");
    }

    let keys = fixture_rows("api_keys");
    assert!(!keys.is_empty(), "the fixture carries keys");
    assert_eq!(store.list_keys().unwrap().len(), keys.len());
    for k in &keys {
        let got = store
            .get_key(fx_str(k, "id"))
            .unwrap()
            .unwrap_or_else(|| panic!("key missing after migrate: {k}"));
        assert_eq!(got.name, fx_str(k, "name"), "{k}");
        assert_eq!(got.generation_hash, fx_str(k, "generation_hash"), "{k}");
        assert_eq!(got.enabled, fx_u64(k, "enabled") != 0, "{k}");
        let group = fx_str(k, "key_group");
        assert_eq!(
            got.group.as_deref(),
            (!group.is_empty()).then_some(group),
            "{k}"
        );
        assert_eq!(got.created_at, fx_u64(k, "created_at"), "{k}");
        assert_eq!(got.revision, fx_u64(k, "revision"), "{k}");
        assert_eq!(got.expires_at, k["expires_at"].as_u64(), "{k}");
        assert_eq!(got.deleted_at, k["deleted_at"].as_u64(), "{k}");
        assert!(k["allowed_pools"].is_null() && got.allowed_scopes.is_none());
        assert!(got.labels.is_empty(), "{k}");
        assert_eq!(
            (got.idp_subject, got.binding_mode, got.minted_by),
            (None, None, None),
            "{k}"
        );
    }

    let audit = fixture_rows("audit_log");
    assert!(!audit.is_empty(), "the fixture carries audit rows");
    let got = store.list_audit().unwrap();
    assert_eq!(got.len(), audit.len());
    for (g, w) in got.iter().zip(&audit) {
        assert_eq!(g.seq, fx_u64(w, "seq"), "{w}");
        assert_eq!(g.ts, fx_u64(w, "ts"), "{w}");
        assert_eq!(g.action, fx_str(w, "action"), "{w}");
        assert_eq!(g.resource, fx_str(w, "resource"), "{w}");
        assert_eq!(g.outcome, fx_str(w, "outcome"), "{w}");
        assert_eq!(g.principal, fx_str(w, "principal"), "{w}");
        assert_eq!(g.prev_hash, fx_str(w, "prev_hash"), "{w}");
        assert_eq!(g.hash, fx_str(w, "hash"), "{w}");
    }
}

/// Every read the assertions above make, as text, so two opens compare whole.
fn read_everything_1_5_5(store: &MysqlStore) -> Vec<String> {
    let mut out = vec![
        format!("{:?}", store.list_keys().unwrap()),
        format!("{:?}", store.list_audit().unwrap()),
    ];
    for r in fixture_rows("usage_metering") {
        let bucket: u64 = fx_str(&r, "bucket").parse().unwrap();
        out.push(format!("{:?}", store.list_metering(bucket).unwrap()));
    }
    for w in fixture_rows("usage_windows") {
        out.push(format!(
            "{:?}",
            store
                .get_usage(fx_str(&w, "bucket_id"), fx_u64(&w, "window_start"))
                .unwrap()
        ));
    }
    out
}

/// Rows written by the 1.5.5 binary read back through this build's migrate, field for field.
#[test]
fn the_1_5_5_binarys_rows_read_back_through_migrate() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("fx155") else {
        return;
    };
    restore_1_5_5(&db);
    let store = MysqlStore::connect(&db.url).expect("this build opens the 1.5.5 database");
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    assert_1_5_5_rows_read_back(&store);
}

/// A second open over the migrated 1.5.5 database changes nothing.
#[test]
fn migrate_over_the_1_5_5_rows_is_idempotent() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("fx155i") else {
        return;
    };
    restore_1_5_5(&db);
    let first = {
        let store = MysqlStore::connect(&db.url).expect("first open");
        assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
        assert_1_5_5_rows_read_back(&store);
        read_everything_1_5_5(&store)
    };
    let store = MysqlStore::connect(&db.url).expect("second open");
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    assert_1_5_5_rows_read_back(&store);
    assert_eq!(read_everything_1_5_5(&store), first);
}

/// `open`/`validate` judge the settings the same way, and every refusal is in the plugin's words.
#[test]
fn settings_are_judged_strictly() {
    let open = |s: &str| MysqlStore::open(s.as_bytes()).err();
    assert_eq!(
        open(r#"{"url":"mysql://u@h/d","bogus":1}"#).as_deref(),
        Some("invalid mysql plugin config: settings: unknown field `bogus`, expected `url`")
    );
    assert_eq!(
        open(r#"{"url":5}"#).as_deref(),
        Some(
            "invalid mysql plugin config: settings: invalid type: integer `***`, expected a string"
        )
    );
    assert_eq!(
        open(r#"{"url":null}"#).as_deref(),
        Some("invalid mysql plugin config: requires a \"url\" (a mysql:// connection string)")
    );
    assert_eq!(
        open(r#"{"url":["mysql://u:s3cret@h/d"]}"#).as_deref(),
        Some("invalid mysql plugin config: settings: invalid type: sequence, expected a string"),
        "a type error names the type and never the value"
    );
    for (settings, ty) in [
        (r#""mysql://u:s3cret@h/d""#, "string \"***\""),
        ("[1]", "sequence"),
        ("7", "integer `***`"),
        ("true", "boolean `***`"),
    ] {
        assert_eq!(
            open(settings).as_deref(),
            Some(format!("invalid mysql plugin config: settings: invalid type: {ty}, expected struct Settings").as_str())
        );
    }
    for settings in ["", "{}", "null", r#"{"url":"  "}"#] {
        assert_eq!(
            open(settings).as_deref(),
            Some("invalid mysql plugin config: requires a \"url\" (a mysql:// connection string)"),
            "{settings:?}"
        );
    }
    let e = open(r#"{"url":"mysql://u@h/d?pool_max=5"}"#).unwrap();
    assert!(
        e.starts_with("invalid mysql plugin config: url: mysql store: URL parameter `pool_max`"),
        "{e}"
    );
    let e = open(r#"{"url":"postgres://u@h/d"}"#).unwrap();
    assert!(e.starts_with("invalid mysql plugin config: url: "), "{e}");
    assert!(open(r#"{"url":"mysql://u@h/d"}"#).is_none());

    assert_eq!(
        <crate::MysqlStore as busbar_contract::abi::sdk::store::StoreSlots>::validate(
            br#"{"url":"mysql://u@h/d","x":1}"#
        )
        .unwrap_err(),
        "invalid mysql plugin config: settings: unknown field `x`, expected `url`"
    );
}

/// A serde struct's positional sequence representation is not a settings object.
#[test]
fn settings_arrays_are_refused_without_echoing_secrets() {
    let settings = br#"["mysql://u:ARRAY_PASSWORD_CANARY@h/d"]"#;
    for error in [
        MysqlStore::open(settings)
            .err()
            .expect("array settings refused"),
        <crate::MysqlStore as busbar_contract::abi::sdk::store::StoreSlots>::validate(settings)
            .expect_err("array settings refused"),
    ] {
        assert_eq!(
            error,
            "invalid mysql plugin config: settings: invalid type: sequence, expected struct Settings"
        );
        assert!(!error.contains("ARRAY_PASSWORD_CANARY"));
    }
}

/// An unencoded `?` in the password makes the URL's tail a bogus parameter; neither `open` nor `validate` may echo any of the password, raw or percent-decoded.
#[test]
fn a_settings_refusal_never_carries_the_url_password() {
    for url in [
        "mysql://u:12?abc@h/db",
        "mysql://u:12?tlsCANARY@h/db",
        "mysql://u:12?sslCANARY@h/db",
        "mysql://u:p%40ss%3Fw0rd@h/db?bogus=1",
        "mysql://u:s3cret@h/db?pool_max=5&bogus",
    ] {
        let settings = serde_json::json!({ "url": url }).to_string();
        for e in [
            MysqlStore::open(settings.as_bytes()).err().unwrap(),
            <crate::MysqlStore as busbar_contract::abi::sdk::store::StoreSlots>::validate(
                settings.as_bytes(),
            )
            .unwrap_err(),
        ] {
            for secret in [
                "12?abc",
                "abc@h",
                "p%40ss%3Fw0rd",
                "p@ss?w0rd",
                "s3cret",
                "tlsCANARY",
                "sslCANARY",
            ] {
                assert!(!e.contains(secret), "{url}: {secret:?} leaked in {e:?}");
            }
        }
    }
}

/// A database stamped ABOVE this build's schema is refused at open, before any DDL; the same version opens.
#[test]
fn a_newer_schema_is_refused_at_open() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("newer") else {
        return;
    };
    drop(MysqlStore::connect(&db.url).expect("a fresh database opens"));
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    drop(MysqlStore::connect(&db.url).expect("the same version opens"));
    let newer = SCHEMA_VERSION + 1;
    db.conn()
        .query_drop(format!(
            "UPDATE store_meta SET v = '{newer}' WHERE k = 'schema_version'"
        ))
        .unwrap();

    db.conn().query_drop("DROP TABLE store_records").unwrap();
    let e = MysqlStore::connect(&db.url)
        .err()
        .expect("a newer schema is refused");
    assert!(
        e.contains(&format!(
            "mysql store: database schema v{newer} is newer than this build (v{SCHEMA_VERSION}); \
             refusing to open"
        )),
        "{e}"
    );
    let recreated: Option<String> = db
        .conn()
        .query_first("SHOW TABLES LIKE 'store_records'")
        .unwrap();
    assert!(recreated.is_none(), "no DDL ran before the refusal");
    assert_eq!(schema_version_of(&db), newer.to_string(), "not restamped");
}

/// Released schema v2 remains an accepted upgrade source.
#[test]
fn released_schema_versions_are_accepted() {
    for version in 0..=SCHEMA_VERSION {
        crate::MysqlStore::refuse_unknown_schema(version, None).unwrap();
    }
    assert!(crate::MysqlStore::refuse_unknown_schema(SCHEMA_VERSION + 1, None).is_err());
}

/// D19, RED BEFORE GREEN: `'abc'` and `'abc '` are TWO keys, as they are in every other store (postgres, sqlite, valkey, memory).
#[test]
fn keys_differing_only_by_trailing_space_are_distinct() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("exact") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).expect("a fresh database opens");

    store.put_key(&sample_key("abc", "gen-plain")).unwrap();
    store.put_key(&sample_key("abc ", "gen-padded")).unwrap();
    assert_eq!(
        store.get_key("abc").unwrap().unwrap().generation_hash,
        "gen-plain",
        "'abc ' overwrote 'abc'"
    );
    let padded = store
        .get_key("abc ")
        .unwrap()
        .expect("'abc ' is its own key");
    assert_eq!(padded.id, "abc ");
    assert_eq!(padded.generation_hash, "gen-padded");

    store
        .upsert_plane_record(active_task("abc", "working", TASK_LIVE_TS + 1).view())
        .unwrap();
    store
        .upsert_plane_record(active_task("abc ", "submitted", TASK_LIVE_TS + 2).view())
        .unwrap();
    assert_eq!(get_task(&store, "abc").unwrap()["state"], "working");
    assert_eq!(get_task(&store, "abc ").unwrap()["state"], "submitted");

    assert!(store
        .redeem_plane_token("ask", "abc", u64::MAX, TRUST_NOW)
        .unwrap());
    assert!(
        store
            .redeem_plane_token("ask", "abc ", u64::MAX, TRUST_NOW)
            .unwrap(),
        "'abc ' was refused as already spent because 'abc' was"
    );

    store.record_put("abc", b"k", b"plain").unwrap();
    store.record_put("abc ", b"k", b"padded").unwrap();
    assert_eq!(
        store.record_get("abc", b"k").unwrap().unwrap().as_slice(),
        b"plain"
    );
    assert_eq!(
        store.record_get("abc ", b"k").unwrap().unwrap().as_slice(),
        b"padded"
    );
}

/// A synthetic pre-D19 layout stamped with released schema 3, holding one row keyed `'abc'` in
fn build_v10_database(db: &ScratchDb) {
    let mut c = db.conn();
    c.query_drop("SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')")
        .unwrap();
    for stmt in schema_fixtures::V10_SCHEMA {
        c.query_drop(*stmt).unwrap();
    }
    for stmt in V10_ABC_ROWS {
        c.query_drop(*stmt).unwrap();
    }
}

const V10_ABC_ROWS: &[&str] = &[
    "INSERT INTO store_meta (k, v) VALUES ('schema_version', '3')",
    "INSERT INTO store_sequence (id, revision) VALUES (1, 7)",
    "INSERT INTO api_keys (id, name, key_group, allowed_pools, labels, enabled, generation_hash, \
     created_at, updated_at, revision) VALUES ('abc', 'old', 'grp', NULL, '{}', 1, 'gen-abc', \
     1000, 1000, 7)",
    "INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form, created_at, \
     updated_at, revision) VALUES ('abc', 'abc', 'sigv4', 0, 'abc', 'v1:plain:abc', \
     'recoverable', 1000, 1000, 7)",
    "INSERT INTO denylist (sub, reason, revoked_at, expires_at, revision) \
     VALUES ('abc', 'r', 2000, 9000000000, 7)",
    "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests, \
     billable_requests) VALUES (3000, 'key', 'abc', 'gpt-x', 9, 8)",
    "INSERT INTO usage_metering (bucket, key_id, provider, model, key_group_at_use, \
     pricing_version, requests, billable_requests) VALUES ('0020260731', 'abc', 'p', 'm', 'grp', \
     'v1', 4, 3)",
    "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
     VALUES ('task', 'abc', 0, 'abc', NULL, 2000000001, FALSE, '{\"state\":\"working\"}')",
    "INSERT INTO plane_tokens (kind, token, expires_at) VALUES ('ask', 'abc', 9000000000)",
    "INSERT INTO usage_window_units (window_start, bucket_scope, bucket_id, model, unit, count) \
     VALUES (3000, 'key', 'abc', 'gpt-x', 'abc', 5)",
    "INSERT INTO usage_metering_units (bucket, key_id, provider, model, priced_from_ms, unit, \
     count) VALUES ('0020260731', 'abc', 'p', 'm', 0, 'abc', 2)",
    "INSERT INTO store_records (schema_id, rkey, value) VALUES ('abc', 'k', 'v-abc')",
];

/// The same rows with `'abc '` where the v10 key held `'abc'`: one per table, each a different key under byte comparison, each the SAME key under v10's PAD SPACE collations.
const V10_PADDED_TWINS: &[&str] = &[
    "INSERT INTO api_keys (id, name, key_group, allowed_pools, labels, enabled, generation_hash, \
     created_at, updated_at, revision) VALUES ('abc ', 'twin', 'grp', NULL, '{}', 1, 'gen-twin', \
     1000, 1000, 8)",
    "INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form, created_at, \
     updated_at, revision) VALUES ('abc ', 'abc', 'sigv4', 1, 'abc2', 'v1:plain:abc', \
     'recoverable', 1000, 1000, 8)",
    "INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form, created_at, \
     updated_at, revision) VALUES ('abc2', 'abc ', 'sigv4', 0, 'abc ', 'v1:plain:abc', \
     'recoverable', 1000, 1000, 8)",
    "INSERT INTO denylist (sub, reason, revoked_at, expires_at, revision) \
     VALUES ('abc ', 'r', 2000, 9000000000, 8)",
    "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests, \
     billable_requests) VALUES (3000, 'key', 'abc ', 'gpt-x', 1, 1)",
    "INSERT INTO usage_metering (bucket, key_id, provider, model, key_group_at_use, \
     pricing_version, requests, billable_requests) VALUES ('0020260731', 'abc ', 'p', 'm', 'grp', \
     'v1', 1, 1)",
    "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
     VALUES ('task', 'abc ', 0, 'abc ', NULL, 2000000001, FALSE, '{}')",
    "INSERT INTO plane_tokens (kind, token, expires_at) VALUES ('ask', 'abc ', 9000000000)",
    "INSERT INTO usage_window_units (window_start, bucket_scope, bucket_id, model, unit, count) \
     VALUES (3000, 'key', 'abc', 'gpt-x', 'abc ', 1)",
    "INSERT INTO usage_metering_units (bucket, key_id, provider, model, priced_from_ms, unit, \
     count) VALUES ('0020260731', 'abc', 'p', 'm', 0, 'abc ', 1)",
    "INSERT INTO store_records (schema_id, rkey, value) VALUES ('abc ', 'k', 'v-twin')",
];

/// Every column, constraint (with its foreign keys' referential actions and each CHECK's clause) and index of `db`'s tables, as `information_schema` reports them.
fn schema_shape(db: &ScratchDb) -> Vec<String> {
    let mut c = db.conn();
    let mut out: Vec<String> = c
        .exec_map(
            "SELECT table_name, column_name, column_type, is_nullable, \
             COALESCE(column_default, '<none>'), COALESCE(collation_name, '<none>') \
             FROM information_schema.columns WHERE table_schema = DATABASE() \
             ORDER BY table_name, ordinal_position",
            (),
            |(t, col, ty, null, def, coll): (String, String, String, String, String, String)| {
                format!("column {t}.{col} {ty} null={null} default={def} collation={coll}")
            },
        )
        .unwrap();
    out.extend(
        c.exec_map(
            "SELECT table_name, constraint_name, constraint_type FROM \
             information_schema.table_constraints WHERE table_schema = DATABASE() \
             ORDER BY table_name, constraint_name",
            (),
            |(t, n, ty): (String, String, String)| format!("constraint {t}.{n} {ty}"),
        )
        .unwrap(),
    );
    out.extend(
        c.exec_map(
            "SELECT table_name, constraint_name, update_rule, delete_rule FROM \
             information_schema.referential_constraints WHERE constraint_schema = DATABASE() \
             ORDER BY table_name, constraint_name",
            (),
            |(t, n, up, del): (String, String, String, String)| {
                format!("foreign key {t}.{n} on_update={up} on_delete={del}")
            },
        )
        .unwrap(),
    );
    out.extend(
        c.exec_map(
            "SELECT constraint_name, check_clause FROM information_schema.check_constraints \
             WHERE constraint_schema = DATABASE() ORDER BY constraint_name",
            (),
            |(n, clause): (String, String)| format!("check {n} {clause}"),
        )
        .unwrap(),
    );
    out.extend(
        c.exec_map(
            "SELECT table_name, index_name, seq_in_index, column_name FROM \
             information_schema.statistics WHERE table_schema = DATABASE() \
             ORDER BY table_name, index_name, seq_in_index",
            (),
            |(t, i, n, col): (String, String, u64, String)| format!("index {t}.{i}[{n}] {col}"),
        )
        .unwrap(),
    );
    out
}

fn meta_row(db: &ScratchDb, k: &str) -> Option<String> {
    db.conn()
        .exec_first("SELECT v FROM store_meta WHERE k = ?", (k,))
        .unwrap()
}

/// The shape a FRESH database gets from this build.
fn fresh_schema_shape() -> Option<Vec<String>> {
    let db = ScratchDb::new("shape")?;
    drop(MysqlStore::connect(&db.url).expect("a fresh database opens"));
    Some(schema_shape(&db))
}

/// The `'abc'` rows read back through this build's surface, unchanged by the migration.
fn assert_abc_rows_read_back(store: &MysqlStore) {
    let k = store.get_key("abc").unwrap().expect("the key survives");
    assert_eq!(
        (k.id.as_str(), k.generation_hash.as_str()),
        ("abc", "gen-abc")
    );
    let cred = store
        .lookup_credential_secret("sigv4", "abc")
        .unwrap()
        .expect("the credential survives");
    assert_eq!(cred.meta.key_id, "abc");
    assert_eq!(
        store.get_plane_record("task", "abc").unwrap().as_deref(),
        Some(&br#"{"state":"working"}"#[..])
    );
    assert!(
        !store
            .redeem_plane_token("ask", "abc", u64::MAX, TRUST_NOW)
            .unwrap(),
        "the spent token is still spent"
    );
    assert_eq!(
        store.record_get("abc", b"k").unwrap().unwrap().as_slice(),
        b"v-abc"
    );
}

/// D19's MIGRATION.
#[test]
fn v11_converts_a_v10_database_to_exact_keys_in_place() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(fresh) = fresh_schema_shape() else {
        return;
    };
    let Some(db) = ScratchDb::new("v11") else {
        return;
    };
    build_v10_database(&db);
    {
        let mut c = db.conn();
        for twin in V10_PADDED_TWINS {
            match c.query_drop(*twin) {
                Err(mysql::Error::MySqlError(e)) if e.code == 1062 => {}
                other => panic!("v10 must merge the padded twin onto 'abc': {other:?}\n{twin}"),
            }
        }
    }
    assert_ne!(schema_shape(&db), fresh, "the fixture is the pre-D19 shape");

    let store = MysqlStore::connect(&db.url).expect("this build opens and migrates a v10 database");
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    assert_eq!(meta_row(&db, "migrating_to"), None, "the marker is cleared");
    assert_eq!(
        schema_shape(&db),
        fresh,
        "a migrated database is a fresh one's shape"
    );
    assert_abc_rows_read_back(&store);

    {
        let mut c = db.conn();
        for twin in V10_PADDED_TWINS {
            c.query_drop(*twin)
                .unwrap_or_else(|e| panic!("after v11 the padded twin is distinct: {e}\n{twin}"));
        }
    }
    assert_eq!(
        store.get_key("abc ").unwrap().unwrap().generation_hash,
        "gen-twin"
    );
    assert_eq!(
        store.get_key("abc").unwrap().unwrap().generation_hash,
        "gen-abc"
    );
    drop(store);

    let again = MysqlStore::connect(&db.url).expect("a second open");
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    assert_eq!(schema_shape(&db), fresh, "the second open changes nothing");
    assert_abc_rows_read_back(&again);
}

/// A v11 migration that crashed part-way (MySQL DDL commits statement by statement) left its marker, both foreign keys onto `api_keys.id` dropped and one table converted.
#[test]
fn v11_resumes_a_migration_that_crashed_part_way() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(fresh) = fresh_schema_shape() else {
        return;
    };
    let Some(db) = ScratchDb::new("v11crash") else {
        return;
    };
    build_v10_database(&db);
    {
        let mut c = db.conn();
        for stmt in [
            "INSERT INTO store_meta (k, v) VALUES ('migrating_to', '4')",
            "ALTER TABLE credentials DROP FOREIGN KEY fk_cred_key",
            "ALTER TABLE usage_metering DROP FOREIGN KEY fk_metering_key",
            "ALTER TABLE api_keys MODIFY COLUMN id VARBINARY(64) NOT NULL, \
             MODIFY COLUMN key_group VARBINARY(128) NOT NULL DEFAULT ''",
        ] {
            c.query_drop(stmt).unwrap();
        }
    }
    let store = MysqlStore::connect(&db.url).expect("the crashed migration resumes");
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    assert_eq!(meta_row(&db, "migrating_to"), None);
    assert_eq!(schema_shape(&db), fresh);
    assert_abc_rows_read_back(&store);
}

/// While ANOTHER connection holds this database's migration lock (it is migrating right now), an open waits, then REFUSES with the reason and the holder rather than serve a schema half way between two shapes.
#[test]
fn an_open_during_another_connections_migration_is_refused() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("v11busy") else {
        return;
    };
    build_v10_database(&db);
    let before = schema_shape(&db);
    let mut migrator = db.conn();
    let holder: u64 = migrator
        .query_first("SELECT CONNECTION_ID()")
        .unwrap()
        .unwrap();
    let got: Option<i64> = migrator
        .query_first(format!("SELECT GET_LOCK({}, 0)", crate::MIGRATION_LOCK))
        .unwrap();
    assert_eq!(got, Some(1));

    let e = MysqlStore::init_schema_waiting(&mut db.conn(), 1)
        .expect_err("an open during another connection's migration is refused")
        .0;
    assert!(
        e.contains(&format!(
            "mysql store: database is mid-migration: connection {holder} holds its migration \
             lock and is migrating it from schema v3 to v{SCHEMA_VERSION}; refusing to open"
        )),
        "{e}"
    );
    assert_eq!(schema_version_of(&db), "3", "not stamped");
    assert_eq!(schema_shape(&db), before, "no DDL ran");

    migrator
        .query_drop(format!("DO RELEASE_LOCK({})", crate::MIGRATION_LOCK))
        .unwrap();
    MysqlStore::init_schema_waiting(&mut db.conn(), 1).expect("the lock is free: it migrates");
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
}

/// A database a NEWER build was part-way through migrating (its marker names a version past this build's) is refused at open, before any DDL, and the marker is left for that build.
#[test]
fn a_database_mid_migration_to_a_newer_schema_is_refused() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("v11newer") else {
        return;
    };
    drop(MysqlStore::connect(&db.url).expect("a fresh database opens"));
    let newer = SCHEMA_VERSION + 1;
    db.conn()
        .query_drop(format!(
            "INSERT INTO store_meta (k, v) VALUES ('migrating_to', '{newer}')"
        ))
        .unwrap();
    db.conn().query_drop("DROP TABLE store_records").unwrap();
    let e = MysqlStore::connect(&db.url)
        .err()
        .expect("a database mid-migration to a newer schema is refused");
    assert!(
        e.contains(&format!(
            "mysql store: database is mid-migration from schema v{SCHEMA_VERSION} to v{newer}, \
             which is newer than this build (v{SCHEMA_VERSION}); refusing to open"
        )),
        "{e}"
    );
    let recreated: Option<String> = db
        .conn()
        .query_first("SHOW TABLES LIKE 'store_records'")
        .unwrap();
    assert!(recreated.is_none(), "no DDL ran before the refusal");
    assert_eq!(meta_row(&db, "migrating_to"), Some(newer.to_string()));
}

/// v11 never orphans a row its old collation let reach its parent under another spelling.
#[test]
fn v11_respells_children_onto_their_parents_keys() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("v11spell") else {
        return;
    };
    build_v10_database(&db);
    {
        let mut c = db.conn();
        for stmt in [
            "INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form, \
             created_at, updated_at, revision) VALUES ('cred_pad', 'abc ', 'sigv4', 1, 'pad', \
             'v1:plain:pad', 'recoverable', 1000, 1000, 7)",
            "INSERT INTO usage_metering (bucket, key_id, provider, model, key_group_at_use, \
             pricing_version, requests, billable_requests) VALUES ('0020991231', 'abc', 'P', \
             'GPT-4o', '', 'v1', 1, 1)",
            "INSERT INTO usage_metering_units (bucket, key_id, provider, model, priced_from_ms, \
             unit, count) VALUES ('0020991231', 'abc', 'p', 'gpt-4o', 0, 'tool_calls', 5)",
        ] {
            c.query_drop(stmt).unwrap();
        }
    }
    let store = MysqlStore::connect(&db.url).expect("v11 migrates");
    let pad = store
        .lookup_credential_secret("sigv4", "pad")
        .unwrap()
        .expect("the credential survives");
    assert_eq!(
        pad.meta.key_id, "abc",
        "the credential takes its key's spelling"
    );
    let rows = store.list_metering(20_991_231).unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].model.as_str(), rows[0].provider.as_str()),
        ("GPT-4o", "P")
    );
    assert_eq!(
        rows[0].usage_units.get("tool_calls"),
        Some(&5),
        "the unit is on its cell"
    );

    let n: u64 = db
        .conn()
        .query_first(
            "SELECT COUNT(*) FROM information_schema.key_column_usage k \
             JOIN information_schema.referential_constraints r \
             ON r.constraint_schema = k.constraint_schema AND r.constraint_name = k.constraint_name \
             WHERE k.table_schema = DATABASE() AND k.table_name = 'credentials' \
             AND k.constraint_name = 'fk_cred_key' AND k.column_name = 'key_id' \
             AND k.referenced_table_name = 'api_keys' AND k.referenced_column_name = 'id' \
             AND r.delete_rule = 'CASCADE'",
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        n, 1,
        "the credential foreign key and its cascade are restored"
    );
    let metering: u64 = db
        .conn()
        .query_first(
            "SELECT COUNT(*) FROM information_schema.table_constraints \
             WHERE table_schema = DATABASE() AND table_name = 'usage_metering' \
             AND constraint_type = 'FOREIGN KEY'",
        )
        .unwrap()
        .unwrap();
    assert_eq!(metering, 0, "metering accepts keys without a live parent");
    db.conn()
        .query_drop("DELETE FROM api_keys WHERE id = 'abc'")
        .unwrap();
    assert!(store
        .lookup_credential_secret("sigv4", "pad")
        .unwrap()
        .is_none());
    assert_eq!(store.list_metering(20_991_231).unwrap().len(), 1);
}

/// UPSERT IS BY `(kind, id)` (the contract's `RecordStore::upsert_plane_record` / `get_plane_record`), with or without a parent: an upserted record that names a parent reads back by its own id, a second id under the same parent is a second record (never an overwrite), and the parent-scoped listing still returns both.
#[test]
fn a_parented_upserted_record_reads_back_by_its_own_id() {
    let Some(url) = test_url() else { return };
    let store = MysqlStore::connect(&url).expect("connect");
    let (t1, t2, ctx) = ("t_parented_1", "t_parented_2", "ctx_parented");
    reset_plane(&store, "task", &[t1, t2, ctx]);
    let child = |id: &str, body: &[u8]| PlaneRecord {
        kind: "task".to_string(),
        id: id.to_string(),
        parent: Some(ctx.to_string()),
        seq: 0,
        ts: TASK_LIVE_TS,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    store.upsert_plane_record(child(t1, b"one").view()).unwrap();
    store.upsert_plane_record(child(t2, b"two").view()).unwrap();

    assert_eq!(
        store.get_plane_record("task", t1).unwrap(),
        Some(b"one".to_vec())
    );
    assert_eq!(
        store.get_plane_record("task", t2).unwrap(),
        Some(b"two".to_vec())
    );
    let mut listed = store
        .list_plane_records("task", &PlaneSelector::Parent(ctx.into()))
        .unwrap();
    listed.sort();
    assert_eq!(listed, vec![b"one".to_vec(), b"two".to_vec()]);

    store
        .upsert_plane_record(child(t1, b"one'").view())
        .unwrap();
    assert_eq!(
        store.get_plane_record("task", t1).unwrap(),
        Some(b"one'".to_vec())
    );
    store.delete_plane_record("task", t1).unwrap();
    assert_eq!(store.get_plane_record("task", t1).unwrap(), None);
    assert_eq!(
        store.get_plane_record("task", t2).unwrap(),
        Some(b"two".to_vec())
    );
    reset_plane(&store, "task", &[t1, t2, ctx]);
}

/// M6: a value the requested type cannot hold is an error naming the type, never a panic and never the value, on every row-reading call of the store's client.
#[test]
fn a_row_value_of_the_wrong_shape_is_an_error_not_a_panic() {
    let Some(s) = fresh_store() else { return };
    let mut raw = s.conn().expect("conn");
    let mut c = harness::store_client(&mut raw);
    use harness::block_on as h;
    for sql in [
        "SELECT NULL",
        "SELECT -1",
        "SELECT 'canary-text'",
        "SELECT CAST(0xff AS BINARY)",
    ] {
        let e = h(c.query_first::<(u64,)>(sql)).expect_err(sql);
        assert!(!e.to_string().contains("canary"), "{e}");
        h(c.query::<(u64,)>(sql)).expect_err(sql);
        let e = h(c.exec_first::<(u64,)>(sql, Params::Empty)).expect_err(sql);
        assert!(!e.to_string().contains("canary"), "{e}");
        h(c.exec::<(u64,)>(sql, Params::Empty)).expect_err(sql);
    }
    h(c.query_first::<(String,)>("SELECT CAST(0xff AS BINARY)")).expect_err("not UTF-8");
    h(c.exec_first::<(String,)>("SELECT CAST(0xff AS BINARY)", Params::Empty))
        .expect_err("not UTF-8");

    let ok: Option<(u64,)> = h(c.query_first("SELECT 7")).expect("reads");
    assert_eq!(ok, Some((7,)));
}

/// M14: the three purge shapes (terminal tasks and their events, terminal-only for another kind, age for any kind) drain a backlog larger than one batch and return exactly the rows removed.
#[test]
fn purges_drain_more_than_one_batch_and_count_exactly() {
    let Some(url) = test_url() else { return };
    let _guard = lock_plane_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    clear_purge_band(&store);
    let mut conn = store.conn().expect("conn");

    const N: u64 = (PURGE_BATCH * 2 + 7) as u64;
    let fill =
        |conn: &mut PooledConn, kind: &str, prefix: &str, ts: u64, terminal: bool, n: u64| {
            for start in (0..n).step_by(1000) {
                let rows: Vec<String> = (start..(start + 1000).min(n))
                    .map(|i| {
                        format!("('{kind}', '{prefix}{i}', 0, '{prefix}{i}', {ts}, {terminal}, '')")
                    })
                    .collect();
                conn.query_drop(format!(
                "INSERT INTO plane_records (kind, ident, seq, id, ts, terminal, body) VALUES {}",
                rows.join(",")
            ))
                .expect("bulk insert");
            }
        };
    let count = |conn: &mut PooledConn, kind: &str, like: &str| -> u64 {
        conn.exec_first(
            "SELECT COUNT(*) FROM plane_records WHERE kind = :k AND ident LIKE :like",
            params! { "k" => kind, "like" => like },
        )
        .unwrap()
        .unwrap()
    };
    use busbar_contract::records::Retention;
    let cutoff = 1_000_000_200;

    fill(&mut conn, "task", "t_batch_", 1_000_000_100, true, N);
    fill(
        &mut conn,
        "task",
        "t_batch_active_",
        1_000_000_100,
        false,
        1,
    );
    fill(&mut conn, "task", "t_batch_new_", 1_000_000_300, true, 1);
    fill(&mut conn, "task_event", "t_batch_", 1_000_000_100, false, 3);
    assert_eq!(
        store
            .purge_plane_records("task", cutoff, Retention::TerminalOnly)
            .unwrap(),
        N
    );
    assert_eq!(
        count(&mut conn, "task", "t\\_batch\\_%"),
        2,
        "the active and the newer task stay"
    );
    assert_eq!(
        count(&mut conn, "task_event", "t\\_batch\\_%"),
        0,
        "their events went with them"
    );

    let kind = "slots_purge_terminal";
    conn.exec_drop(
        "DELETE FROM plane_records WHERE kind = :k",
        params! { "k" => kind },
    )
    .unwrap();
    fill(&mut conn, kind, "p_", 100, true, N);
    fill(&mut conn, kind, "pa_", 100, false, 1);
    assert_eq!(
        store
            .purge_plane_records(kind, 200, Retention::TerminalOnly)
            .unwrap(),
        N
    );
    assert_eq!(count(&mut conn, kind, "%"), 1);

    let kind = "slots_purge_age";
    conn.exec_drop(
        "DELETE FROM plane_records WHERE kind = :k",
        params! { "k" => kind },
    )
    .unwrap();
    fill(&mut conn, kind, "a_", 100, false, N);
    fill(&mut conn, kind, "an_", 300, false, 1);
    assert_eq!(
        store
            .purge_plane_records(kind, 200, Retention::Age)
            .unwrap(),
        N
    );
    assert_eq!(count(&mut conn, kind, "%"), 1);
    conn.exec_drop(
        "DELETE FROM plane_records WHERE kind LIKE 'slots_purge_%'",
        (),
    )
    .unwrap();
    clear_purge_band(&store);
}

mod align;

/// Token expiries use BIGINT UNSIGNED, including permanent node-identity claims.
#[test]
fn token_redemption_preserves_unsigned_expiry_and_ignores_caller_clock() {
    let Some(store) = fresh_store() else { return };
    let kind = trust_ns("unsigned_token_range");
    for expiry in [i64::MAX as u64 + 1, u64::MAX - 1, u64::MAX] {
        let token = trust_ns("unsigned_token");
        assert!(store
            .redeem_plane_token(&kind, &token, expiry, expiry - 1)
            .unwrap());
        assert!(!store
            .redeem_plane_token(&kind, &token, expiry, expiry)
            .unwrap());
        if let Some(after) = expiry.checked_add(1) {
            assert!(!store
                .redeem_plane_token(&kind, &token, u64::MAX, after)
                .unwrap());
            assert!(!store
                .redeem_plane_token(&kind, &token, u64::MAX, after)
                .unwrap());
        }
        reset_tokens(&store, &kind, &[&token]);
    }
}

#[test]
fn usage_cleanup_counts_logical_windows_preserves_full_width_boundaries_and_billing() {
    use busbar_contract::store_calls::StoreCalls;
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("purge_usage") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let mut raw = db.conn();
    for window in [0, 9, 10, 11, u64::MAX - 1, u64::MAX] {
        for scope in ["key", "group", "global"] {
            for bucket in ["first", "second"] {
                for model in ["", "model-a", "model-b"] {
                    raw.exec_drop(
                        "INSERT INTO usage_windows (window_start,bucket_scope,bucket_id,model,requests,tokens_input) VALUES (:w,:s,:b,:m,3,7)",
                        params! { "w" => window, "s" => scope, "b" => bucket, "m" => model },
                    ).unwrap();
                    raw.exec_drop(
                        "INSERT INTO usage_window_units (window_start,bucket_scope,bucket_id,model,unit,count) VALUES (:w,:s,:b,:m,'images',13)",
                        params! { "w" => window, "s" => scope, "b" => bucket, "m" => model },
                    ).unwrap();
                }
            }
        }
    }
    raw.query_drop("INSERT INTO usage_windows (window_start,bucket_scope,bucket_id,model,requests) VALUES (9,'key','model-only','model',5),(9,'key','counters-only','',8)").unwrap();
    raw.query_drop("INSERT INTO usage_metering (bucket,key_id,provider,model,requests) VALUES ('bill','bill-key','provider','model',41)").unwrap();
    raw.query_drop("INSERT INTO usage_metering_units (bucket,key_id,provider,model,unit,count) VALUES ('bill','bill-key','provider','model','images',29)").unwrap();
    let snapshot = |raw: &mut PooledConn, predicate: &str| -> (Vec<String>, Vec<String>) {
        let rows = raw.query(format!("SELECT CONCAT_WS('|',window_start,bucket_scope,bucket_id,model,requests,tokens_input) FROM usage_windows WHERE {predicate} ORDER BY window_start,bucket_scope,bucket_id,model")).unwrap();
        let units = raw.query(format!("SELECT CONCAT_WS('|',window_start,bucket_scope,bucket_id,model,unit,count) FROM usage_window_units WHERE {predicate} ORDER BY window_start,bucket_scope,bucket_id,model,unit")).unwrap();
        (rows, units)
    };
    let all = snapshot(&mut raw, "TRUE");
    let retained = snapshot(&mut raw, "window_start = 0 OR window_start >= 10");
    let purge = |cutoff| harness::block_on(StoreCalls::purge_usage_before(&*store, cutoff));
    assert_eq!(purge(0).unwrap(), 0);
    assert_eq!(snapshot(&mut raw, "TRUE"), all);
    assert_eq!(
        purge(10).unwrap(),
        8,
        "models and units are not separate windows; migrated model-only windows count"
    );
    assert_eq!(snapshot(&mut raw, "TRUE"), retained);
    assert_eq!(purge(10).unwrap(), 0);
    drop(store);
    let store = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(snapshot(&mut raw, "TRUE"), retained);
    let final_retained = snapshot(
        &mut raw,
        &format!("window_start = 0 OR window_start = {}", u64::MAX),
    );
    assert_eq!(
        harness::block_on(StoreCalls::purge_usage_before(&*store, u64::MAX)).unwrap(),
        18
    );
    assert_eq!(snapshot(&mut raw, "TRUE"), final_retained);
    assert_eq!(
        harness::block_on(StoreCalls::purge_usage_before(&*store, u64::MAX)).unwrap(),
        0
    );
    let billing: Vec<(String, u64)> = raw
        .query("SELECT CAST(key_id AS CHAR),requests FROM usage_metering")
        .unwrap();
    assert_eq!(billing, [("bill-key".to_string(), 41)]);
    let billing_units: Vec<(String, u64)> = raw
        .query("SELECT CAST(unit AS CHAR),count FROM usage_metering_units")
        .unwrap();
    assert_eq!(billing_units, [("images".to_string(), 29)]);
}

#[test]
fn usage_cleanup_rolls_back_both_tables_when_the_second_delete_is_refused() {
    use busbar_contract::store_calls::StoreCalls;
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("purge_rollback") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let mut raw = db.conn();
    let mut ddl = db.root.get_conn().unwrap();
    ddl.query_drop(format!("USE {}", db.name)).unwrap();
    raw.query_drop("INSERT INTO usage_windows (window_start,bucket_scope,bucket_id,model,requests) VALUES (5,'key','rollback','model',17)").unwrap();
    raw.query_drop("INSERT INTO usage_window_units (window_start,bucket_scope,bucket_id,model,unit,count) VALUES (5,'key','rollback','model','images',23)").unwrap();
    ddl.query_drop("CREATE TRIGGER refuse_second_window_delete BEFORE DELETE ON usage_windows FOR EACH ROW BEGIN IF NOT EXISTS (SELECT 1 FROM usage_window_units WHERE window_start = OLD.window_start AND bucket_scope = OLD.bucket_scope AND bucket_id = OLD.bucket_id) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'usage cleanup rollback probe'; END IF; END").unwrap();
    ddl.query_drop("CREATE TRIGGER refuse_second_unit_delete BEFORE DELETE ON usage_window_units FOR EACH ROW BEGIN IF NOT EXISTS (SELECT 1 FROM usage_windows WHERE window_start = OLD.window_start AND bucket_scope = OLD.bucket_scope AND bucket_id = OLD.bucket_id) THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'usage cleanup rollback probe'; END IF; END").unwrap();
    let result = harness::block_on(StoreCalls::purge_usage_before(&*store, 10));
    assert!(
        result.is_err(),
        "the database refuses the second table's delete"
    );
    let requests: Vec<u64> = raw.query("SELECT requests FROM usage_windows").unwrap();
    let units: Vec<u64> = raw.query("SELECT count FROM usage_window_units").unwrap();
    assert_eq!(requests, [17]);
    assert_eq!(units, [23]);
    ddl.query_drop("DROP TRIGGER refuse_second_window_delete")
        .unwrap();
    ddl.query_drop("DROP TRIGGER refuse_second_unit_delete")
        .unwrap();
    assert_eq!(
        harness::block_on(StoreCalls::purge_usage_before(&*store, 10)).unwrap(),
        1
    );
    assert_eq!(
        raw.query_first::<u64, _>("SELECT COUNT(*) FROM usage_windows")
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        raw.query_first::<u64, _>("SELECT COUNT(*) FROM usage_window_units")
            .unwrap(),
        Some(0)
    );
}

#[test]
fn usage_cleanup_waits_for_a_writer_then_removes_its_complete_old_window() {
    use busbar_contract::store_calls::StoreCalls;
    use std::sync::{mpsc, Arc};
    use std::time::{Duration, Instant};
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("purge_writer") else {
        return;
    };
    let store = Arc::new(MysqlStore::connect(&db.url).unwrap());
    let mut writer = db.conn();
    writer.query_drop("START TRANSACTION").unwrap();
    writer.query_drop("INSERT INTO usage_windows (window_start,bucket_scope,bucket_id,model,requests) VALUES (7,'key','writer','model',19)").unwrap();
    writer.query_drop("INSERT INTO usage_window_units (window_start,bucket_scope,bucket_id,model,unit,count) VALUES (7,'key','writer','model','images',31)").unwrap();
    let (finished, result) = mpsc::channel();
    let calls = Arc::clone(&store);
    let cleanup = std::thread::spawn(move || {
        let _ = finished.send(harness::block_on(StoreCalls::purge_usage_before(
            &**calls, 10,
        )));
    });
    let mut observer = db.root.get_conn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut waited = false;
    while Instant::now() < deadline {
        let waiting: u64 = observer.exec_first(
            "SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID = w.BLOCKING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA = :db AND l.OBJECT_NAME = 'usage_windows'",
            params! { "db" => &db.name },
        ).unwrap().unwrap();
        if waiting > 0 {
            waited = true;
            break;
        }
        if cleanup.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    writer.query_drop("COMMIT").unwrap();
    let removed = result
        .recv_timeout(Duration::from_secs(10))
        .expect("cleanup completes after the writer commits");
    cleanup.join().unwrap();
    assert!(
        waited,
        "cleanup must synchronize with the server's in-flight usage transaction"
    );
    assert_eq!(removed.unwrap(), 1);
    assert_eq!(
        writer
            .query_first::<u64, _>("SELECT COUNT(*) FROM usage_windows")
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        writer
            .query_first::<u64, _>("SELECT COUNT(*) FROM usage_window_units")
            .unwrap(),
        Some(0)
    );
}

mod metering_attribution;

mod token_clock;

mod raw_era_models;
/// An in-place `put_key` stamps `updated_at` with the write's time, not the key's creation time
/// (the upsert copies `VALUES(updated_at)` over the stored row).
#[test]
fn key_upsert_stamps_updated_at_with_the_write_time_not_created_at() {
    let mut key = sample_key("vk_updated_at", "gen-1");
    key.created_at = 1_000;
    let before = crate_now().unwrap();
    let p = key_params(&key, None, 1).unwrap();
    let crate::mysqlwire::Params::Named(map) = p else {
        panic!("key_params must be named");
    };
    let updated = match &map[b"updated".as_slice()] {
        mysql_common::value::Value::UInt(n) => *n,
        other => panic!("updated bound as {other:?}"),
    };
    assert!(
        updated >= before,
        "updated_at bound to {updated}, the key's created_at, not the write time {before}"
    );
}

/// A refusal that must roll back keeps its own reason when the ROLLBACK itself fails.
#[test]
fn a_failing_rollback_does_not_replace_the_refusal() {
    let text = "put_credential: slot holds a live credential";
    let kept = refusal_after_rollback(store_err(text), Err::<(), _>("connection reset"));
    assert!(
        kept.0.contains("slot holds a live credential"),
        "the refusal must survive a failed rollback: {}",
        kept.0
    );
    assert!(
        kept.0.contains("connection reset"),
        "the rollback failure is appended: {}",
        kept.0
    );
    let clean = refusal_after_rollback(store_err(text), Ok::<(), &str>(()));
    assert_eq!(clean.0, text);
}

#[path = "tests/exact_counts.rs"]
mod exact_counts;

mod migration_count_bounds;
