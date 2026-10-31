// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store-kind family alignment rules (R*/W*) against a live MySQL.

use super::*;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{MeteringDelta, Retention};

/// A name no other test (or earlier run) uses.
fn fresh(tag: &str) -> String {
    format!("{tag}_{}", ulid::Ulid::new())
}

/// A live key and its credential in slot `slot`, under fresh names.
fn seeded(tag: &str, slot: u8) -> (MysqlStore, String, CredentialSecret) {
    let s = fresh_store().expect("these tests need a live server");
    let key = fresh(tag);
    s.put_key(&sample_key(&key, "g")).unwrap();
    let cred = sample_credential(&key, &fresh("AKIA"), slot);
    s.put_credential(&cred).unwrap();
    (s, key, cred)
}

#[test]
fn w2_put_credential_names_a_missing_owner_in_the_family_words() {
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_w2_absent");
    let err = s
        .put_credential(&sample_credential(&key, &fresh("AKIA"), 0))
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "put_credential: key '{key}' does not exist; a credential must hang off a real key"
        )),
        "{err}"
    );
}

#[test]
fn w2_put_credential_names_a_tombstoned_owner_in_the_family_words() {
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_w2_dead");
    s.put_key(&sample_key(&key, "g")).unwrap();
    s.delete_key(&key).unwrap();
    let err = s
        .put_credential(&sample_credential(&key, &fresh("AKIA"), 0))
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "put_credential: key '{key}' is tombstoned; its credentials were revoked with it and \
             are never reissued"
        )),
        "{err}"
    );
}

#[test]
fn w2_a_taken_public_id_is_named_in_the_family_words_by_both_mint_ops() {
    let (s, _key, first) = seeded("vk_w2_pub", 0);
    let other = fresh("vk_w2_pub_other");
    s.put_key(&sample_key(&other, "g")).unwrap();
    let mut clash = sample_credential(&other, &first.meta.public_id, 0);
    clash.meta.id = fresh("cred_w2_clash");
    let want = format!(
        "public_id '{}' is already in use for kind 'sigv4'",
        first.meta.public_id
    );
    let err = s.put_credential(&clash).unwrap_err();
    assert!(
        err.to_string().contains(&format!("put_credential: {want}")),
        "{err}"
    );
    let minted = fresh("vk_w2_pub_mint");
    let mut clash = sample_credential(&minted, &first.meta.public_id, 0);
    clash.meta.id = fresh("cred_w2_clash2");
    let err = s
        .put_key_with_credential(&sample_key(&minted, "g"), &clash)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains(&format!("put_key_with_credential: {want}")),
        "{err}"
    );
}

/// The stored credential `id` as the revision delta carries it.
fn stored(s: &MysqlStore, id: &str) -> Option<CredentialSecret> {
    s.list_credentials_since(0)
        .unwrap()
        .into_iter()
        .find(|c| c.meta.id == id)
}

#[test]
fn r3_a_revoked_credential_id_is_never_re_minted() {
    let (s, key, cred) = seeded("vk_r3", 0);
    s.revoke_credential(&cred.meta.id, "rotated").unwrap();
    let err = s.put_credential(&cred).unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "put_credential: credential '{}' is revoked; a revoked credential is never re-minted",
            cred.meta.id
        )),
        "{err}"
    );
    let row = stored(&s, &cred.meta.id).expect("the revoked row is still there");
    assert!(row.meta.revoked_at.is_some(), "the refusal wrote nothing");

    // A NEW id minted into that slot reclaims it, with the new credential's created_at.
    let mut fresh_cred = sample_credential(&key, &fresh("AKIA"), 0);
    fresh_cred.meta.created_at = 4242;
    fresh_cred.meta.updated_at = 4242;
    s.put_credential(&fresh_cred).unwrap();
    let row = stored(&s, &fresh_cred.meta.id).expect("the new credential holds the slot");
    assert_eq!(row.meta.created_at, 4242);
    assert!(row.meta.revoked_at.is_none());
    assert!(
        stored(&s, &cred.meta.id).is_none(),
        "the old row is replaced"
    );
}

#[test]
fn r3_put_key_with_credential_refuses_a_revoked_credential_id_too() {
    let (s, key, cred) = seeded("vk_r3b", 0);
    s.revoke_credential(&cred.meta.id, "rotated").unwrap();
    let err = s
        .put_key_with_credential(&sample_key(&key, "g2"), &cred)
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "put_key_with_credential: credential '{}' is revoked; a revoked credential is never \
             re-minted",
            cred.meta.id
        )),
        "{err}"
    );
}

#[test]
fn r4_re_putting_an_identical_live_credential_is_ok_and_writes_nothing() {
    let (s, _key, cred) = seeded("vk_r4", 0);
    let before = stored(&s, &cred.meta.id).unwrap();
    s.put_credential(&cred)
        .expect("an identical re-put is the retry of a mint that landed");
    let after = stored(&s, &cred.meta.id).unwrap();
    assert_eq!(after.meta.revision, before.meta.revision, "no write");
    assert_eq!(after, before);
}

#[test]
fn r4_re_putting_a_live_credential_with_different_content_is_refused() {
    let (s, key, cred) = seeded("vk_r4b", 0);
    let want = format!(
        "put_credential: slot 0 for key '{key}' kind 'sigv4' holds a live credential; revoke it \
         first"
    );
    let mut changed = cred.clone();
    changed.secret = "v1:plain:other".to_string();
    let err = s.put_credential(&changed).unwrap_err();
    assert!(err.to_string().contains(&want), "{err}");
    let mut other_id = sample_credential(&key, &fresh("AKIA"), 0);
    other_id.meta.id = fresh("cred_other");
    let err = s.put_credential(&other_id).unwrap_err();
    assert!(err.to_string().contains(&want), "{err}");
    assert_eq!(stored(&s, &cred.meta.id).unwrap().secret, cred.secret);
}

#[test]
fn r5_put_key_with_credential_refuses_a_key_carrying_deleted_at() {
    let Some(s) = fresh_store() else { return };
    let id = fresh("vk_r5_dead");
    let mut key = sample_key(&id, "g");
    key.enabled = false;
    key.deleted_at = Some(5);
    let err = s
        .put_key_with_credential(&key, &sample_credential(&id, &fresh("AKIA"), 0))
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "put_key_with_credential: key '{id}' is tombstoned; a credential is never minted onto it"
        )),
        "{err}"
    );
    assert!(s.get_key(&id).unwrap().is_none(), "nothing was written");
}

#[test]
fn r5_put_key_with_credential_refuses_a_stored_tombstone_at_that_id() {
    let Some(s) = fresh_store() else { return };
    let id = fresh("vk_r5_stone");
    s.put_key(&sample_key(&id, "g")).unwrap();
    s.delete_key(&id).unwrap();
    let err = s
        .put_key_with_credential(
            &sample_key(&id, "g2"),
            &sample_credential(&id, &fresh("AKIA"), 0),
        )
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "put_key_with_credential: '{id}' is tombstoned and its id is never reissued"
        )),
        "{err}"
    );
    assert!(s.get_key(&id).unwrap().unwrap().deleted_at.is_some());
    assert!(s.list_credentials(&id).unwrap().is_empty());
}

#[test]
fn r5_put_key_with_credential_refuses_a_credential_of_another_key() {
    let Some(s) = fresh_store() else { return };
    let (id, other) = (fresh("vk_r5_own"), fresh("vk_r5_other"));
    s.put_key(&sample_key(&other, "g")).unwrap();
    let err = s
        .put_key_with_credential(
            &sample_key(&id, "g"),
            &sample_credential(&other, &fresh("AKIA"), 0),
        )
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "put_key_with_credential: the credential names key '{other}', not the key '{id}' \
             being minted with it"
        )),
        "{err}"
    );
    assert!(s.get_key(&id).unwrap().is_none(), "nothing was written");
    assert!(s.list_credentials(&other).unwrap().is_empty());
}

#[test]
fn r5_put_key_with_credential_over_an_existing_live_key_id_upserts() {
    let Some(s) = fresh_store() else { return };
    let id = fresh("vk_r5_live");
    s.put_key(&sample_key(&id, "g1")).unwrap();
    let mut key = sample_key(&id, "g2");
    key.name = "renamed".to_string();
    let cred = sample_credential(&id, &fresh("AKIA"), 0);
    s.put_key_with_credential(&key, &cred)
        .expect("a live key id is upserted, as put_key does");
    let got = s.get_key(&id).unwrap().unwrap();
    assert_eq!(
        (got.name.as_str(), got.generation_hash.as_str()),
        ("renamed", "g2")
    );
    assert_eq!(s.list_credentials(&id).unwrap().len(), 1);
}

/// `(secret IS NULL, secret_form, revoked_at, revoke_reason, revision)` of credential `id`, by raw SQL.
fn raw_credential(s: &MysqlStore, id: &str) -> (bool, String, Option<u64>, Option<String>, u64) {
    s.conn()
        .unwrap()
        .exec_first(
            "SELECT secret IS NULL, secret_form, revoked_at, revoke_reason, revision \
             FROM credentials WHERE id = :id",
            params! { "id" => id },
        )
        .unwrap()
        .expect("the credential row")
}

#[test]
fn r7_revoke_destroys_the_secret_and_a_repeat_is_a_no_op() {
    let (s, _key, cred) = seeded("vk_r7", 0);
    let before = raw_credential(&s, &cred.meta.id);
    assert!(!before.0, "a live credential holds its secret");
    s.revoke_credential(&cred.meta.id, "leaked").unwrap();

    let (null, form, revoked_at, reason, rev) = raw_credential(&s, &cred.meta.id);
    assert!(null, "the secret column is NULL after a revoke");
    assert_eq!(form, "none");
    assert!(revoked_at.is_some());
    assert_eq!(reason.as_deref(), Some("leaked"));
    assert!(rev > before.4, "the revision is bumped");

    let delta = stored(&s, &cred.meta.id).expect("the delta carries the revoked row");
    assert_eq!(delta.secret, "");
    assert_eq!(delta.meta.secret_form, SecretForm::None);
    assert!(delta.meta.revoked_at.is_some());

    s.revoke_credential(&cred.meta.id, "again").unwrap();
    assert_eq!(
        raw_credential(&s, &cred.meta.id),
        (null, form, revoked_at, reason, rev),
        "a repeat revoke changes nothing"
    );
}

/// A v11 database: this build's schema with the v11 `ck_cred_sigv4_recov` check and the v11
/// `fk_metering_key`, stamped 11, holding a revoked credential that still carries its secret.
fn build_v11_database(db: &ScratchDb) -> String {
    {
        let _store = MysqlStore::connect(&db.url).expect("open");
    }
    let mut c = db.conn();
    let checks: Vec<String> = c
        .query(
            "SELECT constraint_name FROM information_schema.table_constraints \
             WHERE table_schema = DATABASE() AND table_name = 'credentials' \
             AND constraint_type = 'CHECK' AND constraint_name LIKE 'ck_cred_sigv4%'",
        )
        .unwrap();
    for name in checks {
        if c.query_drop(format!("ALTER TABLE credentials DROP CHECK {name}"))
            .is_err()
        {
            c.query_drop(format!("ALTER TABLE credentials DROP CONSTRAINT {name}"))
                .unwrap();
        }
    }
    c.query_drop(
        "ALTER TABLE credentials ADD CONSTRAINT ck_cred_sigv4_recov \
         CHECK (kind <> 'sigv4' OR secret_form = 'recoverable')",
    )
    .unwrap();
    let fks: Vec<String> = c
        .query(
            "SELECT constraint_name FROM information_schema.table_constraints \
             WHERE table_schema = DATABASE() AND table_name = 'usage_metering' \
             AND constraint_type = 'FOREIGN KEY'",
        )
        .unwrap();
    if fks.is_empty() {
        c.query_drop(
            "ALTER TABLE usage_metering ADD CONSTRAINT fk_metering_key \
             FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE RESTRICT",
        )
        .unwrap();
    }
    let key = fresh("vk_v11");
    c.query_drop(format!(
        "INSERT INTO api_keys (id, name, labels, created_at, updated_at, revision) \
         VALUES ('{key}', 'k', '{{}}', 1000, 1000, 3)"
    ))
    .unwrap();
    for (id, public, revoked) in [
        ("cred_v11_dead", "AKIA_V11_DEAD", "2000"),
        ("cred_v11_live", "AKIA_V11_LIVE", "NULL"),
    ] {
        let slot = u8::from(revoked == "NULL");
        c.query_drop(format!(
            "INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form, \
             created_at, updated_at, revoked_at, revoke_reason, revision) VALUES ('{id}_{key}', \
             '{key}', 'sigv4', {slot}, '{public}_{key}', 'v1:plain:old', 'recoverable', 1000, 1000, \
             {revoked}, IF({revoked} IS NULL, NULL, 'old'), 4)"
        ))
        .unwrap();
    }
    c.query_drop("UPDATE store_meta SET v = '11' WHERE k = 'schema_version'")
        .unwrap();
    key
}

#[test]
fn r7_the_schema_step_lets_a_v11_database_destroy_secrets_and_keeps_its_rows() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("r7mig") else {
        return;
    };
    let key = build_v11_database(&db);
    let s = MysqlStore::connect(&db.url).expect("a v11 database opens and migrates");
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());

    let rows = s.list_credentials(&key).unwrap();
    assert_eq!(rows.len(), 2, "no row is lost");
    let dead = stored(&s, &format!("cred_v11_dead_{key}")).unwrap();
    assert_eq!(dead.secret, "", "a revoked row's secret is scrubbed");
    assert_eq!(dead.meta.secret_form, SecretForm::None);
    assert_eq!(dead.meta.revoke_reason.as_deref(), Some("old"));

    s.revoke_credential(&format!("cred_v11_live_{key}"), "now")
        .expect("the migrated check lets a sigv4 credential lose its secret");
    let live = stored(&s, &format!("cred_v11_live_{key}")).unwrap();
    assert_eq!(live.secret, "");
    drop(s);
    let again = MysqlStore::connect(&db.url).expect("a second open");
    assert_eq!(again.list_credentials(&key).unwrap().len(), 2);
}

/// A metering delta for `key_id` in `bucket`, with one request.
fn meter(key_id: &str, bucket: u64) -> MeteringDelta {
    MeteringDelta {
        key_id: key_id.to_string(),
        bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 3,
        tokens_output: 2,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: "v1".to_string(),
        priced_from_ms: 0,
        usage_units: BTreeMap::new(),
    }
}

/// A bucket no other test or run uses.
fn fresh_bucket() -> u64 {
    1_000_000_000 + (ulid::Ulid::new().random() as u64 % 8_000_000_000)
}

#[test]
fn r22_metering_for_a_key_the_store_never_saw_is_accepted() {
    let Some(s) = fresh_store() else { return };
    let (key, bucket) = (fresh("vk_r22_never_put"), fresh_bucket());
    s.add_metering(&meter(&key, bucket))
        .expect("no foreign key from metering to keys");
    let rows = s.list_metering(bucket).unwrap();
    assert!(rows.iter().any(|r| r.key_id == key && r.requests == 1));
}

#[test]
fn r22_the_schema_step_drops_fk_metering_key_and_keeps_the_rows() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("r22mig") else {
        return;
    };
    let key = build_v11_database(&db);
    let bucket = fresh_bucket();
    db.conn()
        .query_drop(format!(
            "INSERT INTO usage_metering (bucket, key_id, provider, model, requests) \
             VALUES ('{bucket:010}', '{key}', 'p', 'm', 5)"
        ))
        .unwrap();
    let s = MysqlStore::connect(&db.url).expect("a v11 database opens and migrates");
    let fks: Vec<String> = db
        .conn()
        .query(
            "SELECT constraint_name FROM information_schema.table_constraints \
             WHERE table_schema = DATABASE() AND table_name = 'usage_metering' \
             AND constraint_type = 'FOREIGN KEY'",
        )
        .unwrap();
    assert!(fks.is_empty(), "fk_metering_key is dropped: {fks:?}");
    let rows = s.list_metering(bucket).unwrap();
    assert!(rows.iter().any(|r| r.key_id == key && r.requests == 5));
    s.add_metering(&meter(&fresh("vk_r22_mig_never"), bucket))
        .expect("metering for any key id");
}

#[test]
fn r12_an_age_purge_of_tasks_takes_each_purged_tasks_event_chain() {
    let Some(url) = test_url() else { return };
    let _guard = lock_plane_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    clear_purge_band(&store);
    let (done, working, newer) = ("t_r12_done", "t_r12_working", "t_r12_newer");
    reset_tasks(&store, &[done, working, newer]);
    store
        .upsert_plane_record(terminal_task(done, "completed", 1_000_000_100).view())
        .unwrap();
    store
        .upsert_plane_record(active_task(working, "working", 1_000_000_100).view())
        .unwrap();
    store
        .upsert_plane_record(active_task(newer, "working", 1_000_000_300).view())
        .unwrap();
    for (t, h) in [(done, "d"), (working, "w"), (newer, "n")] {
        store
            .append_plane_record(event_rec(t, 1, "task.submitted", "", h).view())
            .unwrap();
    }
    let n = store
        .purge_plane_records("task", 1_000_000_200, Retention::Age)
        .unwrap();
    assert_eq!(
        n, 2,
        "the count is the task rows (terminal and active alike)"
    );
    assert!(
        events_of(&store, done).is_empty(),
        "a terminal task's chain goes"
    );
    assert!(
        events_of(&store, working).is_empty(),
        "an active task's chain goes under Age"
    );
    assert_eq!(
        events_of(&store, newer).len(),
        1,
        "a surviving task keeps its chain"
    );
    reset_tasks(&store, &[done, working, newer]);
    clear_purge_band(&store);
}

#[test]
fn r13_deleting_a_task_deletes_its_event_chain() {
    let Some(url) = test_url() else { return };
    let _guard = lock_plane_purge();
    let store = MysqlStore::connect(&url).expect("connect");
    let (gone, stays) = (fresh("t_r13_gone"), fresh("t_r13_stays"));
    let (gone, stays) = (gone.as_str(), stays.as_str());
    reset_tasks(&store, &[gone, stays]);
    for t in [gone, stays] {
        store
            .upsert_plane_record(active_task(t, "working", TASK_LIVE_TS).view())
            .unwrap();
        store
            .append_plane_record(event_rec(t, 1, "task.submitted", "", "h1").view())
            .unwrap();
        store
            .append_plane_record(event_rec(t, 2, "task.working", "h1", "h2").view())
            .unwrap();
    }
    store.delete_plane_record("task", gone).unwrap();
    assert!(get_task(&store, gone).is_none());
    assert!(
        events_of(&store, gone).is_empty(),
        "the chain goes with the task"
    );
    assert_eq!(
        events_of(&store, stays).len(),
        2,
        "another task's chain stays"
    );
    assert!(get_task(&store, stays).is_some());
    reset_tasks(&store, &[stays]);
}

fn refused_with(r: Result<(), OpRefused>, needle: &str) {
    match r {
        Err(OpRefused::Refused(t)) => assert!(t.contains(needle), "{t}"),
        other => panic!("expected a refusal naming {needle:?}, got {other:?}"),
    }
}

const ABOVE: u64 = i64::MAX as u64 + 1;

#[test]
fn r16_an_append_above_i64_max_is_refused_before_any_write() {
    let Some(s) = fresh_store() else { return };
    let t = fresh("t_r16_append");
    let t = t.as_str();
    let mut big_seq = event_rec(t, ABOVE, "task.submitted", "", "h");
    big_seq.ts = TASK_LIVE_TS;
    refused_with(
        s.append_plane_record_op(
            OpId::from_parts(ulid::Ulid::new().random() as u64 | 1, 3),
            big_seq.view(),
        ),
        "append_plane_record: seq",
    );
    let mut big_ts = event_rec(t, 1, "task.submitted", "", "h");
    big_ts.ts = ABOVE;
    refused_with(
        s.append_plane_record_op(
            OpId::from_parts(ulid::Ulid::new().random() as u64 | 1, 5),
            big_ts.view(),
        ),
        "append_plane_record: ts",
    );
    assert!(events_of(&s, t).is_empty(), "nothing was written");
    reset_tasks(&s, &[t]);
}

#[test]
fn r16_metering_priced_from_ms_above_i64_max_is_refused_before_any_write() {
    let Some(s) = fresh_store() else { return };
    let (key, bucket) = (fresh("vk_r16_meter"), fresh_bucket());
    let mut d = meter(&key, bucket);
    d.priced_from_ms = ABOVE;
    refused_with(
        s.add_metering_op(
            OpId::from_parts(ulid::Ulid::new().random() as u64 | 1, 7),
            &[d],
        ),
        "add_metering_batch: priced_from_ms",
    );
    assert!(s.list_metering(bucket).unwrap().is_empty());
}

#[test]
fn r16_redeem_with_expires_at_or_now_above_i64_max_is_refused() {
    let Some(s) = fresh_store() else { return };
    let (kind, token) = (fresh("r16_kind"), fresh("tok"));
    let err = s.redeem_plane_token(&kind, &token, ABOVE, 10).unwrap_err();
    assert!(
        err.to_string().contains("redeem_plane_token: expires_at"),
        "{err}"
    );
    let err = s.redeem_plane_token(&kind, &token, 100, ABOVE).unwrap_err();
    assert!(err.to_string().contains("redeem_plane_token: now"), "{err}");
    assert!(
        s.redeem_plane_token(&kind, &token, 100, 10).unwrap(),
        "the refusals spent nothing"
    );
}

#[test]
fn r16_upsert_and_append_through_the_sync_bridge_name_the_field() {
    let Some(s) = fresh_store() else { return };
    let t = fresh("t_r16_up");
    let mut rec = active_task(&t, "working", TASK_LIVE_TS);
    rec.seq = ABOVE;
    let err = s.upsert_plane_record(rec.view()).unwrap_err();
    assert!(
        err.to_string().contains("upsert_plane_record: seq"),
        "{err}"
    );
    let err = s
        .upsert_plane_record(active_task(&t, "working", ABOVE).view())
        .unwrap_err();
    assert!(err.to_string().contains("upsert_plane_record: ts"), "{err}");
    assert!(get_task(&s, &t).is_none());
}

#[test]
fn r21_a_duplicate_entry_is_rendered_naming_the_constraint_never_the_value() {
    let e = server_error(
        1062,
        "23000",
        "Duplicate entry 'SECRET_ID' for key 'credentials.uq_cred_public'",
    );
    let text = e.to_string();
    assert!(!text.contains("SECRET_ID"), "{text}");
    assert!(
        text.contains("duplicate credentials.uq_cred_public"),
        "{text}"
    );
    // A value that itself looks like the tail of the message does not confuse the constraint.
    let tricky = server_error(
        1062,
        "23000",
        "Duplicate entry 'x' for key 'fake' for key 'credentials.PRIMARY'",
    )
    .to_string();
    assert!(tricky.contains("duplicate credentials.PRIMARY"), "{tricky}");
    assert!(!tricky.contains("fake"), "{tricky}");
}

#[test]
fn r21_an_incorrect_value_error_names_the_column_never_the_value() {
    let text = server_error(
        1292,
        "22007",
        "Incorrect integer value: 'TOP_SECRET' for column 'slot' at row 1",
    )
    .to_string();
    assert!(!text.contains("TOP_SECRET"), "{text}");
    assert!(text.contains("slot"), "{text}");
    let text = server_error(
        1366,
        "HY000",
        "Incorrect string value: '\\xF0\\x9F' for column 'name' at row 1",
    )
    .to_string();
    assert!(!text.contains("xF0"), "{text}");
    assert!(text.contains("name"), "{text}");
}

#[test]
fn r21_a_live_duplicate_names_the_op_and_the_constraint() {
    let (s, _key, cred) = seeded("vk_r21", 0);
    let other = fresh("vk_r21_other");
    s.put_key(&sample_key(&other, "g")).unwrap();
    let mut clash = sample_credential(&other, &fresh("AKIA"), 1);
    clash.meta.id = cred.meta.id.clone();
    let text = s.put_credential(&clash).unwrap_err().to_string();
    assert!(text.contains("put_credential: duplicate "), "{text}");
    assert!(!text.contains("Duplicate entry"), "{text}");
    assert!(!text.contains(&cred.meta.id), "no stored value: {text}");
}

#[test]
fn redeem_plane_token_sweeps_only_its_own_kind() {
    let Some(s) = fresh_store() else { return };
    let (a, b) = (fresh("sweep_a"), fresh("sweep_b"));
    assert!(s.redeem_plane_token(&a, "t1", 100, 10).unwrap());
    // Another kind redeems long after `a`'s entry lapsed: that entry is not its to sweep.
    assert!(s.redeem_plane_token(&b, "x", 5_000, 1_000).unwrap());
    let kept: Option<u64> = s
        .conn()
        .unwrap()
        .exec_first(
            "SELECT expires_at FROM plane_tokens WHERE kind = :k AND token = 't1'",
            params! { "k" => &a },
        )
        .unwrap();
    assert_eq!(kept, Some(100), "a redemption sweeps its own kind only");
    // Its own kind's lapsed entry IS swept by its own redemption.
    assert!(s.redeem_plane_token(&a, "t2", 5_000, 1_000).unwrap());
    let swept: Option<u64> = s
        .conn()
        .unwrap()
        .exec_first(
            "SELECT expires_at FROM plane_tokens WHERE kind = :k AND token = 't1'",
            params! { "k" => &a },
        )
        .unwrap();
    assert_eq!(swept, None);
}

/// TA12: a redemption at the top of the signed range stores and sweeps correctly. The kind is this
/// test's own, so no other test's ledger rows can be swept by (or sweep) these.
#[test]
fn ta12_redeem_plane_token_near_i64_max_stores_and_sweeps_correctly() {
    let Some(s) = fresh_store() else { return };
    let kind = fresh("ta12");
    let top = i64::MAX as u64;
    assert!(s.redeem_plane_token(&kind, "high", top, 10).unwrap());
    assert!(s.redeem_plane_token(&kind, "low", 50, 10).unwrap());
    // now == i64::MAX: the entry expiring AT now is kept, the lapsed one is swept.
    assert!(s.redeem_plane_token(&kind, "fresh", top, top).unwrap());
    assert!(
        !s.redeem_plane_token(&kind, "high", top, top).unwrap(),
        "an entry expiring exactly at now is still spent"
    );
    assert!(
        s.redeem_plane_token(&kind, "low", 50, 10).unwrap(),
        "the lapsed entry was swept, so its token redeems afresh"
    );
    assert!(!s.redeem_plane_token(&kind, "fresh", top, 11).unwrap());
}

#[test]
fn w4_a_connect_failure_is_one_prefix_then_the_driver_words() {
    let e = MysqlStore::connect("mysql://u:CANARYpw9@127.0.0.1:1/definitely_not_a_real_db")
        .err()
        .expect("nothing listens on port 1");
    let prefix = "mysql store: failed to connect:";
    assert_eq!(e.matches(prefix).count(), 1, "{e}");
    let driver = e.split_once(prefix).expect("the store prefix").1;
    assert!(driver.contains("Could not connect"), "{e}");
    assert!(driver.contains("connection was refused"), "{e}");
    assert!(!e.contains("CANARYpw9"), "{e}");
}

#[test]
fn w5_list_keys_orders_by_created_at_then_id() {
    let Some(s) = fresh_store() else { return };
    let p = fresh("vk_w5k");
    for (suffix, created) in [("z", 500), ("b", 1000), ("a", 1000)] {
        let mut k = sample_key(&format!("{p}_{suffix}"), "g");
        k.created_at = created;
        s.put_key(&k).unwrap();
    }
    let got: Vec<String> = s
        .list_keys()
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .filter(|id| id.starts_with(&p))
        .collect();
    assert_eq!(got, [format!("{p}_z"), format!("{p}_a"), format!("{p}_b")]);
}

#[test]
fn w5_list_keys_since_orders_by_revision() {
    let Some(s) = fresh_store() else { return };
    let p = fresh("vk_w5r");
    for suffix in ["z", "m", "a"] {
        s.put_key(&sample_key(&format!("{p}_{suffix}"), "g"))
            .unwrap();
    }
    let got: Vec<String> = s
        .list_keys_since(0)
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .filter(|id| id.starts_with(&p))
        .collect();
    assert_eq!(got, [format!("{p}_z"), format!("{p}_m"), format!("{p}_a")]);
}

#[test]
fn w5_list_credentials_orders_by_kind_then_slot() {
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_w5c");
    s.put_key(&sample_key(&key, "g")).unwrap();
    let mut late = sample_credential(&key, &fresh("AKIA"), 1);
    late.meta.id = fresh("cred_a");
    let mut early = sample_credential(&key, &fresh("AKIA"), 0);
    early.meta.id = fresh("cred_b");
    s.put_credential(&late).unwrap();
    s.put_credential(&early).unwrap();
    let slots: Vec<u8> = s
        .list_credentials(&key)
        .unwrap()
        .into_iter()
        .map(|c| c.slot)
        .collect();
    assert_eq!(slots, [0, 1]);
}
