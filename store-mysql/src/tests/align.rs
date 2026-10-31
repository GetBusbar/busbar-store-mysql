// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store-kind family alignment rules (R*/W*) against a live MySQL.

use super::*;

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
