// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn revision(db: &ScratchDb) -> u64 {
    db.conn()
        .query_first("SELECT revision FROM store_sequence WHERE id=1")
        .unwrap()
        .unwrap()
}

fn raw_envelopes(db: &ScratchDb) -> Vec<String> {
    db.conn()
        .query(
            "SELECT JSON_ARRAY(HEX(id),HEX(key_id),HEX(kind),slot,HEX(public_id),secret_form,
         created_at,updated_at,expires_at,revoked_at,revoke_reason,revision,TO_BASE64(secret))
         FROM credentials ORDER BY id",
        )
        .unwrap()
}

fn sorted(mut rows: Vec<CredentialSecret>) -> Vec<CredentialSecret> {
    rows.sort_by(|a, b| a.meta.id.cmp(&b.meta.id));
    rows
}

/// Two dirty revoked rows plus a live row; the resumable-DDL case also has an already-clean revoked row.
fn legacy_revoked_secrets(db: &ScratchDb, ddl_already_done: bool) -> Vec<CredentialSecret> {
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("retired", "r")).unwrap();
    store.put_key(&sample_key("live", "l")).unwrap();
    for (owner, public, slot) in [
        ("retired", "old_a", 0),
        ("retired", "old_b", 1),
        ("live", "current", 0),
    ] {
        store
            .put_credential(&sample_credential(owner, public, slot))
            .unwrap();
    }
    if ddl_already_done {
        store.put_key(&sample_key("clean", "c")).unwrap();
        let credential = sample_credential("clean", "clean", 0);
        store.put_credential(&credential).unwrap();
        store
            .revoke_credential(&credential.meta.id, "already clean")
            .unwrap();
    }
    let mut raw = db.conn();
    raw.query_drop(
        "UPDATE credentials SET revoked_at=177,updated_at=178,revoke_reason='historical reason'
         WHERE key_id='retired'",
    )
    .unwrap();
    let before = sorted(store.list_credentials_since(0).unwrap());
    drop(store);
    if !ddl_already_done {
        raw.query_drop("ALTER TABLE credentials DROP CHECK ck_cred_sigv4_secret")
            .or_else(|_| {
                raw.query_drop("ALTER TABLE credentials DROP CONSTRAINT ck_cred_sigv4_secret")
            })
            .unwrap();
        raw.query_drop(
            "ALTER TABLE credentials ADD CONSTRAINT ck_cred_sigv4_recov
             CHECK (kind <> 'sigv4' OR secret_form = 'recoverable')",
        )
        .unwrap();
    }
    raw.query_drop("UPDATE store_meta SET v='3' WHERE k='schema_version'")
        .unwrap();
    before
}

fn scrubbed(before: &[CredentialSecret], new_revision: u64) -> Vec<CredentialSecret> {
    before
        .iter()
        .cloned()
        .map(|mut row| {
            if row.meta.key_id == "retired" {
                row.secret.clear();
                row.meta.secret_form = SecretForm::None;
                row.meta.revision = new_revision;
            }
            row
        })
        .collect()
}

fn assert_published(db: &ScratchDb, store: &MysqlStore, before: &[CredentialSecret], cursor: u64) {
    assert_eq!(
        revision(db),
        cursor + 1,
        "one atomic scrub publishes one revision"
    );
    let expected = scrubbed(before, cursor + 1);
    assert!(sorted(store.list_credentials_since(0).unwrap()) == expected);
    let expected_delta: Vec<_> = expected
        .into_iter()
        .filter(|row| row.meta.key_id == "retired")
        .collect();
    assert!(sorted(store.list_credentials_since(cursor).unwrap()) == expected_delta,
        "a retained delta cursor must observe both scrubbed envelopes, with all other metadata intact");
}

#[test]
fn v12_scrub_publishes_exact_revoked_envelopes_to_an_existing_delta_cursor_and_reopens() {
    let _ddl = lock_fresh_database_ddl();
    for ddl_already_done in [false, true] {
        let Some(db) = ScratchDb::new("v12_revision") else {
            return;
        };
        let before = legacy_revoked_secrets(&db, ddl_already_done);
        let cursor = revision(&db);
        for _ in 0..2 {
            let store = MysqlStore::connect(&db.url).expect("upgrade/reopen");
            assert_published(&db, &store, &before, cursor);
            assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
            assert_eq!(meta_row(&db, "migrating_to"), None);
        }
    }
}

#[test]
fn v12_failed_scrub_rolls_back_every_envelope_and_the_sequence_then_reopens() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("v12_revision_rollback") else {
        return;
    };
    let before = legacy_revoked_secrets(&db, false);
    let cursor = revision(&db);
    let before_raw = raw_envelopes(&db);
    db.admin_conn()
        .query_drop(
            "CREATE TRIGGER refuse_revoked_scrub BEFORE UPDATE ON credentials FOR EACH ROW
         BEGIN IF OLD.revoked_at IS NOT NULL AND NEW.secret_form='none' THEN
         SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='v12 scrub rollback probe'; END IF; END",
        )
        .unwrap();
    let error = MysqlStore::connect(&db.url)
        .err()
        .expect("trigger rejects the scrub");
    assert!(error.contains("v12 scrub rollback probe"), "{error}");
    assert_eq!(
        revision(&db),
        cursor,
        "revision allocation rolls back with the failed scrub"
    );
    assert_eq!(schema_version_of(&db), "3");
    assert_eq!(
        meta_row(&db, "migrating_to"),
        Some(SCHEMA_VERSION.to_string())
    );

    assert!(
        raw_envelopes(&db) == before_raw,
        "all credential columns and row counts roll back"
    );
    let mut raw = db.conn();
    raw.query_drop("DROP TRIGGER refuse_revoked_scrub").unwrap();
    drop(raw);
    let store = MysqlStore::connect(&db.url).expect("a new open resumes after rollback");
    assert_published(&db, &store, &before, cursor);
}

#[test]
fn v12_committed_scrub_survives_a_later_stamp_failure_without_duplicate_revision() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("v12_revision_resume") else {
        return;
    };
    let before = legacy_revoked_secrets(&db, false);
    let cursor = revision(&db);
    db.admin_conn()
        .query_drop(format!(
            "CREATE TRIGGER refuse_v12_stamp BEFORE UPDATE ON store_meta FOR EACH ROW
         BEGIN IF OLD.k='schema_version' AND NEW.v='{SCHEMA_VERSION}' THEN
         SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='v12 postcommit stamp probe'; END IF; END"
        ))
        .unwrap();
    let error = MysqlStore::connect(&db.url)
        .err()
        .expect("the later version stamp fails");
    assert!(error.contains("v12 postcommit stamp probe"), "{error}");
    assert_eq!(
        revision(&db),
        cursor + 1,
        "the scrub and its revision committed together"
    );
    let scrubbed_count: u64 = db.conn().exec_first(
        "SELECT COUNT(*) FROM credentials WHERE key_id='retired' AND secret IS NULL AND secret_form='none' AND revision=?",
        (cursor + 1,),
    ).unwrap().unwrap();
    assert_eq!(scrubbed_count, 2);
    assert_eq!(schema_version_of(&db), "3");
    assert_eq!(
        meta_row(&db, "migrating_to"),
        Some(SCHEMA_VERSION.to_string())
    );
    db.conn()
        .query_drop("DROP TRIGGER refuse_v12_stamp")
        .unwrap();
    for _ in 0..2 {
        let store = MysqlStore::connect(&db.url).expect("resume after the committed scrub");
        assert_published(&db, &store, &before, cursor);
    }
}

#[test]
fn v12_upgrade_without_dirty_revoked_credentials_keeps_the_revision() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("v12_revision_noop") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("clean", "c")).unwrap();
    let credential = sample_credential("clean", "clean", 0);
    store.put_credential(&credential).unwrap();
    store
        .revoke_credential(&credential.meta.id, "already scrubbed")
        .unwrap();
    let before = sorted(store.list_credentials_since(0).unwrap());
    let cursor = revision(&db);
    drop(store);
    db.conn()
        .query_drop("UPDATE store_meta SET v='3' WHERE k='schema_version'")
        .unwrap();
    let reopened = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(revision(&db), cursor);
    assert!(sorted(reopened.list_credentials_since(0).unwrap()) == before);
    assert!(reopened.list_credentials_since(cursor).unwrap().is_empty());
}
