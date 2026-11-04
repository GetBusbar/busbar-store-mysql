// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{Arc, Barrier};

pub(super) fn rewrap(
    store: &MysqlStore,
    expected: &CredentialSecret,
    replacement: &str,
) -> RecordStoreResult<bool> {
    RecordStore::rewrap_credential(&**store, expected, replacement)
}

pub(super) fn row(store: &MysqlStore) -> CredentialSecret {
    store
        .lookup_credential_secret("sigv4", "public")
        .unwrap()
        .unwrap()
}

pub(super) fn revision(db: &ScratchDb) -> u64 {
    db.conn()
        .query_first("SELECT revision FROM store_sequence WHERE id=1")
        .unwrap()
        .unwrap()
}

#[test]
fn loaded_rewrap_requires_every_expected_field_without_spending_a_revision_on_refusal() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("rewrap_exact") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    let mut credential = sample_credential("owner", "public", 0);
    credential.meta.created_at = 9_007_199_254_740_993;
    credential.meta.updated_at = 9_007_199_254_740_995;
    credential.meta.expires_at = Some(u64::MAX - 1);
    store.put_credential(&credential).unwrap();
    db.conn()
        .query_drop("UPDATE credentials SET revoke_reason='preserve this metadata' WHERE public_id='public'")
        .unwrap();
    let expected = row(&store);
    let before = revision(&db);
    type CredentialChange = (&'static str, fn(&mut CredentialSecret));
    let changes: &[CredentialChange] = &[
        ("id", |c| c.meta.id.push('x')),
        ("key_id", |c| c.meta.key_id.push('x')),
        ("kind", |c| c.meta.kind.push('x')),
        ("slot", |c| c.meta.slot = 1),
        ("public_id", |c| c.meta.public_id.push('x')),
        ("secret_form", |c| c.meta.secret_form = SecretForm::Digest),
        ("created_at", |c| c.meta.created_at += 1),
        ("updated_at", |c| c.meta.updated_at += 1),
        ("expires_at", |c| c.meta.expires_at = None),
        ("revoked_at", |c| c.meta.revoked_at = Some(1)),
        ("revoke_reason", |c| c.meta.revoke_reason = None),
        ("revision", |c| c.meta.revision += 1),
        ("secret", |c| c.secret.push('x')),
    ];
    for (field, change) in changes {
        let mut altered = expected.clone();
        change(&mut altered);
        assert!(
            !rewrap(&store, &altered, "replacement").unwrap(),
            "a different {field} must refuse the entire CAS"
        );
        assert!(row(&store) == expected);
        assert_eq!(revision(&db), before, "refused {field} consumed a revision");
    }
    assert!(!rewrap(&store, &expected, &expected.secret).unwrap());
    assert_eq!(revision(&db), before, "an identical envelope is a no-op");
    assert!(rewrap(&store, &expected, "replacement").unwrap());
    let current = row(&store);
    let mut wanted = expected.clone();
    wanted.secret = "replacement".into();
    wanted.meta.revision = before + 1;
    assert!(
        current == wanted,
        "only the envelope and revision may change"
    );
    assert_eq!(revision(&db), before + 1);
    assert!(!rewrap(&store, &expected, "stale").unwrap());
    assert!(!rewrap(&store, &current, &current.secret).unwrap());
    assert_eq!(revision(&db), before + 1);
}

#[test]
fn independently_loaded_doors_rewrap_once_and_the_result_survives_reopen() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("rewrap") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    store
        .put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&store);
    let before = revision(&db);
    assert!(!rewrap(&store, &expected, &expected.secret).unwrap());
    let mut altered = expected.clone();
    altered.meta.updated_at += 1;
    assert!(!rewrap(&store, &altered, "altered-metadata").unwrap());
    let gate = Arc::new(Barrier::new(3));
    let connections = [
        MysqlStore::connect(&db.url).unwrap(),
        MysqlStore::connect(&db.url).unwrap(),
    ];
    let writers: Vec<_> = connections
        .into_iter()
        .zip(["envelope-a", "envelope-b"])
        .map(|(connection, envelope)| {
            let gate = Arc::clone(&gate);
            let expected = expected.clone();
            std::thread::spawn(move || {
                gate.wait();
                (envelope, rewrap(&connection, &expected, envelope).unwrap())
            })
        })
        .collect();
    gate.wait();
    let outcomes: Vec<_> = writers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|(_, applied)| *applied).count(), 1);
    let winner = outcomes.iter().find(|(_, applied)| *applied).unwrap().0;
    let current = row(&store);
    let mut wanted = expected.clone();
    wanted.secret = winner.into();
    wanted.meta.revision = current.meta.revision;
    assert!(current == wanted);
    assert!(current.meta.revision > expected.meta.revision);
    assert_eq!(
        revision(&db),
        before + 1,
        "only the winner consumes a revision"
    );
    assert!(!rewrap(&store, &expected, "stale").unwrap());
    assert!(!rewrap(&store, &current, &current.secret).unwrap());
    let mut ordinary = current.clone();
    ordinary.secret = "ordinary-put-must-not-rotate".into();
    assert!(store.put_credential(&ordinary).is_err());
    assert!(row(&store) == current);
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    assert!(row(&reopened) == current);
}

#[test]
fn loaded_rewrap_does_not_resurrect_revoked_deleted_or_reclaimed_credentials() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("rewrap_dead") else {
        return;
    };
    for delete in [false, true] {
        let store = MysqlStore::connect(&db.url).unwrap();
        let owner = if delete { "deleted" } else { "revoked" };
        store.put_key(&sample_key(owner, "hash")).unwrap();
        store
            .put_credential(&sample_credential(owner, owner, 0))
            .unwrap();
        let expected = store
            .lookup_credential_secret("sigv4", owner)
            .unwrap()
            .unwrap();
        if delete {
            store.delete_key(owner).unwrap();
        } else {
            store
                .revoke_credential(&expected.meta.id, "revoked")
                .unwrap();
        }
        let retired = store.list_credentials_since(0).unwrap();
        let before = revision(&db);
        assert!(!rewrap(&store, &expected, "resurrection").unwrap());
        assert!(store.list_credentials_since(0).unwrap() == retired);
        assert_eq!(revision(&db), before);
        if !delete {
            store
                .put_credential(&sample_credential(owner, "reclaimed", 0))
                .unwrap();
            let reclaimed = store.list_credentials_since(0).unwrap();
            let before = revision(&db);
            assert!(!rewrap(&store, &expected, "resurrection").unwrap());
            assert!(store.list_credentials_since(0).unwrap() == reclaimed);
            assert_eq!(revision(&db), before);
        }
    }
}

#[test]
fn loaded_rewrap_requires_a_live_owner_even_when_its_credential_row_still_exists() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("rewrap_owner") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    store
        .put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&store);
    db.conn()
        .query_drop("UPDATE api_keys SET deleted_at=7, enabled=FALSE WHERE id='owner'")
        .unwrap();
    let before = revision(&db);
    assert!(!rewrap(&store, &expected, "replacement").unwrap());
    assert!(row(&store) == expected);
    assert_eq!(revision(&db), before);
}

#[test]
fn failed_loaded_rewrap_rolls_back_both_the_revision_and_the_envelope() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("rewrap_failure") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    store
        .put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&store);
    let before = revision(&db);
    db.admin_conn().query_drop("CREATE TRIGGER refuse_rewrap BEFORE UPDATE ON credentials FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected write failure'").unwrap();
    assert!(rewrap(&store, &expected, "replacement").is_err());
    assert!(row(&store) == expected);
    assert_eq!(revision(&db), before);
    db.conn().query_drop("DROP TRIGGER refuse_rewrap").unwrap();
    assert!(rewrap(&store, &expected, "replacement").unwrap());
    assert_eq!(revision(&db), before + 1);
}
