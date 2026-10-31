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
