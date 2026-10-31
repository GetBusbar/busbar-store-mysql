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
