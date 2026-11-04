// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::abi::sdk::store::StoreSlots;
use busbar_contract::abi::store::OpId;
use busbar_contract::store_calls::StoreFailure;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

pub(super) fn transact(store: &MysqlStore, request: &Request) -> Result<Decision, StoreFailure> {
    super::harness::block_on(
        busbar_contract::store_calls::StoreCalls::record_transaction(&**store, request),
    )
}

pub(super) fn absent_put(counter: u64, key: &[u8], value: &[u8]) -> Request {
    Request {
        version: VERSION,
        op_id: OpId::from_parts(0x434f4e444954494f, counter),
        predicates: vec![Predicate {
            schema: "conditional".into(),
            key: key.to_vec(),
            expected: Expected::Absent,
        }],
        mutations: vec![Mutation::Put {
            schema: "conditional".into(),
            key: key.to_vec(),
            value: value.to_vec(),
        }],
    }
}

fn exact_put(counter: u64, key: &[u8], expected: &[u8], value: &[u8]) -> Request {
    let mut request = absent_put(counter, key, value);
    request.predicates[0].expected = Expected::Bytes(expected.to_vec());
    request
}

fn receipt(db: &ScratchDb, request: &Request) -> Option<Vec<u8>> {
    db.conn()
        .exec_first(
            "SELECT body FROM store_ops WHERE op_id=?",
            (&request.op_id.0[..],),
        )
        .unwrap()
}

fn bytes(store: &MysqlStore, key: &[u8]) -> Option<Vec<u8>> {
    store
        .record_get("conditional", key)
        .unwrap()
        .map(|b| b.as_slice().to_vec())
}

#[test]
fn loaded_conditional_capability_prestate_replay_and_body_conflict() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("conditional_replay") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    assert!(busbar_contract::store_calls::StoreCalls::supports_record_transaction(&*store));
    const { assert!(<crate::MysqlStore as StoreSlots>::RECORD_TRANSACTION) };
    store.record_put("conditional", b"a", b"old-a").unwrap();
    store.record_put("conditional", b"b", b"old-b").unwrap();
    let before = super::credential_rewrap::revision(&db);
    let mut request = exact_put(1, b"a", b"old-a", b"new-a");
    request.predicates.push(Predicate {
        schema: "conditional".into(),
        key: b"b".to_vec(),
        expected: Expected::Bytes(b"old-b".to_vec()),
    });

    request.mutations.insert(
        0,
        Mutation::Put {
            schema: "conditional".into(),
            key: b"b".to_vec(),
            value: b"new-b".to_vec(),
        },
    );
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(bytes(&store, b"a"), Some(b"new-a".to_vec()));
    assert_eq!(bytes(&store, b"b"), Some(b"new-b".to_vec()));
    assert_eq!(receipt(&db, &request), Some(request.fingerprint().to_vec()));
    assert_eq!(super::credential_rewrap::revision(&db), before);
    store.record_put("conditional", b"a", b"external").unwrap();
    assert_eq!(
        transact(&store, &request),
        Ok(Decision::Applied),
        "receipt precedes now-false predicates"
    );
    assert_eq!(
        bytes(&store, b"a"),
        Some(b"external".to_vec()),
        "replay cannot reapply mutations"
    );
    let mut different = request.clone();
    different.mutations[0] = Mutation::Delete {
        schema: "conditional".into(),
        key: b"b".to_vec(),
    };
    assert_eq!(transact(&store, &different), Err(StoreFailure::Conflict));
    assert_eq!(bytes(&store, b"b"), Some(b"new-b".to_vec()));
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(transact(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(bytes(&reopened, b"a"), Some(b"external".to_vec()));
}

#[test]
fn condition_conflict_has_no_record_receipt_or_revision_effect_and_is_not_opid_conflict() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("conditional_false") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store
        .record_put("conditional", b"guard", b"actual")
        .unwrap();
    store.record_put("conditional", b"target", b"keep").unwrap();
    let before = super::credential_rewrap::revision(&db);
    let mut request = exact_put(2, b"guard", b"expected", b"changed");
    request.mutations = vec![Mutation::Delete {
        schema: "conditional".into(),
        key: b"target".to_vec(),
    }];
    assert_eq!(transact(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(bytes(&store, b"target"), Some(b"keep".to_vec()));
    assert_eq!(receipt(&db, &request), None);
    assert_eq!(super::credential_rewrap::revision(&db), before);
    store
        .record_put("conditional", b"guard", b"expected")
        .unwrap();
    assert_eq!(
        transact(&store, &request),
        Ok(Decision::Applied),
        "a conflict stored no receipt"
    );
    assert_eq!(bytes(&store, b"target"), None);
}

#[test]
fn two_loaded_connections_choose_one_winner_from_the_same_present_or_absent_prestate() {
    let _ddl = lock_fresh_database_ddl();
    for present in [false, true] {
        let Some(db) = ScratchDb::new("conditional_race") else {
            return;
        };
        let first = MysqlStore::connect(&db.url).unwrap();
        let second = MysqlStore::connect(&db.url).unwrap();
        if present {
            first.record_put("conditional", b"winner", b"old").unwrap();
        }
        let mut a = absent_put(3, b"winner", b"first");
        let mut b = absent_put(4, b"winner", b"second");
        if present {
            a.predicates[0].expected = Expected::Bytes(b"old".to_vec());
            b.predicates[0].expected = Expected::Bytes(b"old".to_vec());
        }
        let barrier = Arc::new(Barrier::new(2));
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                transact(&first, &a)
            });
            let right = scope.spawn(|| {
                barrier.wait();
                transact(&second, &b)
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        assert!(
            (left == Ok(Decision::Applied) && right == Ok(Decision::ConditionConflict))
                || (right == Ok(Decision::Applied) && left == Ok(Decision::ConditionConflict)),
            "{left:?} {right:?}"
        );
        assert_eq!(
            receipt(&db, &a).is_some() as u8 + receipt(&db, &b).is_some() as u8,
            1
        );
        assert_eq!(
            bytes(&first, b"winner"),
            Some(if left == Ok(Decision::Applied) {
                b"first".to_vec()
            } else {
                b"second".to_vec()
            })
        );
    }
}

fn waiting_on_record(db: &ScratchDb, holder: u64) -> mysql::Result<bool> {
    waiting_record_connection(db, holder).map(|connection| connection.is_some())
}

fn waiting_record_connection(db: &ScratchDb, holder: u64) -> mysql::Result<Option<u64>> {
    waiting_connection(db, holder, "store_records")
}

pub(super) fn waiting_connection(
    db: &ScratchDb,
    holder: u64,
    table: &str,
) -> mysql::Result<Option<u64>> {
    let mut observer = db.root.get_conn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let connection: Option<u64> = observer.exec_first(
            "SELECT requester.PROCESSLIST_ID FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks b \
             ON b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID JOIN performance_schema.threads t ON t.THREAD_ID=b.THREAD_ID \
             JOIN performance_schema.threads requester ON requester.THREAD_ID=w.REQUESTING_THREAD_ID \
             WHERE b.OBJECT_SCHEMA=:db AND b.OBJECT_NAME=:table AND t.PROCESSLIST_ID=:holder LIMIT 1",
            params! { "db"=>&db.name,"holder"=>holder,"table"=>table })?;
        if connection.is_some() || Instant::now() >= deadline {
            return Ok(connection);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn ordinary_put_and_delete_cannot_bypass_absent_record_or_range_locks() {
    let _ddl = lock_fresh_database_ddl();

    for mode in 0..3 {
        let Some(db) = ScratchDb::new("conditional_legacy_locks") else {
            return;
        };
        let conditional = MysqlStore::connect(&db.url).unwrap();
        let legacy = MysqlStore::connect(&db.url).unwrap();
        conditional.record_put("conditional", b"b", b"old").unwrap();
        if mode != 0 {
            conditional
                .record_put("conditional", b"guard", b"g")
                .unwrap();
        }
        let mut request = absent_put(13 + mode, b"guard", b"unused");
        if mode != 0 {
            request.predicates[0].expected = Expected::Bytes(b"g".to_vec());
        }
        let first = if mode == 2 {
            conditional
                .record_put("conditional", b"r/a", b"old-range")
                .unwrap();
            Mutation::DeleteRange {
                schema: "conditional".into(),
                prefix: b"r/".to_vec(),
                exact_key_length: 3,
            }
        } else {
            Mutation::Put {
                schema: "conditional".into(),
                key: b"a".to_vec(),
                value: b"new-a".to_vec(),
            }
        };
        request.mutations = vec![
            first,
            Mutation::Put {
                schema: "conditional".into(),
                key: b"b".to_vec(),
                value: b"new-b".to_vec(),
            },
        ];
        let key = if mode == 2 {
            b"r/b".as_slice()
        } else {
            b"guard".as_slice()
        };
        let value = if mode == 1 {
            b"".as_slice()
        } else {
            b"legacy".as_slice()
        };
        let mut raw = db.conn();
        let holder: u64 = raw.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
        let mut lock = raw.start_transaction(mysql::TxOpts::default()).unwrap();
        lock.query_drop("SELECT value FROM store_records WHERE schema_id='conditional' AND rkey=X'62' FOR UPDATE").unwrap();
        let (waiting, legacy_wait, released, applied, ordinary) = std::thread::scope(|scope| {
            let applying = scope.spawn(|| transact(&conditional, &request));
            let waiting = waiting_record_connection(&db, holder);
            let ordinary = scope.spawn(|| legacy.record_put("conditional", key, value));
            let legacy_wait = match &waiting {
                Ok(Some(connection)) => waiting_connection(&db, *connection, "store_sequence"),
                _ => Ok(None),
            };
            let released = lock.rollback();
            (
                waiting,
                legacy_wait,
                released,
                applying.join(),
                ordinary.join(),
            )
        });
        released.unwrap();
        assert!(
            waiting.unwrap().is_some(),
            "the conditional operation reached its second mutation"
        );
        assert!(legacy_wait.unwrap().is_some(),"mode {mode}: actual ordinary write must wait on the conditional connection's sequence lock");
        assert_eq!(applied.unwrap(), Ok(Decision::Applied));
        assert_eq!(ordinary.unwrap(), Ok(()));
        assert_eq!(bytes(&conditional, b"b"), Some(b"new-b".to_vec()));
        assert_eq!(
            bytes(&conditional, key),
            if mode == 1 {
                None
            } else {
                Some(b"legacy".to_vec())
            }
        );
        if mode == 2 {
            assert_eq!(bytes(&conditional, b"r/a"), None);
        }
        assert_eq!(receipt(&db, &request), Some(request.fingerprint().to_vec()));
    }
}

#[test]
fn an_observer_never_reads_a_half_committed_multi_key_mutation() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("conditional_visibility") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    for (key, value) in [
        (b"a".as_slice(), b"old-a".as_slice()),
        (b"b", b"old-b"),
        (b"guard", b"g"),
    ] {
        store.record_put("conditional", key, value).unwrap();
    }
    let mut request = exact_put(5, b"guard", b"g", b"unused");
    request.mutations = vec![
        Mutation::Put {
            schema: "conditional".into(),
            key: b"a".to_vec(),
            value: b"new-a".to_vec(),
        },
        Mutation::Put {
            schema: "conditional".into(),
            key: b"b".to_vec(),
            value: b"new-b".to_vec(),
        },
    ];
    let mut raw = db.conn();
    let holder: u64 = raw.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
    let mut lock = raw.start_transaction(mysql::TxOpts::default()).unwrap();
    lock.query_drop(
        "SELECT value FROM store_records WHERE schema_id='conditional' AND rkey=X'62' FOR UPDATE",
    )
    .unwrap();
    let (waiting, observed, released, outcome) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| transact(&store, &request));
        let waiting = waiting_on_record(&db, holder);
        let observed=db.conn().exec::<(Vec<u8>,Vec<u8>),_,_>("SELECT rkey,value FROM store_records WHERE schema_id='conditional' AND rkey IN (X'61',X'62') ORDER BY rkey",());
        let released = lock.rollback();
        (waiting, observed, released, worker.join())
    });
    released.unwrap();
    assert!(
        waiting.unwrap(),
        "the real second mutation was blocked after the first"
    );
    assert_eq!(
        observed.unwrap(),
        vec![
            (b"a".to_vec(), b"old-a".to_vec()),
            (b"b".to_vec(), b"old-b".to_vec())
        ]
    );
    assert_eq!(outcome.unwrap(), Ok(Decision::Applied));
    assert_eq!(bytes(&store, b"a"), Some(b"new-a".to_vec()));
    assert_eq!(bytes(&store, b"b"), Some(b"new-b".to_vec()));
}

#[test]
fn a_mid_batch_server_error_rolls_back_all_records_and_the_receipt() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("conditional_rollback") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let mut request = absent_put(6, b"a", b"first");
    store.record_put("conditional", b"victim", b"keep").unwrap();
    request.mutations.insert(
        0,
        Mutation::DeleteRange {
            schema: "conditional".into(),
            prefix: b"v".to_vec(),
            exact_key_length: 6,
        },
    );
    request.mutations.push(Mutation::Put {
        schema: "conditional".into(),
        key: b"blocked".to_vec(),
        value: b"second".to_vec(),
    });
    db.admin_conn().query_drop("CREATE TRIGGER conditional_fail BEFORE INSERT ON store_records FOR EACH ROW BEGIN IF NEW.rkey=X'626c6f636b6564' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='forced conditional failure'; END IF; END").unwrap();
    let before = super::credential_rewrap::revision(&db);
    assert!(matches!(
        transact(&store, &request),
        Err(StoreFailure::Failed(_))
    ));
    assert_eq!(bytes(&store, b"a"), None);
    assert_eq!(bytes(&store, b"blocked"), None);
    assert_eq!(bytes(&store, b"victim"), Some(b"keep".to_vec()));
    assert_eq!(receipt(&db, &request), None);
    assert_eq!(super::credential_rewrap::revision(&db), before);
    db.conn()
        .query_drop("DROP TRIGGER conditional_fail")
        .unwrap();
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(bytes(&store, b"victim"), None);
}

#[test]
fn range_deletion_uses_exact_schema_binary_prefix_and_key_length_and_replays_no_effect() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("conditional_range") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    for key in [
        vec![255],
        vec![255, 1],
        vec![255, 2],
        vec![255, 2, 3],
        vec![254, 1],
    ] {
        store.record_put("conditional", &key, b"old").unwrap();
    }
    store.record_put("other", &[255, 1], b"other").unwrap();
    let mut request = exact_put(11, &[255, 1], b"old", b"unused");
    request.mutations = vec![Mutation::DeleteRange {
        schema: "conditional".into(),
        prefix: vec![255],
        exact_key_length: 2,
    }];
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    for key in [vec![255, 1], vec![255, 2]] {
        assert_eq!(bytes(&store, &key), None);
    }
    for key in [vec![255], vec![255, 2, 3], vec![254, 1]] {
        assert_eq!(bytes(&store, &key), Some(b"old".to_vec()));
    }
    assert_eq!(
        store
            .record_get("other", &[255, 1])
            .unwrap()
            .unwrap()
            .as_slice(),
        b"other"
    );
    store
        .record_put("conditional", &[255, 1], b"external")
        .unwrap();
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(bytes(&store, &[255, 1]), Some(b"external".to_vec()));

    for key in [b"_%\0a".as_slice(), b"_%\0long", b"X%\0a"] {
        store.record_put("conditional", key, b"keep").unwrap();
    }
    let mut bounded = exact_put(12, &[255, 1], b"external", b"unused");
    bounded.mutations = vec![Mutation::DeleteRange {
        schema: "conditional".into(),
        prefix: b"_%\0".to_vec(),
        exact_key_length: 4,
    }];
    assert_eq!(transact(&store, &bounded), Ok(Decision::Applied));
    assert_eq!(bytes(&store, b"_%\0a"), None);
    assert_eq!(bytes(&store, b"_%\0long"), Some(b"keep".to_vec()));
    assert_eq!(bytes(&store, b"X%\0a"), Some(b"keep".to_vec()));
}

#[test]
fn binary_addresses_values_validation_and_refusal_canaries_are_preserved() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("conditional_bytes") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let request = absent_put(7, &[0, 255, 1], &[255, 0, 2]);
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(bytes(&store, &[0, 255, 1]), Some(vec![255, 0, 2]));
    let mut invalid = absent_put(8, b"invalid", b"valid");
    invalid.predicates.push(invalid.predicates[0].clone());
    assert!(matches!(
        transact(&store, &invalid),
        Err(StoreFailure::Refused(_))
    ));
    assert_eq!(receipt(&db, &invalid), None);
    assert_eq!(bytes(&store, b"invalid"), None);
    let mut oversized = absent_put(9, b"canary", b"value");
    let schema = format!("CONDITIONAL-SECRET-CANARY{}", "x".repeat(765));
    oversized.mutations = vec![Mutation::Put {
        schema,
        key: b"canary".to_vec(),
        value: b"value".to_vec(),
    }];
    let Err(StoreFailure::Refused(message)) = transact(&store, &oversized) else {
        panic!("the column refuses its oversized address before commit")
    };
    assert!(!message.contains("CONDITIONAL-SECRET-CANARY"));
    assert_eq!(receipt(&db, &oversized), None);
}
