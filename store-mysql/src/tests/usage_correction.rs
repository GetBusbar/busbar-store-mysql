// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::correction::{
    self, Decision, Request, UsageAddress, UsageChange,
};
use busbar_contract::abi::sdk::store::{OpRefused, StoreSlots};
use busbar_contract::abi::store::OpId;
use busbar_contract::store_calls::StoreFailure;
use std::sync::{Arc, Barrier};

const KEY: &str = "correction-key";
const GENERATION: &str = "correction-generation";
const DAY: u64 = 86_400;
const NODE: u64 = 0x434f5252454354;
const MODEL: &str = "correction-model";
const OPEN_UNIT: &str = "audio_seconds";
const BLOCKED_BUCKET: &str = "b";

fn ledger(count: u64) -> UsageLedger {
    ledger_parts(count, count)
}

/// Request width and quantity width are independent: these fixtures state both explicitly.
fn ledger_parts(requests: u64, quantity: u64) -> UsageLedger {
    UsageLedger {
        requests,
        billable_requests: requests,
        models: vec![ModelTokens {
            scale: 6,
            model: MODEL.into(),
            usage_units: units(&[(UNIT_INPUT, quantity), (OPEN_UNIT, quantity)]),
        }],
    }
}

fn candidate(counter: u64, expected: UsageLedger, replacement: UsageLedger) -> Request {
    Request {
        version: correction::VERSION,
        op_id: OpId::from_parts(NODE, counter),
        key_id: KEY.into(),
        day_start: DAY,
        metering: Vec::new(),
        usage: vec![UsageChange {
            address: UsageAddress {
                bucket_id: "a".into(),
                window_start: DAY,
            },
            expected,
            replacement,
        }],
    }
}

fn apply(store: &MysqlStore, request: &Request) -> Result<Decision, StoreFailure> {
    harness::block_on(
        busbar_contract::store_calls::StoreCalls::apply_usage_correction(&**store, request),
    )
}

fn receipt(db: &ScratchDb, request: &Request) -> Option<Vec<u8>> {
    db.conn()
        .exec_first(
            "SELECT body FROM store_ops WHERE op_id=?",
            (&request.op_id.0[..],),
        )
        .unwrap()
}

fn read(store: &MysqlStore, bucket: &str) -> UsageLedger {
    let mut row = store.get_usage(bucket, DAY).unwrap();
    correction::canonical_ledger(&mut row).unwrap();
    row
}

fn prepare(db: &ScratchDb) -> MysqlStore {
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key(KEY, GENERATION)).unwrap();
    store
}

#[test]
fn loaded_correction_replaces_unsigned_counts_and_replays_before_predicates() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_replay") else {
        return;
    };
    let store = prepare(&db);
    assert!(busbar_contract::store_calls::StoreCalls::supports_usage_correction(&*store));
    const { assert!(<crate::MysqlStore as StoreSlots>::USAGE_CORRECTION) };
    let mut request = candidate(
        1,
        UsageLedger::default(),
        ledger_parts(u64::MAX, i64::MAX as u64),
    );
    request.usage.insert(
        0,
        UsageChange {
            address: UsageAddress {
                bucket_id: "a".into(),
                window_start: 0,
            },
            expected: UsageLedger::default(),
            replacement: ledger(11),
        },
    );
    for bucket in [correction::ADJUST_UP_BUCKET, correction::ADJUST_DOWN_BUCKET] {
        request.usage.push(UsageChange {
            address: UsageAddress {
                bucket_id: bucket.into(),
                window_start: DAY,
            },
            expected: UsageLedger::default(),
            replacement: ledger(12),
        });
    }
    let revision = super::credential_rewrap::revision(&db);
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    assert_eq!(read(&store, "a"), ledger_parts(u64::MAX, i64::MAX as u64));
    assert_eq!(store.get_usage("a", 0).unwrap(), ledger(11));
    assert_eq!(read(&store, correction::ADJUST_UP_BUCKET), ledger(12));
    assert_eq!(read(&store, correction::ADJUST_DOWN_BUCKET), ledger(12));
    assert_eq!(
        receipt(&db, &request),
        Some(
            busbar_contract::abi::sdk::store::dedupe::Dedupe::usage_correction(&request)
                .body()
                .to_vec()
        )
    );
    assert_eq!(super::credential_rewrap::revision(&db), revision);
    store.delete_key(KEY).unwrap();
    store.put_usage("a", DAY, &ledger(3)).unwrap();
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    assert_eq!(read(&store, "a"), ledger(3));
    let mut changed = request.clone();
    changed.usage[0].replacement = ledger(4);
    assert_eq!(apply(&store, &changed), Err(StoreFailure::Conflict));
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(apply(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(read(&reopened, "a"), ledger(3));
}

#[test]
fn stale_usage_missing_key_and_invalid_requests_have_no_effect_or_receipt() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_conflict") else {
        return;
    };
    let store = prepare(&db);
    store.put_usage("a", DAY, &ledger(100)).unwrap();
    let mut request = candidate(2, ledger(100), ledger(40));
    request.usage.push(UsageChange {
        address: UsageAddress {
            bucket_id: BLOCKED_BUCKET.into(),
            window_start: DAY,
        },
        expected: ledger(99),
        replacement: ledger(9),
    });
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(read(&store, "a"), ledger(100));
    assert_eq!(read(&store, BLOCKED_BUCKET), UsageLedger::default());
    assert_eq!(receipt(&db, &request), None);
    request.usage[1].expected = UsageLedger::default();
    let mut missing = request.clone();
    missing.key_id.push_str("-missing");
    assert_eq!(apply(&store, &missing), Ok(Decision::ConditionConflict));
    assert_eq!(receipt(&db, &missing), None);
    store.delete_key(KEY).unwrap();
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    assert_eq!(receipt(&db, &request), None);
    request.version = correction::VERSION + 1;
    assert!(matches!(
        apply(&store, &request),
        Err(StoreFailure::Refused(_))
    ));
    assert_eq!(receipt(&db, &request), None);
    assert_eq!(read(&store, "a"), ledger(100));
}

#[test]
fn present_and_absent_prestate_races_accept_one_correction() {
    let _ddl = lock_fresh_database_ddl();
    for present in [false, true] {
        let Some(db) = ScratchDb::new("correction_race") else {
            return;
        };
        let first = prepare(&db);
        let second = MysqlStore::connect(&db.url).unwrap();
        let expected = if present {
            ledger(100)
        } else {
            UsageLedger::default()
        };
        if present {
            first.put_usage("a", DAY, &expected).unwrap();
        }
        let left = candidate(3, expected.clone(), ledger(40));
        let right = candidate(4, expected, ledger(60));
        let barrier = Arc::new(Barrier::new(2));
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                barrier.wait();
                apply(&first, &left)
            });
            let b = scope.spawn(|| {
                barrier.wait();
                apply(&second, &right)
            });
            (a.join().unwrap(), b.join().unwrap())
        });
        assert!(
            (a == Ok(Decision::Applied) && b == Ok(Decision::ConditionConflict))
                || (b == Ok(Decision::Applied) && a == Ok(Decision::ConditionConflict)),
            "{a:?} {b:?}"
        );
        let (winner, loser) = if a == Ok(Decision::Applied) {
            (&left, &right)
        } else {
            (&right, &left)
        };
        assert_eq!(read(&first, "a"), winner.usage[0].replacement);
        assert!(receipt(&db, winner).is_some());
        assert_eq!(receipt(&db, loser), None);
    }
}

fn meter() -> MeteringDelta {
    MeteringDelta {
        scale: 6,
        key_id: KEY.into(),
        bucket: DAY,
        model: MODEL.into(),
        provider: "provider".into(),
        key_group_at_use: "historical-group".into(),
        pricing_version: "historical-version".into(),
        priced_from_ms: DAY * 1_000,
        requests: 1,
        billable_requests: 2,
        tokens_input: 3,
        tokens_output: 4,
        tokens_cache_read: 5,
        tokens_cache_write: 6,
        usage_units: units(&[(OPEN_UNIT, 7)]),
    }
}

#[test]
fn full_day_selection_compares_every_c4_identity_and_counter() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_metering") else {
        return;
    };
    let store = prepare(&db);
    store.add_metering(&meter()).unwrap();
    let mut request = candidate(5, UsageLedger::default(), ledger(1));
    assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
    request.metering = store.list_metering(DAY).unwrap();
    correction::canonical_metering(&mut request.metering);
    let original = request.metering[0].clone();

    #[derive(Clone, Copy)]
    enum Field {
        Model,
        Provider,
        Group,
        Version,
        Epoch,
        Requests,
        Billable,
        Input,
        Output,
        CacheRead,
        CacheWrite,
        Open,
        MissingOpen,
    }
    for field in [
        Field::Model,
        Field::Provider,
        Field::Group,
        Field::Version,
        Field::Epoch,
        Field::Requests,
        Field::Billable,
        Field::Input,
        Field::Output,
        Field::CacheRead,
        Field::CacheWrite,
        Field::Open,
        Field::MissingOpen,
    ] {
        let row = &mut request.metering[0];
        match field {
            Field::Model => row.model.push('x'),
            Field::Provider => row.provider.push('x'),
            Field::Group => row.key_group_at_use.push('x'),
            Field::Version => row.pricing_version.push('x'),
            Field::Epoch => row.priced_from_ms += 1,
            Field::Requests => row.requests += 1,
            Field::Billable => row.billable_requests += 1,
            Field::Input => row.tokens_input += 1,
            Field::Output => row.tokens_output += 1,
            Field::CacheRead => row.tokens_cache_read += 1,
            Field::CacheWrite => row.tokens_cache_write += 1,
            Field::Open => {
                row.usage_units.insert(OPEN_UNIT.into(), 8);
            }
            Field::MissingOpen => {
                row.usage_units.clear();
            }
        }
        assert_eq!(apply(&store, &request), Ok(Decision::ConditionConflict));
        assert_eq!(receipt(&db, &request), None);
        assert_eq!(read(&store, "a"), UsageLedger::default());
        request.metering[0] = original.clone();
    }
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
}

#[test]
fn later_row_failure_rolls_back_prior_replacements_and_receipt() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_rollback") else {
        return;
    };
    let store = prepare(&db);
    let mut request = candidate(6, UsageLedger::default(), ledger(1));
    request.usage.push(UsageChange {
        address: UsageAddress {
            bucket_id: BLOCKED_BUCKET.into(),
            window_start: DAY,
        },
        expected: UsageLedger::default(),
        replacement: ledger(2),
    });
    db.admin_conn().query_drop("CREATE TRIGGER reject_correction_row BEFORE INSERT ON usage_windows FOR EACH ROW BEGIN IF NEW.bucket_id = 'b' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='correction fault'; END IF; END").unwrap();
    assert!(matches!(
        apply(&store, &request),
        Err(StoreFailure::Failed(_))
    ));
    assert_eq!(read(&store, "a"), UsageLedger::default());
    assert_eq!(read(&store, BLOCKED_BUCKET), UsageLedger::default());
    assert_eq!(receipt(&db, &request), None);
    db.conn()
        .query_drop("DROP TRIGGER reject_correction_row")
        .unwrap();
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
}

#[derive(Clone, Copy, Debug)]
enum OrdinaryWrite {
    AbsentInsert,
    UsageBatch,
    Metering,
    MeteringBatch,
    KeyDelete,
    Purge,
}

#[test]
fn ordinary_writers_wait_until_all_rows_and_receipt_commit() {
    let _ddl = lock_fresh_database_ddl();
    for mode in [
        OrdinaryWrite::AbsentInsert,
        OrdinaryWrite::UsageBatch,
        OrdinaryWrite::Metering,
        OrdinaryWrite::MeteringBatch,
        OrdinaryWrite::KeyDelete,
        OrdinaryWrite::Purge,
    ] {
        let Some(db) = ScratchDb::new("correction_ordinary") else {
            return;
        };
        let correcting = prepare(&db);
        let ordinary = MysqlStore::connect(&db.url).unwrap();
        correcting
            .put_usage(BLOCKED_BUCKET, DAY, &ledger(1))
            .unwrap();
        let mut request = candidate(7, UsageLedger::default(), ledger(2));
        request.usage.push(UsageChange {
            address: UsageAddress {
                bucket_id: BLOCKED_BUCKET.into(),
                window_start: DAY,
            },
            expected: ledger(1),
            replacement: ledger(3),
        });
        let mut raw = db.conn();
        let holder: u64 = raw.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
        let mut lock = raw.start_transaction(mysql::TxOpts::default()).unwrap();
        lock.exec_drop("SELECT model FROM usage_windows WHERE window_start=:day AND bucket_scope='key' AND bucket_id=:bucket AND model='' FOR UPDATE",
            params! { "day"=>DAY, "bucket"=>BLOCKED_BUCKET }).unwrap();
        let (waiting, ordinary_wait, released, applied, written) = std::thread::scope(|scope| {
            let applying = scope.spawn(|| apply(&correcting, &request));
            let waiting =
                super::conditional_records::waiting_connection(&db, holder, "usage_windows");
            let writing = scope.spawn(|| -> Result<(), String> {
                match mode {
                    OrdinaryWrite::AbsentInsert => {
                        ordinary.put_usage("a", DAY, &ledger(9)).map_err(|e| e.0)
                    }
                    OrdinaryWrite::UsageBatch => ordinary
                        .add_usage_op(
                            OpId::from_parts(NODE, 8),
                            "a",
                            DAY,
                            &UsageDelta {
                                requests: 1,
                                ..Default::default()
                            },
                        )
                        .map_err(|e| format!("{e:?}")),
                    OrdinaryWrite::Metering => ordinary.add_metering(&meter()).map_err(|e| e.0),
                    OrdinaryWrite::MeteringBatch => ordinary
                        .add_metering_op(OpId::from_parts(NODE, 9), &[meter()])
                        .map_err(|e| format!("{e:?}")),
                    OrdinaryWrite::KeyDelete => ordinary.delete_key(KEY).map_err(|e| e.0),
                    OrdinaryWrite::Purge => harness::block_on(
                        busbar_contract::store_calls::StoreCalls::purge_usage_before(
                            &*ordinary,
                            DAY + 1,
                        ),
                    )
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                }
            });
            let ordinary_wait = match &waiting {
                Ok(Some(connection)) => super::conditional_records::waiting_connection(
                    &db,
                    *connection,
                    "store_sequence",
                ),
                _ => Ok(None),
            };
            let released = lock.rollback();
            (
                waiting,
                ordinary_wait,
                released,
                applying.join(),
                writing.join(),
            )
        });
        released.unwrap();
        assert!(
            waiting.unwrap().is_some(),
            "correction must hold authority while blocked replacing b: {mode:?}"
        );
        assert!(
            ordinary_wait.unwrap().is_some(),
            "ordinary writer must share authority: {mode:?}"
        );
        assert_eq!(applied.unwrap(), Ok(Decision::Applied));
        written.unwrap().unwrap();
        assert_eq!(
            receipt(&db, &request),
            Some(
                busbar_contract::abi::sdk::store::dedupe::Dedupe::usage_correction(&request)
                    .body()
                    .to_vec()
            )
        );
        match mode {
            OrdinaryWrite::AbsentInsert => assert_eq!(read(&correcting, "a"), ledger(9)),
            OrdinaryWrite::UsageBatch => assert_eq!(read(&correcting, "a").requests, 3),
            OrdinaryWrite::Metering | OrdinaryWrite::MeteringBatch => {
                assert_eq!(correcting.list_metering(DAY).unwrap().len(), 1)
            }
            OrdinaryWrite::KeyDelete => assert!(correcting
                .get_key(KEY)
                .unwrap()
                .unwrap()
                .deleted_at
                .is_some()),
            OrdinaryWrite::Purge => assert_eq!(read(&correcting, "a"), UsageLedger::default()),
        }
    }
}

#[test]
fn fresh_legacy_adjustments_are_refused_but_exact_prior_receipts_replay() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_legacy") else {
        return;
    };
    let store = prepare(&db);
    let delta = UsageDelta {
        requests: 1,
        ..Default::default()
    };
    let cells = [(correction::ADJUST_UP_BUCKET, DAY, delta)];
    let op = OpId::from_parts(NODE, 10);
    assert!(matches!(
        store.add_usage_op(op, cells[0].0, cells[0].1, &cells[0].2),
        Err(OpRefused::Refused(_))
    ));
    assert!(store
        .put_usage(correction::ADJUST_DOWN_BUCKET, DAY, &ledger(1))
        .is_err());
    let dedupe = busbar_contract::abi::sdk::store::dedupe::Dedupe::usage(&cells);
    db.conn()
        .exec_drop(
            "INSERT INTO store_ops (op_id,recorded_at,body,answer) VALUES (:op,:at,:body,'null')",
            params! { "op"=>&op.0[..], "at"=>crate_now().unwrap(), "body"=>&dedupe.body()[..] },
        )
        .unwrap();
    assert_eq!(
        store.add_usage_op(op, cells[0].0, cells[0].1, &cells[0].2),
        Ok(())
    );
    let changed = UsageDelta {
        requests: 2,
        ..Default::default()
    };
    assert_eq!(
        store.add_usage_op(op, cells[0].0, DAY, &changed),
        Err(OpRefused::Conflict)
    );
    assert_eq!(
        read(&store, correction::ADJUST_UP_BUCKET),
        UsageLedger::default()
    );
}

#[test]
fn dropping_a_pending_write_behind_correction_completes_atomically_and_preserves_exact_retry() {
    use std::future::Future;
    use std::sync::mpsc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    const CANCEL_POLL: Duration = Duration::from_millis(10);

    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_cancel") else {
        return;
    };
    let store = prepare(&db);
    store.put_usage(BLOCKED_BUCKET, DAY, &ledger(1)).unwrap();
    let mut request = candidate(11, UsageLedger::default(), ledger(2));
    request.usage.push(UsageChange {
        address: UsageAddress {
            bucket_id: BLOCKED_BUCKET.into(),
            window_start: DAY,
        },
        expected: ledger(1),
        replacement: ledger(3),
    });
    let mut raw = db.conn();
    let holder: u64 = raw.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
    let mut lock = raw.start_transaction(mysql::TxOpts::default()).unwrap();
    lock.exec_drop("SELECT model FROM usage_windows WHERE window_start=:day AND bucket_scope='key' AND bucket_id=:bucket AND model='' FOR UPDATE",
        params! { "day"=>DAY, "bucket"=>BLOCKED_BUCKET }).unwrap();
    let (cancel, cancelled) = mpsc::channel();
    let (waiting, stopped) = std::thread::scope(|scope| {
        let store = &store;
        let request = &request;
        let worker = scope.spawn(move || {
            let mut future =
                busbar_contract::store_calls::StoreCalls::apply_usage_correction(&**store, request);
            let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
            let mut context = Context::from_waker(&waker);
            loop {
                if cancelled.try_recv().is_ok() {
                    break;
                }
                assert!(
                    matches!(Future::poll(future.as_mut(), &mut context), Poll::Pending),
                    "the held replacement cannot complete before cancellation"
                );
                std::thread::park_timeout(CANCEL_POLL);
            }
            drop(future);
        });
        let waiting = super::conditional_records::waiting_connection(&db, holder, "usage_windows");
        cancel.send(()).unwrap();
        (waiting, worker.join())
    });
    stopped.unwrap();
    assert!(
        waiting.unwrap().is_some(),
        "actual loaded call must be Pending in the replacement transaction"
    );

    assert_eq!(read(&store, "a"), UsageLedger::default());
    assert_eq!(read(&store, BLOCKED_BUCKET), ledger(1));
    assert_eq!(receipt(&db, &request), None);
    lock.rollback().unwrap();

    db.conn()
        .query_drop("SELECT revision FROM store_sequence WHERE id=1 FOR UPDATE")
        .unwrap();
    let body = busbar_contract::abi::sdk::store::dedupe::Dedupe::usage_correction(&request)
        .body()
        .to_vec();
    assert_eq!(read(&store, "a"), ledger(2));
    assert_eq!(read(&store, BLOCKED_BUCKET), ledger(3));
    assert_eq!(receipt(&db, &request), Some(body.clone()));
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    assert_eq!(read(&store, "a"), ledger(2));
    assert_eq!(read(&store, BLOCKED_BUCKET), ledger(3));
    assert_eq!(receipt(&db, &request), Some(body));
}

#[test]
fn correction_high_unsigned_counters_survive_ordinary_accrual_refund_and_reopen() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_unsigned_accrual") else {
        return;
    };
    let store = prepare(&db);
    let request = candidate(
        12,
        UsageLedger::default(),
        ledger_parts(u64::MAX, i64::MAX as u64),
    );
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    let delta = |count| UsageDelta {
        requests: count,
        billable_requests: count,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: MODEL.into(),
            usage_units: units(&[(UNIT_INPUT, count), (OPEN_UNIT, count)]),
        }],
    };
    assert!(store.add_usage("a", DAY, &delta(1)).is_err());
    assert_eq!(read(&store, "a"), ledger_parts(u64::MAX, i64::MAX as u64));
    store
        .add_usage_op(OpId::from_parts(NODE, 13), "a", DAY, &delta(-1))
        .unwrap();
    assert_eq!(
        read(&store, "a"),
        ledger_parts(u64::MAX - 1, i64::MAX as u64 - 1)
    );
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(
        read(&reopened, "a"),
        ledger_parts(u64::MAX - 1, i64::MAX as u64 - 1)
    );
    assert_eq!(apply(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(
        read(&reopened, "a"),
        ledger_parts(u64::MAX - 1, i64::MAX as u64 - 1)
    );
}

#[test]
fn empty_model_identity_shares_sentinel_without_losing_requests_tokens_or_open_units() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("correction_empty_model") else {
        return;
    };
    let store = prepare(&db);
    let with_empty = |requests, quantity| {
        let mut row = ledger_parts(requests, quantity);
        row.models.insert(
            0,
            ModelTokens {
                scale: 6,
                model: String::new(),
                usage_units: units(&[
                    (UNIT_INPUT, quantity),
                    (UNIT_CACHE_WRITE, quantity),
                    (OPEN_UNIT, quantity),
                ]),
            },
        );
        row
    };
    let delta = |count| UsageDelta {
        requests: count,
        billable_requests: count,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: String::new(),
            usage_units: units(&[
                (UNIT_INPUT, count),
                (UNIT_CACHE_WRITE, count),
                (OPEN_UNIT, count),
            ]),
        }],
    };

    store.put_usage("a", DAY, &with_empty(10, 10)).unwrap();
    assert_eq!(read(&store, "a"), with_empty(10, 10));
    store.add_usage("a", DAY, &delta(1)).unwrap();
    let mut accrued = with_empty(10, 10);
    accrued.requests += 1;
    accrued.billable_requests += 1;
    for count in accrued.models[0].usage_units.values_mut() {
        *count += 1;
    }
    assert_eq!(read(&store, "a"), accrued);
    let request = candidate(14, accrued, with_empty(u64::MAX, i64::MAX as u64));
    assert_eq!(apply(&store, &request), Ok(Decision::Applied));
    assert_eq!(read(&store, "a"), with_empty(u64::MAX, i64::MAX as u64));
    store
        .add_usage_op(OpId::from_parts(NODE, 15), "a", DAY, &delta(-1))
        .unwrap();
    let mut refunded = with_empty(u64::MAX, i64::MAX as u64);
    refunded.requests -= 1;
    refunded.billable_requests -= 1;
    for count in refunded.models[0].usage_units.values_mut() {
        *count -= 1;
    }
    assert_eq!(read(&store, "a"), refunded);
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(read(&reopened, "a"), refunded);
    assert_eq!(apply(&reopened, &request), Ok(Decision::Applied));
    assert_eq!(read(&reopened, "a"), refunded);
    let clear = candidate(
        16,
        refunded,
        UsageLedger {
            requests: 9,
            billable_requests: 8,
            models: Vec::new(),
        },
    );
    assert_eq!(apply(&reopened, &clear), Ok(Decision::Applied));
    assert_eq!(read(&reopened, "a"), clear.usage[0].replacement);
    assert!(
        reopened.get_usage("a", DAY).unwrap().models.is_empty(),
        "a zero token sentinel is not an empty model fact"
    );

    let open_only = UsageLedger {
        requests: 7,
        billable_requests: 6,
        models: vec![ModelTokens {
            scale: 6,
            model: String::new(),
            usage_units: units(&[(OPEN_UNIT, 5)]),
        }],
    };
    reopened.put_usage("a", DAY, &open_only).unwrap();
    assert_eq!(read(&reopened, "a"), open_only);
}
