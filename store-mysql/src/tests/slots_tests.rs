// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live MySQL: the durable `op_id` dedupe (S1-S4) and the kernel's records.

use super::{fresh_store, lock_fresh_database_ddl, sample_key, test_url, MysqlStore, ScratchDb};
use busbar_contract::abi::sdk::store::fork::chain_fork;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{RecordStore, UsageDelta};
use mysql::prelude::Queryable;

/// A name no other test (or earlier run) uses.
fn fresh(tag: &str) -> String {
    format!("{tag}-{}", ulid::Ulid::new())
}

/// A fresh op id: a random node, then `counter` (never a multiple of the sweep cadence, so no test op triggers a sweep).
fn op(counter: u64) -> OpId {
    OpId::from_parts(ulid::Ulid::new().random() as u64 | 1, counter * 2 + 1)
}

#[test]
fn the_statement_tail_is_a_durable_store_that_refuses_forks() {
    const {
        assert!(!MysqlStore::TAIL.ephemeral);
        assert!(MysqlStore::TAIL.durable_plane);
        assert!(MysqlStore::TAIL.fork_refusal);
    }
}

#[test]
fn open_refuses_settings_it_cannot_run_in_its_own_words() {
    let e = MysqlStore::open(b"").err().expect("no url");
    assert!(e.contains("requires a \"url\""), "{e}");
    let e = MysqlStore::open(b"{ not json").err().expect("bad json");
    assert!(e.contains("invalid mysql plugin config"), "{e}");
    let e = MysqlStore::open(br#"{"url": "  "}"#)
        .err()
        .expect("blank url");
    assert!(e.contains("requires a \"url\""), "{e}");
}

/// S1/S2/S3/S4: a replay applies nothing and answers the original, a different body is a conflict and applies nothing, and the record survives a reconnect (it is in the database, not the process).
#[test]
fn an_op_id_write_applies_once_durably_and_a_different_body_conflicts() {
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("dedupe");
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 2,
        models: Vec::new(),
    };
    let id = op(1);
    s.add_usage_op(id, &bucket, 60, &delta).expect("applies");
    s.add_usage_op(id, &bucket, 60, &delta)
        .expect("a replay answers Ok");
    let again = MysqlStore::connect(&test_url().unwrap()).expect("reconnect");
    again
        .add_usage_op(id, &bucket, 60, &delta)
        .expect("a replay after a reconnect answers Ok");
    let other = UsageDelta {
        requests: 4,
        ..delta.clone()
    };
    assert_eq!(
        again.add_usage_op(id, &bucket, 60, &other),
        Err(OpRefused::Conflict)
    );
    let ledger = s.get_usage(&bucket, 60).expect("get_usage");
    assert_eq!(ledger.requests, 3, "applied exactly once: {ledger:?}");
    assert_eq!(ledger.billable_requests, 2, "{ledger:?}");
}

/// S3: a refused op records nothing, so a retry under the same `op_id` is judged afresh, not as a conflict with the op that failed.
#[test]
fn a_refused_op_applies_nothing_and_records_nothing() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};
    let Some(s) = fresh_store() else { return };
    let parent = fresh("refused");
    let rec = |seq: u64, body: &[u8]| PlaneRecord {
        kind: "slots_test".into(),
        id: format!("{parent}-{seq}"),
        parent: Some(parent.clone()),
        seq,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    s.append_plane_record_op(op(2), rec(1, b"first").view())
        .expect("seed");

    let id = op(3);
    let got = s.append_plane_record_op(id, rec(1, b"forked-content").view());
    let Err(OpRefused::Failed(text)) = got else {
        panic!("a fork is Failed: {got:?}")
    };
    assert_eq!(text, chain_fork("slots_test", &parent, 1).0);
    for echoed in ["first", "forked-content"] {
        assert!(
            !text.contains(echoed),
            "the refusal echoed {echoed}: {text}"
        );
    }

    s.append_plane_record_op(id, rec(2, b"second").view())
        .expect("a retry after a failure is new");
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"first".to_vec(), b"second".to_vec()]);
}

/// Empty model identity shares the physical sentinel row without mixing token and request
/// counters; the actual ABI write and its exact retry apply once under the same op_id.
#[test]
fn an_empty_model_identity_keeps_independent_counters_and_replays_once() {
    use busbar_contract::records::{ModelTokens, ModelTokensDelta, UsageLedger};
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("emptymodel");
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: String::new(),
            usage_units: [("tokens_input".to_owned(), 5)].into_iter().collect(),
        }],
    };
    let expected = UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            scale: 6,
            model: String::new(),
            usage_units: [("tokens_input".to_owned(), 5)].into_iter().collect(),
        }],
    };
    let id = op(7);
    s.add_usage_op(id, &bucket, 60, &delta)
        .expect("the actual store ABI accepts the opaque empty model identity");
    assert_eq!(s.get_usage(&bucket, 60).unwrap(), expected);
    let mut raw = s.pool.get_conn().unwrap();
    let row: Option<(u64, u64, u64)> = raw
        .exec_first(
            "SELECT requests,billable_requests,tokens_input FROM usage_windows \
         WHERE window_start=60 AND bucket_scope='key' AND bucket_id=? AND model=''",
            (&bucket,),
        )
        .unwrap();
    assert_eq!(
        row,
        Some((1, 1, 0)),
        "the sentinel keeps window counters; this open unit is not the reserved input unit"
    );
    let unit_count: Option<u64> = raw
        .exec_first(
            "SELECT count FROM usage_window_units WHERE window_start=60 \
             AND bucket_scope='key' AND bucket_id=? AND model='' AND unit='tokens_input'",
            (&bucket,),
        )
        .unwrap();
    assert_eq!(
        unit_count,
        Some(5),
        "the exact input unit is stored independently"
    );
    let receipts: Option<u64> = raw
        .exec_first("SELECT COUNT(*) FROM store_ops WHERE op_id=?", (&id.0[..],))
        .unwrap();
    assert_eq!(
        receipts,
        Some(1),
        "the successful ABI write has one durable receipt"
    );
    s.add_usage_op(id, &bucket, 60, &delta)
        .expect("exact receipt replay succeeds");
    assert_eq!(
        s.get_usage(&bucket, 60).unwrap(),
        expected,
        "replay doubles neither window counters nor empty-model tokens"
    );
    let replayed_unit: Option<u64> = raw
        .exec_first(
            "SELECT count FROM usage_window_units WHERE window_start=60 \
             AND bucket_scope='key' AND bucket_id=? AND model='' AND unit='tokens_input'",
            (&bucket,),
        )
        .unwrap();
    assert_eq!(
        replayed_unit,
        Some(5),
        "exact replay preserves the physical unit value"
    );
}

/// M1 (S5): a value the columns cannot hold is REFUSED (provably nothing applied), not FAILED (which makes the host replay it forever); nothing is recorded, so the same `op_id` applies afterwards.
#[test]
fn a_value_the_columns_cannot_hold_is_refused_and_records_nothing() {
    use busbar_contract::records::ModelTokensDelta;
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("toolong");
    let delta = |model: String| UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            scale: 6,
            model,
            usage_units: [("tokens_input".to_owned(), 5)].into_iter().collect(),
        }],
    };
    let id = op(5);
    let got = s.add_usage_op(id, &bucket, 60, &delta("m".repeat(2000)));
    assert!(matches!(got, Err(OpRefused::Refused(_))), "{got:?}");
    let mut c = s.pool.get_conn().expect("conn");
    let rows: Option<u64> = c
        .exec_first(
            "SELECT COUNT(*) FROM store_ops WHERE op_id = ?",
            (&id.0[..],),
        )
        .expect("count");
    assert_eq!(rows, Some(0), "a refused op records nothing");
    s.add_usage_op(id, &bucket, 60, &delta("ok".into()))
        .expect("the same op_id with a valid body applies");
}

/// Request counters retain u64 width while quantity overflow refuses the complete write.
#[test]
fn usage_request_width_and_checked_quantity_refunds() {
    use busbar_contract::records::{ModelTokens, ModelTokensDelta, UsageLedger};
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("ceiling");
    let top = i64::MAX as u64;
    let seed = |requests, quantity| UsageLedger {
        requests,
        billable_requests: requests,
        models: vec![ModelTokens {
            scale: 6,
            model: "m".into(),
            usage_units: [
                ("tokens_input".into(), quantity),
                ("images".into(), quantity),
            ]
            .into(),
        }],
    };
    let delta = |amount| UsageDelta {
        requests: amount,
        billable_requests: amount,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: "m".into(),
            usage_units: [("tokens_input".into(), amount), ("images".into(), amount)].into(),
        }],
    };
    let read = || s.get_usage(&bucket, 60).unwrap();
    s.put_usage(&bucket, 60, &seed(u64::MAX - 2, top - 2))
        .unwrap();
    assert!(s.add_usage_op(op(6), &bucket, 60, &delta(5)).is_err());
    assert_eq!(read(), seed(u64::MAX - 2, top - 2));
    s.add_usage_op(op(6), &bucket, 60, &delta(2)).unwrap();
    assert_eq!(read(), seed(u64::MAX, top));
    s.add_usage_op(op(7), &bucket, 60, &delta(-3)).unwrap();
    assert_eq!(read(), seed(u64::MAX - 3, top - 3));
    s.put_usage(&bucket, 60, &seed(u64::MAX, top - 3)).unwrap();
    s.add_usage_op(op(13), &bucket, 60, &delta(1)).unwrap();
    assert_eq!(read(), seed(u64::MAX, top - 2));
    s.put_usage(&bucket, 60, &seed(4, 4)).unwrap();
    s.add_usage_op(op(10), &bucket, 60, &delta(i64::MIN))
        .unwrap();
    let cleared = read();
    assert_eq!((cleared.requests, cleared.billable_requests), (0, 0));
    assert!(cleared
        .models
        .iter()
        .all(|row| row.usage_units.values().all(|n| *n == 0)));
}

/// A quantity at the signed ceiling refuses increments and never clamps a first write.
#[test]
fn metering_quantity_overflow_refuses_at_i64_max() {
    use busbar_contract::records::MeteringDelta;
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_ceiling");
    s.put_key(&sample_key(&key, "g")).expect("put_key");
    let cell = |n: u64| MeteringDelta {
        scale: 6,
        key_id: key.clone(),
        bucket: 20_261_031,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: n,
        tokens_output: n,
        tokens_cache_read: n,
        tokens_cache_write: n,
        requests: n,
        billable_requests: n,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: [("images".to_owned(), n)].into_iter().collect(),
    };
    assert!(s.add_metering_op(op(11), &[cell(u64::MAX - 2)]).is_err());
    s.add_metering_op(op(11), &[cell(i64::MAX as u64)])
        .expect("exact ceiling");
    assert!(s.add_metering_op(op(12), &[cell(10)]).is_err());
    let rows: Vec<_> = s
        .list_metering(20_261_031)
        .expect("list_metering")
        .into_iter()
        .filter(|r| r.key_id == key)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let r = &rows[0];
    for v in [
        r.tokens_input,
        r.tokens_output,
        r.tokens_cache_read,
        r.tokens_cache_write,
        r.requests,
        r.billable_requests,
        r.usage_units["images"],
    ] {
        assert_eq!(v, i64::MAX as u64, "{r:?}");
    }

    // Crossing the ceiling from below also refuses without changing any counter.
    let near = fresh("vk_ceiling_near");
    s.put_key(&sample_key(&near, "g")).expect("put_key");
    let near_cell = |n: u64| MeteringDelta {
        scale: 6,
        key_id: near.clone(),
        ..cell(n)
    };
    s.add_metering_op(op(14), &[near_cell((i64::MAX - 2) as u64)])
        .expect("seed just below the ceiling");
    assert!(s.add_metering_op(op(15), &[near_cell(10)]).is_err());
    let rows: Vec<_> = s
        .list_metering(20_261_031)
        .expect("list_metering")
        .into_iter()
        .filter(|r| r.key_id == near)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    let r = &rows[0];
    for v in [
        r.tokens_input,
        r.tokens_output,
        r.tokens_cache_read,
        r.tokens_cache_write,
        r.requests,
        r.billable_requests,
        r.usage_units["images"],
    ] {
        assert_eq!(v, i64::MAX as u64 - 2, "{r:?}");
    }
}

/// M8: a batch is applied in one global order (the primary key's, `(key_id, bucket, model, provider, priced_from_ms)`) whatever order the caller sent it in (a unit-level check of the order handed to the apply loop; the deadlock itself needs two nodes).
#[test]
fn a_batch_applies_in_one_global_order() {
    use crate::slots::Write;
    use busbar_contract::records::MeteringDelta;
    let cell = |b: &str, w: u64| (b.to_owned(), w, UsageDelta::default());
    let Write::Usage(cells) =
        Write::Usage(vec![cell("b", 2), cell("a", 9), cell("b", 1), cell("a", 3)]).ordered()
    else {
        unreachable!()
    };
    let got: Vec<_> = cells.iter().map(|(b, w, _)| (b.as_str(), *w)).collect();
    assert_eq!(got, [("a", 3), ("a", 9), ("b", 1), ("b", 2)]);

    let m = |bucket: u64, key: &str, model: &str, pfm: u64| MeteringDelta {
        scale: 6,
        key_id: key.into(),
        bucket,
        model: model.into(),
        provider: "p".into(),
        priced_from_ms: pfm,
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 0,
        billable_requests: 0,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        usage_units: Default::default(),
    };
    let Write::Metering(ds) = Write::Metering(vec![
        m(2, "k", "m", 0),
        m(1, "z", "m", 0),
        m(1, "k", "n", 0),
        m(1, "k", "m", 5),
        m(1, "k", "m", 0),
    ])
    .ordered() else {
        unreachable!()
    };
    let got: Vec<_> = ds
        .iter()
        .map(|d| {
            (
                d.bucket,
                d.key_id.as_str(),
                d.model.as_str(),
                d.priced_from_ms,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (1, "k", "m", 0),
            (1, "k", "m", 5),
            (1, "k", "n", 0),
            (2, "k", "m", 0),
            (1, "z", "m", 0)
        ]
    );
}

/// Run `write` on a raw connection in a loop while `read` runs on this thread up to `rounds` times; the first `Err` from `read` fails the test.
fn race(
    s: &MysqlStore,
    rounds: usize,
    write: impl Fn(&mut mysql::PooledConn) + Sync,
    read: impl Fn() -> Result<(), String>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct StopOnDrop<'a>(&'a AtomicBool);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let stop = AtomicBool::new(false);
    let (started, ready) = std::sync::mpsc::sync_channel(1);
    let mut c = s.conn().expect("conn");
    let outcome = std::thread::scope(|sc| {
        sc.spawn(|| {
            write(&mut c);
            started.send(()).unwrap();
            while !stop.load(Ordering::Relaxed) {
                write(&mut c);
            }
        });
        let _completion = StopOnDrop(&stop);
        ready
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("writer must commit before reads begin");
        (0..rounds).try_for_each(|_| read())
    });
    outcome.expect("a torn read");
}

/// M9: `get_usage` reads the window's three tables in one snapshot, so a writer that moves the request counter and a token counter together is never seen half-applied.
#[test]
fn get_usage_reads_one_snapshot() {
    use busbar_contract::records::{ModelTokens, UsageLedger};
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("snap");
    let seed = UsageLedger {
        requests: 0,
        billable_requests: 0,
        models: vec![ModelTokens {
            scale: 6,
            model: "m".into(),
            usage_units: [("tokens_input".to_owned(), 0), ("images".to_owned(), 0)]
                .into_iter()
                .collect(),
        }],
    };
    s.put_usage(&bucket, 60, &seed).expect("seed");
    race(
        &s,
        400,
        |c| {
            let mut tx = c.start_transaction(mysql::TxOpts::default()).expect("tx");
            for sql in [
                "UPDATE usage_windows SET requests = requests + 1 \
                 WHERE window_start = 60 AND bucket_scope = 'key' AND bucket_id = ? AND model = ''",
                "UPDATE usage_windows SET tokens_input = tokens_input + 1 \
                 WHERE window_start = 60 AND bucket_scope = 'key' AND bucket_id = ? AND model = 'm'",
                "UPDATE usage_window_units SET count = count + 1 \
                 WHERE window_start = 60 AND bucket_scope = 'key' AND bucket_id = ?",
            ] {
                tx.exec_drop(sql, (&bucket,)).expect("update");
            }
            tx.commit().expect("commit");
        },
        || {
            let l = s.get_usage(&bucket, 60).map_err(|e| e.to_string())?;
            let m = &l.models[0].usage_units;
            let (t, i) = (
                m.get("tokens_input").copied().unwrap_or(0),
                m.get("images").copied().unwrap_or(0),
            );
            if l.requests == t && t == i {
                Ok(())
            } else {
                Err(format!("{l:?}"))
            }
        },
    );
}

/// M9: `list_metering` reads a cell and its open units in one snapshot.
#[test]
fn list_metering_reads_one_snapshot() {
    use busbar_contract::records::MeteringDelta;
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_snap");
    s.put_key(&sample_key(&key, "g")).expect("put_key");
    let delta = MeteringDelta {
        scale: 6,
        key_id: key.clone(),
        bucket: 20_261_032,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 0,
        billable_requests: 0,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: [("images".to_owned(), 1)].into_iter().collect(),
    };
    s.add_metering_op(op(13), &[delta]).expect("seed");
    race(
        &s,
        400,
        |c| {
            let mut tx = c.start_transaction(mysql::TxOpts::default()).expect("tx");
            tx.exec_drop(
                "UPDATE usage_metering SET requests = requests + 1 \
                 WHERE bucket = '0020261032' AND key_id = ?",
                (&key,),
            )
            .expect("update");
            tx.exec_drop(
                "UPDATE usage_metering_units SET count = count + 1 \
                 WHERE bucket = '0020261032' AND key_id = ?",
                (&key,),
            )
            .expect("update");
            tx.commit().expect("commit");
        },
        || {
            let rows = s.list_metering(20_261_032).map_err(|e| e.to_string())?;
            let r = rows.iter().find(|r| r.key_id == key).expect("the cell");
            if r.requests + 1 == r.usage_units.get("images").copied().unwrap_or(0) {
                Ok(())
            } else {
                Err(format!("{r:?}"))
            }
        },
    );
}

#[test]
fn records_upsert_read_back_and_scan_a_prefix_in_key_order() {
    let Some(s) = fresh_store() else { return };
    let schema = fresh("schema");
    s.record_put(&schema, b"b\xff", b"2").expect("put");
    s.record_put(&schema, b"a", b"0").expect("put");
    s.record_put(&schema, b"b\x00", b"1").expect("put");
    s.record_put(&schema, b"c", b"3").expect("put");
    s.record_put(&schema, b"a", b"0'").expect("upsert");
    let got = s.record_get(&schema, b"a").expect("get").expect("present");
    assert_eq!(got.as_slice(), b"0'");
    assert_eq!(s.record_get(&schema, b"z").expect("get"), None);
    let keys = |prefix: &[u8], limit| -> Vec<Vec<u8>> {
        s.record_scan(&schema, prefix, limit)
            .expect("scan")
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert_eq!(keys(b"b", 10), vec![b"b\x00".to_vec(), b"b\xff".to_vec()]);
    assert_eq!(keys(b"", 2), vec![b"a".to_vec(), b"b\x00".to_vec()]);
    assert!(keys(b"", 0).is_empty());
}

/// The `schema_id` predicate isolates host record schemas: the same key under two schemas holds
/// two values, and get/scan of one never sees the other's rows.
#[test]
fn the_same_record_key_in_two_schemas_stays_apart() {
    let Some(s) = fresh_store() else { return };
    let (a, b) = (fresh("schema_a"), fresh("schema_b"));
    s.record_put(&a, b"k", b"from-a").expect("put");
    s.record_put(&b, b"k", b"from-b").expect("put");
    s.record_put(&b, b"k2", b"b-only").expect("put");
    s.record_put(&a, b"\xfe", b"a-fe").expect("put");
    s.record_put(&b, b"\xff", b"b-ff").expect("put");
    let got = |sc: &str, k: &[u8]| {
        s.record_get(sc, k)
            .expect("get")
            .map(|v| v.as_slice().to_vec())
    };
    assert_eq!(got(&a, b"k"), Some(b"from-a".to_vec()));
    assert_eq!(got(&b, b"k"), Some(b"from-b".to_vec()));
    assert_eq!(got(&a, b"k2"), None);
    let scan = |sc: &str, p: &[u8]| -> Vec<(Vec<u8>, Vec<u8>)> {
        s.record_scan(sc, p, 10)
            .expect("scan")
            .into_iter()
            .map(|(k, v)| (k, v.as_slice().to_vec()))
            .collect()
    };
    assert_eq!(
        scan(&a, b""),
        vec![
            (b"k".to_vec(), b"from-a".to_vec()),
            (b"\xfe".to_vec(), b"a-fe".to_vec())
        ]
    );
    assert_eq!(
        scan(&b, b""),
        vec![
            (b"k".to_vec(), b"from-b".to_vec()),
            (b"k2".to_vec(), b"b-only".to_vec()),
            (b"\xff".to_vec(), b"b-ff".to_vec())
        ]
    );
    // An all-0xFF prefix has no upper bound; it still stays inside its schema.
    assert_eq!(scan(&a, b"\xff"), Vec::new());
    assert_eq!(
        scan(&b, b"\xff"),
        vec![(b"\xff".to_vec(), b"b-ff".to_vec())]
    );
}

/// AN EMPTY PUT REMOVES THE ROW (slot 40's rule, ARCHITECT 2026-10-21): the host writes every
/// strike as an empty `record_put` and reads empty as absent, so the row LEAVES the table:
/// `record_get` answers `None`, `record_scan` never returns it, and the table shrinks. Removing a
/// row that is not there is `Ok`.
#[test]
fn an_empty_put_removes_the_row() {
    let Some(s) = fresh_store() else { return };
    let schema = fresh("schema");
    let held = || -> i64 {
        s.conn()
            .expect("a raw connection")
            .exec_first(
                "SELECT COUNT(*) FROM store_records WHERE schema_id = ?",
                (schema.as_str(),),
            )
            .expect("count")
            .unwrap_or_default()
    };
    s.record_put(&schema, b"a/1", b"one").expect("put");
    s.record_put(&schema, b"a/2", b"two").expect("put");
    assert_eq!(held(), 2);

    s.record_put(&schema, b"a/1", b"").expect("strike");
    assert_eq!(held(), 1, "the struck row left the table");
    assert_eq!(s.record_get(&schema, b"a/1").expect("get"), None);
    let scan: Vec<(Vec<u8>, Vec<u8>)> = s
        .record_scan(&schema, b"a/", 10)
        .expect("scan")
        .into_iter()
        .map(|(k, v)| (k, v.as_slice().to_vec()))
        .collect();
    assert_eq!(
        scan,
        vec![(b"a/2".to_vec(), b"two".to_vec())],
        "a scan never returns a struck row"
    );

    s.record_put(&schema, b"a/9", b"")
        .expect("a strike of nothing is Ok");
    assert_eq!(held(), 1);
    s.record_put(&schema, b"a/1", b"again").expect("put again");
    assert_eq!(
        s.record_get(&schema, b"a/1")
            .expect("get")
            .map(|r| r.as_slice().to_vec()),
        Some(b"again".to_vec())
    );
}

/// The plane-record `op_id` write and the key path still share the store's one schema.
#[test]
fn an_op_id_plane_append_dedupes_and_still_refuses_a_fork() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};
    let Some(s) = fresh_store() else { return };
    s.put_key(&sample_key(&fresh("vk"), "g1"))
        .expect("the key path is untouched");
    let parent = fresh("chain");
    let rec = |body: &[u8]| PlaneRecord {
        kind: "slots_test".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq: 1,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    let id = op(22);
    s.append_plane_record_op(id, rec(b"one").view())
        .expect("append");
    s.append_plane_record_op(id, rec(b"one").view())
        .expect("replay");
    let got = s.append_plane_record_op(op(23), rec(b"two-content").view());
    let Err(OpRefused::Failed(text)) = got else {
        panic!("a fork is Failed: {got:?}")
    };
    assert_eq!(text, chain_fork("slots_test", &parent, 1).0);
    for echoed in ["one", "two-content"] {
        assert!(
            !text.contains(echoed),
            "the refusal echoed {echoed}: {text}"
        );
    }
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"one".to_vec()]);
}

/// Put `body` under `op` in `store_ops`, as a build before the SDK body recorded it (the slot's name, `:`, its values' `{:?}`).
fn record_older_body(conn: &mut mysql::PooledConn, op: OpId, body: &str) {
    conn.exec_drop(
        "UPDATE store_ops SET body = ? WHERE op_id = ?",
        (body.as_bytes(), &op.0[..]),
    )
    .expect("rewrite the body");
    let stored: Vec<u8> = conn
        .exec_first("SELECT body FROM store_ops WHERE op_id = ?", (&op.0[..],))
        .expect("read the body")
        .expect("the op is recorded");
    assert_eq!(stored, body.as_bytes());
}

/// FROZEN: the exact text a v9 build recorded as the body of its three deduped ops, for the fixed
/// fixture values of the tests below (`<ID>` is the one random part, the fixture's id). These are
/// byte literals, NOT built from the contract types' current `{:?}`: the contract's older-form check
/// compares against that very output, so a live-built "older" body could never show rows a real v9
/// build wrote ceasing to match. If one of these goes red after a `busbar-contract` bump, the
/// contract's `Debug` for that type changed and a v9 op's retry would be judged a Conflict: report
/// it to core; never edit the literal to match.
const V9_USAGE_BODY: &str = r#"add_usage_batch:[("<ID>", 60, UsageDelta { requests: 3, billable_requests: 2, models: [] })]"#;
const V9_METERING_BODY: &str = r#"add_metering_batch:[MeteringDelta { key_id: "<ID>", bucket: 20261030, model: "m", provider: "p", tokens_input: 10, tokens_output: 5, tokens_cache_read: 0, tokens_cache_write: 0, requests: 1, billable_requests: 1, key_group_at_use: "g", pricing_version: "v1", priced_from_ms: 0, usage_units: {} }]"#;
const V9_APPEND_BODY: &str = r#"append_plane_record:PlaneRecordRef { kind: "slots_test", id: "<ID>", parent: Some("<ID>"), seq: 1, ts: 1, disposition: Active, body: [111, 110, 101] }"#;

/// ACROSS AN UPGRADE: an op an older build recorded in its `{:?}` body form replays (nothing applied) and a different op under its id is a conflict, for each of the three slots.
#[test]
fn an_op_recorded_in_the_older_body_form_replays_and_a_different_op_conflicts() {
    use busbar_contract::records::{MeteringDelta, PlaneDisposition, PlaneRecord, PlaneSelector};
    let Some(s) = fresh_store() else { return };
    let mut c = s.conn().expect("a raw connection");

    let bucket = fresh("older");
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 2,
        models: Vec::new(),
    };
    let usage = op(31);
    s.add_usage_op(usage, &bucket, 60, &delta).expect("applies");
    record_older_body(&mut c, usage, &V9_USAGE_BODY.replace("<ID>", &bucket));
    s.add_usage_op(usage, &bucket, 60, &delta)
        .expect("the older body replays");
    let other = UsageDelta {
        requests: 4,
        ..delta.clone()
    };
    assert_eq!(
        s.add_usage_op(usage, &bucket, 60, &other),
        Err(OpRefused::Conflict)
    );
    let ledger = s.get_usage(&bucket, 60).expect("get_usage");
    assert_eq!(ledger.requests, 3, "applied exactly once: {ledger:?}");

    let key = fresh("vk_older");
    s.put_key(&sample_key(&key, "g")).expect("put_key");
    let meter = MeteringDelta {
        scale: 0,
        key_id: key.clone(),
        bucket: 20_261_030,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let metering = op(32);
    let deltas = [meter.clone()];
    s.add_metering_op(metering, &deltas).expect("applies");
    record_older_body(&mut c, metering, &V9_METERING_BODY.replace("<ID>", &key));
    s.add_metering_op(metering, &deltas)
        .expect("the older body replays");
    let more = [MeteringDelta {
        scale: 0,
        tokens_input: 11,
        ..meter.clone()
    }];
    assert_eq!(s.add_metering_op(metering, &more), Err(OpRefused::Conflict));
    let rows: Vec<_> = s
        .list_metering(meter.bucket)
        .expect("list_metering")
        .into_iter()
        .filter(|r| r.key_id == key)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].scale, 6);
    assert_eq!(
        rows[0].tokens_input, 10_000_000,
        "applied exactly once: {rows:?}"
    );

    let parent = fresh("older-chain");
    let rec = |body: &[u8]| PlaneRecord {
        kind: "slots_test".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq: 1,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    let append = op(33);
    s.append_plane_record_op(append, rec(b"one").view())
        .expect("applies");
    record_older_body(&mut c, append, &V9_APPEND_BODY.replace("<ID>", &parent));
    s.append_plane_record_op(append, rec(b"one").view())
        .expect("the older body replays");
    assert_eq!(
        s.append_plane_record_op(append, rec(b"two").view()),
        Err(OpRefused::Conflict)
    );
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"one".to_vec()], "appended exactly once");
}

/// A store in a DATABASE of its own, for a test that rewrites the schema.
struct Iso {
    db: super::ScratchDb,
    store: Option<MysqlStore>,
}

impl Iso {
    fn new(tag: &str) -> Option<Self> {
        let db = super::ScratchDb::new(&format!("iso_{tag}"))?;

        let store = {
            let _ddl = super::lock_fresh_database_ddl();
            MysqlStore::connect(&db.url).expect("connect the isolated store")
        };
        Some(Iso {
            db,
            store: Some(store),
        })
    }

    fn s(&self) -> &MysqlStore {
        self.store.as_ref().expect("open")
    }
}

/// A retired development schema cannot be upgraded or have its tables and receipts removed.
#[test]
fn unsupported_prerelease_schema_refusal_preserves_money_dead_slot_tables_and_ops() {
    use busbar_contract::records::{MeteringDelta, PlaneDisposition, PlaneRecord};
    let Some(iso) = Iso::new("v10") else {
        return;
    };
    let bucket = fresh("v10");
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 2,
        models: Vec::new(),
    };
    let usage_op = op(1);
    iso.s()
        .add_usage_op(usage_op, &bucket, 60, &delta)
        .expect("applies");
    let parent = fresh("v10-chain");
    let rec = PlaneRecord {
        kind: "slots_test".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq: 1,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: b"one".to_vec(),
    };
    let plane_op = op(2);
    iso.s()
        .append_plane_record_op(plane_op, rec.view())
        .expect("applies");
    let key = fresh("vk_v10");
    iso.s().put_key(&sample_key(&key, "g")).expect("put_key");
    let meter = MeteringDelta {
        scale: 6,
        key_id: key.clone(),
        bucket: 20_261_030,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 10,
        tokens_output: 5,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let metering_op = op(4);
    let deltas = [meter.clone()];
    iso.s()
        .add_metering_op(metering_op, &deltas)
        .expect("applies");
    let dead_op = op(3);
    let mut c = iso.db.conn();
    // Put the database back to what a v9 build left: the kept ops' bodies in its `{:?}` form, the
    // dead slots' tables with rows in them, and their dedupe rows next to the kept ones.
    record_older_body(&mut c, usage_op, &V9_USAGE_BODY.replace("<ID>", &bucket));
    record_older_body(&mut c, plane_op, &V9_APPEND_BODY.replace("<ID>", &parent));
    record_older_body(&mut c, metering_op, &V9_METERING_BODY.replace("<ID>", &key));
    for stmt in [
        "CREATE TABLE store_caps (bucket VARCHAR(191) NOT NULL PRIMARY KEY, cap BIGINT UNSIGNED NOT NULL)",
        "CREATE TABLE store_slices (slice_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, \
         remaining BIGINT UNSIGNED NOT NULL, valid_until_ms BIGINT UNSIGNED NOT NULL DEFAULT 0)",
        "CREATE TABLE store_epoch (one TINYINT UNSIGNED PRIMARY KEY, epoch BIGINT UNSIGNED NOT NULL)",
        "CREATE TABLE store_journal (stream VARCHAR(191) NOT NULL, seq BIGINT UNSIGNED NOT NULL, \
         record VARBINARY(512) NOT NULL, PRIMARY KEY (stream, seq))",
        "CREATE TABLE store_sessions (session BIGINT UNSIGNED PRIMARY KEY, node TEXT NOT NULL, \
         principal VARCHAR(191) NOT NULL)",
        "INSERT INTO store_caps VALUES ('b', 5)",
        "INSERT INTO store_slices (remaining) VALUES (5)",
        "INSERT INTO store_epoch VALUES (1, 7)",
        "INSERT INTO store_journal VALUES ('s', 1, 'r')",
        "INSERT INTO store_sessions VALUES (1, 'n', 'p')",
        "UPDATE store_meta SET v = '9' WHERE k = 'schema_version'",
    ] {
        c.query_drop(stmt).unwrap();
    }
    for body in [
        "reserve:1:[]",
        "slice_release:1:[]",
        "window_caps:[]",
        "append_batch:\"s\":[]",
        "append_audit:AuditRecord",
        "session_put:1",
    ] {
        c.exec_drop(
            "INSERT INTO store_ops (op_id, recorded_at, body, answer) VALUES (?, ?, ?, '')",
            (&op(40).0[..], 1u64, body),
        )
        .unwrap();
    }
    c.exec_drop(
        "INSERT INTO store_ops (op_id, recorded_at, body, answer) VALUES (?, ?, 'reserve:1:[]', '')",
        (&dead_op.0[..], 1u64),
    )
    .unwrap();
    let ops_before: u64 = c
        .query_first("SELECT COUNT(*) FROM store_ops")
        .unwrap()
        .unwrap();
    let bodies_before: Vec<String> = c
        .query("SELECT CAST(body AS CHAR) FROM store_ops ORDER BY op_id")
        .unwrap();
    drop(c);
    let before = super::schema_shape(&iso.db);
    let error = MysqlStore::connect(&iso.db.url)
        .err()
        .expect("unsupported pre-release schema is refused");
    assert!(error.contains("newer than this build"), "{error}");
    assert_eq!(
        super::schema_shape(&iso.db),
        before,
        "no DDL before refusal"
    );
    assert_eq!(super::schema_version_of(&iso.db), "9", "not restamped");
    let mut c = iso.db.conn();
    let bodies_after: Vec<String> = c
        .query("SELECT CAST(body AS CHAR) FROM store_ops ORDER BY op_id")
        .unwrap();
    assert_eq!(
        bodies_after, bodies_before,
        "all operation receipts survive"
    );
    assert_eq!(bodies_after.len() as u64, ops_before);
    for table in [
        "store_caps",
        "store_slices",
        "store_epoch",
        "store_journal",
        "store_sessions",
    ] {
        let count: u64 = c
            .query_first(format!("SELECT COUNT(*) FROM {table}"))
            .unwrap()
            .unwrap();
        assert_eq!(count, 1, "{table} retains its data");
    }
}

/// M10: a row stamped `revision = 0` is always "changed" (the contract's own arm), whatever `since` is.
#[test]
fn revision_zero_rows_are_listed_for_any_since() {
    let Some(s) = fresh_store() else { return };
    let (key, public_id) = (fresh("vk_rev0"), fresh("AKIA"));
    let cred = super::sample_credential(&key, &public_id, 0);
    s.put_key_with_credential(&sample_key(&key, "g"), &cred)
        .expect("put");
    let mut c = s.conn().expect("conn");
    c.exec_drop("UPDATE api_keys SET revision = 0 WHERE id = ?", (&key,))
        .expect("zero");
    c.exec_drop(
        "UPDATE credentials SET revision = 0 WHERE key_id = ?",
        (&key,),
    )
    .expect("zero");
    let keys = s.list_keys_since(5).expect("list_keys_since");
    assert!(keys.iter().any(|k| k.id == key), "the revision-0 key");
    let creds = s.list_credentials_since(5).expect("list_credentials_since");
    assert!(
        creds.iter().any(|c| c.meta.key_id == key),
        "the revision-0 credential"
    );
}

/// M11: a revoked slot reclaimed by a new credential carries the NEW credential's `created_at`, not its predecessor's.
#[test]
fn a_reclaimed_slot_takes_the_new_credentials_created_at() {
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_reclaim");
    s.put_key(&sample_key(&key, "g")).expect("put_key");
    let old = super::sample_credential(&key, &fresh("AKIA_OLD"), 0);
    s.put_credential(&old).expect("mint");
    s.revoke_credential(&old.meta.id, "rotated")
        .expect("revoke");
    let mut new = super::sample_credential(&key, &fresh("AKIA_NEW"), 0);
    new.meta.created_at = 5000;
    new.meta.updated_at = 5000;
    s.put_credential(&new).expect("re-mint");
    let got = s.list_credentials(&key).expect("list");
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].created_at, 5000, "{got:?}");
}

/// Repeating a denial refreshes its reason and instant, matching the released store.
#[test]
fn a_repeat_denylist_add_refreshes_reason_and_instant() {
    let Some(s) = fresh_store() else { return };
    let sub = fresh("sub_repeat");
    s.add_denylist(&sub, "a").expect("first");
    let mut c = s.conn().expect("conn");
    let first: (String, u64) = c
        .exec_first(
            "SELECT reason, revoked_at FROM denylist WHERE sub = ?",
            (&sub,),
        )
        .expect("read")
        .expect("row");
    c.exec_drop("UPDATE denylist SET revoked_at = 1 WHERE sub = ?", (&sub,))
        .expect("age the row");
    s.add_denylist(&sub, "b").expect("repeat");
    let after: (String, u64) = c
        .exec_first(
            "SELECT reason, revoked_at FROM denylist WHERE sub = ?",
            (&sub,),
        )
        .expect("read")
        .expect("row");
    assert_eq!(first.0, "a");
    assert_eq!(after.0, "b");
    assert!(
        after.1 >= first.1 && after.1 > 1,
        "the repeat refreshes the denial instant"
    );
}

/// M13: an upsert is keyed by `(kind, id)` whatever `seq` the record carries: a second write for the id replaces the first and `get_plane_record` reads it.
#[test]
fn an_upsert_replaces_by_kind_and_id_whatever_its_seq() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord};
    let Some(s) = fresh_store() else { return };
    let id = fresh("upsert-seq");
    let rec = |seq: u64, body: &[u8]| PlaneRecord {
        kind: "slots_upsert".into(),
        id: id.clone(),
        parent: None,
        seq,
        ts: 10_000_000_000,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    s.upsert_plane_record(rec(3, b"first").view())
        .expect("first");
    s.upsert_plane_record(rec(4, b"second").view())
        .expect("second");
    let mut c = s.conn().expect("conn");
    let rows: Option<u64> = c
        .exec_first(
            "SELECT COUNT(*) FROM plane_records WHERE kind = 'slots_upsert' AND ident = ?",
            (&id,),
        )
        .expect("count");
    assert_eq!(rows, Some(1), "one row per (kind, id)");
    assert_eq!(
        s.get_plane_record("slots_upsert", &id).expect("get"),
        Some(b"second".to_vec())
    );
}

/// M15: `put_usage`'s delete-then-insert deadlocks with a concurrent first write on the same window (both hold the window's gap, each waits to insert into it).
#[test]
fn put_usage_survives_a_gap_lock_deadlock_with_a_first_write() {
    use busbar_contract::records::{ModelTokens, UsageLedger};
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("gap_deadlock") else {
        return;
    };
    let s = MysqlStore::connect(&db.url).unwrap();
    let mut observer = db.root.get_conn().unwrap();
    let before_deadlocks: u64 = observer
        .query_first(
            "SELECT COUNT FROM INFORMATION_SCHEMA.INNODB_METRICS WHERE NAME = 'lock_deadlocks'",
        )
        .unwrap()
        .unwrap();
    let bucket = fresh("gapdl");
    let other = fresh("gapdl-weight");
    let mut b = s.conn().expect("conn");
    let holder_id: u64 = b.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
    b.query_drop("SET SESSION innodb_lock_wait_timeout=3")
        .unwrap();
    b.query_drop("START TRANSACTION").expect("begin");
    for i in 0..40 {
        b.exec_drop(
            "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests) \
             VALUES (?, 'key', ?, '', 1)",
            (1000 + i, &other),
        )
        .expect("weight");
    }
    b.exec_drop(
        "DELETE FROM usage_windows WHERE window_start = 60 AND bucket_scope = 'key' AND bucket_id = ?",
        (&bucket,),
    )
    .expect("hold the window's gap");
    let ledger = UsageLedger {
        requests: 7,
        billable_requests: 7,
        models: vec![ModelTokens {
            scale: 6,
            model: "m".into(),
            usage_units: [("tokens_input".to_owned(), 3)].into_iter().collect(),
        }],
    };
    let result = std::thread::scope(|sc| {
        let a = sc.spawn(|| s.put_usage(&bucket, 60, &ledger));
        let waiting =
            super::conditional_records::waiting_connection(&db, holder_id, "usage_windows")
                .map(|connection| connection.is_some());
        let cycle = if waiting.as_ref().is_ok_and(|waiting| *waiting) {
            Some(b.exec_drop(
                "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests)
                 VALUES (60, 'key', ?, '', 1)",
                (&bucket,),
            ))
        } else {
            None
        };

        let committed = b.query_drop("COMMIT");
        let applied = a.join().expect("put_usage thread");
        committed.unwrap();
        assert!(
            waiting.unwrap(),
            "the actual client must reach an InnoDB lock wait"
        );
        cycle
            .unwrap()
            .expect("the heavier holder survives the actual deadlock");
        let after_deadlocks: u64 = observer
            .query_first(
                "SELECT COUNT FROM INFORMATION_SCHEMA.INNODB_METRICS WHERE NAME = 'lock_deadlocks'",
            )
            .unwrap()
            .unwrap();
        assert!(
            after_deadlocks > before_deadlocks,
            "the schedule must trigger a real deadlock before proving retry"
        );
        applied
    });
    result.expect("put_usage is retried after losing the deadlock");
    assert_eq!(s.get_usage(&bucket, 60).expect("read").requests, 7);
}

/// TB1 (S4): one op in `OPS_SWEEP_EVERY` sweeps dedupe rows older than the retention window; rows inside it survive, and so do the op's own row and an old row's neighbours it is not entitled to.
#[test]
fn the_ops_sweep_drops_aged_dedupe_rows_and_keeps_fresh_ones() {
    use busbar_contract::abi::store::OP_ID_RETENTION_SECS;
    let Some(s) = fresh_store() else { return };
    let mut c = s.conn().expect("conn");
    let now: u64 = c
        .query_first("SELECT UNIX_TIMESTAMP()")
        .expect("now")
        .expect("a row");
    let node = ulid::Ulid::new().random() as u64 | 1;
    let seed = |counter: u64, at: u64, c: &mut mysql::PooledConn| {
        let id = OpId::from_parts(node, counter);
        c.exec_drop(
            "INSERT INTO store_ops (op_id, recorded_at, body, answer) VALUES (?, ?, 'x', 'null')",
            (&id.0[..], at),
        )
        .expect("seed");
        id
    };
    let aged = seed(3, now - OP_ID_RETENTION_SECS - 100, &mut c);
    let ancient = seed(5, 1, &mut c);
    let fresh = seed(7, now, &mut c);
    let near_edge = seed(9, now - OP_ID_RETENTION_SECS + 600, &mut c);
    let present = |id: OpId, c: &mut mysql::PooledConn| -> bool {
        c.exec_first::<u8, _, _>("SELECT 1 FROM store_ops WHERE op_id = ?", (&id.0[..],))
            .expect("read")
            .is_some()
    };

    s.add_usage_op(op(40), &fresh_bucket(), 60, &UsageDelta::default())
        .expect("applies");

    let sweeper = OpId::from_parts(node, 256 * 4);
    s.add_usage_op(sweeper, &fresh_bucket(), 60, &UsageDelta::default())
        .expect("applies");
    assert!(!present(aged, &mut c), "an aged row is swept");
    assert!(!present(ancient, &mut c), "an ancient row is swept");
    assert!(present(fresh, &mut c), "a fresh row survives");
    assert!(
        present(near_edge, &mut c),
        "a row inside the window survives"
    );
    assert!(
        present(sweeper, &mut c),
        "the sweeping op's own row survives"
    );
}

/// S4 is governed by ONE clock, the database's: a row is stamped and swept by the server's time, so
/// a node whose own clock is off cannot age out (or pre-age) rows other nodes wrote. The test and
/// the database share a real clock, so the two are made to differ: a session whose `timestamp` is
/// two days ahead stamps its dedupe row with ITS server time, not the process's `SystemTime`, and
/// a sweep from an ordinary session keeps that row.
#[test]
fn the_dedupe_stamp_and_sweep_follow_the_database_clock_not_the_local_one() {
    use super::harness::{block_on, store_client};
    use crate::slots::{deduped, Write};
    use busbar_contract::abi::sdk::store::dedupe::Dedupe;

    let Some(s) = fresh_store() else { return };
    let mut raw = s.conn().expect("conn");
    let mut skewed = store_client(&mut raw);
    const SKEW: u64 = 2 * 86_400;
    block_on(skewed.exec_drop(
        "SET SESSION timestamp = UNIX_TIMESTAMP() + 172800",
        mysql_common::params::Params::Empty,
    ))
    .expect("skew the session clock");
    let bucket = fresh_bucket();
    let cells = [(bucket.as_str(), 60u64, UsageDelta::default())];
    let other = op(60);
    let body = *Dedupe::usage(&cells).body();
    let write = Write::Usage(vec![(bucket.clone(), 60, UsageDelta::default())]);
    assert!(block_on(deduped(&mut skewed, other, body, write))
        .expect("applies")
        .is_none());
    let mut c = s.conn().expect("conn");
    let server_now: u64 = c
        .query_first("SELECT UNIX_TIMESTAMP()")
        .expect("now")
        .expect("a row");
    let at: u64 = c
        .exec_first(
            "SELECT recorded_at FROM store_ops WHERE op_id = ?",
            (&other.0[..],),
        )
        .expect("read")
        .expect("the op's row");
    assert!(
        at.abs_diff(server_now + SKEW) <= 5,
        "the dedupe stamp is the session's server clock (+2d): {at} vs {}",
        server_now + SKEW
    );
    let sweeper = OpId::from_parts(ulid::Ulid::new().random() as u64 | 1, 256 * 6);
    s.add_usage_op(sweeper, &fresh_bucket(), 60, &UsageDelta::default())
        .expect("applies");
    assert!(
        c.exec_first::<u8, _, _>("SELECT 1 FROM store_ops WHERE op_id = ?", (&other.0[..],))
            .expect("read")
            .is_some(),
        "a sweep must not delete a row another session just wrote"
    );
}

fn fresh_bucket() -> String {
    fresh("sweep")
}

/// TB2: the metering batch in its CURRENT body form (not the older `{:?}` one): a replay applies nothing and answers Ok, a changed body under the same `op_id` is a conflict that applies nothing.
#[test]
fn a_metering_op_id_replays_and_a_changed_body_conflicts() {
    use busbar_contract::records::MeteringDelta;
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_meter_replay");
    s.put_key(&sample_key(&key, "g")).expect("put_key");
    let delta = |tokens: u64| MeteringDelta {
        scale: 6,
        key_id: key.clone(),
        bucket: 20_261_033,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: tokens,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let id = op(41);
    s.add_metering_op(id, &[delta(10)]).expect("applies");
    s.add_metering_op(id, &[delta(10)])
        .expect("a replay answers Ok");
    assert_eq!(
        s.add_metering_op(id, &[delta(11)]),
        Err(OpRefused::Conflict)
    );
    let rows: Vec<_> = s
        .list_metering(20_261_033)
        .expect("list_metering")
        .into_iter()
        .filter(|r| r.key_id == key)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].tokens_input, rows[0].requests),
        (10, 1),
        "{rows:?}"
    );
}
