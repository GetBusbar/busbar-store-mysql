// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live MySQL: the durable `op_id` dedupe (S1-S4) and
//! the kernel's records. The store keeps ledger counts and records; money is not its business.
//!
//! Every test names its own buckets, schemas and keys from a fresh ULID, so the suite runs in
//! parallel against the one shared database and leaves nothing another test reads.

use super::{fresh_store, sample_key, test_url, MysqlStore};
use busbar_contract::abi::sdk::store::fork::chain_fork;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{RecordStore, UsageDelta};
use mysql::prelude::Queryable;

/// A name no other test (or earlier run) uses.
fn fresh(tag: &str) -> String {
    format!("{tag}-{}", ulid::Ulid::new())
}

/// A fresh op id: a random node, then `counter` (never a multiple of the sweep cadence, so no test
/// op triggers a sweep).
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

/// S1/S2/S3/S4: a replay applies nothing and answers the original, a different body is a conflict
/// and applies nothing, and the record survives a reconnect (it is in the database, not the
/// process).
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

/// S3: a refused op records nothing, so a retry under the same `op_id` is judged afresh, not as a
/// conflict with the op that failed.
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
    // The same position with another body is a fork: refused, nothing stored.
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
    // Not recorded: the same op id with a DIFFERENT (good) body is judged afresh, not a conflict.
    s.append_plane_record_op(id, rec(2, b"second").view())
        .expect("a retry after a failure is new");
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"first".to_vec(), b"second".to_vec()]);
}

/// M1 (S5): a value the columns cannot hold is REFUSED (provably nothing applied), not FAILED (which
/// makes the host replay it forever); nothing is recorded, so the same `op_id` applies afterwards.
#[test]
fn a_value_the_columns_cannot_hold_is_refused_and_records_nothing() {
    use busbar_contract::records::ModelTokensDelta;
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("toolong");
    let delta = |model: String| UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
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

/// M7/TA4: a usage counter above `i64::MAX` adds without wrapping and pins at the `u64` ceiling,
/// never an error; a negative delta still floors at zero.
#[test]
fn usage_counters_add_across_the_signed_boundary_and_pin_at_the_ceiling() {
    use busbar_contract::records::{ModelTokens, ModelTokensDelta, UsageLedger};
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("ceiling");
    let big = i64::MAX as u64 + 10;
    let units = |n: u64| -> std::collections::BTreeMap<String, u64> {
        [("tokens_input".to_owned(), n), ("images".to_owned(), n)]
            .into_iter()
            .collect()
    };
    let seed = |n: u64| UsageLedger {
        requests: n,
        billable_requests: n,
        models: vec![ModelTokens {
            model: "m".into(),
            usage_units: units(n),
        }],
    };
    let delta = |d: i64| UsageDelta {
        requests: d,
        billable_requests: d,
        models: vec![ModelTokensDelta {
            model: "m".into(),
            usage_units: [("tokens_input".to_owned(), d), ("images".to_owned(), d)]
                .into_iter()
                .collect(),
        }],
    };
    let read = || s.get_usage(&bucket, 60).expect("get_usage");
    let check = |want: u64, what: &str| {
        let l = read();
        assert_eq!((l.requests, l.billable_requests), (want, want), "{what}");
        for unit in ["tokens_input", "images"] {
            let got = l.models[0].usage_units.get(unit).copied().unwrap_or(0);
            assert_eq!(got, want, "{what}: {unit}");
        }
    };
    s.put_usage(&bucket, 60, &seed(big)).expect("seed");
    s.add_usage_op(op(6), &bucket, 60, &delta(5))
        .expect("add above i64::MAX");
    check(big + 5, "an add above i64::MAX does not wrap");
    s.add_usage_op(op(7), &bucket, 60, &delta(-3))
        .expect("refund");
    check(big + 2, "a refund above i64::MAX");
    s.put_usage(&bucket, 60, &seed(u64::MAX - 2)).expect("seed");
    s.add_usage_op(op(8), &bucket, 60, &delta(i64::MAX))
        .expect("pins");
    check(u64::MAX, "pinned at the ceiling");
    s.add_usage_op(op(9), &bucket, 60, &delta(1))
        .expect("stays pinned");
    check(u64::MAX, "stays at the ceiling");
    s.put_usage(&bucket, 60, &seed(4)).expect("seed");
    s.add_usage_op(op(10), &bucket, 60, &delta(i64::MIN))
        .expect("floors");
    check(0, "a negative delta floors at zero");
}

/// M7/TA4: a metering counter at the ceiling pins instead of erroring.
#[test]
fn metering_counters_pin_at_the_ceiling() {
    use busbar_contract::records::MeteringDelta;
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_ceiling");
    s.put_key(&sample_key(&key, "g")).expect("put_key");
    let cell = |n: u64| MeteringDelta {
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
    s.add_metering_op(op(11), &[cell(u64::MAX - 2)])
        .expect("seed");
    s.add_metering_op(op(12), &[cell(10)])
        .expect("pins, no error");
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
        assert_eq!(v, u64::MAX, "{r:?}");
    }
}

/// M8: a batch is applied in one global order whatever order the caller sent it in (a unit-level
/// check of the order handed to the apply loop; the deadlock itself needs two nodes).
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
            (1, "z", "m", 0),
            (2, "k", "m", 0)
        ]
    );
}

/// Run `write` on a raw connection in a loop while `read` runs on this thread up to `rounds`
/// times; the first `Err` from `read` fails the test. Probabilistic evidence: the reader and the
/// writer race, so a missing snapshot shows as a torn read within a few thousand rounds.
fn race(
    s: &MysqlStore,
    rounds: usize,
    write: impl Fn(&mut mysql::PooledConn) + Sync,
    read: impl Fn() -> Result<(), String>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let stop = AtomicBool::new(false);
    let mut c = s.conn().expect("conn");
    let outcome = std::thread::scope(|sc| {
        sc.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                write(&mut c);
            }
        });
        let r = (0..rounds).try_for_each(|_| read());
        stop.store(true, Ordering::Relaxed);
        r
    });
    outcome.expect("a torn read");
}

/// M9: `get_usage` reads the window's three tables in one snapshot, so a writer that moves the
/// request counter and a token counter together is never seen half-applied.
#[test]
fn get_usage_reads_one_snapshot() {
    use busbar_contract::records::{ModelTokens, UsageLedger};
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("snap");
    let seed = UsageLedger {
        requests: 0,
        billable_requests: 0,
        models: vec![ModelTokens {
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

/// Put `body` under `op` in `store_ops`, as a build before the SDK body recorded it (the slot's
/// name, `:`, its values' `{:?}`).
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

/// ACROSS AN UPGRADE: an op an older build recorded in its `{:?}` body form replays (nothing
/// applied) and a different op under its id is a conflict, for each of the three slots.
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
    let cells = [(bucket.as_str(), 60u64, delta.clone())];
    record_older_body(&mut c, usage, &format!("add_usage_batch:{cells:?}"));
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
    record_older_body(&mut c, metering, &format!("add_metering_batch:{deltas:?}"));
    s.add_metering_op(metering, &deltas)
        .expect("the older body replays");
    let more = [MeteringDelta {
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
    assert_eq!(rows[0].tokens_input, 10, "applied exactly once: {rows:?}");

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
    record_older_body(
        &mut c,
        append,
        &format!("append_plane_record:{:?}", rec(b"one").view()),
    );
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

// ── THE v10 UPGRADE ────────────────────────────────────────────────────────────────────────────

/// A store in a DATABASE of its own, for a test that rewrites the schema. The database is dropped
/// with the guard.
struct Iso {
    db: super::ScratchDb,
    store: Option<MysqlStore>,
}

impl Iso {
    fn new(tag: &str) -> Option<Self> {
        let db = super::ScratchDb::new(&format!("iso_{tag}"))?;
        // Building a whole schema is a DDL burst; one at a time (see `lock_fresh_database_ddl`).
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

    /// A RESTART: the instance goes away and a fresh one opens over the same state.
    fn restart(&mut self) {
        self.store = None;
        self.store = Some(MysqlStore::connect(&self.db.url).expect("reopen"));
    }
}

/// The v9 -> v10 step: the tables of the deleted slots are dropped, the dedupe rows of the deleted
/// slots go with them, and a kept slot's op replays across the upgrade, applying nothing.
#[test]
fn the_v10_upgrade_drops_the_money_and_dead_slot_tables() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector};
    let Some(mut iso) = Iso::new("v10") else {
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
    let dead_op = op(3);
    let mut c = iso.db.conn();
    // Put the database back to what a v9 build left: the kept ops' bodies in its `{:?}` form, the
    // dead slots' tables with rows in them, and their dedupe rows next to the kept ones.
    let cells = [(bucket.as_str(), 60u64, delta.clone())];
    record_older_body(&mut c, usage_op, &format!("add_usage_batch:{cells:?}"));
    record_older_body(
        &mut c,
        plane_op,
        &format!("append_plane_record:{:?}", rec.view()),
    );
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
    drop(c);

    iso.restart();

    let mut c = iso.db.conn();
    for table in [
        "store_caps",
        "store_slices",
        "store_epoch",
        "store_journal",
        "store_sessions",
    ] {
        let n: u64 = c
            .exec_first(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = DATABASE() AND table_name = ?",
                (table,),
            )
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "{table} is gone");
    }
    let version: String = c
        .query_first("SELECT v FROM store_meta WHERE k = 'schema_version'")
        .unwrap()
        .unwrap();
    assert_eq!(version, crate::SCHEMA_VERSION.to_string());
    let bodies: Vec<String> = c.query("SELECT CAST(body AS CHAR) FROM store_ops").unwrap();
    assert!(
        bodies.iter().all(|b| b.starts_with("add_usage_batch:")
            || b.starts_with("add_metering_batch:")
            || b.starts_with("append_plane_record:")),
        "only the kept ops' dedupe rows remain: {bodies:?}"
    );
    assert_eq!(
        bodies.len(),
        2,
        "the two kept ops' rows survive of {ops_before}: {bodies:?}"
    );
    drop(c);

    // A retry across the upgrade answers its original and applies nothing.
    iso.s()
        .add_usage_op(usage_op, &bucket, 60, &delta)
        .expect("the usage op replays across the upgrade");
    iso.s()
        .append_plane_record_op(plane_op, rec.view())
        .expect("the plane op replays across the upgrade");
    assert_eq!(
        iso.s().add_usage_op(
            usage_op,
            &bucket,
            60,
            &UsageDelta {
                requests: 4,
                ..delta.clone()
            }
        ),
        Err(OpRefused::Conflict),
        "a different body under the kept op id is still a conflict"
    );
    let ledger = iso.s().get_usage(&bucket, 60).expect("get_usage");
    assert_eq!(ledger.requests, 3, "applied exactly once: {ledger:?}");
    let chain = iso
        .s()
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"one".to_vec()], "appended exactly once");
}

/// M10: a row stamped `revision = 0` is always "changed" (the contract's own arm), whatever
/// `since` is.
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

/// M11: a revoked slot reclaimed by a new credential carries the NEW credential's `created_at`,
/// not its predecessor's.
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

/// M12: adding a denied subject again is a no-op: the first row (its reason and instant) stays.
#[test]
fn a_repeat_denylist_add_keeps_the_first_row() {
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
    assert_eq!(after, ("a".to_owned(), 1), "the repeat changed the row");
}

/// M13: an upsert is keyed by `(kind, id)` whatever `seq` the record carries: a second write for
/// the id replaces the first and `get_plane_record` reads it.
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

/// M15: `put_usage`'s delete-then-insert deadlocks with a concurrent first write on the same
/// window (both hold the window's gap, each waits to insert into it). The loser is retried, not
/// surfaced as a raw 1213. The other writer is made the heavier transaction so InnoDB picks
/// `put_usage` as the victim.
#[test]
fn put_usage_survives_a_gap_lock_deadlock_with_a_first_write() {
    use busbar_contract::records::{ModelTokens, UsageLedger};
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("gapdl");
    let other = fresh("gapdl-weight");
    let mut b = s.conn().expect("conn");
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
            model: "m".into(),
            usage_units: [("tokens_input".to_owned(), 3)].into_iter().collect(),
        }],
    };
    let result = std::thread::scope(|sc| {
        let a = sc.spawn(|| s.put_usage(&bucket, 60, &ledger));
        // Give put_usage time to reach its insert and wait on the held gap (the test user has no
        // PROCESS privilege to watch the lock wait).
        std::thread::sleep(std::time::Duration::from_millis(1500));
        // put_usage now waits on this window's gap; inserting into it closes the cycle.
        b.exec_drop(
            "INSERT INTO usage_windows (window_start, bucket_scope, bucket_id, model, requests) \
             VALUES (60, 'key', ?, '', 1)",
            (&bucket,),
        )
        .expect("the heavier transaction survives the deadlock");
        b.query_drop("COMMIT").expect("commit");
        a.join().expect("put_usage thread")
    });
    result.expect("put_usage is retried after losing the deadlock");
    assert_eq!(s.get_usage(&bucket, 60).expect("read").requests, 7);
}

/// TB1 (S4): one op in `OPS_SWEEP_EVERY` sweeps dedupe rows older than the retention window; rows
/// inside it survive, and so do the op's own row and an old row's neighbours it is not entitled to.
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
    // An ordinary op does not sweep.
    s.add_usage_op(op(40), &fresh_bucket(), 60, &UsageDelta::default())
        .expect("applies");
    assert!(present(aged, &mut c), "only the sweeping op sweeps");
    // The op whose counter is a multiple of the cadence does.
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

fn fresh_bucket() -> String {
    fresh("sweep")
}

/// TB2: the metering batch in its CURRENT body form (not the older `{:?}` one): a replay applies
/// nothing and answers Ok, a changed body under the same `op_id` is a conflict that applies nothing.
#[test]
fn a_metering_op_id_replays_and_a_changed_body_conflicts() {
    use busbar_contract::records::MeteringDelta;
    let Some(s) = fresh_store() else { return };
    let key = fresh("vk_meter_replay");
    s.put_key(&sample_key(&key, "g")).expect("put_key");
    let delta = |tokens: u64| MeteringDelta {
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
