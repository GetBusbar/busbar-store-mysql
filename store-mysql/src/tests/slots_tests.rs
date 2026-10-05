// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live MySQL: the durable `op_id` dedupe (S1-S4),
//! the money slots and window caps, the journal, sessions and the kernel's records.
//!
//! Every test names its own slots, streams, sessions and keys from a fresh ULID, so the suite runs
//! in parallel against the one shared database and leaves nothing another test reads.

use super::{fresh_store, sample_key, test_url, MysqlStore};
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, ReserveRefused,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{AuditRecord, RecordStore, UsageDelta};

/// The epoch every draw here states (fixed at 0 until WIRE-STORE adds the advance).
const EPOCH: u64 = 0;

/// A name no other test (or earlier run) uses.
fn fresh(tag: &str) -> String {
    format!("{tag}-{}", ulid::Ulid::new())
}

/// A fresh op id: a random node, then `counter` (never a multiple of the sweep cadence, so no test
/// op triggers a sweep).
fn op(counter: u64) -> OpId {
    OpId::from_parts(ulid::Ulid::new().random() as u64 | 1, counter * 2 + 1)
}

fn key(bucket: &str, window_start: u64) -> CellKey<'_> {
    CellKey {
        bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start,
    }
}

fn reserve(
    s: &MysqlStore,
    op: OpId,
    epoch: u64,
    cells: &[Cell<'_>],
) -> Result<Vec<Grant>, ReserveRefused> {
    let mut grants = Vec::new();
    s.reserve(op, epoch, cells.iter().copied(), &mut grants)?;
    Ok(grants)
}

fn release(s: &MysqlStore, op: OpId, items: &[(u64, u64)]) -> Result<Vec<u64>, OpRefused> {
    let mut back = Vec::new();
    s.slice_release(op, EPOCH, items.iter().copied(), &mut back)?;
    Ok(back)
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

/// S3: a refused op records nothing, so a retry under the same `op_id` is judged afresh; a fork
/// anywhere in an audit batch rolls back the whole batch.
#[test]
fn a_failed_batch_applies_nothing_and_records_nothing() {
    let Some(s) = fresh_store() else { return };
    let base = 9_000_000_000 + (ulid::Ulid::new().random() as u64 % 1_000_000_000);
    let rec = |seq: u64, action: &str| AuditRecord {
        seq,
        ts: 1_700_000_000,
        action: action.into(),
        resource: "slots-test".into(),
        outcome: "ok".into(),
        principal: "tester".into(),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    };
    s.append_audit(&rec(base, "first")).expect("seed");
    let id = op(2);
    let forked = [rec(base + 1, "new"), rec(base, "forked")];
    assert!(matches!(
        s.append_audit_batch(id, &forked),
        Err(OpRefused::Failed(_))
    ));
    let stored: Vec<u64> = s
        .list_audit()
        .expect("list_audit")
        .into_iter()
        .map(|r| r.seq)
        .filter(|q| *q == base || *q == base + 1)
        .collect();
    assert_eq!(
        stored,
        vec![base],
        "the batch's first record was rolled back"
    );
    // Not recorded: the same op id with a DIFFERENT (good) body is judged afresh, not a conflict.
    s.append_audit_batch(id, &[rec(base + 1, "new")])
        .expect("a retry after a failure is new");
}

#[test]
fn reserve_needs_a_cap_grants_whole_cells_and_refuses_past_the_cap() {
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("reserve");
    let k = key(&bucket, 60);
    let cell = |amount| Cell { key: k, amount };
    assert_eq!(
        reserve(&s, op(3), EPOCH, &[cell(1)]),
        Err(ReserveRefused::NoCap { cell: 0 })
    );
    s.window_caps(
        op(4),
        &[Cap {
            key: k,
            cap: 5,
            config_gen: 1,
        }],
    )
    .expect("cap");
    let id = op(5);
    let g = reserve(&s, id, EPOCH, &[cell(2), cell(3)]).expect("2 + 3 fits 5");
    assert_eq!(g.iter().map(|g| g.granted).collect::<Vec<_>>(), vec![2, 3]);
    assert_ne!(g[0].slice_id, g[1].slice_id);
    // S1: the replay answers the ORIGINAL grants and draws nothing more.
    assert_eq!(reserve(&s, id, EPOCH, &[cell(2), cell(3)]), Ok(g.clone()));
    assert_eq!(
        reserve(&s, id, EPOCH, &[cell(1)]),
        Err(ReserveRefused::Conflict)
    );
    assert_eq!(
        reserve(&s, op(6), EPOCH, &[cell(1)]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    // A release clamps to what the slice holds and frees that much.
    let back = release(&s, op(7), &[(g[1].slice_id, 10), (g[1].slice_id, 1)]).expect("release");
    assert_eq!(
        back,
        vec![3, 0],
        "clamped, and the emptied slice gives back 0"
    );
    assert_eq!(
        release(&s, op(8), &[(g[1].slice_id, 1)]),
        Err(OpRefused::Failed(format!(
            "slice_release: slice {} is not held",
            g[1].slice_id
        )))
    );
    reserve(&s, op(9), EPOCH, &[cell(3)]).expect("the released 3 can be drawn again");
}

/// Epoch 0 until WIRE-STORE adds the advance: no epoch a caller states is refused, and a grant,
/// which `reserve` gives no lifetime, never expires.
#[test]
fn no_epoch_is_stale_and_a_grant_never_expires() {
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("epoch");
    let k = key(&bucket, 0);
    s.window_caps(
        op(10),
        &[Cap {
            key: k,
            cap: 100,
            config_gen: 1,
        }],
    )
    .expect("cap");
    for (i, epoch) in [7, 0, u64::MAX].into_iter().enumerate() {
        let g = reserve(&s, op(11 + i as u64), epoch, &[Cell { key: k, amount: 1 }])
            .expect("never stale");
        assert_eq!(g[0].valid_until_ms, u64::MAX);
    }
}

#[test]
fn window_caps_newest_generation_wins_and_an_equal_generation_must_agree() {
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("caps");
    let k = key(&bucket, 120);
    let cap = |cap, config_gen| Cap {
        key: k,
        cap,
        config_gen,
    };
    s.window_caps(op(13), &[cap(1, 2)]).expect("first push");
    s.window_caps(op(14), &[cap(9, 1)])
        .expect("an older generation is ignored");
    assert_eq!(
        s.window_caps(op(15), &[cap(1, 2), cap(7, 2)]),
        Err(CapsRefused::CapConflict { index: 1 })
    );
    let cell = Cell { key: k, amount: 1 };
    reserve(&s, op(16), EPOCH, &[cell]).expect("cap 1 holds one");
    assert_eq!(
        reserve(&s, op(17), EPOCH, &[cell]),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    s.window_caps(op(18), &[cap(2, 3)])
        .expect("a newer generation raises it");
    reserve(&s, op(19), EPOCH, &[cell]).expect("cap 2 holds a second");
}

#[test]
fn the_journal_appends_in_order_and_states_its_heads() {
    let Some(s) = fresh_store() else { return };
    let stream = fresh("journal");
    let r = |b: &[u8]| RecordBytes::new(b.to_vec()).unwrap();
    let id = op(20);
    let h = s
        .append_batch(id, &stream, &[r(b"a"), r(b"b")])
        .expect("append");
    assert_eq!(h, Head { seq: 2, epoch: 0 });
    assert_eq!(
        s.append_batch(id, &stream, &[r(b"a"), r(b"b")]),
        Ok(h),
        "a replay answers the original head"
    );
    let h = s.append_batch(op(21), &stream, &[r(b"c")]).expect("append");
    assert_eq!(h.seq, 3);
    let heads = s.heads().expect("heads");
    assert!(
        heads.contains(&(stream.clone(), Head { seq: 3, epoch: 0 })),
        "{heads:?}"
    );
}

#[test]
fn sessions_upsert_list_by_principal_and_remove() {
    let Some(s) = fresh_store() else { return };
    let principal = fresh("principal");
    let base = ulid::Ulid::new().random() as u64 >> 1;
    s.session_put(base + 2, "node-b", &principal).expect("put");
    s.session_put(base + 1, "node-a", &principal).expect("put");
    s.session_put(base + 1, "node-c", &principal)
        .expect("upsert");
    assert_eq!(
        s.sessions_for(&principal).expect("list"),
        vec![
            (base + 1, "node-c".to_string()),
            (base + 2, "node-b".to_string())
        ]
    );
    s.session_remove(base + 1).expect("remove");
    s.session_remove(base + 1)
        .expect("an absent session removes Ok");
    assert_eq!(
        s.sessions_for(&principal).expect("list"),
        vec![(base + 2, "node-b".to_string())]
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
    assert!(matches!(
        s.append_plane_record_op(op(23), rec(b"two").view()),
        Err(OpRefused::Failed(_))
    ));
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"one".to_vec()]);
}
