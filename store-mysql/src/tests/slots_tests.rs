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
use mysql::prelude::Queryable;

/// The epoch every draw against the SHARED test database states. The fleet epoch is one row of that
/// database and only rises, so every suite drawing against it states the same high epoch (the
/// plugin's conformance scenario states `1 << 62` too); a test that moves the epoch runs in a
/// database of its own ([`Iso`]).
const EPOCH: u64 = 1 << 62;

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
    // `purge_windows_before` is unscoped; hold the lock so it cannot delete this window mid-test.
    let _guard = super::lock_usage_windows();
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
        Ok(vec![0]),
        "a closed slice is a granted id: a later release of it returns 0"
    );
    reserve(&s, op(9), EPOCH, &[cell(3)]).expect("the released 3 can be drawn again");
}

/// RED before slice life (e): a release on window 0 is final. The holder of a 6-unit window-0 slice
/// spent 4 and hands back 2; the slice closes, so a second release returns 0, the 4 spent stay
/// counted (6 more fill the cap of 10) and nothing past the cap is granted. A slice on a rolling
/// window keeps the partial-release rule: what it still holds can be handed back later.
#[test]
fn a_release_on_window_0_is_final() {
    let Some(s) = fresh_store() else { return };
    let bucket = fresh("window0-final");
    let zero = key(&bucket, 0);
    s.window_caps(
        op(40),
        &[Cap {
            key: zero,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("the window-0 cap is pushed");
    let draw = |n: u64, amount: u64| {
        reserve(&s, op(n), EPOCH, &[Cell { key: zero, amount }]).map(|g| g[0])
    };
    let g = draw(41, 6).expect("a window-0 draw within its cap");
    assert_eq!(g.granted, 6);
    assert_eq!(
        release(&s, op(42), &[(g.slice_id, 2)]).expect("released"),
        vec![2]
    );
    assert_eq!(
        release(&s, op(43), &[(g.slice_id, 4)]).expect("answered"),
        vec![0],
        "a window-0 slice stayed open after its release"
    );
    assert_eq!(draw(44, 6).expect("the returned 2 are drawable").granted, 6);
    assert_eq!(
        draw(45, 1).map(|g| g.granted),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the spent part of a released window-0 slice was not counted"
    );

    let rolling_bucket = fresh("rolling-partial");
    let rolling = key(&rolling_bucket, 60);
    s.window_caps(
        op(46),
        &[Cap {
            key: rolling,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("the rolling cap is pushed");
    let g = reserve(
        &s,
        op(47),
        EPOCH,
        &[Cell {
            key: rolling,
            amount: 6,
        }],
    )
    .expect("a rolling draw")[0];
    assert_eq!(
        release(&s, op(48), &[(g.slice_id, 2)]).expect("released"),
        vec![2]
    );
    assert_eq!(
        release(&s, op(49), &[(g.slice_id, 4)]).expect("released"),
        vec![4],
        "a rolling-window slice keeps what it still holds for a later release"
    );
}

/// Rules (a)-(c): an equal or higher epoch draws (a higher one raises the fleet epoch), a lower one
/// is StaleEpoch, and every grant is bounded by SLICE_TTL_MS on the store's clock, never `u64::MAX`.
#[test]
fn only_a_lower_epoch_is_stale_and_every_grant_is_bounded() {
    let Some(iso) = Iso::new("epoch") else { return };
    iso.cap("epoch", 100);
    for (epoch, stale) in [
        (7, false),
        (7, false),
        (0, true),
        (u64::MAX, false),
        (7, true),
    ] {
        let before = iso.now_ms();
        let drawn = iso.draw("epoch", 1, epoch);
        if stale {
            assert_eq!(
                drawn.map(drop),
                Err(ReserveRefused::StaleEpoch),
                "epoch {epoch}"
            );
            continue;
        }
        let g = drawn.expect("an equal or higher epoch draws");
        assert_ne!(g.valid_until_ms, u64::MAX, "a fleet store's grant expires");
        assert!(
            g.valid_until_ms >= before + TTL && g.valid_until_ms <= iso.now_ms() + TTL,
            "valid_until_ms {} is not now + SLICE_TTL_MS",
            g.valid_until_ms
        );
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

// ── THE FLEET EPOCH AND SLICE LIFE (`abi::store::money`, rules (a)-(c)) ─────────────────────────

/// A store in a DATABASE of its own. The fleet epoch is one row for the whole database, so a test
/// that raises it must not do so in the shared one, where every other test draws at [`EPOCH`]. The
/// database is dropped with the guard.
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
        self.store = Some(self.node());
    }

    /// A second, independent instance over the same state (another node of the fleet).
    fn node(&self) -> MysqlStore {
        MysqlStore::connect(&self.db.url).expect("connect another node")
    }

    /// The database's clock in ms: the store's one clock.
    fn now_ms(&self) -> u64 {
        self.db
            .conn()
            .query_first::<u64, _>(
                "SELECT TIMESTAMPDIFF(MICROSECOND, '1970-01-01', UTC_TIMESTAMP(6)) DIV 1000",
            )
            .unwrap()
            .unwrap()
    }

    /// Move the store's clock forward by `ms`: every slice's expiry moves back by as much.
    fn advance_ms(&self, ms: u64) {
        self.db
            .conn()
            .exec_drop(
                "UPDATE store_slices SET valid_until_ms = GREATEST(valid_until_ms, ?) - ?",
                (ms, ms),
            )
            .unwrap();
    }

    fn cap(&self, bucket: &str, cap: u64) {
        self.s()
            .window_caps(
                op(30),
                &[Cap {
                    key: requests(bucket),
                    cap,
                    config_gen: 1,
                }],
            )
            .expect("the cap is pushed");
    }

    fn draw(&self, bucket: &str, amount: u64, epoch: u64) -> Result<Grant, ReserveRefused> {
        reserve(
            self.s(),
            op(31),
            epoch,
            &[Cell {
                key: requests(bucket),
                amount,
            }],
        )
        .map(|g| g[0])
    }

    /// Release under `epoch` (a fresh `op_id`).
    fn release_at(&self, epoch: u64, items: &[(u64, u64)]) -> Result<Vec<u64>, OpRefused> {
        let mut back = Vec::new();
        self.s()
            .slice_release(op(32), epoch, items.iter().copied(), &mut back)?;
        Ok(back)
    }
}

fn requests(bucket: &str) -> CellKey<'_> {
    key(bucket, 1_790_000_000_000)
}

const TTL: u64 = busbar_contract::abi::store::SLICE_TTL_MS;

/// Rule (b): a reserve under an epoch below the stored one is StaleEpoch, applies nothing and records
/// nothing under its `op_id` (the same id retried under a current epoch is evaluated afresh).
#[test]
fn a_stale_epoch_is_refused_and_applies_nothing() {
    let Some(iso) = Iso::new("stale") else { return };
    iso.cap("stale", 10);
    iso.draw("stale", 1, 2).expect("epoch 2 draws");
    let id = op(33);
    let cell = Cell {
        key: requests("stale"),
        amount: 1,
    };
    assert_eq!(
        reserve(iso.s(), id, 1, &[cell]),
        Err(ReserveRefused::StaleEpoch),
        "a reserve under an epoch below the stored one is StaleEpoch"
    );
    assert!(
        reserve(iso.s(), id, 2, &[cell]).is_ok(),
        "the refused reserve left a row under its op_id"
    );
    iso.draw("stale", 8, 2)
        .expect("the stale reserve applied nothing: 1 + 1 + 8 of 10");
    assert_eq!(
        iso.draw("stale", 1, 2).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

/// Rule (a): the stored epoch survives a restart, and a second node sees the same fleet epoch.
#[test]
fn the_epoch_survives_a_restart() {
    let Some(mut iso) = Iso::new("restart") else {
        return;
    };
    iso.cap("restart", 10);
    iso.draw("restart", 1, 3).expect("epoch 3 draws");
    let other = iso.node();
    iso.restart();
    assert_eq!(
        iso.draw("restart", 1, 2).map(drop),
        Err(ReserveRefused::StaleEpoch),
        "the epoch was lost on restart"
    );
    assert_eq!(
        reserve(
            &other,
            op(34),
            2,
            &[Cell {
                key: requests("restart"),
                amount: 1
            }]
        ),
        Err(ReserveRefused::StaleEpoch),
        "another node of the fleet did not see the epoch"
    );
}

/// Rule (c): a grant is valid for at most SLICE_TTL_MS from the store's clock, and an expired slice's
/// unreturned part is drawable again.
#[test]
fn a_grant_is_bounded_and_an_expired_slice_returns_to_the_window() {
    let Some(iso) = Iso::new("ttl") else { return };
    iso.cap("ttl", 5);
    let before = iso.now_ms();
    let g = iso.draw("ttl", 5, 2).expect("draws the whole window");
    let after = iso.now_ms();
    assert!(
        g.valid_until_ms >= before + TTL && g.valid_until_ms <= after + TTL,
        "valid_until_ms {} is not within [{before} + SLICE_TTL_MS, {after} + SLICE_TTL_MS]",
        g.valid_until_ms
    );
    assert_eq!(
        iso.draw("ttl", 1, 2).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    iso.advance_ms(TTL + 1);
    iso.draw("ttl", 5, 2)
        .expect("an expired slice's unspent returned to the window");
}

/// A release applies whatever the epoch, returns each unit once, and an expiry after the release
/// returns nothing more.
#[test]
fn a_stale_epoch_release_applies_exactly_once() {
    let Some(iso) = Iso::new("release") else {
        return;
    };
    iso.cap("release", 10);
    iso.cap("release-fence", 1);
    let g = iso.draw("release", 4, 5).expect("epoch 5 draws");
    iso.draw("release-fence", 1, 6).expect("epoch 6 draws");
    assert_eq!(
        iso.release_at(5, &[(g.slice_id, 4)]),
        Ok(vec![4]),
        "never refused"
    );
    assert_eq!(
        iso.release_at(6, &[(g.slice_id, 4)]),
        Ok(vec![0]),
        "nothing left"
    );
    iso.advance_ms(TTL + 1);
    iso.draw("release", 10, 6)
        .expect("the returned 4 are drawable");
    assert_eq!(
        iso.draw("release", 1, 6).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "expiry returned the released slice again"
    );
    assert_eq!(
        iso.release_at(6, &[(g.slice_id, 4)]),
        Ok(vec![0]),
        "a slice closed and gone answers 0"
    );
}

/// An EXPIRED slice's unreturned part went back at expiry, whether or not a reserve has reclaimed
/// it yet: its release answers 0, and the window's headroom comes back exactly once.
#[test]
fn a_release_of_an_expired_slice_returns_zero_and_the_headroom_once() {
    let Some(iso) = Iso::new("expired") else {
        return;
    };
    iso.cap("expired", 5);
    let g = iso.draw("expired", 3, 0).expect("a draw");
    iso.advance_ms(TTL + 1);
    assert_eq!(
        iso.release_at(0, &[(g.slice_id, 3)]),
        Ok(vec![0]),
        "an expired slice's unreturned part already went back at expiry"
    );
    iso.draw("expired", 5, 0)
        .expect("the expired 3 are back: the whole cap draws");
    assert_eq!(
        iso.draw("expired", 1, 0).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the expired slice's headroom came back twice"
    );
}

/// A closed rolling-window slice is a granted id: a later release of it (a new `op_id`) answers 0 and
/// does not fail the batch it rides in; an id never granted still FAILS.
#[test]
fn a_closed_slice_releases_zero_and_a_never_granted_id_fails() {
    let Some(iso) = Iso::new("closed") else {
        return;
    };
    iso.cap("closed", 10);
    iso.cap("closed-peer", 10);
    let a = iso.draw("closed", 3, 0).expect("draw a");
    let b = iso.draw("closed-peer", 4, 0).expect("draw b");
    let rel = |items: &[(u64, u64)]| iso.release_at(0, items);
    assert_eq!(rel(&[(a.slice_id, 3)]), Ok(vec![3]), "fully returned");
    assert_eq!(
        rel(&[(b.slice_id, 4), (a.slice_id, 3)]),
        Ok(vec![4, 0]),
        "the closed slice answers 0 and the other item still lands"
    );
    assert_eq!(rel(&[(a.slice_id, 3)]), Ok(vec![0]));
    // Expired and reclaimed by a later reserve is closed too.
    let c = iso.draw("closed", 2, 0).expect("draw c");
    iso.advance_ms(TTL + 1);
    // The last grant: the highest slice id ever granted.
    let last = iso.draw("closed", 10, 0).expect("c's 2 came back").slice_id;
    assert_eq!(rel(&[(c.slice_id, 2)]), Ok(vec![0]));
    for never in [last + 1, last + 1000, u64::MAX, 0] {
        assert!(
            matches!(rel(&[(never, 1)]), Err(OpRefused::Failed(_))),
            "slice {never} was never granted"
        );
    }
}

/// Two nodes pushing the first cap of a new window at once: the higher generation wins whichever
/// lands first, and the same generation with a different cap is a CapConflict for exactly one.
#[test]
fn a_concurrent_first_cap_push_keeps_the_higher_generation() {
    const ROUNDS: usize = 150;
    let Some(iso) = Iso::new("race") else { return };
    let barrier = std::sync::Barrier::new(2);
    let push = |cap: u64, gen: u64, tag: &'static str| {
        let node = iso.node();
        let barrier = &barrier;
        move || {
            (0..ROUNDS)
                .map(|i| {
                    barrier.wait();
                    node.window_caps(
                        op(35),
                        &[Cap {
                            key: requests(&format!("race-{tag}-{i}")),
                            cap,
                            config_gen: gen,
                        }],
                    )
                })
                .collect::<Vec<_>>()
        }
    };
    // Round i of "lt" is gen 6 cap 200 against gen 5 cap 100; of "eq" gen 7 cap 100 against 200.
    let (hi, lo) = std::thread::scope(|sc| {
        let hi = sc.spawn(push(200, 6, "lt"));
        let lo = sc.spawn(push(100, 5, "lt"));
        (hi.join().unwrap(), lo.join().unwrap())
    });
    assert!(hi.iter().all(Result::is_ok), "{hi:?}");
    assert!(lo.iter().all(Result::is_ok), "{lo:?}");
    let rows: Vec<(u64, u64)> = iso
        .db
        .conn()
        .query("SELECT cap, config_gen FROM store_caps")
        .unwrap();
    let lower_won = rows.iter().filter(|r| r.0 != 200 || r.1 != 6).count();
    assert_eq!(rows.len(), ROUNDS);
    assert_eq!(lower_won, 0, "a lower generation overwrote a higher one");

    let (x, y) = std::thread::scope(|sc| {
        let x = sc.spawn(push(100, 7, "eq"));
        let y = sc.spawn(push(200, 7, "eq"));
        (x.join().unwrap(), y.join().unwrap())
    });
    for (i, (x, y)) in x.iter().zip(&y).enumerate() {
        let ok = x.is_ok() as u8 + y.is_ok() as u8;
        let conflict = [x, y]
            .iter()
            .filter(|r| matches!(r, Err(CapsRefused::CapConflict { index: 0 })))
            .count();
        assert_eq!(
            (ok, conflict),
            (1, 1),
            "round {i}: the same generation with a different cap must conflict: {x:?} {y:?}"
        );
    }
}

/// A slice of 2^63 or more must still expire and come back (every `u64` is kept bit for bit).
#[test]
fn a_huge_expired_slice_returns_to_the_window() {
    let Some(iso) = Iso::new("huge") else { return };
    iso.cap("huge", u64::MAX);
    iso.draw("huge", u64::MAX - 1, 0).expect("a huge draw");
    iso.advance_ms(TTL + 1);
    iso.draw("huge", u64::MAX - 1, 0)
        .expect("the expired huge slice came back");
}

/// The v8 -> v9 step: slices a v8 build left open (granted `u64::MAX`, never expiring) are stamped
/// to expire one SLICE_TTL_MS after the upgrade, the epoch row exists at 0, and the step runs once.
#[test]
fn the_v9_upgrade_stamps_open_slices_and_creates_the_epoch() {
    let Some(mut iso) = Iso::new("v9") else {
        return;
    };
    iso.cap("legacy", 5);
    iso.draw("legacy", 5, 0).expect("a slice");
    {
        // Put the database back to what a v8 build left: no epoch table, no expiry column.
        let mut c = iso.db.conn();
        for stmt in [
            "DROP TABLE store_epoch",
            "ALTER TABLE store_slices DROP INDEX idx_store_slices_expiry",
            "ALTER TABLE store_slices DROP COLUMN valid_until_ms",
            "UPDATE store_meta SET v = '8' WHERE k = 'schema_version'",
        ] {
            c.query_drop(stmt).unwrap();
        }
    }
    let before = iso.now_ms();
    iso.restart();
    let after = iso.now_ms();
    let read = |iso: &Iso| -> (u64, u64) {
        let mut c = iso.db.conn();
        let until = c
            .query_first("SELECT valid_until_ms FROM store_slices")
            .unwrap()
            .unwrap();
        let epoch = c
            .query_first("SELECT epoch FROM store_epoch")
            .unwrap()
            .unwrap();
        (until, epoch)
    };
    let (until, epoch) = read(&iso);
    assert_eq!(epoch, 0);
    assert!(
        before + TTL <= until && until <= after + TTL,
        "the stranded slice expires one TTL after the upgrade, not never: {until}"
    );
    iso.restart();
    assert_eq!(read(&iso), (until, 0), "a second boot re-stamped the slice");
    iso.advance_ms(TTL + 1);
    iso.draw("legacy", 5, 0)
        .expect("the stranded slice's money came back");
}
