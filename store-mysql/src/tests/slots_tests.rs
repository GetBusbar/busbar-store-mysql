// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live MySQL: the durable `op_id` dedupe (S1-S4) and
//! the kernel's records. The store keeps ledger counts and records; money is not its business.
//!
//! Every test names its own buckets, schemas and keys from a fresh ULID, so the suite runs in
//! parallel against the one shared database and leaves nothing another test reads.

use super::{fresh_store, sample_key, test_url, MysqlStore};
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
    assert!(matches!(
        s.append_plane_record_op(id, rec(1, b"forked").view()),
        Err(OpRefused::Failed(_))
    ));
    // Not recorded: the same op id with a DIFFERENT (good) body is judged afresh, not a conflict.
    s.append_plane_record_op(id, rec(2, b"second").view())
        .expect("a retry after a failure is new");
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"first".to_vec(), b"second".to_vec()]);
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
    assert!(matches!(
        s.append_plane_record_op(op(23), rec(b"two").view()),
        Err(OpRefused::Failed(_))
    ));
    let chain = s
        .list_plane_records("slots_test", &PlaneSelector::Parent(parent.as_str().into()))
        .expect("list");
    assert_eq!(chain, vec![b"one".to_vec()]);
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
    // Put the database back to what a v9 build left: the dead slots' tables with rows in them, and
    // their dedupe rows next to the kept ones.
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
