// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;

const MARKER: &str = "usage_request_totals_v1";

#[test]
fn released_request_totals_refund_replay_and_reopen() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("request_totals_release") else {
        return;
    };
    restore_1_5_5(&db);
    let key = "vk_c178b4fe1d02f68e5583171e0dc5b7c2";
    let store = MysqlStore::connect(&db.url).unwrap();
    let before = store.get_usage(key, 0).unwrap();
    assert_eq!((before.requests, before.billable_requests), (4, 4));
    let delta = UsageDelta {
        requests: -1,
        billable_requests: -1,
        ..Default::default()
    };
    let op = OpId::from_parts(0x4d5953514c525151, 1);
    store.add_usage_op(op, key, 0, &delta).unwrap();
    store.add_usage_op(op, key, 0, &delta).unwrap();
    let mut expected = before;
    expected.requests = 3;
    expected.billable_requests = 3;
    assert_eq!(store.get_usage(key, 0).unwrap(), expected);
    assert_eq!(meta_row(&db, MARKER).as_deref(), Some("1"));
    drop(store);
    let store = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(store.get_usage(key, 0).unwrap(), expected);
    store.add_usage_op(op, key, 0, &delta).unwrap();
    assert_eq!(store.get_usage(key, 0).unwrap(), expected);
    store
        .add_usage_op(OpId::from_parts(0x4d5953514c525151, 2), key, 0, &delta)
        .unwrap();
    expected.requests = 2;
    expected.billable_requests = 2;
    assert_eq!(store.get_usage(key, 0).unwrap(), expected);
}

fn unmarked_v5(db: &ScratchDb) {
    drop(MysqlStore::connect(&db.url).unwrap());
    db.conn()
        .query_drop("UPDATE store_meta SET v='5' WHERE k='schema_version'")
        .unwrap();
    db.conn()
        .exec_drop("DELETE FROM store_meta WHERE k=?", (MARKER,))
        .unwrap();
}

#[test]
fn existing_v5_request_totals_saturate_preserve_empty_model_and_open_units() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("request_totals_v5") else {
        return;
    };
    unmarked_v5(&db);
    let mut raw = db.conn();
    raw.query_drop(
        "INSERT INTO usage_windows(window_start,bucket_scope,bucket_id,model,requests,billable_requests,tokens_input)
         VALUES(0,'key','key','',5,7,17),(0,'key','key','named',18446744073709551613,9,13)",
    )
    .unwrap();
    raw.query_drop(
        "INSERT INTO usage_window_units(window_start,bucket_scope,bucket_id,model,unit,count)
         VALUES(0,'key','key','','images',19),(0,'key','key','named','images',23)",
    )
    .unwrap();
    let store = MysqlStore::connect(&db.url).unwrap();
    let before = store.get_usage("key", 0).unwrap();
    assert_eq!((before.requests, before.billable_requests), (u64::MAX, 16));
    let models: BTreeMap<_, _> = before
        .models
        .iter()
        .map(|m| (m.model.as_str(), (m.scale, m.usage_units.clone())))
        .collect();
    assert_eq!(models[""], (6, units(&[(UNIT_INPUT, 17), ("images", 19)])));
    assert_eq!(
        models["named"],
        (6, units(&[(UNIT_INPUT, 13), ("images", 23)]))
    );
    let physical: Vec<(String, u64, u64)> = raw
        .query("SELECT model,requests,billable_requests FROM usage_windows ORDER BY model")
        .unwrap();
    assert_eq!(
        physical,
        [("".into(), u64::MAX, 16), ("named".into(), 0, 0)]
    );
    let op = OpId::from_parts(0x4d5953514c525151, 3);
    let delta = UsageDelta {
        requests: -1,
        billable_requests: -1,
        ..Default::default()
    };
    store.add_usage_op(op, "key", 0, &delta).unwrap();
    let mut expected = before;
    expected.requests -= 1;
    expected.billable_requests -= 1;
    assert_eq!(store.get_usage("key", 0).unwrap(), expected);
    drop(store);
    let store = MysqlStore::connect(&db.url).unwrap();
    store.add_usage_op(op, "key", 0, &delta).unwrap();
    assert_eq!(store.get_usage("key", 0).unwrap(), expected);
}

#[test]
fn request_counter_migration_rolls_back_before_marker_and_retries() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("request_totals_rollback") else {
        return;
    };
    unmarked_v5(&db);
    let mut raw = db.conn();
    raw.query_drop(
        "INSERT INTO usage_windows(window_start,bucket_scope,bucket_id,model,requests,billable_requests,tokens_input)
         VALUES(0,'key','key','named',17,13,7)",
    )
    .unwrap();
    raw.query_drop(
        "CREATE TRIGGER refuse_counter_migration BEFORE UPDATE ON usage_windows
         FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='blocked counter migration'",
    )
    .unwrap();
    assert!(MysqlStore::connect(&db.url).is_err());
    assert_eq!(meta_row(&db, MARKER), None);
    let physical: Vec<(String, u64, u64, u64)> = raw
        .query("SELECT model,requests,billable_requests,tokens_input FROM usage_windows")
        .unwrap();
    assert_eq!(physical, [("named".into(), 17, 13, 7)]);
    raw.query_drop("DROP TRIGGER refuse_counter_migration")
        .unwrap();
    let store = MysqlStore::connect(&db.url).unwrap();
    let ledger = store.get_usage("key", 0).unwrap();
    assert_eq!((ledger.requests, ledger.billable_requests), (17, 13));
    assert_eq!(ledger.models[0].usage_units[UNIT_INPUT], 7);
    assert_eq!(meta_row(&db, MARKER).as_deref(), Some("1"));
}
