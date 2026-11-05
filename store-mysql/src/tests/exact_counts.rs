// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{
    MeteringDelta, ModelTokens, ModelTokensDelta, RecordStore, UsageDelta, UsageLedger,
};
use std::collections::BTreeMap;

fn delta(scale: u32, amount: i128, requests: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            scale,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([
                ("input".into(), amount),
                ("audio_seconds".into(), amount),
            ]),
        }],
    }
}

fn meter(key: &str, scale: u32, amount: i128, requests: u64) -> MeteringDelta {
    MeteringDelta {
        scale,
        key_id: key.into(),
        bucket: 0,
        model: "exact-model".into(),
        provider: "provider".into(),
        tokens_input: amount,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests,
        billable_requests: requests,
        key_group_at_use: "group".into(),
        pricing_version: "opening".into(),
        priced_from_ms: 0,
        usage_units: BTreeMap::from([("audio_seconds".into(), amount)]),
    }
}

fn exercise(store: &dyn RecordStore, key: &str) {
    store.add_usage(key, 0, &delta(0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 1);
    let cells = [(key, 0, delta(6, 123_456, 2))];
    store.add_usage_batch_deduped(op, &cells).unwrap();
    store.add_usage_batch_deduped(op, &cells).unwrap();
    let got = store.get_usage(key, 0).unwrap();
    assert_eq!((got.requests, got.billable_requests), (3, 3));
    assert_eq!(got.models[0].scale, 6);
    assert_eq!(got.models[0].usage_units["input"], 2_123_456);
    assert_eq!(got.models[0].usage_units["audio_seconds"], 2_123_456);
    store.add_usage(key, 0, &delta(6, -123_455, 0)).unwrap();
    assert_eq!(
        store.get_usage(key, 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 0, delta(6, 1, 2))])
        .is_err());

    store.add_metering(&meter(key, 0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 2);
    let meters = [meter(key, 6, 123_456, 2)];
    store.add_metering_batch_deduped(op, &meters).unwrap();
    store.add_metering_batch_deduped(op, &meters).unwrap();
    let before = store.list_metering(0).unwrap();
    let got = before.iter().find(|row| row.key_id == key).unwrap();
    assert_eq!(
        (
            got.scale,
            got.tokens_input,
            got.requests,
            got.billable_requests
        ),
        (6, 2_123_456, 3, 3)
    );
    assert_eq!(got.usage_units["audio_seconds"], 2_123_456);
    let op = OpId::from_parts(0xe81, 3);
    assert!(store
        .add_metering_batch_deduped(op, &[meter(key, 6, 1, 1), meter(key, 6, i128::MAX, 1)])
        .is_err());
    assert_eq!(
        store.list_metering(0).unwrap(),
        before,
        "overflow rolls the entire batch back"
    );
    store
        .add_metering_batch_deduped(op, &[meter(key, 6, 1, 1)])
        .unwrap();

    let max = UsageLedger {
        requests: 7,
        billable_requests: 5,
        models: vec![ModelTokens {
            scale: 6,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([("input".into(), i128::MAX)]),
        }],
    };
    store.put_usage(key, 0, &max).unwrap();
    let op = OpId::from_parts(0xe81, 4);
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1)), (key, 0, delta(6, 1, 1))])
        .is_err());
    assert_eq!(store.get_usage(key, 0).unwrap(), max);
    assert_eq!(store.get_usage(key, 1).unwrap(), UsageLedger::default());
    // A refused operation leaves no receipt; the same id can now commit another body.
    store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1))])
        .unwrap();
    assert_eq!(
        store.get_usage(key, 1).unwrap().models[0].usage_units["input"],
        1
    );
    assert!(store.add_usage(key, 2, &delta(3, 1, 1)).is_err());
    assert_eq!(store.get_usage(key, 2).unwrap(), UsageLedger::default());
}

#[test]
fn exact_counts_decimal_legacy_replay_and_atomic_overflow() {
    let _guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("exactcounts") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("exact-counts", "g")).unwrap();
    exercise(&*store, "exact-counts");
}

fn migrated(store: &dyn RecordStore) {
    let row = store.get_usage("legacy", 0).unwrap();
    assert_eq!((row.requests, row.billable_requests), (7, 5));
    let model = row
        .models
        .iter()
        .find(|row| row.model == "exact-model")
        .unwrap();
    assert_eq!(model.scale, 6);
    assert_eq!(model.usage_units["input"], 2_000_000);
    assert_eq!(model.usage_units["audio_seconds"], 3_000_000);
    let rows = store.list_metering(0).unwrap();
    let row = rows.iter().find(|row| row.key_id == "legacy").unwrap();
    assert_eq!(
        (row.scale, row.tokens_input, row.requests),
        (6, 4_000_000, 9)
    );
    assert_eq!(row.usage_units["audio_seconds"], 5_000_000);
}

#[test]
fn exact_counts_legacy_migration_preflight_reopen_idempotent() {
    let _guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("exactmigration") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("legacy", "g")).unwrap();
    drop(store);
    let mut raw = db.conn();
    for sql in [
        "UPDATE store_meta SET v='4' WHERE k='schema_version'",
        "INSERT INTO usage_windows(bucket_scope,bucket_id,window_start,model,requests,billable_requests) VALUES('key','legacy',0,'',7,5)",
        "INSERT INTO usage_windows(bucket_scope,bucket_id,window_start,model,tokens_input) VALUES('key','legacy',0,'exact-model',2)",
        "INSERT INTO usage_window_units(bucket_scope,bucket_id,window_start,model,unit,count) VALUES('key','legacy',0,'exact-model','audio_seconds',170141183460469231731687303715885)",
        "INSERT INTO usage_metering(key_id,bucket,model,provider,tokens_input,requests) VALUES('legacy','0000000000','exact-model','provider',4,9)",
        "INSERT INTO usage_metering_units(key_id,bucket,model,provider,unit,count) VALUES('legacy','0000000000','exact-model','provider','audio_seconds',5)",
    ] {
        raw.query_drop(sql).unwrap();
    }
    assert!(MysqlStore::connect(&db.url).is_err());
    let value: Option<u64> = raw
        .query_first("SELECT tokens_input FROM usage_windows WHERE model='exact-model'")
        .unwrap();
    assert_eq!(value, Some(2));
    let version: Option<String> = raw
        .query_first("SELECT v FROM store_meta WHERE k='schema_version'")
        .unwrap();
    assert_eq!(version.as_deref(), Some("4"));
    raw.query_drop("UPDATE usage_window_units SET count=3")
        .unwrap();
    drop(raw);
    for _ in 0..2 {
        let store = MysqlStore::connect(&db.url).unwrap();
        migrated(&*store);
    }
    let store = MysqlStore::connect(&db.url).unwrap();
    store.add_usage("legacy", 0, &delta(6, 1, 0)).unwrap();
    drop(store);
    let store = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(
        store.get_usage("legacy", 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
}

#[test]
fn exact_i128_driver_decimal_bytes_and_json_numbers() {
    use mysql_common::value::{convert::from_value_opt, Value};
    for amount in [i128::from(u64::MAX) + 1, i128::MAX, i128::MIN] {
        let value = Value::from(amount);
        assert_eq!(value, Value::Bytes(amount.to_string().into_bytes()));
        assert_eq!(from_value_opt::<i128>(value).unwrap(), amount);
        let input = delta(6, amount, 1);
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains(&format!("\"input\":{amount}")), "{json}");
        assert_eq!(serde_json::from_str::<UsageDelta>(&json).unwrap(), input);
    }
}

#[test]
fn exact_i128_wide_refund_min_replay_and_reopen() {
    let _guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("i128_refund") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let wide = i128::from(u64::MAX) + 123_456;
    let op = OpId::from_parts(0xe82, 1);
    let cells = [("wide", 0, delta(6, wide, 1))];
    store.add_usage_batch_deduped(op, &cells).unwrap();
    store.add_usage_batch_deduped(op, &cells).unwrap();
    let before = store.get_usage("wide", 0).unwrap();
    assert_eq!(before.models[0].usage_units["input"], wide);
    assert_eq!(before.models[0].usage_units["audio_seconds"], wide);
    assert_eq!(before.requests, 1);
    let refund = OpId::from_parts(0xe82, 2);
    let cells = [("wide", 0, delta(6, -wide + 1, -1))];
    store.add_usage_batch_deduped(refund, &cells).unwrap();
    store.add_usage_batch_deduped(refund, &cells).unwrap();
    assert_eq!(
        store.get_usage("wide", 0).unwrap().models[0].usage_units["input"],
        1
    );
    // Ordinary refunds keep the floor-at-zero contract, even for MIN.
    store.add_usage("wide", 0, &delta(6, i128::MIN, 0)).unwrap();
    let zero = store.get_usage("wide", 0).unwrap();
    assert!(zero
        .models
        .iter()
        .all(|m| m.usage_units.values().all(|v| *v == 0)));

    let meter_op = OpId::from_parts(0xe82, 3);
    let meters = [meter("wide", 6, wide, u64::MAX)];
    store.add_metering_batch_deduped(meter_op, &meters).unwrap();
    store.add_metering_batch_deduped(meter_op, &meters).unwrap();
    store.add_metering(&meter("wide", 6, 1, 1)).unwrap();
    let rows = store.list_metering(0).unwrap();
    assert_eq!(rows[0].tokens_input, wide + 1);
    assert_eq!(rows[0].usage_units["audio_seconds"], wide + 1);
    assert_eq!(
        (rows[0].requests, rows[0].billable_requests),
        (u64::MAX, u64::MAX)
    );
    drop(store);
    let store = MysqlStore::connect(&db.url).unwrap();
    assert_eq!(store.get_usage("wide", 0).unwrap(), zero);
    assert_eq!(store.list_metering(0).unwrap(), rows);
    store.add_metering_batch_deduped(meter_op, &meters).unwrap();
    assert_eq!(store.list_metering(0).unwrap(), rows);
}

#[test]
fn exact_i128_v5_widens_without_rescaling_and_requires_format_marker() {
    let _guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("i128_v5") else {
        return;
    };
    drop(MysqlStore::connect(&db.url).unwrap());
    let mut raw = db.conn();
    // Restore the actual v5 integer shape before opening the new implementation.
    for (table, columns) in QUANTITY_TABLES {
        raw.query_drop(format!(
            "ALTER TABLE {table} DROP CONSTRAINT {table}_quantity_i128"
        ))
        .unwrap();
        let changes = columns
            .iter()
            .map(|column| format!("MODIFY COLUMN {column} BIGINT UNSIGNED NOT NULL DEFAULT 0"))
            .collect::<Vec<_>>()
            .join(", ");
        raw.query_drop(format!("ALTER TABLE {table} {changes}"))
            .unwrap();
    }
    raw.query_drop("UPDATE store_meta SET v='5' WHERE k='schema_version'")
        .unwrap();
    raw.query_drop("DELETE FROM store_meta WHERE k='quantity_format'")
        .unwrap();
    raw.query_drop("INSERT INTO usage_windows(bucket_scope,bucket_id,window_start,model,tokens_input) VALUES('key','micro',0,'exact-model',9223372036854775807)").unwrap();
    raw.query_drop("INSERT INTO usage_window_units(bucket_scope,bucket_id,window_start,model,unit,count) VALUES('key','micro',0,'exact-model','audio_seconds',9223372036854775807)").unwrap();
    for _ in 0..2 {
        let store = MysqlStore::connect(&db.url).unwrap();
        let row = store.get_usage("micro", 0).unwrap();
        assert_eq!(row.models[0].usage_units["input"], i128::from(i64::MAX));
        assert_eq!(
            row.models[0].usage_units["audio_seconds"],
            i128::from(i64::MAX)
        );
        assert_eq!(schema_version_of(&db), "7");
        assert_eq!(
            meta_row(&db, QUANTITY_FORMAT_KEY).as_deref(),
            Some(QUANTITY_FORMAT)
        );
    }
    raw.query_drop("DELETE FROM store_meta WHERE k='quantity_format'")
        .unwrap();
    let before = schema_shape(&db);
    let error = MysqlStore::connect(&db.url)
        .err()
        .expect("missing range marker refuses");
    assert!(error.contains("quantity format marker"), "{error}");
    assert_eq!(schema_shape(&db), before);
}
