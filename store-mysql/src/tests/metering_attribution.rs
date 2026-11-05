// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{MeteringDelta, MeteringRow};
use std::collections::BTreeMap;
fn attributed_meter(bucket: u64, group: &str, version: &str, n: u64) -> MeteringDelta {
    MeteringDelta {
        scale: 6,
        key_id: "attribution-key".into(),
        bucket,
        model: "model".into(),
        provider: "provider".into(),
        tokens_input: i128::from(n),
        tokens_output: i128::from(n) + 1,
        tokens_cache_read: i128::from(n) + 2,
        tokens_cache_write: i128::from(n) + 3,
        requests: n,
        billable_requests: n,
        key_group_at_use: group.into(),
        pricing_version: version.into(),
        priced_from_ms: 17,
        usage_units: BTreeMap::from([("audio_seconds".into(), i128::from(n))]),
    }
}

fn assert_attributed_rows(rows: Vec<MeteringRow>) {
    let rows: BTreeMap<_, _> = rows
        .into_iter()
        .map(|r| ((r.key_group_at_use.clone(), r.pricing_version.clone()), r))
        .collect();
    let expected = [
        ("", "", 6),
        ("group", "v1", 9),
        ("other", "v1", 12),
        ("group", "V1", 15),
        ("group", "v1 ", 18),
        ("group", "", 21),
        ("", "v1", 24),
    ];
    assert_eq!(rows.len(), expected.len());
    for (group, version, n) in expected {
        let row = &rows[&(group.into(), version.into())];
        assert_eq!(row.key_id, "attribution-key");
        assert_eq!(row.priced_from_ms, 17);
        assert_eq!(row.tokens_input, i128::from(n));
        assert_eq!(row.tokens_output, i128::from(n) + 3);
        assert_eq!(row.tokens_cache_read, i128::from(n) + 6);
        assert_eq!(row.tokens_cache_write, i128::from(n) + 9);
        assert_eq!(row.requests, n);
        assert_eq!(row.billable_requests, n);
        assert_eq!(
            row.usage_units,
            BTreeMap::from([("audio_seconds".into(), i128::from(n))])
        );
    }
}

#[test]
fn historical_attribution_survives_batch_replay_and_reopen() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("attribution") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let bucket = u64::MAX - 1;
    let mut deltas: Vec<_> = [
        ("", ""),
        ("group", "v1"),
        ("other", "v1"),
        ("group", "V1"),
        ("group", "v1 "),
        ("group", ""),
        ("", "v1"),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (g, v))| attributed_meter(bucket, g, v, i as u64 + 2))
    .collect();
    for d in &deltas {
        store.add_metering(d).unwrap();
    }
    deltas.extend(deltas.clone());
    let op = OpId::from_parts(601, 3);
    store.add_metering_op(op, &deltas).unwrap();
    store.add_metering_op(op, &deltas).unwrap();
    let mut changed = deltas.clone();
    changed[0].pricing_version = "changed".into();
    assert_eq!(
        store.add_metering_op(op, &changed),
        Err(OpRefused::Conflict)
    );
    assert_attributed_rows(store.list_metering(bucket).unwrap());
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    reopened.add_metering_op(op, &deltas).unwrap();
    assert_attributed_rows(reopened.list_metering(bucket).unwrap());
}

fn legacy_metering(db: &ScratchDb, interruption: u8) {
    let mut raw = db.conn();
    restore_historical_whole_unit_seed(&mut raw);
    raw.query_drop(
        "CREATE TABLE legacy_metering_units (
        bucket VARBINARY(40) NOT NULL, key_id VARBINARY(64) NOT NULL,
        provider VARBINARY(512) NOT NULL, model VARBINARY(1024) NOT NULL,
        priced_from_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
        unit VARBINARY(512) NOT NULL, count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms,unit)) ENGINE=InnoDB",
    )
    .unwrap();
    raw.query_drop("INSERT INTO legacy_metering_units SELECT bucket,key_id,provider,model,priced_from_ms,unit,count FROM usage_metering_units").unwrap();
    raw.query_drop("DROP TABLE usage_metering_units").unwrap();
    raw.query_drop("RENAME TABLE legacy_metering_units TO usage_metering_units")
        .unwrap();
    raw.query_drop(
        "ALTER TABLE usage_metering DROP PRIMARY KEY,
        ADD PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms),
        MODIFY pricing_version VARCHAR(64) CHARACTER SET utf8mb4 NOT NULL DEFAULT ''",
    )
    .unwrap();
    raw.query_drop("UPDATE store_meta SET v='3' WHERE k='schema_version'")
        .unwrap();
    if interruption != 0 {
        raw.query_drop(
            "INSERT INTO store_meta(k,v) VALUES ('migrating_to','4') ON DUPLICATE KEY UPDATE v='4'",
        )
        .unwrap();
        raw.query_drop(
            "ALTER TABLE usage_metering_units
            ADD COLUMN key_group_at_use VARBINARY(128) NOT NULL DEFAULT '',
            ADD COLUMN pricing_version VARBINARY(256) NOT NULL DEFAULT ''",
        )
        .unwrap();
    }
    if interruption >= 2 {
        raw.query_drop(
            "ALTER TABLE usage_metering MODIFY pricing_version VARBINARY(256) NOT NULL DEFAULT ''",
        )
        .unwrap();
        raw.query_drop(
            "UPDATE usage_metering_units u JOIN usage_metering m
            ON m.key_id=u.key_id AND m.bucket=u.bucket AND m.model=u.model
            AND m.provider=u.provider AND m.priced_from_ms=u.priced_from_ms
            SET u.key_group_at_use=m.key_group_at_use,u.pricing_version=m.pricing_version",
        )
        .unwrap();
        raw.query_drop("ALTER TABLE usage_metering_units DROP PRIMARY KEY,
            ADD PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms,key_group_at_use,pricing_version,unit)").unwrap();
    }
    if interruption >= 3 {
        raw.query_drop("ALTER TABLE usage_metering DROP PRIMARY KEY,
            ADD PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms,key_group_at_use,pricing_version)").unwrap();
    }
}

#[test]
fn migration_preserves_legacy_attribution_units_and_replay_after_interruption() {
    let _ddl = lock_fresh_database_ddl();
    for interruption in 0..4 {
        let Some(db) = ScratchDb::new("meter_history") else {
            return;
        };
        let store = MysqlStore::connect(&db.url).unwrap();

        db.conn().query_drop("ALTER TABLE usage_metering MODIFY pricing_version VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT ''").unwrap();
        let version = "😀".repeat(64);
        let mut old = attributed_meter(u64::MAX, "historical", &version, 7);
        old.scale = 0;
        let mut unknown = attributed_meter(17, "", "", 11);
        unknown.scale = 0;
        let deltas = [old.clone(), unknown.clone()];
        let op = OpId::from_parts(601, 5);
        store.add_metering_op(op, &deltas).unwrap();
        let expected = store.list_metering(old.bucket).unwrap();
        let expected_unknown = store.list_metering(unknown.bucket).unwrap();
        drop(store);
        legacy_metering(&db, interruption);
        let migrated = MysqlStore::connect(&db.url).unwrap();
        migrated.add_metering_op(op, &deltas).unwrap();
        assert_eq!(migrated.list_metering(old.bucket).unwrap(), expected);
        assert_eq!(
            migrated.list_metering(unknown.bucket).unwrap(),
            expected_unknown
        );
        let mut new = MeteringDelta {
            key_group_at_use: "new-group".into(),
            pricing_version: "new-version".into(),
            ..old.clone()
        };
        new.normalize_scale6().unwrap();
        migrated.add_metering(&new).unwrap();
        let rows = migrated.list_metering(old.bucket).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&expected[0]));
        for row in rows {
            assert_eq!(row.scale, 6);
            assert_eq!(row.usage_units, new.usage_units);
        }
        drop(migrated);
        assert_eq!(
            MysqlStore::connect(&db.url)
                .unwrap()
                .list_metering(unknown.bucket)
                .unwrap(),
            expected_unknown
        );
    }
}

#[test]
fn migration_refuses_orphan_metering_units_without_inventing_attribution() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("meter_orphan") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let mut historical = attributed_meter(17, "group", "version", 7);
    historical.scale = 0;
    store.add_metering(&historical).unwrap();
    drop(store);
    legacy_metering(&db, 0);
    db.conn().query_drop("DELETE FROM usage_metering").unwrap();
    for _ in 0..2 {
        let error = MysqlStore::connect(&db.url)
            .err()
            .expect("orphan must refuse migration");
        assert!(
            error.to_string().contains(
                "usage_metering_units contains attribution with no matching usage_metering parent"
            ),
            "{error}"
        );
        let count: u64 = db
            .conn()
            .query_first("SELECT count FROM usage_metering_units")
            .unwrap()
            .unwrap();
        assert_eq!(count, 7);
    }
}
