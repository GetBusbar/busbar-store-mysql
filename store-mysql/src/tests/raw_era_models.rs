// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Opaque price-entry carriers through the loaded store and the resumable released-schema upgrade.
use super::*;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;

const TABLES: [&str; 4] = [
    "usage_windows",
    "usage_window_units",
    "usage_metering",
    "usage_metering_units",
];
const DAY: u64 = 86_400;
const ENTRY_A: &str = "0123456789abcdef01234567";
const ENTRY_B: &str = "0123456789abcdef01234568";

fn original_model() -> String {
    let model = format!("{}x\u{1f}\0 ", "😀".repeat(255));
    assert_eq!(model.len(), 1024);
    model
}

fn era_model(entry: &str) -> String {
    let prefix = format!("busbar.raw-era.v1:{}:{entry}\u{1f}", u64::MAX);
    assert_eq!(prefix.len(), 64);
    format!("{prefix}{}", original_model())
}

fn ledger(models: &[String], count: u64) -> UsageLedger {
    UsageLedger {
        requests: count,
        billable_requests: count,
        models: models
            .iter()
            .map(|model| ModelTokens {
                model: model.clone(),
                usage_units: units(&[(UNIT_INPUT, count), ("audio_seconds", count)]),
            })
            .collect(),
    }
}

fn delta(models: &[String], count: i64) -> UsageDelta {
    UsageDelta {
        requests: count,
        billable_requests: count,
        models: models
            .iter()
            .map(|model| ModelTokensDelta {
                model: model.clone(),
                usage_units: units(&[(UNIT_INPUT, count), ("audio_seconds", count)]),
            })
            .collect(),
    }
}

fn assert_ledger(store: &MysqlStore, models: &[String], count: u64) {
    let mut actual = store.get_usage("era", DAY).unwrap();
    let mut expected = ledger(models, count);
    actual.models.sort_by(|a, b| a.model.cmp(&b.model));
    expected.models.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(actual, expected);
}

fn meter(model: String, version: String, n: u64) -> MeteringDelta {
    MeteringDelta {
        key_id: "era-key".into(),
        bucket: DAY,
        model,
        provider: "provider".into(),
        key_group_at_use: "group".into(),
        pricing_version: version,
        priced_from_ms: 17,
        requests: n,
        billable_requests: n,
        tokens_input: n,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        usage_units: units(&[("audio_seconds", n)]),
    }
}

fn assert_schema(db: &ScratchDb) {
    let mut raw = db.conn();
    for (table, budget) in TABLES.into_iter().zip([1256_u64, 1768, 2096, 2608]) {
        let shape: (String, u64, Option<String>) = raw
            .exec_first(
                "SELECT DATA_TYPE, CHARACTER_OCTET_LENGTH, COLLATION_NAME
             FROM information_schema.columns WHERE table_schema=DATABASE()
             AND table_name=? AND column_name='model'",
                (table,),
            )
            .unwrap()
            .unwrap();
        assert_eq!(shape, ("varbinary".into(), 1088, None), "{table}");
        let columns: Vec<(String, Option<u64>)> = raw
            .exec(
                "SELECT column_name, sub_part FROM information_schema.statistics
             WHERE table_schema=DATABASE() AND table_name=? AND index_name='PRIMARY'
             ORDER BY seq_in_index",
                (table,),
            )
            .unwrap();
        assert!(
            columns.iter().all(|(_, prefix)| prefix.is_none()),
            "{table}: full identities"
        );
        assert!(columns.iter().any(|(name, _)| name == "model"));
        let bytes: u64 = raw.exec_first(
            "SELECT SUM(COALESCE(c.CHARACTER_OCTET_LENGTH,8))
             FROM information_schema.statistics s JOIN information_schema.columns c
             ON c.table_schema=s.table_schema AND c.table_name=s.table_name AND c.column_name=s.column_name
             WHERE s.table_schema=DATABASE() AND s.table_name=? AND s.index_name='PRIMARY'",
            (table,),
        ).unwrap().unwrap();
        assert_eq!(bytes, budget, "{table}");
        assert!(bytes <= 3072, "supported InnoDB full-key budget");
    }
}

#[test]
fn maximum_original_models_keep_entry_identity_through_put_batch_refund_and_reopen() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("raw_era_models") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    assert_schema(&db);
    let fee = format!("busbar.raw-era.v1:{}:{ENTRY_A}", u64::MAX);
    assert_eq!(fee.len(), 63);
    let models = vec![
        era_model(ENTRY_A),
        era_model(ENTRY_B),
        original_model(),
        fee,
    ];
    store.put_usage("era", DAY, &ledger(&models, 5)).unwrap();
    assert_ledger(&store, &models, 5);
    let op = OpId::from_parts(0x4552414d5953514c, 1);
    let change = delta(&models, 3);
    for _ in 0..2 {
        store.add_usage_op(op, "era", DAY, &change).unwrap();
    }
    assert_ledger(&store, &models, 8);
    let mut different = change.clone();
    different.models[0].model.push('x');
    assert_eq!(
        store.add_usage_op(op, "era", DAY, &different),
        Err(OpRefused::Conflict)
    );
    store.add_usage("era", DAY, &delta(&models, -2)).unwrap();
    assert_ledger(&store, &models, 6);

    let version = format!("busbar.card.entry.v1:{ENTRY_A}");
    let meters: Vec<_> = [
        version.clone(),
        format!("{version} "),
        format!("{version}\0"),
        version.to_uppercase(),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, v)| meter(era_model(ENTRY_A), v, i as u64 + 1))
    .collect();
    let meter_op = OpId::from_parts(0x4552414d5953514c, 2);
    store.add_metering_op(meter_op, &meters).unwrap();
    store.add_metering_op(meter_op, &meters).unwrap();
    let before = store.list_metering(DAY).unwrap();
    assert_eq!(before.len(), meters.len());
    for expected in &meters {
        let row = before
            .iter()
            .find(|r| r.pricing_version == expected.pricing_version)
            .unwrap();
        assert_eq!(row.model, expected.model);
        assert_eq!(row.tokens_input, expected.tokens_input);
        assert_eq!(row.requests, expected.requests);
        assert_eq!(row.usage_units, expected.usage_units);
    }
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    reopened.add_usage_op(op, "era", DAY, &change).unwrap();
    reopened.add_metering_op(meter_op, &meters).unwrap();
    assert_ledger(&reopened, &models, 6);
    let after = reopened.list_metering(DAY).unwrap();
    assert_eq!(after.len(), before.len());
    assert!(before.iter().all(|row| after.contains(row)));
}

#[test]
fn released_model_widening_resumes_each_partial_table_and_preserves_existing_rows_and_receipts() {
    let _ddl = lock_fresh_database_ddl();
    for completed in 0..=TABLES.len() {
        let Some(db) = ScratchDb::new("raw_era_migration") else {
            return;
        };
        let store = MysqlStore::connect(&db.url).unwrap();
        let models = vec![original_model()];
        let op = OpId::from_parts(0x4552414d5953514c, 3);
        let change = delta(&models, 7);
        store.add_usage_op(op, "era", DAY, &change).unwrap();
        let old_meter = meter(original_model(), "😀".repeat(64), 9);
        let meter_op = OpId::from_parts(0x4552414d5953514c, 4);
        store
            .add_metering_op(meter_op, std::slice::from_ref(&old_meter))
            .unwrap();
        let expected_metering = store.list_metering(DAY).unwrap();
        drop(store);
        let mut raw = db.conn();

        for table in TABLES {
            raw.query_drop(format!(
                "ALTER TABLE {table} MODIFY model VARBINARY(1024) NOT NULL"
            ))
            .unwrap();
        }
        raw.query_drop("UPDATE store_meta SET v='3' WHERE k='schema_version'")
            .unwrap();
        if completed != 0 {
            raw.query_drop("INSERT INTO store_meta(k,v) VALUES ('migrating_to','4')")
                .unwrap();
        }
        for table in TABLES.iter().take(completed) {
            raw.query_drop(format!(
                "ALTER TABLE {table} MODIFY model VARBINARY(1088) NOT NULL"
            ))
            .unwrap();
        }
        drop(raw);
        for _ in 0..2 {
            let migrated = MysqlStore::connect(&db.url).unwrap();
            assert_schema(&db);
            assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
            assert_eq!(meta_row(&db, "migrating_to"), None);
            migrated.add_usage_op(op, "era", DAY, &change).unwrap();
            migrated
                .add_metering_op(meter_op, std::slice::from_ref(&old_meter))
                .unwrap();
            assert_ledger(&migrated, &models, 7);
            let rows = migrated.list_metering(DAY).unwrap();
            assert_eq!(rows.len(), expected_metering.len());
            assert!(expected_metering.iter().all(|row| rows.contains(row)));
            migrated
                .put_usage("new-era", DAY, &ledger(&[era_model(ENTRY_A)], 11))
                .unwrap();
            assert_eq!(
                migrated.get_usage("new-era", DAY).unwrap(),
                ledger(&[era_model(ENTRY_A)], 11)
            );
        }
    }
}
