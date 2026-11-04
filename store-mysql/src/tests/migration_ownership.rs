// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const REMOVED_SLOT_TABLES: &[&str] = &[
    "tasks",
    "task_events",
    "mcp_demotions",
    "spent_ask_states",
    "store_caps",
    "store_slices",
    "store_epoch",
    "store_journal",
    "store_sessions",
];

fn legacy_database(db: &ScratchDb, prior: u32) {
    let mut conn = db.conn();
    for statement in schema_fixtures::V1_0_6_SCHEMA {
        conn.query_drop(*statement).unwrap();
    }
    conn.exec_drop(
        "INSERT INTO store_meta (k,v) VALUES ('schema_version', ?)",
        (prior.to_string(),),
    )
    .unwrap();
    for table in REMOVED_SLOT_TABLES {
        conn.query_drop(format!(
            "CREATE TABLE {table} (application_marker INT NOT NULL)"
        ))
        .unwrap();
        conn.query_drop(format!("INSERT INTO {table} VALUES (73)"))
            .unwrap();
    }
}

#[test]
fn upgrading_a_released_v3_database_preserves_unrelated_tables_with_old_slot_names() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("v3_owned_tables") else {
        return;
    };
    legacy_database(&db, 3);
    for _ in 0..2 {
        drop(MysqlStore::connect(&db.url).expect("the released schema upgrades"));
        for table in REMOVED_SLOT_TABLES {
            let marker: Option<u64> = db
                .conn()
                .query_first(format!("SELECT application_marker FROM {table}"))
                .expect("the released store never owned this application's table");
            assert_eq!(
                marker,
                Some(73),
                "{table} must retain its application's data"
            );
        }
        assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    }
}

#[test]
fn unsupported_prerelease_schemas_are_refused_without_removing_application_tables() {
    let _ddl = lock_fresh_database_ddl();
    for prior in [8, 9] {
        let Some(db) = ScratchDb::new("prerelease_owned_tables") else {
            return;
        };
        legacy_database(&db, prior);
        let before = schema_shape(&db);
        let error = MysqlStore::connect(&db.url)
            .err()
            .expect("an unsupported schema above the released version is refused");
        assert!(error.contains("newer than this build"), "{error}");
        assert_eq!(schema_version_of(&db), prior.to_string(), "not restamped");
        assert_eq!(schema_shape(&db), before, "no DDL before refusal");
        for table in REMOVED_SLOT_TABLES {
            let markers: Vec<u64> = db
                .conn()
                .query(format!("SELECT application_marker FROM {table}"))
                .unwrap();
            assert_eq!(markers, vec![73], "{table} keeps all application data");
        }
    }
}

#[test]
fn released_v1_and_v2_upgrade_with_their_original_backfill_rules() {
    let _ddl = lock_fresh_database_ddl();
    for prior in [1, 2] {
        let Some(db) = ScratchDb::new("released_early") else {
            return;
        };
        legacy_database(&db, prior);
        db.conn().query_drop("INSERT INTO usage_windows (window_start,bucket_scope,bucket_id,model,requests,billable_requests) VALUES (12,'key','key','',7,0)").unwrap();
        drop(MysqlStore::connect(&db.url).expect("a released schema upgrades"));
        let billable: u64 = db
            .conn()
            .query_first("SELECT billable_requests FROM usage_windows WHERE window_start=12")
            .unwrap()
            .unwrap();
        assert_eq!(billable, if prior == 1 { 7 } else { 0 });
        assert_eq!(schema_version_of(&db), "4");
        drop(MysqlStore::connect(&db.url).expect("the current schema reopens"));
        let again: u64 = db
            .conn()
            .query_first("SELECT billable_requests FROM usage_windows WHERE window_start=12")
            .unwrap()
            .unwrap();
        assert_eq!(again, billable, "the one-time backfill does not fire again");
    }
}

#[test]
fn released_latin1_columns_are_transcoded_before_becoming_exact_bytes() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("latin1_migration") else {
        return;
    };
    legacy_database(&db, 3);
    let mut raw = db.conn();
    raw.query_drop(
        "ALTER TABLE usage_windows MODIFY model VARCHAR(256) CHARACTER SET latin1 NOT NULL",
    )
    .unwrap();
    raw.query_drop("ALTER TABLE usage_metering MODIFY model VARCHAR(256) CHARACTER SET latin1 NOT NULL, MODIFY provider VARCHAR(128) CHARACTER SET latin1 NOT NULL, MODIFY pricing_version VARCHAR(64) CHARACTER SET latin1 NOT NULL DEFAULT ''").unwrap();
    raw.query_drop(
        "INSERT INTO api_keys (id,labels,created_at,updated_at) VALUES ('key','{}',1,1)",
    )
    .unwrap();
    raw.query_drop("INSERT INTO usage_windows (window_start,bucket_scope,bucket_id,model,tokens_input) VALUES (12,'key','key',CONVERT(0xE9 USING latin1),7)").unwrap();
    raw.query_drop("INSERT INTO usage_metering (bucket,key_id,provider,model,pricing_version,requests) VALUES ('0000000012','key',CONVERT(0xE9 USING latin1),CONVERT(0xE9 USING latin1),CONVERT(0xE9 USING latin1),7)").unwrap();
    let store = MysqlStore::connect(&db.url).expect("latin1 legacy data migrates");
    let ledger = store.get_usage("key", 12).unwrap();
    assert_eq!(ledger.models[0].model, "é");
    let metering = store.list_metering(12).unwrap();
    assert_eq!(metering[0].model, "é");
    assert_eq!(metering[0].provider, "é");
    assert_eq!(metering[0].pricing_version, "é");
    drop(store);
    let store = MysqlStore::connect(&db.url).expect("transcoding is resumable and idempotent");
    assert_eq!(store.list_metering(12).unwrap()[0].pricing_version, "é");
}
