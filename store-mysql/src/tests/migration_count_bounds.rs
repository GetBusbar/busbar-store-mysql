// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn seed_v4(db: &ScratchDb, last_count: u64) {
    drop(MysqlStore::connect(&db.url).unwrap());
    let mut raw = db.conn();
    for sql in [
        "UPDATE store_meta SET v='4' WHERE k='schema_version'",
        "INSERT INTO usage_windows(bucket_scope,bucket_id,window_start,model,tokens_input,tokens_output,tokens_cache_read,tokens_cache_write,requests,billable_requests) VALUES('key','legacy',0,'model',2,3,4,5,17,13)",
        "INSERT INTO usage_window_units(bucket_scope,bucket_id,window_start,model,unit,count) VALUES('key','legacy',0,'model','images',7)",
        "INSERT INTO usage_metering(key_id,bucket,model,provider,tokens_input,tokens_output,tokens_cache_read,tokens_cache_write,requests,billable_requests) VALUES('legacy','0','model','provider',11,13,17,19,23,21)",
    ] {
        raw.query_drop(sql).unwrap();
    }
    raw.exec_drop(
        "INSERT INTO usage_metering_units(key_id,bucket,model,provider,unit,count) VALUES('legacy','0','model','provider','images',?)",
        (last_count,),
    )
    .unwrap();
}

fn assert_quantities(db: &ScratchDb, factor: u64, last_count: u64) {
    let mut raw = db.conn();
    let windows: Vec<(u64, u64, u64, u64, u64, u64)> = raw
        .query("SELECT tokens_input,tokens_output,tokens_cache_read,tokens_cache_write,requests,billable_requests FROM usage_windows")
        .unwrap();
    assert_eq!(
        windows,
        [(2 * factor, 3 * factor, 4 * factor, 5 * factor, 17, 13)]
    );
    let metering: Vec<(u64, u64, u64, u64, u64, u64)> = raw
        .query("SELECT tokens_input,tokens_output,tokens_cache_read,tokens_cache_write,requests,billable_requests FROM usage_metering")
        .unwrap();
    assert_eq!(
        metering,
        [(11 * factor, 13 * factor, 17 * factor, 19 * factor, 23, 21)]
    );
    let window_units: Vec<u64> = raw.query("SELECT count FROM usage_window_units").unwrap();
    assert_eq!(window_units, [7 * factor]);
    let meter_units: Vec<u64> = raw.query("SELECT count FROM usage_metering_units").unwrap();
    assert_eq!(meter_units, [last_count * factor]);
}

#[test]
fn migration_count_bounds_more_than_one_million_rows_reopen_exactly_once() {
    let _guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("countbound") else {
        return;
    };
    seed_v4(&db, 29);
    let mut raw = db.conn();
    // One existing row plus 10^6 generated rows crosses the real mysqlwire row
    // budget. All traffic uses the native server and the production store driver.
    raw.query_drop("CREATE TABLE digits (n INT NOT NULL PRIMARY KEY)")
        .unwrap();
    raw.query_drop("INSERT INTO digits VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)")
        .unwrap();
    raw.query_drop(
        "INSERT INTO usage_window_units(bucket_scope,bucket_id,window_start,model,unit,count)
         SELECT 'key','legacy',1+a.n+10*b.n+100*c.n+1000*d.n+10000*e.n+100000*f.n,'model','images',3
         FROM digits a CROSS JOIN digits b CROSS JOIN digits c
         CROSS JOIN digits d CROSS JOIN digits e CROSS JOIN digits f",
    )
    .unwrap();
    raw.query_drop("DROP TABLE digits").unwrap();
    raw.query_drop("UPDATE usage_window_units SET count=9223372036854 WHERE window_start=1000000")
        .unwrap();
    let size: Option<u64> = raw
        .query_first("SELECT COUNT(*) FROM usage_window_units")
        .unwrap();
    assert_eq!(size, Some(1_000_001));
    for _ in 0..2 {
        let opened = MysqlStore::connect(&db.url);
        if let Err(error) = &opened {
            assert_eq!(schema_version_of(&db), "4");
            let values: Option<(u64, u64, u64)> = raw
                .query_first("SELECT COUNT(*),MIN(count),MAX(count) FROM usage_window_units")
                .unwrap();
            assert_eq!(values, Some((1_000_001, 3, 9_223_372_036_854)));
            panic!("a valid large v4 database must open: {error}");
        }
        drop(opened.unwrap());
        let values: Option<(u64, u64, u64)> = raw
            .query_first("SELECT COUNT(*),MIN(count),MAX(count) FROM usage_window_units")
            .unwrap();
        assert_eq!(
            values,
            Some((1_000_001, 3_000_000, 9_223_372_036_854_000_000))
        );
        assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
        assert_eq!(meta_row(&db, "migrating_to"), None);
    }
    // Check all ten quantity columns and both request counters independently.
    raw.query_drop("DELETE FROM usage_window_units WHERE window_start > 0")
        .unwrap();
    assert_quantities(&db, 1_000_000, 29);
}

#[test]
fn migration_count_bounds_overflow_then_concurrent_startups_convert_once() {
    use std::sync::{Arc, Barrier};

    let _guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("countoverflow") else {
        return;
    };
    seed_v4(&db, 9_223_372_036_855);
    let error = MysqlStore::connect(&db.url)
        .err()
        .expect("the last table's overflow must refuse the migration");
    assert!(error.contains("outside the scale-6 range"), "{error}");
    assert_quantities(&db, 1, 9_223_372_036_855);
    assert_eq!(schema_version_of(&db), "4");
    assert_eq!(meta_row(&db, "migrating_to").as_deref(), Some("5"));
    db.conn()
        .query_drop("UPDATE usage_metering_units SET count=29")
        .unwrap();

    let ready = Arc::new(Barrier::new(3));
    let starts: Vec<_> = (0..2)
        .map(|_| {
            let ready = Arc::clone(&ready);
            let url = db.url.clone();
            std::thread::spawn(move || {
                ready.wait();
                MysqlStore::connect(&url).map(drop)
            })
        })
        .collect();
    ready.wait();
    for start in starts {
        start.join().unwrap().expect("concurrent startup completes");
    }
    assert_quantities(&db, 1_000_000, 29);
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    assert_eq!(meta_row(&db, "migrating_to"), None);
}

#[test]
fn migration_count_bounds_marker_failure_rolls_back_every_quantity() {
    let _guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("countrollback") else {
        return;
    };
    seed_v4(&db, 29);
    let mut admin = db.admin_conn();
    admin
        .query_drop(
            "CREATE TRIGGER refuse_count_stamp BEFORE INSERT ON store_meta FOR EACH ROW
         BEGIN IF NEW.k='schema_version' AND NEW.v='5' THEN
         SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='count migration stamp refusal';
         END IF; END",
        )
        .unwrap();
    let error = MysqlStore::connect(&db.url)
        .err()
        .expect("schema stamp refusal must roll back the conversion");
    assert!(error.contains("count migration stamp refusal"), "{error}");
    assert_quantities(&db, 1, 29);
    assert_eq!(schema_version_of(&db), "4");
    admin.query_drop("DROP TRIGGER refuse_count_stamp").unwrap();
    drop(MysqlStore::connect(&db.url).unwrap());
    assert_quantities(&db, 1_000_000, 29);
    assert_eq!(schema_version_of(&db), SCHEMA_VERSION.to_string());
    assert_eq!(meta_row(&db, "migrating_to"), None);
}
