// SPDX-License-Identifier: Apache-2.0
//! Physical ownership of a current dataset created from genuinely empty storage.
//! This is not a fabricated historical source or semantic migration checkpoint.
//! Released 1.0.6 reads/parses schema_version immediately after its first CREATE
//! store_meta IF NOT EXISTS. The protected nonnumeric sentinel refuses that read
//! before any of its other business-table DDL, independently of numeric versions.
use crate::mysqlwire::Conn;
use busbar_contract::persistence::Failure;
use mysql_common::params;

const TAG: &[u8] = b"busbar.native.current.v1";
const DDL:&str="CREATE TABLE store_meta (k VARCHAR(191) PRIMARY KEY,v TEXT NOT NULL) ENGINE=InnoDB AS SELECT 'schema_version' AS k,'busbar.native.current.v1' AS v";
const BODY: &str =
    "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'busbar current dataset rejects legacy writes'";
const EVENTS: [&str; 3] = ["INSERT", "UPDATE", "DELETE"];
const TABLES: [&str; 4] = [
    "store_meta",
    "busbar_v4_meta",
    "busbar_v4_records",
    "busbar_v4_receipts",
];
type Result<T> = std::result::Result<T, Failure>;
fn name(event: &str) -> String {
    format!("busbar_empty_origin_{}", event.as_bytes()[0] as char)
}

/// Read-only recognition of only the exact native origin barrier and its owned
/// DDL subset. An arbitrary preexisting store_meta can never be claimed.
pub(super) async fn owned(conn: &mut Conn) -> Result<bool> {
    let exists:Option<u64>=conn.query_first("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='store_meta'").await.map_err(|_|Failure::Unavailable)?;
    if exists == Some(0) {
        return Ok(false);
    }
    if exists != Some(1) {
        return Err(Failure::Corrupt);
    }
    let rows: Vec<(Vec<u8>, Vec<u8>)> = conn
        .query("SELECT k,v FROM store_meta LIMIT 2")
        .await
        .map_err(|_| Failure::Refused)?;
    if !matches!(rows.as_slice(),[(key,value)]if key==b"schema_version"&&value==TAG) {
        return Ok(false);
    }
    let engine:Option<String>=conn.query_first("SELECT ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='store_meta' AND TABLE_TYPE='BASE TABLE'").await.map_err(|_|Failure::Unavailable)?;
    let columns:Vec<(String,String,String,String,Option<String>,String)>=conn.query("SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_KEY,COLUMN_DEFAULT,EXTRA FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='store_meta' ORDER BY ORDINAL_POSITION").await.map_err(|_|Failure::Unavailable)?;
    if engine.as_deref() != Some("InnoDB")
        || columns
            != vec![
                (
                    "k".into(),
                    "varchar(191)".into(),
                    "NO".into(),
                    "PRI".into(),
                    None,
                    "".into(),
                ),
                (
                    "v".into(),
                    "text".into(),
                    "NO".into(),
                    "".into(),
                    None,
                    "".into(),
                ),
            ]
    {
        return Err(Failure::Refused);
    }
    let indexes:Vec<(String,u64,u64,String,Option<u64>,String)>=conn.query("SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,SUB_PART,INDEX_TYPE FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='store_meta' ORDER BY INDEX_NAME,SEQ_IN_INDEX").await.map_err(|_|Failure::Unavailable)?;
    let constraints:Vec<(String,String)>=conn.query("SELECT CONSTRAINT_NAME,CONSTRAINT_TYPE FROM information_schema.table_constraints WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='store_meta'").await.map_err(|_|Failure::Unavailable)?;
    if indexes != vec![("PRIMARY".into(), 0, 1, "k".into(), None, "BTREE".into())]
        || constraints != vec![("PRIMARY".into(), "PRIMARY KEY".into())]
    {
        return Err(Failure::Refused);
    }
    let names:Vec<String>=conn.query("SELECT TRIGGER_NAME FROM information_schema.triggers WHERE TRIGGER_SCHEMA=DATABASE() ORDER BY TRIGGER_NAME LIMIT 4").await.map_err(|_|Failure::Unavailable)?;
    let mut expected = Vec::new();
    for event in EVENTS {
        if guard(conn, event).await? {
            expected.push(name(event));
        }
    }
    expected.sort();
    if names != expected {
        return Err(Failure::Refused);
    }
    Ok(true)
}
async fn guard(conn: &mut Conn, event: &str) -> Result<bool> {
    let rows:Vec<(String,String,String,String,String)>=conn.exec("SELECT EVENT_OBJECT_TABLE,EVENT_MANIPULATION,ACTION_TIMING,ACTION_ORIENTATION,ACTION_STATEMENT FROM information_schema.triggers WHERE TRIGGER_SCHEMA=DATABASE() AND TRIGGER_NAME=:name",params!{"name"=>name(event)}).await.map_err(|_|Failure::Unavailable)?;
    match rows.as_slice() {
        [] => Ok(false),
        [(table, e, timing, orientation, body)]
            if table == "store_meta"
                && e == event
                && timing == "BEFORE"
                && orientation == "ROW"
                && body == BODY =>
        {
            Ok(true)
        }
        _ => Err(Failure::Refused),
    }
}
pub(super) async fn install(conn: &mut Conn) -> Result<()> {
    if !owned(conn).await? {
        let tables:Vec<String>=conn.query("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() LIMIT 5").await.map_err(|_|Failure::Unavailable)?;
        if !tables.is_empty() {
            return Err(Failure::Refused);
        }
        // CREATE+the protected ownership row is atomic. A competing old starter
        // that wins this name causes refusal, never adoption of its source.
        conn.query_drop(DDL).await.map_err(|_| Failure::Unknown)?;
    }
    if !owned(conn).await? {
        return Err(Failure::Refused);
    }
    for event in EVENTS {
        if !guard(conn, event).await? {
            conn.query_drop(format!(
                "CREATE TRIGGER `{}` BEFORE {event} ON store_meta FOR EACH ROW {BODY}",
                name(event)
            ))
            .await
            .map_err(|_| Failure::Unknown)?;
        }
    }
    check(conn).await
}
pub(super) async fn check(conn: &mut Conn) -> Result<()> {
    if !owned(conn).await? {
        return Err(Failure::Refused);
    }
    for event in EVENTS {
        if !guard(conn, event).await? {
            return Err(Failure::Refused);
        }
    }
    Ok(())
}
/// Only the known physical origin metadata may be ignored. Even one opaque
/// record/receipt (including authority) prevents classification as Empty.
pub(super) async fn empty(conn: &mut Conn) -> Result<bool> {
    if !owned(conn).await? {
        return Ok(false);
    }
    let tables:Vec<String>=conn.query("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME LIMIT 5").await.map_err(|_|Failure::Unavailable)?;
    if tables.iter().any(|name| !TABLES.contains(&name.as_str())) {
        return Err(Failure::Refused);
    }
    let meta = tables.iter().any(|name| name == "busbar_v4_meta");
    if !meta && tables.len() != 1 {
        return Err(Failure::Refused);
    }
    let ready = if meta {
        super::schema::inspect_initializing(conn).await?.1
    } else {
        false
    };
    for table in ["busbar_v4_records", "busbar_v4_receipts"] {
        if tables.iter().any(|name| name == table) {
            super::schema::verify(conn, table).await?;
            let count: Option<u64> = conn
                .query_first(format!("SELECT COUNT(*) FROM {table}"))
                .await
                .map_err(|_| Failure::Unavailable)?;
            if count != Some(0) {
                return Ok(false);
            }
        } else if ready {
            return Err(Failure::Corrupt);
        }
    }
    Ok(true)
}
