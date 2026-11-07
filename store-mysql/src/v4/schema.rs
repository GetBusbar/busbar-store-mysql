// SPDX-License-Identifier: Apache-2.0
//! MySQL DDL commits implicitly. Only a verified owned initialization may resume.
use crate::mysqlwire::Conn;
use busbar_contract::abi::sdk::store::v4::metadata;
use busbar_contract::persistence::{BackendInfo, DatasetId, Durability, Failure};
use mysql_common::params;

const META: &str = "busbar_v4_meta";
const RECORDS: &str = "busbar_v4_records";
const RECEIPTS: &str = "busbar_v4_receipts";
const META_DDL: &str = "CREATE TABLE busbar_v4_meta (k BINARY(1) NOT NULL PRIMARY KEY, facts BINARY(64) NOT NULL, ready BINARY(1) NOT NULL) ENGINE=InnoDB";
const RECORDS_DDL: &str = "CREATE TABLE busbar_v4_records (namespace BINARY(16) NOT NULL, address_hash BINARY(32) NOT NULL, raw_key LONGBLOB NOT NULL, value LONGBLOB NOT NULL, PRIMARY KEY(namespace,address_hash)) ENGINE=InnoDB";
const RECEIPTS_DDL: &str = "CREATE TABLE busbar_v4_receipts (writer BINARY(16) NOT NULL, operation BINARY(16) NOT NULL, payload LONGBLOB NOT NULL, PRIMARY KEY(writer,operation)) ENGINE=InnoDB";

pub(super) async fn posture(conn: &mut Conn) -> Result<(), Failure> {
    let (mode, flush, binlog, sync): (String, u64, u64, u64) = conn.query_first(
        "SELECT @@SESSION.sql_mode, @@GLOBAL.innodb_flush_log_at_trx_commit, @@GLOBAL.log_bin, @@GLOBAL.sync_binlog"
    ).await.map_err(|_| Failure::Unavailable)?.ok_or(Failure::Corrupt)?;
    if !mode.split(',').any(|m| m == "STRICT_ALL_TABLES")
        || flush != 1
        || (binlog != 0 && sync != 1)
    {
        return Err(Failure::Refused);
    }
    Ok(())
}

pub(super) async fn open(conn: &mut Conn) -> Result<BackendInfo, Failure> {
    posture(conn).await?;
    if let Some(upgrade) = crate::legacy::lifecycle::load(conn)
        .await
        .map_err(|_| Failure::Refused)?
    {
        if upgrade.completed.is_none() {
            return Err(Failure::Refused);
        }
        crate::legacy::lifecycle::verify_snapshot(conn, &upgrade)
            .await
            .map_err(|_| Failure::Refused)?;
        let info = inspect_current(conn).await?;
        if info.dataset.0 != upgrade.target {
            return Err(Failure::Refused);
        }
        return Ok(info);
    }
    // A database-scoped native lock serializes initializers across DDL autocommits.
    let lock: Option<u64> = conn
        .query_first("SELECT GET_LOCK(CONCAT('busbar-v4:',LEFT(SHA2(DATABASE(),256),48)),0)")
        .await
        .map_err(|_| Failure::Unavailable)?;
    if lock != Some(1) {
        return Err(Failure::Unavailable);
    }
    let result = initialize(conn, None).await;
    let released: Result<Option<u64>, _> = conn
        .query_first("SELECT RELEASE_LOCK(CONCAT('busbar-v4:',LEFT(SHA2(DATABASE(),256),48)))")
        .await;
    match (result, released) {
        (Ok(info), Ok(Some(1))) => Ok(info),
        (Err(error), _) => Err(error),
        _ => Err(Failure::Unavailable),
    }
}

pub(super) async fn prepare_upgrade(
    conn: &mut Conn,
    upgrade: &crate::legacy::lifecycle::Upgrade,
) -> Result<BackendInfo, Failure> {
    crate::legacy::lifecycle::check(conn, upgrade)
        .await
        .map_err(|_| Failure::Refused)?;
    posture(conn).await?;
    initialize(conn, Some(upgrade)).await
}

pub(super) async fn inspect_current(conn: &mut Conn) -> Result<BackendInfo, Failure> {
    for table in [META, RECORDS, RECEIPTS] {
        verify(conn, table).await?;
    }
    let (info, ready) = inspect_initializing(conn).await?;
    if !ready {
        return Err(Failure::Refused);
    }
    Ok(info)
}

pub(super) async fn inspect_initializing(conn: &mut Conn) -> Result<(BackendInfo, bool), Failure> {
    verify(conn, META).await?;
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query("SELECT k,facts,ready FROM busbar_v4_meta LIMIT 2")
        .await
        .map_err(|_| Failure::Unavailable)?;
    let [(key, facts, ready)] = rows.as_slice() else {
        return Err(Failure::Corrupt);
    };
    if key != &[1] || ![vec![0], vec![1]].contains(ready) {
        return Err(Failure::Refused);
    }
    let info = metadata::decode(facts).map_err(|_| Failure::Corrupt)?;
    if info.physical_version != 1 || info.durability != Durability::Local {
        return Err(Failure::Refused);
    }
    Ok((info, ready == &[1]))
}

async fn initialize(
    conn: &mut Conn,
    upgrade: Option<&crate::legacy::lifecycle::Upgrade>,
) -> Result<BackendInfo, Failure> {
    if upgrade.is_none() {
        if super::empty_origin::empty(conn).await? {
            super::empty_origin::install(conn).await?;
        } else if super::empty_origin::owned(conn).await? {
            super::empty_origin::check(conn).await?;
        } else {
            super::empty_origin::install(conn).await?;
        }
    }
    let tables: Vec<(String, String)> = conn.query("SELECT TABLE_NAME,TABLE_TYPE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME")
        .await.map_err(|_| Failure::Unavailable)?;
    let tables = if let Some(upgrade) = upgrade {
        tables
            .into_iter()
            .filter(|(name, _)| {
                name != "busbar_upgrade_control"
                    && !upgrade.catalogue.iter().any(|t| &t.name == name)
            })
            .collect::<Vec<_>>()
    } else {
        tables
            .into_iter()
            .filter(|(name, _)| name != "store_meta")
            .collect::<Vec<_>>()
    };
    if tables.iter().any(|(name, kind)| {
        kind != "BASE TABLE" || ![META, RECORDS, RECEIPTS].contains(&name.as_str())
    }) {
        return Err(Failure::Refused);
    }
    let triggers: Option<u64> = conn
        .query_first(
            "SELECT COUNT(*) FROM information_schema.triggers WHERE TRIGGER_SCHEMA=DATABASE()",
        )
        .await
        .map_err(|_| Failure::Unavailable)?;
    if upgrade.is_none() && triggers != Some(3) {
        return Err(Failure::Refused);
    }
    if tables.is_empty() {
        let mut identities = [0; 48];
        if let Some(upgrade) = upgrade {
            use sha2::{Digest, Sha256};
            identities[..16].copy_from_slice(&upgrade.target);
            for (offset, domain) in [
                (16, b"mysql.target.atomic.v1".as_slice()),
                (32, b"mysql.target.clock.v1".as_slice()),
            ] {
                let mut hash = Sha256::new();
                hash.update(domain);
                hash.update(upgrade.target);
                identities[offset..offset + 16].copy_from_slice(&hash.finalize()[..16]);
            }
        } else {
            getrandom::fill(&mut identities).map_err(|_| Failure::Unavailable)?;
        }
        let info = BackendInfo {
            dataset: DatasetId(identities[..16].try_into().map_err(|_| Failure::Corrupt)?),
            atomic_domain: identities[16..32]
                .try_into()
                .map_err(|_| Failure::Corrupt)?,
            clock_authority: identities[32..].try_into().map_err(|_| Failure::Corrupt)?,
            physical_version: 1,
            durability: Durability::Local,
        };
        let facts = metadata::encode(info).map_err(|_| Failure::Unavailable)?;
        let hex: String = facts.iter().map(|b| format!("{b:02x}")).collect();
        // One native CREATE ... SELECT installs the marker and identity together.
        // If the server leaves an empty table after a failed DDL, it is unowned and refuses.
        conn.query_drop(format!(
            "{META_DDL} AS SELECT X'01' AS k, X'{hex}' AS facts, X'00' AS ready"
        ))
        .await
        .map_err(|_| Failure::Unknown)?;
    } else if !tables.iter().any(|(name, _)| name == META) {
        return Err(Failure::Refused);
    }
    verify(conn, META).await?;
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query("SELECT k,facts,ready FROM busbar_v4_meta")
        .await
        .map_err(|_| Failure::Unavailable)?;
    let [(key, facts, ready)] = rows.as_slice() else {
        return Err(Failure::Corrupt);
    };
    if key != &[1] || ![vec![0], vec![1]].contains(ready) {
        return Err(Failure::Corrupt);
    }
    let info = metadata::decode(facts).map_err(|_| Failure::Corrupt)?;
    if info.physical_version != 1 || info.durability != Durability::Local {
        return Err(Failure::Refused);
    }
    if upgrade.is_some_and(|u| info.dataset.0 != u.target) {
        return Err(Failure::Refused);
    }
    for (table, ddl) in [(RECORDS, RECORDS_DDL), (RECEIPTS, RECEIPTS_DDL)] {
        let exists: Option<u64> = conn.exec_first("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table", params! {"table" => table}).await.map_err(|_| Failure::Unavailable)?;
        if exists == Some(0) {
            if ready != &[0] {
                return Err(Failure::Corrupt);
            }
            conn.query_drop(ddl).await.map_err(|_| Failure::Unknown)?;
        }
        verify(conn, table).await?;
        if ready == &[0] {
            let count: Option<u64> = conn
                .query_first(format!("SELECT COUNT(*) FROM {table}"))
                .await
                .map_err(|_| Failure::Unavailable)?;
            if count != Some(0) {
                return Err(Failure::Corrupt);
            }
        }
    }
    if ready == &[0] {
        conn.query_drop("UPDATE busbar_v4_meta SET ready=X'01' WHERE k=X'01' AND ready=X'00'")
            .await
            .map_err(|_| Failure::Unknown)?;
    }
    Ok(info)
}

pub(super) async fn verify(conn: &mut Conn, table: &str) -> Result<(), Failure> {
    let engine: Option<String> = conn.exec_first("SELECT ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table AND TABLE_TYPE='BASE TABLE'", params! {"table" => table}).await.map_err(|_| Failure::Unavailable)?;
    if engine.as_deref() != Some("InnoDB") {
        return Err(Failure::Refused);
    }
    let constraints:Vec<(String,String)>=conn.exec("SELECT CONSTRAINT_NAME,CONSTRAINT_TYPE FROM information_schema.table_constraints WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table",params!{"table"=>table}).await.map_err(|_|Failure::Unavailable)?;
    if constraints != vec![("PRIMARY".into(), "PRIMARY KEY".into())] {
        return Err(Failure::Corrupt);
    }
    let columns: Vec<(String, String, String, String, Option<String>, String)> = conn.exec("SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_KEY,COLUMN_DEFAULT,EXTRA FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table ORDER BY ORDINAL_POSITION", params! {"table" => table}).await.map_err(|_| Failure::Unavailable)?;
    let expected = match table {
        META => vec![
            ("k", "binary(1)", "PRI"),
            ("facts", "binary(64)", ""),
            ("ready", "binary(1)", ""),
        ],
        RECORDS => vec![
            ("namespace", "binary(16)", "PRI"),
            ("address_hash", "binary(32)", "PRI"),
            ("raw_key", "longblob", ""),
            ("value", "longblob", ""),
        ],
        RECEIPTS => vec![
            ("writer", "binary(16)", "PRI"),
            ("operation", "binary(16)", "PRI"),
            ("payload", "longblob", ""),
        ],
        _ => return Err(Failure::Corrupt),
    };
    if columns.len() != expected.len()
        || columns
            .iter()
            .zip(expected)
            .any(|((name, ty, null, key, default, extra), (n, t, k))| {
                name != n
                    || ty != t
                    || null != "NO"
                    || key != k
                    || default.is_some()
                    || !extra.is_empty()
            })
    {
        return Err(Failure::Corrupt);
    }
    let indexes: Vec<(String,u64,u64,String,Option<u64>,String)> = conn.exec("SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,SUB_PART,INDEX_TYPE FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table ORDER BY INDEX_NAME,SEQ_IN_INDEX",params!{"table"=>table}).await.map_err(|_|Failure::Unavailable)?;
    let pk = match table {
        META => vec!["k"],
        RECORDS => vec!["namespace", "address_hash"],
        _ => vec!["writer", "operation"],
    };
    if indexes.len() != pk.len()
        || indexes.iter().zip(pk).enumerate().any(
            |(i, ((name, nonunique, seq, col, partial, kind), expected))| {
                name != "PRIMARY"
                    || *nonunique != 0
                    || *seq != i as u64 + 1
                    || col != expected
                    || partial.is_some()
                    || kind != "BTREE"
            },
        )
    {
        return Err(Failure::Corrupt);
    }
    Ok(())
}
