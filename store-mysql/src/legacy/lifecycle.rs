// SPDX-License-Identifier: Apache-2.0
//! Native, resumable source freeze. No logical migration or account mutation.
//!
//! CREATE TRIGGER obtains exclusive metadata ownership of its source table and
//! waits for transactions (including prepared XA) that already touched it. Once
//! every guard exists, all successful pre-cut writes have drained. Transactions
//! first touching a guarded table subsequently fail at its BEFORE trigger.
//! The supported released 1.0.6 startup has no source TRUNCATE/DROP route: its
//! admitted schema-3 DDL is IF NOT EXISTS/duplicate-index checks, followed by the
//! guarded store_meta and store_sequence writes. This is no hostile-DBA fence.
use super::{catalogue_digest, catalogue_inner, native_identity, quote, Metadata, Table};
use crate::mysqlwire::{Conn, Error as WireError};
use mysql_common::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const RESERVED_TABLES: &[&str] = &[
    "busbar_upgrade_control",
    "busbar_v4_meta",
    "busbar_v4_records",
    "busbar_v4_receipts",
];
const CONTROL: &str = "busbar_upgrade_control";
const CONTROL_DDL: &str = "CREATE TABLE busbar_upgrade_control (k BINARY(1) NOT NULL PRIMARY KEY, payload LONGBLOB NOT NULL) ENGINE=InnoDB";
const MAX_JOURNAL: usize = 512 * 1024;
const BODY: &str = "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'busbar legacy source is frozen'";
const EVENTS: [&str; 3] = ["INSERT", "UPDATE", "DELETE"];
const LOCK: &str = "CONCAT('busbar-upgrade:',LEFT(SHA2(DATABASE(),256),48))";

/// Native outcomes contain no server messages, credentials or source payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Busy,
    Pending,
    MissingCapability,
    SourceChanged,
    Corrupt,
}

/// The semantic coordinator supplies these exact stable bindings. The plugin
/// never interprets a route, a logical schema, or application records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub operation: [u8; 16],
    pub route: [u8; 32],
    pub target_format: [u8; 32],
    pub registered_catalogue: [u8; 32],
}

/// Durable native identity, not a process-local authority token. Authority also
/// requires the live native lock and complete verified persistent guard set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    version: u32,
    pub binding: Binding,
    pub source: [u8; 16],
    pub target: [u8; 16],
    pub native_identity: Vec<u8>,
    pub physical: u32,
    pub catalogue: Vec<Table>,
    /// Advisory progress only: every DDL is reconciled against the real catalog.
    guards: u32,
    pub(crate) activation: Option<Selection>,
    pub(crate) completed: Option<Selection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub receipt: [u8; 32],
    pub checkpoint: [u8; 32],
}

fn native(error: WireError) -> Error {
    match error {
        WireError::MySqlError(e) if matches!(e.code, 1205 | 1213) => Error::Busy,
        WireError::MySqlError(e) if matches!(e.code, 1044 | 1045 | 1142 | 1227) => {
            Error::MissingCapability
        }
        _ => Error::Pending,
    }
}
fn decode(bytes: &[u8]) -> Result<Upgrade, Error> {
    if bytes.len() > MAX_JOURNAL {
        return Err(Error::Corrupt);
    }
    let row: Upgrade = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
    if row.version != 1
        || row.source == [0; 16]
        || row.target == [0; 16]
        || row.source == row.target
        || row.binding.operation == [0; 16]
        || row.binding.route == [0; 32]
        || row.binding.target_format == [0; 32]
        || row.native_identity.is_empty()
        || row.native_identity.len() > 1024
        || !matches!(row.physical, 3 | 4 | 5 | 7)
        || row.catalogue.is_empty()
        || row.catalogue.len() > super::MAX_TABLES
        || catalogue_digest(&row.catalogue) != row.binding.registered_catalogue
        || row.guards as usize > row.catalogue.len() * EVENTS.len()
        || row
            .catalogue
            .iter()
            .any(|t| !super::TABLES.contains(&t.name.as_str()))
        || row.catalogue.windows(2).any(|p| p[0].name >= p[1].name)
        || (row.completed.is_some() && row.activation.is_none())
        || row
            .activation
            .iter()
            .chain(row.completed.iter())
            .any(|s| s.receipt == [0; 32] || s.checkpoint == [0; 32])
    {
        return Err(Error::Corrupt);
    }
    Ok(row)
}
fn encode(row: &Upgrade) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(row).map_err(|_| Error::Corrupt)?;
    decode(&bytes)?;
    Ok(bytes)
}
fn trigger(table: &str, event: &str) -> String {
    format!("busbar_frozen_{table}_{}", event.as_bytes()[0] as char)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(crate) async fn acquire(conn: &mut Conn) -> Result<(), Error> {
    // A session-local bound, not a global server setting. DDL uncertainty is
    // retained in the journal; timeout never means rollback of earlier guards.
    conn.query_drop("SET SESSION lock_wait_timeout=5")
        .await
        .map_err(native)?;
    let held: Option<u64> = conn
        .query_first(format!("SELECT GET_LOCK({LOCK},0)"))
        .await
        .map_err(native)?;
    if held != Some(1) {
        return Err(Error::Busy);
    }
    Ok(())
}

pub(crate) async fn load(conn: &mut Conn) -> Result<Option<Upgrade>, Error> {
    let exists: Option<u64> = conn.exec_first(
        "SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:name",
        params!{"name" => CONTROL},
    ).await.map_err(native)?;
    match exists {
        Some(0) => Ok(None),
        Some(1) => {
            verify_control(conn).await?;
            let rows: Vec<(Vec<u8>, Vec<u8>)> = conn
                .query("SELECT k,payload FROM busbar_upgrade_control LIMIT 2")
                .await
                .map_err(native)?;
            match rows.as_slice() {
                [(key, bytes)] if key == &[1] => decode(bytes).map(Some),
                _ => Err(Error::Corrupt),
            }
        }
        _ => Err(Error::Corrupt),
    }
}

/// Claim once before the first nontransactional guard DDL. The inspection
/// snapshot must be closed before calling: its metadata locks would block DDL.
pub(crate) async fn begin(
    conn: &mut Conn,
    source: &Metadata,
    binding: Binding,
) -> Result<Upgrade, Error> {
    acquire(conn).await?;
    if let Some(row) = load(conn).await? {
        if row.binding != binding
            || row.physical != source.schema_version
            || row.native_identity != source.native_identity
        {
            return Err(Error::SourceChanged);
        }
        return complete_guards(conn, row).await;
    }
    if binding.registered_catalogue != source.catalogue_digest {
        return Err(Error::SourceChanged);
    }
    // Reject every unknown native object before the first source/control write.
    let actual = super::catalogue(conn)
        .await
        .map_err(|_| Error::SourceChanged)?;
    if actual != source.catalogue
        || native_identity(conn)
            .await
            .map_err(|_| Error::SourceChanged)?
            != source.native_identity
    {
        return Err(Error::SourceChanged);
    }
    // End any metadata-discovery transaction before DDL. A table's CREATE
    // TRIGGER will independently drain its old writers before becoming effective.
    conn.query_drop("ROLLBACK").await.map_err(native)?;
    let mut ids = [0; 32];
    getrandom::fill(&mut ids).map_err(|_| Error::Pending)?;
    let row = Upgrade {
        version: 1,
        binding,
        source: ids[..16].try_into().map_err(|_| Error::Corrupt)?,
        target: ids[16..].try_into().map_err(|_| Error::Corrupt)?,
        native_identity: source.native_identity.clone(),
        physical: source.schema_version,
        catalogue: source.catalogue.clone(),
        guards: 0,
        activation: None,
        completed: None,
    };
    let bytes = encode(&row)?;
    // Atomic CREATE+row avoids an unowned empty-control-table recovery guess.
    conn.query_drop(format!(
        "{CONTROL_DDL} AS SELECT X'01' AS k,X'{}' AS payload",
        hex(&bytes)
    ))
    .await
    .map_err(native)?;
    let stored = load(conn).await?.ok_or(Error::Corrupt)?;
    if stored != row {
        return Err(Error::SourceChanged);
    }
    complete_guards(conn, row).await
}

async fn complete_guards(conn: &mut Conn, mut row: Upgrade) -> Result<Upgrade, Error> {
    verify_source(conn, &row).await?;
    for table in &row.catalogue {
        for event in EVENTS {
            let name = trigger(&table.name, event);
            if !guard_exists(conn, &name, &table.name, event).await? {
                let ddl = format!(
                    "CREATE TRIGGER {} BEFORE {event} ON {} FOR EACH ROW {BODY}",
                    quote(&name).map_err(|_| Error::Corrupt)?,
                    quote(&table.name).map_err(|_| Error::Corrupt)?
                );
                conn.query_drop(ddl).await.map_err(native)?;
                if !guard_exists(conn, &name, &table.name, event).await? {
                    return Err(Error::Corrupt);
                }
            }
        }
    }
    check_guards(conn, &row, true).await?;
    verify_source(conn, &row).await?;
    let old = encode(&row)?;
    row.guards = u32::try_from(row.catalogue.len() * EVENTS.len()).map_err(|_| Error::Corrupt)?;
    let new = encode(&row)?;
    conn.exec_drop(
        "UPDATE busbar_upgrade_control SET payload=:new WHERE k=X'01' AND payload=:old",
        params! {"new" => &new, "old" => &old},
    )
    .await
    .map_err(native)?;
    if load(conn).await?.as_ref() != Some(&row) {
        return Err(Error::SourceChanged);
    }
    check(conn, &row).await?;
    Ok(row)
}

/// Reconciles ownership, all exact guards and original native metadata. Never
/// trusts the journal's progress counter as evidence of current enforcement.
pub(crate) async fn check(conn: &mut Conn, row: &Upgrade) -> Result<(), Error> {
    let owned: Option<u64> = conn
        .query_first(format!("SELECT IS_USED_LOCK({LOCK})=CONNECTION_ID()"))
        .await
        .map_err(native)?;
    if owned != Some(1) {
        return Err(Error::Busy);
    }
    if load(conn).await?.as_ref() != Some(row) {
        return Err(Error::SourceChanged);
    }
    check_guards(conn, row, true).await?;
    verify_source(conn, row).await
}

pub(crate) async fn verify_snapshot(conn: &mut Conn, row: &Upgrade) -> Result<(), Error> {
    if row.guards as usize != row.catalogue.len() * EVENTS.len()
        || load(conn).await?.as_ref() != Some(row)
    {
        return Err(Error::SourceChanged);
    }
    check_guards(conn, row, true).await?;
    verify_source(conn, row).await
}

pub(crate) async fn verify_source(conn: &mut Conn, row: &Upgrade) -> Result<(), Error> {
    if native_identity(conn)
        .await
        .map_err(|_| Error::SourceChanged)?
        != row.native_identity
        || catalogue_inner(conn, true)
            .await
            .map_err(|_| Error::SourceChanged)?
            != row.catalogue
    {
        return Err(Error::SourceChanged);
    }
    let version: Option<Vec<u8>> = conn
        .query_first("SELECT v FROM store_meta WHERE k='schema_version'")
        .await
        .map_err(native)?;
    let quantity: Option<Vec<u8>> = conn
        .query_first("SELECT v FROM store_meta WHERE k='quantity_format'")
        .await
        .map_err(native)?;
    let migrating: Option<Vec<u8>> = conn
        .query_first("SELECT v FROM store_meta WHERE k='migrating_to'")
        .await
        .map_err(native)?;
    let (physical, _) = super::format(version.as_deref(), quantity.as_deref(), migrating.is_some())
        .map_err(|_| Error::SourceChanged)?;
    if physical != row.physical {
        return Err(Error::SourceChanged);
    }
    check_guards(conn, row, false).await
}

pub(crate) async fn resume(conn: &mut Conn, binding: &Binding) -> Result<Upgrade, Error> {
    acquire(conn).await?;
    let row = load(conn).await?.ok_or(Error::Corrupt)?;
    if &row.binding != binding {
        return Err(Error::SourceChanged);
    }
    complete_guards(conn, row).await
}

pub(crate) async fn select(
    conn: &mut Conn,
    row: &Upgrade,
    selection: Selection,
    complete: bool,
) -> Result<Upgrade, Error> {
    let actual = load(conn).await?.ok_or(Error::Corrupt)?;
    let mut identity = actual.clone();
    identity.activation = row.activation.clone();
    identity.completed = row.completed.clone();
    if &identity != row {
        return Err(Error::SourceChanged);
    }
    let mut next = actual.clone();
    let slot = if complete {
        if next.activation.is_none() {
            return Err(Error::SourceChanged);
        }
        &mut next.completed
    } else {
        &mut next.activation
    };
    if let Some(prior) = slot {
        if prior != &selection {
            return Err(Error::SourceChanged);
        }
    } else {
        *slot = Some(selection);
    }
    let old = encode(&actual)?;
    let new = encode(&next)?;
    conn.exec_drop(
        "UPDATE busbar_upgrade_control SET payload=:new WHERE k=X'01' AND payload=:old",
        params! {"new"=>new,"old"=>old},
    )
    .await
    .map_err(native)?;
    if load(conn).await?.as_ref() != Some(&next) {
        return Err(Error::SourceChanged);
    }
    Ok(next)
}

async fn guard_exists(
    conn: &mut Conn,
    name: &str,
    table: &str,
    event: &str,
) -> Result<bool, Error> {
    let rows: Vec<(String,String,String,String,String)> = conn.exec(
        "SELECT EVENT_OBJECT_TABLE,EVENT_MANIPULATION,ACTION_TIMING,ACTION_ORIENTATION,ACTION_STATEMENT FROM information_schema.triggers WHERE TRIGGER_SCHEMA=DATABASE() AND TRIGGER_NAME=:name",
        params!{"name" => name},
    ).await.map_err(native)?;
    match rows.as_slice() {
        [] => Ok(false),
        [(t, e, timing, orientation, body)]
            if t == table
                && e == event
                && timing == "BEFORE"
                && orientation == "ROW"
                && body == BODY =>
        {
            Ok(true)
        }
        _ => Err(Error::SourceChanged),
    }
}
async fn check_guards(conn: &mut Conn, row: &Upgrade, complete: bool) -> Result<(), Error> {
    let mut names: Vec<String> = conn.query("SELECT TRIGGER_NAME FROM information_schema.triggers WHERE TRIGGER_SCHEMA=DATABASE() ORDER BY TRIGGER_NAME LIMIT 97")
        .await.map_err(native)?;
    // Re-sort by Rust byte order; SQL ORDER BY uses the server's collation
    // which may differ (e.g. utf8_general_ci sorts '_' after letters).
    names.sort();
    if names.len() > row.catalogue.len() * EVENTS.len() {
        return Err(Error::SourceChanged);
    }
    let mut expected = Vec::new();
    for table in &row.catalogue {
        for event in EVENTS {
            let name = trigger(&table.name, event);
            let present = guard_exists(conn, &name, &table.name, event).await?;
            if complete && !present {
                return Err(Error::SourceChanged);
            }
            if present {
                expected.push(name);
            }
        }
    }
    expected.sort();
    if names != expected {
        return Err(Error::SourceChanged);
    }
    Ok(())
}

async fn verify_control(conn: &mut Conn) -> Result<(), Error> {
    let engine: Option<String> = conn.exec_first("SELECT ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:name AND TABLE_TYPE='BASE TABLE'",params!{"name"=>CONTROL})
        .await.map_err(native)?;
    let columns: Vec<(String,String,String,String,Option<String>,String)> = conn.query(
        "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_KEY,COLUMN_DEFAULT,EXTRA FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='busbar_upgrade_control' ORDER BY ORDINAL_POSITION"
    ).await.map_err(native)?;
    let expected = vec![
        (
            "k".into(),
            "binary(1)".into(),
            "NO".into(),
            "PRI".into(),
            None,
            "".into(),
        ),
        (
            "payload".into(),
            "longblob".into(),
            "NO".into(),
            "".into(),
            None,
            "".into(),
        ),
    ];
    if engine.as_deref() != Some("InnoDB") || columns != expected {
        return Err(Error::Corrupt);
    }
    let indexes: Vec<(String,u64,u64,String,Option<u64>,String)> = conn.query("SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,SUB_PART,INDEX_TYPE FROM information_schema.statistics WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='busbar_upgrade_control' ORDER BY INDEX_NAME,SEQ_IN_INDEX").await.map_err(native)?;
    let constraints: Vec<(String,String)> = conn.query("SELECT CONSTRAINT_NAME,CONSTRAINT_TYPE FROM information_schema.table_constraints WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='busbar_upgrade_control'").await.map_err(native)?;
    if indexes != vec![("PRIMARY".into(), 0, 1, "k".into(), None, "BTREE".into())]
        || constraints != vec![("PRIMARY".into(), "PRIMARY KEY".into())]
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// Nonsecret exact native source fingerprint for the lifecycle descriptor.
pub fn source_digest(row: &Upgrade) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"busbar.mysql.frozen-source.v1\0");
    hash.update(row.source);
    hash.update((row.native_identity.len() as u64).to_le_bytes());
    hash.update(&row.native_identity);
    hash.update(row.physical.to_le_bytes());
    hash.update(row.binding.registered_catalogue);
    hash.finalize().into()
}

pub(crate) fn selector_digest(row: &Upgrade) -> Result<[u8; 32], Error> {
    let selected = row.activation.as_ref().ok_or(Error::Corrupt)?;
    let mut hash = Sha256::new();
    hash.update(b"mysql.native.selector.v1\0");
    hash.update(row.target);
    hash.update(source_digest(row));
    hash.update(selected.receipt);
    hash.update(selected.checkpoint);
    Ok(hash.finalize().into())
}

#[cfg(test)]
#[path = "../tests/schema_fixtures.rs"]
mod schemas;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mysqlwire::Opts;
    use std::{
        future::Future,
        sync::Arc,
        task::{Context, Poll, Waker},
    };
    busbar_contract::own_seal!(Own);

    #[test]
    fn native_guard_names_and_error_classification_are_exact() {
        for table in super::super::TABLES {
            for event in EVENTS {
                let name = trigger(table, event);
                assert!(name.len() <= 64);
                assert!(quote(&name).is_ok());
            }
        }
        assert_eq!(decode(b"{}").unwrap_err(), Error::Corrupt);
        assert_eq!(
            decode(&vec![0; MAX_JOURNAL + 1]).unwrap_err(),
            Error::Corrupt
        );
        let _ = (schemas::V6_PLANE_TABLES, schemas::V10_SCHEMA);
    }

    #[test]
    #[ignore = "requires dedicated frozen released DB in BUSBAR_MYSQL_UPGRADE_URL"]
    fn native_partial_guard_resume_blocks_released_startup_and_dml() {
        let url = std::env::var("BUSBAR_MYSQL_UPGRADE_URL").unwrap();
        let mut future = std::pin::pin!(async {
            let opts = Arc::new(Opts::from_url(&url).unwrap());
            let init = &["SET SESSION character_set_results = binary"];
            let conn = Conn::open_tcp(&opts, init).await.unwrap();
            let snapshot = super::super::Snapshot::on_connection(conn).await.unwrap();
            let metadata = snapshot.metadata().clone();
            assert_eq!(metadata.schema_version, 3);
            let mut control = snapshot.release_connection().await.unwrap();
            acquire(&mut control).await.unwrap();
            let binding = Binding {
                operation: [1; 16],
                route: [2; 32],
                target_format: [3; 32],
                registered_catalogue: metadata.catalogue_digest,
            };
            // Persist the real planned journal and one effective DDL, then lose
            // the owning connection, as a crash after a subset of CREATEs does.
            let row = Upgrade {
                version: 1,
                binding: binding.clone(),
                source: [4; 16],
                target: [5; 16],
                native_identity: metadata.native_identity.clone(),
                physical: 3,
                catalogue: metadata.catalogue.clone(),
                guards: 0,
                activation: None,
                completed: None,
            };
            let raw = encode(&row).unwrap();
            control
                .query_drop(format!(
                    "{CONTROL_DDL} AS SELECT X'01' AS k,X'{}' AS payload",
                    hex(&raw)
                ))
                .await
                .unwrap();
            let table = &row.catalogue[0].name;
            control
                .query_drop(format!(
                    "CREATE TRIGGER {} BEFORE INSERT ON {} FOR EACH ROW {BODY}",
                    quote(&trigger(table, "INSERT")).unwrap(),
                    quote(table).unwrap()
                ))
                .await
                .unwrap();
            drop(control);
            let mut control = Conn::open_tcp(&opts, init).await.unwrap();
            let resumed = begin(&mut control, &metadata, binding.clone())
                .await
                .unwrap();
            assert_eq!(resumed.source, row.source);
            assert_eq!(resumed.target, row.target);
            assert_eq!(resumed.guards as usize, metadata.catalogue.len() * 3);
            check(&mut control, &resumed).await.unwrap();
            // Exact released source DDL may be harmlessly retried; the source
            // startup's mandatory marker/sequence writes must then fail.
            let mut old = Conn::open_tcp(&opts, init).await.unwrap();
            for ddl in schemas::V1_0_6_SCHEMA {
                if let Err(error) = old.query_drop(*ddl).await {
                    assert!(matches!(error,WireError::MySqlError(ref e) if e.code==1061));
                }
            }
            let conn = Conn::open_tcp(&opts, init).await.unwrap();
            let mut frozen = super::super::Snapshot::freeze_connection(conn, &resumed)
                .await
                .unwrap();
            assert_eq!(frozen.metadata().snapshot, row.source);
            let table = frozen
                .metadata()
                .catalogue
                .iter()
                .position(|t| t.name == "api_keys")
                .unwrap();
            let page = frozen
                .page::<Own>(&frozen.first(table).unwrap(), 2, 16384)
                .await
                .unwrap();
            assert_eq!(page.rows.len(), 2);
            let mut old = Conn::open_tcp(&opts, init).await.unwrap();
            for sql in [
                "INSERT INTO store_meta(k,v) VALUES('schema_version','3') ON DUPLICATE KEY UPDATE v='3'",
                "INSERT INTO store_sequence(id,revision) VALUES(1,0) ON DUPLICATE KEY UPDATE id=id",
                "UPDATE api_keys SET name=name WHERE name='fixture-grouped'",
                "DELETE FROM api_keys WHERE name='fixture-ungrouped'",
                "INSERT INTO store_meta(k,v) VALUES('old-reconnect','unsafe')",
            ] {
                let error=old.query_drop(sql).await.unwrap_err();
                assert!(matches!(error,WireError::MySqlError(ref e) if e.code==1644),"{error:?}");
            }
            drop(old);
            frozen.close().await.unwrap();
            check(&mut control, &resumed).await.unwrap();
            let version: Option<Vec<u8>> = control
                .query_first("SELECT v FROM store_meta WHERE k='schema_version'")
                .await
                .unwrap();
            assert_eq!(version.as_deref(), Some(b"3".as_slice()));
            let mut mismatch = binding;
            mismatch.route[0] ^= 1;
            assert_eq!(
                begin(&mut control, &metadata, mismatch).await.unwrap_err(),
                Error::SourceChanged
            );
        });
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(())
        ));
    }

    #[test]
    #[ignore = "requires dedicated frozen released DB in BUSBAR_MYSQL_DRAIN_URL"]
    fn native_prepared_xa_drains_before_snapshot_and_cached_write_refuses() {
        use mysql::prelude::Queryable;
        let url = std::env::var("BUSBAR_MYSQL_DRAIN_URL").unwrap();
        let mut old = mysql::Conn::new(mysql::Opts::from_url(&url).unwrap()).unwrap();
        let cached = old
            .prep("UPDATE api_keys SET name=name WHERE name=?")
            .unwrap();
        old.exec_drop(&cached, ("fixture-grouped",)).unwrap();
        let mut future = std::pin::pin!(async {
            let opts = Arc::new(Opts::from_url(&url).unwrap());
            let init = &["SET SESSION character_set_results = binary"];
            let snapshot =
                super::super::Snapshot::on_connection(Conn::open_tcp(&opts, init).await.unwrap())
                    .await
                    .unwrap();
            let metadata = snapshot.metadata().clone();
            let mut control = snapshot.release_connection().await.unwrap();
            old.query_drop("XA START 'busbar-native-source-cut'")
                .unwrap();
            old.query_drop(
                "UPDATE api_keys SET name='fixture-grouped-precut' WHERE name='fixture-grouped'",
            )
            .unwrap();
            old.query_drop("XA END 'busbar-native-source-cut'").unwrap();
            old.query_drop("XA PREPARE 'busbar-native-source-cut'")
                .unwrap();
            let binding = Binding {
                operation: [11; 16],
                route: [12; 32],
                target_format: [13; 32],
                registered_catalogue: metadata.catalogue_digest,
            };
            assert_eq!(
                begin(&mut control, &metadata, binding.clone())
                    .await
                    .unwrap_err(),
                Error::Busy
            );
            // Only this isolated fixture's known transaction is resolved by the
            // test. Production waits/refuses; it never commits someone else's XA.
            old.query_drop("XA COMMIT 'busbar-native-source-cut'")
                .unwrap();
            let row = resume(&mut control, &binding).await.unwrap();
            let source = Conn::open_tcp(&opts, init).await.unwrap();
            let frozen = super::super::Snapshot::freeze_connection(source, &row)
                .await
                .unwrap();
            let mut frozen = frozen;
            let visible: Option<Vec<u8>> = frozen
                .conn
                .query_first("SELECT name FROM api_keys WHERE name='fixture-grouped-precut'")
                .await
                .unwrap();
            assert_eq!(
                visible.as_deref(),
                Some(b"fixture-grouped-precut".as_slice())
            );
            let error = old
                .exec_drop(&cached, ("fixture-grouped-precut",))
                .unwrap_err();
            assert!(matches!(error,mysql::Error::MySqlError(ref e)if e.code==1644));
            let mut reconnected = mysql::Conn::new(mysql::Opts::from_url(&url).unwrap()).unwrap();
            let error=reconnected.query_drop("INSERT INTO store_meta(k,v) VALUES('schema_version','3') ON DUPLICATE KEY UPDATE v='3'").unwrap_err();
            assert!(matches!(error,mysql::Error::MySqlError(ref e)if e.code==1644));
            check(&mut control, &row).await.unwrap();
            frozen.close().await.unwrap();
        });
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(())
        ));
    }
}
