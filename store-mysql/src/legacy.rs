// SPDX-License-Identifier: Apache-2.0
//! Explicit, read-only historical import. Never runs ordinary store admission or DDL.
//!
//! The coordinator must establish the external writer/DDL fence before opening and
//! match the returned catalogue to its registered historical schema edge. A cursor
//! belongs to this live snapshot only; reconnecting requires a new import attempt.
#[cfg(test)]
use std::sync::Arc;

use busbar_contract::persistence::legacy_row::{self, Cell};
use busbar_contract::redacted::OwnerSeal;
use busbar_contract::Secret;
use mysql_common::constants::ColumnType;
use mysql_common::params;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[cfg(test)]
use crate::mysqlwire::Opts;
use crate::mysqlwire::{Conn, Row, Value};

pub mod lifecycle;

const MAX_TABLES: usize = 32;
const MAX_COLUMNS: usize = 64;
pub(crate) const MAX_ROWS: usize = 256;
const TABLES: &[&str] = &[
    "api_keys",
    "audit_log",
    "credentials",
    "denylist",
    "plane_records",
    "plane_tokens",
    "store_meta",
    "store_ops",
    "store_records",
    "store_sequence",
    "usage_metering",
    "usage_metering_units",
    "usage_window_units",
    "usage_windows",
];

/// Content-free errors: server messages and native row values never escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Native,
    UnknownFormat,
    Damaged,
    Budget,
    Cursor,
}

/// Exact native column declarations, in physical ordinal order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Column {
    pub name: String,
    pub native_type: String,
    pub nullable: bool,
    pub charset: Option<String>,
    pub collation: Option<String>,
    pub primary_ordinal: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    /// Digest of the exact native SHOW CREATE TABLE result, including constraints.
    pub definition_digest: [u8; 32],
    /// Exact native structural definition, admitted by the registered catalogue digest.
    pub native_definition: String,
}

/// Source locator digest and exact physical format facts. No business decoding.
#[derive(Debug, Clone)]
pub struct Metadata {
    pub _source: [u8; 32],
    /// Stable native server identity and exact database name; no guessed fallback.
    pub native_identity: Vec<u8>,
    pub snapshot: [u8; 16],
    pub catalogue_digest: [u8; 32],
    pub schema_version: u32,
    pub _quantity_format: Option<String>,
    pub catalogue: Vec<Table>,
}

/// Opaque bounded offset into a primary-key ordered, immutable snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub(crate) snapshot: [u8; 16],
    pub(crate) table: usize,
    pub(crate) offset: u64,
}

/// Durable position; the coordinator separately verifies unchanged source content
/// and fencing before resuming it in a newly opened snapshot.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub source: [u8; 32],
    pub catalogue: [u8; 32],
    pub schema_version: u32,
    pub table: usize,
    pub offset: u64,
}

pub struct Page<O: OwnerSeal> {
    pub rows: Vec<Secret<Vec<u8>, O>>,
    pub next: Option<Cursor>,
}

/// Owns one dedicated connection; dropping it discards the wire and transaction.
/// A failed page poisons the snapshot so a partially consumed import cannot proceed.
pub struct Snapshot {
    conn: Conn,
    metadata: Metadata,
    poisoned: bool,
    admitted: bool,
}

impl Snapshot {
    pub(crate) async fn on_connection(conn: Conn) -> Result<Self, Error> {
        Self::on_connection_inner(conn, None).await
    }

    async fn on_connection_inner(
        mut conn: Conn,
        upgrade: Option<&lifecycle::Upgrade>,
    ) -> Result<Self, Error> {
        conn.query_drop("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .await
            .map_err(|_| Error::Native)?;
        conn.query_drop("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            .await
            .map_err(|_| Error::Native)?;
        let catalogue = if let Some(upgrade) = upgrade {
            lifecycle::verify_snapshot(&mut conn, upgrade)
                .await
                .map_err(|_| Error::UnknownFormat)?;
            catalogue_inner(&mut conn, true).await?
        } else {
            catalogue(&mut conn).await?
        };
        let version: Option<Vec<u8>> = conn
            .query_first("SELECT v FROM store_meta WHERE k='schema_version'")
            .await
            .map_err(|_| Error::Native)?;
        let marker: Option<Vec<u8>> = conn
            .query_first("SELECT v FROM store_meta WHERE k='quantity_format'")
            .await
            .map_err(|_| Error::Native)?;
        let migrating: Option<Vec<u8>> = conn
            .query_first("SELECT v FROM store_meta WHERE k='migrating_to'")
            .await
            .map_err(|_| Error::Native)?;
        let (schema_version, quantity_format) =
            format(version.as_deref(), marker.as_deref(), migrating.is_some())?;
        let locator: Option<(String, u64, String)> = conn
            .query_first("SELECT @@hostname,@@port,DATABASE()")
            .await
            .map_err(|_| Error::Native)?;
        let (hostname, port, database) = locator.ok_or(Error::Damaged)?;
        let mut hash = Sha256::new();
        for bytes in [
            hostname.as_bytes(),
            &port.to_le_bytes(),
            database.as_bytes(),
        ] {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        let native_identity = native_identity(&mut conn).await?;
        let mut snapshot = [0; 16];
        getrandom::fill(&mut snapshot).map_err(|_| Error::Native)?;
        Ok(Self {
            conn,
            metadata: Metadata {
                _source: hash.finalize().into(),
                native_identity,
                snapshot,
                schema_version,
                _quantity_format: quantity_format,
                catalogue_digest: catalogue_digest(&catalogue),
                catalogue,
            },
            poisoned: false,
            admitted: false,
        })
    }

    /// Require the coordinator's registered native catalogue profile before reading
    /// payloads. The digest must come from a trusted migration edge, not a plan's
    /// unverified claim about its own source.
    pub fn admit_catalogue(&mut self, registered: [u8; 32]) -> Result<(), Error> {
        if self.poisoned || registered != self.metadata.catalogue_digest {
            self.poisoned = true;
            return Err(Error::UnknownFormat);
        }
        self.admitted = true;
        Ok(())
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    #[cfg(test)]
    pub fn checkpoint(&self, cursor: &Cursor) -> Result<Checkpoint, Error> {
        if !self.admitted
            || self.poisoned
            || cursor.snapshot != self.metadata.snapshot
            || cursor.table >= self.metadata.catalogue.len()
        {
            return Err(Error::Cursor);
        }
        Ok(Checkpoint {
            source: self.metadata._source,
            catalogue: self.metadata.catalogue_digest,
            schema_version: self.metadata.schema_version,
            table: cursor.table,
            offset: cursor.offset,
        })
    }

    /// Restore an explicit durable checkpoint only after external unchanged-source
    /// verification. A locator/catalogue match alone cannot prove content identity.
    #[cfg(test)]
    pub fn resume(&self, checkpoint: &Checkpoint) -> Result<Cursor, Error> {
        if !self.admitted
            || self.poisoned
            || checkpoint.source != self.metadata._source
            || checkpoint.catalogue != self.metadata.catalogue_digest
            || checkpoint.schema_version != self.metadata.schema_version
            || checkpoint.table >= self.metadata.catalogue.len()
        {
            return Err(Error::Cursor);
        }
        Ok(Cursor {
            snapshot: self.metadata.snapshot,
            table: checkpoint.table,
            offset: checkpoint.offset,
        })
    }

    pub fn first(&self, table: usize) -> Result<Cursor, Error> {
        if self.poisoned || table >= self.metadata.catalogue.len() {
            return Err(Error::Cursor);
        }
        Ok(Cursor {
            snapshot: self.metadata.snapshot,
            table,
            offset: 0,
        })
    }

    /// Read at most `rows` rows and `bytes` newly encoded bytes, in primary-key order.
    /// The native protocol separately caps an entire result at 256 MiB. No page
    /// advances after a malformed cell or budget failure; reopen for a fresh attempt.
    pub async fn page<O: OwnerSeal>(
        &mut self,
        cursor: &Cursor,
        rows: usize,
        bytes: usize,
    ) -> Result<Page<O>, Error> {
        self.page_inner(cursor, rows, bytes, None).await
    }

    pub(crate) async fn exact<O: OwnerSeal>(
        &mut self,
        table: usize,
        key: &[u8],
        bytes: usize,
    ) -> Result<Page<O>, Error> {
        if key.len() > bytes {
            return Err(Error::Budget);
        }
        let cursor = self.first(table)?;
        let mut page = self.page_inner(&cursor, 1, bytes, Some(key)).await?;
        page.next = None;
        Ok(page)
    }

    async fn page_inner<O: OwnerSeal>(
        &mut self,
        cursor: &Cursor,
        rows: usize,
        bytes: usize,
        key: Option<&[u8]>,
    ) -> Result<Page<O>, Error> {
        if !self.admitted
            || self.poisoned
            || cursor.snapshot != self.metadata.snapshot
            || cursor.table >= self.metadata.catalogue.len()
        {
            return Err(Error::Cursor);
        }
        if rows == 0 || rows > MAX_ROWS || bytes == 0 {
            return Err(Error::Budget);
        }
        self.poisoned = true;
        let table = &self.metadata.catalogue[cursor.table];
        let mut primary: Vec<_> = table
            .columns
            .iter()
            .filter_map(|c| c.primary_ordinal.map(|n| (n, c)))
            .collect();
        primary.sort_by_key(|(n, _)| *n);
        let order = primary
            .iter()
            .map(|(_, c)| quote(&c.name))
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        let sql = format!(
            "SELECT * FROM {} ORDER BY {} LIMIT {} OFFSET {}",
            quote(&table.name)?,
            order,
            rows,
            cursor.offset
        );
        let size = size_expression(table)?;
        let native: Vec<Row> = if let Some(key) = key {
            let key = legacy_row::Row::decode(key).map_err(|_| Error::Cursor)?;
            if key.cells().len() != primary.len() {
                return Err(Error::Cursor);
            }
            let supported = |value: Cell<'_>, column: &Column| match value {
                Cell::Integer(_) => ["tinyint", "smallint", "mediumint", "int", "bigint"]
                    .iter()
                    .any(|kind| column.native_type.starts_with(kind)),
                Cell::Text(_) => column.charset.is_some(),
                Cell::Blob(_) => column.charset.is_none(),
                _ => false,
            };
            if !key
                .cells()
                .zip(&primary)
                .all(|(value, (_, column))| supported(value, column))
            {
                return Err(Error::Cursor);
            }
            let predicate = primary
                .iter()
                .map(|(_, column)| quote(&column.name).map(|name| format!("{name}=?")))
                .collect::<Result<Vec<_>, _>>()?
                .join(" AND ");
            let sql = format!(
                "SELECT * FROM {} WHERE {predicate} LIMIT 1",
                quote(&table.name)?
            );
            // Validate every key cell before copying any secret parameter. The
            // transport immediately adopts the complete parameter vector into
            // its wiping SecretParams before its first asynchronous wait.
            let values = || {
                key.cells()
                    .zip(&primary)
                    .map(|(value, (_, column))| match value {
                        Cell::Integer(value) if column.native_type.ends_with(" unsigned") => {
                            Value::UInt(u64::from_le_bytes(value.to_le_bytes()))
                        }
                        Cell::Integer(value) => Value::Int(value),
                        Cell::Text(value) | Cell::Blob(value) => Value::Bytes(value.to_vec()),
                        _ => unreachable!("validated immutable native key cells"),
                    })
                    .collect::<Vec<_>>()
            };
            let sizes: Vec<u64> = self
                .conn
                .exec(
                    format!(
                        "SELECT {size} FROM {} WHERE {predicate} LIMIT 1",
                        quote(&table.name)?
                    ),
                    mysql_common::params::Params::Positional(values()),
                )
                .await
                .map_err(|_| Error::Native)?;
            check_lengths(&sizes, bytes)?;
            self.conn
                .exec(sql, mysql_common::params::Params::Positional(values()))
                .await
                .map_err(|_| Error::Native)?
        } else {
            let sizes: Vec<u64> = self
                .conn
                .query(format!(
                    "SELECT {size} FROM {} ORDER BY {order} LIMIT {rows} OFFSET {}",
                    quote(&table.name)?,
                    cursor.offset
                ))
                .await
                .map_err(|_| Error::Native)?;
            check_lengths(&sizes, bytes)?;
            self.conn.query(sql).await.map_err(|_| Error::Native)?
        };
        let mut native = WipingRows(native);
        let mut encoded = Vec::new();
        let mut remaining = bytes;
        for row in &mut native.0 {
            if row.len() != table.columns.len() {
                return Err(Error::Damaged);
            }
            let cells = row
                .columns_ref()
                .iter()
                .enumerate()
                .map(|(i, column)| {
                    let value = row.as_ref(i).ok_or(Error::Damaged)?;
                    cell(
                        value,
                        column.column_type(),
                        column.character_set(),
                        &table.columns[i],
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let value = legacy_row::encode::<O>(&cells, remaining).map_err(|_| Error::Budget)?;
            // Framing length can be computed without exposing the protected owner.
            let len = cells
                .iter()
                .try_fold(12usize, |n, c| {
                    n.checked_add(match c {
                        Cell::Null => 1,
                        Cell::Integer(_) | Cell::RealBits(_) => 9,
                        Cell::Text(b) | Cell::Blob(b) => 9 + b.len(),
                    })
                })
                .ok_or(Error::Budget)?;
            remaining -= len;
            encoded.push(value);
        }
        let count = encoded.len();
        let next = if count == rows {
            Some(Cursor {
                snapshot: cursor.snapshot,
                table: cursor.table,
                offset: cursor
                    .offset
                    .checked_add(count as u64)
                    .ok_or(Error::Cursor)?,
            })
        } else {
            None
        };
        self.poisoned = false;
        Ok(Page {
            rows: encoded,
            next,
        })
    }

    /// Explicitly finish without committing any transaction.
    #[cfg(test)]
    pub async fn close(mut self) -> Result<(), Error> {
        self.conn
            .query_drop("ROLLBACK")
            .await
            .map_err(|_| Error::Native)
    }

    pub(crate) async fn release_connection(mut self) -> Result<Conn, Error> {
        self.conn
            .query_drop("ROLLBACK")
            .await
            .map_err(|_| Error::Native)?;
        Ok(self.conn)
    }

    pub(crate) async fn freeze_connection(
        conn: Conn,
        upgrade: &lifecycle::Upgrade,
    ) -> Result<Self, Error> {
        let mut snapshot = Self::on_connection_inner(conn, Some(upgrade)).await?;
        snapshot.metadata.snapshot = upgrade.source;
        snapshot.admit_catalogue(upgrade.binding.registered_catalogue)?;
        Ok(snapshot)
    }
}

fn size_expression(table: &Table) -> Result<String, Error> {
    let mut terms = vec!["12".to_owned()];
    for column in &table.columns {
        let name = quote(&column.name)?;
        let integer = ["tinyint", "smallint", "mediumint", "int", "bigint"]
            .iter()
            .any(|kind| column.native_type.starts_with(kind));
        let bytes = [
            "decimal",
            "numeric",
            "json",
            "varchar",
            "char",
            "varbinary",
            "binary",
            "tinytext",
            "text",
            "mediumtext",
            "longtext",
            "tinyblob",
            "blob",
            "mediumblob",
            "longblob",
        ]
        .iter()
        .any(|kind| column.native_type.starts_with(kind));
        let encoded = if integer {
            "9".to_owned()
        } else if bytes {
            format!("9+OCTET_LENGTH({name})")
        } else {
            return Err(Error::UnknownFormat);
        };
        terms.push(format!(
            "CASE WHEN {name} IS NULL THEN 1 ELSE {encoded} END"
        ));
    }
    Ok(terms.join("+"))
}
fn check_lengths(lengths: &[u64], budget: usize) -> Result<(), Error> {
    let total = lengths
        .iter()
        .try_fold(0u64, |sum, len| sum.checked_add(*len))
        .ok_or(Error::Budget)?;
    if total > budget as u64 {
        return Err(Error::Budget);
    }
    Ok(())
}

fn format(
    version: Option<&[u8]>,
    marker: Option<&[u8]>,
    migrating: bool,
) -> Result<(u32, Option<String>), Error> {
    if migrating {
        return Err(Error::UnknownFormat);
    }
    let version = match version {
        Some(b"3") => 3,
        Some(b"4") => 4,
        Some(b"5") => 5,
        Some(b"7") => 7,
        _ => return Err(Error::UnknownFormat),
    };
    // Schema 6 is an explicitly unsupported interrupted development format.
    match (version, marker) {
        (7, Some(b"i128-scale6-v1")) => Ok((version, Some("i128-scale6-v1".into()))),
        (3..=5, None) => Ok((version, None)),
        _ => Err(Error::UnknownFormat),
    }
}

pub(crate) fn quote(name: &str) -> Result<String, Error> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(Error::UnknownFormat);
    }
    Ok(format!("`{name}`"))
}

async fn catalogue(conn: &mut Conn) -> Result<Vec<Table>, Error> {
    catalogue_inner(conn, false).await
}

// Only lifecycle::check may authorize the exact native upgrade delta.
async fn catalogue_inner(conn: &mut Conn, guarded: bool) -> Result<Vec<Table>, Error> {
    let tables: Vec<(String, String, Option<String>)> = conn.query(
        "SELECT TABLE_NAME,TABLE_TYPE,ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME LIMIT 33"
    ).await.map_err(|_| Error::Native)?;
    if tables.is_empty() || tables.len() > MAX_TABLES {
        return Err(Error::UnknownFormat);
    }
    let triggers: Option<u64> = conn
        .query_first(
            "SELECT COUNT(*) FROM information_schema.triggers WHERE TRIGGER_SCHEMA=DATABASE()",
        )
        .await
        .map_err(|_| Error::Native)?;
    if !guarded && triggers != Some(0) {
        return Err(Error::UnknownFormat);
    }
    let mut result = Vec::new();
    for (name, kind, engine) in tables {
        if guarded && lifecycle::RESERVED_TABLES.contains(&name.as_str()) {
            if kind != "BASE TABLE" || engine.as_deref() != Some("InnoDB") {
                return Err(Error::UnknownFormat);
            }
            continue;
        }
        if !TABLES.contains(&name.as_str())
            || kind != "BASE TABLE"
            || engine.as_deref() != Some("InnoDB")
        {
            return Err(Error::UnknownFormat);
        }
        // Touch each native table now, holding its metadata lock for this entire
        // transaction; the external fence remains mandatory for concurrent DDL.
        conn.query_drop(format!("SELECT * FROM {} LIMIT 0", quote(&name)?))
            .await
            .map_err(|_| Error::Native)?;
        type NativeColumn = (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<u64>,
        );
        let columns: Vec<NativeColumn> = conn.exec(
            "SELECT c.COLUMN_NAME,c.COLUMN_TYPE,c.IS_NULLABLE,c.CHARACTER_SET_NAME,c.COLLATION_NAME,s.SEQ_IN_INDEX FROM information_schema.columns c LEFT JOIN information_schema.statistics s ON s.TABLE_SCHEMA=c.TABLE_SCHEMA AND s.TABLE_NAME=c.TABLE_NAME AND s.COLUMN_NAME=c.COLUMN_NAME AND s.INDEX_NAME='PRIMARY' WHERE c.TABLE_SCHEMA=DATABASE() AND c.TABLE_NAME=:table ORDER BY c.ORDINAL_POSITION LIMIT 65",
            params! { "table" => &name }
        ).await.map_err(|_| Error::Native)?;
        if columns.is_empty() || columns.len() > MAX_COLUMNS {
            return Err(Error::UnknownFormat);
        }
        let columns = columns
            .into_iter()
            .map(
                |(name, native_type, nullable, charset, collation, primary_ordinal)| {
                    quote(&name)?;
                    if !matches!(nullable.as_str(), "YES" | "NO") {
                        return Err(Error::Damaged);
                    }
                    Ok(Column {
                        name,
                        native_type,
                        nullable: nullable == "YES",
                        charset,
                        collation,
                        primary_ordinal,
                    })
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        if !columns.iter().any(|c| c.primary_ordinal.is_some()) {
            return Err(Error::UnknownFormat);
        }
        let definition: Option<(String, String)> = conn
            .query_first(format!("SHOW CREATE TABLE {}", quote(&name)?))
            .await
            .map_err(|_| Error::Native)?;
        let (returned, mut ddl) = definition.ok_or(Error::Damaged)?;
        if returned != name {
            ddl.zeroize();
            return Err(Error::Damaged);
        }
        let definition_digest = Sha256::digest(ddl.as_bytes()).into();
        let native_definition = std::mem::take(&mut ddl);
        result.push(Table {
            name,
            columns,
            definition_digest,
            native_definition,
        });
    }
    if !result.iter().any(|t| t.name == "store_meta") {
        return Err(Error::UnknownFormat);
    }
    // Sort by Rust byte order; SQL ORDER BY TABLE_NAME uses the server's
    // collation which may differ (e.g. utf8_general_ci sorts '_' after letters).
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

fn cell<'a>(
    value: &'a Value,
    kind: ColumnType,
    _charset: u16,
    column: &Column,
) -> Result<Cell<'a>, Error> {
    use ColumnType::*;
    if matches!(value, Value::NULL) {
        return if column.nullable {
            Ok(Cell::Null)
        } else {
            Err(Error::Damaged)
        };
    }
    match (kind, value) {
        (
            MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_LONG | MYSQL_TYPE_LONGLONG
            | MYSQL_TYPE_INT24,
            Value::Int(v),
        ) => Ok(Cell::Integer(*v)),
        (
            MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_LONG | MYSQL_TYPE_LONGLONG
            | MYSQL_TYPE_INT24,
            Value::UInt(v),
        ) => Ok(Cell::Integer(i64::from_le_bytes(v.to_le_bytes()))),
        // Text protocol returns numeric bytes. Preserve unsigned i64 bit semantics.
        (
            MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_LONG | MYSQL_TYPE_LONGLONG
            | MYSQL_TYPE_INT24,
            Value::Bytes(v),
        ) => {
            let text = std::str::from_utf8(v).map_err(|_| Error::Damaged)?;
            let value = if column.native_type.ends_with(" unsigned") {
                i64::from_le_bytes(
                    text.parse::<u64>()
                        .map_err(|_| Error::Damaged)?
                        .to_le_bytes(),
                )
            } else {
                text.parse::<i64>().map_err(|_| Error::Damaged)?
            };
            Ok(Cell::Integer(value))
        }
        (MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL, Value::Bytes(v)) => {
            if !decimal(v) {
                return Err(Error::Damaged);
            }
            Ok(Cell::Text(v))
        }
        (MYSQL_TYPE_JSON, Value::Bytes(v)) => Ok(Cell::Text(v)),
        (
            MYSQL_TYPE_STRING
            | MYSQL_TYPE_VAR_STRING
            | MYSQL_TYPE_VARCHAR
            | MYSQL_TYPE_TINY_BLOB
            | MYSQL_TYPE_MEDIUM_BLOB
            | MYSQL_TYPE_LONG_BLOB
            | MYSQL_TYPE_BLOB,
            Value::Bytes(v),
        ) => Ok(if column.charset.is_none() {
            Cell::Blob(v)
        } else {
            Cell::Text(v)
        }),
        _ => Err(Error::UnknownFormat),
    }
}

struct WipingRows(Vec<Row>);
impl Drop for WipingRows {
    fn drop(&mut self) {
        for row in &mut self.0 {
            for i in 0..row.len() {
                if let Some(Value::Bytes(mut bytes)) = row.take::<Value, _>(i) {
                    bytes.zeroize();
                }
            }
        }
    }
}

/// Canonical server-native identity used by archive export and live fence proof.
/// MySQL's UUID and MariaDB's native UID are intentionally different identity kinds.
pub(crate) async fn native_identity(conn: &mut Conn) -> Result<Vec<u8>, Error> {
    let rows: Vec<(String, Option<String>)> =
        match conn.query("SELECT @@GLOBAL.server_uuid,DATABASE()").await {
            Ok(rows) => rows,
            Err(error) if crate::mysqlwire::batching_refused(&error) => {
                return native_identity_compat(conn).await;
            }
            Err(_) => return Err(Error::Native),
        };
    match rows.as_slice() {
        [(instance, Some(database))] => identity_bytes("mysql-server-uuid", instance, database),
        [(_, None)] => Err(Error::UnknownFormat),
        _ => Err(Error::UnknownFormat),
    }
}

/// Preserve MariaDB native UID and managed-server SHOW compatibility exactly.
async fn native_identity_compat(conn: &mut Conn) -> Result<Vec<u8>, Error> {
    let uuid: Vec<(String, String)> = conn
        .query("SHOW GLOBAL VARIABLES LIKE 'server_uuid'")
        .await
        .map_err(|_| Error::Native)?;
    let (kind, instance) = match uuid.as_slice() {
        [(name, value)] if name == "server_uuid" && !value.is_empty() && value.len() <= 256 => {
            ("mysql-server-uuid", value.clone())
        }
        [] => {
            let uid: Vec<(String, String)> = conn
                .query("SHOW GLOBAL VARIABLES LIKE 'server_uid'")
                .await
                .map_err(|_| Error::Native)?;
            match uid.as_slice() {
                [(name, value)]
                    if name == "server_uid" && !value.is_empty() && value.len() <= 256 =>
                {
                    ("mariadb-server-uid", value.clone())
                }
                _ => return Err(Error::UnknownFormat),
            }
        }
        _ => return Err(Error::UnknownFormat),
    };
    let database: Option<String> = conn
        .query_first("SELECT DATABASE()")
        .await
        .map_err(|_| Error::Native)?;
    let database = database
        .filter(|name| !name.is_empty() && name.len() <= 256)
        .ok_or(Error::UnknownFormat)?;
    identity_bytes(kind, &instance, &database)
}

fn identity_bytes(kind: &str, instance: &str, database: &str) -> Result<Vec<u8>, Error> {
    if instance.is_empty() || instance.len() > 256 || database.is_empty() || database.len() > 256 {
        return Err(Error::UnknownFormat);
    }
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        format: &'static str,
        kind: &'a str,
        instance: &'a str,
        database: &'a str,
    }
    let bytes = serde_json::to_vec(&Identity {
        format: "mysql-native-identity-v1",
        kind,
        instance,
        database,
    })
    .map_err(|_| Error::Damaged)?;
    if bytes.len() > 1024 {
        return Err(Error::Budget);
    }
    Ok(bytes)
}

fn decimal(bytes: &[u8]) -> bool {
    let unsigned = bytes.strip_prefix(b"-").unwrap_or(bytes);
    let mut parts = unsigned.split(|b| *b == b'.');
    let whole = parts.next().unwrap_or_default();
    !whole.is_empty()
        && whole.iter().all(u8::is_ascii_digit)
        && parts
            .next()
            .is_none_or(|fraction| !fraction.is_empty() && fraction.iter().all(u8::is_ascii_digit))
        && parts.next().is_none()
}

pub(crate) fn catalogue_digest(tables: &[Table]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"busbar.mysql.legacy.catalogue.v1");
    for table in tables {
        hash.update(table.definition_digest);
        for bytes in
            std::iter::once(table.name.as_bytes()).chain(table.columns.iter().flat_map(|c| {
                [
                    c.name.as_bytes(),
                    c.native_type.as_bytes(),
                    if c.nullable { b"YES" } else { b"NO" },
                    c.charset.as_deref().unwrap_or("").as_bytes(),
                    c.collation.as_deref().unwrap_or("").as_bytes(),
                ]
            }))
        {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        for column in &table.columns {
            hash.update(column.primary_ordinal.unwrap_or(0).to_le_bytes());
        }
        hash.update((table.columns.len() as u64).to_le_bytes());
    }
    hash.update((tables.len() as u64).to_le_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    busbar_contract::own_seal!(Own);
    fn column(ty: &str) -> Column {
        Column {
            name: "v".into(),
            native_type: ty.into(),
            nullable: false,
            charset: None,
            collation: None,
            primary_ordinal: Some(1),
        }
    }

    #[test]
    fn refuses_unknown_partial_and_unmarked_formats() {
        for version in [b"0".as_slice(), b"2", b"6", b"8", b"03", b"7 ", b""] {
            assert_eq!(
                format(Some(version), None, false),
                Err(Error::UnknownFormat)
            );
        }
        for version in [b"3".as_slice(), b"4", b"5"] {
            assert!(format(Some(version), None, false).is_ok());
            assert!(format(Some(version), Some(b"i128-scale6-v1"), false).is_err());
        }
        assert!(format(Some(b"7"), None, false).is_err());
        assert!(format(Some(b"7"), Some(b"i128-scale6-v1"), false).is_ok());
        assert!(format(Some(b"7"), Some(b"i128-scale6-v1"), true).is_err());
    }

    #[test]
    fn physical_cells_keep_unsigned_bits_decimal_bytes_and_empty_distinctions() {
        use ColumnType::*;
        let integer = column("bigint unsigned");
        assert_eq!(
            cell(&Value::UInt(u64::MAX), MYSQL_TYPE_LONGLONG, 63, &integer),
            Ok(Cell::Integer(-1))
        );
        assert_eq!(
            cell(
                &Value::Bytes(b"18446744073709551615".to_vec()),
                MYSQL_TYPE_LONGLONG,
                63,
                &integer
            ),
            Ok(Cell::Integer(-1))
        );
        assert!(cell(
            &Value::Bytes(b"18446744073709551616".to_vec()),
            MYSQL_TYPE_LONGLONG,
            63,
            &integer
        )
        .is_err());
        let mut text_column = column("text");
        text_column.charset = Some("utf8mb4".into());
        let native = [
            Value::Bytes(b"-00012.5000".to_vec()),
            Value::Bytes(vec![]),
            Value::Bytes(vec![]),
        ];
        let cells = [
            cell(
                &native[0],
                MYSQL_TYPE_NEWDECIMAL,
                63,
                &column("decimal(39,0)"),
            )
            .unwrap(),
            cell(&native[1], MYSQL_TYPE_BLOB, 63, &column("blob")).unwrap(),
            cell(&native[2], MYSQL_TYPE_BLOB, 45, &text_column).unwrap(),
        ];
        assert_eq!(
            cells,
            [Cell::Text(b"-00012.5000"), Cell::Blob(b""), Cell::Text(b"")]
        );
        let encoded = legacy_row::encode::<Own>(&cells, 1024).unwrap();
        assert_eq!(
            legacy_row::Row::decode(encoded.expose_own(&Own::here()))
                .unwrap()
                .cells()
                .collect::<Vec<_>>(),
            cells
        );
        assert!(cell(&Value::NULL, MYSQL_TYPE_BLOB, 63, &integer).is_err());
        let mut nullable = column("text");
        nullable.nullable = true;
        assert_eq!(
            cell(&Value::NULL, MYSQL_TYPE_BLOB, 45, &nullable),
            Ok(Cell::Null)
        );
        for bad in [b"-".as_slice(), b".", b"1.2.3", b"1-2", b"NaN", b""] {
            assert!(!decimal(bad));
        }
    }

    #[test]
    fn catalogue_digest_binds_native_types_nullability_and_key_order() {
        let mut table = Table {
            name: "store_meta".into(),
            columns: vec![column("bigint")],
            definition_digest: [0; 32],
            native_definition: String::new(),
        };
        let before = catalogue_digest(&[table.clone()]);
        table.columns[0].nullable = true;
        assert_ne!(before, catalogue_digest(&[table.clone()]));
        table.columns[0].nullable = false;
        table.columns[0].primary_ordinal = Some(2);
        assert_ne!(before, catalogue_digest(&[table]));
        assert!(quote("api_keys; DROP TABLE store_meta").is_err());
    }
    #[test]
    #[ignore = "requires the frozen released dump in a dedicated BUSBAR_MYSQL_LEGACY_URL database"]
    fn native_released_snapshot_is_read_only_stable_and_checkpointed() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let url = std::env::var("BUSBAR_MYSQL_LEGACY_URL").expect("dedicated restored fixture URL");
        let mut future = std::pin::pin!(async {
            let opts = Arc::new(Opts::from_url(&url).unwrap());
            let init = &["SET SESSION character_set_results = binary"];
            let conn = Conn::open_tcp(&opts, init).await.unwrap();
            let mut snapshot = Snapshot::on_connection(conn).await.unwrap();
            assert_eq!(snapshot.metadata.schema_version, 3);
            assert_eq!(snapshot.metadata.catalogue.len(), 8);
            let table = snapshot
                .metadata
                .catalogue
                .iter()
                .position(|t| t.name == "api_keys")
                .unwrap();
            let cursor = snapshot.first(table).unwrap();
            assert!(matches!(
                snapshot.page::<Own>(&cursor, 1, 4096).await,
                Err(Error::Cursor)
            ));
            snapshot
                .admit_catalogue(snapshot.metadata.catalogue_digest)
                .unwrap();
            let page = snapshot.page::<Own>(&cursor, 1, 4096).await.unwrap();
            let first = legacy_row::Row::decode(page.rows[0].expose_own(&Own::here()))
                .unwrap()
                .cells()
                .collect::<Vec<_>>();
            assert_eq!(first[1], Cell::Text(b"fixture-grouped"));
            assert_eq!(first[3], Cell::Null);
            assert_eq!(first[4], Cell::Text(b"{}"));
            let cursor = page.next.unwrap();
            let checkpoint = snapshot.checkpoint(&cursor).unwrap();
            let refusal = snapshot
                .conn
                .query_drop("UPDATE store_meta SET v=v WHERE k='schema_version'")
                .await
                .unwrap_err();
            assert!(
                matches!(refusal, crate::mysqlwire::Error::MySqlError(ref error) if error.code == 1792)
            );
            let mut writer = Conn::open_tcp(&opts, init).await.unwrap();
            writer
                .query_drop(
                    "UPDATE api_keys SET name='snapshot-new-value' WHERE name='fixture-ungrouped'",
                )
                .await
                .unwrap();
            let visible: Option<Vec<u8>> = writer
                .query_first("SELECT name FROM api_keys WHERE name='snapshot-new-value'")
                .await
                .unwrap();
            assert_eq!(visible.as_deref(), Some(b"snapshot-new-value".as_slice()));
            let page = snapshot.page::<Own>(&cursor, 1, 4096).await.unwrap();
            let second = legacy_row::Row::decode(page.rows[0].expose_own(&Own::here()))
                .unwrap()
                .cells()
                .collect::<Vec<_>>();
            assert_eq!(second[1], Cell::Text(b"fixture-ungrouped"));
            assert_eq!(second[2], Cell::Text(b""));
            assert!(snapshot
                .page::<Own>(&page.next.unwrap(), 1, 4096)
                .await
                .unwrap()
                .rows
                .is_empty());
            // Restore only this isolated witness database before a new snapshot.
            writer
                .query_drop(
                    "UPDATE api_keys SET name='fixture-ungrouped' WHERE name='snapshot-new-value'",
                )
                .await
                .unwrap();
            snapshot.close().await.unwrap();
            let conn = Conn::open_tcp(&opts, init).await.unwrap();
            let mut reopened = Snapshot::on_connection(conn).await.unwrap();
            reopened
                .admit_catalogue(reopened.metadata.catalogue_digest)
                .unwrap();
            let resumed = reopened.resume(&checkpoint).unwrap();
            let resumed_page = reopened.page::<Own>(&resumed, 1, 4096).await.unwrap();
            let restored = legacy_row::Row::decode(resumed_page.rows[0].expose_own(&Own::here()))
                .unwrap()
                .cells()
                .collect::<Vec<_>>();
            assert_eq!(restored[1], Cell::Text(b"fixture-ungrouped"));
            let mut wrong = checkpoint.clone();
            wrong.catalogue[0] ^= 1;
            assert!(reopened.resume(&wrong).is_err());
            let version: Option<Vec<u8>> = writer
                .query_first("SELECT v FROM store_meta WHERE k='schema_version'")
                .await
                .unwrap();
            assert_eq!(version.as_deref(), Some(b"3".as_slice()));
            reopened.close().await.unwrap();
        });
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(())
        ));
    }
}
