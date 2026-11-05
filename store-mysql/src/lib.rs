// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MySQL/MariaDB backend for busbar's durable governance store: MySQL 8.0.16+, MariaDB and Aurora MySQL 3 through one common SQL subset.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

use std::sync::{Arc, LazyLock};

use busbar_contract::abi::sdk::store::column::storable_i64;
use busbar_contract::abi::sdk::store::fork;
use busbar_contract::abi::sdk::store::wire::Pool;
use mysql_common::params;
use mysql_common::value::Value;

pub(crate) mod mysqlwire;
use mysqlwire::{Conn, Error, Opts, Params, Row, Transaction};

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStoreError, RecordStoreResult, Retention,
    ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey, UNIT_CACHE_READ, UNIT_CACHE_WRITE,
    UNIT_INPUT, UNIT_OUTPUT,
};
use std::collections::BTreeMap;

type AuditRowTuple = (u64, u64, String, String, String, String, String, String);

fn audit_from_row(
    (seq, ts, action, resource, outcome, principal, prev_hash, hash): AuditRowTuple,
) -> AuditRecord {
    AuditRecord {
        seq,
        ts,
        action,
        resource,
        outcome,
        principal,
        prev_hash,
        hash,
    }
}

/// `(id, parent, ts, terminal, body)` — the stored columns an append's fork check compares.
type PlaneRowTuple = (String, Option<String>, u64, bool, Vec<u8>);

const TICKET_RECORD_KIND: &str = "ticket";

/// The plane-record kind whose retention is TERMINAL-ONLY (see `purge_plane_records_before`), and the child kind that is swept together with it.
const KIND_TASK: &str = "task";
const KIND_TASK_EVENT: &str = "task_event";

/// MySQL's `ER_DUP_ENTRY`: the duplicate-key code the dedupe claim and the write-error mapping both key on.
pub(crate) const ER_DUP_ENTRY: u16 = 1062;

fn store_err<E: std::fmt::Display>(e: E) -> RecordStoreError {
    RecordStoreError(e.to_string())
}

/// The error a refusal returns after its transaction was rolled back. The refusal is the answer; a
/// failed ROLLBACK is appended to it (the connection is discarded and the server rolls the
/// transaction back on disconnect), never allowed to replace it.
fn refusal_after_rollback<E: std::fmt::Display>(
    refusal: RecordStoreError,
    rollback: Result<(), E>,
) -> RecordStoreError {
    match rollback {
        Ok(()) => refusal,
        Err(e) => RecordStoreError(format!("{}; the rollback also failed: {e}", refusal.0)),
    }
}

/// A write's failure for the op named `op`: a duplicate key reads `<op>: duplicate <constraint>` (no value), every other error as [`store_err`] renders it.
fn write_err(op: &str, e: Error) -> RecordStoreError {
    match &e {
        Error::MySqlError(m) if m.code == ER_DUP_ENTRY => {
            RecordStoreError(format!("{op}: {}", m.rendered()))
        }
        _ => store_err(e),
    }
}

/// Why an `op_id` write's effect failed: the text, and the server's error code when the server
/// refused a statement (so the slot can tell a refusal from a failure without matching text).
#[derive(Debug)]
pub(crate) struct ApplyError {
    pub(crate) text: String,
    pub(crate) server_code: Option<u16>,
    /// The store itself judged the write can never apply (nothing was applied): a refusal, not a
    /// failure, though no server code says so.
    pub(crate) refused: bool,
}

impl ApplyError {
    fn text(text: String) -> Self {
        Self {
            text,
            server_code: None,
            refused: false,
        }
    }
}

fn apply_err(e: Error) -> ApplyError {
    let server_code = match &e {
        Error::MySqlError(m) => Some(m.code),
        _ => None,
    };
    ApplyError {
        text: e.to_string(),
        server_code,
        refused: false,
    }
}

/// The schema version this build creates and migrates to. An older released database is v3;
/// v7 stores checked i128 micro-units; v5 already stored micro-units and is never rescaled.
pub const SCHEMA_VERSION: u32 = 7;

const QUANTITY_FORMAT_KEY: &str = "quantity_format";
const QUANTITY_FORMAT: &str = "i128-scale6-v1";
const QUANTITY_MAX: &str = "170141183460469231731687303715884105727";
const WHOLE_QUANTITY_MAX: &str = "170141183460469231731687303715884";
const QUANTITY_TABLES: &[(&str, &[&str])] = &[
    (
        "usage_windows",
        &[
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_write",
        ],
    ),
    ("usage_window_units", &["count"]),
    (
        "usage_metering",
        &[
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_write",
        ],
    ),
    ("usage_metering_units", &["count"]),
];

/// Every key and identity column v11 makes byte-exact, per table, with its v11 definition (v14 subsequently widens the four model columns).
const V11_EXACT_KEY_COLUMNS: &[(&str, &[(&str, &str)])] = &[
    ("store_meta", &[("k", "VARBINARY(764) NOT NULL")]),
    (
        "api_keys",
        &[
            ("id", "VARBINARY(64) NOT NULL"),
            ("key_group", "VARBINARY(128) NOT NULL DEFAULT ''"),
        ],
    ),
    (
        "credentials",
        &[
            ("id", "VARBINARY(64) NOT NULL"),
            ("key_id", "VARBINARY(64) NOT NULL"),
            ("kind", "VARBINARY(128) NOT NULL"),
            ("public_id", "VARBINARY(256) NOT NULL"),
        ],
    ),
    ("denylist", &[("sub", "VARBINARY(64) NOT NULL")]),
    (
        "usage_windows",
        &[
            ("bucket_scope", "VARBINARY(32) NOT NULL"),
            ("bucket_id", "VARBINARY(128) NOT NULL"),
            ("model", "VARBINARY(1024) NOT NULL"),
        ],
    ),
    (
        "usage_metering",
        &[
            ("bucket", "VARBINARY(40) NOT NULL"),
            ("key_id", "VARBINARY(64) NOT NULL"),
            ("provider", "VARBINARY(512) NOT NULL"),
            ("model", "VARBINARY(1024) NOT NULL"),
            ("key_group_at_use", "VARBINARY(128) NOT NULL DEFAULT ''"),
        ],
    ),
    (
        "plane_records",
        &[
            ("kind", "VARBINARY(256) NOT NULL"),
            ("ident", "VARBINARY(764) NOT NULL"),
            ("id", "VARBINARY(764) NOT NULL"),
            ("parent", "VARBINARY(764) NULL"),
        ],
    ),
    (
        "plane_tokens",
        &[
            ("kind", "VARBINARY(256) NOT NULL"),
            ("token", "VARBINARY(764) NOT NULL"),
        ],
    ),
    (
        "usage_window_units",
        &[
            ("bucket_scope", "VARBINARY(32) NOT NULL"),
            ("bucket_id", "VARBINARY(128) NOT NULL"),
            ("model", "VARBINARY(1024) NOT NULL"),
            ("unit", "VARBINARY(512) NOT NULL"),
        ],
    ),
    (
        "usage_metering_units",
        &[
            ("bucket", "VARBINARY(40) NOT NULL"),
            ("key_id", "VARBINARY(64) NOT NULL"),
            ("provider", "VARBINARY(512) NOT NULL"),
            ("model", "VARBINARY(1024) NOT NULL"),
            ("unit", "VARBINARY(512) NOT NULL"),
        ],
    ),
    ("store_records", &[("schema_id", "VARBINARY(764) NOT NULL")]),
];

/// The foreign key onto `api_keys.id`, `(table, constraint, definition)` exactly as `SCHEMA` declares it: v11 drops it to retype the columns it joins and puts it back.
const V11_KEY_FOREIGN_KEYS: &[(&str, &str, &str)] = &[(
    "credentials",
    "fk_cred_key",
    "FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE",
)];

/// The foreign key from metering to keys that earlier builds declared and no build now does (metering is accepted for any key id): v11 drops it to retype `usage_metering.key_id`, v12 drops it from a database v11 left it in.
const FK_METERING_KEY: (&str, &str) = ("usage_metering", "fk_metering_key");

/// v11's child-to-parent re-spelling, run before any key is retyped (see `run_v11_exact_keys`):
const V11_RESPELL: &[&str] = &[
    "UPDATE credentials c JOIN api_keys k ON k.id = c.key_id SET c.key_id = k.id \
     WHERE BINARY c.key_id <> BINARY k.id",
    "UPDATE usage_metering m JOIN api_keys k ON k.id = m.key_id SET m.key_id = k.id \
     WHERE BINARY m.key_id <> BINARY k.id",
    "UPDATE usage_metering_units u JOIN usage_metering m \
     ON m.bucket = u.bucket AND m.key_id = u.key_id AND m.model = u.model \
     AND m.provider = u.provider AND m.priced_from_ms = u.priced_from_ms \
     SET u.key_id = m.key_id, u.model = m.model, u.provider = m.provider \
     WHERE BINARY u.key_id <> BINARY m.key_id OR BINARY u.model <> BINARY m.model \
     OR BINARY u.provider <> BINARY m.provider",
    "UPDATE usage_window_units u JOIN usage_windows w \
     ON w.window_start = u.window_start AND w.bucket_scope = u.bucket_scope \
     AND w.bucket_id = u.bucket_id AND w.model = u.model \
     SET u.bucket_scope = w.bucket_scope, u.bucket_id = w.bucket_id, u.model = w.model \
     WHERE BINARY u.bucket_scope <> BINARY w.bucket_scope \
     OR BINARY u.bucket_id <> BINARY w.bucket_id OR BINARY u.model <> BINARY w.model",
];

/// The `store_meta` row a migration writes BEFORE its first DDL and deletes after the version stamp: MySQL DDL is not transactional, so this row is how a later open knows the schema may be part-way between two shapes (and which version it was heading for).
const MIGRATING_TO: &str = "migrating_to";

/// The SQL naming this database's migration lock.
const MIGRATION_LOCK: &str = "CONCAT('busbar_store_migrate_', LEFT(SHA2(DATABASE(), 256), 40))";

/// How long an open waits for another connection's migration of the same database to finish before refusing (a fleet booting together onto an old database waits for the one migrator).
const MIGRATION_LOCK_WAIT_SECS: u32 = 30;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS store_meta (
        k VARBINARY(764) PRIMARY KEY,
        v TEXT NOT NULL
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS store_sequence (
        id INT PRIMARY KEY,
        revision BIGINT NOT NULL DEFAULT 0,
        CONSTRAINT ck_seq_singleton CHECK (id = 1)
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS api_keys (
        id VARBINARY(64) PRIMARY KEY,
        name VARCHAR(256) NOT NULL DEFAULT '',
        key_group VARBINARY(128) NOT NULL DEFAULT '',
        allowed_pools JSON NULL,
        labels JSON NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        generation_hash VARCHAR(128) NOT NULL DEFAULT '',
        created_at BIGINT UNSIGNED NOT NULL,
        updated_at BIGINT UNSIGNED NOT NULL,
        expires_at BIGINT UNSIGNED NULL,
        deleted_at BIGINT UNSIGNED NULL,
        revision BIGINT NOT NULL DEFAULT 0,
        allowed_scopes_ext JSON NULL,
        idp_subject TEXT NULL,
        binding_mode TEXT NULL,
        minted_by TEXT NULL,
        idp_provider TEXT NULL,
        CONSTRAINT ck_api_keys_tombstone CHECK (deleted_at IS NULL OR enabled = FALSE),
        CONSTRAINT ck_api_keys_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
        CONSTRAINT ck_api_keys_labels_json CHECK (JSON_VALID(labels)),
        CONSTRAINT ck_api_keys_pools_json CHECK (allowed_pools IS NULL OR JSON_VALID(allowed_pools))
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_api_keys_revision ON api_keys (revision)",
    "CREATE INDEX idx_api_keys_group ON api_keys (key_group)",
    "CREATE TABLE IF NOT EXISTS credentials (
        id VARBINARY(64) PRIMARY KEY,
        key_id VARBINARY(64) NOT NULL,
        kind VARBINARY(128) NOT NULL,
        slot TINYINT NOT NULL,
        public_id VARBINARY(256) NOT NULL,
        secret TEXT NULL,
        secret_form VARCHAR(16) NOT NULL,
        created_at BIGINT UNSIGNED NOT NULL,
        updated_at BIGINT UNSIGNED NOT NULL,
        expires_at BIGINT UNSIGNED NULL,
        revoked_at BIGINT UNSIGNED NULL,
        revoke_reason VARCHAR(512) NULL,
        revision BIGINT NOT NULL DEFAULT 0,
        CONSTRAINT ck_cred_kind CHECK (kind IN ('sigv4')),
        CONSTRAINT ck_cred_slot CHECK (slot IN (0,1)),
        CONSTRAINT ck_cred_form CHECK (secret_form IN ('none','recoverable','digest')),
        CONSTRAINT ck_cred_form_null CHECK ((secret_form = 'none') = (secret IS NULL)),
        CONSTRAINT ck_cred_sigv4_secret CHECK (kind <> 'sigv4' OR secret_form = 'recoverable' OR revoked_at IS NOT NULL),
        CONSTRAINT uq_cred_public UNIQUE (kind, public_id),
        CONSTRAINT uq_cred_slot UNIQUE (key_id, kind, slot),
        CONSTRAINT fk_cred_key FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_cred_revision ON credentials (revision)",
    "CREATE TABLE IF NOT EXISTS denylist (
        sub VARBINARY(64) PRIMARY KEY,
        reason VARCHAR(512) NOT NULL DEFAULT '',
        revoked_at BIGINT UNSIGNED NOT NULL,
        expires_at BIGINT UNSIGNED NOT NULL,
        revoked_generation VARCHAR(128) NULL,
        revision BIGINT NOT NULL DEFAULT 0
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_denylist_revision ON denylist (revision)",
    "CREATE INDEX idx_denylist_expires ON denylist (expires_at)",
    "CREATE TABLE IF NOT EXISTS usage_windows (
        window_start BIGINT UNSIGNED NOT NULL,
        bucket_scope VARBINARY(32) NOT NULL,
        bucket_id VARBINARY(128) NOT NULL,
        model VARBINARY(1088) NOT NULL,
        requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        billable_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_input DECIMAL(39,0) NOT NULL DEFAULT 0,
        tokens_output DECIMAL(39,0) NOT NULL DEFAULT 0,
        tokens_cache_read DECIMAL(39,0) NOT NULL DEFAULT 0,
        tokens_cache_write DECIMAL(39,0) NOT NULL DEFAULT 0,
        PRIMARY KEY (window_start, bucket_scope, bucket_id, model),
        CONSTRAINT ck_uw_scope CHECK (bucket_scope IN ('key','group','global'))
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS usage_metering (
        bucket VARBINARY(40) NOT NULL,
        key_id VARBINARY(64) NOT NULL,
        provider VARBINARY(512) NOT NULL,
        model VARBINARY(1088) NOT NULL,
        key_group_at_use VARBINARY(128) NOT NULL DEFAULT '',
        pricing_version VARCHAR(64) NOT NULL DEFAULT '',
        requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        billable_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_input DECIMAL(39,0) NOT NULL DEFAULT 0,
        tokens_output DECIMAL(39,0) NOT NULL DEFAULT 0,
        tokens_cache_read DECIMAL(39,0) NOT NULL DEFAULT 0,
        tokens_cache_write DECIMAL(39,0) NOT NULL DEFAULT 0,
        priced_from_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms)
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_metering_bucket ON usage_metering (bucket)",
    "CREATE TABLE IF NOT EXISTS audit_log (
        seq BIGINT PRIMARY KEY,
        ts BIGINT UNSIGNED NOT NULL,
        action VARCHAR(64) NOT NULL,
        resource VARCHAR(255) NOT NULL DEFAULT '',
        outcome VARCHAR(32) NOT NULL,
        principal VARCHAR(255) NOT NULL DEFAULT '',
        prev_hash CHAR(64) NOT NULL DEFAULT '',
        hash CHAR(64) NOT NULL DEFAULT ''
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_audit_resource_seq ON audit_log (resource, seq)",






    "CREATE TABLE IF NOT EXISTS plane_records (
        kind VARBINARY(256) NOT NULL,
        ident VARBINARY(764) NOT NULL,
        seq BIGINT UNSIGNED NOT NULL,
        id VARBINARY(764) NOT NULL,
        parent VARBINARY(764) NULL,
        ts BIGINT UNSIGNED NOT NULL,
        terminal BOOLEAN NOT NULL DEFAULT FALSE,
        body LONGBLOB NOT NULL,
        PRIMARY KEY (kind, ident, seq)
    ) ENGINE=InnoDB",



    "CREATE INDEX idx_plane_records_kind_ts ON plane_records (kind, ts)",


    "CREATE INDEX idx_plane_records_kind_parent ON plane_records (kind, parent, seq)",











    "CREATE TABLE IF NOT EXISTS plane_tokens (
        kind VARBINARY(256) NOT NULL,
        token VARBINARY(764) NOT NULL,
        expires_at BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (kind, token)
    ) ENGINE=InnoDB",



    "CREATE INDEX idx_plane_tokens_expires ON plane_tokens (expires_at)",







    "CREATE TABLE IF NOT EXISTS usage_window_units (
        window_start BIGINT UNSIGNED NOT NULL,
        bucket_scope VARBINARY(32) NOT NULL,
        bucket_id VARBINARY(128) NOT NULL,
        model VARBINARY(1088) NOT NULL,
        unit VARBINARY(512) NOT NULL,
        count DECIMAL(39,0) NOT NULL DEFAULT 0,
        PRIMARY KEY (window_start, bucket_scope, bucket_id, model, unit)
    ) ENGINE=InnoDB",




    "CREATE TABLE IF NOT EXISTS usage_metering_units (
        bucket VARBINARY(40) NOT NULL,
        key_id VARBINARY(64) NOT NULL,
        provider VARBINARY(512) NOT NULL,
        model VARBINARY(1088) NOT NULL,
        priced_from_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
        unit VARBINARY(512) NOT NULL,
        count DECIMAL(39,0) NOT NULL DEFAULT 0,
        PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms, unit)
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_metering_units_bucket ON usage_metering_units (bucket)",







    "CREATE TABLE IF NOT EXISTS store_ops (
        op_id BINARY(16) PRIMARY KEY,
        recorded_at BIGINT UNSIGNED NOT NULL,
        body LONGBLOB NOT NULL,
        answer LONGBLOB NOT NULL
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_store_ops_recorded ON store_ops (recorded_at)",


    "CREATE TABLE IF NOT EXISTS store_records (
        schema_id VARBINARY(764) NOT NULL,
        rkey VARBINARY(2048) NOT NULL,
        value VARBINARY(512) NOT NULL,
        PRIMARY KEY (schema_id, rkey)
    ) ENGINE=InnoDB",
];

/// How many connections the store keeps: this store is control-plane-frequency (key/credential CRUD) plus write-behind usage flush, not a high-fan-out OLTP workload, and an unbounded set across many instances (a multi-process fleet booting simultaneously) is what exhausts MySQL's default `max_connections`.
pub const KEPT_CONNECTIONS: usize = 8;

/// ESTABLISHED on every connection the store ever opens -- including a reconnect after a dropped connection, or the set growing past the one connection `probe_invariants` checks at boot -- and again after each reset, rather than verifying it once and trusting every future connection inherits the same posture.
pub(crate) const INIT: &[&str] =
    &["SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')"];

/// MySQL/MariaDB-backed store: the connection URL and the kept connections every op runs on (one connection per op at a time).
pub struct MysqlStore {
    pub(crate) opts: Arc<Opts>,
    pub(crate) pool: Arc<Pool>,
}

impl MysqlStore {
    /// The store on `url`: the URL is parsed here (the driver's refusal texts); the server is reached by `open`'s connect step ([`Self::connect_step`]).
    pub fn new(url: &str) -> RecordStoreResult<Self> {
        Ok(Self {
            opts: Arc::new(Opts::from_url(url).map_err(store_err)?),
            pool: Pool::new(KEPT_CONNECTIONS),
        })
    }

    /// `open`'s connect step: create the schema if absent, and run the boot-time invariant probes, on the op's connection.
    pub(crate) async fn connect_step(conn: &mut Conn) -> RecordStoreResult<()> {
        Self::init_schema(conn).await?;
        Self::probe_invariants(conn).await?;
        Ok(())
    }

    /// Schema creation, retried (bounded, immediately) on deadlock.
    async fn init_schema(conn: &mut Conn) -> RecordStoreResult<()> {
        const MAX_ATTEMPTS: u32 = 8;
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_init_schema_waiting(conn, MIGRATION_LOCK_WAIT_SECS).await {
                Ok(()) => return Ok(()),

                Err(e) if attempt < MAX_ATTEMPTS && Self::is_deadlock(&e.0) => {}
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop always returns on the final attempt")
    }

    /// Whether `information_schema.<view>` has a row for `cond` in the connected database (`DATABASE()` scopes it to this store's own schema).
    async fn exists(conn: &mut Conn, view: &str, cond: &str, p: Params) -> RecordStoreResult<bool> {
        let sql = format!(
            "SELECT COUNT(*) FROM information_schema.{view} \
             WHERE table_schema = DATABASE() AND {cond}"
        );
        let n: Option<u64> = conn.exec_first(sql, p).await.map_err(store_err)?;
        Ok(n.unwrap_or(0) > 0)
    }

    async fn table_exists(conn: &mut Conn, table: &str) -> RecordStoreResult<bool> {
        Self::exists(conn, "tables", "table_name = :t", params! { "t" => table }).await
    }

    async fn index_exists(conn: &mut Conn, table: &str, index: &str) -> RecordStoreResult<bool> {
        let p = params! { "t" => table, "i" => index };
        Self::exists(conn, "statistics", "table_name = :t AND index_name = :i", p).await
    }

    async fn column_exists(conn: &mut Conn, table: &str, column: &str) -> RecordStoreResult<bool> {
        let p = params! { "t" => table, "c" => column };
        Self::exists(conn, "columns", "table_name = :t AND column_name = :c", p).await
    }

    /// ADD `column` to `table` unless it is already there.
    async fn ensure_column(
        conn: &mut Conn,
        table: &str,
        column: &str,
        definition: &str,
    ) -> RecordStoreResult<()> {
        if Self::column_exists(conn, table, column).await? {
            return Ok(());
        }
        match conn
            .query_drop(format!(
                "ALTER TABLE {table} ADD COLUMN {column} {definition}"
            ))
            .await
        {
            Ok(()) => Ok(()),
            Err(Error::MySqlError(e)) if e.code == 1060 => Ok(()),
            Err(e) => Err(store_err(format!(
                "schema upgrade failed adding {table}.{column}: {e}"
            ))),
        }
    }

    /// v7 schema upgrade, in place and idempotent, gated on what the database HAS: five NULLable `api_keys` columns, and `usage_metering.priced_from_ms` (DEFAULT 0, "the opening card") joined to the primary key in one `ALTER`, so the `key_id` FK always has an index.
    pub(crate) async fn run_v7_schema_upgrade(
        conn: &mut Conn,
        keys_table: &str,
        metering_table: &str,
    ) -> RecordStoreResult<()> {
        Self::ensure_column(conn, keys_table, "allowed_scopes_ext", "JSON NULL").await?;
        Self::ensure_column(conn, keys_table, "idp_subject", "TEXT NULL").await?;
        Self::ensure_column(conn, keys_table, "binding_mode", "TEXT NULL").await?;
        Self::ensure_column(conn, keys_table, "minted_by", "TEXT NULL").await?;
        Self::ensure_column(conn, keys_table, "idp_provider", "TEXT NULL").await?;
        Self::ensure_column(
            conn,
            metering_table,
            "priced_from_ms",
            "BIGINT UNSIGNED NOT NULL DEFAULT 0",
        )
        .await?;
        let pk_has_it = Self::exists(
            conn,
            "statistics",
            "table_name = :t AND index_name = 'PRIMARY' AND column_name = 'priced_from_ms'",
            params! { "t" => metering_table },
        )
        .await?;
        if !pk_has_it {
            conn.query_drop(format!(
                "ALTER TABLE {metering_table} DROP PRIMARY KEY, \
                 ADD PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms)"
            ))
            .await
            .map_err(|e| {
                store_err(format!(
                    "schema upgrade failed re-keying {metering_table} on priced_from_ms: {e}"
                ))
            })?;
        }
        Ok(())
    }

    /// Transcode legacy character data before making its stored bytes the identity.
    async fn normalize_utf8(
        conn: &mut Conn,
        table: &str,
        columns: &[(&str, &str)],
    ) -> RecordStoreResult<()> {
        for (column, definition) in columns {
            let shape: Option<(Option<String>, Option<u64>)> = conn.exec_first(
                "SELECT CHARACTER_SET_NAME, CHARACTER_MAXIMUM_LENGTH FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=:table AND column_name=:column",
                params! { "table" => table, "column" => *column },
            ).await.map_err(store_err)?;
            let Some((Some(charset), Some(length))) = shape else {
                continue;
            };
            if matches!(
                charset.as_str(),
                "ascii" | "utf8" | "utf8mb3" | "utf8mb4" | "binary"
            ) {
                continue;
            }
            let suffix = definition
                .split_once(')')
                .map(|(_, suffix)| suffix)
                .ok_or_else(|| store_err("invalid migration column definition"))?;
            conn.query_drop(format!("ALTER TABLE {table} MODIFY COLUMN {column} VARCHAR({length}) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin{suffix}"))
                .await.map_err(store_err)?;
        }
        Ok(())
    }

    /// v11 schema upgrade (D19): every key and identity column becomes `VARBINARY`.
    pub(crate) async fn run_v11_exact_keys(conn: &mut Conn) -> RecordStoreResult<()> {
        let mut pending: Vec<(&str, Vec<(&str, &str)>)> = Vec::new();
        for (table, columns) in V11_EXACT_KEY_COLUMNS {
            if !Self::table_exists(conn, table).await? {
                continue;
            }
            let mut todo = Vec::new();
            for (column, definition) in *columns {
                let ty: Option<String> = conn
                    .exec_first(
                        "SELECT DATA_TYPE FROM information_schema.columns \
                         WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c",
                        params! { "t" => *table, "c" => *column },
                    )
                    .await
                    .map_err(store_err)?;
                if ty.is_some_and(|t| !t.eq_ignore_ascii_case("varbinary")) {
                    todo.push((*column, *definition));
                }
            }
            if !todo.is_empty() {
                pending.push((table, todo));
            }
        }
        if !pending.is_empty() {
            for stmt in V11_RESPELL {
                conn.query_drop(*stmt).await.map_err(|e| {
                    store_err(format!(
                        "schema upgrade v11 failed re-spelling a child key: {e}"
                    ))
                })?;
            }
            for (table, constraint, _) in V11_KEY_FOREIGN_KEYS {
                Self::drop_foreign_key(conn, table, constraint, "v11").await?;
            }
            Self::drop_foreign_key(conn, FK_METERING_KEY.0, FK_METERING_KEY.1, "v11").await?;
            for (table, columns) in &pending {
                Self::normalize_utf8(conn, table, columns).await?;
                let modify = columns
                    .iter()
                    .map(|(c, d)| format!("MODIFY COLUMN {c} {d}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                conn.query_drop(format!("ALTER TABLE {table} {modify}"))
                    .await
                    .map_err(|e| {
                        store_err(format!(
                            "schema upgrade v11 failed making {table}'s keys exact: {e}"
                        ))
                    })?;
            }
        }
        for (table, constraint, definition) in V11_KEY_FOREIGN_KEYS {
            if Self::table_exists(conn, table).await?
                && !Self::foreign_key_exists(conn, table, constraint).await?
            {
                conn.query_drop(format!(
                    "ALTER TABLE {table} ADD CONSTRAINT {constraint} {definition}"
                ))
                .await
                .map_err(|e| {
                    store_err(format!(
                        "schema upgrade v11 failed restoring {table}.{constraint}: {e}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// v12 schema upgrade: a revoked credential's secret is destroyed (`revoke_credential`), which v11's `ck_cred_sigv4_recov` forbids for a sigv4 row, so the check is replaced by `ck_cred_sigv4_secret` (the same rule, unless the row is revoked), and the secrets of the rows already revoked are scrubbed.
    pub(crate) async fn run_v12_revoked_secrets(conn: &mut Conn) -> RecordStoreResult<()> {
        let fail =
            |what: &str, e: Error| store_err(format!("schema upgrade v12 failed {what}: {e}"));
        if Self::check_exists(conn, "credentials", "ck_cred_sigv4_recov").await? {
            // MySQL 8.0.16+ spells it DROP CHECK (DROP CONSTRAINT from 8.0.19); MariaDB takes
            // DROP CONSTRAINT.
            if let Err(first) = conn
                .query_drop("ALTER TABLE credentials DROP CHECK ck_cred_sigv4_recov")
                .await
            {
                conn.query_drop("ALTER TABLE credentials DROP CONSTRAINT ck_cred_sigv4_recov")
                    .await
                    .map_err(|e| {
                        fail(
                            &format!(
                                "dropping credentials.ck_cred_sigv4_recov (DROP CHECK: {first})"
                            ),
                            e,
                        )
                    })?;
            }
        }
        if !Self::check_exists(conn, "credentials", "ck_cred_sigv4_secret").await? {
            conn.query_drop(
                "ALTER TABLE credentials ADD CONSTRAINT ck_cred_sigv4_secret CHECK \
                 (kind <> 'sigv4' OR secret_form = 'recoverable' OR revoked_at IS NOT NULL)",
            )
            .await
            .map_err(|e| fail("adding credentials.ck_cred_sigv4_secret", e))?;
        }

        let mut tx = conn
            .start_transaction()
            .await
            .map_err(|e| fail("starting the revoked-secret scrub", e))?;
        let scrub = async {
            tx.query_drop(
                "INSERT INTO store_sequence (id, revision) VALUES (1, 0) \
                 ON DUPLICATE KEY UPDATE id = id",
            )
            .await
            .map_err(|e| fail("locking the scrub sequence", e))?;
            let dirty: Option<u8> = tx
                .query_first(
                    "SELECT 1 FROM credentials WHERE revoked_at IS NOT NULL \
                     AND (secret IS NOT NULL OR secret_form <> 'none') LIMIT 1 FOR UPDATE",
                )
                .await
                .map_err(|e| fail("finding revoked secrets", e))?;
            if dirty.is_some() {
                let revision = Self::bump_revision(&mut tx).await?;
                tx.exec_drop(
                    "UPDATE credentials SET secret = NULL, secret_form = 'none', revision = :r \
                     WHERE revoked_at IS NOT NULL AND (secret IS NOT NULL OR secret_form <> 'none')",
                    params! { "r" => revision },
                )
                .await
                .map_err(|e| fail("scrubbing revoked secrets", e))?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = scrub {
            return Err(refusal_after_rollback(error, tx.rollback().await));
        }
        tx.commit()
            .await
            .map_err(|e| fail("committing the revoked-secret scrub", e))?;
        Self::drop_foreign_key(conn, FK_METERING_KEY.0, FK_METERING_KEY.1, "v12").await
    }

    async fn check_exists(
        conn: &mut Conn,
        table: &str,
        constraint: &str,
    ) -> RecordStoreResult<bool> {
        let cond = "table_name = :t AND constraint_name = :c AND constraint_type = 'CHECK'";
        let p = params! { "t" => table, "c" => constraint };
        Self::exists(conn, "table_constraints", cond, p).await
    }

    /// Drop `table`'s foreign key `constraint` if the database has it (`step` names the schema step in a failure).
    async fn drop_foreign_key(
        conn: &mut Conn,
        table: &str,
        constraint: &str,
        step: &str,
    ) -> RecordStoreResult<()> {
        if !Self::table_exists(conn, table).await?
            || !Self::foreign_key_exists(conn, table, constraint).await?
        {
            return Ok(());
        }
        conn.query_drop(format!("ALTER TABLE {table} DROP FOREIGN KEY {constraint}"))
            .await
            .map_err(|e| {
                store_err(format!(
                    "schema upgrade {step} failed dropping {table}.{constraint}: {e}"
                ))
            })
    }

    async fn foreign_key_exists(
        conn: &mut Conn,
        table: &str,
        constraint: &str,
    ) -> RecordStoreResult<bool> {
        let cond = "table_name = :t AND constraint_name = :c AND constraint_type = 'FOREIGN KEY'";
        let p = params! { "t" => table, "c" => constraint };
        Self::exists(conn, "table_constraints", cond, p).await
    }

    /// A `u32` value of `store_meta` (`table` for test isolation, like `read_prior_version`), or `None` when the row is absent; a value that is not a number is a hard error.
    async fn read_meta_u32(
        conn: &mut Conn,
        table: &str,
        key: &str,
    ) -> RecordStoreResult<Option<u32>> {
        let v: Option<String> = conn
            .exec_first(
                format!("SELECT v FROM {table} WHERE k = :k"),
                params! { "k" => key },
            )
            .await
            .map_err(store_err)?;
        v.map(|v| {
            v.parse().map_err(|e| {
                store_err(format!(
                    "{table}.{key} is corrupt (not a version number): {v:?} ({e})"
                ))
            })
        })
        .transpose()
    }

    /// Refuse a database this build must not touch: older than the oldest released schema, stamped by a newer build, or left part-way through a newer build's migration (its marker names a version this build does not know the steps of, and its tables may be half way to a shape this build cannot read).
    fn refuse_unknown_schema(
        prior_version: u32,
        migrating_to: Option<u32>,
    ) -> RecordStoreResult<()> {
        if prior_version == 6 || migrating_to == Some(6) {
            return Err(store_err(
                "mysql store: unsupported development schema v6; refusing to open",
            ));
        }
        if prior_version > SCHEMA_VERSION {
            return Err(store_err(format!(
                "mysql store: database schema v{prior_version} is newer than this build \
                 (v{SCHEMA_VERSION}); refusing to open"
            )));
        }
        if let Some(to) = migrating_to.filter(|to| *to > SCHEMA_VERSION) {
            return Err(store_err(format!(
                "mysql store: database is mid-migration from schema v{prior_version} to v{to}, \
                 which is newer than this build (v{SCHEMA_VERSION}); refusing to open. Finish the \
                 migration by opening it with a build at v{to} or later"
            )));
        }
        Ok(())
    }

    /// Take the database's migration lock (a server-wide `GET_LOCK` named for this database, so two stores on two databases of one server never wait on each other), waiting up to `wait_secs`.
    async fn acquire_migration_lock(
        conn: &mut Conn,
        prior_version: u32,
        wait_secs: u32,
    ) -> RecordStoreResult<()> {
        let got: Option<Option<i64>> = conn
            .query_first(format!("SELECT GET_LOCK({MIGRATION_LOCK}, {wait_secs})"))
            .await
            .map_err(store_err)?;
        match got.flatten() {
            Some(1) => return Ok(()),
            Some(0) => {}
            _ => {
                return Err(store_err(
                    "mysql store: GET_LOCK failed to return a lock outcome",
                ));
            }
        }
        let holder: Option<Option<u64>> = conn
            .query_first(format!("SELECT IS_USED_LOCK({MIGRATION_LOCK})"))
            .await
            .map_err(store_err)?;
        let holder = holder.flatten().map_or_else(
            || "another connection".to_owned(),
            |id| format!("connection {id}"),
        );
        let what = if prior_version == 0 {
            format!("creating schema v{SCHEMA_VERSION}")
        } else {
            format!("migrating it from schema v{prior_version} to v{SCHEMA_VERSION}")
        };
        Err(store_err(format!(
            "mysql store: database is mid-migration: {holder} holds its migration lock and is \
             {what}; refusing to open after waiting {wait_secs}s (retry once that migration ends)"
        )))
    }

    /// Read the version this database was AT before this boot from `store_meta`, tolerating "no row
    /// yet" (a genuinely fresh database: no released schema ever left one unstamped) as version 0, but
    /// propagating any OTHER query failure (a connection blip, a lock timeout)
    /// instead of silently treating it identically to "fresh install" -- collapsing those
    /// two outcomes would let a transient failure here permanently mark a possibly-unmigrated
    /// database as migrated. A stored value that fails to parse as a version number is ALSO a hard
    /// error rather than a silent 0 -- a corrupt marker is exactly the kind of "looks fine, isn't" state
    /// this store's own boot-probe philosophy (module doc, above) says must hard-fail, not warn.
    /// Takes `table` rather than hardcoding `store_meta`, purely for test isolation -- same reason
    /// `store_meta` is a single shared row the whole test binary's `connect()` calls race on.
    /// Production always calls this with `"store_meta"`.
    pub(crate) async fn read_prior_version(conn: &mut Conn, table: &str) -> RecordStoreResult<u32> {
        match conn
            .query_first::<Option<String>>(format!(
                "SELECT v FROM {table} WHERE k = 'schema_version'"
            ))
            .await
            .map_err(store_err)?
            .flatten()
        {
            None => Ok(0),
            Some(v) => v.parse().map_err(|e| {
                store_err(format!(
                    "store_meta.schema_version is corrupt (not a valid version number): {v:?} ({e})"
                ))
            }),
        }
    }

    /// Stamps `schema_version`.
    pub(crate) async fn stamp_schema_version(
        conn: &mut Conn,
        table: &str,
    ) -> RecordStoreResult<()> {
        conn.query_drop(
            format!(
                "INSERT INTO {table} (k, v) VALUES ('schema_version', '{SCHEMA_VERSION}') \
                 ON DUPLICATE KEY UPDATE v = IF(CAST(v AS UNSIGNED) > {SCHEMA_VERSION}, v, VALUES(v))"
            ),
        )
        .await
        .map_err(store_err)
    }

    /// Create or migrate the schema, waiting at most `wait_secs` for another connection's migration of this database (a parameter so a test can see the refusal without waiting the full term).
    pub(crate) async fn try_init_schema_waiting(
        conn: &mut Conn,
        wait_secs: u32,
    ) -> RecordStoreResult<()> {
        conn.query_drop(SCHEMA[0]).await.map_err(store_err)?;
        let prior_version = Self::read_prior_version(conn, "store_meta").await?;
        let migrating_to = Self::read_meta_u32(conn, "store_meta", MIGRATING_TO).await?;

        Self::refuse_unknown_schema(prior_version, migrating_to)?;
        Self::check_quantity_format(conn, prior_version).await?;
        if prior_version == SCHEMA_VERSION && migrating_to.is_none() {
            return Self::apply_schema(conn, prior_version).await;
        }
        Self::acquire_migration_lock(conn, prior_version, wait_secs).await?;
        let result = Self::migrate_locked(conn).await;
        let released = conn
            .query_drop(format!("DO RELEASE_LOCK({MIGRATION_LOCK})"))
            .await;

        match (result, released) {
            (Ok(()), Err(e)) => Err(store_err(format!(
                "schema migration succeeded but releasing its lock failed: {e}"
            ))),
            (result, _) => result,
        }
    }

    /// The migration, under the database's migration lock. The version and marker are read again:
    async fn migrate_locked(conn: &mut Conn) -> RecordStoreResult<()> {
        let prior_version = Self::read_prior_version(conn, "store_meta").await?;
        let migrating_to = Self::read_meta_u32(conn, "store_meta", MIGRATING_TO).await?;
        Self::refuse_unknown_schema(prior_version, migrating_to)?;
        Self::check_quantity_format(conn, prior_version).await?;
        if prior_version > 0 && prior_version < SCHEMA_VERSION {
            conn.query_drop(format!(
                "INSERT INTO store_meta (k, v) VALUES ('{MIGRATING_TO}', '{SCHEMA_VERSION}') \
                 ON DUPLICATE KEY UPDATE v = VALUES(v)"
            ))
            .await
            .map_err(store_err)?;
        }
        Self::apply_schema(conn, prior_version).await?;
        conn.query_drop(format!("DELETE FROM store_meta WHERE k = '{MIGRATING_TO}'"))
            .await
            .map_err(store_err)
    }

    /// Copy each legacy unit's recorded attribution before widening either identity.
    async fn run_v13_metering_attribution(conn: &mut Conn) -> RecordStoreResult<()> {
        if Self::exists(conn, "statistics",
            "table_name='usage_metering' AND index_name='PRIMARY' AND column_name='pricing_version'",
            Params::Empty).await? {
            return Ok(());
        }
        let orphan: Option<u64> = conn
            .query_first(
                "SELECT EXISTS(SELECT 1 FROM usage_metering_units u LEFT JOIN usage_metering m
             ON m.key_id=u.key_id AND m.bucket=u.bucket AND m.model=u.model
             AND m.provider=u.provider AND m.priced_from_ms=u.priced_from_ms
             WHERE m.key_id IS NULL)",
            )
            .await
            .map_err(store_err)?;
        match orphan {
            Some(0) => {}
            Some(_) => {
                return Err(store_err(
                    "mysql store: usage_metering_units contains attribution with no matching usage_metering parent",
                ));
            }
            None => {
                return Err(store_err(
                    "mysql store: metering orphan probe returned no row",
                ));
            }
        }
        Self::ensure_column(
            conn,
            "usage_metering_units",
            "key_group_at_use",
            "VARBINARY(128) NOT NULL DEFAULT ''",
        )
        .await?;
        Self::ensure_column(
            conn,
            "usage_metering_units",
            "pricing_version",
            "VARBINARY(256) NOT NULL DEFAULT ''",
        )
        .await?;

        Self::normalize_utf8(
            conn,
            "usage_metering",
            &[("pricing_version", "VARBINARY(256) NOT NULL DEFAULT ''")],
        )
        .await?;
        conn.query_drop(
            "ALTER TABLE usage_metering MODIFY pricing_version VARBINARY(256) NOT NULL DEFAULT ''",
        )
        .await
        .map_err(store_err)?;
        conn.query_drop(
            "UPDATE usage_metering_units u JOIN usage_metering m
             ON m.key_id=u.key_id AND m.bucket=u.bucket AND m.model=u.model
             AND m.provider=u.provider AND m.priced_from_ms=u.priced_from_ms
             SET u.key_group_at_use=m.key_group_at_use, u.pricing_version=m.pricing_version",
        )
        .await
        .map_err(store_err)?;
        if !Self::exists(conn, "statistics",
            "table_name='usage_metering_units' AND index_name='PRIMARY' AND column_name='pricing_version'",
            Params::Empty).await? {
            conn.query_drop("ALTER TABLE usage_metering_units DROP PRIMARY KEY,
                ADD PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms,key_group_at_use,pricing_version,unit)")
                .await.map_err(store_err)?;
        }
        conn.query_drop("ALTER TABLE usage_metering DROP PRIMARY KEY,
            ADD PRIMARY KEY (key_id,bucket,model,provider,priced_from_ms,key_group_at_use,pricing_version)")
            .await.map_err(store_err)?;
        Ok(())
    }

    /// Keep all 1024 bytes previously accepted for a model, plus the raw ledger's longest price-entry prefix: `busbar.raw-era.v1:<u64>:<24 hex bytes><US>` (64 bytes).
    async fn run_v14_raw_era_models(conn: &mut Conn) -> RecordStoreResult<()> {
        for table in [
            "usage_windows",
            "usage_window_units",
            "usage_metering",
            "usage_metering_units",
        ] {
            let shape: Option<(String, u64)> = conn
                .exec_first(
                    "SELECT DATA_TYPE, CHARACTER_OCTET_LENGTH FROM information_schema.columns
                     WHERE table_schema=DATABASE() AND table_name=:table AND column_name='model'",
                    params! { "table" => table },
                )
                .await
                .map_err(store_err)?;
            let Some((data_type, bytes)) = shape else {
                return Err(store_err(format!(
                    "schema upgrade v14: {table}.model is missing"
                )));
            };
            if !data_type.eq_ignore_ascii_case("varbinary") {
                return Err(store_err(format!(
                    "schema upgrade v14: {table}.model is not byte-exact"
                )));
            }

            if bytes < 1088 {
                conn.query_drop(format!(
                    "ALTER TABLE {table} MODIFY model VARBINARY(1088) NOT NULL"
                ))
                .await
                .map_err(|e| {
                    store_err(format!(
                        "schema upgrade v14 failed widening {table}.model: {e}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Create missing tables, cross each pending migration, and stamp the schema.
    async fn apply_schema(conn: &mut Conn, prior_version: u32) -> RecordStoreResult<()> {
        for stmt in SCHEMA {
            if let Some((index, table)) = parse_create_index(stmt) {
                if Self::index_exists(conn, table, index).await? {
                    continue;
                }
            }

            if let Err(e) = conn.query_drop(*stmt).await {
                let race = Self::is_ddl_race(&e);
                let msg = e.to_string();
                if !race {
                    return Err(store_err(format!(
                        "schema init failed: {msg}\nstatement: {stmt}"
                    )));
                }
            }
        }

        Self::run_v7_schema_upgrade(conn, "api_keys", "usage_metering").await?;
        if prior_version == 1 {
            loop {
                conn.query_drop("UPDATE usage_windows SET billable_requests = requests WHERE billable_requests = 0 AND requests > 0 LIMIT 5000")
                    .await.map_err(store_err)?;
                if conn.affected_rows() < 5000 {
                    break;
                }
            }
        }
        if (1..3).contains(&prior_version) {
            conn.query_drop("ALTER TABLE usage_metering MODIFY COLUMN key_group_at_use VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT ''")
                .await.map_err(store_err)?;
        }
        if prior_version < 4 {
            Self::run_v11_exact_keys(conn).await?;
            Self::run_v12_revoked_secrets(conn).await?;
            Self::run_v13_metering_attribution(conn).await?;
            Self::run_v14_raw_era_models(conn).await?;
        }
        if prior_version < SCHEMA_VERSION {
            Self::widen_quantity_columns(conn).await?;
            Self::migrate_exact_counts(conn, prior_version < 5).await?;
        }

        conn.query_drop(
            "INSERT INTO store_sequence (id, revision) VALUES (1, 0) \
             ON DUPLICATE KEY UPDATE id = id",
        )
        .await
        .map_err(store_err)?;

        Self::migrate_request_counters(conn).await
    }

    /// Released stores kept request counters on model rows. Move their aggregate to the
    /// empty-model row used by current additive writes, without changing any quantities.
    /// A separate marker also upgrades databases already stamped v5. The ledger sequence
    /// serializes concurrent booters and live writers; conversion and marker commit together.
    async fn migrate_request_counters(conn: &mut Conn) -> RecordStoreResult<()> {
        const MARKER: &str = "usage_request_totals_v1";
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        slots::lock_ledger_sequence(&mut tx)
            .await
            .map_err(|error| store_err(error.text))?;
        let marker: Option<String> = tx
            .exec_first(
                "SELECT v FROM store_meta WHERE k=:marker FOR UPDATE",
                params! { "marker" => MARKER },
            )
            .await
            .map_err(store_err)?;
        if let Some(value) = marker {
            if value != "1" {
                return Err(store_err(
                    "invalid usage_request_totals_v1 migration marker",
                ));
            }
            return tx.commit().await.map_err(store_err);
        }
        // SUM uses decimal arithmetic, so a historical aggregate wider than u64 can be
        // saturated before insertion. Existing empty-model quantity columns are untouched.
        tx.query_drop(format!(
            "INSERT INTO usage_windows
                (window_start,bucket_scope,bucket_id,model,requests,billable_requests)
             SELECT window_start,bucket_scope,bucket_id,'',
                LEAST(SUM(requests),{USAGE_COUNTER_CEILING}),
                LEAST(SUM(billable_requests),{USAGE_COUNTER_CEILING})
             FROM usage_windows GROUP BY window_start,bucket_scope,bucket_id
             ON DUPLICATE KEY UPDATE requests=VALUES(requests),
                billable_requests=VALUES(billable_requests)"
        ))
        .await
        .map_err(store_err)?;
        tx.query_drop(
            "UPDATE usage_windows SET requests=0,billable_requests=0
             WHERE model<>'' AND (requests<>0 OR billable_requests<>0)",
        )
        .await
        .map_err(store_err)?;
        tx.exec_drop(
            "INSERT INTO store_meta(k,v) VALUES(:marker,'1')",
            params! { "marker" => MARKER },
        )
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)
    }

    /// A v7 marker cannot be confused with any unreleased development schema.
    async fn check_quantity_format(conn: &mut Conn, version: u32) -> RecordStoreResult<()> {
        if version != SCHEMA_VERSION {
            return Ok(());
        }
        let format: Option<String> = conn
            .exec_first(
                "SELECT v FROM store_meta WHERE k=:key",
                params! { "key" => QUANTITY_FORMAT_KEY },
            )
            .await
            .map_err(store_err)?;
        if format.as_deref() != Some(QUANTITY_FORMAT) {
            return Err(store_err("mysql store: schema v7 lacks the exact i128 quantity format marker; refusing to open"));
        }
        Ok(())
    }

    /// DDL is idempotent and happens before scaling, while the migration lock is held.
    async fn widen_quantity_columns(conn: &mut Conn) -> RecordStoreResult<()> {
        for (table, columns) in QUANTITY_TABLES {
            let mut changes = Vec::new();
            for column in *columns {
                let shape: Option<(String, Option<u64>, Option<u64>)> = conn.exec_first(
                    "SELECT DATA_TYPE,NUMERIC_PRECISION,NUMERIC_SCALE FROM information_schema.columns
                     WHERE table_schema=DATABASE() AND table_name=:table AND column_name=:column",
                    params! { "table" => *table, "column" => *column },
                ).await.map_err(store_err)?;
                if shape != Some(("decimal".into(), Some(39), Some(0))) {
                    changes.push(format!(
                        "MODIFY COLUMN {column} DECIMAL(39,0) NOT NULL DEFAULT 0"
                    ));
                }
            }
            if !changes.is_empty() {
                conn.query_drop(format!("ALTER TABLE {table} {}", changes.join(", ")))
                    .await
                    .map_err(store_err)?;
            }
            let constraint = format!("{table}_quantity_i128");
            if !Self::exists(
                conn,
                "table_constraints",
                "table_name=:table AND constraint_name=:name",
                params! { "table" => *table, "name" => &constraint },
            )
            .await?
            {
                let bounds = columns
                    .iter()
                    .map(|column| format!("{column} BETWEEN 0 AND {QUANTITY_MAX}"))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                conn.query_drop(format!(
                    "ALTER TABLE {table} ADD CONSTRAINT {constraint} CHECK ({bounds})"
                ))
                .await
                .map_err(store_err)?;
            }
        }
        Ok(())
    }

    /// Quantity conversion and both format markers commit together after widening DDL.
    /// Existing v5 mantissas are already micro-units: validate them, never rescale them.
    async fn migrate_exact_counts(conn: &mut Conn, whole_units: bool) -> RecordStoreResult<()> {
        conn.query_drop("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .await
            .map_err(store_err)?;
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let ceiling = if whole_units {
            WHOLE_QUANTITY_MAX
        } else {
            QUANTITY_MAX
        };
        for (table, columns) in QUANTITY_TABLES {
            let invalid = columns
                .iter()
                .map(|column| format!("{column}<0 OR {column}>{ceiling}"))
                .collect::<Vec<_>>()
                .join(" OR ");
            let invalid: Option<u64> = tx
                .query_first(format!(
                    "SELECT COALESCE(MAX({invalid}),0) FROM {table} FOR UPDATE"
                ))
                .await
                .map_err(store_err)?;
            if invalid != Some(0) {
                return Err(store_err(format!(
                    "exact count migration: {table} contains a quantity outside the nonnegative i128 scale-6 range; nothing was converted"
                )));
            }
        }
        if whole_units {
            for (table, columns) in QUANTITY_TABLES {
                let assignments = columns
                    .iter()
                    .map(|column| format!("{column}={column}*1000000"))
                    .collect::<Vec<_>>()
                    .join(", ");
                tx.query_drop(format!("UPDATE {table} SET {assignments}"))
                    .await
                    .map_err(store_err)?;
            }
        }
        tx.exec_drop(
            "INSERT INTO store_meta(k,v) VALUES(:key,:format) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            params! { "key" => QUANTITY_FORMAT_KEY, "format" => QUANTITY_FORMAT },
        )
        .await
        .map_err(store_err)?;
        Self::stamp_schema_version(&mut tx, "store_meta").await?;
        tx.commit().await.map_err(store_err)
    }

    /// A `CREATE INDEX`/`CREATE TABLE` that lost a race to a concurrent booter.
    pub(crate) fn is_ddl_race(e: &Error) -> bool {
        matches!(e, Error::MySqlError(inner) if inner.code == 1061 || inner.code == 1050)
    }

    /// A deadlock (`ERROR 1213`) surfaced through `store_err`'s text.
    pub(crate) fn is_deadlock(text: &str) -> bool {
        text.contains("ERROR 1213 (")
    }

    /// A rejected probe INSERT is proof of CHECK enforcement ONLY if it's the SPECIFIC CHECK-violation error this schema's two target engines actually produce -- MySQL 8.0.16+'s `ER_CHECK_CONSTRAINT_VIOLATED` (3819) or MariaDB's `ER_CONSTRAINT_FAILED` (4025).
    pub(crate) fn is_check_constraint_violation(e: &Error) -> bool {
        matches!(e, Error::MySqlError(inner) if inner.code == 3819 || inner.code == 4025)
    }

    /// Live functional probes for the two failure modes a schema-shape check cannot catch:
    /// (1) `CHECK` constraints parsed but not enforced (MySQL < 8.0.16, Aurora MySQL 2.x);
    /// (2) `STRICT_ALL_TABLES` not in `sql_mode` (a VARCHAR/BIGINT overflow silently truncates
    ///     instead of erroring). (1) is probed via a session-private `TEMPORARY` table (never the
    ///     real shared schema — zero contention with real traffic or another node's simultaneous
    ///     probe), dropped immediately after; no probe row ever touches real data.
    pub(crate) async fn probe_invariants(conn: &mut Conn) -> RecordStoreResult<()> {
        let sql_mode: String = conn
            .query_first("SELECT @@sql_mode")
            .await
            .map_err(store_err)?
            .unwrap_or_default();
        if !sql_mode.contains("STRICT_ALL_TABLES") && !sql_mode.contains("STRICT_TRANS_TABLES") {
            return Err(store_err(format!(
                "boot probe failed: sql_mode does not include STRICT_ALL_TABLES/STRICT_TRANS_TABLES \
                 (got '{sql_mode}') — a truncated write would silently corrupt data instead of \
                 erroring. Set `SET GLOBAL sql_mode='STRICT_ALL_TABLES';` on this server."
            )));
        }

        conn.query_drop(
            "CREATE TEMPORARY TABLE busbar_check_probe (\
                id INT PRIMARY KEY, CONSTRAINT ck_probe CHECK (id = 1)\
             ) ENGINE=InnoDB",
        )
        .await
        .map_err(store_err)?;
        let probe_result = conn
            .query_drop("INSERT INTO busbar_check_probe (id) VALUES (999)")
            .await;
        let _ = conn
            .query_drop("DROP TEMPORARY TABLE busbar_check_probe")
            .await;

        let rejected = match probe_result {
            Ok(()) => false,
            Err(ref e) if Self::is_check_constraint_violation(e) => true,
            Err(e) => {
                return Err(store_err(format!(
                    "boot probe failed: could not determine whether CHECK constraints are enforced \
                     — the probe INSERT failed for an unexpected reason instead of the expected \
                     CHECK violation (MySQL code 3819 / MariaDB code 4025): {e}"
                )));
            }
        };
        if !rejected {
            return Err(store_err(
                "boot probe failed: a CHECK constraint violation was NOT rejected — this server \
                 parses CHECK constraints but does not enforce them (MySQL < 8.0.16, or Aurora MySQL \
                 2.x). Every CHECK in this schema (tombstone invariants, credential-kind allowlist, \
                 secret-form consistency) is silently unenforced. Upgrade to MySQL >= 8.0.16, MariaDB, \
                 or Aurora MySQL 3.x.",
            ));
        }
        Ok(())
    }

    /// Bump `store_sequence` and return the new revision.
    async fn bump_revision(tx: &mut Transaction<'_>) -> RecordStoreResult<u64> {
        tx.query_drop("UPDATE store_sequence SET revision = revision + 1 WHERE id = 1")
            .await
            .map_err(store_err)?;
        tx.query_first("SELECT revision FROM store_sequence WHERE id = 1")
            .await
            .map_err(store_err)?
            .ok_or_else(|| store_err("store_sequence row missing"))
    }

    fn row_to_key(mut row: Row) -> RecordStoreResult<VirtualKey> {
        let allowed_scopes = assemble_scopes(
            opt_col(&mut row, "allowed_pools")?,
            opt_col(&mut row, "allowed_scopes_ext")?,
        )?;
        let labels: String = col(&mut row, "labels")?;
        let key_group: String = col(&mut row, "key_group")?;
        Ok(VirtualKey {
            id: col(&mut row, "id")?,
            generation_hash: col(&mut row, "generation_hash")?,
            name: col(&mut row, "name")?,
            allowed_scopes,
            enabled: col(&mut row, "enabled")?,
            created_at: col(&mut row, "created_at")?,
            group: Some(key_group).filter(|g| !g.is_empty()),
            labels: serde_json::from_str(&labels).map_err(store_err)?,
            expires_at: opt_col(&mut row, "expires_at")?,
            deleted_at: opt_col(&mut row, "deleted_at")?,
            revision: col(&mut row, "revision")?,
            idp_subject: opt_col(&mut row, "idp_subject")?,
            binding_mode: opt_col(&mut row, "binding_mode")?,
            minted_by: opt_col(&mut row, "minted_by")?,
            idp_provider: opt_col(&mut row, "idp_provider")?,
        })
    }

    /// Reads its columns by NAME, so a caller may first `take` an extra column (`secret`) out of a wider `SELECT`.
    fn row_to_cred_meta(mut row: Row) -> RecordStoreResult<CredentialMeta> {
        let slot: i8 = col(&mut row, "slot")?;
        let secret_form: String = col(&mut row, "secret_form")?;
        Ok(CredentialMeta {
            id: col(&mut row, "id")?,
            key_id: col(&mut row, "key_id")?,
            kind: col(&mut row, "kind")?,
            slot: slot as u8,
            public_id: col(&mut row, "public_id")?,
            secret_form: parse_secret_form(&secret_form)?,
            created_at: col(&mut row, "created_at")?,
            updated_at: col(&mut row, "updated_at")?,
            expires_at: opt_col(&mut row, "expires_at")?,
            revoked_at: opt_col(&mut row, "revoked_at")?,
            revoke_reason: opt_col(&mut row, "revoke_reason")?,
            revision: col(&mut row, "revision")?,
        })
    }
}

/// A required column of `row`, by name.
fn col<T: mysql_common::value::convert::FromValue>(
    row: &mut Row,
    name: &str,
) -> RecordStoreResult<T> {
    match row.take_opt(name) {
        Some(Ok(v)) => Ok(v),
        Some(Err(mut error)) => {
            if let Value::Bytes(bytes) = &mut error.0 {
                zeroize::Zeroize::zeroize(bytes);
            }
            Err(store_err(format!(
                "column {name} does not convert to {}",
                std::any::type_name::<T>()
            )))
        }
        None => Err(store_err(format!("missing column: {name}"))),
    }
}

/// An optional column of `row`, by name: NULL or absent is `None`.
fn opt_col<T: mysql_common::value::convert::FromValue>(
    row: &mut Row,
    name: &str,
) -> RecordStoreResult<Option<T>> {
    match row.take_opt::<Option<T>, _>(name) {
        Some(Ok(v)) => Ok(v),
        Some(Err(mut error)) => {
            if let Value::Bytes(bytes) = &mut error.0 {
                zeroize::Zeroize::zeroize(bytes);
            }
            Err(store_err(format!(
                "column {name} does not convert to {}",
                std::any::type_name::<T>()
            )))
        }
        None => Ok(None),
    }
}

/// `(index, table)` for a `SCHEMA` statement of the form `CREATE INDEX <index> ON <table> (...)`, else `None`.
fn parse_create_index(stmt: &str) -> Option<(&str, &str)> {
    let rest = stmt.trim_start().strip_prefix("CREATE INDEX ")?;
    let mut words = rest.split_whitespace();
    let index = words.next()?;
    if words.next()? != "ON" {
        return None;
    }
    Some((index, words.next()?))
}

fn parse_secret_form(s: &str) -> RecordStoreResult<SecretForm> {
    match s {
        "none" => Ok(SecretForm::None),
        "recoverable" => Ok(SecretForm::Recoverable),
        "digest" => Ok(SecretForm::Digest),
        other => Err(store_err(format!("unknown secret_form '{other}' in store"))),
    }
}

fn secret_form_str(f: &SecretForm) -> &'static str {
    match f {
        SecretForm::None => "none",
        SecretForm::Recoverable => "recoverable",
        SecretForm::Digest => "digest",
    }
}

/// The columns every key read selects, in one place so the three key reads cannot drift apart.
const KEY_COLUMNS: &str = "id, generation_hash, name, allowed_pools, allowed_scopes_ext, labels, \
     enabled, created_at, key_group, expires_at, deleted_at, revision, idp_subject, binding_mode, \
     minted_by, idp_provider";

/// The key write: a new id inserts, an existing one has every field but the id and its creation time replaced.
const KEY_UPSERT: &str = "INSERT INTO api_keys
    (id, name, key_group, allowed_pools, allowed_scopes_ext, labels, enabled, generation_hash,
     created_at, updated_at, expires_at, deleted_at, revision, idp_subject, binding_mode, minted_by,
     idp_provider)
    VALUES (:id, :name, :key_group, :pools, :ext, :labels, :enabled, :gen, :created, :updated,
     :expires, :deleted, :rev, :idp, :binding, :minted_by, :idp_provider)
    ON DUPLICATE KEY UPDATE
     name = VALUES(name), key_group = VALUES(key_group), allowed_pools = VALUES(allowed_pools),
     allowed_scopes_ext = VALUES(allowed_scopes_ext),
     labels = VALUES(labels), enabled = VALUES(enabled), generation_hash = VALUES(generation_hash),
     updated_at = VALUES(updated_at), expires_at = VALUES(expires_at),
     deleted_at = VALUES(deleted_at), revision = VALUES(revision),
     idp_subject = VALUES(idp_subject), binding_mode = VALUES(binding_mode),
     minted_by = VALUES(minted_by), idp_provider = VALUES(idp_provider)";

/// `KEY_UPSERT`'s parameters: `key` at revision `rev`, its tombstone `deleted`.
fn key_params(key: &VirtualKey, deleted: Option<u64>, rev: u64) -> RecordStoreResult<Params> {
    let (pools_json, ext_json) = partition_scopes(&key.allowed_scopes)?;
    let labels_json = serde_json::to_string(&key.labels).map_err(store_err)?;
    Ok(params! {
        "id" => &key.id, "name" => &key.name, "key_group" => key.group.as_deref().unwrap_or(""),
        "pools" => &pools_json, "ext" => &ext_json, "labels" => &labels_json,
        "enabled" => key.enabled, "gen" => &key.generation_hash, "created" => key.created_at,
        "updated" => crate_now()?, "expires" => key.expires_at, "deleted" => deleted,
        "rev" => rev, "idp" => &key.idp_subject, "binding" => &key.binding_mode,
        "minted_by" => &key.minted_by, "idp_provider" => &key.idp_provider,
    })
}

/// Insert `secret` as a new credential row at revision `rev`, in the caller's transaction.
async fn insert_credential(
    tx: &mut Conn,
    op: &str,
    secret: &CredentialSecret,
    rev: u64,
) -> RecordStoreResult<()> {
    let m = &secret.meta;
    tx.exec_drop(
        "INSERT INTO credentials
            (id, key_id, kind, slot, public_id, secret, secret_form, created_at, updated_at,
             expires_at, revoked_at, revoke_reason, revision)
         VALUES (:id, :key, :kind, :slot, :pub, :secret, :form, :created, :updated, :expires,
                 NULL, NULL, :rev)",
        params! {
            "id" => &m.id, "key" => &m.key_id, "kind" => &m.kind, "slot" => m.slot,
            "pub" => &m.public_id, "secret" => &secret.secret,
            "form" => secret_form_str(&m.secret_form),
            "created" => m.created_at, "updated" => m.updated_at, "expires" => m.expires_at,
            "rev" => rev,
        },
    )
    .await
    .map_err(|e| write_err(op, e))
}

/// Write `secret` as a credential row at revision `rev`, in the caller's transaction, for the op named `op` (its refusals name it).
async fn write_credential(
    tx: &mut Conn,
    op: &str,
    secret: &CredentialSecret,
    rev: u64,
) -> RecordStoreResult<()> {
    let m = &secret.meta;

    let own: Option<Row> = tx
        .exec_first(
            "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
             expires_at, revoked_at, revoke_reason, revision, secret FROM credentials \
             WHERE id = :id FOR UPDATE",
            params! { "id" => &m.id },
        )
        .await
        .map_err(store_err)?;
    if let Some(mut row) = own {
        let held = zeroize::Zeroizing::new(opt_col::<String>(&mut row, "secret")?);
        let meta = MysqlStore::row_to_cred_meta(row)?;
        if meta.revoked_at.is_some() {
            return Err(store_err(format!(
                "{op}: credential '{}' is revoked; a revoked credential is never re-minted",
                m.id
            )));
        }
        if (meta.key_id.as_str(), meta.kind.as_str(), meta.slot)
            == (m.key_id.as_str(), m.kind.as_str(), m.slot)
        {
            let same_content = CredentialMeta {
                revision: m.revision,
                ..meta
            } == *m
                && held.as_deref().unwrap_or_default() == secret.secret;
            if same_content {
                return Ok(());
            }
            return Err(store_err(format!(
                "{op}: slot {} for key '{}' kind '{}' holds a live credential; revoke it first",
                m.slot, m.key_id, m.kind
            )));
        }
    }
    let occupied: Option<(Option<u64>,)> = tx
        .exec_first(
            "SELECT revoked_at FROM credentials \
             WHERE key_id = :k AND kind = :kind AND slot = :s FOR UPDATE",
            params! { "k" => &m.key_id, "kind" => &m.kind, "s" => m.slot },
        )
        .await
        .map_err(store_err)?;
    if let Some((None,)) = occupied {
        return Err(store_err(format!(
            "{op}: slot {} for key '{}' kind '{}' holds a live credential; revoke it first",
            m.slot, m.key_id, m.kind
        )));
    }

    let taken: Option<Vec<u8>> = tx
        .exec_first(
            "SELECT id FROM credentials WHERE kind = :kind AND public_id = :pub \
             AND id <> :id AND NOT (key_id = :k AND slot = :s)",
            params! {
                "kind" => &m.kind, "pub" => &m.public_id, "id" => &m.id,
                "k" => &m.key_id, "s" => m.slot,
            },
        )
        .await
        .map_err(store_err)?;
    if taken.is_some() {
        return Err(store_err(format!(
            "{op}: public_id '{}' is already in use for kind '{}'",
            m.public_id, m.kind
        )));
    }
    if occupied.is_some() {
        tx.exec_drop(
            "UPDATE credentials SET
                id = :id, public_id = :pub, secret = :secret, secret_form = :form,
                created_at = :created, updated_at = :updated, expires_at = :expires,
                revoked_at = NULL, revoke_reason = NULL, revision = :rev
             WHERE key_id = :key AND kind = :kind AND slot = :slot",
            params! {
                "id" => &m.id, "key" => &m.key_id, "kind" => &m.kind, "slot" => m.slot,
                "pub" => &m.public_id, "secret" => &secret.secret,
                "form" => secret_form_str(&m.secret_form),
                "created" => m.created_at, "updated" => m.updated_at,
                "expires" => m.expires_at, "rev" => rev,
            },
        )
        .await
        .map_err(|e| write_err(op, e))?;
        Ok(())
    } else {
        insert_credential(tx, op, secret, rev).await
    }
}

/// PARTITION `allowed_scopes` into its two columns: `allowed_pools` (the `pool` kind, a JSON array of bare names -- byte-for-byte the v3 shape, so a 1.5.x node reading a row mid-rolling-upgrade sees exactly the pool grant it always did) and `allowed_scopes_ext` (every OTHER kind, as a JSON array of `[kind, value]` pairs).
fn partition_scopes(
    scopes: &Option<Vec<ScopeRef>>,
) -> RecordStoreResult<(Option<String>, Option<String>)> {
    let Some(list) = scopes else {
        return Ok((None, None));
    };
    let mut pools: Vec<&str> = Vec::new();
    let mut other: Vec<(&str, &str)> = Vec::new();
    for s in list {
        if s.kind == "pool" {
            pools.push(s.value.as_str());
        } else {
            other.push((s.kind.as_str(), s.value.as_str()));
        }
    }
    let pools_json = serde_json::to_string(&pools).map_err(store_err)?;
    let other_json = if other.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&other).map_err(store_err)?)
    };
    Ok((Some(pools_json), other_json))
}

/// The exact inverse of [`partition_scopes`].
fn assemble_scopes(
    pools_json: Option<String>,
    other_json: Option<String>,
) -> RecordStoreResult<Option<Vec<ScopeRef>>> {
    if pools_json.is_none() && other_json.is_none() {
        return Ok(None);
    }
    let mut list: Vec<ScopeRef> = Vec::new();
    if let Some(p) = pools_json {
        let pools: Vec<String> = serde_json::from_str(&p).map_err(store_err)?;
        list.extend(pools.into_iter().map(ScopeRef::pool));
    }
    if let Some(o) = other_json {
        let other: Vec<(String, String)> = serde_json::from_str(&o).map_err(store_err)?;

        list.extend(
            other
                .into_iter()
                .map(|(kind, value)| ScopeRef { kind, value }),
        );
    }
    Ok(Some(list))
}

/// Split a `usage_units` map into the four RESERVED units (which keep their own typed columns -- the v3 layout, so an existing row needs no migration) and the OPEN remainder (which lives in a `*_units` side table).
fn split_units<V: Copy + Default>(units: &BTreeMap<String, V>) -> (V, V, V, V, Vec<(&str, V)>) {
    let get = |k: &str| units.get(k).copied().unwrap_or_default();
    let open = units
        .iter()
        .filter(|(k, _)| !is_reserved_unit(k))
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    (
        get(UNIT_INPUT),
        get(UNIT_OUTPUT),
        get(UNIT_CACHE_READ),
        get(UNIT_CACHE_WRITE),
        open,
    )
}

/// Whole request counters retain the complete unsigned 64-bit range.
const COUNTER_CEILING: &str = "18446744073709551615";

/// The raw usage ledger's full unsigned ceiling, matching `UsageLedger::apply_delta`.
const USAGE_COUNTER_CEILING: &str = "18446744073709551615";

/// SQL for `col` + the inserted row's `col`, pinned at [`COUNTER_CEILING`] instead of erroring.
fn sat_values(col: &str) -> String {
    let held = format!("LEAST({col}, {COUNTER_CEILING})");
    format!("{held} + LEAST(VALUES({col}), {COUNTER_CEILING} - {held})")
}

fn is_reserved_unit(k: &str) -> bool {
    k == UNIT_INPUT || k == UNIT_OUTPUT || k == UNIT_CACHE_READ || k == UNIT_CACHE_WRITE
}

/// Rebuild a name-keyed `usage_units` map from the four reserved columns.
fn reserved_units(
    input: i128,
    output: i128,
    cache_read: i128,
    cache_write: i128,
) -> BTreeMap<String, i128> {
    let mut m = BTreeMap::new();
    for (k, v) in [
        (UNIT_INPUT, input),
        (UNIT_OUTPUT, output),
        (UNIT_CACHE_READ, cache_read),
        (UNIT_CACHE_WRITE, cache_write),
    ] {
        if v != 0 {
            m.insert(k.to_string(), v);
        }
    }
    m
}

impl MysqlStore {
    /// [`busbar_contract::records::RecordStore::add_usage`] on `tx`: the caller's transaction, so a deduped `op_id` write records its `op_id` atomically with the effect.
    pub(crate) async fn add_usage_on(
        tx: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Result<(), ApplyError> {
        let mut delta = delta.clone();
        delta.normalize_scale6().map_err(|e| ApplyError {
            text: e.to_string(),
            server_code: None,
            refused: true,
        })?;
        let delta = &delta;
        let mut checked = Self::get_usage_on(tx, bucket_id, window_start)
            .await
            .map_err(|e| ApplyError {
                text: e.0,
                server_code: None,
                refused: true,
            })?;
        checked.checked_apply_delta(delta).map_err(|e| ApplyError {
            text: e.to_string(),
            server_code: None,
            refused: true,
        })?;

        // Persist the exact checked aggregate under the caller's ledger lock. This shares
        // the replacement path with corrections, preserves request-counter saturation and
        // delegates ordinary refund floor-at-zero semantics to checked_apply_delta.
        Self::put_usage_on(tx, bucket_id, window_start, &checked).await
    }

    /// [`busbar_contract::records::RecordStore::add_metering`] on `tx` (see [`Self::add_usage_on`]).
    pub(crate) async fn add_metering_on(
        tx: &mut Conn,
        delta: &MeteringDelta,
    ) -> Result<(), ApplyError> {
        let mut delta = delta.clone();
        delta.normalize_scale6().map_err(|e| ApplyError {
            text: e.to_string(),
            server_code: None,
            refused: true,
        })?;
        let delta = &delta;
        let quantities = if let Some(mut checked) =
            Self::list_metering_key_on(tx, delta.bucket, Some(&delta.key_id))
                .await
                .map_err(|e| ApplyError {
                    text: e.0,
                    server_code: None,
                    refused: true,
                })?
                .into_iter()
                .find(|row| {
                    row.model == delta.model
                        && row.provider == delta.provider
                        && row.priced_from_ms == delta.priced_from_ms
                        && row.key_group_at_use == delta.key_group_at_use
                        && row.pricing_version == delta.pricing_version
                }) {
            checked.checked_add_delta(delta).map_err(|e| ApplyError {
                text: e.to_string(),
                server_code: None,
                refused: true,
            })?;
            (
                checked.tokens_input,
                checked.tokens_output,
                checked.tokens_cache_read,
                checked.tokens_cache_write,
                checked.usage_units,
            )
        } else {
            (
                delta.tokens_input,
                delta.tokens_output,
                delta.tokens_cache_read,
                delta.tokens_cache_write,
                delta.usage_units.clone(),
            )
        };

        let bucket = format!("{:010}", delta.bucket);

        static STATEMENT_4: LazyLock<String> = LazyLock::new(|| {
            format!(
            "INSERT INTO usage_metering
                (bucket, key_id, provider, model, key_group_at_use, pricing_version, priced_from_ms,
                 requests, billable_requests, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES (:bucket, :key, :provider, :model, :grp, :pv, :pfm, :req, :breq, :ti, :to_, :cr, :cw)
             ON DUPLICATE KEY UPDATE
                requests = {r},
                billable_requests = {br},
                tokens_input = VALUES(tokens_input),
                tokens_output = VALUES(tokens_output),
                tokens_cache_read = VALUES(tokens_cache_read),
                tokens_cache_write = VALUES(tokens_cache_write)",
            r = sat_values("requests"),
            br = sat_values("billable_requests"),
            )
        });
        tx.exec_drop(
            STATEMENT_4.as_str(),
            params! {
                "bucket" => &bucket, "key" => &delta.key_id, "provider" => &delta.provider,
                "model" => &delta.model, "grp" => &delta.key_group_at_use, "pv" => &delta.pricing_version,
                "pfm" => delta.priced_from_ms,
                "req" => delta.requests, "breq" => delta.billable_requests,
                "ti" => quantities.0, "to_" => quantities.1,
                "cr" => quantities.2, "cw" => quantities.3,
            },
        ).await
        .map_err(apply_err)?;

        for (unit, n) in &quantities.4 {
            const STATEMENT_5: &str = "INSERT INTO usage_metering_units
                    (bucket, key_id, provider, model, priced_from_ms, key_group_at_use, pricing_version, unit, count)
                 VALUES (:bucket, :key, :provider, :model, :pfm, :grp, :pv, :unit, :n)
                 ON DUPLICATE KEY UPDATE count = VALUES(count)";
            tx.exec_drop(
                STATEMENT_5,
                params! {
                    "bucket" => &bucket, "key" => &delta.key_id, "provider" => &delta.provider,
                    "model" => &delta.model, "pfm" => delta.priced_from_ms, "unit" => unit, "n" => *n,
                    "grp" => &delta.key_group_at_use, "pv" => &delta.pricing_version,
                },
            ).await
            .map_err(apply_err)?;
        }
        Ok(())
    }

    /// [`busbar_contract::records::RecordStore::append_plane_record`] on `q` (see [`Self::add_usage_on`]).
    pub(crate) async fn append_plane_record_on(
        q: &mut Conn,
        record: &PlaneRecord,
    ) -> Result<(), ApplyError> {
        const MAX_ATTEMPTS: u32 = 3;
        let ident = plane_ident(record);
        for _ in 0..MAX_ATTEMPTS {
            q.exec_drop(
                "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
                 VALUES (:kind, :ident, :seq, :id, :parent, :ts, :terminal, :body) \
                 ON DUPLICATE KEY UPDATE kind = kind",
                plane_params(record, ident, record.seq),
            )
            .await
            .map_err(apply_err)?;
            if q.affected_rows() == 1 {
                return Ok(());
            }
            let existing: Option<PlaneRowTuple> = q
                .exec_first(
                    "SELECT id, parent, ts, terminal, body FROM plane_records \
                     WHERE kind = :kind AND ident = :ident AND seq = :seq",
                    params! { "kind" => &record.kind, "ident" => ident, "seq" => record.seq },
                )
                .await
                .map_err(apply_err)?;
            let Some((id, parent, ts, terminal, body)) = existing else {
                continue;
            };
            if id == record.id
                && parent == record.parent
                && ts == record.ts
                && terminal == is_terminal(record.disposition)
                && body == record.body
            {
                return Ok(());
            }

            return Err(ApplyError::text(
                fork::chain_fork(&record.kind, ident, record.seq).0,
            ));
        }
        Err(ApplyError::text(format!(
            "append_plane_record: kind '{}' seq {} kept being freed between the insert and the \
             read-back after {MAX_ATTEMPTS} attempts; the record was NOT stored",
            record.kind, record.seq
        )))
    }
}

/// The base op set (the kind slots, `abi::store::slot`), each one body on the op's connection.
impl MysqlStore {
    pub(crate) async fn put_key(conn: &mut Conn, key: &VirtualKey) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx).await?;

        // TOMBSTONE PRECONDITION (see `RecordStore::put_key`): a live-shaped write must not overwrite a
        // tombstoned row, which would reissue an id the contract says is never reissued and revive
        // every token minted before the delete.
        //
        // `ON DUPLICATE KEY UPDATE` takes no WHERE, so unlike the other SQL backends this cannot
        // ride on the upsert itself. `SELECT ... FOR UPDATE` inside the transaction is equivalent
        // here and is the idiom this file already uses for exactly this problem (`delete_key`,
        // `revoke_credential`, `write_credential`'s slot guard): the row lock is held to commit, so
        // the test and the write are atomic and a concurrent `delete_key` cannot land in between.
        // Ordered AFTER `bump_revision` to keep the crate's fixed lock order, store_sequence before
        // api_keys.
        if key.deleted_at.is_none() {
            let existing: Option<(Option<u64>,)> = tx
                .exec_first(
                    "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                    params! { "id" => &key.id },
                )
                .await
                .map_err(store_err)?;
            if let Some((Some(_),)) = existing {
                return Err(refusal_after_rollback(
                    store_err(format!(
                        "put_key: '{}' is tombstoned and its id is never reissued; refusing to clear \
                     the tombstone",
                        key.id
                    )),
                    tx.rollback().await,
                ));
            }
        }

        tx.exec_drop(KEY_UPSERT, key_params(key, key.deleted_at, rev)?)
            .await
            .map_err(store_err)?;

        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn get_key(
        conn: &mut Conn,
        id: &str,
    ) -> RecordStoreResult<Option<VirtualKey>> {
        let row: Option<Row> = conn
            .exec_first(
                format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE id = :id"),
                params! { "id" => id },
            )
            .await
            .map_err(store_err)?;
        row.map(Self::row_to_key).transpose()
    }

    pub(crate) async fn list_keys(conn: &mut Conn) -> RecordStoreResult<Vec<VirtualKey>> {
        let rows: Vec<Row> = conn
            .query(format!(
                "SELECT {KEY_COLUMNS} FROM api_keys ORDER BY created_at, id"
            ))
            .await
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_key).collect()
    }

    pub(crate) async fn list_keys_since(
        conn: &mut Conn,
        since: u64,
    ) -> RecordStoreResult<Vec<VirtualKey>> {
        let rows: Vec<Row> = conn
            .exec(
                format!(
                    "SELECT {KEY_COLUMNS} FROM api_keys WHERE revision > :since OR revision = 0 \
                     ORDER BY revision, id"
                ),
                params! { "since" => since },
            )
            .await
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_key).collect()
    }

    /// TOMBSTONE, not row removal — see the trait doc.
    pub(crate) async fn delete_key(conn: &mut Conn, id: &str) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;

        let rev = Self::bump_revision(&mut tx).await?;

        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .await
            .map_err(store_err)?;
        let Some((deleted_at,)) = existing else {
            return Err(refusal_after_rollback(
                store_err(format!("delete_key: unknown id '{id}'")),
                tx.rollback().await,
            ));
        };
        if deleted_at.is_some() {
            tx.rollback().await.map_err(store_err)?;
            return Ok(());
        }

        let now = crate_now()?;

        tx.exec_drop(
            "DELETE FROM credentials WHERE key_id = :id",
            params! { "id" => id },
        )
        .await
        .map_err(store_err)?;

        tx.exec_drop(
            "UPDATE api_keys SET enabled = FALSE, deleted_at = :now, updated_at = :now, revision = :rev \
             WHERE id = :id",
            params! { "now" => now, "rev" => rev, "id" => id },
        ).await
        .map_err(store_err)?;

        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn get_usage(
        conn: &mut Conn,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<UsageLedger> {
        let mut tx = conn.start_snapshot().await.map_err(store_err)?;
        let ledger = Self::get_usage_on(&mut tx, bucket_id, window_start).await?;
        tx.commit().await.map_err(store_err)?;
        Ok(ledger)
    }

    pub(crate) async fn get_usage_on(
        tx: &mut Conn,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<UsageLedger> {
        let rows: Vec<(String, i128, i128, i128, i128)> = tx
            .exec(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write \
                 FROM usage_windows WHERE window_start = :w AND bucket_scope = 'key' \
                 AND bucket_id = :b AND (model <> '' OR tokens_input <> 0 \
                 OR tokens_output <> 0 OR tokens_cache_read <> 0 OR tokens_cache_write <> 0)",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .await
            .map_err(store_err)?;

        let totals: Option<(u64, u64)> = tx
            .exec_first(
                "SELECT COALESCE(SUM(requests), 0), COALESCE(SUM(billable_requests), 0) \
                 FROM usage_windows WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .await
            .map_err(store_err)?;
        let (requests, billable_requests) = totals.unwrap_or((0, 0));

        let open: Vec<(String, String, i128)> = tx
            .exec(
                "SELECT model, unit, count FROM usage_window_units \
                 WHERE bucket_id = :b AND window_start = :w AND bucket_scope = 'key' \
                 ORDER BY model, unit",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .await
            .map_err(store_err)?;
        let mut models: Vec<ModelTokens> = rows
            .into_iter()
            .map(
                |(model, input, output, cache_read, cache_write)| ModelTokens {
                    scale: 6,
                    model,
                    usage_units: reserved_units(input, output, cache_read, cache_write),
                },
            )
            .collect();
        let mut by_model: BTreeMap<String, usize> = models
            .iter()
            .enumerate()
            .map(|(index, model)| (model.model.clone(), index))
            .collect();
        for (model, unit, count) in open {
            if count == 0 {
                continue;
            }
            let idx = match by_model.get(&model) {
                Some(&i) => i,
                None => {
                    by_model.insert(model.clone(), models.len());
                    models.push(ModelTokens {
                        scale: 6,
                        model,
                        ..Default::default()
                    });
                    models.len() - 1
                }
            };
            models[idx].usage_units.insert(unit, count);
        }

        let mut ledger = UsageLedger {
            requests,
            billable_requests,
            models,
        };
        ledger.normalize_scale6().map_err(store_err)?;
        Ok(ledger)
    }

    pub(crate) async fn purge_usage_before(conn: &mut Conn, before: u64) -> RecordStoreResult<u64> {
        if before == 0 {
            return Ok(0);
        }
        const ATTEMPTS: u32 = 3;
        const ER_LOCK_DEADLOCK: u16 = 1213;
        let mut attempt = 1;
        let mut total = 0;
        loop {
            match Self::purge_usage_once(conn, before).await {
                Err(e) if e.server_code == Some(ER_LOCK_DEADLOCK) && attempt < ATTEMPTS => {
                    attempt += 1;
                }
                Err(e) => return Err(RecordStoreError(e.text)),
                Ok(removed) => {
                    total += removed;
                    if removed < PURGE_BATCH as u64 {
                        return Ok(total);
                    }
                    attempt = 1;
                }
            }
        }
    }

    async fn purge_usage_once(conn: &mut Conn, before: u64) -> Result<u64, ApplyError> {
        conn.query_drop("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .await
            .map_err(apply_err)?;
        let mut tx = conn.start_transaction().await.map_err(apply_err)?;
        slots::lock_ledger_sequence(&mut tx).await?;
        let keys: Vec<(u64, Vec<u8>, Vec<u8>)> = tx
            .exec(
                format!(
                    "SELECT DISTINCT window_start,bucket_scope,bucket_id FROM usage_windows
                WHERE window_start > 0 AND window_start < :before
                ORDER BY window_start,bucket_scope,bucket_id LIMIT {PURGE_BATCH}"
                ),
                params! { "before" => before },
            )
            .await
            .map_err(apply_err)?;
        let removed = keys.len() as u64;
        for (window, scope, bucket) in keys {
            for table in ["usage_windows", "usage_window_units"] {
                tx.exec_drop(format!("DELETE FROM {table} WHERE window_start=:window AND bucket_scope=:scope AND bucket_id=:bucket"),
                    params! { "window" => window, "scope" => &scope, "bucket" => &bucket })
                    .await.map_err(apply_err)?;
            }
        }
        tx.commit().await.map_err(apply_err)?;
        Ok(removed)
    }

    /// [`Self::put_usage_once`], retried when this transaction loses a deadlock (its delete and insert hold the window's gap against a concurrent first write on the same window).
    pub(crate) async fn put_usage(
        conn: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        if busbar_contract::abi::sdk::store::correction::reserved_bucket(bucket_id) {
            return Err(store_err("reserved usage correction bucket"));
        }
        const ATTEMPTS: u32 = 3;
        const ER_LOCK_DEADLOCK: u16 = 1213;
        let mut attempt = 1;
        loop {
            match Self::put_usage_once(conn, bucket_id, window_start, ledger).await {
                Err(e) if e.server_code == Some(ER_LOCK_DEADLOCK) && attempt < ATTEMPTS => {
                    attempt += 1;
                }
                other => return other.map_err(|e| RecordStoreError(e.text)),
            }
        }
    }

    async fn put_usage_once(
        conn: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Result<(), ApplyError> {
        let mut tx = conn.start_transaction().await.map_err(apply_err)?;
        slots::lock_ledger_sequence(&mut tx).await?;
        Self::put_usage_on(&mut tx, bucket_id, window_start, ledger).await?;
        tx.commit().await.map_err(apply_err)
    }

    /// Absolute replacement within the caller's locked transaction, preserving unsigned counters.
    pub(crate) async fn put_usage_on(
        tx: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Result<(), ApplyError> {
        let mut ledger = ledger.clone();
        ledger.normalize_scale6().map_err(|e| ApplyError {
            text: e.to_string(),
            server_code: None,
            refused: true,
        })?;
        let ledger = &ledger;

        tx.exec_drop(
            "DELETE FROM usage_windows \
             WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
            params! { "b" => bucket_id, "w" => window_start },
        )
        .await
        .map_err(apply_err)?;

        tx.exec_drop(
            "DELETE FROM usage_window_units \
             WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
            params! { "b" => bucket_id, "w" => window_start },
        )
        .await
        .map_err(apply_err)?;

        tx.exec_drop(
            "INSERT INTO usage_windows
                (window_start, bucket_scope, bucket_id, model, requests, billable_requests)
             VALUES (:w, 'key', :b, '', :req, :breq)
             ON DUPLICATE KEY UPDATE
                requests = VALUES(requests), billable_requests = VALUES(billable_requests)",
            params! {
                "w" => window_start, "b" => bucket_id,
                "req" => ledger.requests, "breq" => ledger.billable_requests,
            },
        )
        .await
        .map_err(apply_err)?;

        let mut models: Vec<&ModelTokens> = ledger.models.iter().collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        for m in models {
            let (ti, to, cr, cw, open) = split_units(&m.usage_units);

            let statement = if m.model.is_empty() {
                "UPDATE usage_windows SET tokens_input=:ti, tokens_output=:to_,
                 tokens_cache_read=:cr, tokens_cache_write=:cw
                 WHERE window_start=:w AND bucket_scope='key' AND bucket_id=:b AND model=:model"
            } else {
                "INSERT INTO usage_windows
                    (window_start, bucket_scope, bucket_id, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (:w, 'key', :b, :model, :ti, :to_, :cr, :cw)"
            };
            tx.exec_drop(
                statement,
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "ti" => ti, "to_" => to, "cr" => cr, "cw" => cw,
                },
            )
            .await
            .map_err(apply_err)?;

            for (unit, count) in open {
                tx.exec_drop(
                    "INSERT INTO usage_window_units
                        (window_start, bucket_scope, bucket_id, model, unit, count)
                     VALUES (:w, 'key', :b, :model, :unit, :n)",
                    params! {
                        "w" => window_start, "b" => bucket_id, "model" => &m.model,
                        "unit" => unit, "n" => count,
                    },
                )
                .await
                .map_err(apply_err)?;
            }
        }
        Ok(())
    }

    pub(crate) async fn list_metering(
        conn: &mut Conn,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let mut tx = conn.start_snapshot().await.map_err(store_err)?;
        let rows = Self::list_metering_on(&mut tx, bucket).await?;
        tx.commit().await.map_err(store_err)?;
        Ok(rows)
    }

    pub(crate) async fn list_metering_on(
        tx: &mut Conn,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        Self::list_metering_key_on(tx, bucket, None).await
    }

    pub(crate) async fn list_metering_key_on(
        tx: &mut Conn,
        bucket: u64,
        key: Option<&str>,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let bucket_s = format!("{bucket:010}");
        let rows: Vec<Row> = tx
            .exec(
                "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read, \
                 tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version, \
                 priced_from_ms FROM usage_metering WHERE bucket = :b AND (:key IS NULL OR key_id = :key)",
                params! { "b" => &bucket_s, "key" => key },
            ).await
            .map_err(store_err)?;
        type MeteringUnitRow = (String, String, String, u64, String, String, String, i128);
        type MeteringCell = (String, String, String, u64, String, String);
        let units: Vec<MeteringUnitRow> = tx
            .exec(


                "SELECT m.key_id, m.model, m.provider, m.priced_from_ms, m.key_group_at_use, m.pricing_version, u.unit, u.count \
                 FROM usage_metering_units u JOIN usage_metering m \
                 ON m.bucket = u.bucket AND m.key_id = u.key_id AND m.model = u.model \
                 AND m.provider = u.provider AND m.priced_from_ms = u.priced_from_ms \
                 AND m.key_group_at_use = u.key_group_at_use AND m.pricing_version = u.pricing_version \
                 WHERE u.bucket = :b AND (:key IS NULL OR u.key_id = :key)",
                params! { "b" => &bucket_s, "key" => key },
            )
            .await
            .map_err(store_err)?;

        let mut by_cell: BTreeMap<MeteringCell, BTreeMap<String, i128>> = BTreeMap::new();
        for (key_id, model, provider, pfm, group, version, unit, count) in units {
            if count == 0 {
                continue;
            }
            by_cell
                .entry((key_id, model, provider, pfm, group, version))
                .or_default()
                .insert(unit, count);
        }
        rows.into_iter()
            .map(|mut r| {
                let (key_id, model, provider): (String, String, String) = (
                    col(&mut r, "key_id")?,
                    col(&mut r, "model")?,
                    col(&mut r, "provider")?,
                );
                let priced_from_ms = col(&mut r, "priced_from_ms")?;
                let key_group_at_use: String = col(&mut r, "key_group_at_use")?;
                let pricing_version: String = col(&mut r, "pricing_version")?;
                let cell = (
                    key_id.clone(),
                    model.clone(),
                    provider.clone(),
                    priced_from_ms,
                    key_group_at_use.clone(),
                    pricing_version.clone(),
                );
                let mut row = MeteringRow {
                    scale: 6,
                    usage_units: by_cell.remove(&cell).unwrap_or_default(),
                    key_id,
                    model,
                    provider,
                    tokens_input: col(&mut r, "tokens_input")?,
                    tokens_output: col(&mut r, "tokens_output")?,
                    tokens_cache_read: col(&mut r, "tokens_cache_read")?,
                    tokens_cache_write: col(&mut r, "tokens_cache_write")?,
                    requests: col(&mut r, "requests")?,
                    billable_requests: col(&mut r, "billable_requests")?,
                    key_group_at_use,
                    pricing_version,
                    priced_from_ms,
                };
                row.normalize_scale6().map_err(store_err)?;
                Ok(row)
            })
            .collect()
    }

    pub(crate) async fn put_credential(
        conn: &mut Conn,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx).await?;
        let m = &secret.meta;

        let owner: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :k FOR UPDATE",
                params! { "k" => &m.key_id },
            )
            .await
            .map_err(store_err)?;
        let refused = match owner {
            None => Some(format!(
                "put_credential: key '{}' does not exist; a credential must hang off a real key",
                m.key_id
            )),
            Some((Some(_),)) => Some(format!(
                "put_credential: key '{}' is tombstoned; its credentials were revoked with it and \
                 are never reissued",
                m.key_id
            )),
            Some((None,)) => None,
        };
        if let Some(text) = refused {
            return Err(refusal_after_rollback(store_err(text), tx.rollback().await));
        }
        if let Err(e) = write_credential(&mut tx, "put_credential", secret, rev).await {
            return Err(refusal_after_rollback(e, tx.rollback().await));
        }
        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn rewrap_credential(
        conn: &mut Conn,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        if expected.meta.revoked_at.is_some()
            || expected.meta.secret_form != SecretForm::Recoverable
            || expected.secret == replacement
        {
            return Ok(false);
        }
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let result = async {


            let sequence: Option<u64> = tx
                .query_first("SELECT revision FROM store_sequence WHERE id=1 FOR UPDATE")
                .await
                .map_err(store_err)?;
            if sequence.is_none() {
                return Err(store_err("store_sequence row missing"));
            }
            let owner: Option<(Option<u64>,)> = tx
                .exec_first(
                    "SELECT deleted_at FROM api_keys WHERE id=:id FOR UPDATE",
                    params! { "id" => &expected.meta.key_id },
                )
                .await
                .map_err(store_err)?;
            if !matches!(owner, Some((None,))) {
                return Ok(false);
            }
            let row: Option<Row> = tx
                .exec_first(
                    "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                     expires_at, revoked_at, revoke_reason, revision, secret FROM credentials \
                     WHERE id=:id FOR UPDATE",
                    params! { "id" => &expected.meta.id },
                )
                .await
                .map_err(store_err)?;
            let matches = if let Some(mut row) = row {
                let secret = zeroize::Zeroizing::new(opt_col::<String>(&mut row, "secret")?);
                Self::row_to_cred_meta(row)? == expected.meta
                    && secret.as_deref() == Some(expected.secret.as_str())
            } else {
                false
            };
            if !matches {
                return Ok(false);
            }
            let revision = Self::bump_revision(&mut tx).await?;
            tx.exec_drop(
                "UPDATE credentials SET secret=:secret, revision=:rev WHERE id=:id",
                params! { "secret" => replacement, "rev" => revision, "id" => &expected.meta.id },
            )
            .await
            .map_err(store_err)?;
            if tx.affected_rows() != 1 {
                return Err(store_err("credential rewrap lost its locked row"));
            }
            Ok(true)
        }.await;
        match result {
            Ok(applied) => {
                tx.commit().await.map_err(store_err)?;
                Ok(applied)
            }
            Err(error) => Err(refusal_after_rollback(error, tx.rollback().await)),
        }
    }

    pub(crate) async fn put_key_with_credential(
        conn: &mut Conn,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        const OP: &str = "put_key_with_credential";

        if key.deleted_at.is_some() {
            return Err(store_err(format!(
                "{OP}: key '{}' is tombstoned; a credential is never minted onto it",
                key.id
            )));
        }
        if secret.meta.key_id != key.id {
            return Err(store_err(format!(
                "{OP}: the credential names key '{}', not the key '{}' being minted with it",
                secret.meta.key_id, key.id
            )));
        }
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx).await?;
        let stored: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => &key.id },
            )
            .await
            .map_err(store_err)?;
        if let Some((Some(_),)) = stored {
            return Err(refusal_after_rollback(
                store_err(format!(
                    "{OP}: '{}' is tombstoned and its id is never reissued",
                    key.id
                )),
                tx.rollback().await,
            ));
        }
        tx.exec_drop(KEY_UPSERT, key_params(key, None, rev)?)
            .await
            .map_err(store_err)?;
        if let Err(e) = write_credential(&mut tx, OP, secret, rev).await {
            return Err(refusal_after_rollback(e, tx.rollback().await));
        }
        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn list_credentials(
        conn: &mut Conn,
        key_id: &str,
    ) -> RecordStoreResult<Vec<CredentialMeta>> {
        let rows: Vec<Row> = conn
            .exec(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision FROM credentials WHERE key_id = :k \
                 ORDER BY kind, slot",
                params! { "k" => key_id },
            ).await
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_cred_meta).collect()
    }

    pub(crate) async fn revoke_credential(
        conn: &mut Conn,
        id: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx).await?;

        // Explicit existence check, matching every other conditional mutation in this file
        // (e.g. write_credential's slot guard): `rows_affected()` alone can't distinguish "id
        // doesn't exist" from "id exists but already revoked" -- the `AND revoked_at IS NULL`
        // clause below makes both cases match zero rows. Without this, revoking an unknown/
        // typo'd id silently reported success.
        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT revoked_at FROM credentials WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .await
            .map_err(store_err)?;
        let Some((revoked_at,)) = existing else {
            return Err(refusal_after_rollback(
                store_err(format!("revoke_credential: unknown id '{id}'")),
                tx.rollback().await,
            ));
        };
        if revoked_at.is_some() {
            tx.rollback().await.map_err(store_err)?;
            return Ok(());
        }

        let now = crate_now()?;
        tx.exec_drop(
            "UPDATE credentials SET secret = NULL, secret_form = 'none', revoked_at = :now, \
             revoke_reason = :reason, updated_at = :now, revision = :rev WHERE id = :id",
            params! { "now" => now, "reason" => reason, "rev" => rev, "id" => id },
        )
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn list_credentials_since(
        conn: &mut Conn,
        since: u64,
    ) -> RecordStoreResult<Vec<CredentialSecret>> {
        let rows: Vec<Row> = conn
            .exec(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision, secret FROM credentials \
                 WHERE revision > :since OR revision = 0",
                params! { "since" => since },
            )
            .await
            .map_err(store_err)?;
        struct PendingRows(Vec<Row>);
        impl Drop for PendingRows {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                for row in &mut self.0 {
                    if let Some(Value::Bytes(mut secret)) = row.take::<Value, _>("secret") {
                        secret.zeroize();
                    }
                }
            }
        }
        let mut rows = PendingRows(rows);
        let mut credentials = Vec::with_capacity(rows.0.len());
        while let Some(mut row) = rows.0.pop() {
            let secret =
                zeroize::Zeroizing::new(opt_col::<String>(&mut row, "secret")?.unwrap_or_default());
            let meta = Self::row_to_cred_meta(row)?;
            credentials.push((meta, secret));
        }
        credentials.reverse();
        Ok(credentials
            .into_iter()
            .map(|(meta, mut secret)| CredentialSecret {
                meta,
                secret: std::mem::take(&mut *secret),
            })
            .collect())
    }

    pub(crate) async fn list_audit(conn: &mut Conn) -> RecordStoreResult<Vec<AuditRecord>> {
        let rows: Vec<AuditRowTuple> = conn
            .query("SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq").await
            .map_err(store_err)?;
        Ok(rows.into_iter().map(audit_from_row).collect())
    }

    pub(crate) async fn list_audit_tail(
        conn: &mut Conn,
        limit: u64,
    ) -> RecordStoreResult<Vec<AuditRecord>> {
        let rows: Vec<AuditRowTuple> = conn
            .exec(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log \
                 ORDER BY seq DESC LIMIT :limit",
                params! { "limit" => limit },
            ).await
            .map_err(store_err)?;
        let mut out: Vec<AuditRecord> = rows.into_iter().map(audit_from_row).collect();
        out.reverse();
        Ok(out)
    }

    pub(crate) async fn add_denylist(
        conn: &mut Conn,
        sub: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx).await?;
        let now = crate_now()?;
        let max_ttl: u64 = 90 * 24 * 3600;
        tx.exec_drop(
            "INSERT INTO denylist (sub, reason, revoked_at, expires_at, revision) \
             VALUES (:sub, :reason, :now, :expires, :rev) \
             ON DUPLICATE KEY UPDATE reason = VALUES(reason), revoked_at = VALUES(revoked_at), expires_at = GREATEST(expires_at, VALUES(expires_at)), revision = VALUES(revision)",
            params! {
                "sub" => sub, "reason" => reason, "now" => now, "expires" => now + max_ttl, "rev" => rev,
            },
        ).await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn list_denylist(conn: &mut Conn) -> RecordStoreResult<Vec<String>> {
        conn.query("SELECT sub FROM denylist")
            .await
            .map_err(store_err)
    }

    pub(crate) async fn upsert_plane_record(
        conn: &mut Conn,
        record: &PlaneRecord,
    ) -> RecordStoreResult<()> {
        storable_i64("upsert_plane_record", "seq", record.seq)?;
        storable_i64("upsert_plane_record", "ts", record.ts)?;

        conn.exec_drop(
            "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
             VALUES (:kind, :ident, :seq, :id, :parent, :ts, :terminal, :body) \
             ON DUPLICATE KEY UPDATE id = VALUES(id), parent = VALUES(parent), ts = VALUES(ts), \
                terminal = VALUES(terminal), body = VALUES(body)",
            plane_params(record, &record.id, UPSERT_SEQ),
        )
        .await
        .map_err(store_err)
    }

    pub(crate) async fn get_plane_record(
        conn: &mut Conn,
        kind: &str,
        id: &str,
    ) -> RecordStoreResult<Option<Vec<u8>>> {
        conn.exec_first(
            "SELECT body FROM plane_records WHERE kind = :kind AND ident = :id AND seq = :seq",
            params! { "kind" => kind, "id" => id, "seq" => UPSERT_SEQ },
        )
        .await
        .map_err(store_err)
    }

    pub(crate) async fn list_plane_records(
        conn: &mut Conn,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        match selector {
            PlaneSelector::All => {
                conn.exec(
                    "SELECT body FROM plane_records WHERE kind = :kind ORDER BY seq, ident",
                    params! { "kind" => kind },
                )
                .await
            }
            PlaneSelector::Parent(parent) => {
                conn.exec(
                    "SELECT body FROM plane_records \
                 WHERE kind = :kind AND parent = :parent ORDER BY seq",
                    params! { "kind" => kind, "parent" => parent.as_ref() },
                )
                .await
            }
        }
        .map_err(store_err)
    }

    pub(crate) async fn list_plane_record_parents(
        conn: &mut Conn,
        kind: &str,
    ) -> RecordStoreResult<Vec<String>> {
        conn.exec(
            "SELECT DISTINCT parent FROM plane_records \
             WHERE kind = :kind AND parent IS NOT NULL ORDER BY parent",
            params! { "kind" => kind },
        )
        .await
        .map_err(store_err)
    }

    pub(crate) async fn purge_plane_records_before(
        conn: &mut Conn,
        kind: &str,
        before: u64,
    ) -> RecordStoreResult<u64> {
        let retention = if kind == KIND_TASK {
            Retention::TerminalOnly
        } else {
            Retention::Age
        };
        Self::purge_plane_records(conn, kind, before, retention).await
    }

    /// Purge records older than the cutoff in bounded batches, retaining nonterminal rows when requested.
    /// Ticket retention samples the database clock while holding the replay lock for each batch.
    pub(crate) async fn purge_plane_records(
        conn: &mut Conn,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        if kind != TICKET_RECORD_KIND {
            return Self::purge_plane_records_on(conn, kind, before, retention).await;
        }
        let mut total = 0;
        loop {
            let mut tx = conn.start_transaction().await.map_err(store_err)?;
            Self::lock_replay_sequence(&mut tx).await?;
            let cutoff = before.min(Self::database_now(&mut tx).await?);
            let terminal = if retention == Retention::TerminalOnly {
                " AND terminal"
            } else {
                ""
            };
            tx.exec_drop(format!("DELETE FROM plane_records WHERE kind=:kind AND ts<:before{terminal} LIMIT {PURGE_BATCH}"),
                params! { "kind" => kind, "before" => cutoff }).await.map_err(store_err)?;
            let removed = tx.affected_rows();
            tx.commit().await.map_err(store_err)?;
            total += removed;
            if removed < PURGE_BATCH as u64 {
                return Ok(total);
            }
        }
    }

    async fn purge_plane_records_on(
        conn: &mut Conn,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        let terminal_only = retention == Retention::TerminalOnly;

        if kind == KIND_TASK {
            return Self::purge_tasks(conn, before, terminal_only).await;
        }

        let mut total = 0u64;
        loop {
            let terminal = if terminal_only { " AND terminal" } else { "" };
            let keys: Vec<(Vec<u8>, u64)> = conn
                .exec(
                    format!(
                        "SELECT ident, seq FROM plane_records \
                         WHERE kind = :kind AND ts < :before{terminal} \
                         ORDER BY ts, ident, seq LIMIT {PURGE_BATCH}"
                    ),
                    params! { "kind" => kind, "before" => before },
                )
                .await
                .map_err(store_err)?;
            if keys.is_empty() {
                break;
            }
            let mut args: Vec<Value> = vec![kind.into()];
            for (ident, seq) in &keys {
                args.push(ident.as_slice().into());
                args.push((*seq).into());
            }
            args.push(before.into());
            conn.exec_drop(
                format!(
                    "DELETE /*+ INDEX(plane_records PRIMARY) */ FROM plane_records \
                     WHERE kind = ? AND (ident, seq) IN ({}) \
                     AND ts < ?{terminal}",
                    vec!["(?, ?)"; keys.len()].join(", ")
                ),
                Params::Positional(args),
            )
            .await
            .map_err(store_err)?;
            let n = conn.affected_rows();
            total += n;
            if keys.len() < PURGE_BATCH || n == 0 {
                break;
            }
        }
        Ok(total)
    }

    /// The `task` rows strictly older than `before` (the TERMINAL ones only when `terminal_only`),
    /// each with its `task_event` chain, in batches: an interrupted task waiting on a human must
    /// survive a terminal-only sweep. A batch's candidates come
    /// from a non-locking read; the transaction then locks them by primary key with the predicate
    /// re-checked (a concurrent sweep may have taken some) and deletes those, so concurrent sweeps
    /// take record locks only. Returns the tasks removed.
    async fn purge_tasks(
        conn: &mut Conn,
        before: u64,
        terminal_only: bool,
    ) -> RecordStoreResult<u64> {
        let terminal = if terminal_only { " AND terminal" } else { "" };
        let mut removed = 0u64;
        loop {
            let candidates: Vec<Vec<u8>> = conn
                .exec(
                    format!(
                        "SELECT ident FROM plane_records WHERE kind = :kind AND seq = :seq \
                         AND ts < :before{terminal} ORDER BY ts, ident LIMIT {PURGE_BATCH}"
                    ),
                    params! { "kind" => KIND_TASK, "before" => before, "seq" => UPSERT_SEQ },
                )
                .await
                .map_err(store_err)?;
            if candidates.is_empty() {
                break;
            }
            let marks = vec!["?"; candidates.len()].join(", ");
            let mut tx = conn.start_transaction().await.map_err(store_err)?;
            let mut args: Vec<Value> = vec![KIND_TASK.into(), UPSERT_SEQ.into()];
            args.extend(candidates.iter().map(|c| Value::from(c.as_slice())));
            args.push(before.into());
            let eligible: Vec<Vec<u8>> = tx
                .exec(
                    format!(
                        "SELECT /*+ INDEX(plane_records PRIMARY) */ ident FROM plane_records \
                         WHERE kind = ? AND seq = ? \
                         AND ident IN ({marks}) AND ts < ?{terminal} FOR UPDATE"
                    ),
                    Params::Positional(args),
                )
                .await
                .map_err(store_err)?;
            if !eligible.is_empty() {
                let marks = vec!["?"; eligible.len()].join(", ");
                for (kind, seq_clause) in [(KIND_TASK, " AND seq = ?"), (KIND_TASK_EVENT, "")] {
                    let mut args: Vec<Value> = vec![kind.into()];
                    args.extend(eligible.iter().map(|c| Value::from(c.as_slice())));
                    if !seq_clause.is_empty() {
                        args.push(UPSERT_SEQ.into());
                    }
                    tx.exec_drop(
                        format!(
                            "DELETE /*+ INDEX(plane_records PRIMARY) */ FROM plane_records \
                             WHERE kind = ? AND ident IN ({marks}){seq_clause}"
                        ),
                        Params::Positional(args),
                    )
                    .await
                    .map_err(store_err)?;
                }
            }
            tx.commit().await.map_err(store_err)?;
            removed += eligible.len() as u64;
            if candidates.len() < PURGE_BATCH || eligible.is_empty() {
                break;
            }
        }
        Ok(removed)
    }

    pub(crate) async fn delete_plane_record(
        conn: &mut Conn,
        kind: &str,
        id: &str,
    ) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        if kind == KIND_TASK {
            tx.exec_drop(
                "DELETE FROM plane_records WHERE kind = :kind AND ident = :id",
                params! { "kind" => KIND_TASK_EVENT, "id" => id },
            )
            .await
            .map_err(store_err)?;
        }
        tx.exec_drop(
            "DELETE FROM plane_records WHERE kind = :kind AND ident = :id",
            params! { "kind" => kind, "id" => id },
        )
        .await
        .map_err(store_err)?;
        tx.commit().await.map_err(store_err)
    }

    async fn lock_replay_sequence(conn: &mut Conn) -> RecordStoreResult<()> {
        let sequence: Option<u64> = conn
            .query_first("SELECT revision FROM store_sequence WHERE id=1 FOR UPDATE")
            .await
            .map_err(store_err)?;
        if sequence.is_none() {
            return Err(store_err("store_sequence row missing"));
        }
        Ok(())
    }

    async fn database_now(conn: &mut Conn) -> RecordStoreResult<u64> {
        conn.query_first("SELECT UNIX_TIMESTAMP()")
            .await
            .map_err(store_err)?
            .ok_or_else(|| store_err("database clock returned no value"))
    }

    pub(crate) async fn redeem_plane_token(
        conn: &mut Conn,
        kind: &str,
        token: &str,
        expires_at: u64,
        _caller_now: u64,
    ) -> RecordStoreResult<bool> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;

        Self::lock_replay_sequence(&mut tx).await?;
        let store_now = Self::database_now(&mut tx).await?;
        if expires_at < store_now {
            tx.rollback().await.map_err(store_err)?;
            return Ok(false);
        }
        tx.exec_drop(
            "DELETE FROM plane_tokens WHERE kind = :kind AND token = :token AND expires_at < :now",
            params! { "kind" => kind, "token" => token, "now" => store_now },
        )
        .await
        .map_err(store_err)?;
        tx.exec_drop(
            format!(
                "DELETE FROM plane_tokens WHERE kind=:kind AND expires_at<:now LIMIT {PURGE_BATCH}"
            ),
            params! { "kind" => kind, "now" => store_now },
        )
        .await
        .map_err(store_err)?;
        tx.exec_drop(
            "INSERT INTO plane_tokens (kind, token, expires_at) VALUES (:kind, :token, :exp)
             ON DUPLICATE KEY UPDATE token = token",
            params! { "kind" => kind, "token" => token, "exp" => expires_at },
        )
        .await
        .map_err(store_err)?;
        let inserted = tx.affected_rows() == 1;
        tx.commit().await.map_err(store_err)?;
        Ok(inserted)
    }

    pub(crate) async fn plane_token_live(
        conn: &mut Conn,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        if kind == TICKET_RECORD_KIND {
            let result: Option<(u64, bool)> = conn.exec_first(
                "SELECT UNIX_TIMESTAMP(), EXISTS(SELECT 1 FROM plane_records WHERE kind=:kind AND ident=:token AND seq=:seq AND ts=:deadline AND terminal)",
                params! { "kind"=>kind, "token"=>token, "seq"=>UPSERT_SEQ, "deadline"=>expires_at },
            ).await.map_err(store_err)?;
            let (store_now, terminal) =
                result.ok_or_else(|| store_err("database clock returned no value"))?;
            return Ok(expires_at >= store_now && terminal);
        }

        if now > expires_at {
            return Ok(false);
        }
        let terminal: Option<bool> = conn
            .exec_first(
                "SELECT terminal FROM plane_records WHERE kind = :kind AND ident = :token AND seq = :seq",
                params! { "kind" => kind, "token" => token, "seq" => UPSERT_SEQ },
            ).await
            .map_err(store_err)?;
        Ok(terminal == Some(false))
    }
}

/// An APPENDED plane record's IDENTITY within its kind: its `parent` when it is a child (a chain position is `(parent, seq)`), else its own `id`.
fn plane_ident(record: &PlaneRecord) -> &str {
    record.parent.as_deref().unwrap_or(&record.id)
}

fn is_terminal(d: PlaneDisposition) -> bool {
    matches!(d, PlaneDisposition::Terminal)
}

/// The `seq` an UPSERTED record is stored at: the contract upserts by `(kind, id)`, so the record's
/// own `seq` is not part of its identity.
const UPSERT_SEQ: u64 = 0;

/// Rows a retention sweep reads and deletes per round trip.
const PURGE_BATCH: usize = 1000;

/// A plane record's row at identity `ident` ([`plane_ident`] for an append, its id for an upsert).
fn plane_params(record: &PlaneRecord, ident: &str, seq: u64) -> Params {
    params! {
        "kind" => &record.kind,
        "ident" => ident,
        "seq" => seq,
        "id" => &record.id,
        "parent" => &record.parent,
        "ts" => record.ts,
        "terminal" => is_terminal(record.disposition),
        "body" => &record.body,
    }
}

fn crate_now() -> RecordStoreResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| store_err("system clock is before the Unix epoch"))
}

/// The store's package name: the name its Statement states and its signed tarball carries.
pub const NAME: &str = "busbar-store-mysql";

impl MysqlStore {
    /// Capture the DSN while the SDK reads the host's settings and lent secret markers.
    pub(crate) fn from_settings_lent(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, String> {
        #[derive(serde::Deserialize, Default)]
        #[serde(deny_unknown_fields)]
        struct Settings {
            url: Option<busbar_contract::abi::sdk::cred::MysqlUrl>,
        }
        const BAD: &str = "invalid mysql plugin config";
        let settings = if settings.iter().all(u8::is_ascii_whitespace) {
            b"null".as_slice()
        } else {
            settings
        };

        if settings.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'[') {
            return Err(format!(
                "{BAD}: settings: invalid type: sequence, expected struct Settings"
            ));
        }
        let config: Option<Settings> =
            busbar_contract::abi::sdk::cred::settings_lent(settings, secrets)
                .map_err(|e| format!("{BAD}: {e}"))?;
        let url = config
            .unwrap_or_default()
            .url
            .filter(|url| !url.0.public().trim().is_empty())
            .ok_or_else(|| format!("{BAD}: requires a \"url\" (a mysql:// connection string)"))?;
        let opts = Opts::from_captured(url.0).map_err(|e| format!("{BAD}: url: {e}"))?;
        Ok(Self {
            opts: Arc::new(opts),
            pool: Pool::new(KEPT_CONNECTIONS),
        })
    }

    /// Parse settings and capture their credentials without opening a connection.
    pub fn from_settings(settings: &[u8]) -> Result<Self, String> {
        Self::from_settings_lent(settings, &[])
    }
}

mod slots;

/// The store door (store v3, `busbar_contract::abi::store`): every slot of the store v3 table over [`MysqlStore`], through the contract's store SDK.
pub use slots::door;

#[cfg(test)]
mod tests;
