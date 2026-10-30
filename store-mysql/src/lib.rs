// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MySQL/MariaDB backend for busbar's durable governance store: MySQL 8.0.16+, MariaDB and
//! Aurora MySQL 3 through one common SQL subset.
//!
//! - `api_keys`, not `keys` (`KEYS` is reserved in MySQL).
//! - `store_sequence` is bumped FIRST in every control-plane transaction, so the lock order
//!   (`store_sequence` -> `api_keys` -> `credentials` -> `denylist`) is fixed and cannot deadlock.
//! - Every key and identity column is `VARBINARY` (schema v11, D19): byte-exact, no PAD SPACE,
//!   no case or accent folding, as in every other store.
//! - `affected_rows` counts rows CHANGED, so a conditional mutation checks existence with
//!   `SELECT ... FOR UPDATE` first instead of trusting the count.
//! - JSON columns are never byte-compared: MySQL normalizes JSON on write, MariaDB does not.
//! - The boot probes hard-fail: a server that parses `CHECK` but does not enforce it (MySQL
//!   < 8.0.16, Aurora 2) is caught only by a live probe ([`MysqlStore::connect_step`]).
//! - No socket of its own: every op runs on a connection the host's connector dials (one `tcp`
//!   need, `slots::NEEDS`), kept in a set of at most [`KEPT_CONNECTIONS`], speaking the MySQL
//!   protocol through [`mysqlwire`].

#![forbid(unsafe_code)]

use std::sync::Arc;

use busbar_contract::abi::sdk::store::fork;
use busbar_contract::abi::sdk::store::wire::Pool;
use mysql_common::params;
use mysql_common::value::Value;

pub(crate) mod mysqlwire;
use mysqlwire::{Conn, Error, Opts, Params, Row, Transaction};

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    ModelTokensDelta, PlaneDisposition, PlaneRecord, PlaneSelector, RecordStoreError,
    RecordStoreResult, Retention, ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey,
    UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
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

/// The CLOSED set of terminal task states the ONE-TIME v7 copy of a pre-v7 `tasks` table uses to
/// set the new envelope's `terminal` column (see `run_v7_plane_record_copy_if_needed`). Closed in
/// the SAFE direction on purpose, exactly as the pre-v7 retention sweep was: a state token this
/// build does not recognise is copied as ACTIVE, so the failure mode of guessing wrong is a row kept
/// too long, never work destroyed. Post-v7 the engine decides terminality itself and hands it over
/// as the envelope's typed `disposition`; this list is consulted by nothing else.
const TERMINAL_TASK_STATES: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

/// The plane-record kind whose retention is TERMINAL-ONLY (see `purge_plane_records_before`), and
/// the child kind that is swept together with it. The same two strings the reference `impl Store`s
/// in busbar branch on; every other kind is opaque to this store.
const KIND_TASK: &str = "task";
const KIND_TASK_EVENT: &str = "task_event";

fn store_err<E: std::fmt::Display>(e: E) -> RecordStoreError {
    RecordStoreError(e.to_string())
}

/// Why an `op_id` write's effect failed: the text, and the server's error code when the server
/// refused a statement (so the slot can tell a refusal from a failure without matching text).
#[derive(Debug)]
pub(crate) struct ApplyError {
    pub(crate) text: String,
    pub(crate) server_code: Option<u16>,
}

impl ApplyError {
    fn text(text: String) -> Self {
        Self {
            text,
            server_code: None,
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
    }
}

/// The schema version this build creates and migrates to. An older released database is v3.
/// v4..v6 never shipped (per-protocol tables); v7 is the neutral `plane_records` /
/// `plane_tokens` and open usage units (`run_v7_*`); v8/v9 added the store v3 door's tables; v10
/// dropped the deleted slots' tables (`run_v10_drop_dead_slot_tables`); v11 made every key exact
/// (`run_v11_exact_keys`).
const SCHEMA_VERSION: u32 = 11;

/// The oldest schema a release shipped (v3): a database stamped older is refused.
const FIRST_RELEASED_SCHEMA: u32 = 3;

/// The version each one-time migration step targets crossing INTO — named so a gate reads as "did
/// this database predate step N" rather than a bare magic number, and so a future step can't be
/// accidentally gated on `< SCHEMA_VERSION` (wrong: that would re-fire EVERY prior step, not just
/// the newest one, every time SCHEMA_VERSION bumps again — each step must stay pinned to the one
/// version boundary it actually closes).
const V7_PLANE_RECORDS: u32 = 7;
const V10_DEAD_SLOTS: u32 = 10;
const V11_EXACT_KEYS: u32 = 11;

/// Every key and identity column v11 makes byte-exact, per table, with the definition `SCHEMA`
/// declares for it (a migrated database ends with exactly the columns a fresh one is created
/// with). `VARBINARY` rather than a collation: it is the one comparison that is byte-exact AND
/// NO PAD on every server this store supports. MySQL 8's `_bin` collations are PAD SPACE, there is
/// no NO PAD collation for `ascii` at all, and the one NO PAD binary text collation
/// (`utf8mb4_0900_bin`) does not exist on MariaDB. Widths are bytes: four per former `utf8mb4`
/// character, one per former `ascii` one.
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

/// The foreign keys onto `api_keys.id`, `(table, constraint, definition)` exactly as `SCHEMA`
/// declares them: v11 drops them to retype the columns they join and puts them back.
const V11_KEY_FOREIGN_KEYS: &[(&str, &str, &str)] = &[
    (
        "credentials",
        "fk_cred_key",
        "FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE",
    ),
    (
        "usage_metering",
        "fk_metering_key",
        "FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE RESTRICT",
    ),
];

/// v11's child-to-parent re-spelling, run before any key is retyped (see `run_v11_exact_keys`):
/// parents before children, so a metering unit takes its cell's spelling after the cell has taken
/// its key's.
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

/// The `store_meta` row a migration writes BEFORE its first DDL and deletes after the version
/// stamp: MySQL DDL is not transactional, so this row is how a later open knows the schema may be
/// part-way between two shapes (and which version it was heading for).
const MIGRATING_TO: &str = "migrating_to";

/// The SQL naming this database's migration lock. `GET_LOCK` names are server-wide, so the name
/// carries the database (hashed: a lock name is at most 64 characters).
const MIGRATION_LOCK: &str = "CONCAT('busbar_store_migrate_', LEFT(SHA2(DATABASE(), 256), 40))";

/// How long an open waits for another connection's migration of the same database to finish
/// before refusing (a fleet booting together onto an old database waits for the one migrator).
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
        CONSTRAINT ck_cred_sigv4_recov CHECK (kind <> 'sigv4' OR secret_form = 'recoverable'),
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
        model VARBINARY(1024) NOT NULL,
        requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        billable_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_input BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_output BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_write BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (window_start, bucket_scope, bucket_id, model),
        CONSTRAINT ck_uw_scope CHECK (bucket_scope IN ('key','group','global'))
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS usage_metering (
        bucket VARBINARY(40) NOT NULL,
        key_id VARBINARY(64) NOT NULL,
        provider VARBINARY(512) NOT NULL,
        model VARBINARY(1024) NOT NULL,
        key_group_at_use VARBINARY(128) NOT NULL DEFAULT '',
        pricing_version VARCHAR(64) NOT NULL DEFAULT '',
        requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        billable_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_input BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_output BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_read BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tokens_cache_write BIGINT UNSIGNED NOT NULL DEFAULT 0,
        priced_from_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms),
        CONSTRAINT fk_metering_key FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE RESTRICT
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
    // v7: ONE table for every plane-record kind. `body` is opaque and returned byte for byte;
    // identity, ordering and retention ride on the typed sidecar columns. Identity is
    // `(kind, ident, seq)`: `ident` is the parent for an appended child, else the record's own id
    // at seq 0. VARBINARY(764) keeps a key inside the 3072-byte index limit. No foreign key between
    // parent and child rows (the engine states no write order); the task -> task_event cascade
    // lives in `purge_plane_records_before`.
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
    // The retention sweep's access path: `purge_plane_records_before` deletes by (kind, ts < cutoff).
    // No IF NOT EXISTS -- MySQL has no such form for CREATE INDEX; a re-run's duplicate error is
    // swallowed by try_init_schema, exactly as it is for every other index here.
    "CREATE INDEX idx_plane_records_kind_ts ON plane_records (kind, ts)",
    // The parent-scoped listing's access path: an appended chain lives at `ident = parent`, but an
    // upserted record that names a parent lives at its own id, so the listing reads `parent`.
    "CREATE INDEX idx_plane_records_kind_parent ON plane_records (kind, parent, seq)",
    // The single-use token ledger (`redeem_plane_token`) -- the durable record that makes a
    // confirm-once approval execute once across a restart AND across the nodes of a fleet. A sealed
    // token is valid bytes on its second presentation exactly as on its first; only a record that
    // the first happened tells them apart, and in process memory that record dies with the process
    // and is never shared with a second node. Keyed by `(kind, token)`, so the ledger is generic over
    // every single-use kind rather than hard-wiring one.
    //
    // A byte-exact key is the SHARPEST instance of the collation hazard in this file:
    // under the schema default the primary key stops telling a token from its case variants, so a
    // genuinely fresh approval would be REFUSED while an attacker's near-miss variants fold onto one
    // row. Byte-exact is the only correct comparison for a random token.
    "CREATE TABLE IF NOT EXISTS plane_tokens (
        kind VARBINARY(256) NOT NULL,
        token VARBINARY(764) NOT NULL,
        expires_at BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (kind, token)
    ) ENGINE=InnoDB",
    // The eviction sweep's access path. Without it the sweep's `expires_at < :now` is a full table
    // scan, and a scan under InnoDB's REPEATABLE READ takes a lock on every row it visits -- which on
    // the one table every concurrent redemption in the fleet touches is a lock-wait storm.
    "CREATE INDEX idx_plane_tokens_expires ON plane_tokens (expires_at)",
    // The open usage units of a budget window. `ModelTokens` is a name-keyed `usage_units` map:
    // the reserved four (`input`/`output`/`cache_read`/`cache_write`) keep their
    // existing `usage_windows` columns -- so a v3 row reads back unchanged with no data migration --
    // and every OTHER unit a plane declares (`tool_calls`, `bytes`, a rerank's search units, ...)
    // lands here, one row per (window, bucket, model, unit), so `add_usage` stays one atomic
    // `count = count + delta` upsert per unit rather than a read-modify-write of a JSON blob.
    // `unit` is binary: two unit names differing in case (or a trailing space) are two counters.
    "CREATE TABLE IF NOT EXISTS usage_window_units (
        window_start BIGINT UNSIGNED NOT NULL,
        bucket_scope VARBINARY(32) NOT NULL,
        bucket_id VARBINARY(128) NOT NULL,
        model VARBINARY(1024) NOT NULL,
        unit VARBINARY(512) NOT NULL,
        count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (window_start, bucket_scope, bucket_id, model, unit)
    ) ENGINE=InnoDB",
    // The open usage units of a metering cell -- every ledgered class the token columns do not hold
    // (`MeteringRow::usage_units`), additive like them. Keyed by the metering cell's own key plus the
    // unit. No foreign key: the parent cell is written first in the same transaction, and
    // a delete of the cell removes both.
    "CREATE TABLE IF NOT EXISTS usage_metering_units (
        bucket VARBINARY(40) NOT NULL,
        key_id VARBINARY(64) NOT NULL,
        provider VARBINARY(512) NOT NULL,
        model VARBINARY(1024) NOT NULL,
        priced_from_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
        unit VARBINARY(512) NOT NULL,
        count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms, unit)
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_metering_units_bucket ON usage_metering_units (bucket)",
    // The durable `op_id` dedupe log (`abi::store` S1-S4). One row per op that APPLIED: its value
    // fields' `sdk::store::dedupe` body (`body`; an older build's `{:?}` form still replays) and
    // `answer`, no longer read (written `null`). The row is inserted FIRST in the op's own
    // transaction, so two racing calls with one `op_id` serialise on its primary key: the second
    // waits, then reads the first's committed row. A failed op rolls its row back with its effect:
    // nothing is recorded (S3). Rows older than the retention are swept (`recorded_at`, epoch
    // seconds).
    "CREATE TABLE IF NOT EXISTS store_ops (
        op_id BINARY(16) PRIMARY KEY,
        recorded_at BIGINT UNSIGNED NOT NULL,
        body LONGBLOB NOT NULL,
        answer LONGBLOB NOT NULL
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_store_ops_recorded ON store_ops (recorded_at)",
    // THE KERNEL'S DURABLE RECORDS (`record_put`/`record_get`/`record_scan`): `(schema, key) ->
    // value`, read back in KEY ORDER under a prefix. VARBINARY keys compare byte for byte.
    "CREATE TABLE IF NOT EXISTS store_records (
        schema_id VARBINARY(764) NOT NULL,
        rkey VARBINARY(2048) NOT NULL,
        value VARBINARY(512) NOT NULL,
        PRIMARY KEY (schema_id, rkey)
    ) ENGINE=InnoDB",
];

/// How many connections the store keeps: this store is control-plane-frequency (key/credential CRUD) plus write-behind usage flush, not a
/// high-fan-out OLTP workload, and an unbounded set across many instances (a multi-process fleet
/// booting simultaneously) is what exhausts MySQL's default `max_connections`.
pub const KEPT_CONNECTIONS: usize = 8;

/// ESTABLISHED on every connection the store ever opens -- including a reconnect after a dropped
/// connection, or the set growing past the one connection `probe_invariants` checks at boot -- and
/// again after each reset, rather than verifying it once and trusting every future connection
/// inherits the same posture. Appends (never replaces) to whatever sql_mode the server/session
/// already carries, so an operator's other modes survive. CHECK-constraint enforcement (the other
/// boot-probe invariant) is a server-wide, not session-scoped, property -- it can't diverge per
/// connection the way sql_mode can, so the one-time probe remains sufficient for that half.
pub(crate) const INIT: &[&str] =
    &["SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')"];

/// MySQL/MariaDB-backed store: the connection URL and the kept connections every op runs on (one
/// connection per op at a time).
pub struct MysqlStore {
    pub(crate) opts: Arc<Opts>,
    pub(crate) pool: Arc<Pool>,
}

impl MysqlStore {
    /// The store on `url`: the URL is parsed here (the driver's refusal texts); the server is
    /// reached by `open`'s connect step ([`Self::connect_step`]).
    ///
    /// # Errors
    /// The URL does not parse.
    pub fn new(url: &str) -> RecordStoreResult<Self> {
        Ok(Self {
            opts: Arc::new(Opts::from_url(url).map_err(store_err)?),
            pool: Pool::new(KEPT_CONNECTIONS),
        })
    }

    /// `open`'s connect step: create the schema if absent, and run the boot-time invariant probes,
    /// on the op's connection. Hard-fails (returns `Err`, never silently degrades) if the server
    /// can't actually enforce what the schema declares — see the module doc for why a version check
    /// alone is insufficient.
    pub(crate) async fn connect_step(conn: &mut Conn) -> RecordStoreResult<()> {
        Self::init_schema(conn).await?;
        Self::probe_invariants(conn).await?;
        Ok(())
    }

    /// Schema creation, retried (bounded, immediately) on deadlock. Concurrent `CREATE TABLE`/`CREATE INDEX` from more than
    /// one connection (a multi-node fleet booting simultaneously against a fresh database, or —
    /// exactly this crate's own parallel test suite — is a REAL scenario, not just a test artifact:
    /// MySQL's metadata locking can genuinely deadlock two concurrent DDL statements against the
    /// same schema (`ERROR 1213`). A bounded retry is the correct response (the losing
    /// transaction is safe to retry — DDL here is idempotent via the `IF NOT EXISTS`/duplicate-error
    /// swallowing below), not a crash.
    async fn init_schema(conn: &mut Conn) -> RecordStoreResult<()> {
        const MAX_ATTEMPTS: u32 = 8;
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_init_schema_waiting(conn, MIGRATION_LOCK_WAIT_SECS).await {
                Ok(()) => return Ok(()),
                // No back-off: the connect step runs on a dispatcher thread and the SDK offers
                // a body no timed pend, so the retry is immediate and bounded.
                Err(e) if attempt < MAX_ATTEMPTS && Self::is_deadlock(&e.0) => {}
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop always returns on the final attempt")
    }

    /// Whether `information_schema.<view>` has a row for `cond` in the connected database
    /// (`DATABASE()` scopes it to this store's own schema).
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

    /// ADD `column` to `table` unless it is already there. MySQL has no `ADD COLUMN IF NOT EXISTS`,
    /// so the check is explicit; a node booting concurrently can still win the race between the
    /// check and the ALTER, and its `ER_DUP_FIELDNAME` (1060) is exactly "already there", so it is
    /// swallowed. Every other error propagates.
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

    /// v7 schema upgrade, in place and idempotent, gated on what the database HAS: five NULLable
    /// `api_keys` columns, and `usage_metering.priced_from_ms` (DEFAULT 0, "the opening card")
    /// joined to the primary key in one `ALTER`, so the `key_id` FK always has an
    /// index. The table names are parameters for test isolation.
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

    /// v7 data step, ONE-TIME (crossing into v7 from v4..v6 only; a re-copy would resurrect rows
    /// the engine has since cleared): `tasks`, `task_events` and `mcp_demotions` become
    /// `plane_records` rows in the envelope the engine reads, `spent_ask_states` becomes the `ask`
    /// token ledger. `mcp_calls` stays (nothing decodes it); nothing is dropped.
    /// `ON DUPLICATE KEY UPDATE kind = kind`, not `INSERT IGNORE`, so a real error is not
    /// downgraded to a warning and a truncated row.
    pub(crate) async fn run_v7_plane_record_copy_if_needed(
        conn: &mut Conn,
        prior_version: u32,
    ) -> RecordStoreResult<()> {
        if !(4..V7_PLANE_RECORDS).contains(&prior_version) {
            return Ok(());
        }
        if Self::table_exists(conn, "tasks").await? {
            let terminal = TERMINAL_TASK_STATES
                .iter()
                .map(|s| format!("'{s}'"))
                .collect::<Vec<_>>()
                .join(",");
            conn.query_drop(format!(
                "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
                 SELECT '{KIND_TASK}', task_id, 0, task_id, NULL, updated_at, \
                        (CAST(state AS BINARY) IN ({terminal})), \
                        CAST(JSON_OBJECT( \
                            'task_id', task_id, 'context_id', context_id, 'principal', principal, \
                            'direction', direction, 'state', state, 'agent_id', agent_id, \
                            'artifact_cursor', artifact_cursor, 'push_callback', push_callback, \
                            'created_at', created_at, 'updated_at', updated_at) AS CHAR) \
                 FROM tasks \
                 ON DUPLICATE KEY UPDATE plane_records.kind = plane_records.kind"
            ))
            .await
            .map_err(store_err)?;
        }
        if Self::table_exists(conn, "task_events").await? {
            conn.query_drop(format!(
                "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
                 SELECT '{KIND_TASK_EVENT}', task_id, seq, task_id, task_id, ts, FALSE, \
                        CAST(JSON_OBJECT( \
                            'task_id', task_id, 'seq', seq, 'ts', ts, 'kind', kind, \
                            'context_id', context_id, 'principal', principal, \
                            'agent_id', agent_id, 'state', state, 'request_id', request_id, \
                            'prev_hash', prev_hash, 'hash', hash) AS CHAR) \
                 FROM task_events \
                 ON DUPLICATE KEY UPDATE plane_records.kind = plane_records.kind"
            ))
            .await
            .map_err(store_err)?;
        }
        if Self::table_exists(conn, "mcp_demotions").await? {
            conn.query_drop(
                "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
                 SELECT 'demotion', server, 0, server, NULL, recorded_at, FALSE, \
                        CAST(JSON_OBJECT('server', server, 'reason', reason, \
                                         'recorded_at', recorded_at) AS CHAR) \
                 FROM mcp_demotions \
                 ON DUPLICATE KEY UPDATE plane_records.kind = plane_records.kind",
            )
            .await
            .map_err(store_err)?;
        }
        if Self::table_exists(conn, "spent_ask_states").await? {
            conn.query_drop(
                "INSERT INTO plane_tokens (kind, token, expires_at) \
                 SELECT 'ask', nonce, expires_at FROM spent_ask_states \
                 ON DUPLICATE KEY UPDATE plane_tokens.kind = plane_tokens.kind",
            )
            .await
            .map_err(store_err)?;
        }
        Ok(())
    }

    /// v10 SCHEMA upgrade (see `SCHEMA_VERSION`): the deleted slots' tables and dedupe rows go.
    /// MySQL DDL commits on its own, so there is no one transaction to hide the steps in; each step
    /// is idempotent (`DROP TABLE IF EXISTS`, a `DELETE` that matches nothing the second time), and
    /// the version is stamped only after the last one, so a crash part-way re-runs the whole step.
    /// The `store_ops` rows kept are those of the three deduped ops that remain (`add_usage_batch`,
    /// `add_metering_batch`, `append_plane_record`, whose bodies begin `add_usage_batch:`,
    /// `add_metering_batch:`, `append_plane_record:`); every other row belongs to a deleted slot.
    pub(crate) async fn run_v10_drop_dead_slot_tables(
        conn: &mut Conn,
        prior_version: u32,
    ) -> RecordStoreResult<()> {
        if prior_version == 0 || prior_version >= V10_DEAD_SLOTS {
            return Ok(());
        }
        for table in [
            "store_slices",
            "store_caps",
            "store_epoch",
            "store_journal",
            "store_sessions",
        ] {
            conn.query_drop(format!("DROP TABLE IF EXISTS {table}"))
                .await
                .map_err(|e| store_err(format!("schema upgrade failed dropping {table}: {e}")))?;
        }
        conn.query_drop(
            "DELETE FROM store_ops WHERE BINARY SUBSTRING_INDEX(body, ':', 1) NOT IN \
             (BINARY 'add_usage_batch', BINARY 'add_metering_batch', BINARY 'append_plane_record')",
        )
        .await
        .map_err(|e| store_err(format!("schema upgrade failed pruning store_ops: {e}")))?;
        Ok(())
    }

    /// v11 schema upgrade (D19): every key and identity column becomes `VARBINARY`. Gated on each
    /// column's `DATA_TYPE`, so it converges after a crash. No existing row can collide: the old
    /// collations' equality is coarser than byte equality. Child keys first take their parent's
    /// spelling (`V11_RESPELL`) so nothing is orphaned; the two foreign keys onto `api_keys.id` are
    /// dropped and re-added around the retype, which MySQL requires.
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
            // FIRST, while every key still compares under its old collation: a row that reaches its
            // parent through a key the old collation folded (`credentials.key_id = 'abc '` onto
            // `api_keys.id = 'abc'`, a metering unit spelled `gpt-4o` under its cell's `GPT-4o`)
            // takes its parent's spelling, or the byte-exact key would orphan it. Matching rows
            // already shared one old key, so no re-spelt row can collide; a re-run matches nothing.
            for stmt in V11_RESPELL {
                conn.query_drop(*stmt).await.map_err(|e| {
                    store_err(format!(
                        "schema upgrade v11 failed re-spelling a child key: {e}"
                    ))
                })?;
            }
            for (table, constraint, _) in V11_KEY_FOREIGN_KEYS {
                if Self::foreign_key_exists(conn, table, constraint).await? {
                    conn.query_drop(format!("ALTER TABLE {table} DROP FOREIGN KEY {constraint}"))
                        .await
                        .map_err(|e| {
                            store_err(format!(
                                "schema upgrade v11 failed dropping {table}.{constraint}: {e}"
                            ))
                        })?;
                }
            }
            for (table, columns) in &pending {
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

    async fn foreign_key_exists(
        conn: &mut Conn,
        table: &str,
        constraint: &str,
    ) -> RecordStoreResult<bool> {
        let cond = "table_name = :t AND constraint_name = :c AND constraint_type = 'FOREIGN KEY'";
        let p = params! { "t" => table, "c" => constraint };
        Self::exists(conn, "table_constraints", cond, p).await
    }

    /// A `u32` value of `store_meta` (`table` for test isolation, like `read_prior_version`), or
    /// `None` when the row is absent; a value that is not a number is a hard error.
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

    /// Refuse a database this build must not touch: older than the oldest released schema, stamped
    /// by a newer build, or left part-way through a newer build's migration (its marker names a
    /// version this build does not know the steps of, and its tables may be half way to a shape this
    /// build cannot read).
    fn refuse_unknown_schema(
        prior_version: u32,
        migrating_to: Option<u32>,
    ) -> RecordStoreResult<()> {
        if prior_version > SCHEMA_VERSION {
            return Err(store_err(format!(
                "mysql store: database schema v{prior_version} is newer than this build \
                 (v{SCHEMA_VERSION}); refusing to open"
            )));
        }
        if prior_version != 0 && prior_version < FIRST_RELEASED_SCHEMA {
            return Err(store_err(format!(
                "mysql store: database schema v{prior_version} predates v{FIRST_RELEASED_SCHEMA}, \
                 the oldest released schema; refusing to open"
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

    /// Take the database's migration lock (a server-wide `GET_LOCK` named for this database, so two
    /// stores on two databases of one server never wait on each other), waiting up to `wait_secs`.
    /// A lock still held after the wait means another connection is migrating this database right
    /// now, and a half-migrated schema is not one this store may serve: refused, naming the holder.
    async fn acquire_migration_lock(
        conn: &mut Conn,
        prior_version: u32,
        wait_secs: u32,
    ) -> RecordStoreResult<()> {
        let got: Option<Option<i64>> = conn
            .query_first(format!("SELECT GET_LOCK({MIGRATION_LOCK}, {wait_secs})"))
            .await
            .map_err(store_err)?;
        if got.flatten() == Some(1) {
            return Ok(());
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
    /// yet" (a genuinely fresh database, or one already at v2 that never needed a marker written
    /// pre-v2) as version 0, but propagating any OTHER query failure (a connection blip, a lock
    /// timeout) instead of silently treating it identically to "fresh install" -- collapsing those
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

    /// Stamps `schema_version`. Takes `table` purely for test isolation, like `read_prior_version`;
    /// production passes `"store_meta"`.
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

    /// Create or migrate the schema, waiting at most `wait_secs` for another connection's migration
    /// of this database (a parameter so a test can see the refusal without waiting the full term).
    ///
    /// A database at this build's version with no migration marker is the steady state and boots
    /// as it always did. Anything else -- a fresh database, an older one, or one a crashed
    /// migration left marked -- is created or migrated under the database's migration lock, so
    /// exactly one connection does it and every other open either waits for it to finish or is
    /// refused with the reason. (Postgres and SQLite get the same guarantee from transactional
    /// DDL under one lock; MySQL DDL commits statement by statement, so the lock and the marker
    /// stand in for that transaction.)
    pub(crate) async fn try_init_schema_waiting(
        conn: &mut Conn,
        wait_secs: u32,
    ) -> RecordStoreResult<()> {
        // `read_prior_version` needs `store_meta` to already exist -- create it FIRST (SCHEMA[0],
        // `IF NOT EXISTS` so harmless to re-run when the full loop below reaches it again) so a
        // genuinely fresh database's read is a real "no row" (Ok(None) -> version 0), not a
        // "table doesn't exist" query ERROR that read_prior_version's error-propagation would now
        // (correctly, for every OTHER failure) treat as a hard failure.
        conn.query_drop(SCHEMA[0]).await.map_err(store_err)?;
        let prior_version = Self::read_prior_version(conn, "store_meta").await?;
        let migrating_to = Self::read_meta_u32(conn, "store_meta", MIGRATING_TO).await?;
        // A database a LATER build stamped, or is part-way through migrating, is refused before
        // any DDL: this build's schema pass over it could re-run steps the newer build already
        // migrated, or serve tables half way to a shape this build cannot read.
        Self::refuse_unknown_schema(prior_version, migrating_to)?;
        if prior_version == SCHEMA_VERSION && migrating_to.is_none() {
            return Self::apply_schema(conn, prior_version).await;
        }
        Self::acquire_migration_lock(conn, prior_version, wait_secs).await?;
        let result = Self::migrate_locked(conn).await;
        let released = conn
            .query_drop(format!("DO RELEASE_LOCK({MIGRATION_LOCK})"))
            .await;
        // A migration failure is the one to report. A successful migration whose lock release
        // failed is not swallowed: the lock would hold every other open of this database waiting.
        match (result, released) {
            (Ok(()), Err(e)) => Err(store_err(format!(
                "schema migration succeeded but releasing its lock failed: {e}"
            ))),
            (result, _) => result,
        }
    }

    /// The migration, under the database's migration lock. The version and marker are read again:
    /// the connection that held the lock while this one waited may have finished the work, or been
    /// a newer build.
    ///
    /// The marker goes in before the first DDL on an existing database and comes out after the
    /// version stamp. A crash in between leaves it; the next open takes the lock (no one else holds
    /// it: the crashed session's lock died with it) and RESUMES, which is safe because every step is
    /// idempotent and gated on what the database has (or on the version, stamped last).
    async fn migrate_locked(conn: &mut Conn) -> RecordStoreResult<()> {
        let prior_version = Self::read_prior_version(conn, "store_meta").await?;
        let migrating_to = Self::read_meta_u32(conn, "store_meta", MIGRATING_TO).await?;
        Self::refuse_unknown_schema(prior_version, migrating_to)?;
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

    /// Create what is missing, run every migration step `prior_version` has not crossed, stamp.
    async fn apply_schema(conn: &mut Conn, prior_version: u32) -> RecordStoreResult<()> {
        for stmt in SCHEMA {
            // An index that is ALREADY THERE is skipped without issuing the DDL at all. A
            // `CREATE INDEX` that is going to fail as a duplicate still takes an exclusive
            // metadata lock first, and several nodes (or this crate's parallel tests) booting at
            // once would deadlock on each other's metadata locks (ERROR 1213). Checking first makes
            // a steady-state boot DDL-free apart from `CREATE TABLE IF NOT EXISTS`, which only
            // takes a shared lock on a table that exists.
            if let Some((index, table)) = parse_create_index(stmt) {
                if Self::index_exists(conn, table, index).await? {
                    continue;
                }
            }
            // IF NOT EXISTS on tables; CREATE INDEX has no IF NOT EXISTS in MySQL/MariaDB, so a
            // "duplicate key name" error (a concurrent booter won the race after the check above)
            // is swallowed here — every other error propagates.
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
        Self::run_v7_plane_record_copy_if_needed(conn, prior_version).await?;
        Self::run_v10_drop_dead_slot_tables(conn, prior_version).await?;
        if prior_version < V11_EXACT_KEYS {
            Self::run_v11_exact_keys(conn).await?;
        }

        Self::stamp_schema_version(conn, "store_meta").await?;
        conn.query_drop(
            "INSERT INTO store_sequence (id, revision) VALUES (1, 0) \
             ON DUPLICATE KEY UPDATE id = id",
        )
        .await
        .map_err(store_err)?;

        Ok(())
    }

    /// A `CREATE INDEX`/`CREATE TABLE` that lost a race to a concurrent booter.
    pub(crate) fn is_ddl_race(e: &Error) -> bool {
        // ER_DUP_KEYNAME (1061) / ER_TABLE_EXISTS_ERROR (1050): codes, not the server's
        // (localisable) message text.
        matches!(e, Error::MySqlError(inner) if inner.code == 1061 || inner.code == 1050)
    }

    /// A deadlock (`ERROR 1213`) surfaced through `store_err`'s text.
    pub(crate) fn is_deadlock(text: &str) -> bool {
        text.contains("ERROR 1213 (")
    }

    /// A rejected probe INSERT is proof of CHECK enforcement ONLY if it's the SPECIFIC
    /// CHECK-violation error this schema's two target engines actually produce -- MySQL 8.0.16+'s
    /// `ER_CHECK_CONSTRAINT_VIOLATED` (3819) or MariaDB's `ER_CONSTRAINT_FAILED` (4025). Any other
    /// error (a lock timeout, a connection blip) is inconclusive and must never be silently read as
    /// "enforced".
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

        // Session-private TEMPORARY table -- zero contention with real traffic or another node's
        // simultaneous boot probe (unlike probing the real, shared `store_sequence` singleton row,
        // which a concurrent live control-plane transaction, or another node probing at the same
        // moment, could genuinely lock -- producing a lock-wait-timeout/deadlock error that has
        // nothing to do with CHECK enforcement and would be misread as "unexpected failure"
        // below). Auto-dropped at session end regardless; explicitly dropped here too.
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

        // ER_CHECK_CONSTRAINT_VIOLATED (3819, MySQL 8.0.16+) / ER_CONSTRAINT_FAILED (4025,
        // MariaDB) -- the two vendor-specific codes this schema's CHECK enforcement actually
        // produces on the two engines this store targets (module doc: "MySQL 8.0.16+, MariaDB, and
        // Aurora MySQL"). Any OTHER error is inconclusive and hard-fails rather than being silently
        // read as "enforced" -- with the temp-table probe above having zero contention with real
        // traffic, there's no remaining benign reason left for a different error here.
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

    /// Bump `store_sequence` and return the new revision. MUST be the first statement of every
    /// control-plane transaction (mint/revoke/rotate/delete) — this fixed lock order
    /// (store_sequence -> api_keys -> credentials -> denylist) is what makes deadlock across the
    /// admin plane structurally impossible. Never call this outside an active transaction.
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

    /// Reads its columns by NAME, so a caller may first `take` an extra column (`secret`) out of a
    /// wider `SELECT`.
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
        Some(Err(_)) => Err(store_err(format!(
            "column {name} does not convert to {}",
            std::any::type_name::<T>()
        ))),
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
        Some(Err(_)) => Err(store_err(format!(
            "column {name} does not convert to {}",
            std::any::type_name::<T>()
        ))),
        None => Ok(None),
    }
}

/// `(index, table)` for a `SCHEMA` statement of the form `CREATE INDEX <index> ON <table> (...)`,
/// else `None`.
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

const KEY_INSERT: &str = "INSERT INTO api_keys
    (id, name, key_group, allowed_pools, allowed_scopes_ext, labels, enabled, generation_hash,
     created_at, updated_at, expires_at, deleted_at, revision, idp_subject, binding_mode, minted_by,
     idp_provider)
    VALUES (:id, :name, :key_group, :pools, :ext, :labels, :enabled, :gen, :created, :updated,
     :expires, :deleted, :rev, :idp, :binding, :minted_by, :idp_provider)";

/// `KEY_INSERT`'s parameters: `key` at revision `rev`, its tombstone `deleted`.
fn key_params(key: &VirtualKey, deleted: Option<u64>, rev: u64) -> RecordStoreResult<Params> {
    let (pools_json, ext_json) = partition_scopes(&key.allowed_scopes)?;
    let labels_json = serde_json::to_string(&key.labels).map_err(store_err)?;
    Ok(params! {
        "id" => &key.id, "name" => &key.name, "key_group" => key.group.as_deref().unwrap_or(""),
        "pools" => &pools_json, "ext" => &ext_json, "labels" => &labels_json,
        "enabled" => key.enabled, "gen" => &key.generation_hash, "created" => key.created_at,
        "updated" => key.created_at, "expires" => key.expires_at, "deleted" => deleted,
        "rev" => rev, "idp" => &key.idp_subject, "binding" => &key.binding_mode,
        "minted_by" => &key.minted_by, "idp_provider" => &key.idp_provider,
    })
}

/// Insert `secret` as a new credential row at revision `rev`, in the caller's transaction.
async fn insert_credential(
    tx: &mut Conn,
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
    .map_err(store_err)
}

/// PARTITION `allowed_scopes` into its two columns: `allowed_pools` (the `pool` kind, a JSON array
/// of bare names -- byte-for-byte the v3 shape, so a 1.5.x node reading a row mid-rolling-upgrade
/// sees exactly the pool grant it always did) and `allowed_scopes_ext` (every OTHER kind, as a JSON
/// array of `[kind, value]` pairs).
///
/// Writing only the value of every scope into `allowed_pools`, whatever its kind, would bring an
/// `mcp_server` grant back as a POOL grant: the MCP grant lost AND a pool the key was never given
/// admitted. Non-`pool` kinds (`mcp_server`, `agent`) exist, so a kind is never remapped and never
/// dropped.
///
/// `None` (the wildcard) writes NULL to both. An explicit grant ALWAYS writes `allowed_pools`, even
/// as `[]`, so `Some([])` -- no scopes at all -- survives the trip and can never widen to `None`.
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

/// The exact inverse of [`partition_scopes`]. Both columns NULL is the omitted-grant wildcard;
/// either present makes the grant an explicit, exhaustive-across-kinds list (pools first, then the
/// other kinds in the order they were written -- `scope_allowed` is a membership test, so order is
/// never consulted).
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
        // Every non-`pool` kind crosses the wire as data (`ScopeRef { kind, value }`): no
        // registry is consulted on either side of the store ABI.
        list.extend(
            other
                .into_iter()
                .map(|(kind, value)| ScopeRef { kind, value }),
        );
    }
    Ok(Some(list))
}

/// Split a `usage_units` map into the four RESERVED units (which keep their own typed columns --
/// the v3 layout, so an existing row needs no migration) and the OPEN remainder (which lives in a
/// `*_units` side table). Returned as `(input, output, cache_read, cache_write, open)`.
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

/// A signed delta as `(up, down)`: the amount to add and the amount to take off, one of them zero.
fn split_delta(d: i64) -> (u64, u64) {
    if d >= 0 {
        (d.unsigned_abs(), 0)
    } else {
        (0, d.unsigned_abs())
    }
}

/// SQL for `col` + a signed delta, over a `BIGINT UNSIGNED` column: floored at zero and pinned at
/// `u64::MAX`, never wrapping and never an out-of-range error. `up` and `down` name the
/// [`split_delta`] parameters.
fn sat_add(col: &str, up: &str, down: &str) -> String {
    let floored = format!("(GREATEST({col}, :{down}) - :{down})");
    format!("{floored} + LEAST(:{up}, 18446744073709551615 - {floored})")
}

/// SQL for `col` + the inserted row's `col`, pinned at `u64::MAX` instead of erroring.
fn sat_values(col: &str) -> String {
    format!("{col} + LEAST(VALUES({col}), 18446744073709551615 - {col})")
}

fn is_reserved_unit(k: &str) -> bool {
    k == UNIT_INPUT || k == UNIT_OUTPUT || k == UNIT_CACHE_READ || k == UNIT_CACHE_WRITE
}

/// Rebuild a name-keyed `usage_units` map from the four reserved columns. SPARSE, like the
/// contract's own canonical form (`busbar_kernel_ledger::usage_migration`): a zero count is simply absent,
/// which `ModelTokens::tier` reads back as 0 anyway.
fn reserved_units(
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
) -> BTreeMap<String, u64> {
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
    /// [`busbar_contract::records::RecordStore::add_usage`] on `tx`: the caller's transaction, so a deduped `op_id` write
    /// records its `op_id` atomically with the effect.
    pub(crate) async fn add_usage_on(
        tx: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Result<(), ApplyError> {
        // The window's request counters accumulate ONCE, on the reserved `model = ''` sentinel row,
        // not once per model. Applied inside the per-model loop instead, a single delta added its
        // request count once for every model it carried, and a delta with no models recorded
        // nothing. This is the fleet flush primitive, so both errors compounded permanently across
        // every node and every flush interval.
        let ((req_up, req_down), (breq_up, breq_down)) = (
            split_delta(delta.requests),
            split_delta(delta.billable_requests),
        );
        tx.exec_drop(
            format!(
                "INSERT INTO usage_windows
                    (window_start, bucket_scope, bucket_id, model, requests, billable_requests)
                 VALUES (:w, 'key', :b, '', GREATEST(0, :req), GREATEST(0, :breq))
                 ON DUPLICATE KEY UPDATE
                    requests = {},
                    billable_requests = {}",
                sat_add("requests", "req_up", "req_down"),
                sat_add("billable_requests", "breq_up", "breq_down"),
            ),
            params! {
                "w" => window_start, "b" => bucket_id,
                "req" => delta.requests, "breq" => delta.billable_requests,
                "req_up" => req_up, "req_down" => req_down,
                "breq_up" => breq_up, "breq_down" => breq_down,
            },
        )
        .await
        .map_err(apply_err)?;
        // Deterministic order, same reason as `put_usage`: the primary key orders by model name, so
        // caller-order inserts from two concurrent flushes can deadlock on overlapping windows.
        let mut models: Vec<&ModelTokensDelta> = delta.models.iter().collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        for m in models {
            let (ti, to, cr, cw, open) = split_units(&m.usage_units);
            // The VALUES(...) row constructor is type-checked against the target UNSIGNED columns
            // even on rows where ON DUPLICATE KEY UPDATE will fire instead of the INSERT -- MySQL
            // validates the whole statement's row shape up front. A refund delta's negative i64
            // would out-of-range error there even though it's never actually inserted as-is. Clamp
            // each VALUES(...) literal at 0 with its own `GREATEST(0, :x)` (a negative delta on a
            // brand-new, never-charged row is nonsensical anyway); the UPDATE arithmetic below still
            // uses the RAW (possibly negative) bound value, which is where the real floor-at-0 signed
            // accumulation happens.
            let (ti_s, to_s, cr_s, cw_s) = (
                split_delta(ti),
                split_delta(to),
                split_delta(cr),
                split_delta(cw),
            );
            tx.exec_drop(
                format!(
                    "INSERT INTO usage_windows
                        (window_start, bucket_scope, bucket_id, model,
                         tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                     VALUES (:w, 'key', :b, :model,
                             GREATEST(0, :ti), GREATEST(0, :to_), GREATEST(0, :cr), GREATEST(0, :cw))
                     ON DUPLICATE KEY UPDATE
                        tokens_input = {},
                        tokens_output = {},
                        tokens_cache_read = {},
                        tokens_cache_write = {}",
                    sat_add("tokens_input", "ti_up", "ti_down"),
                    sat_add("tokens_output", "to_up", "to_down"),
                    sat_add("tokens_cache_read", "cr_up", "cr_down"),
                    sat_add("tokens_cache_write", "cw_up", "cw_down"),
                ),
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "ti" => ti, "to_" => to, "cr" => cr, "cw" => cw,
                    "ti_up" => ti_s.0, "ti_down" => ti_s.1,
                    "to_up" => to_s.0, "to_down" => to_s.1,
                    "cr_up" => cr_s.0, "cr_down" => cr_s.1,
                    "cw_up" => cw_s.0, "cw_down" => cw_s.1,
                },
            )
            .await
            .map_err(apply_err)?;
            // Every OPEN unit accumulates the same way, floored at 0, one atomic upsert per unit
            // (BTreeMap order, so concurrent flushes take the rows in one order).
            for (unit, d) in open {
                let (up, down) = split_delta(d);
                tx.exec_drop(
                    format!(
                        "INSERT INTO usage_window_units
                            (window_start, bucket_scope, bucket_id, model, unit, count)
                         VALUES (:w, 'key', :b, :model, :unit, GREATEST(0, :d))
                         ON DUPLICATE KEY UPDATE count = {}",
                        sat_add("count", "up", "down"),
                    ),
                    params! {
                        "w" => window_start, "b" => bucket_id, "model" => &m.model,
                        "unit" => unit, "d" => d, "up" => up, "down" => down,
                    },
                )
                .await
                .map_err(apply_err)?;
            }
        }
        Ok(())
    }

    /// [`busbar_contract::records::RecordStore::add_metering`] on `tx` (see [`Self::add_usage_on`]). ONE transaction for the
    /// cell and its open units, so a reader never sees a cell's token counts advanced without the
    /// units the same response accrued (or the reverse).
    pub(crate) async fn add_metering_on(
        tx: &mut Conn,
        delta: &MeteringDelta,
    ) -> Result<(), ApplyError> {
        let bucket = format!("{:010}", delta.bucket);
        // `priced_from_ms` is part of the KEY: a rate-card edit inside the UTC day opens a SECOND
        // cell for that day, so each half keeps the card it was earned under rather than one card
        // repricing the whole day.
        tx.exec_drop(
            format!(
            "INSERT INTO usage_metering
                (bucket, key_id, provider, model, key_group_at_use, pricing_version, priced_from_ms,
                 requests, billable_requests, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES (:bucket, :key, :provider, :model, :grp, :pv, :pfm, :req, :breq, :ti, :to_, :cr, :cw)
             ON DUPLICATE KEY UPDATE
                requests = {r},
                billable_requests = {br},
                tokens_input = {ti},
                tokens_output = {to},
                tokens_cache_read = {cr},
                tokens_cache_write = {cw}",
            r = sat_values("requests"),
            br = sat_values("billable_requests"),
            ti = sat_values("tokens_input"),
            to = sat_values("tokens_output"),
            cr = sat_values("tokens_cache_read"),
            cw = sat_values("tokens_cache_write"),
            ),
            params! {
                "bucket" => &bucket, "key" => &delta.key_id, "provider" => &delta.provider,
                "model" => &delta.model, "grp" => &delta.key_group_at_use, "pv" => &delta.pricing_version,
                "pfm" => delta.priced_from_ms,
                "req" => delta.requests, "breq" => delta.billable_requests,
                "ti" => delta.tokens_input, "to_" => delta.tokens_output,
                "cr" => delta.tokens_cache_read, "cw" => delta.tokens_cache_write,
            },
        ).await
        .map_err(apply_err)?;
        // Every ledgered class the token columns do not hold, additive like them (BTreeMap order,
        // so concurrent writers take the unit rows in one order).
        for (unit, n) in &delta.usage_units {
            tx.exec_drop(
                format!("INSERT INTO usage_metering_units
                    (bucket, key_id, provider, model, priced_from_ms, unit, count)
                 VALUES (:bucket, :key, :provider, :model, :pfm, :unit, :n)
                 ON DUPLICATE KEY UPDATE count = {}", sat_values("count")),
                params! {
                    "bucket" => &bucket, "key" => &delta.key_id, "provider" => &delta.provider,
                    "model" => &delta.model, "pfm" => delta.priced_from_ms, "unit" => unit, "n" => *n,
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
        // APPEND-ONLY at a chain position `(parent, seq)`. A record arriving on a position that
        // already holds one is settled by comparing the two, exactly as `append_audit` settles a
        // duplicate `seq`:
        //   identical -> the write-through retrying after a lost ACK. Common, benign, Ok.
        //   different -> two records claiming one chain position: a forked or tampered chain, and
        //                an error. Overwriting would destroy exactly the case worth reporting; this
        //                store never restates a digest it was handed.
        //
        // INSERT FIRST, with no preceding `SELECT ... FOR UPDATE`, for the reason `append_audit`
        // gives: a locking read of a MISSING row takes a gap lock under REPEATABLE READ, and two
        // appends into the same gap then deadlock on each other's insert-intention lock. `kind =
        // kind` makes the duplicate a no-op whose affected-row count is 0; NOT `INSERT IGNORE`,
        // which would also downgrade every OTHER error -- a body or id too long for its column -- to a
        // warning and a silently truncated row.
        //
        // The loop covers the row being purged between the insert and the read-back: the position
        // is free again, so inserting is right. Bounded, and exhausting it is an error.
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
                continue; // purged between the insert and the read: the position is free, retry
            };
            if id == record.id
                && parent == record.parent
                && ts == record.ts
                && terminal == is_terminal(record.disposition)
                && body == record.body
            {
                return Ok(());
            }
            // Names the position and nothing else -- it must not echo stored (or caller) content.
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

/// The base op set (store slots 0-32), each one body on the op's connection.
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
        // `revoke_credential`, `put_credential`'s slot guard): the row lock is held to commit, so
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
                tx.rollback().await.map_err(store_err)?;
                return Err(store_err(format!(
                    "put_key: '{}' is tombstoned and its id is never reissued; refusing to clear \
                     the tombstone",
                    key.id
                )));
            }
        }

        tx.exec_drop(
            format!(
                "{KEY_INSERT} ON DUPLICATE KEY UPDATE
                name = VALUES(name), key_group = VALUES(key_group), allowed_pools = VALUES(allowed_pools),
                allowed_scopes_ext = VALUES(allowed_scopes_ext),
                labels = VALUES(labels), enabled = VALUES(enabled), generation_hash = VALUES(generation_hash),
                updated_at = VALUES(updated_at), expires_at = VALUES(expires_at),
                deleted_at = VALUES(deleted_at), revision = VALUES(revision),
                idp_subject = VALUES(idp_subject), binding_mode = VALUES(binding_mode),
                minted_by = VALUES(minted_by), idp_provider = VALUES(idp_provider)"
            ),
            key_params(key, key.deleted_at, rev)?,
        )
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
            .query(format!("SELECT {KEY_COLUMNS} FROM api_keys"))
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
                    "SELECT {KEY_COLUMNS} FROM api_keys WHERE revision > :since OR revision = 0"
                ),
                params! { "since" => since },
            )
            .await
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_key).collect()
    }

    /// TOMBSTONE, not row removal — see the trait doc. Cascades credential destruction, sets
    /// enabled=false + deleted_at, all in ONE transaction with ONE revision stamp on the api_keys
    /// row, so a hydrator reading a consistent snapshot can never observe the tombstone without the
    /// credentials already gone (the hard-delete-invisible-to-hydration fix).
    pub(crate) async fn delete_key(conn: &mut Conn, id: &str) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;

        // bump_revision FIRST, matching the crate's fixed lock order (store_sequence before
        // api_keys) — the existence/state check below still runs before any write, it just
        // acquires its FOR UPDATE lock second. A no-op path (unknown id / already tombstoned)
        // rolls the transaction back, so the revision it consumed is never observably committed;
        // per the locked design, gaps in the sequence are harmless, only inversions are fatal.
        let rev = Self::bump_revision(&mut tx).await?;

        // Explicit existence/state check — rows_affected() alone can't distinguish
        // "not found" from "already tombstoned, no-op" (both report 0 rows changed).
        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .await
            .map_err(store_err)?;
        let Some((deleted_at,)) = existing else {
            tx.rollback().await.map_err(store_err)?;
            // NOT the same case as already-tombstoned below. "Already tombstoned" means the
            // operator's intent is satisfied and the evidence is on disk; "no such id" means
            // nothing was touched, and Ok(()) there tells an operator who typo'd an id that a key
            // was revoked when none was.
            return Err(store_err(format!("delete_key: unknown id '{id}'")));
        };
        if deleted_at.is_some() {
            tx.rollback().await.map_err(store_err)?;
            return Ok(()); // already tombstoned: idempotent no-op per the trait doc
        }

        let now = crate_now();

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
        // One snapshot: a writer moving the request and token counters together is never seen
        // half-applied.
        let mut tx = conn.start_snapshot().await.map_err(store_err)?;
        let rows: Vec<(String, u64, u64, u64, u64)> = tx
            .exec(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write \
                 FROM usage_windows WHERE window_start = :w AND bucket_scope = 'key' \
                 AND bucket_id = :b AND model <> ''",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .await
            .map_err(store_err)?;
        // `SUM()` with no GROUP BY always returns exactly one row, even when zero rows match the
        // WHERE clause — it returns SQL NULL for each aggregate, not an empty result set. So
        // `exec_first::<(u64, u64)>` is NEVER `None` here (that would require zero rows, which
        // never happens); instead it is a `Some(Row)` whose columns are NULL for a bucket/window
        // with no usage yet, which a non-Option `u64` refuses. `COALESCE(..., 0)` makes MySQL
        // itself hand back 0 for the empty-aggregate case, matching Postgres/SQLite's "no row
        // yet" -> 0 semantics.
        let totals: Option<(u64, u64)> = tx
            .exec_first(
                "SELECT COALESCE(SUM(requests), 0), COALESCE(SUM(billable_requests), 0) \
                 FROM usage_windows WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .await
            .map_err(store_err)?;
        let (requests, billable_requests) = totals.unwrap_or((0, 0));
        // The OPEN units (everything but the reserved four) for this window, merged onto their
        // model's entry. A model that carries only open units still has its `usage_windows` row --
        // `put_usage`/`add_usage` always write one per model -- so it is already in `rows`; the
        // `or_insert` below only guards a row an operator deleted by hand.
        let open: Vec<(String, String, u64)> = tx
            .exec(
                "SELECT model, unit, count FROM usage_window_units \
                 WHERE bucket_id = :b AND window_start = :w AND bucket_scope = 'key' \
                 ORDER BY model, unit",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .await
            .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;

        let mut models: Vec<ModelTokens> = rows
            .into_iter()
            .map(
                |(model, input, output, cache_read, cache_write)| ModelTokens {
                    model,
                    usage_units: reserved_units(input, output, cache_read, cache_write),
                },
            )
            .collect();
        for (model, unit, count) in open {
            if count == 0 {
                continue; // sparse, like the reserved four
            }
            let idx = match models.iter().position(|m| m.model == model) {
                Some(i) => i,
                None => {
                    models.push(ModelTokens {
                        model,
                        ..Default::default()
                    });
                    models.len() - 1
                }
            };
            models[idx].usage_units.insert(unit, count);
        }

        Ok(UsageLedger {
            requests,
            billable_requests,
            models,
        })
    }

    /// [`Self::put_usage_once`], retried when this transaction loses a deadlock (its delete and
    /// insert hold the window's gap against a concurrent first write on the same window).
    pub(crate) async fn put_usage(
        conn: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
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
        // `bucket_scope` is named EXPLICITLY even though this path only ever writes 'key'. The
        // primary key is (window_start, bucket_scope, bucket_id, model), so a predicate that skips
        // `bucket_scope` cannot use the key beyond its first column: InnoDB then takes a next-key
        // lock running to the index supremum, and two DELETEs for DIFFERENT windows both end up
        // holding the gap at the end of the index and then both try to insert into it. That is a
        // genuine deadlock between unrelated writers, and it is what MySQL's own deadlock record
        // showed. Naming the scope lets the range close on (window_start, 'key', bucket_id, ...).
        tx.exec_drop(
            "DELETE FROM usage_windows \
             WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
            params! { "b" => bucket_id, "w" => window_start },
        )
        .await
        .map_err(apply_err)?;
        // The window's OPEN units are part of the same absolute set: a unit the new ledger no
        // longer carries must not survive it.
        tx.exec_drop(
            "DELETE FROM usage_window_units \
             WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
            params! { "b" => bucket_id, "w" => window_start },
        )
        .await
        .map_err(apply_err)?;
        // The request counters belong to the WINDOW, not to any one model, so they live on a single
        // reserved `model = ''` sentinel row and the per-model rows carry tokens only. Written onto
        // every per-model row instead, `get_usage`'s `SUM(requests)` returned the count multiplied by
        // the number of models, and a ledger with no model breakdown wrote nothing at all and
        // discarded its counters. store-sqlite uses the same sentinel for the same reason.
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
        // Insert the per-model rows in a DETERMINISTIC order. The primary key orders by model name,
        // so two transactions writing overlapping windows in caller order can acquire the same rows
        // in opposite orders and deadlock. Sorting makes the acquisition order identical for every
        // writer, which is the same discipline the control-plane paths get from taking the
        // `store_sequence` row lock first.
        let mut models: Vec<&ModelTokens> = ledger.models.iter().collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        for m in models {
            let (ti, to, cr, cw, open) = split_units(&m.usage_units);
            tx.exec_drop(
                "INSERT INTO usage_windows
                    (window_start, bucket_scope, bucket_id, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (:w, 'key', :b, :model, :ti, :to_, :cr, :cw)",
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "ti" => ti, "to_" => to, "cr" => cr, "cw" => cw,
                },
            )
            .await
            .map_err(apply_err)?;
            // BTreeMap order, so the unit rows are acquired in one deterministic order too.
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
        tx.commit().await.map_err(apply_err)
    }

    pub(crate) async fn list_metering(
        conn: &mut Conn,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let bucket_s = format!("{bucket:010}");
        // One snapshot: a cell and its open units are read at one point in time.
        let mut tx = conn.start_snapshot().await.map_err(store_err)?;
        let rows: Vec<Row> = tx
            .exec(
                "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read, \
                 tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version, \
                 priced_from_ms FROM usage_metering WHERE bucket = :b",
                params! { "b" => &bucket_s },
            ).await
            .map_err(store_err)?;
        let units: Vec<(String, String, String, u64, String, u64)> = tx
            .exec(
                // Joined to the cell in SQL. Both tables' keys are byte-exact (v11, which re-spelt
                // any unit a pre-v11 case-insensitive key had let differ from its cell).
                "SELECT m.key_id, m.model, m.provider, m.priced_from_ms, u.unit, u.count \
                 FROM usage_metering_units u JOIN usage_metering m \
                 ON m.bucket = u.bucket AND m.key_id = u.key_id AND m.model = u.model \
                 AND m.provider = u.provider AND m.priced_from_ms = u.priced_from_ms \
                 WHERE u.bucket = :b",
                params! { "b" => &bucket_s },
            )
            .await
            .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        // The open units, keyed by their cell, so each lands on exactly the row it was accrued to.
        let mut by_cell: BTreeMap<(String, String, String, u64), BTreeMap<String, u64>> =
            BTreeMap::new();
        for (key_id, model, provider, pfm, unit, count) in units {
            if count == 0 {
                continue;
            }
            by_cell
                .entry((key_id, model, provider, pfm))
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
                let cell = (
                    key_id.clone(),
                    model.clone(),
                    provider.clone(),
                    priced_from_ms,
                );
                Ok(MeteringRow {
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
                    key_group_at_use: col(&mut r, "key_group_at_use")?,
                    pricing_version: col(&mut r, "pricing_version")?,
                    priced_from_ms,
                })
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

        // THE OWNING KEY MUST BE LIVE. `delete_key` cascades a key's credentials away precisely so
        // the secret material stops resolving; accepting a credential onto a TOMBSTONED key puts it
        // back under a key an operator just revoked, and the FK alone only catches a key that names
        // no row at all. Checked here, under a `FOR UPDATE` row lock held to commit, rather than by
        // the caller: a caller-side check is a read-then-write, and a `delete_key` committing in the
        // gap would cascade away only the rows that existed at that moment. Taken AFTER
        // `bump_revision` and BEFORE the credentials rows, which is the crate's fixed lock order
        // (store_sequence -> api_keys -> credentials) and the same order `delete_key` locks in.
        let owner: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :k FOR UPDATE",
                params! { "k" => &m.key_id },
            )
            .await
            .map_err(store_err)?;
        match owner {
            None => {
                tx.rollback().await.map_err(store_err)?;
                return Err(store_err(format!(
                    "put_credential: owning key '{}' does not exist",
                    m.key_id
                )));
            }
            Some((Some(_),)) => {
                tx.rollback().await.map_err(store_err)?;
                return Err(store_err(format!(
                    "put_credential: owning key '{}' is tombstoned; a revoked key takes no new \
                     credentials",
                    m.key_id
                )));
            }
            Some((None,)) => {}
        }

        // Slot-occupied-by-a-LIVE-credential guard: an explicit slot pointed at a live credential
        // must fail loudly, not silently clobber a working credential mid-overlap-window.
        let occupied: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT revoked_at FROM credentials WHERE key_id = :k AND kind = :kind AND slot = :s FOR UPDATE",
                params! { "k" => &m.key_id, "kind" => &m.kind, "s" => m.slot },
            ).await
            .map_err(store_err)?;
        if let Some((None,)) = occupied {
            tx.rollback().await.map_err(store_err)?;
            return Err(store_err(format!(
                "put_credential: slot {} for key {} kind {} holds a LIVE credential — revoke it first",
                m.slot, m.key_id, m.kind
            )));
        }

        // `credentials` has THREE unique keys total: `id` (PRIMARY KEY), `uq_cred_public
        // UNIQUE(kind, public_id)`, and `uq_cred_slot UNIQUE(key_id, kind, slot)` (checked above).
        // A single `INSERT ... ON DUPLICATE KEY UPDATE` fires its UPDATE on ANY of the 3, but its
        // SET list only ever touches `id`/`public_id`/`secret`/etc, never `key_id`/`slot` -- so a
        // collision on `id` OR `public_id` against an UNRELATED row (different key_id/slot) would
        // silently overwrite that row's identity/secret while leaving it pointed at the WRONG
        // key/slot. Branching INSERT-vs-UPDATE off the slot guard above (the only unique key that
        // legitimately gets reused, when reclaiming a revoked slot) instead of a blanket upsert
        // means a collision on `id` or `public_id` now surfaces as a real MySQL 1062 duplicate-key
        // error rather than a silent cross-row overwrite.
        if occupied.is_some() {
            // A revoked row already holds this exact (key_id, kind, slot) -- reclaim it in place.
            tx.exec_drop(
                "UPDATE credentials SET
                    id = :id, public_id = :pub, secret = :secret, secret_form = :form,
                    created_at = :created, updated_at = :updated, expires_at = :expires,
                    revoked_at = NULL,
                    revoke_reason = NULL, revision = :rev
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
            .map_err(store_err)?;
        } else {
            insert_credential(&mut tx, secret, rev).await?;
        }

        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn put_key_with_credential(
        conn: &mut Conn,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx).await?;
        tx.exec_drop(KEY_INSERT, key_params(key, None, rev)?)
            .await
            .map_err(store_err)?;
        insert_credential(&mut tx, secret, rev).await?;
        tx.commit().await.map_err(store_err)
    }

    pub(crate) async fn list_credentials(
        conn: &mut Conn,
        key_id: &str,
    ) -> RecordStoreResult<Vec<CredentialMeta>> {
        let rows: Vec<Row> = conn
            .exec(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision FROM credentials WHERE key_id = :k",
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
        // (e.g. put_credential's slot guard): `rows_affected()` alone can't distinguish "id
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
        if existing.is_none() {
            tx.rollback().await.map_err(store_err)?;
            return Err(store_err(format!(
                "revoke_credential: unknown credential id {id}"
            )));
        }

        let now = crate_now();
        tx.exec_drop(
            "UPDATE credentials SET revoked_at = :now, revoke_reason = :reason, updated_at = :now, \
             revision = :rev WHERE id = :id AND revoked_at IS NULL",
            params! { "now" => now, "reason" => reason, "rev" => rev, "id" => id },
        ).await
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
        rows.into_iter()
            .map(|mut row| {
                let secret: Option<String> = opt_col(&mut row, "secret")?;
                let meta = Self::row_to_cred_meta(row)?;
                Ok(CredentialSecret {
                    meta,
                    secret: secret.unwrap_or_default(),
                })
            })
            .collect()
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
        out.reverse(); // DESC LIMIT then reverse = the last N, oldest-first
        Ok(out)
    }

    pub(crate) async fn add_denylist(
        conn: &mut Conn,
        sub: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let mut tx = conn.start_transaction().await.map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx).await?;
        let now = crate_now();
        let max_ttl: u64 = 90 * 24 * 3600; // matches the 90d default token expiry ceiling documented in admin-api.md
        tx.exec_drop(
            "INSERT INTO denylist (sub, reason, revoked_at, expires_at, revision) \
             VALUES (:sub, :reason, :now, :expires, :rev) \
             ON DUPLICATE KEY UPDATE sub = sub",
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

    // The neutral kind-tagged plane-record verbs: eight verbs over ONE table.
    // Every one is GENERIC over `kind`: nothing here decodes a `body`, and identity, ordering and
    // retention read only the typed sidecar columns. That is what lets a plane registered after this
    // build persist through it unchanged. The one kind-aware rule is retention's, and it is the
    // contract's: `task` drops only TERMINAL rows, and takes its `task_event` chain with it.

    pub(crate) async fn upsert_plane_record(
        conn: &mut Conn,
        record: &PlaneRecord,
    ) -> RecordStoreResult<()> {
        // UPSERT by identity: a second write for one `(kind, id)` REPLACES the row -- the engine
        // writes a task through on every state transition, and the boot read must find one row per
        // id, holding the last state.
        //
        // No `affected_rows` check, deliberately: MySQL reports 1 for an insert, 2 for a row it
        // changed and 0 for an update that changed nothing, so the number cannot tell "stored" from
        // "failed". Correctness rests on the statement succeeding.
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
        // No caller filter, deliberately: the contract puts caller-scoping ENGINE-side, because an
        // authorization check living in the backend is one an unauthorized reader bypasses by
        // configuring a different backend. An unknown id is `None`, never an error.
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
        // Oldest-first by `seq` -- the order the engine's chain verifier reads a parent's chain in.
        // `All` is UNFILTERED (terminal rows included): the boot rehydrate wants the active rows,
        // retention the terminal ones and a scoped listing one caller's, and a store that
        // pre-filtered for one of them would break the other two.
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
        // The boot enumeration a restart resumes chains from: every distinct parent holding at
        // least one record of the kind, including one this process has never seen written.
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
        // The age-only entry: `task` has always dropped only its TERMINAL rows here, every other
        // kind every row older than `before`.
        let retention = if kind == KIND_TASK {
            Retention::TerminalOnly
        } else {
            Retention::Age
        };
        Self::purge_plane_records(conn, kind, before, retention).await
    }

    pub(crate) async fn purge_plane_records(
        conn: &mut Conn,
        kind: &str,
        before: u64,
        retention: Retention,
    ) -> RecordStoreResult<u64> {
        // STRICTLY older than the cutoff: a row exactly at `before` is kept. The count returned is
        // one the DELETE actually performed (`affected_rows`), never an estimate. WHICH rows go is
        // the rule the call carries, never one inferred from the kind's name.
        let terminal_only = retention == Retention::TerminalOnly;
        if terminal_only && kind == KIND_TASK {
            return Self::purge_terminal_tasks(conn, before).await;
        }
        // Every other kind: a batch of primary keys is read (no locks), then deleted by primary
        // key with the predicate re-checked, so concurrent writers and sweeps take record locks
        // only and never deadlock on each other's ranges. Terminal-only keeps an ACTIVE row (the
        // typed `terminal` column, never the body). Looped until the backlog is gone.
        let mut total = 0u64;
        loop {
            let terminal = if terminal_only { " AND terminal" } else { "" };
            let keys: Vec<(Vec<u8>, u64)> = conn
                .exec(
                    format!(
                        "SELECT ident, seq FROM plane_records \
                         WHERE kind = :kind AND ts < :before{terminal} \
                         ORDER BY ident, seq LIMIT {PURGE_BATCH}"
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

    /// (The statements that lock by primary key carry an `INDEX(.. PRIMARY)` hint: left to itself the
    /// optimizer can pick the `(kind, ts)` index and lock its range, which is what this avoids.)
    ///
    /// The terminal `task` rows strictly older than `before`, each with its `task_event` chain, in
    /// batches: an interrupted task waiting on a human must survive. A batch's candidates come
    /// from a non-locking read; the transaction then locks them by primary key with the predicate
    /// re-checked (a concurrent sweep may have taken some) and deletes those, so concurrent sweeps
    /// take record locks only. Returns the tasks removed.
    async fn purge_terminal_tasks(conn: &mut Conn, before: u64) -> RecordStoreResult<u64> {
        let mut removed = 0u64;
        loop {
            let candidates: Vec<Vec<u8>> = conn
                .exec(
                    format!(
                        "SELECT ident FROM plane_records WHERE kind = :kind AND seq = :seq \
                         AND ts < :before AND terminal ORDER BY ident LIMIT {PURGE_BATCH}"
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
                         AND ident IN ({marks}) AND ts < ? AND terminal FOR UPDATE"
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
        // Absent is a NO-OP, not an error: the engine clears a demotion on every observation that
        // agrees with the approval rather than tracking whether it had demoted, so the common call
        // is one against no row at all. Every `seq` under the identity goes, so deleting a parent's
        // record can never leave part of a chain behind.
        conn.exec_drop(
            "DELETE FROM plane_records WHERE kind = :kind AND ident = :id",
            params! { "kind" => kind, "id" => id },
        )
        .await
        .map_err(store_err)
    }

    pub(crate) async fn redeem_plane_token(
        conn: &mut Conn,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // THE EVICTION SWEEP the redemption carries, so the ledger is bounded by one validity
        // window rather than growing forever: an entry recording a token that can no longer be
        // presented protects nothing. STRICTLY less-than, so an entry expiring exactly at `now` is
        // kept -- the boundary convention every retention method in this crate uses. It runs
        // BEFORE the insert, so it can never delete the row this very call is about to write.
        //
        // DELIBERATELY NOT IN A TRANSACTION WITH THE INSERT. The atomicity that matters belongs to
        // the INSERT alone; InnoDB under REPEATABLE READ holds NEXT-KEY locks over the range a
        // DELETE scans until commit, so wrapping the sweep in would make every node's redemption
        // sit on a range lock across the one table the whole fleet writes to. The sweep is an
        // independent, idempotent statement; a crash between the two leaves a ledger that is
        // correct and merely one sweep behind.
        conn.exec_drop(
            "DELETE FROM plane_tokens WHERE expires_at < :now",
            params! { "now" => now },
        )
        .await
        .map_err(store_err)?;
        // THE TEST AND SET, as ONE statement. `ON DUPLICATE KEY UPDATE token = token` makes the
        // duplicate case a no-op, so `affected_rows` is exactly 1 when THIS call inserted the row
        // and 0 when it was already there. Reading and then writing would tell BOTH halves of a race
        // they were first -- two nodes behind a load balancer -- which is the shape this verb is
        // specified not to have. Not INSERT IGNORE: it would downgrade every other error on the
        // statement to a warning, and a redemption that swallowed a failed write would answer from a
        // row that never landed.
        conn.exec_drop(
            "INSERT INTO plane_tokens (kind, token, expires_at) VALUES (:kind, :token, :exp) \
             ON DUPLICATE KEY UPDATE token = token",
            params! { "kind" => kind, "token" => token, "exp" => expires_at },
        )
        .await
        .map_err(store_err)?;
        Ok(conn.affected_rows() == 1)
    }

    pub(crate) async fn plane_token_live(
        conn: &mut Conn,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        // MULTI-USE and SPENDS NOTHING -- the opposite of `redeem_plane_token`. A plain READ of the
        // `(kind, token)` upsert record: live only while it is present, still ACTIVE (not
        // terminal), and `now` has not passed `expires_at`. Each of the three failing is `false`,
        // so this stays fail-closed on an unknown token, a finished task and a lapsed deadline
        // alike. Nothing is written, so asking twice answers the same twice.
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

/// An APPENDED plane record's IDENTITY within its kind: its `parent` when it is a child (a chain
/// position is `(parent, seq)`), else its own `id`. An upserted record's identity is always its own
/// `id`, parent or not (the contract upserts by `(kind, id)`).
fn plane_ident(record: &PlaneRecord) -> &str {
    record.parent.as_deref().unwrap_or(&record.id)
}

fn is_terminal(d: PlaneDisposition) -> bool {
    matches!(d, PlaneDisposition::Terminal)
}

/// A plane record's row at identity `ident` ([`plane_ident`] for an append, its id for an upsert).
/// The `seq` an UPSERTED record is stored at: the contract upserts by `(kind, id)`, so the record's
/// own `seq` is not part of its identity.
const UPSERT_SEQ: u64 = 0;

/// Rows a retention sweep reads and deletes per round trip.
const PURGE_BATCH: usize = if cfg!(test) { 7 } else { 1000 };

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

fn crate_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// The store's door lives HERE, in the logic crate (`slots`: `store_door!` over this store's
// `StoreSlots`): a busbar build that links this crate registers `door` as its compiled-in row
// (`LinkedRow::of(door)`), and the sibling `busbar-store-mysql-plugin` cdylib exports the same
// `door` as the image's one symbol (`export_door!`). One source, both doors.

/// The store's package name: the name its Statement states and its signed tarball carries.
pub const NAME: &str = "busbar-store-mysql";

impl MysqlStore {
    /// The `url` of the settings JSON the host hands `open`:
    ///
    /// ```json
    /// { "url": "mysql://user:pass@host:3306/busbar" }
    /// ```
    ///
    /// # Errors
    /// A text naming why the settings do not name a store.
    pub(crate) fn settings_url(settings: &[u8]) -> Result<String, String> {
        let v: serde_json::Value = if settings.iter().all(u8::is_ascii_whitespace) {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_slice(settings)
                .map_err(|e| format!("invalid mysql plugin config: {e}"))?
        };
        if let Some(map) = v.as_object() {
            if let Some(k) = map.keys().find(|k| k.as_str() != "url") {
                return Err(format!(
                    "invalid mysql plugin config: unknown setting `{k}` (accepted: url)"
                ));
            }
        }
        let url = match v.get("url") {
            Some(serde_json::Value::String(s)) => Some(s.trim()).filter(|s| !s.is_empty()),
            Some(_) => {
                return Err("invalid mysql plugin config: `url` must be a string".to_string())
            }
            None => None,
        }
        .ok_or_else(|| {
            "mysql plugin config requires a \"url\" (a mysql:// connection string)".to_string()
        })?;
        Ok(url.to_owned())
    }

    /// A MySQL/MariaDB store from the settings JSON the host hands `open`: parsed here (the same
    /// refusal texts); the server is reached by `open`'s connect step.
    ///
    /// # Errors
    /// A text naming why the settings do not open a store.
    pub fn from_settings(settings: &[u8]) -> Result<Self, String> {
        MysqlStore::new(&Self::settings_url(settings)?)
            .map_err(|e| format!("invalid mysql plugin config: url: {}", e.0))
    }
}

mod slots;

/// The store door (store v3, `busbar_contract::abi::store`): every slot of the store v3 table over
/// [`MysqlStore`], through the contract's store SDK.
pub use slots::door;

#[cfg(test)]
mod tests;
