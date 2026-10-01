// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MySQL/MariaDB backend for busbar's durable governance store. Targets the common SQL subset
//! supported by MySQL 8.0.16+, MariaDB, and Aurora MySQL — one plugin, protocol-compatible with all
//! three, same reasoning as busbar's Valkey store covering any server that speaks the standard RESP
//! protocol: broad coverage via standard SQL, not three separate builds.
//!
//! Schema and design notes (every decision here traces to the locked cross-backend contract this
//! plugin was designed against — see the sibling store-postgres/store-sqlite/store-valkey repos for
//! the same contract's other physical realizations):
//!
//! - `api_keys`, not `keys`: `KEYS` is a MySQL/MariaDB reserved word. Renamed here specifically —
//!   Postgres/SQLite/Valkey keep `keys`.
//! - `store_sequence`: a single-row revision counter, bumped FIRST in every control-plane
//!   transaction (mint/revoke/rotate/delete), before touching `api_keys`/`credentials`/`denylist`.
//!   This fixed lock order (`store_sequence` -> `api_keys` -> `credentials` -> `denylist`) is what
//!   makes deadlock across the admin plane structurally impossible.
//! - `ascii_bin` collation on every opaque identifier column (`id`, `key_id`, `public_id`,
//!   `key_group`, `bucket_id`): MySQL's default collation is case-INSENSITIVE + PAD SPACE, a real
//!   security-relevant footgun for a credential lookup handle. Byte-exact comparison, matching
//!   Postgres/SQLite's default behavior.
//! - `rows_affected()` reports "rows CHANGED", not "rows MATCHED" — an idempotent no-op UPDATE
//!   (disabling an already-disabled key) returns 0, indistinguishable from "not found" by row count
//!   alone. Every conditional mutation here does an explicit `SELECT ... FOR UPDATE` existence/state
//!   check first, never relies on the affected-row count to tell "not found" from "no-op".
//! - JSON columns (`allowed_pools`, `labels`) are NEVER byte-compared or hashed after a round trip:
//!   MySQL 8's native JSON type normalizes on write (reorders keys, strips whitespace); MariaDB
//!   stores JSON as `LONGTEXT`, byte-identical. Canonicalize in the caller before hashing if ever
//!   needed — this store never does.
//! - Boot-time invariant probes (see [`MysqlStore::connect`]) hard-fail rather than warn: MySQL
//!   < 8.0.16 and Aurora MySQL 2.x PARSE `CHECK` constraints but ENFORCE none — a schema that
//!   *looks* validated can silently accept garbage. A live functional probe (attempt a CHECK
//!   violation, confirm it's rejected) is the only way to catch this; a version-string check alone
//!   is not sufficient since parsing-without-enforcing doesn't show up as a version mismatch.

use mysql::prelude::*;
use mysql::{params, Opts, Pool, PooledConn, TxOpts};

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    ModelTokensDelta, PlaneDisposition, PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStore,
    RecordStoreError, RecordStoreResult, ScopeRef, SecretForm, UsageDelta, UsageLedger, VirtualKey,
    UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use std::collections::BTreeMap;

/// `(key_id, model, provider, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,
/// requests, billable_requests, key_group_at_use, pricing_version, priced_from_ms)` as selected by
/// `list_metering`.
type MeteringRowTuple = (
    String,
    String,
    String,
    u64,
    u64,
    u64,
    u64,
    u64,
    u64,
    String,
    String,
    u64,
);
type AuditRowTuple = (u64, u64, String, String, String, String, String, String);

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

/// Numeric, not the original `&str`: `try_init_schema` needs to compare "the version this database
/// was AT before this boot" against this constant to decide which one-time migration steps below
/// have already run, and `"1" < "2"` string-comparison stops being safe the moment version numbers
/// reach two digits.
/// v4..v6 (never in a released build): per-protocol durable tables -- `mcp_calls` (v4), `tasks` +
/// `task_events` (v5), `mcp_demotions` + `spent_ask_states` (v6) -- behind typed `Store` methods
/// (`append_mcp_call`, `put_task`, `redeem_ask_state`, ...) that busbar 1.6.0 deleted.
/// v7: busbar 1.6.0's store interface. The typed per-protocol methods collapsed onto eight neutral
/// KIND-TAGGED verbs over an opaque `PlaneRecord` envelope, so the per-protocol tables above give
/// way to ONE `plane_records` table plus the `plane_tokens` single-use ledger. `VirtualKey` gained
/// `idp_subject`/`binding_mode`/`minted_by` and non-`pool` scope kinds, `ModelTokens` became a
/// name-keyed `usage_units` map, and a metering cell is now keyed by `priced_from_ms` as well
/// (DECISION #79) and carries open `usage_units`. Every existing table is upgraded IN PLACE and no
/// existing row is dropped or rewritten -- see `run_v7_upgrade`. A released 1.5.x database is v3.
const SCHEMA_VERSION: u32 = 7;

/// The version each one-time migration step targets crossing INTO — named so a gate reads as "did
/// this database predate step N" rather than a bare magic number, and so a future step can't be
/// accidentally gated on `< SCHEMA_VERSION` (wrong: that would re-fire EVERY prior step, not just
/// the newest one, every time SCHEMA_VERSION bumps again — each step must stay pinned to the one
/// version boundary it actually closes).
const V2_BILLABLE_REQUESTS_BACKFILL: u32 = 2;
const V3_KEY_GROUP_AT_USE_ASCII_BIN: u32 = 3;
const V7_PLANE_RECORDS: u32 = 7;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS store_meta (
        k VARCHAR(191) PRIMARY KEY,
        v TEXT NOT NULL
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS store_sequence (
        id INT PRIMARY KEY,
        revision BIGINT NOT NULL DEFAULT 0,
        CONSTRAINT ck_seq_singleton CHECK (id = 1)
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS api_keys (
        id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
        name VARCHAR(256) NOT NULL DEFAULT '',
        key_group VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
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
        CONSTRAINT ck_api_keys_tombstone CHECK (deleted_at IS NULL OR enabled = FALSE),
        CONSTRAINT ck_api_keys_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
        CONSTRAINT ck_api_keys_labels_json CHECK (JSON_VALID(labels)),
        CONSTRAINT ck_api_keys_pools_json CHECK (allowed_pools IS NULL OR JSON_VALID(allowed_pools))
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_api_keys_revision ON api_keys (revision)",
    "CREATE INDEX idx_api_keys_group ON api_keys (key_group)",
    "CREATE TABLE IF NOT EXISTS credentials (
        id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
        key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        kind VARCHAR(32) NOT NULL,
        slot TINYINT NOT NULL,
        public_id VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
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
        sub VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
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
        bucket_scope VARCHAR(8) NOT NULL,
        bucket_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        model VARCHAR(256) NOT NULL,
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
        bucket CHAR(10) NOT NULL,
        key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        provider VARCHAR(128) NOT NULL,
        model VARCHAR(256) NOT NULL,
        key_group_at_use VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
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
    // ── v7 (busbar 1.6.0) ─────────────────────────────────────────────────────────────────────
    //
    // THE NEUTRAL PLANE-RECORD TABLE. One table for every kind the engine's planes persist (`task`,
    // `task_event`, `call`, `demotion`, `push_config`, and any kind a plane registers later),
    // because busbar 1.6.0 names a durable record by its KIND STRING rather than by a per-protocol
    // `Store` method. `body` is the plane's OPAQUE serialized row: this store persists it and hands
    // it back BYTE-FOR-BYTE and never decodes it. Everything the store itself needs -- identity,
    // ordering, retention -- rides on the TYPED sidecar columns instead.
    //
    // IDENTITY is `(kind, ident, seq)`, the same key busbar's reference stores use: `ident` is the
    // record's `parent` when it is an APPENDED child (a chain position is `(parent, seq)`), else its
    // own `id` at seq 0. So an upsert kind is one row per id, and an append kind is one row per
    // chain position -- one primary key serves the point read, the upsert and the fork check.
    //
    // COLLATE utf8mb4_bin on every key column, for the reason the v4..v6 tables carried it: this
    // schema's default collation is utf8mb4_0900_ai_ci -- CASE- AND ACCENT-INSENSITIVE -- under which
    // two task ids, two principals or two upstreams differing only in case COLLIDE ON THE PRIMARY
    // KEY: one silently upserts onto the other, a scoped read hands one caller another caller's
    // chain, and an append is reported as a "fork" of a chain it never wrote. Binary rather than
    // `CHARACTER SET ascii` because an id is an opaque protocol-supplied string that may be
    // non-ASCII, and ascii would HARD-FAIL that write under STRICT_ALL_TABLES. VARCHAR(191) on the
    // keyed columns is the utf8mb4 length that keeps a key inside the index limit on the older
    // 3072-byte configurations this store still supports (the same reason store_meta.k is 191).
    //
    // `terminal` is the envelope's `PlaneDisposition` as a typed column, because retention has to
    // read it: the `task` kind drops only TERMINAL rows older than the cutoff (an interrupted task
    // waiting on a human is exactly the old row that must survive), and a backend that had to decode
    // the body to learn that would be a backend that names a plane's row type.
    //
    // BIGINT UNSIGNED for `seq`/`ts`, as for every other u64 here: the full u64 range round-trips
    // and there is no value the contract can hand this backend that it must refuse or mangle.
    //
    // NO FOREIGN KEY between a parent's rows and its children's, deliberately: the engine's
    // write-throughs state no ORDER between a task's first upsert and its first event, and a DELETE
    // trigger needs SUPER on a binlog-enabled server, which the app-level user does not hold. The
    // one cascade this store owes (a purged task takes its event chain with it) lives in
    // `purge_plane_records_before`, in the same transaction as the parent delete.
    "CREATE TABLE IF NOT EXISTS plane_records (
        kind VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
        ident VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        seq BIGINT UNSIGNED NOT NULL,
        id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        parent VARCHAR(191) COLLATE utf8mb4_bin NULL,
        ts BIGINT UNSIGNED NOT NULL,
        terminal BOOLEAN NOT NULL DEFAULT FALSE,
        body LONGBLOB NOT NULL,
        PRIMARY KEY (kind, ident, seq)
    ) ENGINE=InnoDB",
    // The retention sweep's access path: `purge_plane_records_before` deletes by (kind, ts < cutoff).
    // No IF NOT EXISTS -- MySQL has no such form for CREATE INDEX; a re-run's duplicate error is
    // swallowed by try_init_schema, exactly as it is for every other index here.
    "CREATE INDEX idx_plane_records_kind_ts ON plane_records (kind, ts)",
    // THE SINGLE-USE TOKEN LEDGER (`redeem_plane_token`) -- the durable record that makes a
    // confirm-once approval execute once across a restart AND across the nodes of a fleet. A sealed
    // token is valid bytes on its second presentation exactly as on its first; only a record that
    // the first happened tells them apart, and in process memory that record dies with the process
    // and is never shared with a second node. Keyed by `(kind, token)`, so the ledger is generic over
    // every single-use kind rather than hard-wiring one.
    //
    // COLLATE utf8mb4_bin on the key is the SHARPEST instance of the collation hazard in this file:
    // under the schema default the primary key stops telling a token from its case variants, so a
    // genuinely fresh approval would be REFUSED while an attacker's near-miss variants fold onto one
    // row. Byte-exact is the only correct comparison for a random token.
    "CREATE TABLE IF NOT EXISTS plane_tokens (
        kind VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
        token VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        expires_at BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (kind, token)
    ) ENGINE=InnoDB",
    // The eviction sweep's access path. Without it the sweep's `expires_at < :now` is a full table
    // scan, and a scan under InnoDB's REPEATABLE READ takes a lock on every row it visits -- which on
    // the one table every concurrent redemption in the fleet touches is a lock-wait storm.
    "CREATE INDEX idx_plane_tokens_expires ON plane_tokens (expires_at)",
    // THE OPEN USAGE UNITS of a budget window. busbar 1.6.0 made `ModelTokens` a name-keyed
    // `usage_units` map: the reserved four (`input`/`output`/`cache_read`/`cache_write`) keep their
    // existing `usage_windows` columns -- so a v3 row reads back unchanged with no data migration --
    // and every OTHER unit a plane declares (`tool_calls`, `bytes`, a rerank's search units, ...)
    // lands here, one row per (window, bucket, model, unit), so `add_usage` stays one atomic
    // `count = count + delta` upsert per unit rather than a read-modify-write of a JSON blob.
    // `unit` is utf8mb4_bin: two unit names differing in case are two counters, never one.
    "CREATE TABLE IF NOT EXISTS usage_window_units (
        window_start BIGINT UNSIGNED NOT NULL,
        bucket_scope VARCHAR(8) NOT NULL,
        bucket_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        model VARCHAR(256) NOT NULL,
        unit VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
        count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (window_start, bucket_scope, bucket_id, model, unit)
    ) ENGINE=InnoDB",
    // THE OPEN USAGE UNITS of a metering cell -- every ledgered class the token columns do not hold
    // (`MeteringRow::usage_units`), additive like them. Keyed by the metering cell's own key plus the
    // unit. No foreign key: the parent cell is written first in the same transaction, and
    // `purge_metering_before` removes both.
    "CREATE TABLE IF NOT EXISTS usage_metering_units (
        bucket CHAR(10) NOT NULL,
        key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        provider VARCHAR(128) NOT NULL,
        model VARCHAR(256) NOT NULL,
        priced_from_ms BIGINT UNSIGNED NOT NULL DEFAULT 0,
        unit VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
        count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms, unit)
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_metering_units_bucket ON usage_metering_units (bucket)",
];

/// MySQL/MariaDB-backed [`Store`]. A single mutex-guarded pooled connection is used for all control-
/// plane (keys/credentials/denylist) work — low frequency, correctness over throughput; usage/audit
/// writes go through the same pool without an explicit app-level mutex since the pool itself
/// serializes checkouts safely.
pub struct MysqlStore {
    pool: Pool,
}

impl MysqlStore {
    /// Connect, create the schema if absent, and run the boot-time invariant probes. Hard-fails
    /// (returns `Err`, never silently degrades) if the server can't actually enforce what the schema
    /// declares — see the module doc for why a version check alone is insufficient.
    ///
    /// The pool is capped small (8 connections) — this store is control-plane-frequency (key/
    /// credential CRUD) plus write-behind usage flush, not a high-fan-out OLTP workload, and an
    /// unbounded pool across many `MysqlStore::connect()` calls (e.g. one per test, or a multi-
    /// process fleet booting simultaneously) is what exhausts MySQL's default `max_connections`.
    pub fn connect(url: &str) -> RecordStoreResult<Self> {
        let opts = Opts::from_url(url).map_err(store_err)?;
        let opts = mysql::OptsBuilder::from_opts(opts)
            .pool_opts(mysql::PoolOpts::default().with_constraints(
                mysql::PoolConstraints::new(1, 8).expect("1 <= 8 is a valid pool constraint"),
            ))
            // ESTABLISH strict mode on every connection this pool ever creates -- including a
            // reconnect after a dropped connection, or the pool growing past the one connection
            // `probe_invariants` (below) checks at boot -- rather than verifying it once and
            // trusting every future connection inherits the same posture. Appends (never replaces)
            // to whatever sql_mode the server/session already carries, so an operator's other
            // modes survive. CHECK-constraint enforcement (the other boot-probe invariant) is a
            // server-wide, not session-scoped, property -- it can't diverge per connection the way
            // sql_mode can, so the one-time probe below remains sufficient for that half.
            .init(vec![
                "SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')",
            ]);
        let pool = Pool::new(opts).map_err(store_err)?;

        Self::init_schema(&pool)?;

        let mut conn = pool.get_conn().map_err(store_err)?;
        Self::probe_invariants(&mut conn)?;
        drop(conn);

        Ok(Self { pool })
    }

    /// Schema creation, retried on deadlock. Concurrent `CREATE TABLE`/`CREATE INDEX` from more than
    /// one connection (a multi-node fleet booting simultaneously against a fresh database, or —
    /// exactly this crate's own parallel test suite — is a REAL scenario, not just a test artifact:
    /// MySQL's metadata locking can genuinely deadlock two concurrent DDL statements against the
    /// same schema (`ERROR 1213`). A bounded retry-with-backoff is the correct response (the losing
    /// transaction is safe to retry — DDL here is idempotent via the `IF NOT EXISTS`/duplicate-error
    /// swallowing below), not a crash.
    fn init_schema(pool: &Pool) -> RecordStoreResult<()> {
        const MAX_ATTEMPTS: u32 = 8;
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_init_schema(pool) {
                Ok(()) => return Ok(()),
                Err(e) if attempt < MAX_ATTEMPTS && e.0.contains("Deadlock found") => {
                    // Linear backoff plus a per-process/per-thread jitter, so two booters that
                    // deadlocked once do not retry in lockstep and deadlock again.
                    let jitter = {
                        use std::hash::{Hash, Hasher};
                        let mut h = std::collections::hash_map::DefaultHasher::new();
                        std::thread::current().id().hash(&mut h);
                        std::process::id().hash(&mut h);
                        attempt.hash(&mut h);
                        h.finish() % 50
                    };
                    std::thread::sleep(std::time::Duration::from_millis(
                        50 * attempt as u64 + jitter,
                    ));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop always returns on the final attempt")
    }

    /// v2 one-time backfill, closing the SAME `hydrate_budgets` billing bug store-postgres's own v6
    /// backfill closes (busbar core's `crates/busbar/src/governance/state.rs`): pre-v2 rows may
    /// have `billable_requests = 0` alongside a real, positive `requests` count purely because this
    /// store didn't track the split before v2, never because of a genuine refund/discount. Trusting
    /// `billable_requests` unconditionally (as `hydrate_budgets` now does) needs those historical
    /// rows backfilled once, here, at the source — never re-derived from `requests` at read time by
    /// a heuristic (that heuristic is exactly the bug being closed). Only fires when crossing INTO v2
    /// from a database that genuinely predates it (`prior_version < 2` and `prior_version > 0`, i.e.
    /// `store_meta` already existed with an old value) — a brand-new v1-absent database has no
    /// pre-migration rows and must not run this pointless no-op.
    ///
    /// Takes `prior_version` as an explicit argument rather than reading `store_meta` itself, purely
    /// so the migration tests can call this directly with a hardcoded version and never have to
    /// mutate the single GLOBAL `store_meta.schema_version` row the whole shared test-server
    /// suite reads/writes on every `connect()`. Mutating that row instead races: any concurrently
    /// running test's own `connect()` unconditionally overwrites `schema_version` back to current,
    /// clobbering another test's deliberately-lowered marker.
    ///
    /// Also takes `table` rather than hardcoding `usage_windows`, again purely for test isolation:
    /// unlike store-postgres's own equivalent test (which runs each migration test against its own
    /// throwaway DATABASE), the CI `busbar` MySQL user has no `CREATE DATABASE` privilege (confirmed:
    /// `ERROR 1044 Access denied for user 'busbar'@'%' to database ...` — the official mysql image's
    /// `MYSQL_USER` mechanism only grants `ALL PRIVILEGES` on the one `MYSQL_DATABASE`, not globally)
    /// — table-level isolation within that one shared database is the only DDL this user can do, and
    /// it's real DDL the rest of this crate's suite already exercises freely. Production always calls
    /// this with `"usage_windows"`; the table parameter exists ONLY so a test can point it at a
    /// private scratch table instead of racing every other concurrently-running test's legitimate
    /// writes to the real, shared `usage_windows`.
    ///
    /// KNOWN, DOCUMENTED, NOT-YET-CLOSED GAP — and a lock is NOT the fix for it (see below): this
    /// UPDATE is UNSCOPED and assumes "a one-time
    /// boot migration runs before any concurrent traffic exists" — true for a full-fleet restart, but
    /// this store's own target topology is a ROLLING upgrade (README: multiple busbar nodes sharing
    /// one MySQL server). In a rolling upgrade, some nodes are ALREADY LIVE on v2 — genuinely writing
    /// `billable_requests > 0` via real traffic — while another node is still booting and about to
    /// run this backfill. If live traffic reaches a still-pre-v2 row before this UPDATE does, the
    /// predicate (`billable_requests = 0 AND requests > 0`) no longer matches it, and that row's
    /// PRE-v2 historical `requests` are PERMANENTLY never reclassified as billable — a silent,
    /// unrepairable billing undercount, i.e. exactly the `hydrate_budgets` bug class this migration
    /// exists to close, reintroduced by a race in the migration itself. A `GET_LOCK` does not close
    /// it: a lock can only serialize NODES STILL BOOTING against each other, and the backfill's own
    /// re-run is already idempotent, so that case was never unsafe in the first place. It does
    /// nothing about a node that is ALREADY LIVE and never enters this function at all, which is the
    /// actual race. Closing this for real needs pre-v2 rows to be identifiable by something live
    /// traffic cannot change (a captured `window_start`/time cutoff, or a per-row provenance
    /// marker), which is a schema redesign rather than a lock. OPERATIONAL MITIGATION
    /// until that redesign lands: either pause the whole fleet briefly for a v1->v2 upgrade
    /// specifically (not required for any OTHER version bump), or re-run this same predicate as a
    /// manual reconciliation query after a rolling upgrade completes — safe to do since the
    /// predicate is idempotent (a row already at `billable_requests > 0` never matches it again).
    /// See `characterize_v2_backfill_loses_a_row_to_a_racing_live_write` below for a reproduction.
    fn run_v2_backfill_if_needed(
        conn: &mut PooledConn,
        prior_version: u32,
        table: &str,
    ) -> RecordStoreResult<()> {
        if prior_version > 0 && prior_version < V2_BILLABLE_REQUESTS_BACKFILL {
            // Batched (LIMIT 5000 per statement, looped until exhausted), matching the same
            // bounded-batch convention purge_windows_before/purge_metering_before already use
            // elsewhere in this file -- an unbounded single UPDATE across the whole table risks
            // holding its lock/scan for a long time on a large production table, worse than
            // necessary even for a one-time migration.
            loop {
                conn.query_drop(format!(
                    "UPDATE {table} SET billable_requests = requests \
                     WHERE billable_requests = 0 AND requests > 0 LIMIT 5000"
                ))
                .map_err(store_err)?;
                if conn.affected_rows() < 5000 {
                    break;
                }
            }
        }
        Ok(())
    }

    /// v3: `usage_metering.key_group_at_use` shipped in v1.0.0 without `ascii_bin` (inherited
    /// MySQL's default case-INSENSITIVE collation) -- a real gap against this crate's own stated
    /// invariant that every opaque identifier/group-name column gets byte-exact comparison. The
    /// The `CREATE TABLE IF NOT EXISTS` declaration above only affects a FRESH database; any
    /// database created by a pre-v3 release already has the table at the wrong collation, so a real
    /// `ALTER TABLE` is required to close it on upgrade.
    /// Idempotent: MODIFY COLUMN to the same collation it's already at is a harmless no-op on a
    /// database created fresh (already ascii_bin) or one already migrated past v3.
    ///
    /// Same `table` parameter for test isolation as `run_v2_backfill_if_needed` -- see that
    /// function's doc comment for why (no `CREATE DATABASE` privilege in CI).
    fn run_v3_ascii_bin_fix_if_needed(
        conn: &mut PooledConn,
        prior_version: u32,
        table: &str,
    ) -> RecordStoreResult<()> {
        if prior_version > 0 && prior_version < V3_KEY_GROUP_AT_USE_ASCII_BIN {
            conn.query_drop(format!(
                "ALTER TABLE {table} MODIFY COLUMN key_group_at_use \
                 VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT ''"
            ))
            .map_err(store_err)?;
        }
        Ok(())
    }

    /// Whether `table` exists in the connected database. `DATABASE()` scopes the lookup to this
    /// store's own schema, so a same-named table in a sibling database on the server never answers.
    fn table_exists(conn: &mut PooledConn, table: &str) -> RecordStoreResult<bool> {
        let n: Option<u64> = conn
            .exec_first(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_schema = DATABASE() AND table_name = :t",
                params! { "t" => table },
            )
            .map_err(store_err)?;
        Ok(n.unwrap_or(0) > 0)
    }

    /// Whether index `index` exists on `table` in the connected database.
    fn index_exists(conn: &mut PooledConn, table: &str, index: &str) -> RecordStoreResult<bool> {
        let n: Option<u64> = conn
            .exec_first(
                "SELECT COUNT(*) FROM information_schema.statistics \
                 WHERE table_schema = DATABASE() AND table_name = :t AND index_name = :i",
                params! { "t" => table, "i" => index },
            )
            .map_err(store_err)?;
        Ok(n.unwrap_or(0) > 0)
    }

    /// Whether `table.column` exists in the connected database.
    fn column_exists(conn: &mut PooledConn, table: &str, column: &str) -> RecordStoreResult<bool> {
        let n: Option<u64> = conn
            .exec_first(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c",
                params! { "t" => table, "c" => column },
            )
            .map_err(store_err)?;
        Ok(n.unwrap_or(0) > 0)
    }

    /// ADD `column` to `table` unless it is already there. MySQL has no `ADD COLUMN IF NOT EXISTS`,
    /// so the check is explicit; a node booting concurrently can still win the race between the
    /// check and the ALTER, and its `ER_DUP_FIELDNAME` (1060) is exactly "already there", so it is
    /// swallowed. Every other error propagates.
    fn ensure_column(
        conn: &mut PooledConn,
        table: &str,
        column: &str,
        definition: &str,
    ) -> RecordStoreResult<()> {
        if Self::column_exists(conn, table, column)? {
            return Ok(());
        }
        match conn.query_drop(format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )) {
            Ok(()) => Ok(()),
            Err(mysql::Error::MySqlError(e)) if e.code == 1060 => Ok(()),
            Err(e) => Err(store_err(format!(
                "schema upgrade failed adding {table}.{column}: {e}"
            ))),
        }
    }

    /// v7 SCHEMA upgrade, IN PLACE and IDEMPOTENT. Gated on what the database actually HAS rather
    /// than on `schema_version`, so it converges whatever path a database took to get here: a fresh
    /// database already carries every column (the `CREATE TABLE`s above declare the v7 shape) and
    /// this is four cheap no-op lookups; a released 1.5.x database (v3) gains the columns; a crash
    /// half-way through is finished on the next boot.
    ///
    /// Purely ADDITIVE on `api_keys`: four NULLable trailing columns (an instant ADD on MySQL 8),
    /// every existing row reading back exactly as before -- `NULL` is `None` for every new field,
    /// which is what the 1.6.0 contract says a pre-field key reads as.
    ///
    /// `usage_metering` gains `priced_from_ms` (DEFAULT 0) AND it joins the PRIMARY KEY, because
    /// DECISION #79 makes it part of the accrual key: a rate-card edit inside a UTC day opens a
    /// SECOND cell for that day so each half prices at the card it was earned under. Every existing
    /// row takes `0`, which the contract defines as "the opening card", so no existing cell changes
    /// meaning, and the old key's rows are unique under the new key by construction (one value of
    /// the new column), so the rebuild cannot fail on a duplicate. The FK on `key_id` stays served:
    /// the new key still leads with `key_id`, and both halves happen in ONE `ALTER` so there is no
    /// instant where the table has no index the FK can use.
    ///
    /// `keys_table`/`metering_table` exist for test isolation only, like the `table` parameter on
    /// the v2/v3 steps; production passes `"api_keys"`/`"usage_metering"`.
    fn run_v7_schema_upgrade(
        conn: &mut PooledConn,
        keys_table: &str,
        metering_table: &str,
    ) -> RecordStoreResult<()> {
        Self::ensure_column(conn, keys_table, "allowed_scopes_ext", "JSON NULL")?;
        Self::ensure_column(conn, keys_table, "idp_subject", "TEXT NULL")?;
        Self::ensure_column(conn, keys_table, "binding_mode", "TEXT NULL")?;
        Self::ensure_column(conn, keys_table, "minted_by", "TEXT NULL")?;
        Self::ensure_column(
            conn,
            metering_table,
            "priced_from_ms",
            "BIGINT UNSIGNED NOT NULL DEFAULT 0",
        )?;
        let pk_has_it: Option<u64> = conn
            .exec_first(
                "SELECT COUNT(*) FROM information_schema.statistics \
                 WHERE table_schema = DATABASE() AND table_name = :t \
                 AND index_name = 'PRIMARY' AND column_name = 'priced_from_ms'",
                params! { "t" => metering_table },
            )
            .map_err(store_err)?;
        if pk_has_it.unwrap_or(0) == 0 {
            conn.query_drop(format!(
                "ALTER TABLE {metering_table} DROP PRIMARY KEY, \
                 ADD PRIMARY KEY (key_id, bucket, model, provider, priced_from_ms)"
            ))
            .map_err(|e| {
                store_err(format!(
                    "schema upgrade failed re-keying {metering_table} on priced_from_ms: {e}"
                ))
            })?;
        }
        Ok(())
    }

    /// v7 DATA step, ONE-TIME: carry the durable plane state a v4..v6 database holds in its
    /// per-protocol tables into the neutral `plane_records`/`plane_tokens` tables, in the envelope
    /// the 1.6.0 engine reads. Fires only when crossing INTO v7 from v4..v6 (`schema_version`
    /// gated, unlike the schema step above) -- after the crossing the engine owns those rows through
    /// the neutral verbs, and re-copying on a later boot would RESURRECT a demotion the engine has
    /// since cleared or a task it has since purged. A released 1.5.x database is v3 and has none of
    /// these tables, so for it this is a no-op.
    ///
    /// What moves, and in what shape (each body is the JSON object of the plane's own row, with the
    /// field names the plane decodes by):
    /// - `tasks` -> kind `task`, `ts` = `updated_at`, `terminal` from the same closed
    ///   [`TERMINAL_TASK_STATES`] set (compared byte-exactly) the v5 sweep used;
    /// - `task_events` -> kind `task_event`, parent = its task, keyed by `seq`. No `digest_version`
    ///   is written, so the engine reads these as the legacy framing they were sealed under;
    /// - `mcp_demotions` -> kind `demotion`, keyed by `server` -- a quarantine outlives the upgrade;
    /// - `spent_ask_states` -> the `ask` kind of the token ledger -- a spent approval stays spent.
    ///
    /// `mcp_calls` does NOT move, deliberately: busbar 1.6.0 persists a call as a neutral
    /// `{seq, prev_hash, hash, content}` journal body and states there is no legacy typed-body path
    /// to decode, so a copied row would only be skipped at the next boot as unreadable. It stays
    /// where it is. NOTHING here drops or rewrites a legacy table; they are simply no longer read.
    ///
    /// `ON DUPLICATE KEY UPDATE <table>.kind = <table>.kind` (a no-op), not `INSERT IGNORE`: a node booting concurrently makes
    /// the duplicate case real, and IGNORE would also downgrade every OTHER error -- a value too long
    /// for the new column, say -- to a warning and a silently truncated row.
    fn run_v7_plane_record_copy_if_needed(
        conn: &mut PooledConn,
        prior_version: u32,
    ) -> RecordStoreResult<()> {
        if !(4..V7_PLANE_RECORDS).contains(&prior_version) {
            return Ok(());
        }
        if Self::table_exists(conn, "tasks")? {
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
            .map_err(store_err)?;
        }
        if Self::table_exists(conn, "task_events")? {
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
            .map_err(store_err)?;
        }
        if Self::table_exists(conn, "mcp_demotions")? {
            conn.query_drop(
                "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
                 SELECT 'demotion', server, 0, server, NULL, recorded_at, FALSE, \
                        CAST(JSON_OBJECT('server', server, 'reason', reason, \
                                         'recorded_at', recorded_at) AS CHAR) \
                 FROM mcp_demotions \
                 ON DUPLICATE KEY UPDATE plane_records.kind = plane_records.kind",
            )
            .map_err(store_err)?;
        }
        if Self::table_exists(conn, "spent_ask_states")? {
            conn.query_drop(
                "INSERT INTO plane_tokens (kind, token, expires_at) \
                 SELECT 'ask', nonce, expires_at FROM spent_ask_states \
                 ON DUPLICATE KEY UPDATE plane_tokens.kind = plane_tokens.kind",
            )
            .map_err(store_err)?;
        }
        Ok(())
    }

    /// Read the version this database was AT before this boot from `store_meta`, tolerating "no row
    /// yet" (a genuinely fresh database, or one already at v2 that never needed a marker written
    /// pre-v2) as version 0, but propagating any OTHER query failure (a connection blip, a lock
    /// timeout) instead of silently treating it identically to "fresh install" -- collapsing those
    /// two outcomes previously meant a transient failure here permanently marked a possibly-
    /// unmigrated database as migrated (schema_version still got written unconditionally right
    /// after). A stored value that fails to parse as a version number is ALSO now a hard error
    /// rather than a silent 0 -- a corrupt marker is exactly the kind of "looks fine, isn't" state
    /// this store's own boot-probe philosophy (module doc, above) says must hard-fail, not warn.
    /// Takes `table` rather than hardcoding `store_meta`, purely for test isolation -- same reason
    /// `run_v2_backfill_if_needed` takes its own `table` param (see that function's doc comment):
    /// `store_meta` is a single shared row the whole test binary's `connect()` calls race on.
    /// Production always calls this with `"store_meta"`.
    fn read_prior_version(conn: &mut PooledConn, table: &str) -> RecordStoreResult<u32> {
        match conn
            .query_first::<Option<String>, _>(format!(
                "SELECT v FROM {table} WHERE k = 'schema_version'"
            ))
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

    fn try_init_schema(pool: &Pool) -> RecordStoreResult<()> {
        let mut conn = pool.get_conn().map_err(store_err)?;

        // `read_prior_version` needs `store_meta` to already exist -- create it FIRST (SCHEMA[0],
        // `IF NOT EXISTS` so harmless to re-run when the full loop below reaches it again) so a
        // genuinely fresh database's read is a real "no row" (Ok(None) -> version 0), not a
        // "table doesn't exist" query ERROR that read_prior_version's error-propagation would now
        // (correctly, for every OTHER failure) treat as a hard failure.
        conn.query_drop(SCHEMA[0]).map_err(store_err)?;
        let prior_version = Self::read_prior_version(&mut conn, "store_meta")?;

        for stmt in SCHEMA {
            // An index that is ALREADY THERE is skipped without issuing the DDL at all. A
            // `CREATE INDEX` that is going to fail as a duplicate still takes an exclusive
            // metadata lock first, so every boot of an up-to-date database used to run a dozen DDL
            // statements for nothing -- and several nodes (or this crate's parallel tests) booting
            // at once then deadlocked on each other's metadata locks (ERROR 1213). Checking first
            // makes a steady-state boot DDL-free apart from `CREATE TABLE IF NOT EXISTS`, which
            // only takes a shared lock on a table that exists.
            if let Some((index, table)) = parse_create_index(stmt) {
                if Self::index_exists(&mut conn, table, index)? {
                    continue;
                }
            }
            // IF NOT EXISTS on tables; CREATE INDEX has no IF NOT EXISTS in MySQL/MariaDB, so a
            // "duplicate key name" error (a concurrent booter won the race after the check above)
            // is swallowed here — every other error propagates.
            if let Err(e) = conn.query_drop(*stmt) {
                let msg = e.to_string();
                if !(msg.contains("Duplicate key name") || msg.contains("already exists")) {
                    return Err(store_err(format!(
                        "schema init failed: {msg}\nstatement: {stmt}"
                    )));
                }
            }
        }

        Self::run_v2_backfill_if_needed(&mut conn, prior_version, "usage_windows")?;
        Self::run_v3_ascii_bin_fix_if_needed(&mut conn, prior_version, "usage_metering")?;
        Self::run_v7_schema_upgrade(&mut conn, "api_keys", "usage_metering")?;
        Self::run_v7_plane_record_copy_if_needed(&mut conn, prior_version)?;

        conn.query_drop(
            "INSERT INTO store_meta (k, v) VALUES ('schema_version', :v) \
             ON DUPLICATE KEY UPDATE v = :v"
                .replace(':', "?")
                .replace("?v", &format!("'{SCHEMA_VERSION}'")),
        )
        .map_err(store_err)?;
        conn.query_drop(
            "INSERT INTO store_sequence (id, revision) VALUES (1, 0) \
             ON DUPLICATE KEY UPDATE id = id",
        )
        .map_err(store_err)?;

        Ok(())
    }

    /// A rejected probe INSERT is proof of CHECK enforcement ONLY if it's the SPECIFIC
    /// CHECK-violation error this schema's two target engines actually produce -- MySQL 8.0.16+'s
    /// `ER_CHECK_CONSTRAINT_VIOLATED` (3819) or MariaDB's `ER_CONSTRAINT_FAILED` (4025). Any other
    /// error (a lock timeout, a connection blip) is inconclusive and must never be silently read as
    /// "enforced" -- that was the bug: the prior code treated ANY error as proof.
    fn is_check_constraint_violation(e: &mysql::Error) -> bool {
        matches!(e, mysql::Error::MySqlError(inner) if inner.code == 3819 || inner.code == 4025)
    }

    /// Live functional probes for the two failure modes a schema-shape check cannot catch:
    /// (1) `CHECK` constraints parsed but not enforced (MySQL < 8.0.16, Aurora MySQL 2.x);
    /// (2) `STRICT_ALL_TABLES` not in `sql_mode` (a VARCHAR/BIGINT overflow silently truncates
    ///     instead of erroring). (1) is probed via a session-private `TEMPORARY` table (never the
    ///     real shared schema — zero contention with real traffic or another node's simultaneous
    ///     probe), dropped immediately after; no probe row ever touches real data.
    fn probe_invariants(conn: &mut PooledConn) -> RecordStoreResult<()> {
        let sql_mode: String = conn
            .query_first("SELECT @@sql_mode")
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
        .map_err(store_err)?;
        let probe_result = conn.query_drop("INSERT INTO busbar_check_probe (id) VALUES (999)");
        let _ = conn.query_drop("DROP TEMPORARY TABLE busbar_check_probe");

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

    fn conn(&self) -> RecordStoreResult<PooledConn> {
        self.pool.get_conn().map_err(store_err)
    }

    /// Bump `store_sequence` and return the new revision. MUST be the first statement of every
    /// control-plane transaction (mint/revoke/rotate/delete) — this fixed lock order
    /// (store_sequence -> api_keys -> credentials -> denylist) is what makes deadlock across the
    /// admin plane structurally impossible. Never call this outside an active transaction.
    fn bump_revision(tx: &mut mysql::Transaction<'_>) -> RecordStoreResult<u64> {
        tx.query_drop("UPDATE store_sequence SET revision = revision + 1 WHERE id = 1")
            .map_err(store_err)?;
        tx.query_first("SELECT revision FROM store_sequence WHERE id = 1")
            .map_err(store_err)?
            .ok_or_else(|| store_err("store_sequence row missing"))
    }

    fn row_to_key(mut row: mysql::Row) -> RecordStoreResult<VirtualKey> {
        let id: String = row
            .take("id")
            .ok_or_else(|| store_err("missing column: id"))?;
        let generation_hash: String = row
            .take("generation_hash")
            .ok_or_else(|| store_err("missing column: generation_hash"))?;
        let name: String = row
            .take("name")
            .ok_or_else(|| store_err("missing column: name"))?;
        let allowed_pools_json: Option<String> = row.take("allowed_pools").unwrap_or(None);
        let labels_json: String = row
            .take("labels")
            .ok_or_else(|| store_err("missing column: labels"))?;
        let enabled: bool = row
            .take("enabled")
            .ok_or_else(|| store_err("missing column: enabled"))?;
        let created_at: u64 = row
            .take("created_at")
            .ok_or_else(|| store_err("missing column: created_at"))?;
        let key_group: String = row
            .take("key_group")
            .ok_or_else(|| store_err("missing column: key_group"))?;
        let expires_at: Option<u64> = row.take("expires_at").unwrap_or(None);
        let deleted_at: Option<u64> = row.take("deleted_at").unwrap_or(None);
        let revision: u64 = row
            .take("revision")
            .ok_or_else(|| store_err("missing column: revision"))?;

        let allowed_scopes_ext: Option<String> = row.take("allowed_scopes_ext").unwrap_or(None);
        let idp_subject: Option<String> = row.take("idp_subject").unwrap_or(None);
        let binding_mode: Option<String> = row.take("binding_mode").unwrap_or(None);
        let minted_by: Option<String> = row.take("minted_by").unwrap_or(None);

        let allowed_scopes = assemble_scopes(allowed_pools_json, allowed_scopes_ext)?;
        let labels = serde_json::from_str(&labels_json).map_err(store_err)?;

        Ok(VirtualKey {
            id,
            generation_hash,
            name,
            allowed_scopes,
            enabled,
            created_at,
            group: if key_group.is_empty() {
                None
            } else {
                Some(key_group)
            },
            labels,
            expires_at,
            deleted_at,
            revision,
            idp_subject,
            binding_mode,
            minted_by,
        })
    }

    /// Reads its columns by NAME, not position — safe to call after the caller has already
    /// `row.take()`n an extra column (e.g. `secret`) out of a wider `SELECT`, which a positional
    /// `mysql::from_row_opt` tuple conversion cannot tolerate (it requires an exact column count
    /// match and errors on any row shape it doesn't recognize as a valid conversion target).
    fn row_to_cred_meta(mut row: mysql::Row) -> RecordStoreResult<CredentialMeta> {
        let id: String = row
            .take("id")
            .ok_or_else(|| store_err("missing column: id"))?;
        let key_id: String = row
            .take("key_id")
            .ok_or_else(|| store_err("missing column: key_id"))?;
        let kind: String = row
            .take("kind")
            .ok_or_else(|| store_err("missing column: kind"))?;
        let slot: i8 = row
            .take("slot")
            .ok_or_else(|| store_err("missing column: slot"))?;
        let public_id: String = row
            .take("public_id")
            .ok_or_else(|| store_err("missing column: public_id"))?;
        let secret_form: String = row
            .take("secret_form")
            .ok_or_else(|| store_err("missing column: secret_form"))?;
        let created_at: u64 = row
            .take("created_at")
            .ok_or_else(|| store_err("missing column: created_at"))?;
        let updated_at: u64 = row
            .take("updated_at")
            .ok_or_else(|| store_err("missing column: updated_at"))?;
        let expires_at: Option<u64> = row.take("expires_at").unwrap_or(None);
        let revoked_at: Option<u64> = row.take("revoked_at").unwrap_or(None);
        let revoke_reason: Option<String> = row.take("revoke_reason").unwrap_or(None);
        let revision: u64 = row
            .take("revision")
            .ok_or_else(|| store_err("missing column: revision"))?;

        Ok(CredentialMeta {
            id,
            key_id,
            kind,
            slot: slot as u8,
            public_id,
            secret_form: parse_secret_form(&secret_form)?,
            created_at,
            updated_at,
            expires_at,
            revoked_at,
            revoke_reason,
            revision,
        })
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
     minted_by";

/// PARTITION `allowed_scopes` into its two columns: `allowed_pools` (the `pool` kind, a JSON array
/// of bare names -- byte-for-byte the v3 shape, so a 1.5.x node reading a row mid-rolling-upgrade
/// sees exactly the pool grant it always did) and `allowed_scopes_ext` (every OTHER kind, as a JSON
/// array of `[kind, value]` pairs).
///
/// This used to write ONLY the value of every scope into `allowed_pools`, whatever its kind -- so
/// an `mcp_server` grant came back from the store as a POOL grant: the MCP grant lost AND a pool
/// the key was never given admitted. busbar 1.6.0 ships non-`pool` kinds (`mcp_server`, `agent`),
/// which makes that a live escalation, not a latent one. A kind is never remapped and never dropped.
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
        // REGISTER every non-`pool` kind this row carries with the scope-kind wire registry of the
        // image this code runs in. When this store runs as a PLUGIN, that is the cdylib's OWN copy
        // of the registry, which the engine's boot-time registration (`PlaneDecl.scope_kinds`) never
        // reaches -- so a key granting an `mcp_server` or `agent` scope could not be serialized back
        // across the store ABI at all ("scope kind 'mcp_server' has no registered wire field"), and
        // the engine's governance boot, which lists every key, refused to start. Registering here is
        // sound: the grant was serialized ENGINE-side under this exact kind when it was written,
        // which the registry only permits for a registered kind, and registration only names the
        // kind's wire field (`allowed_{kind}s`); it never remaps or widens a grant.
        for (kind, _) in &other {
            busbar_contract::records::register_scope_kind(kind);
        }
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

impl RecordStore for MysqlStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;

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
                .map_err(store_err)?;
            if let Some((Some(_),)) = existing {
                tx.rollback().map_err(store_err)?;
                return Err(store_err(format!(
                    "put_key: '{}' is tombstoned and its id is never reissued; refusing to clear \
                     the tombstone",
                    key.id
                )));
            }
        }

        let (pools_json, ext_json) = partition_scopes(&key.allowed_scopes)?;
        let labels_json = serde_json::to_string(&key.labels).map_err(store_err)?;
        let group = key.group.clone().unwrap_or_default();

        tx.exec_drop(
            "INSERT INTO api_keys
                (id, name, key_group, allowed_pools, allowed_scopes_ext, labels, enabled,
                 generation_hash, created_at, updated_at, expires_at, deleted_at, revision,
                 idp_subject, binding_mode, minted_by)
             VALUES (:id, :name, :key_group, :pools, :ext, :labels, :enabled, :gen, :created,
                     :updated, :expires, :deleted, :rev, :idp, :binding, :minted_by)
             ON DUPLICATE KEY UPDATE
                name = VALUES(name), key_group = VALUES(key_group), allowed_pools = VALUES(allowed_pools),
                allowed_scopes_ext = VALUES(allowed_scopes_ext),
                labels = VALUES(labels), enabled = VALUES(enabled), generation_hash = VALUES(generation_hash),
                updated_at = VALUES(updated_at), expires_at = VALUES(expires_at),
                deleted_at = VALUES(deleted_at), revision = VALUES(revision),
                idp_subject = VALUES(idp_subject), binding_mode = VALUES(binding_mode),
                minted_by = VALUES(minted_by)",
            params! {
                "id" => &key.id,
                "name" => &key.name,
                "key_group" => &group,
                "pools" => &pools_json,
                "ext" => &ext_json,
                "labels" => &labels_json,
                "enabled" => key.enabled,
                "gen" => &key.generation_hash,
                "created" => key.created_at,
                "updated" => key.created_at,
                "expires" => key.expires_at,
                "deleted" => key.deleted_at,
                "rev" => rev,
                "idp" => &key.idp_subject,
                "binding" => &key.binding_mode,
                "minted_by" => &key.minted_by,
            },
        )
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        let mut conn = self.conn()?;
        let row: Option<mysql::Row> = conn
            .exec_first(
                format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE id = :id"),
                params! { "id" => id },
            )
            .map_err(store_err)?;
        row.map(Self::row_to_key).transpose()
    }

    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .query(format!("SELECT {KEY_COLUMNS} FROM api_keys"))
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_key).collect()
    }

    fn list_keys_since(&self, since: u64) -> RecordStoreResult<Vec<VirtualKey>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .exec(
                format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE revision > :since"),
                params! { "since" => since },
            )
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_key).collect()
    }

    /// TOMBSTONE, not row removal — see the trait doc. Cascades credential destruction, sets
    /// enabled=false + deleted_at, all in ONE transaction with ONE revision stamp on the api_keys
    /// row, so a hydrator reading a consistent snapshot can never observe the tombstone without the
    /// credentials already gone (the hard-delete-invisible-to-hydration fix).
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;

        // bump_revision FIRST, matching the crate's fixed lock order (store_sequence before
        // api_keys) — the existence/state check below still runs before any write, it just
        // acquires its FOR UPDATE lock second. A no-op path (unknown id / already tombstoned)
        // rolls the transaction back, so the revision it consumed is never observably committed;
        // per the locked design, gaps in the sequence are harmless, only inversions are fatal.
        let rev = Self::bump_revision(&mut tx)?;

        // Explicit existence/state check — rows_affected() alone can't distinguish
        // "not found" from "already tombstoned, no-op" (both report 0 rows changed).
        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .map_err(store_err)?;
        let Some((deleted_at,)) = existing else {
            tx.rollback().map_err(store_err)?;
            // NOT the same case as already-tombstoned below. "Already tombstoned" means the
            // operator's intent is satisfied and the evidence is on disk; "no such id" means
            // nothing was touched, and Ok(()) there tells an operator who typo'd an id that a key
            // was revoked when none was.
            return Err(store_err(format!("delete_key: unknown id '{id}'")));
        };
        if deleted_at.is_some() {
            tx.rollback().map_err(store_err)?;
            return Ok(()); // already tombstoned: idempotent no-op per the trait doc
        }

        let now = crate_now();

        tx.exec_drop(
            "DELETE FROM credentials WHERE key_id = :id",
            params! { "id" => id },
        )
        .map_err(store_err)?;

        tx.exec_drop(
            "UPDATE api_keys SET enabled = FALSE, deleted_at = :now, updated_at = :now, revision = :rev \
             WHERE id = :id",
            params! { "now" => now, "rev" => rev, "id" => id },
        )
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn scrub_key(&self, id: &str) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;

        // bump_revision FIRST — see delete_key's comment on the fixed lock order.
        let rev = Self::bump_revision(&mut tx)?;

        let existing: Option<(Option<u64>,)> = tx
            .exec_first(
                "SELECT deleted_at FROM api_keys WHERE id = :id FOR UPDATE",
                params! { "id" => id },
            )
            .map_err(store_err)?;
        match existing {
            None => {
                tx.rollback().map_err(store_err)?;
                Err(store_err(format!("scrub_key: unknown id '{id}'")))
            }
            Some((None,)) => {
                tx.rollback().map_err(store_err)?;
                Err(store_err(format!(
                    "scrub_key: key '{id}' is not tombstoned — delete_key first"
                )))
            }
            Some((Some(_),)) => {
                let now = crate_now();
                tx.exec_drop(
                    "UPDATE api_keys SET name = '', labels = '{}', updated_at = :now, revision = :rev \
                     WHERE id = :id",
                    params! { "now" => now, "rev" => rev, "id" => id },
                )
                .map_err(store_err)?;
                tx.commit().map_err(store_err)
            }
        }
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        let mut conn = self.conn()?;
        let rows: Vec<(String, u64, u64, u64, u64)> = conn
            .exec(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write \
                 FROM usage_windows WHERE bucket_id = :b AND window_start = :w AND model <> ''",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .map_err(store_err)?;
        // `SUM()` with no GROUP BY always returns exactly one row, even when zero rows match the
        // WHERE clause — it returns SQL NULL for each aggregate, not an empty result set. So
        // `exec_first::<(u64, u64)>` is NEVER `None` here (that would require zero rows, which
        // never happens); instead it was a `Some(Row)` whose columns are NULL for a bucket/window
        // with no usage yet, and mysql_common's `FromRow` for a non-Option tuple PANICS trying to
        // convert NULL into `u64` (confirmed: this crashed the freshly-restarted process during
        // governance boot's budget hydration on a brand-new store, well before it enforced
        // `STRICT_ALL_TABLES` any differently — this is a Rust-side conversion bug, not a sql_mode
        // issue). `COALESCE(..., 0)` makes MySQL itself hand back 0 for the empty-aggregate case,
        // matching Postgres/SQLite's "no row yet" -> 0 semantics.
        let totals: Option<(u64, u64)> = conn
            .exec_first(
                "SELECT COALESCE(SUM(requests), 0), COALESCE(SUM(billable_requests), 0) \
                 FROM usage_windows WHERE bucket_id = :b AND window_start = :w",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .map_err(store_err)?;
        let (requests, billable_requests) = totals.unwrap_or((0, 0));
        // The OPEN units (everything but the reserved four) for this window, merged onto their
        // model's entry. A model that carries only open units still has its `usage_windows` row --
        // `put_usage`/`add_usage` always write one per model -- so it is already in `rows`; the
        // `or_insert` below only guards a row an operator deleted by hand.
        let open: Vec<(String, String, u64)> = conn
            .exec(
                "SELECT model, unit, count FROM usage_window_units \
                 WHERE bucket_id = :b AND window_start = :w AND bucket_scope = 'key' \
                 ORDER BY model, unit",
                params! { "b" => bucket_id, "w" => window_start },
            )
            .map_err(store_err)?;

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

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
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
        .map_err(store_err)?;
        // The window's OPEN units are part of the same absolute set: a unit the new ledger no
        // longer carries must not survive it.
        tx.exec_drop(
            "DELETE FROM usage_window_units \
             WHERE window_start = :w AND bucket_scope = 'key' AND bucket_id = :b",
            params! { "b" => bucket_id, "w" => window_start },
        )
        .map_err(store_err)?;
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
        .map_err(store_err)?;
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
            .map_err(store_err)?;
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
                .map_err(store_err)?;
            }
        }
        tx.commit().map_err(store_err)
    }

    fn add_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;

        // Pre-dedupe by (bucket_id, window_start, model) — a batch with duplicate PKs in one
        // multi-row upsert would hit "cannot affect row a second time" on Postgres and undefined
        // last-writer-wins on MySQL; the caller is trusted to flush one model at most once per
        // call here (this is the per-delta path, not a batch upsert), so this loop just applies
        // each model delta as its own upsert.
        // The window's request counters accumulate ONCE, on the reserved `model = ''` sentinel row,
        // not once per model. Applied inside the per-model loop instead, a single delta added its
        // request count once for every model it carried, and a delta with no models recorded
        // nothing. This is the fleet flush primitive, so both errors compounded permanently across
        // every node and every flush interval.
        tx.exec_drop(
            "INSERT INTO usage_windows
                (window_start, bucket_scope, bucket_id, model, requests, billable_requests)
             VALUES (:w, 'key', :b, '', GREATEST(0, :req), GREATEST(0, :breq))
             ON DUPLICATE KEY UPDATE
                requests = GREATEST(0, CAST(requests AS SIGNED) + :req),
                billable_requests = GREATEST(0, CAST(billable_requests AS SIGNED) + :breq)",
            params! {
                "w" => window_start, "b" => bucket_id,
                "req" => delta.requests, "breq" => delta.billable_requests,
            },
        )
        .map_err(store_err)?;
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
            tx.exec_drop(
                "INSERT INTO usage_windows
                    (window_start, bucket_scope, bucket_id, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES (:w, 'key', :b, :model,
                         GREATEST(0, :ti), GREATEST(0, :to_), GREATEST(0, :cr), GREATEST(0, :cw))
                 ON DUPLICATE KEY UPDATE
                    tokens_input = GREATEST(0, CAST(tokens_input AS SIGNED) + :ti),
                    tokens_output = GREATEST(0, CAST(tokens_output AS SIGNED) + :to_),
                    tokens_cache_read = GREATEST(0, CAST(tokens_cache_read AS SIGNED) + :cr),
                    tokens_cache_write = GREATEST(0, CAST(tokens_cache_write AS SIGNED) + :cw)",
                params! {
                    "w" => window_start, "b" => bucket_id, "model" => &m.model,
                    "ti" => ti, "to_" => to, "cr" => cr, "cw" => cw,
                },
            )
            .map_err(store_err)?;
            // Every OPEN unit accumulates the same way, floored at 0, one atomic upsert per unit
            // (BTreeMap order, so concurrent flushes take the rows in one order).
            for (unit, d) in open {
                tx.exec_drop(
                    "INSERT INTO usage_window_units
                        (window_start, bucket_scope, bucket_id, model, unit, count)
                     VALUES (:w, 'key', :b, :model, :unit, GREATEST(0, :d))
                     ON DUPLICATE KEY UPDATE count = GREATEST(0, CAST(count AS SIGNED) + :d)",
                    params! {
                        "w" => window_start, "b" => bucket_id, "model" => &m.model,
                        "unit" => unit, "d" => d,
                    },
                )
                .map_err(store_err)?;
            }
        }
        tx.commit().map_err(store_err)
    }

    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        let bucket = format!("{:010}", delta.bucket); // matches the CHAR(10) 'YYYY-MM-DD'-shaped bucket
        let mut conn = self.conn()?;
        // ONE transaction for the cell and its open units, so a reader never sees a cell's token
        // counts advanced without the units the same response accrued (or the reverse).
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        // `priced_from_ms` is part of the KEY (DECISION #79): a rate-card edit inside the UTC day
        // opens a SECOND cell for that day, so each half keeps the card it was earned under rather
        // than one card repricing the whole day.
        tx.exec_drop(
            "INSERT INTO usage_metering
                (bucket, key_id, provider, model, key_group_at_use, pricing_version, priced_from_ms,
                 requests, billable_requests, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
             VALUES (:bucket, :key, :provider, :model, :grp, :pv, :pfm, :req, :breq, :ti, :to_, :cr, :cw)
             ON DUPLICATE KEY UPDATE
                requests = requests + VALUES(requests),
                billable_requests = billable_requests + VALUES(billable_requests),
                tokens_input = tokens_input + VALUES(tokens_input),
                tokens_output = tokens_output + VALUES(tokens_output),
                tokens_cache_read = tokens_cache_read + VALUES(tokens_cache_read),
                tokens_cache_write = tokens_cache_write + VALUES(tokens_cache_write)",
            params! {
                "bucket" => &bucket, "key" => &delta.key_id, "provider" => &delta.provider,
                "model" => &delta.model, "grp" => &delta.key_group_at_use, "pv" => &delta.pricing_version,
                "pfm" => delta.priced_from_ms,
                "req" => delta.requests, "breq" => delta.billable_requests,
                "ti" => delta.tokens_input, "to_" => delta.tokens_output,
                "cr" => delta.tokens_cache_read, "cw" => delta.tokens_cache_write,
            },
        )
        .map_err(store_err)?;
        // Every ledgered class the token columns do not hold, additive like them (BTreeMap order,
        // so concurrent writers take the unit rows in one order).
        for (unit, n) in &delta.usage_units {
            tx.exec_drop(
                "INSERT INTO usage_metering_units
                    (bucket, key_id, provider, model, priced_from_ms, unit, count)
                 VALUES (:bucket, :key, :provider, :model, :pfm, :unit, :n)
                 ON DUPLICATE KEY UPDATE count = count + VALUES(count)",
                params! {
                    "bucket" => &bucket, "key" => &delta.key_id, "provider" => &delta.provider,
                    "model" => &delta.model, "pfm" => delta.priced_from_ms, "unit" => unit, "n" => *n,
                },
            )
            .map_err(store_err)?;
        }
        tx.commit().map_err(store_err)
    }

    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        let bucket_s = format!("{bucket:010}");
        let mut conn = self.conn()?;
        let rows: Vec<MeteringRowTuple> = conn
            .exec(
                "SELECT key_id, model, provider, tokens_input, tokens_output, tokens_cache_read, \
                 tokens_cache_write, requests, billable_requests, key_group_at_use, pricing_version, \
                 priced_from_ms FROM usage_metering WHERE bucket = :b",
                params! { "b" => &bucket_s },
            )
            .map_err(store_err)?;
        let units: Vec<(String, String, String, u64, String, u64)> = conn
            .exec(
                "SELECT key_id, model, provider, priced_from_ms, unit, count \
                 FROM usage_metering_units WHERE bucket = :b",
                params! { "b" => &bucket_s },
            )
            .map_err(store_err)?;
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
        Ok(rows
            .into_iter()
            .map(
                |(
                    key_id,
                    model,
                    provider,
                    tokens_input,
                    tokens_output,
                    tokens_cache_read,
                    tokens_cache_write,
                    requests,
                    billable_requests,
                    key_group_at_use,
                    pricing_version,
                    priced_from_ms,
                )| {
                    let usage_units = by_cell
                        .remove(&(
                            key_id.clone(),
                            model.clone(),
                            provider.clone(),
                            priced_from_ms,
                        ))
                        .unwrap_or_default();
                    MeteringRow {
                        key_id,
                        model,
                        provider,
                        tokens_input,
                        tokens_output,
                        tokens_cache_read,
                        tokens_cache_write,
                        requests,
                        billable_requests,
                        key_group_at_use,
                        pricing_version,
                        priced_from_ms,
                        usage_units,
                    }
                },
            )
            .collect())
    }

    fn purge_windows_before(&self, before: u64) -> RecordStoreResult<u64> {
        // Batched AND LOOPED. The batch bound keeps any single DELETE's lock footprint and undo log
        // small, which is why it is here; without the loop it also silently capped the purge at one
        // batch, so a retention backlog larger than the cap was never swept and each tick returned a
        // nonzero count that looked like progress. The contract is "purge every window below the
        // cutoff", and the returned figure is the total actually deleted.
        const BATCH: u64 = 5000;
        let mut conn = self.conn()?;
        let mut total = 0u64;
        loop {
            conn.exec_drop(
                "DELETE FROM usage_windows WHERE window_start < :b LIMIT 5000",
                params! { "b" => before },
            )
            .map_err(store_err)?;
            let n = conn.affected_rows();
            total += n;
            if n < BATCH {
                break;
            }
        }
        // The same windows' OPEN units, swept by the same rule. Not added to the returned figure:
        // that counts the ledger rows the contract names, and a unit row is part of one of them.
        loop {
            conn.exec_drop(
                "DELETE FROM usage_window_units WHERE window_start < :b LIMIT 5000",
                params! { "b" => before },
            )
            .map_err(store_err)?;
            if conn.affected_rows() < BATCH {
                break;
            }
        }
        Ok(total)
    }

    fn purge_metering_before(&self, bucket: &str) -> RecordStoreResult<u64> {
        // The `bucket` column is CHAR(10) and BOTH the write path (`add_metering`) and the read path
        // (`list_metering`) zero-pad into it. Only this method compared the caller's string as given,
        // so the obvious caller (a u64 bucket rendered the obvious way) matched zero of its own rows
        // and got a successful purge of nothing. Pad the same way when the input is numeric; a
        // non-numeric value is passed through unchanged so an already-padded caller still works.
        let padded = match bucket.trim().parse::<u64>() {
            Ok(n) => format!("{n:010}"),
            Err(_) => bucket.to_string(),
        };
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        // The cells' open units go with them, in the same transaction.
        tx.exec_drop(
            "DELETE FROM usage_metering_units WHERE bucket = :b",
            params! { "b" => &padded },
        )
        .map_err(store_err)?;
        tx.exec_drop(
            "DELETE FROM usage_metering WHERE bucket = :b",
            params! { "b" => &padded },
        )
        .map_err(store_err)?;
        // Read BEFORE the commit: `affected_rows` reports the LAST statement on this connection,
        // and the COMMIT is one. This is the number of metering CELLS removed.
        let removed = tx.affected_rows();
        tx.commit().map_err(store_err)?;
        Ok(removed)
    }

    fn put_credential(&self, secret: &CredentialSecret) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;
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
            .map_err(store_err)?;
        match owner {
            None => {
                tx.rollback().map_err(store_err)?;
                return Err(store_err(format!(
                    "put_credential: owning key '{}' does not exist",
                    m.key_id
                )));
            }
            Some((Some(_),)) => {
                tx.rollback().map_err(store_err)?;
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
            )
            .map_err(store_err)?;
        if let Some((None,)) = occupied {
            tx.rollback().map_err(store_err)?;
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
                    updated_at = :updated, expires_at = :expires, revoked_at = NULL,
                    revoke_reason = NULL, revision = :rev
                 WHERE key_id = :key AND kind = :kind AND slot = :slot",
                params! {
                    "id" => &m.id, "key" => &m.key_id, "kind" => &m.kind, "slot" => m.slot,
                    "pub" => &m.public_id, "secret" => &secret.secret,
                    "form" => secret_form_str(&m.secret_form),
                    "updated" => m.updated_at, "expires" => m.expires_at, "rev" => rev,
                },
            )
        } else {
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
        }
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;

        let (pools_json, ext_json) = partition_scopes(&key.allowed_scopes)?;
        let labels_json = serde_json::to_string(&key.labels).map_err(store_err)?;
        let group = key.group.clone().unwrap_or_default();

        tx.exec_drop(
            "INSERT INTO api_keys
                (id, name, key_group, allowed_pools, allowed_scopes_ext, labels, enabled,
                 generation_hash, created_at, updated_at, expires_at, deleted_at, revision,
                 idp_subject, binding_mode, minted_by)
             VALUES (:id, :name, :key_group, :pools, :ext, :labels, :enabled, :gen, :created,
                     :updated, :expires, NULL, :rev, :idp, :binding, :minted_by)",
            params! {
                "id" => &key.id, "name" => &key.name, "key_group" => &group, "pools" => &pools_json,
                "ext" => &ext_json,
                "labels" => &labels_json, "enabled" => key.enabled, "gen" => &key.generation_hash,
                "created" => key.created_at, "updated" => key.created_at, "expires" => key.expires_at,
                "rev" => rev, "idp" => &key.idp_subject, "binding" => &key.binding_mode,
                "minted_by" => &key.minted_by,
            },
        )
        .map_err(store_err)?;

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
        .map_err(store_err)?;

        tx.commit().map_err(store_err)
    }

    fn list_credentials(&self, key_id: &str) -> RecordStoreResult<Vec<CredentialMeta>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .exec(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision FROM credentials WHERE key_id = :k",
                params! { "k" => key_id },
            )
            .map_err(store_err)?;
        rows.into_iter().map(Self::row_to_cred_meta).collect()
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        let mut conn = self.conn()?;
        let row: Option<(mysql::Row, Option<String>)> = conn
            .exec_first(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision, secret FROM credentials \
                 WHERE kind = :kind AND public_id = :pub",
                params! { "kind" => kind, "pub" => public_id },
            )
            .map_err(store_err)
            .and_then(|r: Option<mysql::Row>| {
                r.map(|mut row| {
                    let secret: Option<String> = row.take("secret");
                    Ok((row, secret))
                })
                .transpose()
            })?;

        match row {
            None => Ok(None),
            Some((row, secret)) => {
                let meta = Self::row_to_cred_meta(row)?;
                Ok(Some(CredentialSecret {
                    meta,
                    secret: secret.unwrap_or_default(),
                }))
            }
        }
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;

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
            .map_err(store_err)?;
        if existing.is_none() {
            tx.rollback().map_err(store_err)?;
            return Err(store_err(format!(
                "revoke_credential: unknown credential id {id}"
            )));
        }

        let now = crate_now();
        tx.exec_drop(
            "UPDATE credentials SET revoked_at = :now, revoke_reason = :reason, updated_at = :now, \
             revision = :rev WHERE id = :id AND revoked_at IS NULL",
            params! { "now" => now, "reason" => reason, "rev" => rev, "id" => id },
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)
    }

    fn list_credentials_since(&self, since: u64) -> RecordStoreResult<Vec<CredentialSecret>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn
            .exec(
                "SELECT id, key_id, kind, slot, public_id, secret_form, created_at, updated_at, \
                 expires_at, revoked_at, revoke_reason, revision, secret FROM credentials \
                 WHERE revision > :since",
                params! { "since" => since },
            )
            .map_err(store_err)?;
        rows.into_iter()
            .map(|mut row| {
                let secret: Option<String> = row.take("secret");
                let meta = Self::row_to_cred_meta(row)?;
                Ok(CredentialSecret {
                    meta,
                    secret: secret.unwrap_or_default(),
                })
            })
            .collect()
    }

    fn append_audit(&self, entry: &AuditRecord) -> RecordStoreResult<()> {
        // `ON DUPLICATE KEY UPDATE seq = seq` kept the stored record and said nothing, which is
        // right for ONE of the two ways a seq collides and wrong for the other. Compare them and
        // let the difference decide (see the trait contract):
        //   identical -> the write-through retrying after a lost commit ACK. Common, benign, Ok.
        //   different -> two records claiming one chain position: a forked or tampered log, and the
        //                single most important thing an audit store can report.
        //
        // INSERT FIRST, and deliberately with NO preceding `SELECT ... FOR UPDATE`.
        //
        // The obvious shape — take a row lock, look, then insert — DEADLOCKS here, and measurably:
        // `SELECT ... FOR UPDATE` on a MISSING row takes a next-key/gap lock under REPEATABLE READ
        // (which is what `TxOpts::default()` leaves the server on). Two appends of DIFFERENT, both
        // new seqs land in the same gap; the gap locks are mutually compatible, but each side's
        // following INSERT needs an insert-intention lock that conflicts with the other's gap lock.
        // Four threads appending 200 distinct seqs each produced 39 deadlocks that way against 0
        // for the plain autocommit insert. `append_audit` is also the one control-plane path that
        // does not call `bump_revision`, so it sits OUTSIDE the `store_sequence` serialization that
        // makes every other admin-plane transaction deadlock-free — it has no other protection.
        //
        // A bare INSERT takes only an insert-intention lock and no gap lock, so the ordinary path
        // keeps the baseline's concurrency exactly, and the read only happens on the rare collision.
        //
        // The loop covers the row being deleted between the insert and the read-back: the seq is
        // free again, so inserting is the right move. Bounded, and exhausting the bound is an error
        // rather than a success, so no path here returns Ok without the record being stored.
        const MAX_ATTEMPTS: u32 = 3;
        let mut conn = self.conn()?;
        for _ in 0..MAX_ATTEMPTS {
            conn.exec_drop(
                "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash) \
                 VALUES (:seq, :ts, :action, :resource, :outcome, :principal, :prev, :hash) \
                 ON DUPLICATE KEY UPDATE seq = seq",
                params! {
                    "seq" => entry.seq, "ts" => entry.ts, "action" => &entry.action,
                    "resource" => &entry.resource, "outcome" => &entry.outcome,
                    "principal" => &entry.principal, "prev" => &entry.prev_hash, "hash" => &entry.hash,
                },
            )
            .map_err(store_err)?;
            // 1 = inserted. 0 = the seq was already occupied and `seq = seq` changed nothing.
            if conn.affected_rows() == 1 {
                return Ok(());
            }
            let existing: Option<AuditRowTuple> = conn
                .exec_first(
                    "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash \
                     FROM audit_log WHERE seq = :seq",
                    params! { "seq" => entry.seq },
                )
                .map_err(store_err)?;
            let Some((seq, ts, action, resource, outcome, principal, prev_hash, hash)) = existing
            else {
                continue; // gone between the insert and the read: the seq is free, try again
            };
            let stored = AuditRecord {
                seq,
                ts,
                action,
                resource,
                outcome,
                principal,
                prev_hash,
                hash,
            };
            if stored == *entry {
                return Ok(());
            }
            return Err(store_err(format!(
                "append_audit: seq {} already holds a DIFFERENT record; the audit chain has forked \
                 (stored action '{}', incoming '{}')",
                entry.seq, stored.action, entry.action
            )));
        }
        Err(store_err(format!(
            "append_audit: seq {} kept being freed between the insert and the read-back after \
             {MAX_ATTEMPTS} attempts; something is deleting audit rows concurrently and the record \
             was NOT stored",
            entry.seq
        )))
    }

    fn list_audit(&self) -> RecordStoreResult<Vec<AuditRecord>> {
        let mut conn = self.conn()?;
        let rows: Vec<AuditRowTuple> = conn
            .query("SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log ORDER BY seq")
            .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(
                |(seq, ts, action, resource, outcome, principal, prev_hash, hash)| AuditRecord {
                    seq,
                    ts,
                    action,
                    resource,
                    outcome,
                    principal,
                    prev_hash,
                    hash,
                },
            )
            .collect())
    }

    fn list_audit_tail(&self, limit: u64) -> RecordStoreResult<Vec<AuditRecord>> {
        let mut conn = self.conn()?;
        let rows: Vec<AuditRowTuple> = conn
            .exec(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash FROM audit_log \
                 ORDER BY seq DESC LIMIT :limit",
                params! { "limit" => limit },
            )
            .map_err(store_err)?;
        let mut out: Vec<AuditRecord> = rows
            .into_iter()
            .map(
                |(seq, ts, action, resource, outcome, principal, prev_hash, hash)| AuditRecord {
                    seq,
                    ts,
                    action,
                    resource,
                    outcome,
                    principal,
                    prev_hash,
                    hash,
                },
            )
            .collect();
        out.reverse(); // DESC LIMIT then reverse = the last N, oldest-first
        Ok(out)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> RecordStoreResult<()> {
        let mut conn = self.conn()?;
        let mut tx = conn
            .start_transaction(TxOpts::default())
            .map_err(store_err)?;
        let rev = Self::bump_revision(&mut tx)?;
        let now = crate_now();
        let max_ttl: u64 = 90 * 24 * 3600; // matches the 90d default token expiry ceiling documented in admin-api.md
        tx.exec_drop(
            "INSERT INTO denylist (sub, reason, revoked_at, expires_at, revision) \
             VALUES (:sub, :reason, :now, :expires, :rev) \
             ON DUPLICATE KEY UPDATE
                reason = VALUES(reason), revoked_at = VALUES(revoked_at),
                expires_at = GREATEST(expires_at, VALUES(expires_at)), revision = VALUES(revision)",
            params! {
                "sub" => sub, "reason" => reason, "now" => now, "expires" => now + max_ttl, "rev" => rev,
            },
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)
    }

    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        let mut conn = self.conn()?;
        conn.query("SELECT sub FROM denylist").map_err(store_err)
    }

    // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD VERBS (busbar 1.6.0) ─────────────────────────────
    //
    // Eight verbs over ONE table replace the fourteen per-protocol methods (`put_task`,
    // `append_mcp_call`, `put_mcp_demotion`, `redeem_ask_state`, ...) this store used to implement.
    // Every one is GENERIC over `kind`: nothing here decodes a `body`, and identity, ordering and
    // retention read only the typed sidecar columns. That is what lets a plane registered after this
    // build persist through it unchanged. The one kind-aware rule is retention's, and it is the
    // contract's: `task` drops only TERMINAL rows, and takes its `task_event` chain with it.

    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        // This store binds owned rows: the one copy of the borrowed view happens here.
        let record = &record.to_record();
        // UPSERT by identity: a second write for one `(kind, id)` REPLACES the row -- the engine
        // writes a task through on every state transition, and the boot read must find one row per
        // id, holding the last state.
        //
        // No `affected_rows` check, deliberately: MySQL reports 1 for an insert, 2 for a row it
        // changed and 0 for an update that changed nothing, so the number cannot tell "stored" from
        // "failed". Correctness rests on the statement succeeding.
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
             VALUES (:kind, :ident, :seq, :id, :parent, :ts, :terminal, :body) \
             ON DUPLICATE KEY UPDATE id = VALUES(id), parent = VALUES(parent), ts = VALUES(ts), \
                terminal = VALUES(terminal), body = VALUES(body)",
            plane_params(record),
        )
        .map_err(store_err)
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        // No caller filter, deliberately: the contract puts caller-scoping ENGINE-side, because an
        // authorization check living in the backend is one an unauthorized reader bypasses by
        // configuring a different backend. An unknown id is `None`, never an error.
        let mut conn = self.conn()?;
        conn.exec_first(
            "SELECT body FROM plane_records WHERE kind = :kind AND ident = :id AND seq = 0",
            params! { "kind" => kind, "id" => id },
        )
        .map_err(store_err)
    }

    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        // This store binds owned rows: the one copy of the borrowed view happens here.
        let record = &record.to_record();
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
        let mut conn = self.conn()?;
        for _ in 0..MAX_ATTEMPTS {
            conn.exec_drop(
                "INSERT INTO plane_records (kind, ident, seq, id, parent, ts, terminal, body) \
                 VALUES (:kind, :ident, :seq, :id, :parent, :ts, :terminal, :body) \
                 ON DUPLICATE KEY UPDATE kind = kind",
                plane_params(record),
            )
            .map_err(store_err)?;
            if conn.affected_rows() == 1 {
                return Ok(());
            }
            let existing: Option<PlaneRowTuple> = conn
                .exec_first(
                    "SELECT id, parent, ts, terminal, body FROM plane_records \
                     WHERE kind = :kind AND ident = :ident AND seq = :seq",
                    params! { "kind" => &record.kind, "ident" => ident, "seq" => record.seq },
                )
                .map_err(store_err)?;
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
            return Err(store_err(format!(
                "append_plane_record: kind '{}' seq {} already holds a different record for this \
                 parent; the chain has forked",
                record.kind, record.seq
            )));
        }
        Err(store_err(format!(
            "append_plane_record: kind '{}' seq {} kept being freed between the insert and the \
             read-back after {MAX_ATTEMPTS} attempts; the record was NOT stored",
            record.kind, record.seq
        )))
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        // Oldest-first by `seq` -- the order the engine's chain verifier reads a parent's chain in.
        // `All` is UNFILTERED (terminal rows included): the boot rehydrate wants the active rows,
        // retention the terminal ones and a scoped listing one caller's, and a store that
        // pre-filtered for one of them would break the other two.
        let mut conn = self.conn()?;
        match selector {
            PlaneSelector::All => conn.exec(
                "SELECT body FROM plane_records WHERE kind = :kind ORDER BY seq, ident",
                params! { "kind" => kind },
            ),
            PlaneSelector::Parent(parent) => conn.exec(
                "SELECT body FROM plane_records \
                 WHERE kind = :kind AND ident = :parent AND parent = :parent ORDER BY seq",
                params! { "kind" => kind, "parent" => parent.as_ref() },
            ),
        }
        .map_err(store_err)
    }

    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        // The boot enumeration a restart resumes chains from: every distinct parent holding at
        // least one record of the kind, including one this process has never seen written.
        let mut conn = self.conn()?;
        conn.exec(
            "SELECT DISTINCT parent FROM plane_records \
             WHERE kind = :kind AND parent IS NOT NULL ORDER BY parent",
            params! { "kind" => kind },
        )
        .map_err(store_err)
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        // STRICTLY older than the cutoff: a row exactly at `before` is kept. The count returned is
        // one the DELETE actually performed (`affected_rows`), never an estimate.
        let mut conn = self.conn()?;
        if kind == KIND_TASK {
            // TERMINAL ONLY. An interrupted task waiting on a human is exactly the row that sits
            // still for a long time; compacting it is losing the work, not reclaiming space.
            // Terminality is the envelope's typed `terminal` column -- never decoded from the body.
            //
            // The task's event chain goes with it, in the SAME TRANSACTION. That cascade is
            // load-bearing: nothing else ever purges a `task_event` row, so a purge that left them
            // behind would leave the chains of every swept task with no bound anywhere in the
            // contract. It lives here because neither schema-side mechanism is available (see the
            // `plane_records` DDL), and one transaction makes the pair atomic -- a crash between the
            // two statements cannot leave a task whose chain has been half-swept. Only the chains
            // under a task that actually goes are touched: an event whose task is retained, or was
            // never written, is left alone.
            //
            // SHAPE, and why it is not one set-based DELETE: two sweeps running at once (two nodes,
            // or the retention tick racing an operator purge) each took next-key locks across the
            // `(kind, ts)` range and the joined event ranges, and deadlocked on each other
            // (ERROR 1213, reproduced by the interleaved-runs conformance check). So the candidates
            // are found by a plain NON-LOCKING read, and each is then removed in its own short
            // transaction by PRIMARY KEY, with the retention predicate RE-CHECKED in the DELETE --
            // a task re-activated or re-timestamped since the read is simply not matched. A point
            // delete on a unique key takes a record lock and no gap lock, so concurrent sweeps can
            // at worst wait on one row, never on each other's ranges; ascending ident order keeps
            // even that wait ordered. A task that turns terminal after the read is the next sweep's.
            let candidates: Vec<String> = conn
                .exec(
                    "SELECT ident FROM plane_records \
                     WHERE kind = :kind AND seq = 0 AND ts < :before AND terminal ORDER BY ident",
                    params! { "kind" => KIND_TASK, "before" => before },
                )
                .map_err(store_err)?;
            let mut removed = 0u64;
            for ident in candidates {
                let mut tx = conn
                    .start_transaction(TxOpts::default())
                    .map_err(store_err)?;
                tx.exec_drop(
                    "DELETE FROM plane_records WHERE kind = :kind AND ident = :ident AND seq = 0 \
                     AND ts < :before AND terminal",
                    params! { "kind" => KIND_TASK, "ident" => &ident, "before" => before },
                )
                .map_err(store_err)?;
                // Read BEFORE the next statement: `affected_rows` reports the LAST statement on
                // this connection. 0 = a concurrent sweep took it first, or it is no longer
                // eligible; either way its chain is not this sweep's to touch.
                if tx.affected_rows() == 1 {
                    tx.exec_drop(
                        "DELETE FROM plane_records WHERE kind = :event_kind AND ident = :ident",
                        params! { "event_kind" => KIND_TASK_EVENT, "ident" => &ident },
                    )
                    .map_err(store_err)?;
                    removed += 1;
                }
                tx.commit().map_err(store_err)?;
            }
            return Ok(removed);
        }
        // Every other kind drops ALL of its rows older than the cutoff. Batched and looped, like
        // `purge_windows_before`: the batch bound keeps any one DELETE's lock footprint small, and
        // the loop makes the contract -- every row below the cutoff -- actually hold for a backlog
        // larger than one batch.
        const BATCH: u64 = 5000;
        let mut total = 0u64;
        loop {
            conn.exec_drop(
                "DELETE FROM plane_records WHERE kind = :kind AND ts < :before LIMIT 5000",
                params! { "kind" => kind, "before" => before },
            )
            .map_err(store_err)?;
            let n = conn.affected_rows();
            total += n;
            if n < BATCH {
                break;
            }
        }
        Ok(total)
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        // Absent is a NO-OP, not an error: the engine clears a demotion on every observation that
        // agrees with the approval rather than tracking whether it had demoted, so the common call
        // is one against no row at all. Every `seq` under the identity goes, so deleting a parent's
        // record can never leave part of a chain behind.
        let mut conn = self.conn()?;
        conn.exec_drop(
            "DELETE FROM plane_records WHERE kind = :kind AND ident = :id",
            params! { "kind" => kind, "id" => id },
        )
        .map_err(store_err)
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        let mut conn = self.conn()?;
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
        .map_err(store_err)?;
        Ok(conn.affected_rows() == 1)
    }

    fn plane_token_live(
        &self,
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
        let mut conn = self.conn()?;
        let terminal: Option<bool> = conn
            .exec_first(
                "SELECT terminal FROM plane_records WHERE kind = :kind AND ident = :token AND seq = 0",
                params! { "kind" => kind, "token" => token },
            )
            .map_err(store_err)?;
        Ok(terminal == Some(false))
    }
}

/// A plane record's IDENTITY within its kind: its `parent` when it is an appended child (a chain
/// position is `(parent, seq)`), else its own `id` (at seq 0 for an upsert kind). The same rule
/// busbar's reference stores key by, so every backend agrees on what "the same record" means.
fn plane_ident(record: &PlaneRecord) -> &str {
    record.parent.as_deref().unwrap_or(&record.id)
}

fn is_terminal(d: PlaneDisposition) -> bool {
    matches!(d, PlaneDisposition::Terminal)
}

fn plane_params(record: &PlaneRecord) -> mysql::Params {
    params! {
        "kind" => &record.kind,
        "ident" => plane_ident(record),
        "seq" => record.seq,
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

// ── THE DOOR (DECISIONS #2 rule (1): compiled in or dropped in, one contract, one loading path) ──
//
// The store's one door registration lives HERE, in the logic crate: a busbar build that links this
// crate registers `linked::STORE` (its `BUSBAR_COLD_ENTRY`), and the sibling
// `busbar-store-mysql-plugin` cdylib only re-exports this crate, so the frozen symbols the loader
// looks up in the library answer through this same registration. One source, both doors.

/// The store's package name — the name its signed tarball states and a linked row registers.
pub const NAME: &str = "busbar-store-mysql";

/// The alias `store.module` selects it by.
pub const ALIAS: &str = "mysql";

/// Construct a MySQL/MariaDB store from the JSON config the engine passes through `open`:
///
/// ```json
/// { "url": "mysql://user:pass@host:3306/busbar" }
/// ```
pub fn open(cfg: &str) -> Result<Box<dyn RecordStore>, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid mysql plugin config: {e}"))?
    };
    let url = v
        .get("url")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "mysql plugin config requires a \"url\" (a mysql:// connection string)".to_string()
        })?;
    let store = MysqlStore::connect(url).map_err(|e| e.0)?;
    Ok(Box::new(store))
}

busbar_contract::abi::sdk::export_store_plugin!(open);

/// THE LINKED ENTRY: what a build that links this store registers onto the cold-kind axis — the same
/// row the dropped-in tarball states, over the boundary the one cold load runs.
pub mod linked {
    /// `(name, alias, boundary)`.
    pub const STORE: (&str, &str, &busbar_contract::abi::sdk::ColdEntry) =
        (super::NAME, super::ALIAS, &super::BUSBAR_COLD_ENTRY);
}

#[cfg(test)]
mod tests;
