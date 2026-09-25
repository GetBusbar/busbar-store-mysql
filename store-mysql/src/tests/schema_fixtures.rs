// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FROZEN schemas of databases this backend must upgrade in place. Test fixtures only: each is a
//! VERBATIM copy of DDL an earlier build of this repo shipped or ran, so a migration test can build
//! a genuinely old database rather than a hand-guessed approximation of one. Never edit these to
//! match the current schema — that would make the upgrade tests test nothing.

/// `store-mysql/src/lib.rs` `SCHEMA` at tag v1.0.6 — the released plugin for busbar 1.5.5, schema
/// v3. Comments stripped; statements verbatim.
pub const V1_0_6_SCHEMA: &[&str] = &[
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
        PRIMARY KEY (key_id, bucket, model, provider),
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
];

/// The per-protocol plane tables a pre-release 1.6.0 development build added at v4..v6
/// (`store-mysql/src/lib.rs` at dev `07e774e`). Comments stripped; statements verbatim.
pub const V6_PLANE_TABLES: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS mcp_calls (
        principal VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        seq BIGINT UNSIGNED NOT NULL,
        ts BIGINT UNSIGNED NOT NULL,
        prev_hash CHAR(64) NOT NULL DEFAULT '',
        hash CHAR(64) NOT NULL DEFAULT '',
        body TEXT NOT NULL,
        expires_at BIGINT UNSIGNED NULL,
        version BIGINT UNSIGNED NOT NULL DEFAULT 0,
        PRIMARY KEY (principal, seq)
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_mcp_calls_ts ON mcp_calls (ts)",
    "CREATE TABLE IF NOT EXISTS tasks (
        task_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        context_id VARCHAR(191) NOT NULL DEFAULT '',
        principal VARCHAR(191) NOT NULL DEFAULT '',
        direction VARCHAR(16) NOT NULL DEFAULT '',
        state VARCHAR(64) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
        agent_id VARCHAR(191) NOT NULL DEFAULT '',
        artifact_cursor BIGINT UNSIGNED NOT NULL DEFAULT 0,
        push_callback TEXT NOT NULL,
        created_at BIGINT UNSIGNED NOT NULL,
        updated_at BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (task_id)
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_tasks_state_updated ON tasks (state, updated_at)",
    "CREATE TABLE IF NOT EXISTS task_events (
        task_id VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        seq BIGINT UNSIGNED NOT NULL,
        ts BIGINT UNSIGNED NOT NULL,
        kind VARCHAR(64) NOT NULL DEFAULT '',
        context_id VARCHAR(191) NOT NULL DEFAULT '',
        principal VARCHAR(191) NOT NULL DEFAULT '',
        agent_id VARCHAR(191) NOT NULL DEFAULT '',
        state VARCHAR(64) NOT NULL DEFAULT '',
        request_id VARCHAR(191) NOT NULL DEFAULT '',
        prev_hash CHAR(64) NOT NULL DEFAULT '',
        hash CHAR(64) NOT NULL DEFAULT '',
        PRIMARY KEY (task_id, seq)
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS mcp_demotions (
        server VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        reason VARCHAR(191) NOT NULL DEFAULT '',
        recorded_at BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (server)
    ) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS spent_ask_states (
        nonce VARCHAR(191) COLLATE utf8mb4_bin NOT NULL,
        expires_at BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY (nonce)
    ) ENGINE=InnoDB",
    "CREATE INDEX idx_spent_ask_states_expires ON spent_ask_states (expires_at)",
];
