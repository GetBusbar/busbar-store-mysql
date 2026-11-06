<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-store-mysql

First-party signed kind:store plugin cdylib: the MySQL/MariaDB backend for busbar's durable governance store, exported over the store C ABI. Drop the built library into the plugins folder and set store.module: mysql to share virtual keys, budgets, and usage across a fleet of busbar nodes.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `mysql` | `busbar-store-mysql-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

[![Coverage](https://codecov.io/gh/GetBusbar/busbar-store-mysql/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-store-mysql)

The MySQL/MariaDB backend for busbar's durable governance store — a `kind: store` plugin.

Targets the common SQL subset supported by MySQL 8.0.16+, MariaDB, and Aurora MySQL: one plugin,
protocol-compatible with all three, same reasoning as busbar's Valkey store covering any server that
speaks the standard RESP protocol — broad coverage via standard SQL, not three separate builds.

Point a fleet of busbar nodes at one MySQL/MariaDB server and they share virtual keys, budgets, and
usage across the cluster, same as the sibling `store-postgres` plugin.

### Install

```yaml
store:
  module: mysql
  settings:
    url: "mysql://user:pass@host:3306/busbar"
```

Drop the built `.so`/`.dll`/`.dylib` into busbar's `plugins_dir`, or install it live via
`POST /plugins` — see busbar's admin API docs.

### Requirements

- MySQL **>= 8.0.16** (older 8.x releases and Aurora MySQL 2.x parse `CHECK` constraints but do not
  enforce them — this plugin boot-probes for real enforcement and refuses to start if it's missing,
  rather than silently accepting unvalidated data), or MariaDB, or Aurora MySQL 3.x.
- `sql_mode`: the store appends `STRICT_ALL_TABLES` to every connection's session it opens (an
  operator's other modes survive), so a truncating write errors instead of silently corrupting data
  whatever the server default is; the boot probe then checks the session really is strict and refuses
  to start if it is not. Setting it server-wide is no longer required.

### Security: the network path to the server

TLS is not supported by this store. The SDK captures the DSN password before public URL parsing
and constructs complete sealed authentication packets. With `caching_sha2_password`, full
authentication over plaintext TCP requires `server_public_key_sha256=<64 hex digits>`, the SHA-256
of the server public key's DER. A mismatched key is refused before the encrypted response is sent.
An operator-selected `socket=` URL permits full authentication over that local connection.
`mysql_native_password` and fast `caching_sha2_password` authentication keep their scramble responses;
`mysql_old_password` and `mysql_clear_password` retain their explicit operator switches.

### Design notes

- `api_keys`, not `keys`: `KEYS` is a MySQL/MariaDB reserved word. Every other backend (Postgres,
  SQLite, Valkey) keeps `keys`.
- A single-row `store_sequence` revision counter is bumped FIRST in every control-plane transaction,
  before `api_keys`/`credentials`/`denylist` — a fixed lock order that makes deadlock across the
  admin plane structurally impossible.
- Every opaque identifier column (credential lookup handles, key ids, group names, plane-record
  identities, token and unit names) is `VARBINARY`: MySQL's default collation is case-insensitive and
  its `_bin` collations are PAD SPACE, either a real security-relevant footgun for a credential
  handle. Byte-exact comparison, matching Postgres/SQLite's default.
- Every conditional mutation does an explicit `SELECT ... FOR UPDATE` existence/state check before
  acting — MySQL's `rows_affected()` reports rows *changed*, not rows *matched*, so an idempotent
  no-op can't be distinguished from "not found" by row count alone.
- `DELETE /keys/{id}` **tombstones**, it never removes the row: every credential is destroyed,
  `enabled=false`/`deleted_at` are set, but `id`/`name`/`key_group`/`labels` survive so billing
  attribution (`usage_metering.key_id`) keeps resolving forever. The tombstone and credential
  destruction land in the SAME transaction with ONE revision stamp — a hydrator can never observe
  the tombstone without the credentials already being gone.

- busbar 1.6.0's neutral plane records (A2A tasks and their event chains, the MCP call log,
  MCP demotions, push-callback capabilities, and any kind a plane registers later) live in ONE
  `plane_records` table keyed by `(kind, identity, seq)`, with the record body stored opaquely and
  byte-for-byte; single-use tokens (`redeem_plane_token`) live in `plane_tokens`. Retention for the
  `task` kind takes each purged task's event chain with it (a terminal-only sweep drops only terminal
  tasks; an age sweep drops every task older than the cutoff), and deleting a task deletes its chain.
- Raw usage and metering request and billable-request counters preserve the full `u64` range and saturate
  at `u64::MAX`. Quantities use exact signed-128-bit scale-6
  mantissas stored as `DECIMAL(39,0)`, with totals from zero through `i128::MAX` micro-units; quantity overflow is
  refused rather than saturated. A `u64` the other stores' signed columns could not hold (an append's `seq`/`ts`, an upsert's
  `seq`/`ts`, a metering `priced_from_ms`) is refused, never clamped or wrapped. Token redemption
  expiry and clock values retain the full `u64` range, including `u64::MAX`.
- A revoked credential's secret is destroyed with the revoke (the column is NULL, the form `none`).
- Metering is accepted for any `key_id`: there is no foreign key from `usage_metering` to
  `api_keys`, as in the other stores.
- The store v3 tables are `store_ops` (the durable op-id dedupe log) and `store_records` (the
  kernel's records). The store keeps ledger counts, not money: busbar derives money from the counts
  and its rate card. The released schema v3 upgrades directly to v7. Tables belonging to other applications
  are preserved; schema 6 and markers above v7 are refused. The upgrade
  retypes every key column to `VARBINARY` (exact keys), lets a revoked credential lose its
  secret and drops
  `fk_metering_key`. The v4 upgrade adds the recorded group and pricing version to metering
  identities and their open units. Migration preserves each legacy parent's attribution,
  including empty unknown values, and refuses orphan units. Already-collapsed attribution
  cannot be reconstructed. `pricing_version` is now byte-exact `VARBINARY(256)`, preserving
  the full UTF-8 content of the old 64-character column.
  The v4 upgrade widens all four usage model columns to 1088 bytes, preserving the previous
  1024-byte model together with the longest 64-byte exact price-entry carrier. The store
  treats the entire string opaquely; primary keys still compare every byte.

Drain and stop older store processes before upgrading, including an existing schema-v5
deployment receiving the request-counter consolidation below. The existing migration
marker and newer-schema checks refuse incompatible opens, but cannot fence already-open
processes or older binaries without those checks. Reopen all nodes with this build;
rollback requires a pre-upgrade backup and its matching binary.

### Column width limits

A value wider than its column is refused by the server (the store runs `STRICT_ALL_TABLES`), naming
the column and never the value. Widths are in bytes for `VARBINARY`/`TEXT` and characters for
`VARCHAR`:

| column | limit |
|---|---|
| `api_keys.id`, `credentials.id`, `credentials.key_id`, `denylist.sub`, `usage_metering.key_id` | 64 |
| `api_keys.key_group`, `usage_windows.bucket_id`, `usage_window_units.bucket_id`, `usage_metering.key_group_at_use`, `credentials.kind` | 128 |
| `usage_metering.pricing_version`, `usage_metering_units.pricing_version` | 256 |
| `api_keys.name`, `plane_records.kind`, `plane_tokens.kind`, `credentials.public_id` | 256 |
| `credentials.revoke_reason`, `denylist.reason`, `usage_metering.provider`, `usage_metering_units.provider`, `usage_window_units.unit`, `usage_metering_units.unit` | 512 |
| `usage_*.model` | 1088 |
| `usage_windows.bucket_scope`, `usage_window_units.bucket_scope`, `usage_metering.bucket`, `usage_metering_units.bucket` | 32 / 32 / 40 / 40 |
| `plane_records.ident`/`id`/`parent`, `plane_tokens.token`, `store_records.schema_id` | 764 |
| `store_records.rkey` / `value` | 2048 / 512 |
| `api_keys.generation_hash` | 128 |

## Versioning

This is v1.6.0, built against busbar 1.6.0 (pinned in `.busbar-ref`). The crates
`busbar-store-mysql` and `busbar-store-mysql-plugin` carry the same version, and the database schema
version this build creates is **7** (`store_meta.schema_version`).

## Upgrading an existing database

Upgrades are IN PLACE on boot, under a server-wide `GET_LOCK` named for the database: exactly one
connection migrates, every other open waits (30 s) and is then refused naming the holder rather than
serve a half-migrated schema. A migration marker (`store_meta.migrating_to`) makes a crashed migration
resume on the next open. A database stamped with a NEWER schema than this build is refused.

The released schema versions 1, 2 and 3 upgrade directly to **7**. The v1 billable-request
backfill and v2 group-collation repair run before the common upgrade. Development schema 6 and schemas above v7 are refused.

The upgrade adds five nullable key columns, `usage_metering.priced_from_ms`, and the neutral
record tables. It makes keys byte-exact, permits revoked credentials to hold no secret, scrubs
already-revoked secrets with a published revision, and removes the metering-to-key foreign key.
It preserves each metering cell's recorded attribution, widens pricing versions to 256 bytes
and model names to 1088 bytes, and resumes interrupted DDL. Unrelated application tables,
including tables named `tasks`, are preserved. The largest complete primary key is 2812 bytes,
within the supported InnoDB 3072-byte limit.

Schema v7 widens the ten quantity columns to `DECIMAL(39,0)` with nonnegative i128
bounds. Parameters and results use exact integer decimal bytes; no floating-point conversion
is involved. Existing schema-v5 quantities already contain micro-units and remain unchanged.
Versions 0–4 contain whole units: after widening, the migration multiplies only their
quantities by 1,000,000. Every released `u64` whole-unit quantity fits the new range. The
whole-unit ceiling is 170,141,183,460,469,231,731,687,303,715,884; larger values refuse startup.
Request and billable-request counters remain unscaled. Quantity preflight, conversion,
`store_meta.quantity_format=i128-scale6-v1`, and the v7 stamp commit together; interrupted
DDL resumes and failed conversions leave quantities unchanged. A v7 database missing the
format marker is refused. Do not lower version markers or manually reinterpret micro-units
as whole units. Keep a pre-upgrade backup; rollback needs that backup and its matching binary.

The plugin attests `busbar.store.count-scale=6` and `busbar.store.count-range=i128`.
Quantity JSON uses exact numeric tokens. New writes use scale 6; scale-0 inputs are checked
and normalized. Ordinary signed usage refunds floor at zero, including the most negative
i128 delta. Explicit corrections accept only nonnegative replacement totals and apply their
expected-value checks transactionally; an invalid correction leaves no effect or receipt.

The one-time `store_meta.usage_request_totals_v1=1` migration also runs on existing v5
stores. In one transaction it consolidates each window's historical request/billable totals
into the empty-model total row, saturating each aggregate at `u64::MAX`, and clears those
counter fields on other model rows. It preserves every model quantity and open-unit count,
including quantities whose model name is empty. This makes subsequent signed refunds and
saturation operate on the same total returned by reads. The marker commits with the
conversion; interrupted attempts roll back and retry on the next open. The existing ledger
lock serializes conversion with current writers and other booters. Older processes must be
stopped because they do not enforce this representation or migration marker.

## Config

Configured under the `mysql` module name. Every settings refusal starts
`invalid mysql plugin config: `.

| setting | type | default | meaning |
|---|---|---|---|
| `url` | string | none (required) | `mysql://user:pass@host:3306/db`, or `socket=` for a unix socket; accepts `{env:}`/`{file:}` references |

Any other key is refused; a settings value that is not a JSON object, or a `url` that is not a
string, is refused naming the field or JSON type, without quoting its value. Host-lent secret
markers are captured through the SDK settings parser, as are literal DSNs. A server that cannot be reached fails the load as `mysql store: failed to connect: ...`.

URL parameters honoured: `user`, `password`, `host`, `port`, `socket`, `db_name`, `compress`,
`secure_auth`, `enable_cleartext_plugin`, `server_public_key_sha256`, `tcp_connect_timeout_ms`,
`max_allowed_packet`. A DSN may name its password once, in userinfo or `password=`.

URL parameters REFUSED (never silently ignored), each naming the parameter as "is not supported":
`pool_min`, `pool_max` (the store keeps 8 connections over the host's connector), `prefer_socket`,
`reset_connection`, `check_health`, `tcp_keepalive_time_ms`, `tcp_keepalive_probe_interval_secs`,
`tcp_keepalive_probe_count`, `tcp_user_timeout_ms`, `stmt_cache_size`, and every TLS parameter
(`ssl*`, `tls*`, `require_ssl`, `verify_ca`, `verify_identity`): TLS is not supported by this store.
A URL error never echoes the password; a database stamped with a newer schema than this build is
refused at open.

## Build

```bash
cargo build --release -p busbar-store-mysql-plugin
```

## Tests

```
docker run -d -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=busbar -e MYSQL_USER=busbar -e MYSQL_PASSWORD=busbar \
  -e MYSQL_DATABASE=busbar_test mysql:8
BUSBAR_TEST_MYSQL_URL=mysql://busbar:busbar@127.0.0.1:3306/busbar_test cargo test
```

The tests read the server from `BUSBAR_TEST_MYSQL_URL`. Policy: locally, with the variable unset,
most tests skip cleanly; in CI (`CI` set) an unset variable FAILS the run, and the trust-state cases
(MCP demotions and the single-use token ledger, in-crate and over the plugin ABI) fail even locally,
because their unimplemented form is silently green. CI always sets the URL via the `mysql:8` service
container in the shared `plugin-ci.yml` workflow. The migration tests also need the server's `root`
account (`BUSBAR_TEST_MYSQL_ROOT_PASSWORD`, default `busbar`).

### Status

Built against busbar 1.6.0's `Store` interface (the neutral `PlaneRecord` verbs). MariaDB compatibility is
validated by schema/query design (standard SQL, no MySQL-8-only syntax used) but not yet exercised
against a live MariaDB container in this repo's test suite — flagged as a follow-up, not a
guarantee. MySQL 8 is the fully tested target.

## License

Apache-2.0. See [LICENSE](LICENSE).

Replay-token expiry uses the shared database server's Unix clock. `expires_at` remains an
absolute Unix-seconds deadline; the caller clock argument does not expire or reclaim tokens.
An expired presentation returns false before mutation, equality with the sampled server second
remains live, and duplicate presentations preserve the winner's expiry. For reserved kind `ticket`, `plane_token_live` checks a persisted Terminal record with an
exact matching expiry against that same database clock without spending it. Missing, pruned,
expired or mismatched receipts return false. Other kinds keep their Active/caller-clock contract. Clock read failures propagate as errors.

Built-in `ticket` records store their absolute expiry in `ts`. Their retention cutoff is
capped at the database clock, preserving still-live receipts even when a caller requests
a future cutoff. Equal deadlines are retained; other record kinds keep their existing rules.

## Differences from 1.5.5

Host-owned pool and socket options listed above are now explicitly refused instead of being
silently ineffective. Invalid packet-size settings and compression levels outside 0–9 are
refused. Incoming results are bounded to 1,000,000 rows and 256 MiB of row payload per statement,
64 result sets, and 1024 consecutive progress packets. Without an explicit packet-size setting,
the server's advertised packet size is capped at 64 MiB. Exceeding these bounds discards the
connection instead of permitting unbounded allocation. A pre-Unix-epoch system clock is an
error rather than a zero timestamp. Transient credential parameter and packet copies are wiped.
