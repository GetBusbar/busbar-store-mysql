<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-store-mysql

First-party signed kind:store plugin cdylib: the MySQL/MariaDB backend for busbar's durable governance store, exported over the store C ABI. Drop the built library into the plugins folder and set store.module: mysql to share virtual keys, budgets, and usage across a fleet of busbar nodes.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `mysql` | `busbar-store-mysql-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-store-mysql/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-store-mysql/actions/workflows/ci.yml)
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

TLS is not supported by this store. With `mysql_native_password` the password is never sent in the
clear, but with `caching_sha2_password` (the MySQL 8 default) a full authentication over plaintext TCP
RSA-encrypts the password to the public key the SERVER sends, and that key is not authenticated: an
attacker on the path can substitute their own key and recover the password. Use a trusted network or a
`socket=` (unix socket) URL, or an account that authenticates with `mysql_native_password`.

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
- Counters (usage and metering) pin at `i64::MAX`, the largest value every store of the family can
  hold; a `u64` the other stores' signed columns could not hold (an append's `seq`/`ts`, an upsert's
  `seq`/`ts`, a metering `priced_from_ms`, a redemption's `expires_at`/`now`) is refused, never
  clamped or wrapped.
- A revoked credential's secret is destroyed with the revoke (the column is NULL, the form `none`).
- Metering is accepted for any `key_id`: there is no foreign key from `usage_metering` to
  `api_keys`, as in the other stores.
- The store v3 tables are `store_ops` (the durable op-id dedupe log) and `store_records` (the
  kernel's records). The store keeps ledger counts, not money: busbar derives money from the counts
  and its rate card. Schema v10 drops the tables a pre-release v8/v9 build created for the deleted
  store slots (`store_caps`, `store_slices`, `store_epoch`, `store_journal`, `store_sessions`) and
  prunes `store_ops` to the rows of the three op-id writes that remain; schema v11 retypes every key
  column to `VARBINARY` (exact keys); schema v12 lets a revoked credential lose its secret and drops
  `fk_metering_key`.

### Column width limits

A value wider than its column is refused by the server (the store runs `STRICT_ALL_TABLES`), naming
the column and never the value. Widths are in bytes for `VARBINARY`/`TEXT` and characters for
`VARCHAR`:

| column | limit |
|---|---|
| `api_keys.id`, `credentials.id`, `credentials.key_id`, `denylist.sub`, `usage_metering.key_id` | 64 |
| `api_keys.key_group`, `usage_*.bucket_id`, `usage_metering.key_group_at_use`, `credentials.kind` | 128 |
| `api_keys.name`, `plane_records.kind`, `plane_tokens.kind`, `credentials.public_id` | 256 |
| `credentials.revoke_reason`, `denylist.reason`, `usage_*.provider`, `usage_*.unit` | 512 |
| `usage_*.model` | 1024 |
| `plane_records.ident`/`id`/`parent`, `plane_tokens.token`, `store_records.schema_id` | 764 |
| `store_records.rkey` / `value` | 2048 / 512 |
| `api_keys.generation_hash`, `usage_metering.pricing_version` | 128 / 64 |

## Versioning

This is v1.6.0, built against busbar 1.6.0 (pinned in `.busbar-ref`). The crates
`busbar-store-mysql` and `busbar-store-mysql-plugin` carry the same version, and the database schema
version this build creates is **12** (`store_meta.schema_version`).

## Upgrading an existing database

Upgrades are IN PLACE on boot, under a server-wide `GET_LOCK` named for the database: exactly one
connection migrates, every other open waits (30 s) and is then refused naming the holder rather than
serve a half-migrated schema. A migration marker (`store_meta.migrating_to`) makes a crashed migration
resume on the next open. A database stamped with a NEWER schema than this build is refused.

- From busbar 1.5.x's `store-mysql` plugin (schema v3): five nullable `api_keys` columns
  (`allowed_scopes_ext`, `idp_subject`, `binding_mode`, `minted_by`, `idp_provider`),
  `usage_metering.priced_from_ms` (default 0, and part of the metering key, so a rate-card change
  inside a day opens a second cell) and the new tables; then v10 to v12 below.
- v10 drops the tables of the deleted store slots and prunes `store_ops` to the rows of the three
  op-id writes that remain.
- v11 retypes every key and identity column to `VARBINARY` (types, not values).
- v12 replaces `ck_cred_sigv4_recov` with `ck_cred_sigv4_secret` (a revoked sigv4 row may hold no
  secret), scrubs the secret of every already-revoked credential, and drops `fk_metering_key`.
  No row is deleted.

## Config

Configured under the `mysql` module name. Every settings refusal starts
`invalid mysql plugin config: `.

| setting | type | default | meaning |
|---|---|---|---|
| `url` | string | none (required) | `mysql://user:pass@host:3306/db`, or `socket=` for a unix socket; accepts `{env:}`/`{file:}` references |

Any other key is refused (`unknown setting `k` (accepted: url)`); a settings value that is not a
JSON object, or a `url` that is not a string, is refused naming the JSON type it is (never its
value). A server that cannot be reached fails the load as `mysql store: failed to connect: ...`.

URL parameters honoured: `user`, `password`, `host`, `port`, `socket`, `db_name`, `compress`,
`secure_auth`, `enable_cleartext_plugin`, `tcp_connect_timeout_ms`, `max_allowed_packet`.

URL parameters REFUSED (never silently ignored), each with a "not supported by this store" message:
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
