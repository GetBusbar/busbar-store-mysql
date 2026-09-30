<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
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
- `sql_mode` must include `STRICT_ALL_TABLES` or `STRICT_TRANS_TABLES` — also boot-probed. Set it
  server-wide (`SET GLOBAL sql_mode='STRICT_ALL_TABLES';`) before pointing busbar at the server.

### Design notes

- `api_keys`, not `keys`: `KEYS` is a MySQL/MariaDB reserved word. Every other backend (Postgres,
  SQLite, Valkey) keeps `keys`.
- A single-row `store_sequence` revision counter is bumped FIRST in every control-plane transaction,
  before `api_keys`/`credentials`/`denylist` — a fixed lock order that makes deadlock across the
  admin plane structurally impossible.
- `ascii_bin` collation on every opaque identifier column (credential lookup handles, key ids, group
  names): MySQL's default collation is case-insensitive, which would be a real security-relevant
  footgun for a credential handle. Byte-exact comparison, matching Postgres/SQLite's default.
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
  `task` kind drops only terminal rows and takes their event chain with it.
- Upgrades are IN PLACE on boot. A database written by the 1.5.x plugin (v1.0.x, schema v3) gains
  four nullable `api_keys` columns (`allowed_scopes_ext`, `idp_subject`, `binding_mode`,
  `minted_by`), `usage_metering.priced_from_ms` (default 0, and part of the metering key, so a
  rate-card change inside a day opens a second cell), and the new tables. No existing row is
  dropped or rewritten.

## Config

Configured under the `mysql` module name.

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

Most tests skip cleanly when `BUSBAR_TEST_MYSQL_URL` is unset locally. The trust-state cases (MCP
demotions and the single-use token ledger, in-crate and over the plugin ABI) deliberately FAIL
instead, because their unimplemented form is silently green. CI always sets the URL via the
`mysql:8` service container in the shared `plugin-ci.yml` workflow.

### Status

Built against busbar 1.6.0's `Store` interface (the neutral `PlaneRecord` verbs). MariaDB compatibility is
validated by schema/query design (standard SQL, no MySQL-8-only syntax used) but not yet exercised
against a live MariaDB container in this repo's test suite — flagged as a follow-up, not a
guarantee. MySQL 8 is the fully tested target.

## License

Apache-2.0. See [LICENSE](LICENSE).
