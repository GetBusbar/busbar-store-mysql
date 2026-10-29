// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 door over [`MysqlStore`]: `store_door!` and the slots the store v3 table adds to
//! the base op set ([`StoreSlots`]): the `op_id`-carrying writes, the kernel's records, and the
//! base op set itself, every slot one body on the op's connection. The store keeps ledger counts
//! and records; money is a view on the ledger and the rate card, computed in core.
//!
//! DEDUPE (`abi::store` S1-S4), DURABLE: every `op_id` write runs in ONE transaction that first
//! inserts the op's row into `store_ops` (its value fields), then applies the effect, then stores
//! the answer, then commits. Two racing calls with one `op_id` serialise on that primary key: the
//! second waits for the first, and reads its committed row (same value fields: the original
//! answer, nothing applied; different: a conflict). A refused or failed op rolls back with its row,
//! so nothing is recorded (S3). Rows older than [`OP_ID_RETENTION_SECS`] are swept (S4).
//!
//! CONNECTIONS: every slot runs on one of the instance's kept connections over the host's
//! connector, as straight-line async code driven by the store SDK's `wire::drive_kept` (every call
//! Ready or Pending(wake), no socket of the plugin's own). The door declares one
//! outbound `tcp` need ([`NEEDS`], `operator-infrastructure`); `open` parses the settings and its
//! connect step reaches the server, creates the schema and runs the probes, so an unreachable or
//! refusing server still fails the load at open, in the driver's words.

use mysql_common::params;
use serde_json::Value;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::store::wire::{drive_kept, Body};
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecord,
    PlaneRecordRef, PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::mysqlwire::{Conn, Error};
use crate::{crate_now, store_err, MysqlStore, INIT, NAME};

const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The store's one need: the server, dialled over `tcp` at the URL's `host:port` (or its
/// `socket=` path as `unix:<path>`; the store names the target per connection), in the
/// `operator-infrastructure` egress class (private, loopback and plaintext allowed; pinned; cloud
/// metadata hosts refused). Its timeout is the host's default (a URL's
/// `tcp_connect_timeout_ms` bounds the dial).
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
    transport: abi_str("tcp"),
    auth: NO_TEXT,
    target_from: NO_TEXT,
    trust_from: NO_TEXT,
    details: Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    },
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

/// The need index of [`NEEDS`]' one entry.
const NEED: u32 = 0;

/// THE REFERENCE-CAPABLE, NOT-SECRET SETTINGS FIELDS (busbar lead ruling item 7a), stated in the
/// Statement's extensions under the contract's `EXT_REFERENCE_FIELDS` key: a `{env:}`/`{file:}`/
/// `{module:}` reference written at `url` is resolved by the kernel IN PLACE to its string (a 1.5.5
/// config's `url: {env: VAR}` keeps booting), and a literal url passes as written (never refused
/// as a secret literal). The value is not a secret: it is never lent.
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

busbar_contract::store_door!(
    MysqlStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    64,
    needs: NEEDS,
    extensions: EXTENSIONS
);

/// Run one op on one of the instance's kept connections (a fresh one when none is idle): open the
/// connection (a failure is `$fail` of the driver's words), run
/// `$body` on it as `$c`, and reset it for the next op. Every argument the body names is owned
/// (the body runs across the op's entries).
macro_rules! on_conn {
    ($self:ident, $cx:ident, $fail:expr, |$c:ident| $body:expr) => {{
        let (opts, pool) = ($self.opts.clone(), $self.pool.clone());
        drive_kept($cx, &pool, move |wire| -> Body<_> {
            Box::pin(async move {
                #[allow(unused_mut)]
                let mut $c = match Conn::open(wire, &opts, NEED, INIT).await {
                    Ok(c) => c,
                    Err(e) => return Err(($fail)(e)),
                };
                let answer = $body;
                $c.release(INIT).await;
                answer
            })
        })
    }};
}

/// One base op: `MysqlStore::$f(&mut conn, args..)` on the op's connection.
macro_rules! op {
    ($self:ident, $cx:ident, $f:ident($($a:expr),*)) => {
        on_conn!($self, $cx, store_err, |c| MysqlStore::$f(&mut c, $($a),*).await)
    };
}

/// The effect of one `op_id`-carrying write.
enum Write {
    Usage(Vec<(String, u64, UsageDelta)>),
    Metering(Vec<MeteringDelta>),
    Append(PlaneRecord),
}

impl Write {
    async fn apply(&self, tx: &mut Conn) -> RecordStoreResult<()> {
        match self {
            Write::Usage(cells) => {
                for (bucket, window, delta) in cells {
                    MysqlStore::add_usage_on(tx, bucket, *window, delta).await?;
                }
            }
            Write::Metering(deltas) => {
                for d in deltas {
                    MysqlStore::add_metering_on(tx, d).await?;
                }
            }
            Write::Append(record) => MysqlStore::append_plane_record_on(tx, record).await?,
        }
        Ok(())
    }
}

/// One `op_id`-carrying write (module doc, DEDUPE) on `conn`: a replay answers the original
/// answer, a conflict applies nothing, and a new op applies `write` in the op's transaction and is
/// recorded only if it applied, at the server's isolation level.
async fn deduped(conn: &mut Conn, op: OpId, body: String, write: Write) -> OpResult<()> {
    // The claim can find a row a concurrent sweep or rollback removes before it is read; the op is
    // then new again, so the claim is retried (bounded).
    for _ in 0..3 {
        let mut tx = conn.start_transaction().await.map_err(backend)?;
        match tx
            .exec_drop(
                "INSERT INTO store_ops (op_id, recorded_at, body, answer) \
                 VALUES (:op, :at, :body, '')",
                params! { "op" => &op.0[..], "at" => crate_now(), "body" => body.as_bytes() },
            )
            .await
        {
            Ok(()) => {
                write
                    .apply(&mut tx)
                    .await
                    .map_err(|e| OpRefused::Failed(e.0))?;
                tx.exec_drop(
                    "UPDATE store_ops SET answer = :answer WHERE op_id = :op",
                    params! { "answer" => Value::Null.to_string(), "op" => &op.0[..] },
                )
                .await
                .map_err(backend)?;
                tx.commit().await.map_err(backend)?;
                if op.counter().is_multiple_of(OPS_SWEEP_EVERY) {
                    // Best effort: a sweep that fails is retried by the next one.
                    let _ = conn
                        .exec_drop(
                            "DELETE FROM store_ops WHERE recorded_at < :cut LIMIT 1000",
                            params! { "cut" => crate_now().saturating_sub(OP_ID_RETENTION_SECS) },
                        )
                        .await;
                }
                return Ok(());
            }
            // ER_DUP_ENTRY: the op is recorded (the insert waited for its writer to commit).
            Err(Error::MySqlError(e)) if e.code == 1062 => {
                tx.rollback().await.map_err(backend)?;
                let row: Option<(Vec<u8>, Vec<u8>)> = conn
                    .exec_first(
                        "SELECT body, answer FROM store_ops WHERE op_id = :op",
                        params! { "op" => &op.0[..] },
                    )
                    .await
                    .map_err(backend)?;
                match row {
                    Some((b, _)) if b != body.as_bytes() => return Err(OpRefused::Conflict),
                    Some((_, a)) => {
                        return serde_json::from_slice::<Value>(&a)
                            .map(drop)
                            .map_err(backend)
                    }
                    None => continue,
                }
            }
            Err(e) => return Err(backend(e)),
        }
    }
    Err(OpRefused::Failed(
        "store_ops: the op's row kept vanishing between its claim and its read".into(),
    ))
}

/// One op in `OPS_SWEEP_EVERY` (by the minting node's counter) sweeps expired dedupe rows.
const OPS_SWEEP_EVERY: u64 = 256;

/// The backend could not run the op; nothing applied.
fn backend<D: std::fmt::Display>(e: D) -> OpRefused {
    OpRefused::Failed(e.to_string())
}

/// A backend text (the slots that answer `Result<_, String>`).
fn text(e: Error) -> String {
    e.to_string()
}

async fn v3_record_scan(
    conn: &mut Conn,
    schema: &str,
    prefix: &[u8],
    limit: u32,
) -> Result<Scanned, String> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    // A key-ordered RANGE over the primary key: `[prefix, the prefix's successor)`; a prefix
    // with no successor (empty, or every byte 0xFF) has no upper bound.
    let rows: Vec<(Vec<u8>, Vec<u8>)> = match prefix_end(prefix) {
        Some(end) => {
            conn.exec(
                "SELECT rkey, value FROM store_records WHERE schema_id = :schema \
                 AND rkey >= :start AND rkey < :end ORDER BY rkey LIMIT :limit",
                params! { "schema" => schema, "start" => prefix, "end" => end, "limit" => limit },
            )
            .await
        }
        None => {
            conn.exec(
                "SELECT rkey, value FROM store_records WHERE schema_id = :schema \
                 AND rkey >= :start ORDER BY rkey LIMIT :limit",
                params! { "schema" => schema, "start" => prefix, "limit" => limit },
            )
            .await
        }
    }
    .map_err(|e| e.to_string())?;
    rows.into_iter().map(|(k, v)| Ok((k, record(v)?))).collect()
}

impl StoreSlots for MysqlStore {
    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    /// The settings parsed (the URL included, in the driver's words); nothing is reached.
    fn validate(settings: &[u8]) -> Result<(), String> {
        Self::from_settings(settings).map(drop)
    }

    /// Open from the store section's settings (`{ "url": "mysql://..." }`): parsed here; the
    /// server is reached by the connect step.
    fn open(settings: &[u8], _host: Option<Host>) -> Result<Self, String> {
        Self::from_settings(settings)
    }

    /// Reach the server, create the schema and run the probes (at the load), in the driver's words
    /// when it cannot.
    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        on_conn!(self, cx, text, |c| MysqlStore::connect_step(&mut c)
            .await
            .map_err(|e| c.scrub(e.0)))
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        let body = format!("append_plane_record:{record:?}");
        let record = record.to_record();
        on_conn!(self, cx, backend, |c| deduped(
            &mut c,
            op,
            body,
            Write::Append(record)
        )
        .await)
    }

    /// `record_put` (slot 40): an upsert on `(schema, key)`. An EMPTY value removes the row:
    /// it is the host's strike, so `record_get` then answers `None` and
    /// `record_scan` never returns it. Removing a row that is not there is `Ok`.
    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        let (schema, key, value) = (schema.to_owned(), key.to_vec(), value.to_vec());
        if value.is_empty() {
            return on_conn!(self, cx, text, |c| {
                c.exec_drop(
                    "DELETE FROM store_records WHERE schema_id = :schema AND rkey = :rkey",
                    params! { "schema" => &schema, "rkey" => &key },
                )
                .await
                .map_err(|e| e.to_string())
            });
        }
        on_conn!(self, cx, text, |c| {
            // AN EMPTY VALUE REMOVES THE ROW (abi/store slot 26 `record_put`).
            if value.is_empty() {
                c.exec_drop(
                    "DELETE FROM store_records WHERE schema_id = :schema AND rkey = :rkey",
                    params! { "schema" => &schema, "rkey" => &key },
                )
                .await
                .map_err(|e| e.to_string())
            } else {
                c.exec_drop(
                    "INSERT INTO store_records (schema_id, rkey, value) VALUES (:schema, :rkey, :value) \
                     ON DUPLICATE KEY UPDATE value = VALUES(value)",
                    params! { "schema" => &schema, "rkey" => &key, "value" => &value },
                )
                .await
                .map_err(|e| e.to_string())
            }
        })
    }

    fn record_get(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        let (schema, key) = (schema.to_owned(), key.to_vec());
        on_conn!(self, cx, text, |c| {
            let v: Result<Option<Vec<u8>>, String> = c
                .exec_first(
                    "SELECT value FROM store_records WHERE schema_id = :schema AND rkey = :rkey",
                    params! { "schema" => &schema, "rkey" => &key },
                )
                .await
                .map_err(|e| e.to_string());
            v.and_then(|v| v.map(record).transpose())
        })
    }

    fn record_scan(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        let (schema, prefix) = (schema.to_owned(), prefix.to_vec());
        on_conn!(self, cx, text, |c| v3_record_scan(
            &mut c, &schema, &prefix, limit
        )
        .await)
    }

    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        let body = format!("add_usage_batch:{cells:?}");
        let cells: Vec<(String, u64, UsageDelta)> = cells
            .iter()
            .map(|(b, w, d)| ((*b).to_owned(), *w, d.clone()))
            .collect();
        on_conn!(self, cx, backend, |c| deduped(
            &mut c,
            op,
            body,
            Write::Usage(cells)
        )
        .await)
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        let body = format!("add_metering_batch:{deltas:?}");
        let deltas = deltas.to_vec();
        on_conn!(self, cx, backend, |c| deduped(
            &mut c,
            op,
            body,
            Write::Metering(deltas)
        )
        .await)
    }

    // The base op set (slots 0-32), each one body on the op's connection.

    fn put_key(&self, cx: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>> {
        let key = key.clone();
        op!(self, cx, put_key(&key))
    }

    fn get_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        let id = id.to_owned();
        op!(self, cx, get_key(&id))
    }

    fn list_keys(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        op!(self, cx, list_keys())
    }

    fn delete_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        let id = id.to_owned();
        op!(self, cx, delete_key(&id))
    }

    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        op!(self, cx, list_keys_since(since))
    }

    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        let bucket_id = bucket_id.to_owned();
        op!(self, cx, get_usage(&bucket_id, window_start))
    }

    fn put_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        let (bucket_id, ledger) = (bucket_id.to_owned(), ledger.clone());
        op!(self, cx, put_usage(&bucket_id, window_start, &ledger))
    }

    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        op!(self, cx, list_metering(bucket))
    }

    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let secret = secret.clone();
        op!(self, cx, put_credential(&secret))
    }

    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let (key, secret) = (key.clone(), secret.clone());
        op!(self, cx, put_key_with_credential(&key, &secret))
    }

    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        let key_id = key_id.to_owned();
        op!(self, cx, list_credentials(&key_id))
    }

    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (id, reason) = (id.to_owned(), reason.to_owned());
        op!(self, cx, revoke_credential(&id, &reason))
    }

    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        op!(self, cx, list_credentials_since(since))
    }

    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        op!(self, cx, list_audit())
    }

    fn add_denylist(
        &self,
        cx: &mut Op<'_>,
        sub: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (sub, reason) = (sub.to_owned(), reason.to_owned());
        op!(self, cx, add_denylist(&sub, &reason))
    }

    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        op!(self, cx, list_denylist())
    }

    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        op!(self, cx, list_audit_tail(limit))
    }

    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        let record = record.to_record();
        op!(self, cx, upsert_plane_record(&record))
    }

    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        let (kind, id) = (kind.to_owned(), id.to_owned());
        op!(self, cx, get_plane_record(&kind, &id))
    }

    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        let (kind, selector) = (kind.to_owned(), selector.to_static());
        op!(self, cx, list_plane_records(&kind, &selector))
    }

    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        let kind = kind.to_owned();
        op!(self, cx, list_plane_record_parents(&kind))
    }

    fn purge_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
        retention: busbar_contract::records::Retention,
    ) -> Step<RecordStoreResult<u64>> {
        let kind = kind.to_owned();
        on_conn!(self, cx, store_err, |c| {
            MysqlStore::purge_plane_records(&mut c, &kind, before, retention).await
        })
    }

    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        let kind = kind.to_owned();
        op!(self, cx, purge_plane_records_before(&kind, before))
    }

    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (kind, id) = (kind.to_owned(), id.to_owned());
        op!(self, cx, delete_plane_record(&kind, &id))
    }

    fn redeem_plane_token(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        let (kind, token) = (kind.to_owned(), token.to_owned());
        op!(self, cx, redeem_plane_token(&kind, &token, expires_at, now))
    }

    fn plane_token_live(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        // Answered without the server (no connection) when the deadline has passed.
        if now > expires_at {
            return Step::Ready(Ok(false));
        }
        let (kind, token) = (kind.to_owned(), token.to_owned());
        op!(self, cx, plane_token_live(&kind, &token, expires_at, now))
    }
}

/// A stored record's bytes as a [`RecordBytes`] (the column is sized to the ceiling).
fn record(v: Vec<u8>) -> Result<RecordBytes, String> {
    RecordBytes::new(v).map_err(|n| format!("a stored record of {n} bytes is over the ceiling"))
}

/// The smallest key above every key that starts with `prefix`, or `None` when there is none.
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

#[cfg(test)]
mod prefix_end_tests {
    use super::prefix_end;

    #[test]
    fn prefix_end_carries_past_trailing_0xff_and_has_no_successor_for_all_0xff_or_empty() {
        assert_eq!(prefix_end(b"a"), Some(b"b".to_vec()));
        assert_eq!(prefix_end(b"b\xff"), Some(b"c".to_vec()));
        assert_eq!(prefix_end(b"b\xff\xff"), Some(b"c".to_vec()));
        assert_eq!(prefix_end(b"\xff\xff"), None);
        assert_eq!(prefix_end(b""), None);
    }
}
