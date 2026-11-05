// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 door over [`MysqlStore`]: `store_door!` and the slots the store v3 table adds to the base op set ([`StoreSlots`]): the `op_id`-carrying writes, the kernel's records, and the base op set itself, every slot one body on the op's connection.

use mysql_common::params;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::store::column::{prefix_end, storable_i64};
use busbar_contract::abi::sdk::store::conditional::{self, Decision, Expected, Mutation, Request};
use busbar_contract::abi::sdk::store::correction;
use busbar_contract::abi::sdk::store::dedupe::{Body as DedupeBody, Dedupe, Seen};
use busbar_contract::abi::sdk::store::wire::{drive_kept, Body};
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecord,
    PlaneRecordRef, PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::mysqlwire::{Conn, Error};
use crate::{store_err, ApplyError, MysqlStore, INIT, NAME};

const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The store's one need: the server, dialled over `tcp` at the URL's `host:port` (or its `socket=` path as `unix:<path>`; the store names the target per connection), in the `operator-infrastructure` egress class (private, loopback and plaintext allowed; pinned; cloud metadata hosts refused).
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

busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
    (busbar_contract::abi::sdk::store::rewrap::INTENT, b"1"),
    (conditional::CAPABILITY, b"1"),
    ("busbar.store.count-scale", b"6"),
    ("busbar.store.count-range", b"i128"),
    (correction::CAPABILITY, b"1"),
]);

/// The most ops in flight at once, as the door states it: one per kept connection and then some waiting on a free one.
pub const MAX_INFLIGHT: u32 = 64;

/// The settings accepted by this plugin's lifecycle parser.
const SETTINGS_SCHEMA: busbar_contract::abi::mechanism::call::Blob =
    busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json"));

busbar_contract::store_door!(
    MysqlStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    MAX_INFLIGHT,
    needs: NEEDS,
    extensions: EXTENSIONS,
    settings_schema: SETTINGS_SCHEMA
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
pub(crate) enum Write {
    Usage(Vec<(String, u64, UsageDelta)>),
    Metering(Vec<MeteringDelta>),
    Append(PlaneRecord),
}

impl Write {
    /// The cells in one global order, so two nodes flushing overlapping cells take their row locks in the same order (sums commute, so the order is free to choose).
    pub(crate) fn ordered(mut self) -> Self {
        match &mut self {
            Write::Usage(cells) => cells.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1))),

            Write::Metering(ds) => ds.sort_by(|a, b| {
                (
                    &a.key_id,
                    a.bucket,
                    &a.model,
                    &a.provider,
                    a.priced_from_ms,
                    &a.key_group_at_use,
                    &a.pricing_version,
                )
                    .cmp(&(
                        &b.key_id,
                        b.bucket,
                        &b.model,
                        &b.provider,
                        b.priced_from_ms,
                        &b.key_group_at_use,
                        &b.pricing_version,
                    ))
            }),
            Write::Append(_) => {}
        }
        self
    }

    async fn apply(&self, tx: &mut Conn) -> Result<(), ApplyError> {
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

/// One atomically deduplicated `op_id`-carrying write on `conn`: `None` when it applied `write` and
/// recorded `body` in one transaction, `Some(recorded)` when a body was already recorded under the
/// op's id (nothing applied; [`Dedupe::answer`] tells a replay from a conflict).
pub(crate) async fn deduped(
    conn: &mut Conn,
    op: OpId,
    body: DedupeBody,
    write: Write,
) -> OpResult<Option<Vec<u8>>> {
    let write = write.ordered();
    // The claim can find a row a concurrent sweep or rollback removes before it is read; the op is
    // then new again, so the claim is retried (bounded).
    for _ in 0..3 {
        let mut tx = conn.start_transaction().await.map_err(backend)?;

        if matches!(&write, Write::Usage(_) | Write::Metering(_)) {
            lock_ledger_sequence(&mut tx)
                .await
                .map_err(|e| backend(e.text))?;
        }
        match tx
            .exec_drop(
                "INSERT INTO store_ops (op_id, recorded_at, body, answer) \
                 VALUES (:op, UNIX_TIMESTAMP(), :body, 'null')",
                params! { "op" => &op.0[..], "body" => &body[..] },
            )
            .await
        {
            Ok(()) => {
                if matches!(&write, Write::Usage(cells) if cells.iter().any(|(bucket, _, _)| correction::reserved_bucket(bucket)))
                {
                    return Err(after_rollback(
                        OpRefused::Refused("reserved usage correction bucket".into()),
                        tx.rollback().await,
                    ));
                }
                if let Err(e) = write.apply(&mut tx).await {
                    return Err(after_rollback(apply_refusal(e), tx.rollback().await));
                }
                tx.commit().await.map_err(backend)?;
                sweep_ops(conn, op).await;
                return Ok(None);
            }

            Err(Error::MySqlError(e)) if e.code == crate::ER_DUP_ENTRY => {
                tx.rollback().await.map_err(backend)?;
                let recorded: Option<Vec<u8>> = conn
                    .exec_first(
                        "SELECT body FROM store_ops WHERE op_id = :op",
                        params! { "op" => &op.0[..] },
                    )
                    .await
                    .map_err(backend)?;
                if recorded.is_some() {
                    return Ok(recorded);
                }
            }
            Err(e) => return Err(backend(e)),
        }
    }
    Err(OpRefused::Failed(
        "store_ops: the op's row kept vanishing between its claim and its read".into(),
    ))
}

fn apply_refusal(error: ApplyError) -> OpRefused {
    if error.refused || error.server_code.is_some_and(is_refusal) {
        OpRefused::Refused(error.text)
    } else {
        OpRefused::Failed(error.text)
    }
}

fn after_rollback(error: OpRefused, rollback: Result<(), Error>) -> OpRefused {
    match (error, rollback) {
        (OpRefused::Refused(message), Err(other)) => {
            OpRefused::Refused(format!("{message}; rollback also failed: {other}"))
        }
        (OpRefused::Failed(message), Err(other)) => {
            OpRefused::Failed(format!("{message}; rollback also failed: {other}"))
        }
        (error, _) => error,
    }
}

async fn sweep_ops(conn: &mut Conn, op: OpId) {
    if op.counter().is_multiple_of(OPS_SWEEP_EVERY)
        && conn
            .exec_drop(
                "DELETE FROM store_ops WHERE recorded_at < UNIX_TIMESTAMP() - :retention LIMIT 1000",
                params! { "retention" => OP_ID_RETENTION_SECS },
            )
            .await.is_err() {
        tracing::warn!("mysql store: dedupe retention sweep failed; committed operation retained");
    }
}

/// Existing sequence-row authority shared by all raw ledger writers and key deletion.
pub(crate) async fn lock_ledger_sequence(tx: &mut Conn) -> Result<(), ApplyError> {
    let sequence: Option<u64> = tx
        .query_first("SELECT revision FROM store_sequence WHERE id=1 FOR UPDATE")
        .await
        .map_err(crate::apply_err)?;
    sequence.map(|_| ()).ok_or_else(|| ApplyError {
        text: "store_sequence row missing".into(),
        server_code: None,
        refused: false,
    })
}

/// Whole-prestate acceptance and every replacement share one durable transaction.
async fn usage_correction_on(
    conn: &mut Conn,
    request: &correction::Request,
) -> OpResult<correction::Decision> {
    let mut tx = conn.start_transaction().await.map_err(backend)?;
    lock_ledger_sequence(&mut tx)
        .await
        .map_err(|e| backend(e.text))?;
    let dedupe = Dedupe::usage_correction(request);
    let mut normalized_request = request.clone();
    for row in &mut normalized_request.metering {
        row.normalize_scale6()
            .map_err(|e| OpRefused::Refused(e.to_string()))?;
    }
    for change in &mut normalized_request.usage {
        change
            .expected
            .normalize_scale6()
            .map_err(|e| OpRefused::Refused(e.to_string()))?;
        change
            .replacement
            .normalize_scale6()
            .map_err(|e| OpRefused::Refused(e.to_string()))?;
    }
    let request = &normalized_request;
    let recorded: Option<Vec<u8>> = tx
        .exec_first(
            "SELECT body FROM store_ops WHERE op_id=:op FOR UPDATE",
            params! { "op" => &request.op_id.0[..] },
        )
        .await
        .map_err(backend)?;
    match dedupe.seen(recorded.as_deref()) {
        Seen::Replay => {
            tx.rollback().await.map_err(backend)?;
            return Ok(correction::Decision::Applied);
        }
        Seen::Conflict => {
            tx.rollback().await.map_err(backend)?;
            return Err(OpRefused::Conflict);
        }
        Seen::New => {}
    }
    let live: Option<(Option<u64>,)> = tx
        .exec_first(
            "SELECT deleted_at FROM api_keys WHERE id=:id FOR UPDATE",
            params! { "id" => &request.key_id },
        )
        .await
        .map_err(backend)?;
    let mut metering =
        MysqlStore::list_metering_key_on(&mut tx, request.day_start, Some(&request.key_id))
            .await
            .map_err(backend)?;
    correction::canonical_metering(&mut metering);
    if live != Some((None,)) || metering != request.metering {
        tx.rollback().await.map_err(backend)?;
        return Ok(correction::Decision::ConditionConflict);
    }
    for change in &request.usage {
        let mut current = MysqlStore::get_usage_on(
            &mut tx,
            &change.address.bucket_id,
            change.address.window_start,
        )
        .await
        .map_err(backend)?;
        correction::canonical_ledger(&mut current)
            .map_err(|message| OpRefused::Failed(message.into()))?;
        if current != change.expected {
            tx.rollback().await.map_err(backend)?;
            return Ok(correction::Decision::ConditionConflict);
        }
    }
    for change in &request.usage {
        if let Err(error) = MysqlStore::put_usage_on(
            &mut tx,
            &change.address.bucket_id,
            change.address.window_start,
            &change.replacement,
        )
        .await
        {
            return Err(after_rollback(apply_refusal(error), tx.rollback().await));
        }
    }
    tx.exec_drop(
        "INSERT INTO store_ops (op_id,recorded_at,body,answer) VALUES (:op,UNIX_TIMESTAMP(),:body,'null')",
        params! { "op" => &request.op_id.0[..], "body" => &dedupe.body()[..] },
    )
    .await
    .map_err(backend)?;

    tx.commit().await.map_err(backend)?;
    sweep_ops(conn, request.op_id).await;
    Ok(correction::Decision::Applied)
}

/// The first lock of every generic-record writer, including legacy single-key puts/deletes.
async fn lock_record_sequence(tx: &mut Conn) -> Result<(), String> {
    lock_ledger_sequence(tx).await.map_err(|error| error.text)
}

async fn record_put_on(
    conn: &mut Conn,
    schema: &str,
    key: &[u8],
    value: &[u8],
) -> Result<(), String> {
    let mut tx = conn.start_transaction().await.map_err(text)?;
    lock_record_sequence(&mut tx).await?;
    if value.is_empty() {
        tx.exec_drop(
            "DELETE FROM store_records WHERE schema_id=:schema AND rkey=:rkey",
            params! { "schema"=>schema,"rkey"=>key },
        )
        .await
        .map_err(text)?;
    } else {
        tx.exec_drop(
            "INSERT INTO store_records (schema_id,rkey,value) VALUES (:schema,:rkey,:value) \
             ON DUPLICATE KEY UPDATE value=VALUES(value)",
            params! { "schema"=>schema,"rkey"=>key,"value"=>value },
        )
        .await
        .map_err(text)?;
    }
    tx.commit().await.map_err(text)
}

/// A single pre-state comparison, mutation batch, and applied-only receipt.
async fn record_transaction_on(conn: &mut Conn, request: &Request) -> OpResult<Decision> {
    conn.query_drop("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .await
        .map_err(backend)?;
    let mut tx = conn.start_transaction().await.map_err(backend)?;
    lock_record_sequence(&mut tx).await.map_err(backend)?;
    let dedupe = Dedupe::record_transaction(request);
    let recorded: Option<Vec<u8>> = tx
        .exec_first(
            "SELECT body FROM store_ops WHERE op_id=:op FOR UPDATE",
            params! { "op" => &request.op_id.0[..] },
        )
        .await
        .map_err(backend)?;
    match dedupe.seen(recorded.as_deref()) {
        Seen::Replay => {
            tx.rollback().await.map_err(backend)?;
            return Ok(Decision::Applied);
        }
        Seen::Conflict => {
            tx.rollback().await.map_err(backend)?;
            return Err(OpRefused::Conflict);
        }
        Seen::New => {}
    }
    for predicate in &request.predicates {
        let current: Option<Vec<u8>> = tx
            .exec_first(
                "SELECT value FROM store_records WHERE schema_id=:schema AND rkey=:rkey FOR UPDATE",
                params! { "schema" => &predicate.schema, "rkey" => &predicate.key },
            )
            .await
            .map_err(backend)?;
        let matches = match &predicate.expected {
            Expected::Absent => current.is_none(),
            Expected::Bytes(expected) => current.as_ref() == Some(expected),
        };
        if !matches {
            tx.rollback().await.map_err(backend)?;
            return Ok(Decision::ConditionConflict);
        }
    }
    for mutation in &request.mutations {
        let changed = match mutation {
            Mutation::Put { schema, key, value } => tx
                .exec_drop(
                    "INSERT INTO store_records (schema_id,rkey,value) VALUES (:schema,:rkey,:value) \
                     ON DUPLICATE KEY UPDATE value=VALUES(value)",
                    params! { "schema" => schema, "rkey" => key, "value" => value },
                )
                .await,
            Mutation::Delete { schema, key } => tx
                .exec_drop(
                    "DELETE FROM store_records WHERE schema_id=:schema AND rkey=:rkey",
                    params! { "schema" => schema, "rkey" => key },
                )
                .await,
            Mutation::DeleteRange {
                schema,
                prefix,
                exact_key_length,
            } => match prefix_end(prefix) {
                Some(end) => tx
                    .exec_drop(
                        "DELETE FROM store_records WHERE schema_id=:schema \
                         AND rkey>=:start AND rkey<:end AND OCTET_LENGTH(rkey)=:length",
                        params! { "schema" => schema, "start" => prefix, "end" => end, "length" => *exact_key_length },
                    )
                    .await,
                None => tx
                    .exec_drop(
                        "DELETE FROM store_records WHERE schema_id=:schema \
                         AND rkey>=:start AND OCTET_LENGTH(rkey)=:length",
                        params! { "schema" => schema, "start" => prefix, "length" => *exact_key_length },
                    )
                    .await,
            },
        };
        if let Err(error) = changed {
            let refusal = match &error {
                Error::MySqlError(e) if is_refusal(e.code) => OpRefused::Refused(error.to_string()),
                _ => backend(error),
            };
            return Err(after_rollback(refusal, tx.rollback().await));
        }
    }
    tx.exec_drop(
        "INSERT INTO store_ops (op_id,recorded_at,body,answer) VALUES (:op,UNIX_TIMESTAMP(),:body,'null')",
        params! { "op" => &request.op_id.0[..], "body" => &dedupe.body()[..] },
    )
    .await
    .map_err(backend)?;

    tx.commit().await.map_err(backend)?;
    sweep_ops(conn, request.op_id).await;
    Ok(Decision::Applied)
}

/// The server errors that are deterministic refusals of the statement's values (S5): the same write can never apply, and nothing did.
fn is_refusal(code: u16) -> bool {
    matches!(
        code,
        1264 // ER_WARN_DATA_OUT_OF_RANGE
        | 1292 // ER_TRUNCATED_WRONG_VALUE
        | 1366 // ER_TRUNCATED_WRONG_VALUE_FOR_FIELD
        | 1406 // ER_DATA_TOO_LONG
        | 1452 // ER_NO_REFERENCED_ROW_2
        | 1690 // ER_DATA_OUT_OF_RANGE
        | 3819 // ER_CHECK_CONSTRAINT_VIOLATED
    )
}

/// One op in `OPS_SWEEP_EVERY` (by the minting node's counter) sweeps expired dedupe rows.
const OPS_SWEEP_EVERY: u64 = 256;

/// The backend could not confirm the op.
fn backend<D: std::fmt::Display>(e: D) -> OpRefused {
    OpRefused::Failed(e.to_string())
}

/// The connect step could not open its connection: one prefix, then the driver's words.
fn connect_failure(e: Error) -> String {
    format!("{NAME_PREFIX}: failed to connect: {e}")
}

const NAME_PREFIX: &str = "mysql store";

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
    .map_err(text)?;
    rows.into_iter().map(|(k, v)| Ok((k, record(v)?))).collect()
}

impl StoreSlots for MysqlStore {
    const USAGE_CORRECTION: bool = true;

    fn apply_usage_correction(
        &self,
        cx: &mut Op<'_>,
        request: &correction::Request,
    ) -> Step<OpResult<correction::Decision>> {
        if let Err(message) = request.validate() {
            return Step::Ready(Err(OpRefused::Refused(message.into())));
        }
        let request = request.clone();
        on_conn!(self, cx, backend, |c| usage_correction_on(&mut c, &request)
            .await)
    }

    const RECORD_TRANSACTION: bool = true;

    fn record_transaction(&self, cx: &mut Op<'_>, request: &Request) -> Step<OpResult<Decision>> {
        if let Err(message) = request.validate() {
            return Step::Ready(Err(OpRefused::Refused(message.into())));
        }
        let request = request.clone();
        on_conn!(self, cx, backend, |c| record_transaction_on(
            &mut c, &request
        )
        .await)
    }

    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    /// The settings parsed (the URL included, in the driver's words); nothing is reached.
    fn validate(settings: &[u8]) -> Result<(), String> {
        Self::from_settings(settings).map(drop)
    }

    /// Open from the store section's settings (`{ "url": "mysql://..." }`): parsed here; the server is reached by the connect step.
    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        _host: Option<Host>,
    ) -> Result<Self, String> {
        Self::from_settings_lent(settings, secrets)
    }

    /// Reach the server, create the schema and run the probes (at the load), in the driver's words when it cannot.
    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        on_conn!(self, cx, connect_failure, |c| MysqlStore::connect_step(
            &mut c
        )
        .await
        .map_err(|e| c.scrub(e.0)))
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        for (field, v) in [("seq", record.seq), ("ts", record.ts)] {
            if let Err(e) = storable_i64("append_plane_record", field, v) {
                return Step::Ready(Err(OpRefused::Refused(e.0)));
            }
        }
        let d = Dedupe::append(record);
        let (body, record) = (*d.body(), record.to_record());
        on_conn!(self, cx, backend, |c| deduped(
            &mut c,
            op,
            body,
            Write::Append(record)
        )
        .await)
        .map(|r| d.answer(r))
    }

    /// `record_put` (slot 26): an upsert on `(schema, key)`. An EMPTY value removes the row:
    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        let (schema, key, value) = (schema.to_owned(), key.to_vec(), value.to_vec());
        on_conn!(self, cx, text, |c| record_put_on(
            &mut c, &schema, &key, &value
        )
        .await)
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
                .map_err(text);
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
        let d = Dedupe::usage(cells);
        let body = *d.body();
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
        .map(|r| d.answer(r))
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        for d in deltas {
            if let Err(e) = storable_i64("add_metering_batch", "priced_from_ms", d.priced_from_ms) {
                return Step::Ready(Err(OpRefused::Refused(e.0)));
            }
        }
        let d = Dedupe::metering(deltas);
        let (body, deltas) = (*d.body(), deltas.to_vec());
        on_conn!(self, cx, backend, |c| deduped(
            &mut c,
            op,
            body,
            Write::Metering(deltas)
        )
        .await)
        .map(|r| d.answer(r))
    }

    // The base op set (the kind slots, `abi::store::slot`), each one body on the op's connection.

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

    fn purge_usage_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        op!(self, cx, purge_usage_before(before))
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
        let request = busbar_contract::abi::sdk::store::rewrap::Request::new(secret, "");
        op!(self, cx, put_credential(&request.expected))
    }

    fn rewrap_credential(
        &self,
        cx: &mut Op<'_>,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> Step<RecordStoreResult<bool>> {
        let request = busbar_contract::abi::sdk::store::rewrap::Request::new(expected, replacement);
        op!(
            self,
            cx,
            rewrap_credential(&request.expected, &request.replacement)
        )
    }

    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let key = key.clone();
        let request = busbar_contract::abi::sdk::store::rewrap::Request::new(secret, "");
        op!(self, cx, put_key_with_credential(&key, &request.expected))
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
        if kind != crate::TICKET_RECORD_KIND && now > expires_at {
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

#[cfg(test)]
#[path = "slots_refusal_tests.rs"]
mod refusal_tests;

#[cfg(test)]
#[path = "settings_schema_tests.rs"]
mod settings_schema_tests;
