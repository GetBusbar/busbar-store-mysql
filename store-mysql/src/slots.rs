// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE V3 DOOR over [`MysqlStore`]: `store_door!` and the slots the store v3 table adds to
//! the 1.5.5 op set ([`StoreSlots`]): the `op_id`-carrying writes, the journal, sessions, the
//! kernel's records, the money slots and `window_caps`, and the 1.5.5 op set itself, every slot
//! one body on the op's connection.
//!
//! DEDUPE (`abi::store` S1-S4), DURABLE: every `op_id` write runs in ONE transaction that first
//! inserts the op's row into `store_ops` (its value fields), then applies the effect, then stores
//! the answer, then commits. Two racing calls with one `op_id` serialise on that primary key: the
//! second waits for the first, and reads its committed row (same value fields: the original
//! answer, nothing applied; different: a conflict). A refused or failed op rolls back with its row,
//! so nothing is recorded (S3). Rows older than [`OP_ID_RETENTION_SECS`] are swept (S4).
//!
//! EPOCH (ARCHITECT 2026-10-02): fixed at 0. No store ABI operation advances the epoch yet, so a
//! `reserve` or `slice_release` is never refused for the epoch it states and every head states 0.
//! When WIRE-STORE adds the advance, the store persists the epoch and refuses stale writers.
//!
//! GRANT LIFETIME: `reserve` carries no requested lifetime (`ReserveIn`, `UnitCell`), so a grant
//! never expires (`valid_until_ms = u64::MAX`): a slice holds its draw until it is released.
//!
//! LOCK ORDER: a call that locks several cap or slice rows locks them in key order first, so two
//! concurrent draws over the same slots cannot deadlock on each other.
//!
//! CONNECTIONS: every slot runs on one of the instance's kept connections over the host's
//! connector, as straight-line async code driven by the store SDK's `wire::drive_kept` (busbar THE
//! DESIGN: every call Ready or Pending(wake), no socket of the plugin's own). The door declares one
//! outbound `tcp` need ([`NEEDS`], `operator-infrastructure`); `open` parses the settings and its
//! connect step reaches the server, creates the schema and runs the probes, so an unreachable or
//! refusing server still fails the load at open, in the driver's words.

use std::collections::BTreeMap;

use mysql_common::params;
use serde_json::{json, Value};

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::store::wire::{drive_kept, Body};
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, Op, OpRefused, OpResult, ReserveRefused,
    Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::mysqlwire::{Conn, Error, Params, Transaction, Value as SqlValue};
use crate::{crate_now, store_err, MysqlStore, INIT, NAME};

const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// THE STORE'S ONE NEED: the server, dialled over `tcp` at the URL's `host:port` (or its
/// `socket=` path as `unix:<path>`; the store names the target per connection), in the
/// `operator-infrastructure` egress class (private, loopback and plaintext allowed; pinned; cloud
/// metadata hosts refused). Its timeout is the host's default (1.5.5 set none; a URL's
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

busbar_contract::store_door!(
    MysqlStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    64,
    needs: NEEDS
);

/// RUN ONE OP on one of the instance's kept connections (a fresh one when none is idle): open the
/// connection (a failure is `$fail` of the driver's words, as 1.5.5's `get_conn` failure was), run
/// `$body` on it as `$c`, and reset it for the next op. Every argument the body names is owned
/// (the body runs across the op's entries).
macro_rules! on_conn {
    ($self:ident, $cx:ident, $fail:expr, |$c:ident| $body:expr) => {{
        let shared = $self.shared();
        let pool = shared.pool.clone();
        drive_kept($cx, &pool, move |wire| -> Body<_> {
            Box::pin(async move {
                #[allow(unused_mut)]
                let mut $c = match Conn::open(wire, &shared.opts, NEED, INIT).await {
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

/// One `op_id`-carrying write (module doc, DEDUPE) on `$conn`: a replay answers the original
/// answer, a conflict applies nothing, and a new op runs `$apply` in the op's transaction (its
/// answer, or an `$E`) and is recorded only if it applied. Evaluates to the answer; returns the
/// refusal from the enclosing fn.
macro_rules! deduped {
    ($conn:expr, $op:expr, $body:expr, $E:ty, |$tx:ident| $apply:block) => {{
        let conn: &mut Conn = $conn;
        let op: OpId = $op;
        let body: &str = $body;
        let mut attempts = 0;
        // The claim can find a row a concurrent sweep or rollback removes before it is read; the
        // op is then new again, so the claim is retried (bounded).
        loop {
            attempts += 1;
            if attempts > 3 {
                return Err(<$E as Refusal>::backend(
                    "store_ops: the op's row kept vanishing between its claim and its read".into(),
                ));
            }
            let mut tx = conn
                .start_transaction()
                .await
                .map_err(backend::<$E, _>)?;
            match tx
                .exec_drop(
                    "INSERT INTO store_ops (op_id, recorded_at, body, answer) \
                     VALUES (:op, :at, :body, '')",
                    params! { "op" => &op.0[..], "at" => crate_now(), "body" => body.as_bytes() },
                )
                .await
            {
                Ok(()) => {
                    let answer: Value = {
                        let $tx: &mut Transaction<'_> = &mut tx;
                        applied::<$E, _>(async { $apply }).await?
                    };
                    tx.exec_drop(
                        "UPDATE store_ops SET answer = :answer WHERE op_id = :op",
                        params! { "answer" => answer.to_string(), "op" => &op.0[..] },
                    )
                    .await
                    .map_err(backend::<$E, _>)?;
                    tx.commit().await.map_err(backend::<$E, _>)?;
                    if op.counter().is_multiple_of(OPS_SWEEP_EVERY) {
                        // Best effort: a sweep that fails is retried by the next one.
                        let _ = conn
                            .exec_drop(
                                "DELETE FROM store_ops WHERE recorded_at < :cut LIMIT 1000",
                                params! { "cut" => crate_now().saturating_sub(OP_ID_RETENTION_SECS) },
                            )
                            .await;
                    }
                    break answer;
                }
                // ER_DUP_ENTRY: the op is recorded (the insert waited for its writer to commit).
                Err(Error::MySqlError(e)) if e.code == 1062 => {
                    tx.rollback().await.map_err(backend::<$E, _>)?;
                    let row: Option<(Vec<u8>, Vec<u8>)> = conn
                        .exec_first(
                            "SELECT body, answer FROM store_ops WHERE op_id = :op",
                            params! { "op" => &op.0[..] },
                        )
                        .await
                        .map_err(backend::<$E, _>)?;
                    match row {
                        Some((b, _)) if b != body.as_bytes() => {
                            return Err(<$E as Refusal>::conflict())
                        }
                        Some((_, a)) => {
                            break serde_json::from_slice(&a).map_err(backend::<$E, _>)?
                        }
                        None => continue,
                    }
                }
                Err(e) => return Err(backend(e)),
            }
        }
    }};
}

/// Pin an apply block's answer and refusal types.
fn applied<E, F: std::future::Future<Output = Result<Value, E>>>(f: F) -> F {
    f
}

/// One op in `OPS_SWEEP_EVERY` (by the minting node's counter) sweeps expired dedupe rows.
const OPS_SWEEP_EVERY: u64 = 256;

/// A slot as its key columns: `(bucket, pooled, pool, dimension, class_key, window_start)`.
type Slot = (String, bool, String, u32, String, u64);

/// The `WHERE` clause naming one slot by its key columns.
const SLOT_WHERE: &str = "bucket = :bucket AND pooled = :pooled AND pool = :pool \
     AND dimension = :dimension AND class_key = :class_key AND window_start = :window_start";

fn slot_of(k: &CellKey<'_>) -> Slot {
    let (dimension, class_key) = match k.dimension {
        Dimension::NanoUnits => (0, ""),
        Dimension::Requests => (1, ""),
        Dimension::Concurrency => (2, ""),
        Dimension::Class(c) => (3, c),
    };
    (
        k.bucket.to_string(),
        k.pool.is_some(),
        k.pool.unwrap_or_default().to_string(),
        dimension,
        class_key.to_string(),
        k.window_start,
    )
}

/// `slot`'s key columns as named parameters, plus `extra`.
fn slot_params(slot: &Slot, extra: Vec<(&str, SqlValue)>) -> Params {
    let (bucket, pooled, pool, dimension, class_key, window_start) = slot;
    let mut p: Vec<(String, SqlValue)> = vec![
        ("bucket".into(), bucket.as_str().into()),
        ("pooled".into(), (*pooled).into()),
        ("pool".into(), pool.as_str().into()),
        ("dimension".into(), (*dimension).into()),
        ("class_key".into(), class_key.as_str().into()),
        ("window_start".into(), (*window_start).into()),
    ];
    p.extend(extra.into_iter().map(|(n, v)| (n.to_string(), v)));
    Params::from(p)
}

/// The 1.5.5 admission test for one cell (`abi::store::ReserveIn`, GRANT SIZE): whether drawing
/// `amount` onto `used` under `cap` is refused. `used + amount` is checked: an overflow refuses.
fn exhausted(dimension: u32, used: u64, amount: u64, cap: u64) -> bool {
    let Some(after) = used.checked_add(amount) else {
        return true;
    };
    match dimension {
        // DIM_CLASS: `tokens >= cap`: the draw that crosses the cap is granted whole.
        3 => used >= cap,
        // DIM_NANO_UNITS: `derived >= cap || derived + fee > cap`.
        0 => used >= cap || after > cap,
        // DIM_REQUESTS / DIM_CONCURRENCY: `used + amount > cap`.
        _ => after > cap,
    }
}

/// How an `op_id` write's refusal type spells the two refusals the dedupe itself answers.
trait Refusal {
    /// The same `op_id` with different value fields.
    fn conflict() -> Self;
    /// The backend could not run the op; nothing applied.
    fn backend(text: String) -> Self;
}

impl Refusal for OpRefused {
    fn conflict() -> Self {
        OpRefused::Conflict
    }
    fn backend(text: String) -> Self {
        OpRefused::Failed(text)
    }
}

impl Refusal for ReserveRefused {
    fn conflict() -> Self {
        ReserveRefused::Conflict
    }
    fn backend(_: String) -> Self {
        ReserveRefused::Unavailable
    }
}

impl Refusal for CapsRefused {
    fn conflict() -> Self {
        CapsRefused::Conflict
    }
    fn backend(text: String) -> Self {
        CapsRefused::Failed(text)
    }
}

fn backend<E: Refusal, D: std::fmt::Display>(e: D) -> E {
    E::backend(e.to_string())
}

fn failed(e: busbar_contract::records::RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

/// A backend text (the slots that answer `Result<_, String>`).
fn text(e: Error) -> String {
    e.to_string()
}

/// An answer that does not decode as its op's shape: the stored row is not this op's.
fn undecodable<E: Refusal>(answer: &Value) -> E {
    E::backend(format!(
        "store_ops holds an answer this op cannot read: {answer}"
    ))
}

/// The current cap and drawn total of each slot in `slots` that has a cap, its row locked; the
/// rows are locked in key order.
async fn lock_caps(
    tx: &mut Conn,
    slots: impl Iterator<Item = Slot>,
) -> Result<BTreeMap<Slot, (u64, u64, u64)>, String> {
    let mut keys: Vec<Slot> = slots.collect();
    keys.sort();
    keys.dedup();
    let mut held = BTreeMap::new();
    for k in keys {
        let row: Option<(u64, u64, u64)> = tx
            .exec_first(
                format!(
                    "SELECT cap, config_gen, used FROM store_caps WHERE {SLOT_WHERE} FOR UPDATE"
                ),
                slot_params(&k, vec![]),
            )
            .await
            .map_err(|e| e.to_string())?;
        if let Some(r) = row {
            held.insert(k, r);
        }
    }
    Ok(held)
}

// ── the v3 bodies (each on the op's connection) ─────────────────────────────────────────────────

/// A deduped write whose answer is "done": `apply` is the effect's body.
macro_rules! done_op {
    ($conn:expr, $op:expr, $body:expr, |$tx:ident| $apply:block) => {{
        let answer = deduped!($conn, $op, $body, OpRefused, |$tx| {
            $apply;
            Ok(Value::Null)
        });
        let _ = answer;
        Ok(())
    }};
}

async fn v3_add_usage_batch(
    conn: &mut Conn,
    op: OpId,
    body: String,
    cells: Vec<(String, u64, UsageDelta)>,
) -> OpResult<()> {
    done_op!(conn, op, &body, |tx| {
        for (bucket, window, delta) in &cells {
            MysqlStore::add_usage_on(tx, bucket, *window, delta)
                .await
                .map_err(failed)?;
        }
    })
}

async fn v3_add_metering_batch(
    conn: &mut Conn,
    op: OpId,
    body: String,
    deltas: Vec<MeteringDelta>,
) -> OpResult<()> {
    done_op!(conn, op, &body, |tx| {
        for d in &deltas {
            MysqlStore::add_metering_on(tx, d).await.map_err(failed)?;
        }
    })
}

/// One transaction: a fork anywhere in the batch rolls back every record before it.
async fn v3_append_audit_batch(
    conn: &mut Conn,
    op: OpId,
    body: String,
    entries: Vec<AuditRecord>,
) -> OpResult<()> {
    done_op!(conn, op, &body, |tx| {
        for e in &entries {
            MysqlStore::append_audit_on(tx, e).await.map_err(failed)?;
        }
    })
}

async fn v3_append_plane_record(
    conn: &mut Conn,
    op: OpId,
    body: String,
    record: busbar_contract::records::PlaneRecord,
) -> OpResult<()> {
    done_op!(conn, op, &body, |tx| {
        MysqlStore::append_plane_record_on(tx, &record)
            .await
            .map_err(failed)?;
    })
}

async fn v3_append_batch(
    conn: &mut Conn,
    op: OpId,
    body: String,
    stream: String,
    records: Vec<RecordBytes>,
) -> OpResult<Head> {
    let answer = deduped!(conn, op, &body, OpRefused, |tx| {
        let last: Option<u64> = tx
            .exec_first(
                "SELECT seq FROM store_journal WHERE stream = :stream \
                 ORDER BY seq DESC LIMIT 1 FOR UPDATE",
                params! { "stream" => &stream },
            )
            .await
            .map_err(backend::<OpRefused, _>)?;
        let first = last.unwrap_or(0) + 1;
        tx.exec_batch(
            "INSERT INTO store_journal (stream, seq, record) VALUES (:stream, :seq, :record)",
            records.iter().zip(first..).map(|(r, seq)| {
                params! { "stream" => &stream, "seq" => seq, "record" => r.as_slice() }
            }),
        )
        .await
        .map_err(backend::<OpRefused, _>)?;
        Ok(json!([first - 1 + records.len() as u64, 0]))
    });
    match serde_json::from_value::<(u64, u64)>(answer.clone()) {
        Ok((seq, epoch)) => Ok(Head { seq, epoch }),
        Err(_) => Err(undecodable(&answer)),
    }
}

async fn v3_reserve(
    conn: &mut Conn,
    op: OpId,
    body: String,
    cells: Vec<(Slot, u64)>,
) -> Result<Vec<Grant>, ReserveRefused> {
    let answer = deduped!(conn, op, &body, ReserveRefused, |tx| {
        let slots: Vec<Slot> = cells.iter().map(|(s, _)| s.clone()).collect();
        let held = lock_caps(tx, slots.iter().cloned())
            .await
            .map_err(backend::<ReserveRefused, _>)?;
        // The chain draw is all or nothing: test every cell against what the cells before it
        // in THIS draw add, and apply only when every cell passes.
        let mut drawn: BTreeMap<&Slot, u64> = BTreeMap::new();
        for (i, ((_, amount), slot)) in cells.iter().zip(&slots).enumerate() {
            let Some(&(cap, _, used)) = held.get(slot) else {
                return Err(ReserveRefused::NoCap { cell: i as u32 });
            };
            let used = used.saturating_add(drawn.get(slot).copied().unwrap_or(0));
            if exhausted(slot.3, used, *amount, cap) {
                return Err(ReserveRefused::Exhausted { cell: i as u32 });
            }
            *drawn.entry(slot).or_default() += *amount;
        }
        for (slot, amount) in &drawn {
            tx.exec_drop(
                format!("UPDATE store_caps SET used = used + :amount WHERE {SLOT_WHERE}"),
                slot_params(slot, vec![("amount", (*amount).into())]),
            )
            .await
            .map_err(backend::<ReserveRefused, _>)?;
        }
        let mut granted = Vec::with_capacity(cells.len());
        for ((_, amount), slot) in cells.iter().zip(&slots) {
            tx.exec_drop(
                "INSERT INTO store_slices \
                 (bucket, pooled, pool, dimension, class_key, window_start, remaining) \
                 VALUES (:bucket, :pooled, :pool, :dimension, :class_key, :window_start, :amount)",
                slot_params(slot, vec![("amount", (*amount).into())]),
            )
            .await
            .map_err(backend::<ReserveRefused, _>)?;
            let slice_id = tx.last_insert_id().ok_or(ReserveRefused::Unavailable)?;
            granted.push(json!([slice_id, amount, u64::MAX]));
        }
        Ok(Value::Array(granted))
    });
    let rows: Vec<(u64, u64, u64)> =
        serde_json::from_value(answer.clone()).map_err(|_| undecodable(&answer))?;
    Ok(rows
        .into_iter()
        .map(|(slice_id, granted, valid_until_ms)| Grant {
            slice_id,
            granted,
            valid_until_ms,
        })
        .collect())
}

async fn v3_slice_release(
    conn: &mut Conn,
    op: OpId,
    body: String,
    items: Vec<(u64, u64)>,
) -> OpResult<Vec<u64>> {
    let answer = deduped!(conn, op, &body, OpRefused, |tx| {
        // Lock every named slice in id order, then refuse the whole call on one not held.
        let mut ids: Vec<u64> = items.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        let mut held: BTreeMap<u64, (Slot, u64)> = BTreeMap::new();
        for id in ids {
            type Row = (String, bool, String, u32, String, u64, u64);
            let row: Option<Row> = tx
                .exec_first(
                    "SELECT bucket, pooled, pool, dimension, class_key, window_start, \
                     remaining FROM store_slices WHERE slice_id = :id FOR UPDATE",
                    params! { "id" => id },
                )
                .await
                .map_err(backend::<OpRefused, _>)?;
            let Some((b, pd, p, d, c, w, remaining)) = row else {
                return Err(OpRefused::Failed(format!(
                    "slice_release: slice {id} is not held"
                )));
            };
            held.insert(id, ((b, pd, p, d, c, w), remaining));
        }
        // Clamp each item to what its slice has left: an item naming a slice an EARLIER item
        // of this call emptied takes back 0.
        let mut back_all = Vec::with_capacity(items.len());
        let mut by_slot: BTreeMap<Slot, u64> = BTreeMap::new();
        for (id, unspent) in &items {
            let (slot, left) = held.get_mut(id).expect("every item's slice is held");
            let back = (*unspent).min(*left);
            *left -= back;
            *by_slot.entry(slot.clone()).or_default() += back;
            back_all.push(back);
        }
        for (id, (_, left)) in &held {
            if *left == 0 {
                tx.exec_drop(
                    "DELETE FROM store_slices WHERE slice_id = :id",
                    params! { "id" => *id },
                )
                .await
            } else {
                tx.exec_drop(
                    "UPDATE store_slices SET remaining = :left WHERE slice_id = :id",
                    params! { "id" => *id, "left" => *left },
                )
                .await
            }
            .map_err(backend::<OpRefused, _>)?;
        }
        for (slot, back) in &by_slot {
            tx.exec_drop(
                format!(
                    "UPDATE store_caps SET used = used - LEAST(used, :back) WHERE {SLOT_WHERE}"
                ),
                slot_params(slot, vec![("back", (*back).into())]),
            )
            .await
            .map_err(backend::<OpRefused, _>)?;
        }
        Ok(json!(back_all))
    });
    serde_json::from_value(answer.clone()).map_err(|_| undecodable(&answer))
}

async fn v3_window_caps(
    conn: &mut Conn,
    op: OpId,
    body: String,
    caps: Vec<(Slot, u64, u64)>,
) -> Result<(), CapsRefused> {
    let _ = deduped!(conn, op, &body, CapsRefused, |tx| {
        let slots: Vec<Slot> = caps.iter().map(|(s, _, _)| s.clone()).collect();
        let stored = lock_caps(tx, slots.iter().cloned())
            .await
            .map_err(CapsRefused::Failed)?;
        // Atomic per push: find the first conflict before applying any cap.
        let mut pushed: BTreeMap<&Slot, (u64, u64)> = BTreeMap::new();
        for (index, ((_, cap, config_gen), slot)) in caps.iter().zip(&slots).enumerate() {
            let prior = pushed
                .get(slot)
                .copied()
                .or_else(|| stored.get(slot).map(|&(cap, gen, _)| (cap, gen)));
            match prior {
                Some((c, gen)) if gen == *config_gen && c != *cap => {
                    return Err(CapsRefused::CapConflict { index });
                }
                Some((_, gen)) if gen >= *config_gen => {}
                _ => {
                    pushed.insert(slot, (*cap, *config_gen));
                }
            }
        }
        for (slot, (cap, gen)) in pushed {
            tx.exec_drop(
                "INSERT INTO store_caps \
                 (bucket, pooled, pool, dimension, class_key, window_start, cap, config_gen) \
                 VALUES (:bucket, :pooled, :pool, :dimension, :class_key, :window_start, \
                         :cap, :gen) \
                 ON DUPLICATE KEY UPDATE cap = VALUES(cap), config_gen = VALUES(config_gen)",
                slot_params(slot, vec![("cap", cap.into()), ("gen", gen.into())]),
            )
            .await
            .map_err(backend::<CapsRefused, _>)?;
        }
        Ok(Value::Null)
    });
    Ok(())
}

async fn v3_heads(conn: &mut Conn) -> Result<Vec<(String, Head)>, String> {
    let rows: Vec<(String, u64)> = conn
        .query("SELECT stream, MAX(seq) FROM store_journal GROUP BY stream ORDER BY stream")
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|(s, seq)| (s, Head { seq, epoch: 0 }))
        .collect())
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

    /// Reach the server, create the schema and run the probes (1.5.5's connect, at the same
    /// moment: the load), in the driver's words when it cannot.
    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        on_conn!(self, cx, text, |c| MysqlStore::connect_step(&mut c)
            .await
            .map_err(|e| e.0))
    }

    fn add_usage_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        let cells = vec![(bucket.to_owned(), window_start, delta.clone())];
        on_conn!(self, cx, backend::<OpRefused, _>, |c| v3_add_usage_batch(
            &mut c, op, body, cells
        )
        .await)
    }

    fn add_metering_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>> {
        let body = format!("add_metering:{delta:?}");
        let deltas = vec![delta.clone()];
        on_conn!(self, cx, backend::<OpRefused, _>, |c| {
            v3_add_metering_batch(&mut c, op, body, deltas).await
        })
    }

    fn append_audit_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entry: &AuditRecord,
    ) -> Step<OpResult<()>> {
        let body = format!("append_audit:{entry:?}");
        let entries = vec![entry.clone()];
        on_conn!(self, cx, backend::<OpRefused, _>, |c| {
            v3_append_audit_batch(&mut c, op, body, entries).await
        })
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        let body = format!("append_plane_record:{record:?}");
        let record = record.to_record();
        on_conn!(self, cx, backend::<OpRefused, _>, |c| {
            v3_append_plane_record(&mut c, op, body, record).await
        })
    }

    fn append_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let (stream, records) = (stream.to_owned(), records.to_vec());
        on_conn!(self, cx, backend::<OpRefused, _>, |c| v3_append_batch(
            &mut c, op, body, stream, records
        )
        .await)
    }

    fn heads(&self, cx: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        on_conn!(self, cx, text, |c| v3_heads(&mut c).await)
    }

    fn session_put(
        &self,
        cx: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>> {
        let (node, principal) = (node.to_owned(), principal.to_owned());
        on_conn!(self, cx, text, |c| c
            .exec_drop(
                "INSERT INTO store_sessions (session, node, principal) \
                 VALUES (:session, :node, :principal) \
                 ON DUPLICATE KEY UPDATE node = VALUES(node), principal = VALUES(principal)",
                params! { "session" => session, "node" => &node, "principal" => &principal },
            )
            .await
            .map_err(|e| e.to_string()))
    }

    fn session_remove(&self, cx: &mut Op<'_>, session: u64) -> Step<Result<(), String>> {
        on_conn!(self, cx, text, |c| c
            .exec_drop(
                "DELETE FROM store_sessions WHERE session = :session",
                params! { "session" => session },
            )
            .await
            .map_err(|e| e.to_string()))
    }

    fn sessions_for(
        &self,
        cx: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        let principal = principal.to_owned();
        on_conn!(self, cx, text, |c| c
            .exec(
                "SELECT session, node FROM store_sessions WHERE principal = :principal \
                 ORDER BY session",
                params! { "principal" => &principal },
            )
            .await
            .map_err(|e| e.to_string()))
    }

    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        let (schema, key, value) = (schema.to_owned(), key.to_vec(), value.to_vec());
        on_conn!(self, cx, text, |c| {
            c
            .exec_drop(
                "INSERT INTO store_records (schema_id, rkey, value) VALUES (:schema, :rkey, :value) \
                 ON DUPLICATE KEY UPDATE value = VALUES(value)",
                params! { "schema" => &schema, "rkey" => &key, "value" => &value },
            )
            .await
            .map_err(|e| e.to_string())
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

    fn reserve<'c>(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let owned: Vec<(Slot, u64)> = cells.iter().map(|c| (slot_of(&c.key), c.amount)).collect();
        match on_conn!(self, cx, backend::<ReserveRefused, _>, |c| v3_reserve(
            &mut c, op, body, owned
        )
        .await)
        {
            Step::Ready(Ok(g)) => {
                grants.extend(g);
                Step::Ready(Ok(()))
            }
            Step::Ready(Err(e)) => Step::Ready(Err(e)),
            Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
        }
    }

    fn slice_release(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        match on_conn!(self, cx, backend::<OpRefused, _>, |c| v3_slice_release(
            &mut c, op, body, items
        )
        .await)
        {
            Step::Ready(Ok(back)) => {
                released.extend(back);
                Step::Ready(Ok(()))
            }
            Step::Ready(Err(e)) => Step::Ready(Err(e)),
            Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
        }
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
        on_conn!(self, cx, backend::<OpRefused, _>, |c| v3_add_usage_batch(
            &mut c, op, body, cells
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
        on_conn!(self, cx, backend::<OpRefused, _>, |c| {
            v3_add_metering_batch(&mut c, op, body, deltas).await
        })
    }

    fn append_audit_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>> {
        let body = format!("append_audit_batch:{entries:?}");
        let entries = entries.to_vec();
        on_conn!(self, cx, backend::<OpRefused, _>, |c| {
            v3_append_audit_batch(&mut c, op, body, entries).await
        })
    }

    fn window_caps(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        let body = format!("window_caps:{caps:?}");
        let caps: Vec<(Slot, u64, u64)> = caps
            .iter()
            .map(|c| (slot_of(&c.key), c.cap, c.config_gen))
            .collect();
        on_conn!(self, cx, backend::<CapsRefused, _>, |c| v3_window_caps(
            &mut c, op, body, caps
        )
        .await)
    }

    // ── the 1.5.5 op set (slots 0-32), each one body on the op's connection ──────────────────

    fn put_key(&self, cx: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>> {
        let key = key.clone();
        on_conn!(self, cx, store_err, |c| MysqlStore::put_key(&mut c, &key)
            .await)
    }

    fn get_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        let id = id.to_owned();
        on_conn!(self, cx, store_err, |c| MysqlStore::get_key(&mut c, &id)
            .await)
    }

    fn list_keys(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::list_keys(&mut c).await)
    }

    fn delete_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        let id = id.to_owned();
        on_conn!(self, cx, store_err, |c| MysqlStore::delete_key(&mut c, &id)
            .await)
    }

    fn scrub_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        let id = id.to_owned();
        on_conn!(self, cx, store_err, |c| MysqlStore::scrub_key(&mut c, &id)
            .await)
    }

    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::list_keys_since(
            &mut c, since
        )
        .await)
    }

    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        let bucket_id = bucket_id.to_owned();
        on_conn!(self, cx, store_err, |c| MysqlStore::get_usage(
            &mut c,
            &bucket_id,
            window_start
        )
        .await)
    }

    fn put_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        let (bucket_id, ledger) = (bucket_id.to_owned(), ledger.clone());
        on_conn!(self, cx, store_err, |c| MysqlStore::put_usage(
            &mut c,
            &bucket_id,
            window_start,
            &ledger
        )
        .await)
    }

    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::list_metering(
            &mut c, bucket
        )
        .await)
    }

    fn purge_windows_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::purge_windows_before(
            &mut c, before
        )
        .await)
    }

    fn purge_metering_before(&self, cx: &mut Op<'_>, bucket: &str) -> Step<RecordStoreResult<u64>> {
        let bucket = bucket.to_owned();
        on_conn!(self, cx, store_err, |c| MysqlStore::purge_metering_before(
            &mut c, &bucket
        )
        .await)
    }

    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let secret = secret.clone();
        on_conn!(self, cx, store_err, |c| MysqlStore::put_credential(
            &mut c, &secret
        )
        .await)
    }

    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let (key, secret) = (key.clone(), secret.clone());
        on_conn!(self, cx, store_err, |c| {
            MysqlStore::put_key_with_credential(&mut c, &key, &secret).await
        })
    }

    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        let key_id = key_id.to_owned();
        on_conn!(self, cx, store_err, |c| MysqlStore::list_credentials(
            &mut c, &key_id
        )
        .await)
    }

    fn lookup_credential_secret(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        let (kind, public_id) = (kind.to_owned(), public_id.to_owned());
        on_conn!(self, cx, store_err, |c| {
            MysqlStore::lookup_credential_secret(&mut c, &kind, &public_id).await
        })
    }

    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (id, reason) = (id.to_owned(), reason.to_owned());
        on_conn!(self, cx, store_err, |c| MysqlStore::revoke_credential(
            &mut c, &id, &reason
        )
        .await)
    }

    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::list_credentials_since(
            &mut c, since
        )
        .await)
    }

    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::list_audit(&mut c)
            .await)
    }

    fn add_denylist(
        &self,
        cx: &mut Op<'_>,
        sub: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (sub, reason) = (sub.to_owned(), reason.to_owned());
        on_conn!(self, cx, store_err, |c| MysqlStore::add_denylist(
            &mut c, &sub, &reason
        )
        .await)
    }

    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::list_denylist(&mut c)
            .await)
    }

    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        on_conn!(self, cx, store_err, |c| MysqlStore::list_audit_tail(
            &mut c, limit
        )
        .await)
    }

    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        let record = record.to_record();
        on_conn!(self, cx, store_err, |c| MysqlStore::upsert_plane_record(
            &mut c, &record
        )
        .await)
    }

    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        let (kind, id) = (kind.to_owned(), id.to_owned());
        on_conn!(self, cx, store_err, |c| MysqlStore::get_plane_record(
            &mut c, &kind, &id
        )
        .await)
    }

    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        let (kind, selector) = (kind.to_owned(), selector.to_static());
        on_conn!(self, cx, store_err, |c| MysqlStore::list_plane_records(
            &mut c, &kind, &selector
        )
        .await)
    }

    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        let kind = kind.to_owned();
        on_conn!(self, cx, store_err, |c| {
            MysqlStore::list_plane_record_parents(&mut c, &kind).await
        })
    }

    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        let kind = kind.to_owned();
        on_conn!(self, cx, store_err, |c| {
            MysqlStore::purge_plane_records_before(&mut c, &kind, before).await
        })
    }

    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (kind, id) = (kind.to_owned(), id.to_owned());
        on_conn!(self, cx, store_err, |c| MysqlStore::delete_plane_record(
            &mut c, &kind, &id
        )
        .await)
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
        on_conn!(self, cx, store_err, |c| MysqlStore::redeem_plane_token(
            &mut c, &kind, &token, expires_at, now
        )
        .await)
    }

    fn plane_token_live(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        // Answered without the server when the deadline has passed, as 1.5.5 did (no connection).
        if now > expires_at {
            return Step::Ready(Ok(false));
        }
        let (kind, token) = (kind.to_owned(), token.to_owned());
        on_conn!(self, cx, store_err, |c| MysqlStore::plane_token_live(
            &mut c, &kind, &token, expires_at, now
        )
        .await)
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
