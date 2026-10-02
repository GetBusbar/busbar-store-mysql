// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE V3 DOOR over [`MysqlStore`]: `store_door!` and the slots the store v3 table adds to
//! the 1.5.5 op set ([`StoreSlots`]): the `op_id`-carrying writes, the journal, sessions, the
//! kernel's records, the money slots and `window_caps`.
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

use std::collections::BTreeMap;

use mysql::prelude::*;
use mysql::{params, Params, Transaction, TxOpts};
use serde_json::{json, Value};

use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, OpResult, ReserveRefused,
    StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{AuditRecord, MeteringDelta, PlaneRecordRef, UsageDelta};

use crate::{crate_now, MysqlStore, NAME};

busbar_contract::store_door!(MysqlStore, NAME, env!("CARGO_PKG_VERSION"), 64);

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
fn slot_params(slot: &Slot, extra: Vec<(&str, mysql::Value)>) -> Params {
    let (bucket, pooled, pool, dimension, class_key, window_start) = slot;
    let mut p: Vec<(String, mysql::Value)> = vec![
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

/// An answer that does not decode as its op's shape: the stored row is not this op's.
fn undecodable<E: Refusal>(answer: &Value) -> E {
    E::backend(format!(
        "store_ops holds an answer this op cannot read: {answer}"
    ))
}

impl MysqlStore {
    /// Run one `op_id`-carrying write (module doc, DEDUPE): a replay answers the original answer,
    /// a conflict applies nothing, and a new op runs `apply` in the op's transaction and is
    /// recorded only if it applied.
    fn deduped<E: Refusal>(
        &self,
        op: OpId,
        body: &str,
        apply: impl FnOnce(&mut Transaction<'_>) -> Result<Value, E>,
    ) -> Result<Value, E> {
        let mut conn = self.pool.get_conn().map_err(backend::<E, _>)?;
        let mut apply = Some(apply);
        // The claim can find a row a concurrent sweep or rollback removes before it is read; the
        // op is then new again, so the claim is retried (bounded).
        for _ in 0..3 {
            let mut tx = conn
                .start_transaction(TxOpts::default())
                .map_err(backend::<E, _>)?;
            match tx.exec_drop(
                "INSERT INTO store_ops (op_id, recorded_at, body, answer) \
                 VALUES (:op, :at, :body, '')",
                params! { "op" => &op.0[..], "at" => crate_now(), "body" => body.as_bytes() },
            ) {
                Ok(()) => {
                    let apply = apply.take().expect("an op applies at most once");
                    let answer = apply(&mut tx)?;
                    tx.exec_drop(
                        "UPDATE store_ops SET answer = :answer WHERE op_id = :op",
                        params! { "answer" => answer.to_string(), "op" => &op.0[..] },
                    )
                    .map_err(backend::<E, _>)?;
                    tx.commit().map_err(backend::<E, _>)?;
                    if op.counter().is_multiple_of(OPS_SWEEP_EVERY) {
                        // Best effort: a sweep that fails is retried by the next one.
                        let _ = conn.exec_drop(
                            "DELETE FROM store_ops WHERE recorded_at < :cut LIMIT 1000",
                            params! { "cut" => crate_now().saturating_sub(OP_ID_RETENTION_SECS) },
                        );
                    }
                    return Ok(answer);
                }
                // ER_DUP_ENTRY: the op is recorded (the insert waited for its writer to commit).
                Err(mysql::Error::MySqlError(e)) if e.code == 1062 => {
                    tx.rollback().map_err(backend::<E, _>)?;
                    let row: Option<(Vec<u8>, Vec<u8>)> = conn
                        .exec_first(
                            "SELECT body, answer FROM store_ops WHERE op_id = :op",
                            params! { "op" => &op.0[..] },
                        )
                        .map_err(backend::<E, _>)?;
                    match row {
                        Some((b, _)) if b != body.as_bytes() => return Err(E::conflict()),
                        Some((_, a)) => return serde_json::from_slice(&a).map_err(backend::<E, _>),
                        None => continue,
                    }
                }
                Err(e) => return Err(backend(e)),
            }
        }
        Err(E::backend(
            "store_ops: the op's row kept vanishing between its claim and its read".into(),
        ))
    }

    /// A deduped write whose answer is "done".
    fn done_op(
        &self,
        op: OpId,
        body: &str,
        apply: impl FnOnce(&mut Transaction<'_>) -> OpResult<()>,
    ) -> OpResult<()> {
        self.deduped(op, body, |tx| apply(tx).map(|()| Value::Null))
            .map(drop)
    }

    /// The current cap and drawn total of each slot in `slots` that has a cap, its row locked; the
    /// rows are locked in key order.
    fn lock_caps(
        tx: &mut Transaction<'_>,
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
                .map_err(|e| e.to_string())?;
            if let Some(r) = row {
                held.insert(k, r);
            }
        }
        Ok(held)
    }
}

impl StoreSlots for MysqlStore {
    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn open(settings: &[u8]) -> Result<Self, String> {
        Self::from_settings(settings)
    }

    fn add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        self.done_op(op, &body, |tx| {
            Self::add_usage_on(tx, bucket, window_start, delta).map_err(failed)
        })
    }

    fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        self.done_op(op, &body, |tx| {
            Self::add_metering_on(tx, delta).map_err(failed)
        })
    }

    fn append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        self.done_op(op, &body, |tx| {
            Self::append_audit_on(tx, entry).map_err(failed)
        })
    }

    fn append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()> {
        let body = format!("append_plane_record:{record:?}");
        self.done_op(op, &body, |tx| {
            Self::append_plane_record_on(tx, record).map_err(failed)
        })
    }

    fn append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let answer = self.deduped(op, &body, |tx| {
            let last: Option<u64> = tx
                .exec_first(
                    "SELECT seq FROM store_journal WHERE stream = :stream \
                     ORDER BY seq DESC LIMIT 1 FOR UPDATE",
                    params! { "stream" => stream },
                )
                .map_err(backend::<OpRefused, _>)?;
            let first = last.unwrap_or(0) + 1;
            tx.exec_batch(
                "INSERT INTO store_journal (stream, seq, record) VALUES (:stream, :seq, :record)",
                records.iter().zip(first..).map(|(r, seq)| {
                    params! { "stream" => stream, "seq" => seq, "record" => r.as_slice() }
                }),
            )
            .map_err(backend::<OpRefused, _>)?;
            Ok(json!([first - 1 + records.len() as u64, 0]))
        })?;
        match serde_json::from_value::<(u64, u64)>(answer.clone()) {
            Ok((seq, epoch)) => Ok(Head { seq, epoch }),
            Err(_) => Err(undecodable(&answer)),
        }
    }

    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        let mut conn = self.pool.get_conn().map_err(|e| e.to_string())?;
        let rows: Vec<(String, u64)> = conn
            .query("SELECT stream, MAX(seq) FROM store_journal GROUP BY stream ORDER BY stream")
            .map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|(s, seq)| (s, Head { seq, epoch: 0 }))
            .collect())
    }

    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String> {
        let mut conn = self.pool.get_conn().map_err(|e| e.to_string())?;
        conn.exec_drop(
            "INSERT INTO store_sessions (session, node, principal) \
             VALUES (:session, :node, :principal) \
             ON DUPLICATE KEY UPDATE node = VALUES(node), principal = VALUES(principal)",
            params! { "session" => session, "node" => node, "principal" => principal },
        )
        .map_err(|e| e.to_string())
    }

    fn session_remove(&self, session: u64) -> Result<(), String> {
        let mut conn = self.pool.get_conn().map_err(|e| e.to_string())?;
        conn.exec_drop(
            "DELETE FROM store_sessions WHERE session = :session",
            params! { "session" => session },
        )
        .map_err(|e| e.to_string())
    }

    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        let mut conn = self.pool.get_conn().map_err(|e| e.to_string())?;
        conn.exec(
            "SELECT session, node FROM store_sessions WHERE principal = :principal \
             ORDER BY session",
            params! { "principal" => principal },
        )
        .map_err(|e| e.to_string())
    }

    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut conn = self.pool.get_conn().map_err(|e| e.to_string())?;
        conn.exec_drop(
            "INSERT INTO store_records (schema_id, rkey, value) VALUES (:schema, :rkey, :value) \
             ON DUPLICATE KEY UPDATE value = VALUES(value)",
            params! { "schema" => schema, "rkey" => key, "value" => value },
        )
        .map_err(|e| e.to_string())
    }

    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        let mut conn = self.pool.get_conn().map_err(|e| e.to_string())?;
        let v: Option<Vec<u8>> = conn
            .exec_first(
                "SELECT value FROM store_records WHERE schema_id = :schema AND rkey = :rkey",
                params! { "schema" => schema, "rkey" => key },
            )
            .map_err(|e| e.to_string())?;
        v.map(record).transpose()
    }

    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut conn = self.pool.get_conn().map_err(|e| e.to_string())?;
        // A key-ordered RANGE over the primary key: `[prefix, the prefix's successor)`; a prefix
        // with no successor (empty, or every byte 0xFF) has no upper bound.
        let rows: Vec<(Vec<u8>, Vec<u8>)> = match prefix_end(prefix) {
            Some(end) => conn.exec(
                "SELECT rkey, value FROM store_records WHERE schema_id = :schema \
                 AND rkey >= :start AND rkey < :end ORDER BY rkey LIMIT :limit",
                params! { "schema" => schema, "start" => prefix, "end" => end, "limit" => limit },
            ),
            None => conn.exec(
                "SELECT rkey, value FROM store_records WHERE schema_id = :schema \
                 AND rkey >= :start ORDER BY rkey LIMIT :limit",
                params! { "schema" => schema, "start" => prefix, "limit" => limit },
            ),
        }
        .map_err(|e| e.to_string())?;
        rows.into_iter().map(|(k, v)| Ok((k, record(v)?))).collect()
    }

    fn reserve<'c>(
        &self,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let answer = self.deduped(op, &body, |tx| {
            let slots: Vec<Slot> = cells.iter().map(|c| slot_of(&c.key)).collect();
            let held = Self::lock_caps(tx, slots.iter().cloned())
                .map_err(backend::<ReserveRefused, _>)?;
            // The chain draw is all or nothing: test every cell against what the cells before it
            // in THIS draw add, and apply only when every cell passes.
            let mut drawn: BTreeMap<&Slot, u64> = BTreeMap::new();
            for (i, (c, slot)) in cells.iter().zip(&slots).enumerate() {
                let Some(&(cap, _, used)) = held.get(slot) else {
                    return Err(ReserveRefused::NoCap { cell: i as u32 });
                };
                let used = used.saturating_add(drawn.get(slot).copied().unwrap_or(0));
                if exhausted(slot.3, used, c.amount, cap) {
                    return Err(ReserveRefused::Exhausted { cell: i as u32 });
                }
                *drawn.entry(slot).or_default() += c.amount;
            }
            for (slot, amount) in &drawn {
                tx.exec_drop(
                    format!("UPDATE store_caps SET used = used + :amount WHERE {SLOT_WHERE}"),
                    slot_params(slot, vec![("amount", (*amount).into())]),
                )
                .map_err(backend::<ReserveRefused, _>)?;
            }
            let mut granted = Vec::with_capacity(cells.len());
            for (c, slot) in cells.iter().zip(&slots) {
                tx.exec_drop(
                    "INSERT INTO store_slices \
                     (bucket, pooled, pool, dimension, class_key, window_start, remaining) \
                     VALUES (:bucket, :pooled, :pool, :dimension, :class_key, :window_start, :amount)",
                    slot_params(slot, vec![("amount", c.amount.into())]),
                )
                .map_err(backend::<ReserveRefused, _>)?;
                let slice_id = tx
                    .last_insert_id()
                    .ok_or(ReserveRefused::Unavailable)?;
                granted.push(json!([slice_id, c.amount, u64::MAX]));
            }
            Ok(Value::Array(granted))
        })?;
        let rows: Vec<(u64, u64, u64)> =
            serde_json::from_value(answer.clone()).map_err(|_| undecodable(&answer))?;
        grants.extend(
            rows.into_iter()
                .map(|(slice_id, granted, valid_until_ms)| Grant {
                    slice_id,
                    granted,
                    valid_until_ms,
                }),
        );
        Ok(())
    }

    fn slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let answer = self.deduped(op, &body, |tx| {
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
                } else {
                    tx.exec_drop(
                        "UPDATE store_slices SET remaining = :left WHERE slice_id = :id",
                        params! { "id" => *id, "left" => *left },
                    )
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
                .map_err(backend::<OpRefused, _>)?;
            }
            Ok(json!(back_all))
        })?;
        let amounts: Vec<u64> =
            serde_json::from_value(answer.clone()).map_err(|_| undecodable(&answer))?;
        released.extend(amounts);
        Ok(())
    }

    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        let body = format!("add_usage_batch:{cells:?}");
        self.done_op(op, &body, |tx| {
            for (bucket, window, delta) in cells {
                Self::add_usage_on(tx, bucket, *window, delta).map_err(failed)?;
            }
            Ok(())
        })
    }

    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.done_op(op, &body, |tx| {
            for d in deltas {
                Self::add_metering_on(tx, d).map_err(failed)?;
            }
            Ok(())
        })
    }

    fn append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        let body = format!("append_audit_batch:{entries:?}");
        // One transaction: a fork anywhere in the batch rolls back every record before it.
        self.done_op(op, &body, |tx| {
            for e in entries {
                Self::append_audit_on(tx, e).map_err(failed)?;
            }
            Ok(())
        })
    }

    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        let body = format!("window_caps:{caps:?}");
        self.deduped(op, &body, |tx| {
            let slots: Vec<Slot> = caps.iter().map(|c| slot_of(&c.key)).collect();
            let stored = Self::lock_caps(tx, slots.iter().cloned()).map_err(CapsRefused::Failed)?;
            // Atomic per push: find the first conflict before applying any cap.
            let mut pushed: BTreeMap<&Slot, (u64, u64)> = BTreeMap::new();
            for (index, (c, slot)) in caps.iter().zip(&slots).enumerate() {
                let prior = pushed
                    .get(slot)
                    .copied()
                    .or_else(|| stored.get(slot).map(|&(cap, gen, _)| (cap, gen)));
                match prior {
                    Some((cap, gen)) if gen == c.config_gen && cap != c.cap => {
                        return Err(CapsRefused::CapConflict { index });
                    }
                    Some((_, gen)) if gen >= c.config_gen => {}
                    _ => {
                        pushed.insert(slot, (c.cap, c.config_gen));
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
                .map_err(backend::<CapsRefused, _>)?;
            }
            Ok(Value::Null)
        })
        .map(drop)
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
