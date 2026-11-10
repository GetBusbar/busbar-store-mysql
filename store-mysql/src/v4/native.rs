// SPDX-License-Identifier: Apache-2.0
//! Native InnoDB transactions; every locking prestate read survives until COMMIT.
use super::backend::{Own, OwnSecret};
use super::schema;
use crate::mysqlwire::Conn;
use busbar_contract::abi::sdk::store::v4::backend::Committed;
use busbar_contract::abi::sdk::store::v4::retirement::Horizon;
use busbar_contract::persistence::{control, *};
use mysql_common::params;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Instant;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Failure>;
const RECEIPT_PREFIX: &[u8; 8] = b"BSMR1\0\0\0";
const FETCH_ROWS: usize = 128;

fn hash_parts(namespace: [u8; 16], key: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(namespace);
    digest.update(key);
    digest.finalize().into()
}
fn hash(address: &Address) -> [u8; 32] {
    hash_parts(address.namespace, &address.key)
}
fn address(namespace: NamespaceId, key: &[u8]) -> Address {
    Address {
        namespace: namespace.0,
        key: key.to_vec(),
    }
}
fn generation_address(namespace: [u8; 16]) -> Address {
    address(control::GENERATION_NAMESPACE, &namespace)
}
fn bytes(value: &OwnSecret) -> &[u8] {
    value.expose_own(&Own::here())
}
fn generation(value: Option<&[u8]>) -> Result<u64> {
    match value {
        None => Ok(0),
        Some(value) => {
            let number = u64::from_le_bytes(value.try_into().map_err(|_| Failure::Corrupt)?);
            if number == 0 {
                Err(Failure::Corrupt)
            } else {
                Ok(number)
            }
        }
    }
}

/// Empty suffix is a consistent read. Callers use explicit shared/exclusive locks
/// for admission; full stored keys are always checked even though the index is hashed.
async fn get(conn: &mut Conn, at: &Address, lock: &str) -> Result<Option<OwnSecret>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn.exec_first(format!("SELECT raw_key,value FROM busbar_v4_records WHERE namespace=:ns AND address_hash=:hash {lock}"), params! {"ns"=>at.namespace.as_slice(),"hash"=>hash(at).as_slice()}).await.map_err(|_|Failure::Unavailable)?;
    match row {
        None => Ok(None),
        Some((key, value)) => {
            let value = OwnSecret::held(value);
            if key != at.key {
                return Err(Failure::Corrupt);
            }
            Ok(Some(value))
        }
    }
}

pub(super) async fn admission_marker(conn: &mut Conn) -> Result<Option<OwnSecret>> {
    get(
        conn,
        &Address {
            namespace: lifecycle::ADMISSION_NAMESPACE,
            key: lifecycle::ADMISSION_KEY.to_vec(),
        },
        "",
    )
    .await
}
async fn lock_locator(conn: &mut Conn, at: &Address, exclusive: bool) -> Result<()> {
    let lock = if exclusive {
        "FOR UPDATE"
    } else {
        "LOCK IN SHARE MODE"
    };
    let _:Option<Vec<u8>>=conn.exec_first(format!("SELECT address_hash FROM busbar_v4_records WHERE namespace=:ns AND address_hash=:hash {lock}"),params!{"ns"=>at.namespace.as_slice(),"hash"=>hash(at).as_slice()}).await.map_err(|_|Failure::Unknown)?;
    Ok(())
}
async fn put(conn: &mut Conn, at: &Address, value: &[u8]) -> Result<()> {
    conn.exec_drop("INSERT INTO busbar_v4_records(namespace,address_hash,raw_key,value) VALUES(:ns,:hash,:key,:value) ON DUPLICATE KEY UPDATE value=VALUES(value)",params!{"ns"=>at.namespace.as_slice(),"hash"=>hash(at).as_slice(),"key"=>&at.key,"value"=>value}).await.map_err(|_|Failure::Unknown)
}
async fn delete(conn: &mut Conn, at: &Address) -> Result<()> {
    conn.exec_drop(
        "DELETE FROM busbar_v4_records WHERE namespace=:ns AND address_hash=:hash",
        params! {"ns"=>at.namespace.as_slice(),"hash"=>hash(at).as_slice()},
    )
    .await
    .map_err(|_| Failure::Unknown)
}

pub(super) async fn clock(conn: &mut Conn, info: BackendInfo) -> Result<ClockObservation> {
    // UTC_TIMESTAMP is statement-time; no caller wall clock enters the decision.
    let now: Option<u64> = conn
        .query_first("SELECT TIMESTAMPDIFF(SECOND,'1970-01-01 00:00:00',UTC_TIMESTAMP())")
        .await
        .map_err(|_| Failure::Unavailable)?;
    Ok(ClockObservation {
        authority: info.clock_authority,
        unix_seconds: now.ok_or(Failure::Corrupt)?,
    })
}

pub(super) async fn read(
    conn: &mut Conn,
    info: BackendInfo,
    request: &Read,
) -> Result<ReadResult<Own>> {
    if request.dataset != info.dataset {
        return Err(Failure::Refused);
    }
    let mut tx = conn
        .start_transaction()
        .await
        .map_err(|_| Failure::Unavailable)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(request.addresses.len())
        .map_err(|_| Failure::Overloaded)?;
    // Shared row and absence/gap locks make every observed value current at the
    // later clock sample; a preceding MVCC snapshot cannot prove that relationship.
    for at in &request.addresses {
        values.push(get(&mut tx, at, "LOCK IN SHARE MODE").await?);
    }
    let observed_at = clock(&mut tx, info).await?;
    if request
        .time
        .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
    {
        tx.rollback().await.map_err(|_| Failure::Unavailable)?;
        return Ok(ReadResult::TimeGuardFailed { observed_at });
    }
    tx.commit().await.map_err(|_| Failure::Unavailable)?;
    Ok(ReadResult::Values {
        observed_at,
        values,
    })
}

/// Hash-index pagination is independent of raw-key order. It visits the entire
/// matching namespace under one snapshot and keeps only the lowest page+lookahead.
/// MySQL's LONGBLOB ORDER BY/max_sort_length never determines raw-key ordering.
async fn key_batch(
    conn: &mut Conn,
    namespace: [u8; 16],
    after: Option<&[u8]>,
    lock: &str,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let (condition, cursor) = match after {
        Some(hash) => ("AND address_hash>:after", hash),
        None => ("", &[][..]),
    };
    // Inspect only fixed-size hashes/lengths first. This prevents an internal
    // batch of individually legal large keys from overflowing the wire's existing
    // response budget. The byte target only changes batching: even a larger first
    // key is fetched, so this adds no key-size or range-size admission cap.
    let lengths:Vec<(Vec<u8>,u64)>=conn.exec(format!("SELECT address_hash,OCTET_LENGTH(raw_key) FROM busbar_v4_records WHERE namespace=:ns {condition} ORDER BY address_hash LIMIT {FETCH_ROWS} {lock}"),params!{"ns"=>namespace.as_slice(),"after"=>cursor}).await.map_err(|_|Failure::Unavailable)?;
    if lengths.is_empty() {
        return Ok(Vec::new());
    }
    let mut fetch = 0usize;
    let mut size = 0u64;
    for (_, length) in lengths {
        let next = size.saturating_add(length).saturating_add(256);
        if fetch != 0 && next > 8 * 1024 * 1024 {
            break;
        }
        fetch += 1;
        size = next;
    }
    conn.exec(format!("SELECT address_hash,raw_key FROM busbar_v4_records WHERE namespace=:ns {condition} ORDER BY address_hash LIMIT {fetch} {lock}"),params!{"ns"=>namespace.as_slice(),"after"=>cursor}).await.map_err(|_|Failure::Unavailable)
}
fn check_key(namespace: [u8; 16], digest: &[u8], key: &[u8]) -> Result<()> {
    if hash_parts(namespace, key).as_slice() != digest {
        return Err(Failure::Corrupt);
    }
    Ok(())
}

fn select_key(
    selected: &mut BTreeSet<Vec<u8>>,
    key: Vec<u8>,
    prefix: &[u8],
    after: Option<&[u8]>,
    keep: usize,
) {
    if key.starts_with(prefix) && after.is_none_or(|after| key.as_slice() > after) {
        selected.insert(key);
        if selected.len() > keep {
            selected.pop_last();
        }
    }
}

pub(super) async fn scan(conn: &mut Conn, info: BackendInfo, request: &Scan) -> Result<Page<Own>> {
    if request.dataset != info.dataset
        || request.max_items == 0
        || request.max_bytes == 0
        || (request.after.is_some() && request.generation.is_none() && !request.allow_change)
    {
        return Err(Failure::Refused);
    }
    let keep = request
        .max_items
        .checked_add(1)
        .ok_or(Failure::Overloaded)?;
    let mut tx = conn
        .start_snapshot()
        .await
        .map_err(|_| Failure::Unavailable)?;
    let gen_value = get(&mut tx, &generation_address(request.namespace.0), "").await?;
    let current = generation(gen_value.as_ref().map(bytes))?;
    if !request.allow_change
        && request
            .generation
            .is_some_and(|expected| expected != current)
    {
        return Err(Failure::StaleScan);
    }
    let mut selected = BTreeSet::new();
    let mut cursor = None;
    loop {
        let batch = key_batch(&mut tx, request.namespace.0, cursor.as_deref(), "").await?;
        if batch.is_empty() {
            break;
        }
        for (digest, key) in batch {
            check_key(request.namespace.0, &digest, &key)?;
            cursor = Some(digest);
            select_key(
                &mut selected,
                key,
                &request.prefix,
                request.after.as_deref(),
                keep,
            );
        }
    }
    let mut rows = Vec::new();
    let mut used = 0usize;
    let mut more = false;
    for key in selected {
        if rows.len() == request.max_items {
            more = true;
            break;
        }
        let at = Address {
            namespace: request.namespace.0,
            key,
        };
        let value = get(&mut tx, &at, "").await?.ok_or(Failure::Corrupt)?;
        let size = at
            .key
            .len()
            .checked_add(bytes(&value).len())
            .ok_or(Failure::Overloaded)?;
        let total = used.checked_add(size).ok_or(Failure::Overloaded)?;
        if total > request.max_bytes {
            if rows.is_empty() {
                return Err(Failure::Overloaded);
            }
            more = true;
            break;
        }
        used = total;
        rows.push((at, value));
    }
    let next = if more {
        rows.last().map(|(at, _)| at.key.clone())
    } else {
        None
    };
    tx.commit().await.map_err(|_| Failure::Unavailable)?;
    Ok(Page {
        generation: current,
        rows,
        next,
    })
}

struct Receipt {
    fingerprint: [u8; 32],
    writer_epoch: u64,
    execution_epoch: u64,
    time: u64,
    result: OwnSecret,
}
fn decode_receipt(payload: Vec<u8>) -> Result<Receipt> {
    let mut payload = Zeroizing::new(payload);
    if payload.len() < 64 || &payload[..8] != RECEIPT_PREFIX {
        return Err(Failure::Corrupt);
    }
    let fingerprint = payload[8..40].try_into().map_err(|_| Failure::Corrupt)?;
    let writer_epoch =
        u64::from_le_bytes(payload[40..48].try_into().map_err(|_| Failure::Corrupt)?);
    let execution_epoch =
        u64::from_le_bytes(payload[48..56].try_into().map_err(|_| Failure::Corrupt)?);
    let time = u64::from_le_bytes(payload[56..64].try_into().map_err(|_| Failure::Corrupt)?);
    if writer_epoch == 0 || execution_epoch == 0 {
        return Err(Failure::Corrupt);
    }
    let result = OwnSecret::held(payload.split_off(64));
    Ok(Receipt {
        fingerprint,
        writer_epoch,
        execution_epoch,
        time,
        result,
    })
}
fn receipt_bytes(request: &PreparedCandidate<Own>, time: u64) -> Result<Zeroizing<Vec<u8>>> {
    let candidate = request.candidate();
    let size = 64usize
        .checked_add(bytes(&candidate.result).len())
        .ok_or(Failure::Overloaded)?;
    let mut payload = Zeroizing::new(Vec::new());
    payload
        .try_reserve_exact(size)
        .map_err(|_| Failure::Overloaded)?;
    payload.extend_from_slice(RECEIPT_PREFIX);
    payload.extend_from_slice(&request.fingerprint());
    payload.extend_from_slice(&candidate.id.writer_epoch.to_le_bytes());
    payload.extend_from_slice(&candidate.id.execution_epoch.to_le_bytes());
    payload.extend_from_slice(&time.to_le_bytes());
    payload.extend_from_slice(bytes(&candidate.result));
    Ok(payload)
}

/// Verify the original physical Applied receipt and current exact checkpoint in
/// one transaction. The plugin does not interpret core checkpoint contents.
pub(super) async fn finish_upgrade(
    conn: &mut Conn,
    row: &crate::legacy::lifecycle::Upgrade,
    proof: &lifecycle::ActivationReceipt<Own>,
) -> Result<crate::legacy::lifecycle::Upgrade> {
    if proof.attempt.dataset.0 != row.target {
        return Err(Failure::Refused);
    }
    let mut hash = Sha256::new();
    hash.update(b"mysql.native.activation.receipt.v1\0");
    hash.update([u8::from(
        proof.phase == lifecycle::CompletionPhase::Complete,
    )]);
    hash.update(proof.attempt.dataset.0);
    hash.update(proof.attempt.writer_epoch.to_le_bytes());
    hash.update(proof.attempt.writer);
    hash.update(proof.attempt.execution_epoch.to_le_bytes());
    hash.update(proof.attempt.operation);
    hash.update(proof.candidate_fingerprint);
    hash.update((proof.original_result.expose_own(&Own::here()).len() as u64).to_le_bytes());
    hash.update(proof.original_result.expose_own(&Own::here()));
    hash.update(proof.checkpoint_address.namespace);
    hash.update((proof.checkpoint_address.key.len() as u64).to_le_bytes());
    hash.update(&proof.checkpoint_address.key);
    hash.update(proof.checkpoint_value_digest);
    let selection = crate::legacy::lifecycle::Selection {
        receipt: hash.finalize().into(),
        checkpoint: proof.checkpoint_value_digest,
    };
    // This exact proof was verified against the original native receipt and
    // atomic phase marker before selection. A later legitimate Complete marker
    // must not invalidate replay of the original Activation acknowledgement.
    let prior = if proof.phase == lifecycle::CompletionPhase::Activation {
        &row.activation
    } else {
        &row.completed
    };
    if let Some(prior) = prior {
        return if prior == &selection {
            Ok(row.clone())
        } else {
            Err(Failure::Refused)
        };
    }
    let mut tx = conn
        .start_transaction()
        .await
        .map_err(|_| Failure::Unavailable)?;
    let checked = async {
    let payload:Option<Vec<u8>>=tx.exec_first("SELECT payload FROM busbar_v4_receipts WHERE writer=:writer AND operation=:operation LOCK IN SHARE MODE",params!{"writer"=>proof.attempt.writer.as_slice(),"operation"=>proof.attempt.operation.as_slice()}).await.map_err(|_|Failure::Unavailable)?;
    let payload = Zeroizing::new(payload.ok_or(Failure::Refused)?);
    let receipt = decode_receipt(payload.to_vec())?;
    if receipt.fingerprint != proof.candidate_fingerprint
        || receipt.writer_epoch != proof.attempt.writer_epoch
        || receipt.execution_epoch != proof.attempt.execution_epoch
        || bytes(&receipt.result) != proof.original_result.expose_own(&Own::here()).as_slice()
    {
        return Err(Failure::Refused);
    }
    let checkpoint = get(&mut tx, &proof.checkpoint_address, "LOCK IN SHARE MODE")
        .await?
        .ok_or(Failure::Refused)?;
    let checkpoint_digest: [u8; 32] = Sha256::digest(bytes(&checkpoint)).into();
    if checkpoint_digest != proof.checkpoint_value_digest {
        return Err(Failure::Refused);
    }
    let marker = get(
        &mut tx,
        &lifecycle::completion_marker_address(row.target),
        "LOCK IN SHARE MODE",
    )
    .await?
    .ok_or(Failure::Refused)?;
    let marker = lifecycle::codec::decode_completion_marker(
        bytes(&marker),
        lifecycle::Bounds {
            items: 1,
            bytes: u32::try_from(bytes(&marker).len()).map_err(|_| Failure::Corrupt)?,
        },
    )
    .map_err(|_| Failure::Corrupt)?;
    let anchor = Sha256::digest(&row.native_identity);
    if marker.version != lifecycle::VERSION
        || marker.phase != proof.phase
        || marker.upgrade != row.target
        || marker.source.0.as_slice() != &anchor[..16]
        || marker.target.0 != row.target
        || marker.checkpoint_address != proof.checkpoint_address
        || marker.checkpoint_value_digest != checkpoint_digest
    {
        return Err(Failure::Refused);
    }
    let next = crate::legacy::lifecycle::select(
        &mut tx,
        row,
        selection,
        proof.phase == lifecycle::CompletionPhase::Complete,
    )
    .await
    .map_err(|_| Failure::Unknown)?;
    Ok(next)
    }.await;
    match checked {
        Ok(next) => {
            tx.commit().await.map_err(|_| Failure::Unknown)?;
            Ok(next)
        }
        Err(error) => {
            tx.rollback().await.map_err(|_| Failure::Unknown)?;
            Err(error)
        }
    }
}
fn changes_control(candidate: &Candidate<Own>, key: &[u8]) -> bool {
    candidate.mutations.iter().any(|m| matches!(m,Mutation::Put{address,..} if address.namespace==control::NAMESPACE.0 && address.key==key))
}

pub(super) async fn commit(
    conn: &mut Conn,
    info: BackendInfo,
    request: &PreparedCandidate<Own>,
) -> Result<Committed<Own>> {
    let candidate = request.candidate();
    if candidate.validate().is_err() || candidate.id.dataset != info.dataset {
        return Err(Failure::Refused);
    }
    schema::posture(conn).await?;
    // No write has happened yet; a failed START TRANSACTION is not indeterminate.
    let mut tx = conn
        .start_transaction()
        .await
        .map_err(|_| Failure::Unavailable)?;
    let result = apply(&mut tx, info, request).await;
    match result {
        Ok(answer) => {
            tx.commit().await.map_err(|_| Failure::Unknown)?;
            Ok(answer)
        }
        Err(failure) => {
            // Explicit successful rollback is the only native proof of no effects.
            tx.rollback().await.map_err(|_| Failure::Unknown)?;
            Err(
                if matches!(failure, Failure::Unknown | Failure::Unavailable) {
                    Failure::Refused
                } else {
                    failure
                },
            )
        }
    }
}

async fn apply(
    conn: &mut Conn,
    info: BackendInfo,
    request: &PreparedCandidate<Own>,
) -> Result<Committed<Own>> {
    let candidate = request.candidate();
    let id = candidate.id;
    // Admission locks precede receipt lookup, but carry no authority verdict.
    // In particular, a retirement must not hold a missing-receipt gap lock while
    // waiting for a prior writer's shared authority lock: that writer still needs
    // to insert its receipt. Only locator hashes are read here; full-key/content
    // checks and all authority validation remain after matching receipt replay.
    let bootstrap = control::initialization(candidate, info.dataset);
    let root_at = address(control::NAMESPACE, control::DATASET_KEY);
    let root_exclusive = bootstrap || changes_control(candidate, control::DATASET_KEY);
    lock_locator(conn, &root_at, root_exclusive).await?;
    let mut writer_locks = BTreeMap::from([(id.writer, bootstrap)]);
    for mutation in &candidate.mutations {
        if let Mutation::Put { address, .. } = mutation {
            if address.namespace == control::NAMESPACE.0 {
                if let Some(control::Key::Writer(writer)) = control::Key::decode(&address.key) {
                    writer_locks.insert(writer, true);
                }
            }
        }
    }
    for (writer, exclusive) in writer_locks {
        lock_locator(
            conn,
            &address(control::NAMESPACE, &control::writer_key(writer)),
            exclusive,
        )
        .await?;
    }
    // Receipt comes before fences, time, predicates and any business-state reads.
    let receipt:Option<Vec<u8>>=conn.exec_first("SELECT payload FROM busbar_v4_receipts WHERE writer=:writer AND operation=:operation FOR UPDATE",params!{"writer"=>id.writer.as_slice(),"operation"=>id.operation.as_slice()}).await.map_err(|_|Failure::Unknown)?;
    if let Some(payload) = receipt {
        let receipt = decode_receipt(payload)?;
        let decision = if receipt.fingerprint == request.fingerprint() {
            if receipt.writer_epoch != id.writer_epoch
                || receipt.execution_epoch != id.execution_epoch
            {
                return Err(Failure::Corrupt);
            }
            Decision::Applied(receipt.result)
        } else {
            Decision::OpIdConflict
        };
        return Ok(Committed {
            observed_at: ClockObservation {
                authority: info.clock_authority,
                unix_seconds: receipt.time,
            },
            decision,
        });
    }
    let writer_at = address(control::NAMESPACE, &control::writer_key(id.writer));
    let root_lock = if bootstrap || changes_control(candidate, control::DATASET_KEY) {
        "FOR UPDATE"
    } else {
        "LOCK IN SHARE MODE"
    };
    let root = get(conn, &root_at, root_lock).await?;
    let writer_lock = if bootstrap || changes_control(candidate, &writer_at.key) {
        "FOR UPDATE"
    } else {
        "LOCK IN SHARE MODE"
    };
    let writer = get(conn, &writer_at, writer_lock).await?;
    if bootstrap {
        let any_record: Option<Vec<u8>> = conn
            .query_first("SELECT address_hash FROM busbar_v4_records LIMIT 1 FOR UPDATE")
            .await
            .map_err(|_| Failure::Unknown)?;
        let any_receipt: Option<Vec<u8>> = conn
            .query_first("SELECT writer FROM busbar_v4_receipts LIMIT 1 FOR UPDATE")
            .await
            .map_err(|_| Failure::Unknown)?;
        if any_record.is_some() || any_receipt.is_some() || root.is_some() || writer.is_some() {
            return Err(Failure::Refused);
        }
    } else {
        let root = control::Dataset::decode(bytes(root.as_ref().ok_or(Failure::Refused)?))
            .ok_or(Failure::Corrupt)?;
        let writer = control::Writer::decode(bytes(writer.as_ref().ok_or(Failure::Refused)?))
            .ok_or(Failure::Corrupt)?;
        if root.id != info.dataset {
            return Err(Failure::Corrupt);
        }
        if root.writer_epoch != id.writer_epoch || !writer.admits(id.execution_epoch) {
            return Ok(Committed {
                observed_at: clock(conn, info).await?,
                decision: Decision::ExpiredUnknown,
            });
        }
    }
    // Namespace locks serialize affected partitions, including range phantoms.
    // There is no exclusive dataset lock on an ordinary write.
    let namespaces: BTreeSet<_> = candidate
        .mutations
        .iter()
        .map(|mutation| match mutation {
            Mutation::Put { address, .. } | Mutation::Delete(address) => address.namespace,
            Mutation::DeleteRange { namespace, .. } => namespace.0,
        })
        .collect();
    let mut invalid = None;
    if namespaces.contains(&control::GENERATION_NAMESPACE.0) {
        invalid = Some(Failure::Refused);
    }
    let mut generations = Vec::new();
    for namespace in namespaces {
        let at = generation_address(namespace);
        let previous = get(conn, &at, "FOR UPDATE").await?;
        match generation(previous.as_ref().map(bytes))?.checked_add(1) {
            Some(next) => generations.push((at, next)),
            None => invalid = Some(Failure::Refused),
        }
    }
    let mut conditions = true;
    for predicate in &candidate.predicates {
        let previous = get(conn, &predicate.address, "LOCK IN SHARE MODE").await?;
        conditions &= match (&predicate.expected, previous.as_ref()) {
            (ExpectedValue::Absent, None) => true,
            (ExpectedValue::Exact(expected), Some(previous)) => bytes(expected) == bytes(previous),
            _ => false,
        };
    }
    // Validate and lock every mutation's prestate before the clock/effects.
    for mutation in &candidate.mutations {
        match mutation {
            Mutation::Put { address: at, value } => {
                let previous = get(conn, at, "FOR UPDATE").await?;
                if at.namespace == control::NAMESPACE.0 && !bootstrap {
                    if let Some(key) = control::Key::decode(&at.key) {
                        if !candidate.predicates.iter().any(|p| p.address == *at) {
                            invalid = Some(Failure::Refused);
                        }
                        if let Err(error) = control::replacement(
                            key,
                            info.dataset,
                            previous.as_ref().map(bytes),
                            bytes(value),
                        ) {
                            invalid = Some(error);
                        }
                    } else {
                        invalid = Some(Failure::Refused);
                    }
                }
            }
            Mutation::Delete(at) => {
                if at.namespace == control::NAMESPACE.0 {
                    invalid = Some(Failure::Refused);
                }
                get(conn, at, "FOR UPDATE").await?;
            }
            Mutation::DeleteRange { namespace, .. } => {
                if *namespace == control::NAMESPACE {
                    invalid = Some(Failure::Refused);
                }
                // The exclusive generation lock excludes all native namespace writers.
                // A locking traversal also protects every selected native prestate.
                walk_range(conn, mutation, false).await?;
            }
        }
    }
    let observed_at = clock(conn, info).await?;
    if candidate
        .time
        .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
    {
        return Ok(Committed {
            observed_at,
            decision: Decision::TimeGuardFailed { observed_at },
        });
    }
    if !conditions {
        return Ok(Committed {
            observed_at,
            decision: Decision::ConditionConflict,
        });
    }
    if let Some(error) = invalid {
        return Err(error);
    }
    let payload = receipt_bytes(request, observed_at.unix_seconds)?;
    for mutation in &candidate.mutations {
        match mutation {
            Mutation::Put { address, value } => put(conn, address, bytes(value)).await?,
            Mutation::Delete(at) => delete(conn, at).await?,
            Mutation::DeleteRange { .. } => walk_range(conn, mutation, true).await?,
        }
    }
    for (at, next) in generations {
        put(conn, &at, &next.to_le_bytes()).await?;
    }
    conn.exec_drop("INSERT INTO busbar_v4_receipts(writer,operation,payload) VALUES(:writer,:operation,:payload)",params!{"writer"=>id.writer.as_slice(),"operation"=>id.operation.as_slice(),"payload"=>payload.as_slice()}).await.map_err(|_|Failure::Unknown)?;
    Ok(Committed {
        observed_at,
        decision: Decision::Applied(candidate.result.clone()),
    })
}

async fn walk_range(conn: &mut Conn, mutation: &Mutation<Own>, remove: bool) -> Result<()> {
    let Mutation::DeleteRange {
        namespace,
        prefix,
        exact_key_length,
    } = mutation
    else {
        return Err(Failure::Refused);
    };
    let mut cursor = None;
    loop {
        let batch = key_batch(conn, namespace.0, cursor.as_deref(), "FOR UPDATE").await?;
        if batch.is_empty() {
            return Ok(());
        }
        for (digest, key) in batch {
            check_key(namespace.0, &digest, &key)?;
            cursor = Some(digest);
            if remove
                && key.starts_with(prefix)
                && u64::try_from(key.len()).ok() == Some(*exact_key_length)
            {
                delete(
                    conn,
                    &Address {
                        namespace: namespace.0,
                        key,
                    },
                )
                .await?;
            }
        }
    }
}

/// A durable retirement is observed only while holding its exclusive native row
/// lock. This waits for every earlier shared-lock writer transaction to complete.
pub(super) async fn maintain(
    conn: &mut Conn,
    horizons: &Mutex<BTreeMap<[u8; 16], Horizon>>,
    writers: &BTreeSet<[u8; 16]>,
) -> Result<()> {
    // Native Finish must be able to verify the original Applied receipt even
    // after a long stopped upgrade or cold recovery. Pin all upgrade receipts
    // until the exact Complete checkpoint has been confirmed natively.
    if crate::legacy::lifecycle::load(conn)
        .await
        .map_err(|_| Failure::Unavailable)?
        .is_some_and(|row| row.completed.is_none())
    {
        return Ok(());
    }
    for writer in writers {
        let mut tx = conn
            .start_transaction()
            .await
            .map_err(|_| Failure::Unavailable)?;
        let stored = get(
            &mut tx,
            &address(control::NAMESPACE, &control::writer_key(*writer)),
            "FOR UPDATE",
        )
        .await?
        .ok_or(Failure::Corrupt)?;
        let floor = control::Writer::decode(bytes(&stored))
            .ok_or(Failure::Corrupt)?
            .retired_through;
        // Sample monotonic time after native lock admission, never while waiting.
        let now = Instant::now();
        let collectible = {
            let mut guards = horizons.lock().map_err(|_| Failure::Unavailable)?;
            guards
                .entry(*writer)
                .or_insert_with(|| Horizon::new(floor, now))
                .observe(floor, now)?
        };
        if collectible != 0 {
            let mut receipt_cursor = None;
            loop {
                let (condition, after) = match receipt_cursor.as_deref() {
                    Some(after) => ("AND operation>:after", after),
                    None => ("", &[][..]),
                };
                let rows:Vec<Vec<u8>>=tx.exec(format!("SELECT operation FROM busbar_v4_receipts WHERE writer=:writer {condition} ORDER BY operation LIMIT {FETCH_ROWS} FOR UPDATE"),params!{"writer"=>writer.as_slice(),"after"=>after}).await.map_err(|_|Failure::Unavailable)?;
                let length = rows.len();
                for operation in rows {
                    let payload:Option<Vec<u8>>=tx.exec_first("SELECT payload FROM busbar_v4_receipts WHERE writer=:writer AND operation=:operation FOR UPDATE",params!{"writer"=>writer.as_slice(),"operation"=>operation.as_slice()}).await.map_err(|_|Failure::Unavailable)?;
                    let receipt = decode_receipt(payload.ok_or(Failure::Corrupt)?)?;
                    if receipt.execution_epoch <= collectible {
                        tx.exec_drop("DELETE FROM busbar_v4_receipts WHERE writer=:writer AND operation=:operation",params!{"writer"=>writer.as_slice(),"operation"=>operation.as_slice()}).await.map_err(|_|Failure::Unknown)?;
                    }
                    receipt_cursor = Some(operation);
                }
                if length < FETCH_ROWS {
                    break;
                }
            }
        }
        tx.commit().await.map_err(|_| Failure::Unknown)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_selection_orders_full_binary_keys_after_a_long_common_prefix() {
        let prefix = vec![0; 4096];
        let make = |tail: &[u8]| {
            let mut key = prefix.clone();
            key.extend_from_slice(tail);
            key
        };
        let after = make(&[0]);
        let mut selected = BTreeSet::new();
        for tail in [&[255][..], &[0, 0], &[127], &[0], &[1], &[0, 255]] {
            select_key(&mut selected, make(tail), &prefix, Some(&after), 3);
        }
        select_key(&mut selected, vec![1], &prefix, Some(&after), 3);
        assert_eq!(
            selected.into_iter().collect::<Vec<_>>(),
            vec![make(&[0, 0]), make(&[0, 255]), make(&[1])]
        );
    }
    #[test]
    fn receipt_codec_round_trips_prepared_fingerprint_and_empty_result() {
        let candidate = Candidate {
            id: AttemptId {
                dataset: DatasetId([1; 16]),
                writer_epoch: u64::MAX,
                writer: [2; 16],
                execution_epoch: u64::MAX,
                operation: [3; 16],
            },
            codec: CANDIDATE_VERSION,
            predicates: vec![],
            mutations: vec![Mutation::Delete(Address {
                namespace: [4; 16],
                key: vec![0, 255],
            })],
            time: None,
            result: OwnSecret::held(vec![]),
        };
        let prepared = PreparedCandidate::new(candidate).unwrap();
        let mut encoded = receipt_bytes(&prepared, 42).unwrap();
        let receipt = decode_receipt(std::mem::take(&mut *encoded)).unwrap();
        assert_eq!(receipt.fingerprint, prepared.fingerprint());
        assert_eq!(receipt.writer_epoch, u64::MAX);
        assert_eq!(receipt.execution_epoch, u64::MAX);
        assert_eq!(receipt.time, 42);
        assert!(bytes(&receipt.result).is_empty());
    }
    #[test]
    fn full_key_hash_and_generation_are_exact_binary() {
        let mut at = Address {
            namespace: [255; 16],
            key: vec![0; 2048],
        };
        let first = hash(&at);
        at.key[2047] = 255;
        assert_ne!(first, hash(&at));
        assert_eq!(generation(Some(&u64::MAX.to_le_bytes())), Ok(u64::MAX));
        assert_eq!(generation(Some(&[0; 8])), Err(Failure::Corrupt));
        assert_eq!(generation(None), Ok(0));
    }
    #[test]
    fn receipts_preserve_unsigned_epochs_time_and_wiping_result() {
        let mut payload = Vec::from(RECEIPT_PREFIX.as_slice());
        payload.extend_from_slice(&[255; 32]);
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        payload.extend_from_slice(&(u64::MAX - 1).to_le_bytes());
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        payload.extend_from_slice(&[0, 255, 0]);
        let receipt = decode_receipt(payload).unwrap();
        assert_eq!(receipt.fingerprint, [255; 32]);
        assert_eq!(receipt.writer_epoch, u64::MAX);
        assert_eq!(receipt.execution_epoch, u64::MAX - 1);
        assert_eq!(receipt.time, u64::MAX);
        assert_eq!(bytes(&receipt.result), &[0, 255, 0]);
        assert!(matches!(decode_receipt(vec![0; 64]), Err(Failure::Corrupt)));
    }
}
