// SPDX-License-Identifier: Apache-2.0
//! Host-owned native preparation channels. No historical business interpretation.
use super::backend::{Own, INIT};
use crate::{
    legacy::{self, lifecycle as native},
    mysqlwire::{Conn, Opts},
};
use busbar_contract::{
    abi::sdk::store::{
        wire::{drive_channels, Channels},
        Op, Step,
    },
    persistence::{self as p, lifecycle as l},
    Secret,
};
use mysql_common::params;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, OnceLock};

const OWNER: [u8; 16] = *b"legacy.mysql..v1";
pub(super) struct Bootstrap {
    channels: Arc<Channels>,
    state: Arc<Mutex<Option<State>>>,
    anchor: Arc<OnceLock<[u8; 32]>>,
}
struct State {
    control: Option<Conn>,
    source: Option<Conn>,
    snapshot: Option<legacy::Snapshot>,
    inspected: Option<legacy::Metadata>,
    upgrade: Option<native::Upgrade>,
    authority: Secret<Vec<u8>, Own>,
    reset: bool,
    inspected_current: Option<l::SourceIdentity>,
    inspected_empty: bool,
}
struct StateLease {
    owner: Arc<Mutex<Option<State>>>,
    state: Option<State>,
}
impl Drop for StateLease {
    fn drop(&mut self) {
        if let Some(mut state) = self.state.take() {
            // A dropped in-flight native operation is reconciled from its exact
            // durable journal. Never reuse a cancelled protocol transaction.
            state.reset = true;
            if let Ok(mut slot) = self.owner.lock() {
                *slot = Some(state);
            }
        }
    }
}
impl Bootstrap {
    pub(super) fn anchor(&self) -> Arc<OnceLock<[u8; 32]>> {
        self.anchor.clone()
    }
    pub(super) fn open(
        &self,
        op: &mut Op<'_>,
        opts: Arc<Opts>,
        info: Arc<OnceLock<p::BackendInfo>>,
        binding: &l::OpenBinding,
    ) -> Step<Result<(), String>> {
        let state = self.state.clone();
        let anchor = self.anchor.clone();
        let binding = binding.clone();
        drive_channels(op, &self.channels, move |wires| {
            Box::pin(async move {
                let owned = state
                    .lock()
                    .map_err(|_| "native session unavailable".to_owned())?
                    .take()
                    .ok_or_else(|| "native session busy".to_owned())?;
                let mut lease = StateLease {
                    owner: state.clone(),
                    state: Some(owned),
                };
                let owned = lease
                    .state
                    .as_mut()
                    .ok_or_else(|| "native session unavailable".to_owned())?;
                let result = owned.open(&opts, &info, &wires, &binding, &anchor).await;
                owned.reset = result.is_err();
                *state
                    .lock()
                    .map_err(|_| "native session unavailable".to_owned())? = lease.state.take();
                result.map_err(|_| "native prepared admission refused".to_owned())
            })
        })
    }
    pub(super) fn new() -> Result<Self, String> {
        let mut authority = zeroize::Zeroizing::new(vec![0; 32]);
        getrandom::fill(&mut authority).map_err(|_| "native session identity unavailable")?;
        Ok(Self {
            channels: Arc::new(Channels::new(3)),
            anchor: Arc::new(OnceLock::new()),
            state: Arc::new(Mutex::new(Some(State {
                control: None,
                source: None,
                snapshot: None,
                inspected: None,
                upgrade: None,
                authority: Secret::held(authority.to_vec()),
                reset: false,
                inspected_current: None,
                inspected_empty: false,
            }))),
        })
    }
    pub(super) fn call(
        &self,
        op: &mut Op<'_>,
        opts: Arc<Opts>,
        info: Arc<OnceLock<p::BackendInfo>>,
        request: &l::Request<Own>,
    ) -> Step<Result<l::Response<Own>, l::Error>> {
        let request = request.clone();
        let state = self.state.clone();
        let anchor = self.anchor.clone();
        drive_channels(op, &self.channels, move |wires| {
            Box::pin(async move {
                let owned = state
                    .lock()
                    .map_err(|_| l::Error::Corrupt)?
                    .take()
                    .ok_or(l::Error::Busy)?;
                let mut lease = StateLease {
                    owner: state.clone(),
                    state: Some(owned),
                };
                let owned = lease.state.as_mut().ok_or(l::Error::Corrupt)?;
                let result = owned.call(&opts, &info, &wires, request, &anchor).await;
                owned.reset = matches!(&result, Err(l::Error::Unknown | l::Error::Unavailable));
                *state.lock().map_err(|_| l::Error::Corrupt)? = lease.state.take();
                result
            })
        })
    }
}
fn native_error(error: native::Error) -> l::Error {
    match error {
        native::Error::Busy => l::Error::Busy,
        native::Error::Pending => l::Error::Unknown,
        native::Error::MissingCapability => l::Error::MissingCapability,
        native::Error::SourceChanged => l::Error::SourceChanged,
        native::Error::Corrupt => l::Error::Corrupt,
    }
}
fn source_error(error: legacy::Error) -> l::Error {
    match error {
        legacy::Error::Native => l::Error::Unavailable,
        legacy::Error::UnknownFormat => l::Error::UnsupportedFormat,
        legacy::Error::Damaged => l::Error::Corrupt,
        legacy::Error::Budget => l::Error::Bounds,
        legacy::Error::Cursor => l::Error::SourceChanged,
    }
}
fn layouts(tables: &[legacy::Table]) -> Result<Vec<p::archive::Table>, l::Error> {
    tables
        .iter()
        .map(|t| {
            Ok(p::archive::Table {
                name: t.name.clone(),
                columns: t.columns.iter().map(|c| c.name.clone()).collect(),
                native_layout: serde_json::to_vec(t).map_err(|_| l::Error::Corrupt)?,
            })
        })
        .collect()
}
fn descriptor(
    identity: &[u8],
    physical: u32,
    tables: &[legacy::Table],
) -> Result<l::SourceIdentity, l::Error> {
    let anchor: [u8; 32] = Sha256::digest(identity).into();
    let catalogue = legacy::catalogue_digest(tables);
    let layout = Sha256::digest(serde_json::to_vec(tables).map_err(|_| l::Error::Corrupt)?).into();
    Ok(l::SourceIdentity {
        native_anchor: anchor,
        dataset: p::DatasetId(anchor[..16].try_into().map_err(|_| l::Error::Corrupt)?),
        format: Some(l::Format {
            owner: OWNER,
            physical,
            logical: 0,
            codec: 1,
        }),
        catalogue_digest: catalogue,
        layout_digest: layout,
    })
}
fn target_format(format: l::Format) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(format.owner);
    hash.update(format.physical.to_le_bytes());
    hash.update(format.logical.to_le_bytes());
    hash.update(format.codec.to_le_bytes());
    hash.finalize().into()
}
impl State {
    async fn open(
        &mut self,
        opts: &Arc<Opts>,
        info: &Arc<OnceLock<p::BackendInfo>>,
        wires: &[busbar_contract::abi::sdk::store::wire::Wire],
        binding: &l::OpenBinding,
        anchor: &OnceLock<[u8; 32]>,
    ) -> Result<(), l::Error> {
        if self.reset {
            self.snapshot = None;
            self.source = None;
            self.control = None;
            for wire in &wires[..2] {
                wire.close().await;
            }
            self.reset = false;
        }
        if self.control.is_none() {
            self.control = Some(
                Conn::open(wires[0].clone(), opts, 0, INIT)
                    .await
                    .map_err(|_| l::Error::Unavailable)?,
            );
        }
        let control = self.control.as_mut().ok_or(l::Error::Corrupt)?;
        bind_anchor(control, anchor).await?;
        let facts = match binding {
            l::OpenBinding::Empty => {
                if !self.inspected_empty {
                    return Err(l::Error::Refused);
                }
                let count:Option<u64>=control.query_first("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE()").await.map_err(|_|l::Error::Unavailable)?;
                if count != Some(0)
                    && !super::empty_origin::empty(control)
                        .await
                        .map_err(|_| l::Error::SourceChanged)?
                {
                    return Err(l::Error::SourceChanged);
                }
                super::schema::open(control)
                    .await
                    .map_err(|_| l::Error::Unavailable)?
            }
            l::OpenBinding::Current {
                source,
                admission_marker_digest,
            } => {
                if self.inspected_current.as_ref() != Some(source) {
                    return Err(l::Error::Refused);
                }
                if let Some(row) = self.upgrade.as_ref() {
                    native::verify_snapshot(control, row)
                        .await
                        .map_err(native_error)?;
                }
                let (actual, marker, _) = current_source(control).await?;
                if &actual != source
                    || marker
                        .as_ref()
                        .map(|s| p::archive::digest(s.expose_own(&Own::here())))
                        .unwrap_or([0; 32])
                        != *admission_marker_digest
                {
                    return Err(l::Error::SourceChanged);
                }
                super::schema::inspect_current(control)
                    .await
                    .map_err(|_| l::Error::Corrupt)?
            }
            l::OpenBinding::Recovery(expected) => {
                native::acquire(control).await.map_err(native_error)?;
                let row = native::load(control)
                    .await
                    .map_err(native_error)?
                    .ok_or(l::Error::Refused)?;
                native::check(control, &row).await.map_err(native_error)?;
                if &recovery(&row)? != expected {
                    return Err(l::Error::SourceChanged);
                }
                self.upgrade = Some(row);
                super::schema::inspect_current(control)
                    .await
                    .map_err(|_| l::Error::Corrupt)?
            }
        };
        if let Some(prior) = info.get() {
            if prior != &facts {
                return Err(l::Error::SourceChanged);
            }
        } else {
            info.set(facts).map_err(|_| l::Error::Corrupt)?;
        }
        Ok(())
    }
    fn authorize(&self, reference: &l::UpgradeRef<Own>) -> Result<&native::Upgrade, l::Error> {
        let row = self.upgrade.as_ref().ok_or(l::Error::Refused)?;
        if reference.id != row.target
            || reference.authority.expose_own(&Own::here())
                != self.authority.expose_own(&Own::here())
        {
            return Err(l::Error::Refused);
        }
        Ok(row)
    }
    fn reference(&self, row: &native::Upgrade) -> l::UpgradeRef<Own> {
        l::UpgradeRef {
            id: row.target,
            authority: self.authority.clone(),
        }
    }
    async fn call(
        &mut self,
        opts: &Arc<Opts>,
        info: &Arc<OnceLock<p::BackendInfo>>,
        wires: &[busbar_contract::abi::sdk::store::wire::Wire],
        request: l::Request<Own>,
        anchor: &OnceLock<[u8; 32]>,
    ) -> Result<l::Response<Own>, l::Error> {
        if self.reset {
            self.snapshot = None;
            self.source = None;
            self.control = None;
            for wire in &wires[..2] {
                wire.close().await;
            }
            self.reset = false;
        }
        if self.control.is_none() {
            self.control = Some(
                Conn::open(wires[0].clone(), opts, 0, INIT)
                    .await
                    .map_err(|_| l::Error::Unavailable)?,
            );
            if self.upgrade.is_some() {
                native::acquire(self.control.as_mut().ok_or(l::Error::Corrupt)?)
                    .await
                    .map_err(native_error)?;
            }
        }
        bind_anchor(self.control.as_mut().ok_or(l::Error::Corrupt)?, anchor).await?;
        match request {
            l::Request::Inspect { bounds } => {
                if bounds.items == 0 || bounds.bytes == 0 {
                    return Err(l::Error::Bounds);
                }
                let control = self.control.as_mut().ok_or(l::Error::Corrupt)?;
                let tables:Vec<String>=control.query("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME LIMIT 34").await.map_err(|_|l::Error::Unavailable)?;
                if tables.is_empty() {
                    self.inspected_empty = true;
                    return Ok(l::Response::Inspected(l::Inspection {
                        state: l::InspectionState::Empty,
                        source: None,
                        admission_marker: None,
                        catalogue: Vec::new(),
                        capabilities: vec![l::NativeCapability::CurrentOpen],
                    }));
                }
                let origin = super::empty_origin::owned(control)
                    .await
                    .map_err(|_| l::Error::Corrupt)?;
                if origin
                    && super::empty_origin::empty(control)
                        .await
                        .map_err(|_| l::Error::Corrupt)?
                {
                    self.inspected_empty = true;
                    return Ok(l::Response::Inspected(l::Inspection {
                        state: l::InspectionState::Empty,
                        source: None,
                        admission_marker: None,
                        catalogue: Vec::new(),
                        capabilities: vec![l::NativeCapability::CurrentOpen],
                    }));
                }
                if let Some(row) = native::load(control).await.map_err(native_error)? {
                    native::verify_source(control, &row)
                        .await
                        .map_err(native_error)?;
                    if row.completed.is_some() {
                        native::verify_snapshot(control, &row)
                            .await
                            .map_err(native_error)?;
                        let (source, marker, catalogue) = current_source(control).await?;
                        check_catalogue_bounds(&catalogue, bounds, 1)?;
                        self.inspected_current = Some(source.clone());
                        self.upgrade = Some(row);
                        return Ok(l::Response::Inspected(l::Inspection {
                            state: l::InspectionState::Current,
                            source: Some(source),
                            admission_marker: marker,
                            catalogue,
                            capabilities: vec![l::NativeCapability::CurrentOpen],
                        }));
                    }
                    let identity = descriptor(&row.native_identity, row.physical, &row.catalogue)?;
                    let catalogue = layouts(&row.catalogue)?;
                    check_catalogue_bounds(&catalogue, bounds, 4)?;
                    self.upgrade = Some(row);
                    return Ok(l::Response::Inspected(l::Inspection {
                        state: l::InspectionState::InProgress,
                        source: Some(identity),
                        admission_marker: None,
                        catalogue,
                        capabilities: capabilities(),
                    }));
                }
                if tables.iter().all(|t| {
                    matches!(
                        t.as_str(),
                        "busbar_v4_meta" | "busbar_v4_records" | "busbar_v4_receipts"
                    ) || (origin && t == "store_meta")
                }) {
                    let (source, marker, catalogue) = current_source(control).await?;
                    check_catalogue_bounds(&catalogue, bounds, 1)?;
                    self.inspected_current = Some(source.clone());
                    return Ok(l::Response::Inspected(l::Inspection {
                        state: l::InspectionState::Current,
                        source: Some(source),
                        admission_marker: marker,
                        catalogue,
                        capabilities: vec![l::NativeCapability::CurrentOpen],
                    }));
                }
                if self.snapshot.is_none() {
                    let conn = match self.source.take() {
                        Some(c) => c,
                        None => Conn::open(
                            wires[1].clone(),
                            opts,
                            0,
                            &["SET SESSION character_set_results = binary"],
                        )
                        .await
                        .map_err(|_| l::Error::Unavailable)?,
                    };
                    self.snapshot = Some(
                        legacy::Snapshot::on_connection(conn)
                            .await
                            .map_err(source_error)?,
                    );
                }
                let metadata = self
                    .snapshot
                    .as_ref()
                    .ok_or(l::Error::Corrupt)?
                    .metadata()
                    .clone();
                if anchor.get() != Some(&p::archive::digest(&metadata.native_identity)) {
                    return Err(l::Error::SourceChanged);
                }
                let source = descriptor(
                    &metadata.native_identity,
                    metadata.schema_version,
                    &metadata.catalogue,
                )?;
                let catalogue = layouts(&metadata.catalogue)?;
                check_catalogue_bounds(&catalogue, bounds, 4)?;
                self.inspected = Some(metadata);
                Ok(l::Response::Inspected(l::Inspection {
                    state: l::InspectionState::Legacy,
                    source: Some(source),
                    admission_marker: None,
                    catalogue,
                    capabilities: capabilities(),
                }))
            }
            l::Request::BeginOrResume {
                expected_source,
                route_digest,
                target_format: format,
                operation_id,
            } => {
                if format != l::CORE_FORMAT {
                    return Err(l::Error::UnsupportedFormat);
                }
                let binding = native::Binding {
                    operation: operation_id,
                    route: route_digest,
                    target_format: target_format(format),
                    registered_catalogue: expected_source.catalogue_digest,
                };
                let existing = self
                    .upgrade
                    .as_ref()
                    .map(|r| descriptor(&r.native_identity, r.physical, &r.catalogue))
                    .transpose()?;
                let inspected = self
                    .inspected
                    .as_ref()
                    .map(|m| descriptor(&m.native_identity, m.schema_version, &m.catalogue))
                    .transpose()?;
                if existing.or(inspected).as_ref() != Some(&expected_source) {
                    return Err(l::Error::SourceChanged);
                }
                if let Some(snapshot) = self.snapshot.take() {
                    self.source = Some(snapshot.release_connection().await.map_err(source_error)?);
                }
                let control = self.control.as_mut().ok_or(l::Error::Corrupt)?;
                let row = if self.upgrade.is_some() {
                    native::resume(control, &binding)
                        .await
                        .map_err(native_error)?
                } else {
                    native::begin(
                        control,
                        self.inspected.as_ref().ok_or(l::Error::Refused)?,
                        binding,
                    )
                    .await
                    .map_err(native_error)?
                };
                self.upgrade = Some(row.clone());
                let target = super::schema::prepare_upgrade(control, &row)
                    .await
                    .map_err(|_| l::Error::Unknown)?;
                if let Some(old) = info.get() {
                    if old != &target {
                        return Err(l::Error::SourceChanged);
                    }
                } else {
                    info.set(target).map_err(|_| l::Error::Corrupt)?;
                }
                if self.source.is_none() {
                    self.source = Some(
                        Conn::open(
                            wires[1].clone(),
                            opts,
                            0,
                            &["SET SESSION character_set_results = binary"],
                        )
                        .await
                        .map_err(|_| l::Error::Unavailable)?,
                    );
                }
                self.snapshot = Some(
                    legacy::Snapshot::freeze_connection(
                        self.source.take().ok_or(l::Error::Corrupt)?,
                        &row,
                    )
                    .await
                    .map_err(source_error)?,
                );
                Ok(l::Response::Begun(l::Upgrade {
                    reference: self.reference(&row),
                    source: expected_source,
                    snapshot: row.source,
                    target,
                    native_step: 1,
                    catalogue: layouts(&row.catalogue)?,
                }))
            }
            l::Request::CheckFence { upgrade } => {
                let row = self.authorize(&upgrade)?.clone();
                native::check(self.control.as_mut().ok_or(l::Error::Corrupt)?, &row)
                    .await
                    .map_err(native_error)?;
                if self.snapshot.is_none() {
                    let conn = Conn::open(
                        wires[1].clone(),
                        opts,
                        0,
                        &["SET SESSION character_set_results = binary"],
                    )
                    .await
                    .map_err(|_| l::Error::Unavailable)?;
                    self.snapshot = Some(
                        legacy::Snapshot::freeze_connection(conn, &row)
                            .await
                            .map_err(source_error)?,
                    );
                }
                let source = descriptor(&row.native_identity, row.physical, &row.catalogue)?;
                let enforcement = Sha256::digest(b"mysql-native-before-dml-guard-v1").into();
                let mut nonce = [0; 32];
                getrandom::fill(&mut nonce).map_err(|_| l::Error::Unavailable)?;
                let mut hash = Sha256::new();
                hash.update(native::source_digest(&row));
                hash.update(enforcement);
                hash.update(nonce);
                Ok(l::Response::Fence(l::Fence {
                    upgrade: row.target,
                    source,
                    enforcement_digest: enforcement,
                    observation_digest: hash.finalize().into(),
                    snapshot: row.source,
                }))
            }
            l::Request::SourcePage {
                upgrade,
                snapshot,
                family,
                selector,
                cursor,
                bounds,
            } => {
                let row = self.authorize(&upgrade)?.clone();
                if snapshot != row.source {
                    return Err(l::Error::SourceChanged);
                }
                native::check(self.control.as_mut().ok_or(l::Error::Corrupt)?, &row)
                    .await
                    .map_err(native_error)?;
                if self.snapshot.is_none() {
                    let conn = Conn::open(
                        wires[1].clone(),
                        opts,
                        0,
                        &["SET SESSION character_set_results = binary"],
                    )
                    .await
                    .map_err(|_| l::Error::Unavailable)?;
                    self.snapshot = Some(
                        legacy::Snapshot::freeze_connection(conn, &row)
                            .await
                            .map_err(source_error)?,
                    );
                }
                let (table, exact) = match selector {
                    l::SourceSelector::Scan { table } => (table, None),
                    l::SourceSelector::Exact { table, key } => (table, Some(key)),
                    _ => return Err(l::Error::MissingCapability),
                };
                if exact.is_some() && cursor.is_some() {
                    return Err(l::Error::Refused);
                }
                let table_index = usize::try_from(table).map_err(|_| l::Error::Bounds)?;
                if table_index >= row.catalogue.len() || bounds.items == 0 || bounds.bytes == 0 {
                    return Err(l::Error::Bounds);
                }
                let source = self.snapshot.as_mut().ok_or(l::Error::SourceChanged)?;
                let (offset, mut coverage) = match cursor {
                    None => (0, native::source_digest(&row)),
                    Some(cursor) => {
                        let bytes = cursor.expose_own(&Own::here());
                        if bytes.len() != 60
                            || bytes[..16] != snapshot
                            || bytes[16..20] != table.to_le_bytes()
                        {
                            return Err(l::Error::SourceChanged);
                        }
                        (
                            u64::from_le_bytes(
                                bytes[20..28].try_into().map_err(|_| l::Error::Corrupt)?,
                            ),
                            bytes[28..].try_into().map_err(|_| l::Error::Corrupt)?,
                        )
                    }
                };
                let start = legacy::Cursor {
                    snapshot,
                    table: table_index,
                    offset,
                };
                let mut page = if let Some(key) = exact.as_ref() {
                    source
                        .exact::<Own>(
                            table_index,
                            key.expose_own(&Own::here()),
                            bounds.bytes as usize / 2,
                        )
                        .await
                        .map_err(source_error)?
                } else {
                    source
                        .page::<Own>(
                            &start,
                            usize::try_from(bounds.items)
                                .map_err(|_| l::Error::Bounds)?
                                .min(legacy::MAX_ROWS),
                            usize::try_from(bounds.bytes / 2).map_err(|_| l::Error::Bounds)?,
                        )
                        .await
                        .map_err(source_error)?
                };
                let columns = &row.catalogue[table_index].columns;
                let mut rows = Vec::new();
                let mut used = 0usize;
                for value in page.rows.drain(..) {
                    let bytes = value.expose_own(&Own::here());
                    let decoded =
                        p::legacy_row::Row::decode(bytes).map_err(|_| l::Error::Corrupt)?;
                    let cells = decoded.cells().collect::<Vec<_>>();
                    let mut primary = columns
                        .iter()
                        .enumerate()
                        .filter_map(|(i, c)| c.primary_ordinal.map(|ordinal| (ordinal, i)))
                        .collect::<Vec<_>>();
                    primary.sort_unstable();
                    let key = p::legacy_row::encode::<Own>(
                        &primary.iter().map(|(_, i)| cells[*i]).collect::<Vec<_>>(),
                        bounds.bytes as usize,
                    )
                    .map_err(|_| l::Error::Bounds)?;
                    if exact.as_ref().is_some_and(|expected| {
                        expected.expose_own(&Own::here()) != key.expose_own(&Own::here())
                    }) {
                        return Err(l::Error::SourceChanged);
                    }
                    used = used
                        .checked_add(bytes.len())
                        .and_then(|n| n.checked_add(key.expose_own(&Own::here()).len()))
                        .ok_or(l::Error::Bounds)?;
                    if used > bounds.bytes as usize {
                        return Err(l::Error::Bounds);
                    }
                    let mut hash = Sha256::new();
                    hash.update(coverage);
                    hash.update(table.to_le_bytes());
                    hash.update((offset + rows.len() as u64).to_le_bytes());
                    hash.update((key.expose_own(&Own::here()).len() as u64).to_le_bytes());
                    hash.update(key.expose_own(&Own::here()));
                    hash.update((bytes.len() as u64).to_le_bytes());
                    hash.update(bytes);
                    coverage = hash.finalize().into();
                    rows.push(l::SourceRow {
                        table,
                        native_key: key,
                        value,
                    });
                }
                let next = page.next.map(|cursor| {
                    let mut bytes = Vec::from(snapshot);
                    bytes.extend_from_slice(&table.to_le_bytes());
                    bytes.extend_from_slice(&cursor.offset.to_le_bytes());
                    bytes.extend_from_slice(&coverage);
                    Secret::held(bytes)
                });
                Ok(l::Response::SourcePage(l::SourcePage {
                    snapshot,
                    family,
                    rows,
                    next,
                    source_digest: native::source_digest(&row),
                    coverage_digest: coverage,
                }))
            }
            l::Request::Target { upgrade } => {
                let row = self.authorize(&upgrade)?.clone();
                native::check(self.control.as_mut().ok_or(l::Error::Corrupt)?, &row)
                    .await
                    .map_err(native_error)?;
                Ok(l::Response::Target(l::TargetBinding {
                    upgrade: row.target,
                    info: *info.get().ok_or(l::Error::Refused)?,
                    binding: self.authority.clone(),
                }))
            }
            l::Request::Finish {
                upgrade,
                activation_receipt,
            } => {
                let prior = self.authorize(&upgrade)?.clone();
                let control = self.control.as_mut().ok_or(l::Error::Corrupt)?;
                let actual = native::load(control)
                    .await
                    .map_err(native_error)?
                    .ok_or(l::Error::Corrupt)?;
                let mut identity = actual.clone();
                identity.activation = prior.activation.clone();
                identity.completed = prior.completed.clone();
                if identity != prior {
                    return Err(l::Error::SourceChanged);
                }
                native::check(control, &actual)
                    .await
                    .map_err(native_error)?;
                let row = super::native::finish_upgrade(control, &actual, &activation_receipt)
                    .await
                    .map_err(|e| {
                        if e == p::Failure::Unknown {
                            l::Error::Unknown
                        } else {
                            l::Error::Refused
                        }
                    })?;
                let recovery = recovery(&row)?;
                self.upgrade = Some(row.clone());
                if activation_receipt.phase == l::CompletionPhase::Complete {
                    Ok(l::Response::ServingReady(l::ServingReady {
                        recovery,
                        completed_checkpoint_digest: row
                            .completed
                            .as_ref()
                            .ok_or(l::Error::Corrupt)?
                            .checkpoint,
                    }))
                } else {
                    Ok(l::Response::RecoveryReady(recovery))
                }
            }
        }
    }
}
fn capabilities() -> Vec<l::NativeCapability> {
    vec![
        l::NativeCapability::Snapshot,
        l::NativeCapability::PersistentFence,
        l::NativeCapability::Resume,
        l::NativeCapability::InactiveTarget,
    ]
}

fn recovery(row: &native::Upgrade) -> Result<l::RecoveryReady, l::Error> {
    Ok(l::RecoveryReady {
        upgrade: row.target,
        target: p::DatasetId(row.target),
        activation_receipt_digest: row.activation.as_ref().ok_or(l::Error::Refused)?.receipt,
        selector_digest: native::selector_digest(row).map_err(native_error)?,
    })
}

pub(super) async fn bind_anchor(
    conn: &mut Conn,
    anchor: &OnceLock<[u8; 32]>,
) -> Result<(), l::Error> {
    let identity = legacy::native_identity(conn).await.map_err(source_error)?;
    let actual = p::archive::digest(&identity);
    let expected = anchor.get_or_init(|| actual);
    if expected != &actual {
        return Err(l::Error::SourceChanged);
    }
    Ok(())
}

async fn current_source(
    conn: &mut Conn,
) -> Result<
    (
        l::SourceIdentity,
        Option<Secret<Vec<u8>, Own>>,
        Vec<p::archive::Table>,
    ),
    l::Error,
> {
    if native::load(conn).await.map_err(native_error)?.is_none() {
        super::empty_origin::check(conn)
            .await
            .map_err(|_| l::Error::SourceChanged)?;
    }
    let info = super::schema::inspect_current(conn)
        .await
        .map_err(|_| l::Error::Corrupt)?;
    let identity = legacy::native_identity(conn).await.map_err(source_error)?;
    let names:Vec<String>=conn.query("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME LIMIT 34").await.map_err(|_|l::Error::Unavailable)?;
    if names.len() > 32 {
        return Err(l::Error::Bounds);
    }
    let mut tables = Vec::new();
    let mut hash = Sha256::new();
    hash.update(b"mysql.native.current.catalogue.v1\0");
    for name in names {
        let columns:Vec<String>=conn.exec("SELECT COLUMN_NAME FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:name ORDER BY ORDINAL_POSITION LIMIT 65",mysql_common::params!{"name"=>&name}).await.map_err(|_|l::Error::Unavailable)?;
        if columns.is_empty() || columns.len() > 64 {
            return Err(l::Error::Corrupt);
        }
        let definition: Option<(String, String)> = conn
            .query_first(format!(
                "SHOW CREATE TABLE {}",
                legacy::quote(&name).map_err(source_error)?
            ))
            .await
            .map_err(|_| l::Error::Unavailable)?;
        let (returned, ddl) = definition.ok_or(l::Error::Corrupt)?;
        if returned != name {
            return Err(l::Error::Corrupt);
        }
        let layout = ddl.into_bytes();
        for bytes in std::iter::once(name.as_bytes())
            .chain(columns.iter().map(|s| s.as_bytes()))
            .chain(std::iter::once(layout.as_slice()))
        {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        tables.push(p::archive::Table {
            name,
            columns,
            native_layout: layout,
        });
    }
    let triggers:Vec<(String,String,String,String,String)>=conn.query("SELECT TRIGGER_NAME,EVENT_OBJECT_TABLE,EVENT_MANIPULATION,ACTION_TIMING,ACTION_STATEMENT FROM information_schema.triggers WHERE TRIGGER_SCHEMA=DATABASE() ORDER BY TRIGGER_NAME LIMIT 97").await.map_err(|_|l::Error::Unavailable)?;
    if triggers.len() > 96 {
        return Err(l::Error::Bounds);
    }
    hash.update(serde_json::to_vec(&triggers).map_err(|_| l::Error::Corrupt)?);
    let digest = hash.finalize().into();
    let marker = super::native::admission_marker(conn)
        .await
        .map_err(|_| l::Error::Unavailable)?;
    if marker.is_none() {
        return Err(l::Error::Refused);
    }
    Ok((
        l::SourceIdentity {
            native_anchor: Sha256::digest(identity).into(),
            dataset: info.dataset,
            format: Some(l::Format {
                owner: l::CORE_FORMAT.owner,
                physical: info.physical_version,
                logical: 0,
                codec: 1,
            }),
            catalogue_digest: digest,
            layout_digest: digest,
        },
        marker,
        tables,
    ))
}
fn check_catalogue_bounds(
    tables: &[p::archive::Table],
    bounds: l::Bounds,
    capabilities: usize,
) -> Result<(), l::Error> {
    let bytes = tables
        .iter()
        .try_fold(0usize, |sum, t| {
            sum.checked_add(t.name.len())
                .and_then(|n| n.checked_add(t.columns.iter().map(String::len).sum::<usize>()))
                .and_then(|n| n.checked_add(t.native_layout.len()))
        })
        .ok_or(l::Error::Bounds)?;
    let items = tables
        .iter()
        .try_fold(tables.len(), |sum, t| sum.checked_add(t.columns.len()))
        .and_then(|n| n.checked_add(capabilities))
        .ok_or(l::Error::Bounds)?;
    if items > bounds.items as usize || bytes > bounds.bytes as usize {
        return Err(l::Error::Bounds);
    }
    Ok(())
}
