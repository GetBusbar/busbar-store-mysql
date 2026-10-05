// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE UNDER TEST, AS BUSBAR RUNS IT: the store's door loaded through the real loader on a
//! dispatcher, every connection over the host's connection path (the loader's test connection
//! table, `tcp_conns::TcpConns`), opened with `open`'s connect step. [`MysqlStore`] (this module's,
//! which the tests name as they always did) answers the 1.5.5 op set through the loader's
//! synchronous bridge (`RecordStore`, by deref) and the store v3 slots through `StoreCalls`, in the
//! slots' own result types.
//!
//! RAW SQL: [`MysqlStore::pool`] / [`MysqlStore::conn`] are an INDEPENDENT connection of the 1.5.5
//! `mysql` driver's own (a dev-dependency; never in the shipped image), for what a test sets up or
//! verifies. The store's internals a test calls directly (the migration steps, the probes) run on
//! the store's own client ([`crate::mysqlwire::Conn`]) over a plain TCP stream to the same database,
//! in the same session posture (`sql_mode`) as the driver connection the test hands them.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Wake, Waker};

use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, Grant, OpRefused, ReserveRefused, StoreSlots, Tail,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{AuditRecord, PlaneRecordRef, RecordStoreResult, UsageDelta};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use busbar_plugin_loader::tcp_conns::TcpConns;
use mysql::prelude::Queryable;

use crate::mysqlwire;

struct Unpark(std::thread::Thread);
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Run `f` to completion on this thread.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

/// The process's one dispatcher and test connection table (as one busbar process has one).
fn host() -> &'static (
    Arc<Dispatcher>,
    Arc<dyn busbar_contract::conn::DeclaredConns>,
) {
    static HOST: OnceLock<(
        Arc<Dispatcher>,
        Arc<dyn busbar_contract::conn::DeclaredConns>,
    )> = OnceLock::new();
    HOST.get_or_init(|| {
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let conns: Arc<dyn busbar_contract::conn::DeclaredConns> =
            Arc::new(TcpConns::new(d.conn_waker()));
        (d, conns)
    })
}

/// The node's `op_id` allocator for the bridge's writes: a node half no earlier run used (the
/// dedupe is durable) and one counter.
fn mint() -> OpId {
    static NODE: OnceLock<u64> = OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(|| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        (t ^ (u64::from(std::process::id()) << 40)) | 1
    });
    OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// The store's linked door opened on `settings`, as the host opens it.
pub(crate) fn open_loaded(settings: &str) -> Result<LoadedStore, String> {
    let (d, conns) = host();
    let row = LinkedRow::of(crate::door).map_err(|e| e.to_string())?;
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("store-mysql-test"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: Some(conns.clone()),
        },
    )
    .map_err(|e| e.to_string())?;
    LoadedStore::open(p, d.clone(), settings.as_bytes(), mint)
}

/// An INDEPENDENT `mysql` driver pool on the store's URL (made on first use), with the session
/// posture the 1.5.5 store gave every connection.
#[derive(Clone)]
pub(crate) struct RawPool {
    url: String,
    pool: Arc<OnceLock<mysql::Pool>>,
}

impl RawPool {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            pool: Arc::new(OnceLock::new()),
        }
    }

    /// A driver connection to the store's database.
    pub(crate) fn get_conn(&self) -> mysql::Result<mysql::PooledConn> {
        let pool = match self.pool.get() {
            Some(p) => p,
            None => {
                let opts = mysql::Opts::from_url(&self.url)?;
                let opts = mysql::OptsBuilder::from_opts(opts)
                    .pool_opts(
                        mysql::PoolOpts::default()
                            .with_constraints(mysql::PoolConstraints::new(1, 8).expect("1 <= 8")),
                    )
                    .init(vec![crate::INIT[0]]);
                let p = mysql::Pool::new(opts)?;
                let _ = self.pool.set(p);
                self.pool.get().expect("set above")
            }
        };
        pool.get_conn()
    }
}

/// THE STORE UNDER TEST (the tests' `MysqlStore`).
pub(crate) struct MysqlStore {
    store: LoadedStore,
    /// An independent driver pool on the same database, for raw SQL.
    pub(crate) pool: RawPool,
}

impl std::ops::Deref for MysqlStore {
    type Target = LoadedStore;
    fn deref(&self) -> &LoadedStore {
        &self.store
    }
}

fn op_refused(f: StoreFailure) -> OpRefused {
    match f {
        StoreFailure::Conflict => OpRefused::Conflict,
        StoreFailure::Failed(t) | StoreFailure::Refused(t) | StoreFailure::Fault(t) => {
            OpRefused::Failed(t)
        }
        other => OpRefused::Failed(other.to_string()),
    }
}

fn text(f: StoreFailure) -> String {
    match f {
        StoreFailure::Failed(t) | StoreFailure::Refused(t) | StoreFailure::Fault(t) => t,
        other => other.to_string(),
    }
}

/// The store's own client on the database `conn` is connected to, in `conn`'s `sql_mode`.
fn own_client_like(conn: &mut mysql::PooledConn) -> mysqlwire::Conn {
    let url = super::test_url().expect("a live test hands a live connection");
    let db: Option<String> = conn
        .query_first::<Option<String>, _>("SELECT DATABASE()")
        .expect("SELECT DATABASE()")
        .flatten();
    let mode: String = conn
        .query_first("SELECT @@SESSION.sql_mode")
        .expect("SELECT @@SESSION.sql_mode")
        .unwrap_or_default();
    let mut opts = mysqlwire::Opts::from_url(&url).expect("the test URL parses");
    opts.db_name = db;
    let set_mode = format!("SET SESSION sql_mode = '{mode}'");
    block_on(mysqlwire::Conn::open_tcp(
        &Arc::new(opts),
        &[set_mode.as_str()],
    ))
    .expect("the store's client connects")
}

impl MysqlStore {
    /// The store on `url`, as the host opens it (`{"url": url}`; the connect step runs).
    pub(crate) fn connect(url: &str) -> Result<Self, String> {
        let settings = serde_json::json!({ "url": url }).to_string();
        Ok(Self {
            store: open_loaded(&settings)?,
            pool: RawPool::new(url),
        })
    }

    /// An independent driver connection, for raw SQL.
    pub(crate) fn conn(&self) -> mysql::Result<mysql::PooledConn> {
        self.pool.get_conn()
    }

    /// The store's Statement tail.
    pub(crate) const TAIL: Tail = <crate::MysqlStore as StoreSlots>::TAIL;

    /// `StoreSlots::open` on `settings` (the settings' judge), with no host.
    pub(crate) fn open(settings: &[u8]) -> Result<crate::MysqlStore, String> {
        <crate::MysqlStore as StoreSlots>::open(settings, None)
    }

    // ── the store's internals, on its own client ───────────────────────────────────────────

    pub(crate) fn run_v2_backfill_if_needed(
        conn: &mut mysql::PooledConn,
        prior_version: u32,
        table: &str,
    ) -> RecordStoreResult<()> {
        let mut c = own_client_like(conn);
        block_on(crate::MysqlStore::run_v2_backfill_if_needed(
            &mut c,
            prior_version,
            table,
        ))
    }

    pub(crate) fn run_v3_ascii_bin_fix_if_needed(
        conn: &mut mysql::PooledConn,
        prior_version: u32,
        table: &str,
    ) -> RecordStoreResult<()> {
        let mut c = own_client_like(conn);
        block_on(crate::MysqlStore::run_v3_ascii_bin_fix_if_needed(
            &mut c,
            prior_version,
            table,
        ))
    }

    pub(crate) fn read_prior_version(
        conn: &mut mysql::PooledConn,
        table: &str,
    ) -> RecordStoreResult<u32> {
        let mut c = own_client_like(conn);
        block_on(crate::MysqlStore::read_prior_version(&mut c, table))
    }

    pub(crate) fn probe_invariants(conn: &mut mysql::PooledConn) -> RecordStoreResult<()> {
        let mut c = own_client_like(conn);
        block_on(crate::MysqlStore::probe_invariants(&mut c))
    }

    /// The driver's error, as the store's client spells the same server answer.
    pub(crate) fn is_check_constraint_violation(e: &mysql::Error) -> bool {
        let own = match e {
            mysql::Error::MySqlError(m) => mysqlwire::Error::MySqlError(mysqlwire::MySqlError {
                state: m.state.clone(),
                message: m.message.clone(),
                code: m.code,
            }),
            other => mysqlwire::Error::IoError(other.to_string()),
        };
        crate::MysqlStore::is_check_constraint_violation(&own)
    }

    // ── the store v3 slots, through `StoreCalls` (the slots' own result types) ─────────────

    pub(crate) fn add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Result<(), OpRefused> {
        let cells = [(bucket, window_start, delta.clone())];
        block_on(StoreCalls::add_usage_batch(&self.store, op, &cells)).map_err(op_refused)
    }

    pub(crate) fn append_audit_batch(
        &self,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Result<(), OpRefused> {
        block_on(StoreCalls::append_audit_batch(&self.store, op, entries)).map_err(op_refused)
    }

    pub(crate) fn append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Result<(), OpRefused> {
        block_on(StoreCalls::append_plane_record(&self.store, op, record)).map_err(op_refused)
    }

    pub(crate) fn reserve<'c>(
        &self,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>>,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        let cells: Vec<Cell<'c>> = cells.collect();
        match block_on(StoreCalls::reserve(&self.store, op, epoch, &cells)) {
            Ok(g) => {
                grants.extend(g);
                Ok(())
            }
            Err(StoreFailure::Reserve(r)) => Err(r),
            Err(StoreFailure::Conflict) => Err(ReserveRefused::Conflict),
            Err(_) => Err(ReserveRefused::Unavailable),
        }
    }

    pub(crate) fn slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)>,
        released: &mut impl Extend<u64>,
    ) -> Result<(), OpRefused> {
        let items: Vec<(u64, u64)> = items.collect();
        let back = block_on(StoreCalls::slice_release(&self.store, op, epoch, &items))
            .map_err(op_refused)?;
        released.extend(back);
        Ok(())
    }

    pub(crate) fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        block_on(StoreCalls::window_caps(&self.store, op, caps)).map_err(|f| match f {
            StoreFailure::CapConflict(index) => CapsRefused::CapConflict { index },
            StoreFailure::Conflict => CapsRefused::Conflict,
            other => CapsRefused::Failed(text(other)),
        })
    }

    pub(crate) fn append_batch(
        &self,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Result<Head, OpRefused> {
        block_on(StoreCalls::append_batch(&self.store, op, stream, records)).map_err(op_refused)
    }

    pub(crate) fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        block_on(StoreCalls::heads(&self.store)).map_err(text)
    }

    pub(crate) fn session_put(
        &self,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Result<(), String> {
        block_on(StoreCalls::session_put(
            &self.store,
            session,
            node,
            principal,
        ))
        .map_err(text)
    }

    pub(crate) fn session_remove(&self, session: u64) -> Result<(), String> {
        block_on(StoreCalls::session_remove(&self.store, session)).map_err(text)
    }

    pub(crate) fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        block_on(StoreCalls::sessions_for(&self.store, principal)).map_err(text)
    }

    pub(crate) fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let value = RecordBytes::new(value.to_vec()).map_err(|n| format!("{n} bytes"))?;
        block_on(StoreCalls::record_put(&self.store, schema, key, &value)).map_err(text)
    }

    pub(crate) fn record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        block_on(StoreCalls::record_get(&self.store, schema, key)).map_err(text)
    }

    pub(crate) fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        block_on(StoreCalls::record_scan(&self.store, schema, prefix, limit)).map_err(text)
    }
}
