// SPDX-License-Identifier: Apache-2.0
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::v4::backend::{Backend, Committed};
use busbar_contract::abi::sdk::store::v4::retirement::Horizon;
use busbar_contract::abi::sdk::store::wire::{drive_kept, Body, Pool};
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::persistence::*;
use busbar_contract::Secret;

use super::{native, schema};
use crate::mysqlwire::{Conn, Opts};

busbar_contract::own_seal!(Own);
pub(super) type OwnSecret = Secret<Vec<u8>, Own>;

pub(super) const INIT: &[&str] = &[
    "SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')",
    "SET SESSION time_zone = '+00:00'",
    "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
];

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    url: busbar_contract::abi::sdk::cred::MysqlUrl,
    input_budget: usize,
}

pub(crate) struct MysqlV4 {
    pub(crate) opts: Arc<Opts>,
    pool: Arc<Pool>,
    own: Own,
    budget: usize,
    info: Arc<OnceLock<BackendInfo>>,
    horizons: Arc<Mutex<BTreeMap<[u8; 16], Horizon>>>,
    bootstrap: super::bootstrap::Bootstrap,
}

macro_rules! on_conn {
    ($self:ident, $op:ident, $fail:expr, |$conn:ident| $body:expr) => {{
        let opts = $self.opts.clone();
        let pool = $self.pool.clone();
        let anchor = $self.bootstrap.anchor();
        drive_kept($op, &pool, move |wire| -> Body<_> {
            Box::pin(async move {
                let mut $conn = match Conn::open(wire, &opts, 0, INIT).await {
                    Ok(conn) => conn,
                    Err(_) => return Err($fail),
                };
                if super::bootstrap::bind_anchor(&mut $conn, &anchor)
                    .await
                    .is_err()
                {
                    return Err($fail);
                }
                let result = $body;
                $conn.release(INIT).await;
                result
            })
        })
    }};
}

impl Backend for MysqlV4 {
    type Owner = Own;
    fn owner(&self) -> &Own {
        &self.own
    }
    fn input_budget(&self) -> usize {
        self.budget
    }
    fn validate(settings: &[u8]) -> Result<(), String> {
        Self::open(settings, &[], None).map(drop)
    }
    fn open(settings: &[u8], secrets: &[&[u8]], _: Option<Host>) -> Result<Self, String> {
        let settings: Settings = busbar_contract::abi::sdk::cred::settings_lent(settings, secrets)
            .map_err(|_| "invalid primitive MySQL settings".to_owned())?;
        if settings.input_budget == 0 {
            return Err("input_budget must be positive".into());
        }
        let opts = Opts::from_captured(settings.url.0)
            .map_err(|_| "invalid primitive MySQL URL".to_owned())?;
        Ok(Self {
            opts: Arc::new(opts),
            pool: Pool::new(crate::KEPT_CONNECTIONS),
            own: Own::here(),
            budget: settings.input_budget,
            info: Arc::new(OnceLock::new()),
            horizons: Arc::new(Mutex::new(BTreeMap::new())),
            bootstrap: super::bootstrap::Bootstrap::new()?,
        })
    }
    fn connect(&self, op: &mut Op<'_>) -> Step<Result<(), String>> {
        let info = self.info.clone();
        on_conn!(
            self,
            op,
            "primitive MySQL connection unavailable".to_owned(),
            |conn| {
                let facts = schema::open(&mut conn)
                    .await
                    .map_err(|_| "primitive MySQL physical admission refused".to_owned())?;
                info.set(facts)
                    .map_err(|_| "primitive MySQL already connected".to_owned())
            }
        )
    }
    fn bootstrap(
        &self,
        op: &mut Op<'_>,
        request: &lifecycle::Request<Own>,
    ) -> Step<Result<lifecycle::Response<Own>, lifecycle::Error>> {
        self.bootstrap
            .call(op, self.opts.clone(), self.info.clone(), request)
    }
    fn connect_prepared(
        &self,
        op: &mut Op<'_>,
        binding: &lifecycle::OpenBinding,
    ) -> Step<Result<(), String>> {
        self.bootstrap
            .open(op, self.opts.clone(), self.info.clone(), binding)
    }
    fn info(&self) -> BackendInfo {
        *self.info.get().expect("connected primitive MySQL")
    }
    fn read(&self, op: &mut Op<'_>, request: &Read) -> Step<Result<ReadResult<Own>, Failure>> {
        let request = Read {
            dataset: request.dataset,
            addresses: request.addresses.clone(),
            time: request.time,
        };
        let info = self.info();
        on_conn!(self, op, Failure::Unavailable, |conn| native::read(
            &mut conn, info, &request
        )
        .await)
    }
    fn scan(&self, op: &mut Op<'_>, request: &Scan) -> Step<Result<Page<Own>, Failure>> {
        let request = Scan {
            dataset: request.dataset,
            namespace: request.namespace,
            prefix: request.prefix.clone(),
            after: request.after.clone(),
            generation: request.generation,
            allow_change: request.allow_change,
            max_items: request.max_items,
            max_bytes: request.max_bytes,
        };
        let info = self.info();
        on_conn!(self, op, Failure::Unavailable, |conn| native::scan(
            &mut conn, info, &request
        )
        .await)
    }
    fn commit(
        &self,
        op: &mut Op<'_>,
        request: &PreparedCandidate<Own>,
    ) -> Step<Result<Committed<Own>, Failure>> {
        let request = request.clone();
        let info = self.info();
        let horizons = self.horizons.clone();
        on_conn!(self, op, Failure::Unknown, |conn| {
            let result = native::commit(&mut conn, info, &request).await;
            // Receipt maintenance is a separate transaction and must never replace Applied.
            if matches!(
                &result,
                Ok(Committed {
                    decision: Decision::Applied(_),
                    ..
                })
            ) {
                let mut writers = BTreeSet::from([request.candidate().id.writer]);
                for mutation in &request.candidate().mutations {
                    if let Mutation::Put { address, .. } = mutation {
                        if address.namespace == control::NAMESPACE.0 {
                            if let Some(control::Key::Writer(writer)) =
                                control::Key::decode(&address.key)
                            {
                                writers.insert(writer);
                            }
                        }
                    }
                }
                let _ = native::maintain(&mut conn, &horizons, &writers).await;
            }
            result
        })
    }
    fn clock(
        &self,
        op: &mut Op<'_>,
        dataset: DatasetId,
    ) -> Step<Result<ClockObservation, Failure>> {
        let info = self.info();
        if dataset != info.dataset {
            return Step::Ready(Err(Failure::Refused));
        }
        on_conn!(self, op, Failure::Unavailable, |conn| native::clock(
            &mut conn, info
        )
        .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_budget_is_explicit_and_settings_are_strict() {
        assert!(
            MysqlV4::validate(br#"{"url":"mysql://user:password@localhost/database"}"#).is_err()
        );
        assert!(MysqlV4::validate(
            br#"{"url":"mysql://user:password@localhost/database","input_budget":0}"#
        )
        .is_err());
        assert!(MysqlV4::validate(
            br#"{"url":"mysql://user:password@localhost/database","input_budget":67108864}"#
        )
        .is_ok());
        assert!(MysqlV4::validate(br#"{"url":"mysql://user:password@localhost/database","input_budget":1,"unknown":true}"#).is_err());
    }
}
