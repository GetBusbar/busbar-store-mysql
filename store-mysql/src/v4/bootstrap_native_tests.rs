// SPDX-License-Identifier: Apache-2.0
//! Actual pre-OPEN ABI/Host witness over a dedicated frozen source database.
use busbar_contract::{
    persistence::{
        self as p, control, lifecycle as l, lifecycle::PreparedStore, PersistenceBackend,
    },
    Secret,
};
use busbar_plugin_loader::{
    dispatch::{
        kinds::store_v4::StoreV4, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher,
        LinkedRow, NoSink,
    },
    store_v4::{Limits, LoadedPrepared},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn at(namespace: [u8; 16], key: &[u8]) -> p::Address {
    p::Address {
        namespace,
        key: key.to_vec(),
    }
}
fn put(address: p::Address, value: &[u8]) -> p::Mutation {
    p::Mutation::Put {
        address,
        value: Secret::new(value.to_vec()),
    }
}
fn candidate(
    info: p::BackendInfo,
    op: u8,
    predicates: Vec<p::Predicate>,
    mutations: Vec<p::Mutation>,
) -> p::PreparedCandidate {
    p::PreparedCandidate::new(p::Candidate {
        id: p::AttemptId {
            dataset: info.dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [op; 16],
        },
        codec: p::CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(if op == 1 { Vec::new() } else { vec![op] }),
    })
    .unwrap()
}
async fn applied(store: &dyn PersistenceBackend, candidate: p::PreparedCandidate) {
    let expected = candidate.candidate().result.clone();
    assert!(
        matches!(store.commit(candidate).await.unwrap(),p::Decision::Applied(result) if result==expected)
    );
}
fn prepared(url: &str) -> LoadedPrepared {
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    dispatcher.install_runtime(tokio::runtime::Handle::current());
    dispatcher.install_io(busbar_core_connector::hostio::process());
    let conns = crate::test_mysql_io::host(dispatcher.conn_waker(), Default::default());
    let row =
        LinkedRow::of_kind::<StoreV4>(super::door as busbar_contract::abi::mechanism::door::DoorFn)
            .unwrap();
    let plugin = load_linked::<StoreV4>(
        &row,
        Bind {
            instance: Arc::from("mysql-preopen-native"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(conns),
        },
    )
    .unwrap();
    let settings = serde_json::json!({"url":url,"input_budget":16777216}).to_string();
    LoadedPrepared::new(
        plugin,
        dispatcher,
        settings.as_bytes(),
        Limits {
            descriptor_bytes: 16777216,
            output_items: 256,
            output_bytes: 16777216,
            decode_bytes: 16777216,
        },
    )
    .unwrap()
}

#[test]
#[ignore = "requires dedicated frozen released DB in BUSBAR_MYSQL_CHANNELS_URL"]
fn native_preopen_channels_snapshot_target_and_phase_proofs() {
    let url = std::env::var("BUSBAR_MYSQL_CHANNELS_URL").unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let prepared = prepared(&url);
            assert_eq!(prepared.phase(), l::Phase::Bound);
            let inspected = prepared
                .bootstrap(Arc::new(l::Request::Inspect {
                    bounds: l::Bounds {
                        items: 256,
                        bytes: 1048576,
                    },
                }))
                .await
                .unwrap();
            let l::Response::Inspected(inspected) = inspected.as_ref() else {
                panic!("inspection response");
            };
            assert_eq!(inspected.state, l::InspectionState::Legacy);
            let source = inspected.source.clone().unwrap();
            assert_eq!(source.format.unwrap().physical, 3);
            assert_eq!(prepared.phase(), l::Phase::Prepared);
            let mut wrong_source = source.clone();
            wrong_source.native_anchor[0] ^= 1;
            assert_eq!(
                prepared
                    .bootstrap(Arc::new(l::Request::BeginOrResume {
                        expected_source: wrong_source,
                        route_digest: [2; 32],
                        target_format: l::CORE_FORMAT,
                        operation_id: [1; 16],
                    }))
                    .await
                    .unwrap_err(),
                l::Error::SourceChanged
            );
            let begun = prepared
                .bootstrap(Arc::new(l::Request::BeginOrResume {
                    expected_source: source.clone(),
                    route_digest: [2; 32],
                    target_format: l::CORE_FORMAT,
                    operation_id: [1; 16],
                }))
                .await
                .unwrap();
            let l::Response::Begun(begun) = begun.as_ref() else {
                panic!("begun response");
            };
            assert_eq!(begun.source, source);
            assert_ne!(begun.snapshot, [0; 16]);
            let upgrade = begun.reference.clone();
            let info = begun.target;
            let table = begun
                .catalogue
                .iter()
                .position(|t| t.name == "api_keys")
                .unwrap() as u32;
            let page = Arc::new(l::Request::SourcePage {
                upgrade: upgrade.clone(),
                snapshot: begun.snapshot,
                family: *b"legacy.mysql..v1",
                selector: l::SourceSelector::Scan { table },
                cursor: None,
                bounds: l::Bounds {
                    items: 1,
                    bytes: 16384,
                },
            });
            let first = prepared.bootstrap(page.clone()).await.unwrap();
            let replay = prepared.bootstrap(page).await.unwrap();
            let (l::Response::SourcePage(first), l::Response::SourcePage(replay)) =
                (first.as_ref(), replay.as_ref())
            else {
                panic!("source page response");
            };
            assert_eq!(first.coverage_digest, replay.coverage_digest);
            assert_eq!(first.rows.len(), 1);
            assert_eq!(first.rows[0].value, replay.rows[0].value);
            let exact = prepared
                .bootstrap(Arc::new(l::Request::SourcePage {
                    upgrade: upgrade.clone(),
                    snapshot: begun.snapshot,
                    family: *b"legacy.mysql..v1",
                    selector: l::SourceSelector::Exact {
                        table,
                        key: first.rows[0].native_key.clone(),
                    },
                    cursor: None,
                    bounds: l::Bounds {
                        items: 1,
                        bytes: 16384,
                    },
                }))
                .await
                .unwrap();
            let l::Response::SourcePage(exact) = exact.as_ref() else {
                panic!("exact native PK response");
            };
            assert_eq!(exact.rows.len(), 1);
            assert_eq!(exact.rows[0].value, first.rows[0].value);
            assert!(exact.next.is_none());

            let next = prepared
                .bootstrap(Arc::new(l::Request::SourcePage {
                    upgrade: upgrade.clone(),
                    snapshot: begun.snapshot,
                    family: *b"legacy.mysql..v1",
                    selector: l::SourceSelector::Scan { table },
                    cursor: first.next.clone(),
                    bounds: l::Bounds {
                        items: 1,
                        bytes: 16384,
                    },
                }))
                .await
                .unwrap();
            let l::Response::SourcePage(next) = next.as_ref() else {
                panic!("next page");
            };
            assert_eq!(next.rows.len(), 1);
            assert_ne!(first.rows[0].native_key, next.rows[0].native_key);
            assert!(matches!(
                prepared
                    .bootstrap(Arc::new(l::Request::CheckFence {
                        upgrade: upgrade.clone()
                    }))
                    .await
                    .unwrap()
                    .as_ref(),
                l::Response::Fence(_)
            ));
            let target = prepared.target(upgrade.clone()).await.unwrap();
            assert_eq!(target.info(), info);
            assert_eq!(target.upgrade_id(), upgrade.id);
            let root = at(control::NAMESPACE.0, control::DATASET_KEY);
            let writer = at(control::NAMESPACE.0, &control::writer_key([2; 16]));
            let dataset = control::Dataset {
                id: info.dataset,
                writer_epoch: 1,
            }
            .encode()
            .unwrap();
            let writer_value = control::Writer {
                retired_through: 0,
                admitted_through: 1,
            }
            .encode()
            .unwrap();
            applied(
                target.as_ref(),
                candidate(
                    info,
                    1,
                    vec![
                        p::Predicate {
                            address: root.clone(),
                            expected: p::ExpectedValue::Absent,
                        },
                        p::Predicate {
                            address: writer.clone(),
                            expected: p::ExpectedValue::Absent,
                        },
                    ],
                    vec![put(root, &dataset), put(writer, &writer_value)],
                ),
            )
            .await;
            let checkpoint = at([31; 16], b"checkpoint");
            let mut activation = None;
            let mut original_activation = None;
            for (op, phase, value) in [
                (
                    2,
                    l::CompletionPhase::Activation,
                    b"activation-checkpoint".as_slice(),
                ),
                (
                    3,
                    l::CompletionPhase::Complete,
                    b"complete-checkpoint".as_slice(),
                ),
            ] {
                let digest = Sha256::digest(value).into();
                let marker = l::CompletionMarker {
                    version: l::VERSION,
                    phase,
                    upgrade: upgrade.id,
                    source: source.dataset,
                    target: info.dataset,
                    checkpoint_address: checkpoint.clone(),
                    checkpoint_value_digest: digest,
                };
                let marker = l::codec::encode_completion_marker(
                    &marker,
                    l::Bounds {
                        items: 1,
                        bytes: 4096,
                    },
                )
                .unwrap();
                let commit = candidate(
                    info,
                    op,
                    Vec::new(),
                    vec![
                        put(checkpoint.clone(), value),
                        p::Mutation::Put {
                            address: l::completion_marker_address(upgrade.id),
                            value: marker,
                        },
                    ],
                );
                let proof = l::ActivationReceipt {
                    attempt: commit.candidate().id,
                    candidate_fingerprint: commit.fingerprint(),
                    original_result: commit.candidate().result.clone(),
                    checkpoint_address: checkpoint.clone(),
                    checkpoint_value_digest: digest,
                    phase,
                };
                if phase==l::CompletionPhase::Activation{original_activation=Some(proof.clone());}
                applied(target.as_ref(), commit).await;
                if phase==l::CompletionPhase::Complete {
                    let replay=prepared.bootstrap(Arc::new(l::Request::Finish{upgrade:upgrade.clone(),activation_receipt:original_activation.clone().unwrap()})).await.unwrap();
                    assert!(matches!(replay.as_ref(),l::Response::RecoveryReady(ready)if ready.target==info.dataset));
                    assert!(prepared.serving().is_err());
                }
                let finished = prepared
                    .bootstrap(Arc::new(l::Request::Finish {
                        upgrade: upgrade.clone(),
                        activation_receipt: proof.clone(),
                    }))
                    .await
                    .unwrap();
                if phase == l::CompletionPhase::Activation {
                    let l::Response::RecoveryReady(ready) = finished.as_ref() else {
                        panic!("recovery proof");
                    };
                    assert!(prepared.serving().is_err());
                    let opened = prepared
                        .open(l::OpenBinding::Recovery(ready.clone()))
                        .await
                        .unwrap();
                    assert_eq!(opened.info(), info);
                    assert!(prepared.serving().is_err());
                    let mut forged = proof.clone();
                    forged.phase = l::CompletionPhase::Complete;
                    assert_eq!(
                        prepared
                            .bootstrap(Arc::new(l::Request::Finish {
                                upgrade: upgrade.clone(),
                                activation_receipt: forged
                            }))
                            .await
                            .unwrap_err(),
                        l::Error::Refused
                    );
                    activation = Some(opened);
                } else {
                    assert!(matches!(finished.as_ref(), l::Response::ServingReady(_)));
                    let serving = prepared.serving().unwrap();
                    assert!(Arc::ptr_eq(&serving, activation.as_ref().unwrap()));
                }
            }
        });
}

#[test]
#[ignore = "requires dedicated empty DB in BUSBAR_MYSQL_EMPTY_URL"]
fn native_empty_origin_refuses_old_startup_and_opaque_orphans() {
    use mysql::prelude::Queryable;
    let url = std::env::var("BUSBAR_MYSQL_EMPTY_URL").unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async{
        let first=prepared(&url);
        let inspected=first.bootstrap(Arc::new(l::Request::Inspect{bounds:l::Bounds{items:256,bytes:1048576}})).await.unwrap();
        assert!(matches!(inspected.as_ref(),l::Response::Inspected(i)if i.state==l::InspectionState::Empty));
        let opened=first.open(l::OpenBinding::Empty).await.unwrap();assert_eq!(opened.info().physical_version,1);
        let second=prepared(&url);
        let inspected=second.bootstrap(Arc::new(l::Request::Inspect{bounds:l::Bounds{items:256,bytes:1048576}})).await.unwrap();
        assert!(matches!(inspected.as_ref(),l::Response::Inspected(i)if i.state==l::InspectionState::Empty));
        let mut old=mysql::Conn::new(mysql::Opts::from_url(&url).unwrap()).unwrap();
        // Exact first released startup CREATE and the immediately following
        // version read; its u32 parse fails BEFORE its remaining source DDL.
        old.query_drop("CREATE TABLE IF NOT EXISTS store_meta (k VARCHAR(191) PRIMARY KEY,v TEXT NOT NULL) ENGINE=InnoDB").unwrap();
        let version:Option<String>=old.query_first("SELECT v FROM store_meta WHERE k='schema_version'").unwrap();
        assert!(version.unwrap().parse::<u32>().is_err());
        let source_tables:Option<u64>=old.query_first("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('api_keys','credentials','denylist','store_sequence','usage_windows','usage_metering','audit_log')").unwrap();assert_eq!(source_tables,Some(0));
        let error=old.query_drop("INSERT INTO store_meta(k,v) VALUES('schema_version','3') ON DUPLICATE KEY UPDATE v='3'").unwrap_err();assert!(matches!(error,mysql::Error::MySqlError(ref e)if e.code==1644));
        // A current physical shell may be called Empty only while *all* opaque
        // rows, receipts and authority are absent. No missing marker heuristic.
        let address=at([55;16],b"orphan");let mut hash=Sha256::new();hash.update(address.namespace);hash.update(&address.key);let hash=hash.finalize().to_vec();
        old.exec_drop("INSERT INTO busbar_v4_records(namespace,address_hash,raw_key,value) VALUES(?,?,?,?)",(address.namespace.as_slice(),hash,address.key,b"opaque-without-admission".as_slice())).unwrap();
        let broken=prepared(&url);
        assert_eq!(broken.bootstrap(Arc::new(l::Request::Inspect{bounds:l::Bounds{items:256,bytes:1048576}})).await.unwrap_err(),l::Error::Refused);
    });
}

#[test]
#[ignore = "requires dedicated frozen released DB in BUSBAR_MYSQL_RESUME_URL"]
fn native_preopen_restart_retains_target_receipt_and_source_cursor() {
    use mysql::prelude::Queryable;
    let url = std::env::var("BUSBAR_MYSQL_RESUME_URL").unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let first = prepared(&url);
            let bounds = l::Bounds {
                items: 256,
                bytes: 1048576,
            };
            let inspection = first
                .bootstrap(Arc::new(l::Request::Inspect { bounds }))
                .await
                .unwrap();
            let l::Response::Inspected(inspection) = inspection.as_ref() else {
                panic!("inspect");
            };
            let source = inspection.source.clone().unwrap();
            let begin = Arc::new(l::Request::BeginOrResume {
                expected_source: source.clone(),
                route_digest: [42; 32],
                target_format: l::CORE_FORMAT,
                operation_id: [41; 16],
            });
            let begun = first.bootstrap(begin.clone()).await.unwrap();
            let l::Response::Begun(begun) = begun.as_ref() else {
                panic!("begin");
            };
            let info = begun.target;
            let id = begun.reference.id;
            let snapshot = begun.snapshot;
            let table = begun
                .catalogue
                .iter()
                .position(|t| t.name == "api_keys")
                .unwrap() as u32;
            let page = first
                .bootstrap(Arc::new(l::Request::SourcePage {
                    upgrade: begun.reference.clone(),
                    snapshot,
                    family: *b"legacy.mysql..v1",
                    selector: l::SourceSelector::Scan { table },
                    cursor: None,
                    bounds: l::Bounds {
                        items: 1,
                        bytes: 16384,
                    },
                }))
                .await
                .unwrap();
            let l::Response::SourcePage(page) = page.as_ref() else {
                panic!("page");
            };
            let saved_cursor = page.next.clone();
            let first_key = page.rows[0].native_key.clone();
            let source_digest = page.source_digest;
            let target = first.target(begun.reference.clone()).await.unwrap();
            let root = at(control::NAMESPACE.0, control::DATASET_KEY);
            let writer = at(control::NAMESPACE.0, &control::writer_key([2; 16]));
            let dataset = control::Dataset {
                id: info.dataset,
                writer_epoch: 1,
            }
            .encode()
            .unwrap();
            let writer_value = control::Writer {
                retired_through: 0,
                admitted_through: 1,
            }
            .encode()
            .unwrap();
            applied(
                target.as_ref(),
                candidate(
                    info,
                    1,
                    vec![
                        p::Predicate {
                            address: root.clone(),
                            expected: p::ExpectedValue::Absent,
                        },
                        p::Predicate {
                            address: writer.clone(),
                            expected: p::ExpectedValue::Absent,
                        },
                    ],
                    vec![put(root, &dataset), put(writer, &writer_value)],
                ),
            )
            .await;
            let address = at([56; 16], b"retained-copy");
            let copied = candidate(
                info,
                9,
                Vec::new(),
                vec![put(address.clone(), b"exact retained target")],
            );
            applied(target.as_ref(), copied.clone()).await;
            drop(target);
            drop(first);
            // Wait on the actual native ownership lock, not a guessed wall-clock
            // delay. This observes that teardown released the old session's owner.
            let mut observer = mysql::Conn::new(mysql::Opts::from_url(&url).unwrap()).unwrap();
            let lock: Option<u64> = observer
                .query_first(
                    "SELECT GET_LOCK(CONCAT('busbar-upgrade:',LEFT(SHA2(DATABASE(),256),48)),5)",
                )
                .unwrap();
            assert_eq!(lock, Some(1));
            let released: Option<u64> = observer
                .query_first(
                    "SELECT RELEASE_LOCK(CONCAT('busbar-upgrade:',LEFT(SHA2(DATABASE(),256),48)))",
                )
                .unwrap();
            assert_eq!(released, Some(1));
            drop(observer);
            let second = prepared(&url);
            let inspected = second
                .bootstrap(Arc::new(l::Request::Inspect { bounds }))
                .await
                .unwrap();
            let l::Response::Inspected(inspected) = inspected.as_ref() else {
                panic!("reinspect");
            };
            assert_eq!(inspected.state, l::InspectionState::InProgress);
            assert_eq!(inspected.source.as_ref(), Some(&source));
            let resumed = second.bootstrap(begin).await.unwrap();
            let l::Response::Begun(resumed) = resumed.as_ref() else {
                panic!("resume");
            };
            assert_eq!(resumed.reference.id, id);
            assert_eq!(resumed.snapshot, snapshot);
            assert_eq!(resumed.target, info);
            assert_ne!(resumed.reference.authority, begun.reference.authority);
            let target = second.target(resumed.reference.clone()).await.unwrap();
            applied(target.as_ref(), copied).await;
            let read = target
                .read(Arc::new(p::Read {
                    dataset: info.dataset,
                    addresses: vec![address],
                    time: None,
                }))
                .await
                .unwrap();
            let p::ReadResult::Values { values, .. } = read else {
                panic!("read");
            };
            assert_eq!(
                values,
                vec![Some(Secret::new(b"exact retained target".to_vec()))]
            );
            let page = second
                .bootstrap(Arc::new(l::Request::SourcePage {
                    upgrade: resumed.reference.clone(),
                    snapshot,
                    family: *b"legacy.mysql..v1",
                    selector: l::SourceSelector::Scan { table },
                    cursor: saved_cursor,
                    bounds: l::Bounds {
                        items: 1,
                        bytes: 16384,
                    },
                }))
                .await
                .unwrap();
            let l::Response::SourcePage(page) = page.as_ref() else {
                panic!("resume page");
            };
            assert_eq!(page.source_digest, source_digest);
            assert_eq!(page.rows.len(), 1);
            assert_ne!(page.rows[0].native_key, first_key);
        });
}
