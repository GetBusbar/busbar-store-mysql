// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual linked and loadable native primitive images, including replay after unload.
mod common;
use busbar_contract::{
    persistence::{self as p, control, PersistenceBackend},
    Secret,
};
use busbar_plugin_loader::dispatch::{self, kinds::store_v4::StoreV4};
use std::sync::Arc;

#[test]
fn actual_linked_and_dropped_mysql_images_open_ready_read_and_close() {
    let server = match std::env::var("BUSBAR_TEST_MYSQL_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => panic!("CI requires BUSBAR_TEST_MYSQL_URL"),
        Err(_) => return,
    };
    let database = common::ScratchDb::new(&server);
    let library = common::plugin_path();
    let linked = common::connect_linked(&database.url).unwrap();
    let info = linked.info();
    let root = p::Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    };
    let writer = p::Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key([2; 16]).to_vec(),
    };
    let address = p::Address {
        namespace: [9; 16],
        key: b"real-image-reopen".to_vec(),
    };
    let bootstrap = p::PreparedCandidate::new(p::Candidate {
        id: p::AttemptId {
            dataset: info.dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [1; 16],
        },
        codec: p::CANDIDATE_VERSION,
        predicates: vec![
            p::Predicate {
                address: root.clone(),
                expected: p::ExpectedValue::Absent,
            },
            p::Predicate {
                address: writer.clone(),
                expected: p::ExpectedValue::Absent,
            },
        ],
        mutations: vec![
            p::Mutation::Put {
                address: root,
                value: Secret::new(
                    control::Dataset {
                        id: info.dataset,
                        writer_epoch: 1,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            },
            p::Mutation::Put {
                address: writer,
                value: Secret::new(
                    control::Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            },
        ],
        time: None,
        result: Secret::new(vec![]),
    })
    .unwrap();
    assert!(matches!(
        common::block(linked.commit(bootstrap)),
        Ok(p::Decision::Applied(_))
    ));
    let candidate = p::PreparedCandidate::new(p::Candidate {
        id: p::AttemptId {
            dataset: info.dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [2; 16],
        },
        codec: p::CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![p::Mutation::Put {
            address: address.clone(),
            value: Secret::new(vec![0, 255, 42]),
        }],
        time: None,
        result: Secret::new(vec![7, 0, 255]),
    })
    .unwrap();
    assert!(matches!(
        common::block(linked.commit(candidate.clone())),
        Ok(p::Decision::Applied(_))
    ));
    drop(linked);
    let (plugin, dispatcher) = common::native_plugin(Some(&library)).unwrap();
    let dropped = common::open_native(plugin, dispatcher, &database.url).unwrap();
    assert_eq!(dropped.info(), info);
    assert!(
        matches!(common::block(dropped.commit(candidate)),Ok(p::Decision::Applied(value)) if value==Secret::new(vec![7,0,255]))
    );
    let read = common::block(dropped.read(Arc::new(p::Read {
        dataset: info.dataset,
        addresses: vec![address],
        time: None,
    })))
    .unwrap();
    assert!(
        matches!(read,p::ReadResult::Values{values,..} if values==vec![Some(Secret::new(vec![0,255,42]))])
    );
}

#[test]
fn a_statement_that_is_not_the_librarys_own_is_refused() {
    let library = common::plugin_path();
    let stated = dispatch::rendering_of_library(&library).unwrap().unwrap();
    let actual = busbar_contract::abi::mechanism::rendering::read(&stated).unwrap();
    let mut changed = stated.clone();
    let at = changed
        .windows(actual.name.len())
        .position(|bytes| bytes == actual.name.as_bytes())
        .unwrap();
    changed[at] ^= 1;
    let dispatcher = Arc::new(dispatch::Dispatcher::new(
        dispatch::DispatchConfig::default(),
    ));
    let bind = dispatch::Bind {
        instance: Arc::from("mysql-mismatch"),
        max_inflight_cap: 64,
        sink: Arc::new(dispatch::NoSink),
        dispatcher: dispatcher.adopter(),
        conns: dispatch::ConnTable::Probe,
    };
    let error = dispatch::load_dropped::<StoreV4>(&library, &changed, bind)
        .err()
        .unwrap();
    assert_eq!(error, dispatch::LoadError::StatementMismatch);
}

#[test]
fn a_store_library_loaded_as_another_kind_is_refused() {
    let library = common::plugin_path();
    let stated = dispatch::rendering_of_library(&library).unwrap().unwrap();
    let dispatcher = Arc::new(dispatch::Dispatcher::new(
        dispatch::DispatchConfig::default(),
    ));
    let bind = dispatch::Bind {
        instance: Arc::from("mysql-wrong-kind"),
        max_inflight_cap: 64,
        sink: Arc::new(dispatch::NoSink),
        dispatcher: dispatcher.adopter(),
        conns: dispatch::ConnTable::Probe,
    };
    assert!(
        dispatch::load_dropped::<dispatch::kinds::secret::Secret>(&library, &stated, bind).is_err()
    );
}
