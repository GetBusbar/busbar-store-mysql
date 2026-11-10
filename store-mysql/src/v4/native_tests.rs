// SPDX-License-Identifier: Apache-2.0
//! Explicit native witnesses, using the real linked v4 door and Host TCP fixture.
//! The configured URL must name a dedicated, empty disposable test database.
use busbar_contract::persistence::{control, *};
use busbar_contract::Secret;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
use mysql::prelude::Queryable;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use crate::test_mysql_io as mysql_io;

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}
fn open(url: &str) -> Arc<LoadedPersistence> {
    // Independent dispatchers model separate native writers. A shared default
    // dispatcher has one worker and serializes calls before database admission.
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let conns = mysql_io::host(dispatcher.conn_waker(), Default::default());
    let row =
        LinkedRow::of_kind::<StoreV4>(super::door as busbar_contract::abi::mechanism::door::DoorFn)
            .unwrap();
    static NEXT_INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let instance = NEXT_INSTANCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let plugin = load_linked::<StoreV4>(
        &row,
        Bind {
            instance: Arc::from(format!("mysql-v4-native-test-{instance}")),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(
                busbar_contract::conn::admissions::AdmissionAuthority::issue(
                    &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
                    conns.clone(),
                    Default::default(),
                ),
            ),
        },
    )
    .unwrap();
    let settings = serde_json::json!({"url":url,"input_budget":67108864}).to_string();
    Arc::new(
        run(LoadedPersistence::open(
            plugin,
            dispatcher.clone(),
            settings.as_bytes(),
            Limits {
                descriptor_bytes: 67108864,
                output_items: 1024,
                output_bytes: 67108864,
                decode_bytes: 67108864,
            },
        ))
        .expect("native v4 door opens"),
    )
}
fn at(namespace: NamespaceId, key: &[u8]) -> Address {
    Address {
        namespace: namespace.0,
        key: key.to_vec(),
    }
}
fn put(address: Address, value: &[u8]) -> Mutation {
    Mutation::Put {
        address,
        value: Secret::new(value.to_vec()),
    }
}
fn candidate(
    info: BackendInfo,
    operation: u8,
    epoch: u64,
    predicates: Vec<Predicate>,
    mutations: Vec<Mutation>,
    time: Option<TimeGuard>,
) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: info.dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: epoch,
            operation: [operation; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time,
        result: Secret::new(if operation == 1 {
            vec![]
        } else {
            vec![0, 255, operation]
        }),
    })
    .unwrap()
}
fn applied(store: &LoadedPersistence, candidate: PreparedCandidate) {
    let expected = candidate.candidate().result.clone();
    match run(store.commit(candidate)) {
        Ok(Decision::Applied(result)) => assert_eq!(result, expected),
        other => panic!("expected native Applied, got {other:?}"),
    }
}
fn scan_request(info: BackendInfo, namespace: NamespaceId, prefix: Vec<u8>) -> Scan {
    Scan {
        dataset: info.dataset,
        namespace,
        prefix,
        after: None,
        generation: None,
        allow_change: false,
        max_items: 2,
        max_bytes: 65536,
    }
}
fn raw_options(url: &str) -> mysql::Opts {
    // The independent SQL driver does not implement the SDK's RSA pin option.
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let query = query
        .split('&')
        .filter(|pair| {
            !pair.is_empty() && pair.split('=').next() != Some("server_public_key_sha256")
        })
        .collect::<Vec<_>>()
        .join("&");
    let url = if query.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{query}")
    };
    mysql::Opts::from_url(&url).unwrap()
}
fn raw(url: &str) -> mysql::Conn {
    mysql::Conn::new(raw_options(url)).unwrap()
}
fn observer(url: &str) -> mysql::Conn {
    // Native lock-wait metadata is a privileged fixture observation. Keep the
    // store under its scoped user; only this independent observer uses root.
    let password =
        std::env::var("BUSBAR_TEST_MYSQL_ROOT_PASSWORD").unwrap_or_else(|_| "busbar".into());
    let opts = mysql::OptsBuilder::from_opts(raw_options(url))
        .user(Some("root"))
        .pass(Some(password));
    mysql::Conn::new(opts).unwrap()
}
fn native_wait(conn: &mut mysql::Conn, at: &Address, statement: &str) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(15);
    let digest = address_hash(at)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    loop {
        // MySQL 8.4 can display a waiting read-only transaction as "not started"
        // in SHOW ENGINE. Its actual lock-wait edge remains explicit here.
        // Match the complete address digest (which includes the namespace),
        // primary index, real wait edge and expected statement together.
        // THREAD_ID belongs to the lock structure's creator, which can be a
        // purge thread after reuse. INNODB_TRX identifies its current requester.
        let waits: Vec<(String, u64, String)> = conn
            .query(
                "SELECT l.LOCK_DATA,i.TRX_MYSQL_THREAD_ID,i.TRX_QUERY \
             FROM performance_schema.data_lock_waits w \
             JOIN performance_schema.data_locks l \
               ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID \
             JOIN information_schema.INNODB_TRX i ON i.TRX_ID=w.REQUESTING_ENGINE_TRANSACTION_ID \
             WHERE l.OBJECT_SCHEMA=DATABASE() AND l.OBJECT_NAME='busbar_v4_records' \
               AND l.INDEX_NAME='PRIMARY' AND l.LOCK_TYPE='RECORD' \
               AND l.LOCK_STATUS='WAITING' AND l.LOCK_DATA IS NOT NULL \
               AND i.TRX_MYSQL_THREAD_ID IS NOT NULL AND i.TRX_QUERY IS NOT NULL",
            )
            .unwrap();
        for (data, thread, query) in waits {
            if data.to_ascii_uppercase().contains(&digest) && query.contains(statement) {
                return thread;
            }
        }
        assert!(
            Instant::now() < deadline,
            "exact native wait was not observed for {statement}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_until(conn: &mut mysql::Conn, expiry: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now: Option<u64> = conn
            .query_first("SELECT TIMESTAMPDIFF(SECOND,'1970-01-01 00:00:00',UTC_TIMESTAMP())")
            .unwrap();
        if now.is_some_and(|now| now >= expiry) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "native clock did not reach expiry"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn address_hash(address: &Address) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(address.namespace);
    digest.update(&address.key);
    digest.finalize().to_vec()
}
fn lock_record(conn: &mut mysql::Conn, address: &Address) {
    conn.query_drop("START TRANSACTION").unwrap();
    let rows: Vec<mysql::Row> = conn
        .exec(
            "SELECT value FROM busbar_v4_records WHERE namespace=? AND address_hash=? FOR UPDATE",
            (address.namespace.as_slice(), address_hash(address)),
        )
        .unwrap();
    assert_eq!(rows.len(), 1, "fixture locks an existing record");
}

#[test]
fn native_door_primitives_replay_and_serialization_boundaries() {
    let Ok(url) = std::env::var("BUSBAR_TEST_MYSQL_V4_URL") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI must provide a dedicated empty BUSBAR_TEST_MYSQL_V4_URL for native fault witnesses"
        );
        eprintln!("native v4 witness skipped: BUSBAR_TEST_MYSQL_V4_URL is unset");
        return;
    };
    let store = open(&url);
    let info = store.info();
    assert_eq!(info.durability, Durability::Local);
    assert_ne!(info.dataset.0, [0; 16]);
    let root = at(control::NAMESPACE, control::DATASET_KEY);
    let writer = at(control::NAMESPACE, &control::writer_key([2; 16]));
    let dataset = control::Dataset {
        id: info.dataset,
        writer_epoch: 1,
    }
    .encode()
    .unwrap();
    let initial = control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .unwrap();
    let bootstrap = candidate(
        info,
        1,
        1,
        vec![
            Predicate {
                address: root.clone(),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: writer.clone(),
                expected: ExpectedValue::Absent,
            },
        ],
        vec![put(root.clone(), &dataset), put(writer.clone(), &initial)],
        None,
    );
    applied(&store, bootstrap.clone());
    let reopened = open(&url);
    assert_eq!(reopened.info(), info);
    applied(&reopened, bootstrap);
    let namespace = NamespaceId([9; 16]);
    let prefix = vec![0; 4096];
    let make = |tail: &[u8]| {
        let mut key = prefix.clone();
        key.extend_from_slice(tail);
        key
    };
    let mut keys = vec![
        make(&[255]),
        make(&[1]),
        make(&[0, 1]),
        make(&[0]),
        make(&[2]),
    ];
    let mutations = keys
        .iter()
        .map(|key| put(at(namespace, key), &[0, 255, 1]))
        .collect();
    let write = candidate(info, 2, 1, vec![], mutations, None);
    // Discard the original return, then retry exactly through a reopened door.
    applied(&store, write.clone());
    applied(&reopened, write);
    keys.sort();
    let mut request = scan_request(info, namespace, prefix.clone());
    let first = run(store.scan(Arc::new(request))).unwrap();
    assert_eq!(
        first
            .rows
            .iter()
            .map(|(at, _)| at.key.clone())
            .collect::<Vec<_>>(),
        keys[..2]
    );
    let old_generation = first.generation;
    let mut observed = first
        .rows
        .iter()
        .map(|(at, _)| at.key.clone())
        .collect::<Vec<_>>();
    let mut cursor = first.next;
    while let Some(after) = cursor {
        request = scan_request(info, namespace, prefix.clone());
        request.after = Some(after);
        request.generation = Some(old_generation);
        let page = run(store.scan(Arc::new(request))).unwrap();
        observed.extend(page.rows.iter().map(|(at, _)| at.key.clone()));
        cursor = page.next;
    }
    assert_eq!(observed, keys);
    let read = run(store.read(Arc::new(Read {
        dataset: info.dataset,
        addresses: vec![at(namespace, &keys[0]), at(namespace, b"absent")],
        time: None,
    })))
    .unwrap();
    assert!(
        matches!(read,ReadResult::Values{values,..} if values==vec![Some(Secret::new(vec![0,255,1])),None])
    );
    applied(
        &store,
        candidate(
            info,
            3,
            1,
            vec![],
            vec![put(at(namespace, b"other"), b"x")],
            None,
        ),
    );
    request = scan_request(info, namespace, prefix.clone());
    request.after = Some(keys[1].clone());
    request.generation = Some(old_generation);
    assert!(matches!(
        run(store.scan(Arc::new(request))),
        Err(Failure::StaleScan)
    ));
    let generation_at = at(control::GENERATION_NAMESPACE, &namespace.0);
    assert!(matches!(
        run(store.commit(candidate(
            info,
            4,
            1,
            vec![Predicate {
                address: generation_at.clone(),
                expected: ExpectedValue::Exact(Secret::new(old_generation.to_le_bytes().to_vec()))
            }],
            vec![put(at(namespace, b"guarded"), b"x")],
            None
        ))),
        Ok(Decision::ConditionConflict)
    ));
    applied(
        &store,
        candidate(
            info,
            5,
            1,
            vec![],
            vec![Mutation::DeleteRange {
                namespace,
                prefix: prefix.clone(),
                exact_key_length: 4097,
            }],
            None,
        ),
    );
    let page = run(store.scan(Arc::new(scan_request(info, namespace, prefix.clone())))).unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].0.key, make(&[0, 1]));

    let mut fixture = raw(&url);
    let mut observer = observer(&url);
    eprintln!("native stage: blocked commit expiry");
    // Commit guard must sample after the writer's exclusive lock is released.
    lock_record(&mut fixture, &writer);
    let expiry = run(store.clock(info.dataset)).unwrap().unix_seconds + 2;
    let delayed = candidate(
        info,
        6,
        1,
        vec![],
        vec![put(at(namespace, b"expired"), b"x")],
        Some(TimeGuard {
            not_before: None,
            before: Some(expiry),
        }),
    );
    let worker = store.clone();
    let (sent, received) = mpsc::channel();
    let join = std::thread::spawn(move || sent.send(run(worker.commit(delayed))).unwrap());
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        matches!(received.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "worker finished instead of waiting"
    );
    native_wait(&mut observer, &writer, "SELECT address_hash");
    wait_until(&mut observer, expiry);
    fixture.query_drop("COMMIT").unwrap();
    assert!(matches!(
        received.recv_timeout(Duration::from_secs(5)).unwrap(),
        Ok(Decision::TimeGuardFailed { .. })
    ));
    join.join().unwrap();
    eprintln!("native stage: blocked read expiry");
    // Exact READ uses current shared locks; it must observe expiry after waiting.
    let existing = at(namespace, b"other");
    lock_record(&mut fixture, &existing);
    let expiry = run(store.clock(info.dataset)).unwrap().unix_seconds + 2;
    let read_at = existing.clone();
    let worker = store.clone();
    let (sent, received) = mpsc::channel();
    let join = std::thread::spawn(move || {
        sent.send(run(worker.read(Arc::new(Read {
            dataset: info.dataset,
            addresses: vec![existing],
            time: Some(TimeGuard {
                not_before: None,
                before: Some(expiry),
            }),
        }))))
        .unwrap()
    });
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        matches!(received.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "worker finished instead of waiting"
    );
    native_wait(&mut observer, &read_at, "SELECT raw_key,value");
    wait_until(&mut observer, expiry);
    fixture.query_drop("COMMIT").unwrap();
    assert!(matches!(
        received.recv_timeout(Duration::from_secs(5)).unwrap(),
        Ok(ReadResult::TimeGuardFailed { .. })
    ));
    join.join().unwrap();

    let admitted = control::Writer {
        retired_through: 0,
        admitted_through: 2,
    }
    .encode()
    .unwrap();
    applied(
        &store,
        candidate(
            info,
            7,
            1,
            vec![Predicate {
                address: writer.clone(),
                expected: ExpectedValue::Exact(Secret::new(initial.to_vec())),
            }],
            vec![put(writer.clone(), &admitted)],
            None,
        ),
    );
    eprintln!("native stage: retirement barrier");
    // An epoch-1 writer has passed authority admission and waits on its partition.
    lock_record(&mut fixture, &generation_at);
    let delayed = candidate(
        info,
        8,
        1,
        vec![],
        vec![put(at(namespace, b"before-retire"), b"x")],
        None,
    );
    let earlier_replay = delayed.clone();
    let worker = store.clone();
    let (sent, received) = mpsc::channel();
    let earlier = std::thread::spawn(move || sent.send(run(worker.commit(delayed))).unwrap());
    let earlier_thread = native_wait(&mut observer, &generation_at, "SELECT raw_key,value");
    let retired = control::Writer {
        retired_through: 1,
        admitted_through: 2,
    }
    .encode()
    .unwrap();
    let retirement = candidate(
        info,
        9,
        2,
        vec![Predicate {
            address: writer.clone(),
            expected: ExpectedValue::Exact(Secret::new(admitted.to_vec())),
        }],
        vec![put(
            at(control::NAMESPACE, &control::writer_key([2; 16])),
            &retired,
        )],
        None,
    );
    let worker = reopened.clone();
    let (sent_retired, received_retired) = mpsc::channel();
    let retiring =
        std::thread::spawn(move || sent_retired.send(run(worker.commit(retirement))).unwrap());
    std::thread::sleep(Duration::from_millis(200));
    match received_retired.try_recv() {
        Err(mpsc::TryRecvError::Empty) => (),
        other => panic!("retirement exited before fixture release: {other:?}"),
    }
    eprintln!("native retirement submitted: observing two native waiters");
    let retiring_thread = native_wait(&mut observer, &writer, "SELECT address_hash");
    assert_ne!(earlier_thread, retiring_thread);
    assert!(matches!(
        received.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let durable: Option<Vec<u8>> = observer
        .exec_first(
            "SELECT value FROM busbar_v4_records WHERE namespace=? AND address_hash=?",
            (writer.namespace.as_slice(), address_hash(&writer)),
        )
        .unwrap();
    assert_eq!(
        durable,
        Some(admitted.to_vec()),
        "retirement cannot advance the durable floor before the earlier writer finishes"
    );
    assert!(
        received_retired.try_recv().is_err(),
        "retirement must wait for the earlier admitted writer"
    );
    fixture.query_drop("COMMIT").unwrap();
    assert!(matches!(
        received.recv_timeout(Duration::from_secs(5)).unwrap(),
        Ok(Decision::Applied(_))
    ));
    let retired_result = received_retired
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    assert!(
        matches!(retired_result, Ok(Decision::Applied(_))),
        "retirement must apply without retry: {retired_result:?}"
    );
    earlier.join().unwrap();
    retiring.join().unwrap();
    assert!(matches!(
        run(store.commit(candidate(
            info,
            10,
            1,
            vec![],
            vec![put(at(namespace, b"too-late"), b"x")],
            None
        ))),
        Ok(Decision::ExpiredUnknown)
    ));
    applied(&store, earlier_replay.clone());
    // A matching receipt precedes authority decoding, even when a later physical
    // fault corrupts that authority. Failed separate maintenance cannot erase it.
    fixture
        .exec_drop(
            "UPDATE busbar_v4_records SET value=? WHERE namespace=? AND address_hash=?",
            (
                vec![0u8],
                writer.namespace.as_slice(),
                address_hash(&writer),
            ),
        )
        .unwrap();
    applied(&store, earlier_replay);
    println!("native v4 witness passed: metadata/reopen, receipts, full-key pages/range/generation, post-lock read/commit time, shared-lock retirement barrier");
}
