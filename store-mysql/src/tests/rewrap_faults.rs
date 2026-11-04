// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::credential_rewrap::{revision, rewrap, row};
use super::*;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn waiting_connection(db: &ScratchDb, holder: u64) -> mysql::Result<Option<u64>> {
    let mut observer = db.root.get_conn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let waiting: Option<u64> = observer.exec_first(
            "SELECT requester.PROCESSLIST_ID FROM performance_schema.data_lock_waits w \
             JOIN performance_schema.data_locks blocker \
               ON blocker.ENGINE_LOCK_ID = w.BLOCKING_ENGINE_LOCK_ID \
             JOIN performance_schema.threads owner ON owner.THREAD_ID = blocker.THREAD_ID \
             JOIN performance_schema.threads requester ON requester.THREAD_ID = w.REQUESTING_THREAD_ID \
             WHERE blocker.OBJECT_SCHEMA = :db AND blocker.OBJECT_NAME = 'api_keys' \
               AND owner.PROCESSLIST_ID = :holder LIMIT 1",
            params! { "db" => &db.name, "holder" => holder },
        )?;
        if waiting.is_some() || Instant::now() >= deadline {
            return Ok(waiting);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_server_disconnect_during_a_loaded_rewrap_rolls_back_the_transaction() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("rewrap_disconnect") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    store.put_key(&sample_key("owner", "hash")).unwrap();
    store
        .put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&store);
    let before = revision(&db);
    let mut raw = db.conn();
    let holder_id: u64 = raw.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
    let mut holder = raw.start_transaction(mysql::TxOpts::default()).unwrap();
    holder
        .query_drop("SELECT id FROM api_keys WHERE id='owner' FOR UPDATE")
        .unwrap();
    let (waiting, killed, released, outcome) = std::thread::scope(|scope| {
        let call = scope.spawn(|| rewrap(&store, &expected, "cancelled"));
        let waiting = waiting_connection(&db, holder_id);
        let killed = match &waiting {
            Ok(Some(connection)) => db
                .root
                .get_conn()
                .and_then(|mut c| c.query_drop(format!("KILL CONNECTION {connection}"))),
            _ => Ok(()),
        };
        let released = holder.rollback();
        let outcome = call.join();
        (waiting, killed, released, outcome)
    });
    assert!(
        waiting.unwrap().is_some(),
        "rewrap reached the locked owner"
    );
    killed.unwrap();
    released.unwrap();
    assert!(outcome.unwrap().is_err());
    assert!(row(&store) == expected);
    assert_eq!(revision(&db), before);
    assert!(rewrap(&store, &expected, "replacement").unwrap());
    assert_eq!(revision(&db), before + 1);
}

/// Forwards the real MySQL protocol, withholding exactly one armed COMMIT response after the server has sent its OK.
struct LostCommitReply {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    armed: Arc<AtomicBool>,
    swallowed: Arc<AtomicUsize>,
    sockets: Arc<Mutex<Vec<TcpStream>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

fn packet(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let len =
        usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
    let mut bytes = vec![0; len + header.len()];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}

fn forward_connection(
    mut client: TcpStream,
    mut server: TcpStream,
    armed: Arc<AtomicBool>,
    swallowed: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let pending = AtomicBool::new(false);
    let mut outgoing = server.try_clone()?;
    let mut incoming = client.try_clone()?;
    std::thread::scope(|scope| {
        let send = scope.spawn(|| {
            while let Ok(bytes) = packet(&mut incoming) {
                if bytes.get(4) == Some(&3)
                    && bytes[5..].eq_ignore_ascii_case(b"COMMIT")
                    && armed.swap(false, Ordering::SeqCst)
                {
                    pending.store(true, Ordering::SeqCst);
                }
                if outgoing.write_all(&bytes).is_err() {
                    break;
                }
            }
            let _ = incoming.shutdown(Shutdown::Both);
            let _ = outgoing.shutdown(Shutdown::Both);
        });
        while let Ok(bytes) = packet(&mut server) {
            if pending.swap(false, Ordering::SeqCst) {
                if bytes.get(4) == Some(&0) {
                    swallowed.fetch_add(1, Ordering::SeqCst);
                }
                break;
            }
            if client.write_all(&bytes).is_err() {
                break;
            }
        }
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        send.join().unwrap();
    });
    Ok(())
}

impl LostCommitReply {
    fn new(db_url: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let target = crate::mysqlwire::Opts::from_url(db_url).unwrap().target();
        let stop = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));
        let swallowed = Arc::new(AtomicUsize::new(0));
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let (stopping, arm, lost, connections) = (
            stop.clone(),
            armed.clone(),
            swallowed.clone(),
            sockets.clone(),
        );
        let worker = std::thread::spawn(move || {
            let mut workers = Vec::new();
            for client in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(client) = client else { break };
                let Ok(server) = TcpStream::connect(&target) else {
                    break;
                };
                for socket in [&client, &server] {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(30)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(30)))
                        .unwrap();
                }
                {
                    let mut sockets = connections.lock().unwrap();
                    if stopping.load(Ordering::SeqCst) {
                        let _ = client.shutdown(Shutdown::Both);
                        let _ = server.shutdown(Shutdown::Both);
                        break;
                    }
                    sockets.extend([client.try_clone().unwrap(), server.try_clone().unwrap()]);
                }
                let (armed, swallowed) = (arm.clone(), lost.clone());
                workers.push(std::thread::spawn(move || {
                    let _ = forward_connection(client, server, armed, swallowed);
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            address,
            stop,
            armed,
            swallowed,
            sockets,
            worker: Some(worker),
        }
    }

    fn url(&self, original: &str) -> String {
        let mut url = url::Url::parse(original).unwrap();
        url.set_host(Some("127.0.0.1")).unwrap();
        url.set_port(Some(self.address.port())).unwrap();
        url.into()
    }
}

impl Drop for LostCommitReply {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        for socket in self
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn a_lost_loaded_rewrap_commit_reply_is_reconciled_without_replaying_the_old_row() {
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("rewrap_reply") else {
        return;
    };
    let seed = MysqlStore::connect(&db.url).unwrap();
    seed.put_key(&sample_key("owner", "hash")).unwrap();
    seed.put_credential(&sample_credential("owner", "public", 0))
        .unwrap();
    let expected = row(&seed);
    let before = revision(&db);
    let proxy = LostCommitReply::new(&db.url);
    let store = MysqlStore::connect(&proxy.url(&db.url)).unwrap();
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(rewrap(&store, &expected, "committed").is_err());
    assert_eq!(proxy.swallowed.load(Ordering::SeqCst), 1);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    let current = row(&reopened);
    let mut wanted = expected.clone();
    wanted.secret = "committed".into();
    wanted.meta.revision = before + 1;
    assert!(current == wanted);
    assert_eq!(revision(&db), before + 1);
    assert!(!rewrap(&store, &expected, "replayed").unwrap());
    assert!(!rewrap(&store, &current, &current.secret).unwrap());
    assert!(row(&store) == current);
    assert_eq!(revision(&db), before + 1);
}

#[test]
fn a_conditional_record_commit_with_a_lost_ok_replays_only_the_identical_receipt() {
    use super::conditional_records::{absent_put, transact};
    use busbar_contract::abi::sdk::store::conditional::{Decision, Mutation};
    use busbar_contract::store_calls::StoreFailure;
    let _ddl = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("conditional_lost_ok") else {
        return;
    };
    let seed = MysqlStore::connect(&db.url).unwrap();
    let proxy = LostCommitReply::new(&db.url);
    let store = MysqlStore::connect(&proxy.url(&db.url)).unwrap();
    let request = absent_put(10, b"lost-ok", b"committed");
    let before = revision(&db);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        transact(&store, &request),
        Err(StoreFailure::Failed(_) | StoreFailure::Fault(_))
    ));
    assert_eq!(
        proxy.swallowed.load(Ordering::SeqCst),
        1,
        "the server sent a real COMMIT OK"
    );
    assert_eq!(
        seed.record_get("conditional", b"lost-ok")
            .unwrap()
            .unwrap()
            .as_slice(),
        b"committed"
    );

    seed.record_put("conditional", b"lost-ok", b"external")
        .unwrap();
    assert_eq!(transact(&store, &request), Ok(Decision::Applied));
    assert_eq!(
        seed.record_get("conditional", b"lost-ok")
            .unwrap()
            .unwrap()
            .as_slice(),
        b"external"
    );
    let mut changed = request.clone();
    changed.mutations = vec![Mutation::Delete {
        schema: "conditional".into(),
        key: b"lost-ok".to_vec(),
    }];
    assert_eq!(transact(&store, &changed), Err(StoreFailure::Conflict));
    assert_eq!(revision(&db), before);
}
