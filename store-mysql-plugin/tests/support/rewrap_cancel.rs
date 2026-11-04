// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, OutHead, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::sdk::store::rewrap;
use busbar_contract::abi::store::{slot, BlobIn};
use busbar_contract::records::{CredentialMeta, CredentialSecret, SecretForm};
use busbar_plugin_loader::dispatch::{in_head, out_head, Frame};
use mysql::params;
use mysql::prelude::Queryable;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static CANCEL_DDL: Mutex<()> = Mutex::new(());

struct PrivateDb {
    name: String,
    url: String,
    settings: Vec<u8>,
}

impl PrivateDb {
    fn new(server: &str) -> Self {
        let name = format!("busbar_rewrap_cancel_{}", common::node());
        let (scheme, rest) = server
            .split_once("://")
            .expect("the MySQL URL names its scheme");
        let (authority, tail) = rest
            .split_once('/')
            .expect("the MySQL URL names its database");
        let query = tail.find('?').map_or("", |at| &tail[at..]);
        let url = format!("{scheme}://{authority}/{name}{query}");
        let settings = serde_json::json!({ "url": url }).to_string().into_bytes();
        create_fold_database(&name, &settings);
        Self {
            name,
            url,
            settings,
        }
    }

    fn conn(&self) -> mysql::Conn {
        mysql::Conn::new(mysql::Opts::from_url(&crate::common::raw_mysql_url(&self.url)).unwrap())
            .unwrap()
    }

    fn revision(&self) -> u64 {
        self.conn()
            .query_first("SELECT revision FROM store_sequence WHERE id=1")
            .unwrap()
            .unwrap()
    }

    fn waiting_connection(&self, holder: u64) -> mysql::Result<Option<u64>> {
        let (mut observer, _) = fold_root(&self.settings);
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
                params! { "db" => &self.name, "holder" => holder },
            )?;
            if waiting.is_some() || Instant::now() >= deadline {
                return Ok(waiting);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn disconnected(&self, connection: u64) -> mysql::Result<bool> {
        let (mut observer, _) = fold_root(&self.settings);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining: u64 = observer.exec_first(
                "SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_ID=:connection",
                params! { "connection" => connection },
            )?.unwrap();
            if remaining == 0 {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for PrivateDb {
    fn drop(&mut self) {
        drop_fold_database(&self.name, &self.settings);
    }
}

struct RequestBytes {
    record: Vec<u8>,
    extensions: Vec<u8>,
}

impl RequestBytes {
    fn frame(&self) -> Frame<BlobIn, OutHead> {
        let mut head = in_head();
        head.extensions = Blob {
            ptr: self.extensions.as_ptr(),
            len: self.extensions.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        Frame::new(
            BlobIn {
                head,
                record: Blob {
                    ptr: self.record.as_ptr(),
                    len: self.record.len(),
                    fmt: BLOB_JSON,
                    flags: BLOB_SECRET,
                },
            },
            out_head(),
        )
    }
}

fn credential(store: &LoadedStore) -> CredentialSecret {
    store
        .list_credentials_since(0)
        .unwrap()
        .into_iter()
        .find(|c| c.meta.id == "cancel_credential")
        .unwrap()
}

fn cancel_pending_rewrap(load: impl Fn() -> Loaded, server: &str) {
    let db = PrivateDb::new(server);
    let (plugin, dispatcher) = load();
    let store = LoadedStore::open(plugin, dispatcher.clone(), &db.settings, mint).unwrap();
    store
        .put_key(&VirtualKey {
            id: "cancel_owner".into(),
            generation_hash: "cancel-owner-hash".into(),
            enabled: true,
            created_at: 1,
            ..VirtualKey::default()
        })
        .unwrap();
    store
        .put_credential(&CredentialSecret {
            meta: CredentialMeta {
                id: "cancel_credential".into(),
                key_id: "cancel_owner".into(),
                kind: "sigv4".into(),
                slot: 0,
                public_id: "cancel_public".into(),
                secret_form: SecretForm::Recoverable,
                created_at: 1,
                updated_at: 1,
                expires_at: None,
                revoked_at: None,
                revoke_reason: None,
                revision: 0,
            },
            secret: "v1:plain:cancel-original".into(),
        })
        .unwrap();
    let expected = credential(&store);
    let before = db.revision();
    let mut raw = db.conn();
    let holder_id: u64 = raw.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
    let mut holder = raw.start_transaction(mysql::TxOpts::default()).unwrap();
    holder
        .query_drop("SELECT id FROM api_keys WHERE id='cancel_owner' FOR UPDATE")
        .unwrap();
    let owner = Arc::new(RequestBytes {
        record: serde_json::to_vec(&rewrap::Request::new(&expected, "v1:plain:cancelled")).unwrap(),
        extensions: extensions::encode(&[(rewrap::INTENT, b"1")]),
    });
    let weak = Arc::downgrade(&owner);
    let ticket = dispatcher.mint(0).unwrap();
    let reply = dispatcher.submit_lent(
        store.plugin(),
        ticket,
        slot::PUT_CREDENTIAL,
        owner.frame(),
        DeadlineClass::Call,
        0,
        owner.clone(),
    );
    let waiting = db.waiting_connection(holder_id);
    let unfinished = reply.wait(Duration::ZERO).is_none();

    drop(owner);
    drop(reply);
    let deadline = Instant::now() + Duration::from_secs(5);
    while weak.strong_count() != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let released_request = weak.strong_count() == 0;

    let released_holder = holder.rollback();
    let disconnected = match &waiting {
        Ok(Some(connection)) => db.disconnected(*connection),
        _ => Ok(false),
    };

    if released_request {
        dispatcher.recycle(ticket);
    }
    assert!(
        waiting.unwrap().is_some(),
        "the submitted ABI operation reached the held owner row"
    );
    assert!(
        unfinished,
        "the submitted reply is still waiting for that operation"
    );
    assert!(
        released_request,
        "CANCEL finished and released the lent request"
    );
    assert!(
        disconnected.unwrap(),
        "the cancelled transaction's connection is gone after the server leaves its lock wait"
    );
    released_holder.unwrap();
    assert!(credential(&store) == expected);
    assert_eq!(db.revision(), before);
    assert!(store
        .rewrap_credential(&expected, "v1:plain:replacement")
        .unwrap());
    let current = credential(&store);
    let mut wanted = expected.clone();
    wanted.secret = "v1:plain:replacement".into();
    wanted.meta.revision = before + 1;
    assert!(current == wanted);
    assert_eq!(db.revision(), before + 1);
    drop(store);
    let (plugin, dispatcher) = load();
    let reopened = LoadedStore::open(plugin, dispatcher, &db.settings, mint).unwrap();
    assert!(credential(&reopened) == current);
    assert!(!reopened
        .rewrap_credential(&expected, "v1:plain:stale")
        .unwrap());
    assert_eq!(db.revision(), before + 1);
}

#[test]
fn dropping_a_linked_pending_rewrap_reply_cancels_its_parked_transaction() {
    let _ddl = CANCEL_DDL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(server) = mysql_url() else { return };
    cancel_pending_rewrap(linked, &server);
}

#[test]
fn dropping_a_dropped_in_pending_rewrap_reply_cancels_its_parked_transaction() {
    let _ddl = CANCEL_DDL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(server) = mysql_url() else { return };
    let library = cdylib();
    let stated = packed_rendering(&library);
    cancel_pending_rewrap(|| dropped(&library, &stated), &server);
}
