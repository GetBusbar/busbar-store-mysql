// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::Retention;
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn wait_for_event_delete(db: &ScratchDb, holder: u64) -> mysql::Result<bool> {
    let mut observer = db.root.get_conn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let waiting: u64 = observer
            .exec_first(
                "SELECT COUNT(*) FROM performance_schema.data_lock_waits w \
                 JOIN performance_schema.data_locks l \
                   ON l.ENGINE_LOCK_ID = w.BLOCKING_ENGINE_LOCK_ID \
                 JOIN performance_schema.threads t ON t.THREAD_ID = l.THREAD_ID \
                 WHERE l.OBJECT_SCHEMA = :db AND l.OBJECT_NAME = 'plane_records' \
                   AND t.PROCESSLIST_ID = :holder",
                params! { "db" => &db.name, "holder" => holder },
            )?
            .unwrap();
        if waiting > 0 {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn an_age_sweep_never_deletes_a_late_eligible_task_without_its_events() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("task_age_race") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let (old, late, equal, newer) = ("age_old", "age_late", "age_equal", "age_newer");
    for task in [
        active_task(old, "working", 9),
        active_task(late, "input-required", 10),
        terminal_task(equal, "completed", 10),
        active_task(newer, "working", 11),
    ] {
        store.upsert_plane_record(task.view()).unwrap();
        store
            .append_plane_record(event_rec(&task.id, 1, "status", "", "one").view())
            .unwrap();
        store
            .append_plane_record(event_rec(&task.id, 2, "status", "one", "two").view())
            .unwrap();
    }
    assert_eq!(
        store
            .purge_plane_records("task", 10, Retention::TerminalOnly)
            .unwrap(),
        0,
        "terminal-only keeps active tasks and a terminal task exactly at the cutoff"
    );

    let mut raw = db.conn();
    let holder_id: u64 = raw.query_first("SELECT CONNECTION_ID()").unwrap().unwrap();
    let mut holder = raw.start_transaction(mysql::TxOpts::default()).unwrap();
    holder
        .exec_drop(
            "SELECT seq FROM plane_records \
             WHERE kind = 'task_event' AND ident = :id AND seq = 1 FOR UPDATE",
            params! { "id" => old },
        )
        .unwrap();

    let (waited, changed, released, written, removed) = std::thread::scope(|scope| {
        let cleanup = scope.spawn(|| store.purge_plane_records("task", 10, Retention::Age));
        let waited = wait_for_event_delete(&db, holder_id);
        let (sent, received) = mpsc::channel();
        let writer_store = &store;
        let writer = scope.spawn(move || {
            let result =
                writer_store.upsert_plane_record(active_task(late, "input-required", 9).view());
            let _ = sent.send(result);
        });
        let changed = received.recv_timeout(Duration::from_secs(5));

        let released = holder.rollback();
        let written = writer.join();
        let removed = cleanup.join();
        (waited, changed, released, written, removed)
    });
    assert!(waited.unwrap(), "the cascade reached the held event row");
    changed
        .expect("the second task changes while the cascade is still waiting")
        .unwrap();
    released.unwrap();
    written.unwrap();
    let removed = removed.unwrap().unwrap();
    assert!(get_task(&store, old).is_none());
    assert!(events_of(&store, old).is_empty());
    let late_remains = get_task(&store, late).is_some();
    assert!(
        late_remains || events_of(&store, late).is_empty(),
        "a task deleted during an Age sweep must take its entire event chain with it"
    );
    assert_eq!(removed, if late_remains { 1 } else { 2 });
    assert_eq!(
        events_of(&store, late).len(),
        if late_remains { 2 } else { 0 }
    );
    for task in [equal, newer] {
        assert_eq!(events_of(&store, task).len(), 2);
    }
    assert!(get_task(&store, equal).is_some());
    assert!(get_task(&store, newer).is_some());

    assert_eq!(
        store
            .purge_plane_records("task", 10, Retention::Age)
            .unwrap(),
        u64::from(late_remains),
        "the next sweep removes the newly eligible active task if it was left for later"
    );
    assert!(get_task(&store, late).is_none());
    assert!(events_of(&store, late).is_empty());
    assert_eq!(
        store
            .purge_plane_records("task", 11, Retention::TerminalOnly)
            .unwrap(),
        1
    );
    assert!(get_task(&store, equal).is_none());
    assert!(events_of(&store, equal).is_empty());
    assert_eq!(
        store
            .purge_plane_records("task", 11, Retention::Age)
            .unwrap(),
        0,
        "Age also keeps a task exactly at the cutoff"
    );
    assert!(get_task(&store, newer).is_some());
    assert_eq!(events_of(&store, newer).len(), 2);
    assert_eq!(
        store
            .purge_plane_records("task", 12, Retention::Age)
            .unwrap(),
        1
    );
    assert!(get_task(&store, newer).is_none());
    assert!(events_of(&store, newer).is_empty());
}

#[test]
fn an_age_sweep_rolls_back_the_parent_when_deleting_its_event_chain_fails() {
    let _ddl_guard = lock_fresh_database_ddl();
    let Some(db) = ScratchDb::new("task_age_rollback") else {
        return;
    };
    let store = MysqlStore::connect(&db.url).unwrap();
    let task = active_task("age_rollback", "working", 9);
    store.upsert_plane_record(task.view()).unwrap();
    for (seq, previous, hash) in [(1, "", "one"), (2, "one", "two")] {
        store
            .append_plane_record(event_rec(&task.id, seq, "status", previous, hash).view())
            .unwrap();
    }
    db.admin_conn()
        .query_drop(
            "CREATE TRIGGER refuse_age_event_delete BEFORE DELETE ON plane_records \
             FOR EACH ROW BEGIN IF OLD.kind = 'task_event' THEN \
             SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected event delete failure'; \
             END IF; END",
        )
        .unwrap();
    assert!(store
        .purge_plane_records("task", 10, Retention::Age)
        .is_err());
    assert!(get_task(&store, &task.id).is_some());
    assert_eq!(events_of(&store, &task.id).len(), 2);
    drop(store);
    let reopened = MysqlStore::connect(&db.url).unwrap();
    assert!(get_task(&reopened, &task.id).is_some());
    assert_eq!(events_of(&reopened, &task.id).len(), 2);
    db.conn()
        .query_drop("DROP TRIGGER refuse_age_event_delete")
        .unwrap();
    assert_eq!(
        reopened
            .purge_plane_records("task", 10, Retention::Age)
            .unwrap(),
        1
    );
    assert!(get_task(&reopened, &task.id).is_none());
    assert!(events_of(&reopened, &task.id).is_empty());
}
