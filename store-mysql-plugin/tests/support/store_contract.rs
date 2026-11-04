// SPDX-License-Identifier: Apache-2.0
//! MySQL's ordinary tests over all 31 store slots, migrated from the pinned store script.
use super::*;
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta, ScopeRef, SecretForm,
    UsageLedger,
};
use busbar_contract::store_calls::StoreCalls;
use std::fmt::{Debug, Display};
use std::sync::atomic::Ordering;
const _: () = assert!(busbar_contract::abi::store::KIND_SLOTS == 31);
const LEASED: u64 = 2;
const LIVE_REPLAY_DEADLINE: u64 = u64::MAX;
fn ans<T: Debug, E: Display>(r: Result<T, E>) -> String {
    match r {
        Ok(v) => format!("= {v:?}"),
        Err(e) => format!("! {e}"),
    }
}
fn text_of(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}
fn block<T>(rt: &tokio::runtime::Runtime, f: impl std::future::Future<Output = T>) -> T {
    rt.block_on(f)
}
fn op(n: u64) -> OpId {
    OpId::from_parts(2, n)
}
fn key(id: &str, group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h_{id}"),
        name: format!("key {id}"),
        enabled: true,
        group: group.map(str::to_string),
        created_at: 100,
        ..Default::default()
    }
}

fn delta(requests: i64, input: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("input".to_string(), input)].into_iter().collect(),
        }],
    }
}

fn meter(key_id: &str, provider: &str, input: u64) -> MeteringDelta {
    MeteringDelta {
        key_id: key_id.into(),
        bucket: 86_400,
        model: "m".into(),
        provider: provider.into(),
        tokens_input: input,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    }
}

fn secret(kind: &str, id: &str, key_id: &str, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.into(),
            key_id: key_id.into(),
            kind: kind.into(),
            slot: 0,
            public_id: public_id.into(),
            secret_form: SecretForm::Recoverable,
            created_at: 5,
            updated_at: 5,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: format!("v1:plain:s3cret-{id}"),
    }
}

fn plane(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: &[u8]) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(str::to_string),
        seq,
        ts: 7,
        disposition: if seq == 2 {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: body.to_vec(),
    }
}

fn scoped_key() -> VirtualKey {
    VirtualKey {
        id: "vk_scopekinds".into(),
        generation_hash: "binding:vk_scopekinds:1".into(),
        name: "scope-kinds".into(),
        allowed_scopes: Some(vec![
            ScopeRef::pool("fast"),
            ScopeRef {
                kind: "engine_server".into(),
                value: "filesystem".into(),
            },
            ScopeRef {
                kind: "engine_tool".into(),
                value: "filesystem_read_file".into(),
            },
        ]),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    }
}

fn at<'v>(k: &'v serde_json::Value, path: &str) -> &'v serde_json::Value {
    path.split('.').fold(k, |v, p| &v[p])
}

struct Inputs<'a> {
    credential_kind: &'a str,
    _node: u64,
    usage_bucket: &'a str,
    window: u64,
    schema: &'a str,
    grouped: &'a str,
    group: &'a str,
    plain: &'a str,
    absent: &'a str,
}

impl<'a> Inputs<'a> {
    fn of(k: &'a serde_json::Value) -> Self {
        assert!(k.is_object(), "conformance.json has no `store` inputs");
        let s = |path: &str| -> &'a str {
            at(k, path)
                .as_str()
                .unwrap_or_else(|| panic!("conformance.json: store.{path} must be a string"))
        };
        let n = |path: &str| {
            at(k, path)
                .as_u64()
                .unwrap_or_else(|| panic!("conformance.json: store.{path} must be a number"))
        };
        Self {
            credential_kind: s("credential_kind"),
            _node: n("node"),
            usage_bucket: s("usage.bucket"),
            window: n("usage.window"),
            schema: s("schema"),
            grouped: s("keys.grouped"),
            group: s("keys.group"),
            plain: s("keys.plain"),
            absent: s("keys.absent"),
        }
    }
}

fn exercise(
    load: impl Fn() -> Loaded,
    settings: &[u8],
    dropped_meta: Option<(&std::path::Path, &[u8])>,
) -> Vec<(&'static str, String)> {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../conformance.json")).unwrap();
    let i = Inputs::of(&config["store"]);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (p, d) = load();
    let held = Arc::clone(&p.inner);
    let first = || held.crossings.load(Ordering::SeqCst) - held.resumes.load(Ordering::SeqCst);
    let facts_before = first();
    let mut answers = vec![(
        "facts",
        format!(
            "{:?} {} max_inflight={} {:?}",
            p.kind(),
            p.name(),
            p.max_inflight(),
            p.context::<busbar_plugin_loader::dispatch::kinds::store::StoreFacts>()
        ),
    )];
    assert_eq!(first() - facts_before, 0, "facts crosses no store slot");
    let before = first();
    let refused = match dropped_meta {
        Some((lib, stated)) => {
            load_dropped::<busbar_plugin_loader::dispatch::kinds::hook::Hook>(lib, stated, bind(&d))
                .err()
        }
        None => LinkedRow::of(busbar_store_mysql::door)
            .and_then(|row| {
                load_linked::<busbar_plugin_loader::dispatch::kinds::hook::Hook>(&row, bind(&d))
            })
            .err(),
    };
    assert!(matches!(
        refused,
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Store,
            want: busbar_contract::abi::mechanism::KindCode::Hook
        })
    ));
    assert_eq!(first() - before, 0, "wrong kind crosses no store slot");
    answers.push(("refused as another kind", "refused=true".into()));
    let open_pin = 1 + u64::from(p.has_ready());
    let before = first();
    let st = LoadedStore::open(p, Arc::clone(&d), settings, common::mint).expect("MySQL opens");
    assert_eq!(first() - before, open_pin, "open crossings");
    answers.push(("open", format!("Ready {:?}", st.facts())));
    let before = first();
    let ready_pin = u64::from(st.plugin().has_ready());
    st.plugin()
        .ready(&d, std::time::Duration::from_secs(30))
        .expect("MySQL ready");
    assert_eq!(first() - before, ready_pin, "ready crossings");
    answers.push((
        "ready",
        format!("has_ready={} Ok(())", st.plugin().has_ready()),
    ));
    let b: &dyn RecordStore = &st;
    let keys = |r: Result<Vec<VirtualKey>, busbar_contract::records::RecordStoreError>| {
        ans(r.map(|mut ks| {
            ks.sort_by(|a, b| a.id.cmp(&b.id));
            ks.into_iter()
                .map(|k| (k.id, k.revision, k.deleted_at.is_some(), k.group))
                .collect::<Vec<_>>()
        }))
    };
    {
        let before = first();
        let answer = ans(b.put_key(&key(i.grouped, Some(i.group))));
        assert_eq!(first() - before, 1, "crossings: {}", "put grouped");
        answers.push(("put grouped", answer));
    };
    {
        let before = first();
        let answer = ans(b.put_key(&key(i.plain, None)));
        assert_eq!(first() - before, 1, "crossings: {}", "put plain");
        answers.push(("put plain", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_key(i.grouped).map(|k| k.map(|k| (k.id, k.group))));
        assert_eq!(first() - before, LEASED, "crossings: {}", "get grouped");
        answers.push(("get grouped", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_key(i.absent).map(|k| k.map(|k| k.id)));
        assert_eq!(first() - before, 1, "crossings: {}", "get absent");
        answers.push(("get absent", answer));
    };
    {
        let before = first();
        let answer = keys(b.list_keys());
        assert_eq!(first() - before, LEASED, "crossings: {}", "key list");
        answers.push(("key list", answer));
    };
    {
        let before = first();
        let answer = ans(b.delete_key(i.plain));
        assert_eq!(first() - before, 1, "crossings: {}", "delete plain");
        answers.push(("delete plain", answer));
    };
    {
        let before = first();
        let answer = ans(b.delete_key(i.absent));
        assert_eq!(first() - before, 1, "crossings: {}", "delete absent");
        answers.push(("delete absent", answer));
    };
    {
        let before = first();
        let answer = ans(b.put_key(&key(i.plain, None)));
        assert_eq!(first() - before, 1, "crossings: {}", "relive plain");
        answers.push(("relive plain", answer));
    };
    {
        let before = first();
        let answer = keys(b.list_keys_since(0));
        assert_eq!(first() - before, LEASED, "crossings: {}", "keys since 0");
        answers.push(("keys since 0", answer));
    };

    let (ub, w) = (i.usage_bucket, i.window);
    {
        let before = first();
        let answer = ans(b.get_usage(ub, w));
        assert_eq!(first() - before, LEASED, "crossings: {}", "usage untouched");
        answers.push(("usage untouched", answer));
    };
    {
        let before = first();
        let answer = ans(b.add_usage(ub, w, &delta(2, 30)));
        assert_eq!(first() - before, 1, "crossings: {}", "add usage");
        answers.push(("add usage", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_usage(ub, w));
        assert_eq!(first() - before, LEASED, "crossings: {}", "usage");
        answers.push(("usage", answer));
    };
    let mut set = UsageLedger::default();
    set.apply_delta(&delta(9, 1));
    {
        let before = first();
        let answer = ans(b.put_usage("j", w * 2, &set));
        assert_eq!(first() - before, 1, "crossings: {}", "put usage");
        answers.push(("put usage", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_usage("j", w * 2));
        assert_eq!(first() - before, LEASED, "crossings: {}", "usage j");
        answers.push(("usage j", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_usage(ub, w));
        assert_eq!(first() - before, LEASED, "crossings: {}", "usage again");
        answers.push(("usage again", answer));
    };

    {
        let before = first();
        let answer = ans(b.add_metering(&meter(i.grouped, "p", 3)));
        assert_eq!(first() - before, 1, "crossings: {}", "meter p 3");
        answers.push(("meter p 3", answer));
    };
    {
        let before = first();
        let answer = ans(b.add_metering(&meter(i.grouped, "p", 4)));
        assert_eq!(first() - before, 1, "crossings: {}", "meter p 4");
        answers.push(("meter p 4", answer));
    };
    {
        let before = first();
        let answer = ans(b.add_metering(&meter(i.grouped, "q", 1)));
        assert_eq!(first() - before, 1, "crossings: {}", "meter q 1");
        answers.push(("meter q 1", answer));
    };
    {
        let before = first();
        let answer = ans(b.list_metering(86_400).map(|mut v| {
            v.sort_by(|x, y| x.provider.cmp(&y.provider));
            v
        }));
        assert_eq!(first() - before, LEASED, "crossings: {}", "metering");
        answers.push(("metering", answer));
    };

    {
        let before = first();
        let answer = ans(b.put_key(&key("k1", None)));
        assert_eq!(first() - before, 1, "crossings: {}", "put k1");
        answers.push(("put k1", answer));
    };
    {
        let before = first();
        let answer = ans(b.put_credential(&secret(i.credential_kind, "c1", "k1", "pub1")));
        assert_eq!(first() - before, 1, "crossings: {}", "cred c1");
        answers.push(("cred c1", answer));
    };
    {
        let before = first();
        let answer = ans(b.put_credential(&secret(i.credential_kind, "c9", "k1", "pub9")));
        assert_eq!(first() - before, 1, "crossings: {}", "cred c9 (live slot)");
        answers.push(("cred c9 (live slot)", answer));
    };
    {
        let before = first();
        let answer = ans(b.put_key_with_credential(
            &key("k2", None),
            &secret(i.credential_kind, "c2", "k2", "pub2"),
        ));
        assert_eq!(first() - before, 1, "crossings: {}", "key+cred k2");
        answers.push(("key+cred k2", answer));
    };
    {
        let before = first();
        let answer = ans(b
            .list_credentials("k1")
            .map(|v| v.into_iter().map(|c| c.id).collect::<Vec<_>>()));
        assert_eq!(first() - before, LEASED, "crossings: {}", "creds k1");
        answers.push(("creds k1", answer));
    };
    {
        let before = first();
        let answer = ans(b.revoke_credential("c1", "rotated"));
        assert_eq!(first() - before, 1, "crossings: {}", "revoke c1");
        answers.push(("revoke c1", answer));
    };
    {
        let before = first();
        let answer = ans(b.revoke_credential("zz", "x"));
        assert_eq!(first() - before, 1, "crossings: {}", "revoke absent");
        answers.push(("revoke absent", answer));
    };
    {
        let before = first();
        let answer = ans(b.list_credentials_since(0).map(|mut v| {
            v.sort_by(|x, y| x.meta.id.cmp(&y.meta.id));
            v.into_iter()
                .map(|c| (c.meta.id, c.meta.revoked_at.is_some()))
                .collect::<Vec<_>>()
        }));
        assert_eq!(first() - before, LEASED, "crossings: {}", "creds since");
        answers.push(("creds since", answer));
    };

    {
        let before = first();
        let answer = ans(b.list_audit());
        assert_eq!(first() - before, 1, "crossings: {}", "audit");
        answers.push(("audit", answer));
    };
    {
        let before = first();
        let answer = ans(b.list_audit_tail(1));
        assert_eq!(first() - before, 1, "crossings: {}", "audit tail 1");
        answers.push(("audit tail 1", answer));
    };
    {
        let before = first();
        let answer = ans(b.add_denylist("x", "why"));
        assert_eq!(first() - before, 1, "crossings: {}", "deny x");
        answers.push(("deny x", answer));
    };
    {
        let before = first();
        let answer = ans(b.list_denylist().map(|mut v| {
            v.sort();
            v
        }));
        assert_eq!(first() - before, LEASED, "crossings: {}", "deny");
        answers.push(("deny", answer));
    };

    let bodies = |r: busbar_contract::records::RecordStoreResult<Vec<Vec<u8>>>| {
        ans(r.map(|v| {
            let mut v: Vec<String> = v.iter().map(|b| text_of(b)).collect();
            v.sort();
            v
        }))
    };
    {
        let before = first();
        let answer = ans(b.upsert_plane_record(plane("task", "t1", None, 0, b"{}").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "upsert t1");
        answers.push(("upsert t1", answer));
    };
    {
        let before = first();
        let answer = ans(b
            .get_plane_record("task", "t1")
            .map(|v| v.map(|v| text_of(&v))));
        assert_eq!(first() - before, 1, "crossings: {}", "get t1");
        answers.push(("get t1", answer));
    };
    {
        let before = first();
        let answer = ans(b.append_plane_record(plane("ev", "e", Some("t1"), 1, b"1").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "append e1");
        answers.push(("append e1", answer));
    };
    {
        let before = first();
        let answer = ans(b.append_plane_record(plane("ev", "e", Some("t1"), 2, b"2").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "append e2");
        answers.push(("append e2", answer));
    };
    {
        let before = first();
        let answer = ans(b.append_plane_record(plane("ev", "e", Some("t1"), 2, b"x").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "append e2 fork");
        answers.push(("append e2 fork", answer));
    };
    {
        let before = first();
        let answer = bodies(b.list_plane_records("ev", &PlaneSelector::Parent("t1".into())));
        assert_eq!(first() - before, 1, "crossings: {}", "list ev t1");
        answers.push(("list ev t1", answer));
    };
    {
        let before = first();
        let answer = ans(b.list_plane_record_parents("ev").map(|mut v| {
            v.sort();
            v
        }));
        assert_eq!(first() - before, LEASED, "crossings: {}", "parents ev");
        answers.push(("parents ev", answer));
    };
    {
        let before = first();
        let answer =
            ans(b.purge_plane_records("ev", 100, busbar_contract::records::Retention::Age));
        assert_eq!(first() - before, 1, "crossings: {}", "purge ev");
        answers.push(("purge ev", answer));
    };

    {
        let before = first();
        let answer = ans(b.append_plane_record(plane("rt", "r", Some("p"), 1, b"active").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "append rt1");
        answers.push(("append rt1", answer));
    };
    {
        let before = first();
        let answer = ans(b.append_plane_record(plane("rt", "r", Some("p"), 2, b"terminal").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "append rt2");
        answers.push(("append rt2", answer));
    };
    {
        let before = first();
        let answer = ans(b.purge_plane_records(
            "rt",
            100,
            busbar_contract::records::Retention::TerminalOnly,
        ));
        assert_eq!(
            first() - before,
            1,
            "crossings: {}",
            "purge rt terminal-only"
        );
        answers.push(("purge rt terminal-only", answer));
    };
    {
        let before = first();
        let answer = bodies(b.list_plane_records("rt", &PlaneSelector::Parent("p".into())));
        assert_eq!(first() - before, 1, "crossings: {}", "list rt kept");
        answers.push(("list rt kept", answer));
    };
    {
        let before = first();
        let answer =
            ans(b.purge_plane_records("rt", 100, busbar_contract::records::Retention::Age));
        assert_eq!(first() - before, 1, "crossings: {}", "purge rt age");
        answers.push(("purge rt age", answer));
    };
    {
        let before = first();
        let answer = bodies(b.list_plane_records("rt", &PlaneSelector::Parent("p".into())));
        assert_eq!(first() - before, 1, "crossings: {}", "list rt aged");
        answers.push(("list rt aged", answer));
    };
    {
        let before = first();
        let answer = ans(b.delete_plane_record("task", "t1"));
        assert_eq!(first() - before, 1, "crossings: {}", "delete t1");
        answers.push(("delete t1", answer));
    };
    {
        let before = first();
        let answer = ans(b
            .get_plane_record("task", "t1")
            .map(|v| v.map(|v| text_of(&v))));
        assert_eq!(first() - before, 1, "crossings: {}", "get t1 after");
        answers.push(("get t1 after", answer));
    };

    {
        let before = first();
        let answer = ans(b.upsert_plane_record(plane("ctask", "c1", Some("p"), 0, b"c1").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "upsert c1 under p");
        answers.push(("upsert c1 under p", answer));
    };
    {
        let before = first();
        let answer = ans(b.upsert_plane_record(plane("ctask", "c2", Some("p"), 0, b"c2").view()));
        assert_eq!(first() - before, 1, "crossings: {}", "upsert c2 under p");
        answers.push(("upsert c2 under p", answer));
    };
    {
        let before = first();
        let answer = ans(b
            .get_plane_record("ctask", "c1")
            .map(|v| v.map(|v| text_of(&v))));
        assert_eq!(first() - before, 1, "crossings: {}", "get c1");
        answers.push(("get c1", answer));
    };
    {
        let before = first();
        let answer = bodies(b.list_plane_records("ctask", &PlaneSelector::Parent("p".into())));
        assert_eq!(first() - before, 1, "crossings: {}", "list ctask p");
        answers.push(("list ctask p", answer));
    };
    {
        let before = first();
        let answer = ans(b.delete_plane_record("ctask", "c1"));
        assert_eq!(first() - before, 1, "crossings: {}", "delete c1");
        answers.push(("delete c1", answer));
    };
    {
        let before = first();
        let answer = ans(b
            .get_plane_record("ctask", "c1")
            .map(|v| v.map(|v| text_of(&v))));
        assert_eq!(first() - before, 1, "crossings: {}", "get c1 after");
        answers.push(("get c1 after", answer));
    };
    {
        let before = first();
        let answer = ans(b
            .get_plane_record("ctask", "c2")
            .map(|v| v.map(|v| text_of(&v))));
        assert_eq!(first() - before, 1, "crossings: {}", "get c2");
        answers.push(("get c2", answer));
    };
    {
        let before = first();
        let answer = ans(b.plane_token_live("tok", "x", 100, 1));
        assert_eq!(first() - before, 1, "crossings: {}", "token live");
        answers.push(("token live", answer));
    };
    {
        let before = first();
        let answer = ans(b.redeem_plane_token("tok", "x", LIVE_REPLAY_DEADLINE, 1));
        assert_eq!(first() - before, 1, "crossings: {}", "redeem");
        answers.push(("redeem", answer));
    };
    {
        let before = first();
        let answer = ans(b.redeem_plane_token("tok", "x", LIVE_REPLAY_DEADLINE, 1));
        assert_eq!(first() - before, 1, "crossings: {}", "redeem again");
        answers.push(("redeem again", answer));
    };

    let batch = [(ub, w, delta(1, 5)), (ub, w, delta(1, 5))];
    {
        let before = first();
        let answer = ans(block(&rt, st.add_usage_batch(op(8), &batch)));
        assert_eq!(first() - before, 1, "crossings: {}", "usage batch");
        answers.push(("usage batch", answer));
    };
    {
        let before = first();
        let answer = ans(block(&rt, st.add_usage_batch(op(8), &batch)));
        assert_eq!(first() - before, 1, "crossings: {}", "usage batch replay");
        answers.push(("usage batch replay", answer));
    };
    {
        let before = first();
        let answer = ans(block(&rt, st.add_usage_batch(op(8), &batch[..1])));
        assert_eq!(first() - before, 1, "crossings: {}", "usage batch conflict");
        answers.push(("usage batch conflict", answer));
    };
    {
        let before = first();
        let answer = ans(block(
            &rt,
            st.add_metering_batch(op(9), &[meter(i.grouped, "p", 1)]),
        ));
        assert_eq!(first() - before, 1, "crossings: {}", "metering batch");
        answers.push(("metering batch", answer));
    };
    let rec = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("a record");
    let shown = |v: Option<RecordBytes>| v.map(|v| text_of(v.as_slice()));
    {
        let before = first();
        let answer = ans(block(&rt, st.record_put(i.schema, b"a/1", &rec(b"one"))));
        assert_eq!(first() - before, 1, "crossings: {}", "record put a/1");
        answers.push(("record put a/1", answer));
    };
    {
        let before = first();
        let answer = ans(block(&rt, st.record_put(i.schema, b"a/2", &rec(b"two"))));
        assert_eq!(first() - before, 1, "crossings: {}", "record put a/2");
        answers.push(("record put a/2", answer));
    };
    {
        let before = first();
        let answer = ans(block(&rt, StoreCalls::record_get(&st, i.schema, b"a/1")).map(shown));
        assert_eq!(first() - before, 1, "crossings: {}", "record get");
        answers.push(("record get", answer));
    };
    {
        let before = first();
        let answer = ans(block(&rt, StoreCalls::record_get(&st, i.schema, b"zz")).map(shown));
        assert_eq!(first() - before, 1, "crossings: {}", "record get absent");
        answers.push(("record get absent", answer));
    };
    let scan = || {
        ans(block(&rt, st.record_scan(i.schema, b"a/", 5)).map(|mut v| {
            v.sort_by(|x, y| x.0.cmp(&y.0));
            v.into_iter()
                .map(|(k, v)| (text_of(&k), text_of(v.as_slice())))
                .collect::<Vec<_>>()
        }))
    };
    {
        let before = first();
        let answer = (scan)();
        assert_eq!(first() - before, 1, "crossings: {}", "record scan");
        answers.push(("record scan", answer));
    };

    {
        let before = first();
        let answer = ans(block(&rt, st.record_put(i.schema, b"a/1", &rec(b""))));
        assert_eq!(first() - before, 1, "crossings: {}", "record put a/1 empty");
        answers.push(("record put a/1 empty", answer));
    };
    {
        let before = first();
        let answer = ans(block(&rt, StoreCalls::record_get(&st, i.schema, b"a/1")).map(shown));
        assert_eq!(first() - before, 1, "crossings: {}", "record get emptied");
        answers.push(("record get emptied", answer));
    };
    {
        let before = first();
        let answer = (scan)();
        assert_eq!(first() - before, 1, "crossings: {}", "record scan emptied");
        answers.push(("record scan emptied", answer));
    };
    {
        let before = first();
        let answer = ans(block(
            &rt,
            StoreCalls::upsert_plane_record(&st, plane("task", "t2", None, 0, b"b").view()),
        ));
        assert_eq!(first() - before, 1, "crossings: {}", "typed upsert");
        answers.push(("typed upsert", answer));
    };
    {
        let before = first();
        let answer = ans(block(&rt, StoreCalls::get_plane_record(&st, "task", "t2"))
            .map(|v| v.map(|v| text_of(&v))));
        assert_eq!(first() - before, 1, "crossings: {}", "typed get");
        answers.push(("typed get", answer));
    };
    {
        let before = first();
        let answer = ans(block(
            &rt,
            StoreCalls::append_plane_record(
                &st,
                op(13),
                plane("ev", "f", Some("t2"), 1, b"1").view(),
            ),
        ));
        assert_eq!(first() - before, 1, "crossings: {}", "typed append");
        answers.push(("typed append", answer));
    };
    {
        let before = first();
        let answer = bodies(
            block(
                &rt,
                StoreCalls::list_plane_records(&st, "ev", &PlaneSelector::Parent("t2".into())),
            )
            .map_err(|e| busbar_contract::records::RecordStoreError(e.to_string())),
        );
        assert_eq!(first() - before, 1, "crossings: {}", "typed list");
        answers.push(("typed list", answer));
    };
    {
        let before = first();
        let answer = ans(block(
            &rt,
            StoreCalls::delete_plane_record(&st, "task", "t2"),
        ));
        assert_eq!(first() - before, 1, "crossings: {}", "typed delete");
        answers.push(("typed delete", answer));
    };
    {
        let before = first();
        let answer = ans(block(
            &rt,
            StoreCalls::redeem_plane_token(&st, "tok", "y", LIVE_REPLAY_DEADLINE, 1),
        ));
        assert_eq!(first() - before, 1, "crossings: {}", "typed redeem");
        answers.push(("typed redeem", answer));
    };
    {
        let before = first();
        let answer = ans(block(
            &rt,
            StoreCalls::plane_token_live(&st, "tok", "y", 100, 1),
        ));
        assert_eq!(first() - before, 1, "crossings: {}", "typed live");
        answers.push(("typed live", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_usage(ub, w));
        assert_eq!(
            first() - before,
            LEASED,
            "crossings: {}",
            "usage at the end"
        );
        answers.push(("usage at the end", answer));
    };

    {
        let before = first();
        let answer = ans(block(&rt, st.purge_usage_before(w * 2)));
        assert_eq!(first() - before, 1, "crossings: {}", "usage purge");
        answers.push(("usage purge", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_usage(ub, w));
        assert_eq!(first() - before, LEASED, "crossings: {}", "usage purged");
        answers.push(("usage purged", answer));
    };
    {
        let before = first();
        let answer = ans(b.get_usage("j", w * 2));
        assert_eq!(first() - before, LEASED, "crossings: {}", "usage kept");
        answers.push(("usage kept", answer));
    };

    let sk = scoped_key();
    {
        let before = first();
        let answer = ans(b.put_key(&sk));
        assert_eq!(first() - before, 1, "crossings: {}", "scope-kind put");
        answers.push(("scope-kind put", answer));
    };
    let back = {
        let before = first();
        let (answer, value) = match b.get_key(&sk.id) {
            Ok(Some(k)) => {
                let want = VirtualKey {
                    revision: k.revision,
                    ..scoped_key()
                };
                let same = serde_json::to_vec(&k).ok() == serde_json::to_vec(&want).ok();
                let line = format!(
                    "identical={same} plane_grants={}",
                    k.scope_allowed("engine_tool", "filesystem_read_file")
                        && k.scope_allowed("engine_server", "filesystem")
                        && !k.scope_allowed("pool", "filesystem_read_file")
                );
                (line, Some(k))
            }
            other => (ans(other.map(|k| k.map(|k| k.id))), None),
        };
        assert_eq!(first() - before, LEASED, "crossings: {}", "scope-kind get");
        answers.push(("scope-kind get", answer));
        value
    };
    {
        let before = first();
        let answer = match b.list_keys() {
            Ok(ks) => {
                let listed = ks.iter().find(|k| k.id == sk.id);
                format!(
                    "identical={}",
                    listed.is_some()
                        && listed.and_then(|k| serde_json::to_vec(k).ok())
                            == back.as_ref().and_then(|k| serde_json::to_vec(k).ok())
                )
            }
            Err(e) => format!("! {e}"),
        };
        assert_eq!(first() - before, LEASED, "crossings: {}", "scope-kind list");
        answers.push(("scope-kind list", answer));
    };

    assert!(
        held.resumes.load(Ordering::SeqCst) > 0,
        "live MySQL I/O exercises pending/resume"
    );
    contract(&answers, &i);
    answers
}
#[test]
fn all_store_slots_match_through_linked_and_fresh_dropped_mysql() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let mut runs = Vec::new();
    for dropped_in in [false, true] {
        let name = format!("mysql_contract_{}", common::node());
        let settings = inputs().replace("{fold}", &name);
        let config: serde_json::Value = serde_json::from_str(&settings).unwrap();
        let settings = serde_json::to_vec(&config["settings"]).unwrap();
        create_fold_database(&name, &settings);
        let run = exercise(
            || {
                if dropped_in {
                    dropped(&lib, &stated)
                } else {
                    linked()
                }
            },
            &settings,
            if dropped_in {
                Some((&lib, &stated))
            } else {
                None
            },
        );
        drop_fold_database(&name, &settings);
        runs.push(run);
    }
    assert_eq!(runs[0], runs[1], "all store answers through both doors");
}
#[test]
fn mysql_refuses_a_schema_newer_than_its_build_through_both_doors() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    for dropped_in in [false, true] {
        let name = format!("mysql_newer_{}", common::node());
        let config: serde_json::Value =
            serde_json::from_str(&inputs().replace("{fold}", &name)).unwrap();
        let settings = serde_json::to_vec(&config["settings"]).unwrap();
        create_fold_database(&name, &settings);
        let load = || {
            if dropped_in {
                dropped(&lib, &stated)
            } else {
                linked()
            }
        };
        let (p, d) = load();
        drop(LoadedStore::open(p, d, &settings, common::mint).expect("own schema opens"));
        stamp_newer_schema(&name, &settings);
        let (p, d) = load();
        let e = LoadedStore::open(p, d, &settings, common::mint).expect_err("newer schema refused");
        assert!(
            e.contains("is newer than this build"),
            "schema refusal states why: {e}"
        );
        drop_fold_database(&name, &settings);
    }
}
fn contract(fold: &[(&str, String)], i: &Inputs<'_>) {
    let at = |label: &str| {
        fold.iter()
            .find(|(name, _)| *name == label)
            .expect("script answer")
            .1
            .as_str()
    };
    assert_eq!(at("refused as another kind"), "refused=true");
    let tail = |label: &str| at(label).split_once(' ').map_or("", |x| x.1);
    for (label, answer) in fold {
        assert!(!answer.contains("faulted"), "{label}: {answer}");
    }
    assert!(at("open").starts_with("Ready "), "open: {}", at("open"));
    for label in [
        "put grouped",
        "put plain",
        "delete plain",
        "add usage",
        "put usage",
        "meter p 3",
        "cred c1",
        "key+cred k2",
        "revoke c1",
        "deny x",
        "upsert t1",
        "append e1",
        "append e2",
        "delete t1",
        "usage batch",
        "metering batch",
        "record put a/1",
        "record put a/1 empty",
        "typed upsert",
        "typed delete",
        "scope-kind put",
    ] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("get grouped"),
        format!("= Some(({:?}, Some({:?})))", i.grouped, i.group),
        "a key put is the key got"
    );
    for label in [
        "get absent",
        "get t1 after",
        "record get absent",
        "record get emptied",
    ] {
        assert_eq!(at(label), "= None", "{label}");
    }
    for label in ["delete absent", "relive plain", "append e2 fork"] {
        assert!(
            at(label).starts_with("! "),
            "refused: {label}: {}",
            at(label)
        );
    }
    assert_eq!(
        at("list ev t1"),
        "= [\"1\", \"2\"]",
        "a refused sequence fork leaves both original events intact"
    );
    assert!(
        at("cred c9 (live slot)").starts_with("! "),
        "a live slot is not taken twice"
    );
    assert_eq!(at("usage batch replay"), at("usage batch"));
    assert_eq!(at("usage batch conflict"), "! STORE_OPID_CONFLICT");
    for label in ["upsert c1 under p", "upsert c2 under p", "delete c1"] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("get c1"),
        "= Some(\"c1\")",
        "a parented upsert reads back by its own id"
    );
    assert_eq!(
        at("list ctask p"),
        "= [\"c1\", \"c2\"]",
        "two ids under one parent are two records, both listed under it"
    );
    assert_eq!(at("get c1 after"), "= None", "deleted by its own id");
    assert_eq!(at("get c2"), "= Some(\"c2\")", "deleting c1 leaves c2");

    for label in ["append rt1", "append rt2"] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("purge rt terminal-only"),
        "= 1",
        "a terminal-only purge drops the old TERMINAL row and only it"
    );
    assert_eq!(
        at("list rt kept"),
        r#"= ["active"]"#,
        "a terminal-only purge keeps an ACTIVE row however old"
    );
    assert_eq!(
        at("purge rt age"),
        "= 1",
        "an age purge drops the old ACTIVE row"
    );
    assert_eq!(
        at("list rt aged"),
        "= []",
        "nothing old survives an age purge"
    );
    assert_eq!(at("redeem"), "= true");
    assert_eq!(at("redeem again"), "= false", "a token is redeemed once");
    assert_eq!(at("record get"), "= Some(\"one\")");
    assert_eq!(
        at("record scan"),
        "= [(\"a/1\", \"one\"), (\"a/2\", \"two\")]"
    );
    assert_eq!(
        at("record scan emptied"),
        "= [(\"a/2\", \"two\")]",
        "an empty put removes the row: the scan never returns it"
    );

    assert!(
        tail("usage again").contains("UsageLedger { requests: 2,"),
        "{}",
        at("usage again")
    );
    assert!(
        tail("usage at the end").contains("UsageLedger { requests: 4,"),
        "{}",
        at("usage at the end")
    );
    assert_eq!(at("usage purge"), "= 1", "the one window before the cutoff");
    assert!(
        tail("usage purged").contains("UsageLedger { requests: 0,"),
        "{}",
        at("usage purged")
    );
    assert!(
        tail("usage kept").contains("UsageLedger { requests: 9,"),
        "{}",
        at("usage kept")
    );
    assert_eq!(at("scope-kind get"), "identical=true plane_grants=true");
    assert_eq!(at("scope-kind list"), "identical=true");
}
