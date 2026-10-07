// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// RENDERED by `busbar-release plugin sync busbar-store-mysql` from GetBusbar/busbar-release
// template/conformance-host/, because this repo's declares file states network needs (`needs`:
// `tcp`); a hand edit is overwritten by the next sync.

//! **THE SUITE'S HOST CONNECTOR, IN THIS PLUGIN'S OWN TEST** (ARCHITECT Q-P4-9 (d)). busbar keeps
//! only the neutral seam (`busbar_plugin_loader::conformance::Host`, the suite's `host:` and `tls:`
//! arguments); this adapter implements it the way busbar's composition root composes the process's
//! one connector — carrier -> [TLS] -> framer (`BUSBAR-1.6.0.md` THE DESIGN §5):
//!
//! * busbar's own `Connector` (`busbar-core-connector`, a dev-dependency at the pin), its framer
//!   entries the transport doors this plugin's needs name (`tcp`), each loaded
//!   through the loader's one load and opened as the root opens a transport door;
//! * the connector's own TLS (connsec), trusting the platform roots plus the suite's TEST trust
//!   anchors (`tls:`), never handed to the plugin: no plugin holds a key, a certificate or a TLS
//!   type (TRANSPORT-STACK (1));
//! * a dial judge that admits loopback only: the suite dials the REAL local endpoints its settings
//!   name, never the network;
//! * a parked read wakes the plugin's ticket through the leg dispatcher's conn waker.
//!
//! [`far_end`] is a TLS far end at [`FAR_END`] whose certificate chains to [`anchors`] (busbar's
//! test kit, `busbar_core_connector::test_support`): the plugin's `conformance.json` settings name
//! it, and its `answer` speaks the plugin's protocol. Its own tests, below, run with the suite:
//! a TLS upgrade verifies against the anchors, and is REFUSED with the anchors withheld (RED).
//!
//! The plugin's `tests/conformance.rs` mounts this file and names it:
//!
//! ```ignore
//! #[path = "support/conformance_host.rs"]
//! mod conformance_host;
//!
//! busbar_plugin_loader::conformance_suite! {
//!     door: …, cdylib: …, inputs: include_str!("conformance.json"),
//!     host: conformance_host::host,
//!     tls: conformance_host::anchors(),
//! }
//! ```
//!
//! with the dev-dependencies the rendered root `Cargo.toml` states (`{ workspace = true }`):
//! `busbar-core-connector`, `busbar-transport-tcp`, `tokio`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::slot;
use busbar_contract::conn::{
    ConnError, ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, NO_TICKET,
};
use busbar_contract::transport::EgressTrust;
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::test_support::{private_ca, ServerTls, StdServerSession, TestCa};
use busbar_core_connector::{Connector, Judged, Verdict};
use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, NoSink,
    OutFrame, Plugin,
};

/// Where [`far_end`] listens: loopback, a port of this repo's own.
pub const FAR_END: &str = "localhost:41517";

/// The framer doors the host serves, as the root links them: (claim, door). One row a line,
/// whatever the claims' lengths (a `vec!` would be reflowed by rustfmt).
#[allow(clippy::vec_init_then_push)]
fn doors() -> Vec<(&'static str, DoorFn)> {
    use busbar_transport_tcp::linked::door as tcp_door;
    // Each row is compiled against this repo's own pin of busbar-contract (the rendered `[patch]`),
    // as busbar compiles the rows it links.
    let mut doors: Vec<(&'static str, DoorFn)> = Vec::new();
    doors.push(("tcp", tcp_door));
    doors
}

/// The suite's test CA: [`anchors`] is its certificate, [`far_end`] serves a leaf it signed.
fn ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(private_ca)
}

/// THE SUITE'S TEST TRUST ANCHORS (PEM), for `conformance_suite!`'s `tls:`.
#[must_use]
pub fn anchors() -> &'static str {
    &ca().ca_pem
}

/// THE HOST CONNECTOR (`busbar_plugin_loader::conformance::Host`): one per leg.
///
/// # Panics
/// The anchors do not parse, a transport door does not load or open, or the view does not compose.
#[must_use]
pub fn host(wake: Arc<dyn Fn(u64) + Send + Sync>, anchors: Option<&str>) -> Arc<dyn DeclaredConns> {
    // The reactor a socket a plugin opens from a dispatcher worker registers on, as the root
    // installs it (`root::connector::io_reactor`): the connector's own I/O thread.
    busbar_core_connector::io::install_process_reactor(io_reactor());
    let trust = EgressTrust {
        extra_anchors: anchors.map(pem_certs).unwrap_or_default(),
        ..EgressTrust::default()
    };
    let tls = busbar_core_connector::tls::client::build_client_config(&trust)
        .unwrap_or_else(|e| panic!("the host's connection security does not build: {e}"));
    let view = Transports::new(entries())
        .unwrap_or_else(|e| panic!("the host's transport doors do not compose: {e}"));
    Arc::new(Connector::serving(
        view,
        Arc::new(loopback),
        Some(Arc::new(tls)),
        wake,
    ))
}

/// The connector's I/O thread: a single-threaded runtime of its own whose reactor drives every
/// socket the plugin opens from a dispatcher worker. Built once.
fn io_reactor() -> tokio::runtime::Handle {
    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    IO.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the host's I/O runtime builds");
        let handle = rt.handle().clone();
        std::thread::Builder::new()
            .name("conformance-host-io".into())
            .spawn(move || rt.block_on(std::future::pending::<()>()))
            .expect("the host's I/O thread starts");
        handle
    })
    .clone()
}

/// THE DIAL JUDGE: a loopback address (a literal, or a name that resolves to one) and nothing else.
fn loopback(dest: &str, _class: u32, _done: Judged) -> Option<Result<SocketAddr, Verdict>> {
    let refused = busbar_contract::abi::host::service::DEST_UNRESOLVABLE;
    let at = dest
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.find(|a| a.ip().is_loopback()));
    Some(at.ok_or(refused))
}

/// Every certificate in `pem`, DER.
fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    let certs = busbar_core_connector::test_support::certs_from_pem(pem);
    assert!(
        !certs.is_empty(),
        "the suite's trust anchors hold no certificate"
    );
    certs
}

/// The dispatcher the host's transport doors are adopted by.
fn transport_dispatcher() -> &'static Dispatcher {
    static ONE: OnceLock<Dispatcher> = OnceLock::new();
    ONE.get_or_init(|| Dispatcher::new(DispatchConfig::default()))
}

/// The framer entries: each door loaded through the one loader and opened with no settings, as
/// the root opens a transport door that declares none it reads.
fn entries() -> Vec<Entry> {
    doors()
        .into_iter()
        .map(|(claim, door)| {
            let bind = Bind {
                instance: Arc::from(claim),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: transport_dispatcher().adopter(),
                // A transport door is a framer the connector drives: it declares no need.
                conns: ConnTable::NoNeeds,
            };
            let plugin = LinkedRow::of(door)
                .and_then(|row| load_linked::<Transport>(&row, bind))
                .unwrap_or_else(|e| panic!("the host's transport `{claim}` does not load: {e}"));
            Entry {
                door: Arc::new(Opened::open(plugin, claim)),
                alpn: Vec::new(),
            }
        })
        .collect()
}

/// One transport door, opened, as the connector reaches it (the root's `doors::Dispatched`).
struct Opened {
    plugin: Plugin<Transport>,
    facts: DoorFacts,
}

impl Opened {
    fn open(plugin: Plugin<Transport>, claim: &str) -> Self {
        let stated = plugin
            .context::<TransportFacts>()
            .cloned()
            .unwrap_or_else(|| panic!("the host's transport `{claim}` states no transport tail"));
        let mut i: OpenIn = blank_in();
        i.settings = Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        };
        let mut f = Frame::new(i, blank_out::<OpenOut>());
        let opened = plugin.call(life::OPEN, &mut f);
        assert_eq!(
            opened.outcome,
            Outcome::Ready,
            "the host's transport `{claim}` does not open"
        );
        plugin
            .ready(transport_dispatcher(), Duration::from_secs(10))
            .unwrap_or_else(|e| panic!("the host's transport `{claim}` is not ready: {e}"));
        let facts = DoorFacts {
            name: plugin.name().to_owned(),
            claims: stated.claims,
            composes_over: stated.composes_over,
            status_rows: stated.status_rows,
        };
        Self { plugin, facts }
    }
}

/// One crossing through the dispatcher: the host's `in`/`out` copied in, the answer copied back.
fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: &mut I, o: &mut O) -> Crossed {
    let mut f = Frame::new(*i, *o);
    let c = p.call(s, &mut f);
    *i = f.input;
    *o = f.out;
    Crossed {
        outcome: c.outcome,
        error: c.error,
    }
}

impl FramerDoor for Opened {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        let p = &self.plugin;
        match call {
            Call::Locate(i, o) => go(p, slot::LOCATE, i, o),
            Call::Begin(i, o) => go(p, slot::BEGIN, i, o),
            Call::Ingest(i, o) => go(p, slot::INGEST, i, o),
            Call::Emit(i, o) => go(p, slot::EMIT, i, o),
            Call::Encode(i, o) => go(p, slot::ENCODE, i, o),
            Call::Refuse(i, o) => go(p, slot::REFUSE, i, o),
            Call::Finish(i, o) => go(p, slot::FINISH, i, o),
            Call::Detach(i, o) => go(p, slot::DETACH, i, o),
            Call::Adopt(i, o) => go(p, slot::ADOPT, i, o),
            Call::Timer(i, o) => go(p, slot::TIMER, i, o),
        }
    }
}

// ---- the far end ----

/// What a far end answers a connection: given every byte it has read so far, the bytes to send
/// back and close (`Some`), or `None` to read on.
pub type Answer = fn(&[u8]) -> Option<Vec<u8>>;

/// THE SUITE'S TLS FAR END at [`FAR_END`] (started once; later calls are no-ops): every connection's
/// handshake is busbar's test kit's, with a `localhost` certificate [`anchors`] trusts, and its
/// bytes are answered by `answer`.
///
/// # Panics
/// [`FAR_END`] cannot be bound.
pub fn far_end(answer: Answer) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let listener = TcpListener::bind(FAR_END)
            .unwrap_or_else(|e| panic!("the suite's far end cannot bind {FAR_END}: {e}"));
        serve(listener, answer);
    });
}

/// Serve `listener` over TLS with a leaf the test CA signed, answering each connection by `answer`.
fn serve(listener: TcpListener, answer: Answer) {
    let tls = ServerTls::new(&[ca().leaf_der.clone()], &ca().key_der, None, &[])
        .unwrap_or_else(|e| panic!("the suite's far end has no TLS identity: {e}"));
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { return };
            let tls = tls.clone();
            std::thread::spawn(move || {
                if let Ok(mut s) = tls.accept_std(tcp) {
                    if s.handshake_ok() {
                        reply(&mut s, answer);
                    }
                }
            });
        }
    });
}

fn reply(s: &mut StdServerSession, answer: Answer) {
    let mut seen = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        if let Some(out) = answer(&seen) {
            let _ = s.write_all(&out);
            let _ = s.flush();
            s.close();
            return;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
}

/// A far end's cleartext negotiation before TLS (a protocol's own StartTLS: Postgres's
/// `SSLRequest` answered `S`, LDAP's StartTLS extended operation, ...): `true` = go on to TLS.
pub type Preamble = fn(&mut TcpStream) -> bool;

/// THE SUITE'S TLS FRONT at [`FAR_END`] (started once; later calls are no-ops): each connection's
/// cleartext `preamble` runs, then the TLS handshake (busbar's test kit, a `localhost` certificate
/// [`anchors`] trusts), then its bytes are carried both ways to the REAL backend at `upstream`
/// (the plugin's live service, in the clear on loopback). What it proves: the plugin's own
/// connection is secured by the HOST's TLS against the suite's anchors.
///
/// # Panics
/// [`FAR_END`] cannot be bound.
pub fn tls_front(preamble: Preamble, upstream: &'static str) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let listener = TcpListener::bind(FAR_END)
            .unwrap_or_else(|e| panic!("the suite's TLS front cannot bind {FAR_END}: {e}"));
        let tls = ServerTls::new(&[ca().leaf_der.clone()], &ca().key_der, None, &[])
            .unwrap_or_else(|e| panic!("the suite's TLS front has no TLS identity: {e}"));
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { return };
                let tls = tls.clone();
                std::thread::spawn(move || front(tcp, &tls, preamble, upstream));
            }
        });
    });
}

/// One connection through the TLS front: preamble, handshake, then both directions carried until
/// either side ends.
fn front(mut tcp: TcpStream, tls: &ServerTls, preamble: Preamble, upstream: &str) {
    if !preamble(&mut tcp) {
        return;
    }
    let Ok(ctl) = tcp.try_clone() else { return };
    let Ok(mut s) = tls.accept_std(tcp) else {
        return;
    };
    if !s.handshake_ok() {
        return;
    }
    let Ok(mut up) = TcpStream::connect(upstream) else {
        return;
    };
    let tick = Some(Duration::from_millis(2));
    if ctl.set_read_timeout(tick).is_err() || up.set_read_timeout(tick).is_err() {
        return;
    }
    let idle = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    };
    let mut buf = [0_u8; 16 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if up.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
        match up.read(&mut buf) {
            Ok(0) => {
                s.close();
                return;
            }
            Ok(n) => {
                if s.write_all(&buf[..n]).and_then(|()| s.flush()).is_err() {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
    }
}

// ---- the host's own proof, run with the suite ----

const OWNER: InstanceId = InstanceId(7);

fn need(transport: &str, class: u32) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: class,
        transport: transport.to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

/// `f` until it answers other than PENDING, as a plugin's re-entries on its ticket would.
fn settle<T>(mut f: impl FnMut() -> Result<T, ConnError>) -> Result<T, ConnError> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match f() {
            Err(ConnError::Pending) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(2));
            }
            answered => return answered,
        }
    }
}

/// Read `id` to its completion (or `want` body bytes): its fields pieces' count and its body.
fn drain(c: &dyn DeclaredConns, id: ConnId, want: usize) -> (usize, Vec<u8>) {
    let (mut fields, mut body) = (0, Vec::new());
    let mut buf = [0_u8; 256];
    while body.len() < want {
        let Ok(p) = settle(|| c.read(OWNER, id, NO_TICKET, &mut buf)) else {
            break;
        };
        match p.kind {
            PieceKind::Fields => fields += 1,
            PieceKind::Body => body.extend_from_slice(&buf[..p.len]),
            PieceKind::Completion => break,
            PieceKind::HookReply => {}
        }
    }
    (fields, body)
}

/// Five bytes back for five bytes in: the TLS echo the host's own proof dials.
fn echo(seen: &[u8]) -> Option<Vec<u8>> {
    (seen.len() >= 5).then(|| seen[..5].to_vec())
}

/// A raw `tcp` stream to a TLS echo, upgraded through the host's TLS: what came back.
fn upgraded_echo(c: &dyn DeclaredConns, far: &str) -> Result<Vec<u8>, ConnError> {
    c.declare(
        OWNER,
        NeedId(0),
        &need("tcp", EGRESS_OPERATOR_INFRASTRUCTURE),
        None,
        None,
    )?;
    let id = settle(|| {
        c.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: far,
                timeout_ms: 5_000,
                ..OpenDesc::default()
            },
        )
    })?;
    settle(|| c.upgrade_secure(OWNER, id, Some("localhost"), None, false, NO_TICKET))?;
    let mut at = 0;
    while at < 5 {
        at += settle(|| c.write(OWNER, id, &b"hello"[at..], false, false))?;
    }
    let (_, body) = drain(c, id, 5);
    let _ = c.close(OWNER, id);
    Ok(body)
}

/// A TLS echo on a port of its own; its address.
fn tls_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    let at = listener.local_addr().expect("its address").to_string();
    serve(listener, echo);
    at
}

/// THE HOST'S TLS TRUSTS THE SUITE'S TEST ANCHORS: a stream to a far end whose certificate chains
/// to the test CA is upgraded and round-trips (the anchors went to the host, never to the plugin).
#[test]
fn the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors() {
    let c = host(Arc::new(|_| {}), Some(anchors()));
    assert_eq!(
        upgraded_echo(c.as_ref(), &tls_echo()),
        Ok(b"hello".to_vec())
    );
}

/// RED: the same upgrade with the anchors withheld is refused: the platform roots alone do not
/// trust the test CA.
#[test]
fn red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused() {
    let c = host(Arc::new(|_| {}), None);
    let answer = upgraded_echo(c.as_ref(), &tls_echo());
    assert!(answer.is_err(), "upgraded over an untrusted CA: {answer:?}");
}
