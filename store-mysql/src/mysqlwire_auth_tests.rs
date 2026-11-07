// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual store door, settings capture, mysqlwire and SDK Wire against a scripted host.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};

use crate::v4::backend::MysqlV4;
use busbar_contract::abi::host::conn::connector::{self, ConnectorSlots};
use busbar_contract::abi::host::conn::connector::{EstablishIn, FactsIn, IoIn, StreamFacts};
use busbar_contract::abi::host::service::ServiceOut;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, RawOutcome};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::sdk::store::v4::backend::Backend;
use mysql_common::constants::CapabilityFlags;
use mysql_common::io::ParseBuf;
use mysql_common::packets::{AuthPlugin, HandshakeResponse};
use mysql_common::proto::MySerialize;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::size_of;

use super::tests::packet;
use super::Opts;

const PASSWORD: &str = "CANARY-auth-17";
const NONCE: &[u8; 20] = b"12345678abcdefghijkl";
const STOP: &[u8] = b"\xff\x15\x04#HY000auth fixture reached public SQL";
const OK: &[u8] = &[0, 0, 0, 2, 0, 0, 0];

#[derive(Default)]
struct Script {
    reads: VecDeque<Vec<u8>>,
    written: Vec<u8>,
    pending: HashSet<CompletionHandle>,
    pends: usize,
    opens: usize,
    closes: usize,
    fail_write_after: Option<usize>,
    secure: bool,
    invalid_read_capacity: bool,
}

thread_local! { static SCRIPT: RefCell<Script> = RefCell::new(Script::default()); }

fn pend(handle: CompletionHandle) -> bool {
    SCRIPT.with(|state| {
        let mut state = state.borrow_mut();
        if state.pending.insert(handle) {
            state.pends += 1;
            true
        } else {
            false
        }
    })
}

// These callbacks are the exact scripted MySQL host inputs needed by the auth tests.
// They are not a plugin implementation: the actual MySQL door performs every handshake.
#[allow(unsafe_code)]
unsafe extern "C" fn establish(
    _: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    let i = unsafe { &*input.cast::<EstablishIn>() };
    let outcome = if pend(i.head.handle) {
        Outcome::Pending
    } else {
        SCRIPT.with(|s| s.borrow_mut().opens += 1);
        unsafe {
            (*out).value = 1;
        }
        Outcome::Ready
    };
    unsafe {
        (*out).outcome = RawOutcome::of(outcome);
    }
    RawOutcome::of(outcome)
}
#[allow(unsafe_code)]
unsafe extern "C" fn read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let i = unsafe { &*input.cast::<IoIn>() };
    let outcome = if pend(i.head.handle) {
        Outcome::Pending
    } else {
        match SCRIPT.with(|s| s.borrow_mut().reads.pop_front()) {
            Some(bytes) if bytes.len() <= i.len => {
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.buf, bytes.len());
                    (*out).len = bytes.len() as u64;
                }
                Outcome::Ready
            }
            Some(_) => {
                SCRIPT.with(|s| s.borrow_mut().invalid_read_capacity = true);
                Outcome::Failed
            }
            None => Outcome::Failed,
        }
    };
    unsafe {
        (*out).outcome = RawOutcome::of(outcome);
    }
    RawOutcome::of(outcome)
}
#[allow(unsafe_code)]
unsafe extern "C" fn write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let i = unsafe { &*input.cast::<IoIn>() };
    let outcome = if pend(i.head.handle) {
        Outcome::Pending
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(i.buf, i.len) };
        match SCRIPT.with(|s| {
            let mut s = s.borrow_mut();
            if s.fail_write_after.is_some_and(|n| s.written.len() >= n) {
                None
            } else {
                let n = bytes.len().min(3);
                s.written.extend_from_slice(&bytes[..n]);
                Some(n)
            }
        }) {
            Some(n) => {
                unsafe {
                    (*out).len = n as u64;
                }
                Outcome::Ready
            }
            None => {
                unsafe {
                    (*out).error = AbiStr::of("auth fixture write failed");
                }
                Outcome::Failed
            }
        }
    };
    unsafe {
        (*out).outcome = RawOutcome::of(outcome);
    }
    RawOutcome::of(outcome)
}
#[allow(unsafe_code)]
unsafe extern "C" fn facts(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let i = unsafe { &*input.cast::<FactsIn>() };
    let outcome = if pend(i.head.handle) {
        Outcome::Pending
    } else {
        unsafe {
            i.facts.write(StreamFacts {
                size: size_of::<StreamFacts>() as u32,
                secure: SCRIPT.with(|s| u32::from(s.borrow().secure)),
                endpoint: AbiStr::ZERO,
                agreed_protocol: AbiStr::ZERO,
                peer_cert_hash: AbiStr::ZERO,
                peer_key_pin: AbiStr::ZERO,
                client_identity: 0,
                _reserved: 0,
            });
        }
        Outcome::Ready
    };
    unsafe {
        (*out).outcome = RawOutcome::of(outcome);
    }
    RawOutcome::of(outcome)
}
#[allow(unsafe_code)]
unsafe extern "C" fn close_stream(
    _: HostCtx,
    _: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    SCRIPT.with(|s| s.borrow_mut().closes += 1);
    unsafe {
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}
#[allow(unsafe_code)]
const CONNECTOR: ConnectorSlots = ConnectorSlots {
    size: size_of::<ConnectorSlots>() as u32,
    slots: connector::SERVICES,
    establish: Some(establish),
    read: Some(read),
    write: Some(write),
    facts: Some(facts),
    close: Some(close_stream),
    // All remaining slots are absent; the test exercises only the five operations above.
    ..unsafe { std::mem::zeroed() }
};
#[allow(unsafe_code)]
fn host() -> HostTables {
    HostTables {
        size: size_of::<HostTables>() as u32,
        conns: &CONNECTOR,
        ctx: HostCtx::NONE,
        ..unsafe { std::mem::zeroed() }
    }
}

fn greeting(plugin: &[u8]) -> Vec<u8> {
    let caps = (CapabilityFlags::CLIENT_PROTOCOL_41
        | CapabilityFlags::CLIENT_SECURE_CONNECTION
        | CapabilityFlags::CLIENT_LONG_PASSWORD
        | CapabilityFlags::CLIENT_PLUGIN_AUTH
        | CapabilityFlags::CLIENT_CONNECT_ATTRS
        | CapabilityFlags::CLIENT_CONNECT_WITH_DB)
        .bits();
    let mut payload = b"\x0a8.0.36\0\x01\0\0\0".to_vec();
    payload.extend_from_slice(&NONCE[..8]);
    payload.push(0);
    payload.extend_from_slice(&(caps as u16).to_le_bytes());
    payload.extend_from_slice(&[45, 2, 0]);
    payload.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(&NONCE[8..]);
    payload.push(0);
    payload.extend_from_slice(plugin);
    payload.push(0);
    packet(0, &payload)
}

fn script(plugin: &[u8], rest: impl IntoIterator<Item = Vec<u8>>) {
    SCRIPT.with(|state| {
        *state.borrow_mut() = Script {
            reads: std::iter::once(greeting(plugin)).chain(rest).collect(),
            ..Script::default()
        }
    });
}

fn frames() -> Vec<(u8, Vec<u8>)> {
    SCRIPT.with(|state| {
        let state = state.borrow();
        let mut bytes = state.written.as_slice();
        let mut out = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= 4);
            let len =
                usize::from(bytes[0]) | usize::from(bytes[1]) << 8 | usize::from(bytes[2]) << 16;
            assert!(bytes.len() >= len + 4);
            out.push((bytes[3], bytes[4..4 + len].to_vec()));
            bytes = &bytes[4 + len..];
        }
        out
    })
}

// A single pending OPEN of this actual door. Owners of all lent memory outlive each call.
struct Handshake<'h> {
    input: OpenIn,
    _secrets: Box<[Blob; 1]>,
    instance: *mut c_void,
    outcome: Outcome,
    _loan: PhantomData<(&'h HostTables, &'h [u8])>,
}
#[allow(unsafe_code)]
fn ops() -> &'static busbar_contract::abi::mechanism::lifecycle::OpsHead {
    // SAFETY: the actual macro door's static table starts with OpsHead.
    unsafe { &*busbar_contract::abi::mechanism::door::Door::read_parts(crate::door()).ops }
}
#[allow(unsafe_code)]
fn open_entry<'h>(host: &'h HostTables, url: &'h [u8]) -> Handshake<'h> {
    let secrets = Box::new([unsafe {
        Blob::from_raw_parts(
            url.as_ptr(),
            url.len(),
            busbar_contract::abi::mechanism::call::BLOB_OCTETS,
            0,
        )
    }]);
    let mut input: OpenIn = blank_in();
    input.head.size = size_of::<OpenIn>() as u32;
    input.head.op = busbar_contract::abi::mechanism::lifecycle::slot::OPEN;
    input.head.ticket = Ticket {
        slot: 19,
        generation: 1,
        ..Ticket::ZERO
    };
    input.settings = unsafe {
        Blob::from_raw_parts(
            br#"{"url":{"$secret":0},"input_budget":1048576}"#.as_ptr(),
            br#"{"url":{"$secret":0},"input_budget":1048576}"#.len(),
            busbar_contract::abi::mechanism::call::BLOB_JSON,
            0,
        )
    };
    input.host = host;
    input.secrets = secrets.as_ptr();
    input.secrets_len = 1;
    let mut h = Handshake {
        input,
        _secrets: secrets,
        instance: std::ptr::null_mut(),
        outcome: Outcome::Fault,
        _loan: PhantomData,
    };
    h.advance();
    h
}
impl Handshake<'_> {
    #[allow(unsafe_code)]
    fn advance(&mut self) {
        let mut out: OpenOut = blank_out();
        out.head.size = size_of::<OpenOut>() as u32;
        let previous = self.instance;
        // SAFETY: actual OPEN, matching live initialized frames, same ticket and instance on resume.
        self.outcome = unsafe {
            ops().open.unwrap()(
                self.instance,
                std::ptr::from_ref(&self.input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            )
        }
        .outcome();
        self.instance = out.instance;
        assert!(
            !SCRIPT.with(|s| s.borrow().invalid_read_capacity),
            "script bytes fit the lent READ buffer"
        );
        if matches!(self.outcome, Outcome::Ready | Outcome::Pending) {
            assert!(!self.instance.is_null());
            if !previous.is_null() {
                assert_eq!(previous, self.instance);
            }
        } else {
            assert!(self.instance.is_null(), "failed OPEN kept an instance");
        }
        self.input.head.flags |= busbar_contract::abi::mechanism::call::FLAG_RESUME;
    }
    #[allow(unsafe_code)]
    fn cancel(&mut self) {
        let mut input: CancelIn = blank_in();
        input.head.size = size_of::<CancelIn>() as u32;
        input.head.op = busbar_contract::abi::mechanism::lifecycle::slot::CANCEL;
        input.ticket = self.input.head.ticket;
        let mut out: CancelOut = blank_out();
        out.head.size = size_of::<CancelOut>() as u32;
        // SAFETY: this live pending instance's own ticket; matching CANCEL frames stay live.
        let answer = unsafe {
            ops().cancel.unwrap()(
                self.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            )
        }
        .outcome();
        assert_eq!(answer, Outcome::Ready);
    }
}
impl Drop for Handshake<'_> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if self.instance.is_null() {
            return;
        }
        let mut input: InHead = blank_in();
        input.size = size_of::<InHead>() as u32;
        input.op = busbar_contract::abi::mechanism::lifecycle::slot::CLOSE;
        let mut out: OutHead = blank_out();
        out.size = size_of::<OutHead>() as u32;
        // SAFETY: exclusive last call on this still-live actual instance, while loans remain owned.
        unsafe {
            ops().close.unwrap()(
                self.instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut out).cast(),
            );
        }
        self.instance = std::ptr::null_mut();
    }
}
fn open(url: &str) -> Outcome {
    let host = host();
    let mut h = open_entry(&host, url.as_bytes());
    for _ in 0..2048 {
        if h.outcome != Outcome::Pending {
            return h.outcome;
        }
        h.advance();
    }
    panic!("script did not finish")
}

fn dsn(options: &str) -> String {
    format!("mysql://u:{PASSWORD}@db/d?max_allowed_packet=65536{options}")
}

#[test]
fn literal_and_lent_dsn_capture_keep_only_public_configuration() {
    let url = dsn("&secure_auth=false&enable_cleartext_plugin=true");
    let settings = serde_json::json!({"url": url.as_str(), "input_budget":1048576}).to_string();
    let literal = MysqlV4::open(settings.as_bytes(), &[], None).unwrap();
    let lent = MysqlV4::open(
        br#"{"url":{"$secret":0},"input_budget":1048576}"#,
        &[url.as_bytes()],
        None,
    )
    .unwrap();
    assert_eq!(literal.opts.as_ref(), lent.opts.as_ref());
    let padded =
        serde_json::json!({"url": format!("  {url} \n"), "input_budget":1048576}).to_string();
    let padded = MysqlV4::open(padded.as_bytes(), &[], None).unwrap();
    assert_eq!(
        padded.opts.as_ref(),
        literal.opts.as_ref(),
        "settings trim before password and auth-floor capture"
    );
    let query_url = "mysql://u@db/d?secure_auth=false&password=p+q";
    let query =
        serde_json::json!({"url": format!("  {query_url} \n"), "input_budget":1048576}).to_string();
    let query = MysqlV4::open(query.as_bytes(), &[], None).unwrap();
    let exact = Opts::from_url(query_url).unwrap();
    assert_eq!(
        query.opts.as_ref(),
        &exact,
        "query password trailing whitespace is outside the DSN"
    );
    assert!(!lent.opts.secure_auth && lent.opts.enable_cleartext_plugin);
    let debug = format!("{:?}", lent.opts);
    assert!(!debug.contains(PASSWORD));
    assert_eq!(lent.opts.target(), "db:3306");
    for bytes in [
        br#"{"url":{"$secret":9}}"#.as_slice(),
        br#"{"url":99}"#,
        br#"{"url":"x","unknown":"CANARY-auth-17"}"#,
    ] {
        let error = MysqlV4::open(bytes, &[url.as_bytes()], None)
            .err()
            .expect("bad settings");
        assert!(!error.contains(PASSWORD), "{error}");
    }
}

#[test]
fn native_and_fast_sha2_handshakes_preserve_driver_bytes_across_partial_writes_and_pending() {
    for plugin in [
        AuthPlugin::MysqlNativePassword,
        AuthPlugin::CachingSha2Password,
    ] {
        let rest = if plugin == AuthPlugin::CachingSha2Password {
            vec![packet(2, &[1, 3]), packet(3, OK), packet(1, STOP)]
        } else {
            vec![packet(2, OK), packet(1, STOP)]
        };
        script(plugin.as_bytes(), rest);
        assert_eq!(open(&dsn("")), Outcome::Failed);
        let out = frames();
        assert_eq!(out[0].0, 1);
        let response = ParseBuf(&out[0].1)
            .parse::<HandshakeResponse<'_>>(())
            .unwrap();
        let data = plugin.gen_data(Some(PASSWORD), NONCE).unwrap();
        let expected = HandshakeResponse::new(
            Some(data.as_ref()),
            (8, 0, 36),
            Some(b"u"),
            Some(b"d"),
            Some(plugin),
            CapabilityFlags::CLIENT_PROTOCOL_41
                | CapabilityFlags::CLIENT_SECURE_CONNECTION
                | CapabilityFlags::CLIENT_LONG_PASSWORD
                | CapabilityFlags::CLIENT_PLUGIN_AUTH
                | CapabilityFlags::CLIENT_CONNECT_ATTRS
                | CapabilityFlags::CLIENT_CONNECT_WITH_DB,
            response.connect_attributes(),
            65536,
        );

        let mut expected_bytes = Vec::new();
        expected.serialize(&mut expected_bytes);
        assert_eq!(&out[0].1[..32], &expected_bytes[..32]);
        assert_eq!(response.scramble_buf(), &*data);
        assert_eq!(response.auth_plugin(), expected.auth_plugin());
        assert_eq!(
            response.connect_attributes().unwrap(),
            super::connect_attrs()
        );
        assert_eq!(response.user(), b"u");
        assert_eq!(response.db_name(), Some(b"d".as_slice()));
        assert_eq!(out[1].0, 0, "SQL starts a new sequence after auth");
        SCRIPT.with(|state| {
            let state = state.borrow();
            assert!(state.pends > 5);
            assert_eq!(state.opens, 1);
            assert_eq!(state.closes, 1);
        });
    }
}

#[test]
fn switched_old_native_sha2_and_clear_auth_keep_their_wire_packets_and_operator_flags() {
    for (plugin, options) in [
        (AuthPlugin::MysqlNativePassword, ""),
        (AuthPlugin::CachingSha2Password, ""),
        (AuthPlugin::MysqlOldPassword, "&secure_auth=false"),
        (
            AuthPlugin::MysqlClearPassword,
            "&enable_cleartext_plugin=true",
        ),
    ] {
        let mut request = vec![0xfe];
        request.extend_from_slice(plugin.as_bytes());
        request.push(0);
        request.extend_from_slice(NONCE);
        request.push(0);
        script(
            b"mysql_native_password",
            [packet(2, &request), packet(4, OK), packet(1, STOP)],
        );
        assert_eq!(open(&dsn(options)), Outcome::Failed);
        let out = frames();
        assert_eq!(out[1].0, 3);
        let mut expected = Vec::new();
        plugin
            .gen_data(Some(PASSWORD), NONCE)
            .unwrap()
            .serialize(&mut expected);
        assert_eq!(out[1].1, expected);
        assert_eq!(out[2].0, 0);
    }
    for name in [b"mysql_old_password".as_slice(), b"mysql_clear_password"] {
        let mut request = vec![0xfe];
        request.extend_from_slice(name);
        request.push(0);
        request.extend_from_slice(NONCE);
        request.push(0);
        script(b"mysql_native_password", [packet(2, &request)]);
        assert_eq!(open(&dsn("")), Outcome::Failed);
        assert_eq!(frames().len(), 1, "disabled plugins write no answer");
    }
}

#[test]
fn full_auth_over_operator_socket_sends_one_sealed_clear_packet() {
    script(
        b"caching_sha2_password",
        [packet(2, &[1, 4]), packet(4, OK), packet(1, STOP)],
    );
    assert_eq!(open(&dsn("&socket=/run/mysql.sock")), Outcome::Failed);
    let out = frames();
    assert_eq!(out[1], (3, [PASSWORD.as_bytes(), &[0]].concat()));
    assert_eq!(out[2].0, 0);
}

#[test]
fn cancelling_or_failing_a_partial_sealed_handshake_closes_it_and_reopen_starts_at_sequence_one() {
    script(b"mysql_native_password", [packet(2, OK), packet(1, STOP)]);
    let fake = host();
    let url = dsn("");
    let mut pending = open_entry(&fake, url.as_bytes());
    loop {
        assert_eq!(pending.outcome, Outcome::Pending);
        if SCRIPT.with(|state| !state.borrow().written.is_empty()) {
            break;
        }
        pending.advance();
    }
    pending.cancel();
    drop(pending);
    SCRIPT.with(|state| {
        let state = state.borrow();
        assert_eq!(state.closes, 1);
        assert_eq!(state.written.len(), 3);
    });
    script(b"mysql_native_password", []);
    SCRIPT.with(|state| state.borrow_mut().fail_write_after = Some(3));
    assert_eq!(open(&url), Outcome::Failed);
    SCRIPT.with(|state| {
        let state = state.borrow();
        assert_eq!(state.closes, 1);
        assert_eq!(state.written.len(), 3);
    });
    script(b"mysql_native_password", [packet(2, OK), packet(1, STOP)]);
    assert_eq!(open(&url), Outcome::Failed);
    assert_eq!(frames()[0].0, 1);
    SCRIPT.with(|state| assert_eq!(state.borrow().opens, 1));
}

const PUBLIC_KEY: &[u8] = b"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAeGNPEkihhFwx9XuiW0X6VMAp
LuC5WLdzvwnpZSXfmzok6brqc60v9bnBiCl/T9O5m7/eLcck0usOyQ9eV5p9T4Y4
ijJ7b5W7pYuuReJdv9h481JKwwV75KY1M6dRf7kpYFOCA4Zo8xgdso69qxPTVUXL
9WgH5N2PTtsNkF6eCwIDAQAB
-----END PUBLIC KEY-----
";
const KEY_PIN: &str = "6ddde6e6398722551e6dd73f2c62f247560990a999022d11fc55198facec8e98";

#[test]
fn full_sha2_auth_checks_the_operator_pin_and_sequence_before_sending_ciphertext() {
    let key = [b"\x01".as_slice(), PUBLIC_KEY].concat();
    for (options, encrypted) in [
        (
            format!("&server_public_key_sha256={}", KEY_PIN.to_uppercase()),
            true,
        ),
        (
            format!("&server_public_key_sha256={}", "ab".repeat(32)),
            false,
        ),
        (String::new(), false),
    ] {
        script(
            b"caching_sha2_password",
            [
                packet(2, &[1, 4]),
                packet(4, &key),
                packet(6, OK),
                packet(1, STOP),
            ],
        );
        assert_eq!(open(&dsn(&options)), Outcome::Failed);
        let out = frames();
        assert_eq!(
            out[1],
            (3, vec![2]),
            "request the server key in the public protocol"
        );
        if encrypted {
            assert_eq!(out[2].0, 5);
            assert_eq!(out[2].1.len(), 128);
            assert!(!out[2]
                .1
                .windows(PASSWORD.len())
                .any(|bytes| bytes == PASSWORD.as_bytes()));
            assert_eq!(
                out[3].0, 0,
                "the OK consumed sequence six before SQL begins"
            );
        } else {
            assert_eq!(
                out.len(),
                2,
                "untrusted key sends no credential-bearing full-auth packet"
            );
        }
        SCRIPT.with(|state| assert_eq!(state.borrow().closes, 1));
    }
    script(
        b"caching_sha2_password",
        [
            packet(2, &[1, 4]),
            packet(4, &key),
            packet(6, OK),
            packet(1, STOP),
        ],
    );
    SCRIPT.with(|state| state.borrow_mut().secure = true);
    assert_eq!(open(&dsn("")), Outcome::Failed);
    let out = frames();
    assert_eq!(out[2].0, 5);
    assert_eq!(
        out[2].1.len(),
        128,
        "an observed secured connection accepts the SDK seal without a pin"
    );
    assert_eq!(out[3].0, 0);
    for key in [b"k".as_slice(), b""] {
        let payload = [b"\x01".as_slice(), key].concat();
        script(
            b"caching_sha2_password",
            [packet(2, &[1, 4]), packet(4, &payload)],
        );
        assert_eq!(
            open(&dsn(&format!("&server_public_key_sha256={KEY_PIN}"))),
            Outcome::Failed
        );
        assert_eq!(frames().len(), 2);
    }
}

#[test]
fn empty_password_switch_and_full_socket_auth_keep_the_protocols_empty_packets() {
    let url = "mysql://u@db/d?max_allowed_packet=65536&socket=/run/mysql.sock";
    script(
        b"caching_sha2_password",
        [packet(2, &[1, 4]), packet(4, OK), packet(1, STOP)],
    );
    assert_eq!(open(url), Outcome::Failed);
    let out = frames();
    assert!(ParseBuf(&out[0].1)
        .parse::<HandshakeResponse<'_>>(())
        .unwrap()
        .scramble_buf()
        .is_empty());
    assert_eq!(out[1], (3, vec![0]));
    let request = [b"\xfemysql_native_password\0".as_slice(), NONCE, &[0]].concat();
    script(
        b"mysql_native_password",
        [packet(2, &request), packet(4, OK), packet(1, STOP)],
    );
    assert_eq!(open(url), Outcome::Failed);
    assert_eq!(frames()[1], (3, Vec::new()));
}
