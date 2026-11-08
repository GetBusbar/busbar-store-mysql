// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{Conn, DriverError, Error, Io, Opts, UrlError};
use mysql_common::packets::AuthSwitchRequest;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

thread_local! {
    static SEALED_TCP: std::cell::RefCell<Option<TcpStream>> = const { std::cell::RefCell::new(None) };
}

#[allow(unsafe_code)]
pub(super) fn write_sealed_tcp(
    stream: &TcpStream,
    seal: busbar_contract::abi::sdk::cred::Seal,
) -> Result<(), String> {
    use busbar_contract::abi::host::conn::connector::IoIn;
    use busbar_contract::abi::host::conn::connector::{self, ConnectorSlots};
    use busbar_contract::abi::host::service::ServiceOut;
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::call::{AbiStr, RawOutcome};
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
    use busbar_contract::abi::sdk::conn::Host;
    use busbar_contract::abi::sdk::cred::SealedWrite;
    unsafe extern "C" fn write_tcp(
        _: HostCtx,
        input: *const std::ffi::c_void,
        out: *mut ServiceOut,
    ) -> RawOutcome {
        // SAFETY: SealedWrite lends this WRITE frame and its buffer for this call.
        let i = unsafe { &*input.cast::<IoIn>() };
        let bytes = unsafe { std::slice::from_raw_parts(i.buf, i.len) };
        let result = SEALED_TCP.with(|cell| {
            std::io::Write::write(cell.borrow_mut().as_mut().expect("test TCP stream"), bytes)
        });
        let outcome = match result {
            Ok(n) => {
                unsafe {
                    (*out).len = n as u64;
                }
                Outcome::Ready
            }
            Err(_) => {
                unsafe {
                    (*out).error = AbiStr::of("test TCP write failed");
                }
                Outcome::Failed
            }
        };
        unsafe {
            (*out).outcome = RawOutcome::of(outcome);
        }
        RawOutcome::of(outcome)
    }
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            SEALED_TCP.with(|cell| {
                cell.borrow_mut().take();
            });
        }
    }
    SEALED_TCP
        .with(|cell| {
            *cell.borrow_mut() = Some(stream.try_clone()?);
            Ok::<_, std::io::Error>(())
        })
        .map_err(|e| e.to_string())?;
    let _clear = Clear;
    let slots = ConnectorSlots {
        size: std::mem::size_of::<ConnectorSlots>() as u32,
        slots: connector::SERVICES,
        write: Some(write_tcp),
        ..unsafe { std::mem::zeroed() }
    };
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        conns: &slots,
        ctx: HostCtx::NONE,
        ..unsafe { std::mem::zeroed() }
    };
    // SAFETY: tables and connector slots remain live through the sole sealed write below.
    let host =
        unsafe { Host::<busbar_contract::plugin::markers::StoreKind>::test_from_raw(&tables) };
    let mut connector = host.connector(Ticket {
        slot: 1,
        generation: 1,
    });
    let mut write = SealedWrite::message(seal);
    match write.poll(&mut connector, 1) {
        Poll::Ready(result) => result.map_err(|e| e.to_string()),
        Poll::Pending => Err("blocking test TCP write unexpectedly pended".into()),
    }
}

/// One MySQL packet: 3-byte little-endian length, the sequence id, the payload.
pub(super) fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let n = payload.len().to_le_bytes();
    let mut out = vec![n[0], n[1], n[2], seq];
    out.extend_from_slice(payload);
    out
}

/// A `Conn` over a plain TCP stream to a fake server running `script` on its own thread.
fn fake_server(
    script: impl FnOnce(TcpStream) + Send + 'static,
) -> (Conn, std::thread::JoinHandle<()>) {
    fake_server_at("mysql://u:p@127.0.0.1:1/d", script)
}

/// [`fake_server`] with the client's options parsed from `url`.
fn fake_server_at(
    url: &str,
    script: impl FnOnce(TcpStream) + Send + 'static,
) -> (Conn, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || script(listener.accept().unwrap().0));
    let stream = TcpStream::connect(addr).unwrap();
    let opts = Opts::from_url(url).unwrap();
    (Conn::new(Io::Tcp(stream), Arc::new(opts)), server)
}

/// Drive `f` to completion: the TCP transport blocks, so one poll finishes it.
fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the TCP transport must not pend"),
    }
}

/// The URL password never reaches an error: a server (or a proxy in front of it) whose ERR packet echoes it is scrubbed, and so is `Debug`.
#[test]
fn a_server_error_echoing_the_password_is_scrubbed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut s = listener.accept().unwrap().0;
        let mut err = vec![0xff, 0x15, 0x04];
        err.extend_from_slice(b"Access denied for u using password CANARY-my-p4ss");
        s.write_all(&packet(0, &err)).unwrap();
    });
    let stream = TcpStream::connect(addr).unwrap();
    let opts = Opts::from_url("mysql://u:CANARY%2Dmy%2Dp4ss@127.0.0.1:1/d").unwrap();
    let mut conn = Conn::new(Io::Tcp(stream), Arc::new(opts));
    let Err(err) = run(conn.handshake(&[])) else {
        panic!("the ERR packet refuses");
    };
    server.join().unwrap();
    for out in [err.to_string(), format!("{err:?}"), format!("{conn:?}")] {
        assert!(!out.contains("CANARY"), "password leaked: {out}");
    }
    assert!(err.to_string().contains("Access denied"), "{err}");
}

#[test]
fn an_empty_reply_packet_is_refused_not_a_panic() {
    let (mut conn, server) = fake_server(|mut s| {
        s.write_all(&packet(0, &[])).unwrap();
    });
    assert!(run(conn.handle_result_set()).is_err());
    assert!(conn.broken, "a corrupt reply must not keep the connection");
    server.join().unwrap();
}

/// A reply packet that fails to parse leaves the rest of the reply unread, so the connection
/// is desynced and must be discarded (never reset and kept by `release`).
#[test]
fn a_malformed_column_definition_breaks_the_connection() {
    let (mut conn, server) = fake_server(|mut s| {
        s.write_all(&packet(0, &[0x01])).unwrap(); // one column follows
        s.write_all(&packet(1, &[0x01, 0x02])).unwrap(); // not a column definition
    });
    assert!(run(conn.handle_result_set()).is_err());
    assert!(
        conn.broken,
        "a reply that failed to parse must not keep the connection"
    );
    server.join().unwrap();
}

/// A bare IPv6 literal in `host=` is an address, so the target brackets it.
#[test]
fn a_bare_ipv6_host_parameter_targets_bracketed() {
    let o = Opts::from_url("mysql://u:p@x/db?host=::1").unwrap();
    assert_eq!(o.target(), "[::1]:3306");
}

#[test]
fn a_lying_column_count_is_refused_not_an_allocation() {
    let (mut conn, server) = fake_server(|mut s| {
        let mut header = vec![0xfe];
        header.extend_from_slice(&u64::MAX.to_le_bytes());
        s.write_all(&packet(0, &header)).unwrap();
    });
    assert!(matches!(
        run(conn.handle_result_set()),
        Err(Error::DriverError(DriverError::UnexpectedPacket))
    ));
    assert!(conn.broken);
    server.join().unwrap();
}

/// A column count above MySQL's 4096 ceiling is refused by name before any definition is read.
#[test]
fn a_column_count_above_mysqls_ceiling_is_refused_as_an_unexpected_packet() {
    let (mut conn, server) = fake_server(|mut s| {
        s.write_all(&packet(0, &[0xfc, 0x89, 0x13])).unwrap(); // 5001 columns
    });
    let got = run(conn.handle_result_set()).err();
    assert!(
        matches!(got, Some(Error::DriverError(DriverError::UnexpectedPacket))),
        "{got:?}"
    );
    assert!(conn.broken, "the connection must not be kept");
    server.join().unwrap();
}

#[test]
fn full_auth_over_tcp_with_an_empty_nonce_is_refused_not_a_panic() {
    let (mut conn, server) = fake_server(|mut s| {
        s.write_all(&packet(0, &[0x01, 0x04])).unwrap();

        let mut buf = [0_u8; 5];
        if s.read(&mut buf).unwrap_or(0) > 0 {
            let _ = s.write_all(&packet(2, &[0x01, b'k']));
        }
    });
    conn.st.nonce.clear();
    assert!(run(conn.continue_caching_sha2(true)).is_err());
    drop(conn);
    server.join().unwrap();
}

/// M2: a key the server sends that is not a PEM public key is refused, not a panic in the RSA encrypt.
#[test]
fn full_auth_over_tcp_with_a_non_pem_key_is_refused_not_a_panic() {
    for key in [
        &b"k"[..],
        b"",
        b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
    ] {
        let key = key.to_vec();
        let (mut conn, server) = fake_server(move |mut s| {
            s.write_all(&packet(0, &[0x01, 0x04])).unwrap();
            let mut buf = [0_u8; 5];
            if s.read(&mut buf).unwrap_or(0) > 0 {
                let mut p = vec![0x01];
                p.extend_from_slice(&key);
                let _ = s.write_all(&packet(2, &p));
            }
        });
        conn.st.nonce = vec![7; 20];
        assert!(run(conn.continue_caching_sha2(true)).is_err());
        drop(conn);
        server.join().unwrap();
    }
}

/// M3: an auth switch to MariaDB's ed25519 (not built in) is refused, not a panic in the driver.
#[test]
fn an_auth_switch_to_ed25519_is_refused_not_a_panic() {
    let (mut conn, server) = fake_server(|_| {});
    let req = AuthSwitchRequest::new("client_ed25519".as_bytes(), &[7_u8; 32][..]).into_owned();
    let got = run(conn.auth_switch(req));
    assert!(
        matches!(
            got,
            Err(Error::DriverError(DriverError::UnknownAuthPlugin(ref n))) if n == "client_ed25519"
        ),
        "{got:?}"
    );
    drop(conn);
    server.join().unwrap();
}

/// M4: `mysql_old_password` with an empty (or short) nonce is refused, not a panic in the scramble.
#[test]
fn an_old_password_switch_with_no_nonce_is_refused_not_a_panic() {
    let (mut conn, server) = fake_server_at("mysql://u:p@127.0.0.1:1/d?secure_auth=false", |_| {});
    for nonce in [&[][..], &[1, 2, 3][..]] {
        let req = AuthSwitchRequest::new("mysql_old_password".as_bytes(), nonce).into_owned();
        assert!(run(conn.auth_switch(req)).is_err());
    }
    drop(conn);
    server.join().unwrap();
}

/// M5: a switch to `mysql_clear_password` with the cleartext plugin off says so.
#[test]
fn a_cleartext_switch_with_the_plugin_off_is_named_as_disabled() {
    let (mut conn, server) = fake_server(|_| {});
    let req =
        AuthSwitchRequest::new("mysql_clear_password".as_bytes(), &[1_u8; 20][..]).into_owned();
    let got = run(conn.auth_switch(req));
    assert!(
        matches!(
            got,
            Err(Error::DriverError(DriverError::CleartextPluginDisabled))
        ),
        "{got:?}"
    );
    drop(conn);
    server.join().unwrap();
}

/// A server-reported `@@max_allowed_packet` outside MySQL's own range is refused at setup.
#[test]
fn server_reported_max_allowed_packet_outside_mysqls_range_is_refused() {
    for v in [0usize, 1, 1023, (1 << 30) + 1, 1 << 40] {
        assert!(super::checked_packet_ceiling(v).is_err(), "{v} accepted");
    }
    assert_eq!(super::checked_packet_ceiling(1024).unwrap(), 1024);
    assert_eq!(super::checked_packet_ceiling(1 << 30).unwrap(), 1 << 30);
}

/// A TLS-prefixed query key can be the tail of an unencoded password; its text is withheld.
#[test]
fn tls_prefixed_key_in_a_password_url_does_not_echo_the_tail() {
    let e = Opts::from_url("mysql://u:123?tlsSECRET@h/db")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("SECRET"), "{e}");
    // Without a password the key is still named.
    let e = Opts::from_url("mysql://u@h/d?tlsmode=1")
        .unwrap_err()
        .to_string();
    assert!(e.contains("tlsmode"), "{e}");
}

/// M17: `max_allowed_packet` outside MySQL's 1024..=1 GiB is refused at parse, naming the parameter and the range (not truncated to a u32 or accepted as 0 and failed at connect).
#[test]
fn max_allowed_packet_outside_mysqls_range_is_refused_at_parse() {
    for v in ["0", "1", "1023", "4294967296", "1073741825"] {
        let e = Opts::from_url(&format!("mysql://u@h/d?max_allowed_packet={v}"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("`max_allowed_packet`") && e.contains("between 1024 and 1073741824 bytes"),
            "{v}: {e}"
        );
    }
    assert!(Opts::from_url("mysql://u@h/d?max_allowed_packet=1024").is_ok());
    assert!(Opts::from_url("mysql://u@h/d?max_allowed_packet=1073741824").is_ok());
}

#[test]
fn a_url_parses_as_the_driver_parsed_it() {
    let o = Opts::from_url("mysql://u%40x:p%3Ass@db.internal:3307/busbar?compress=true").unwrap();
    assert_eq!(o.user.as_deref(), Some("u@x"));
    assert_eq!(o.credential_url.credential().len(), 4);
    assert!(!o.credential_url.public().contains("p%3Ass"));
    assert_eq!(o.target(), "db.internal:3307");
    assert_eq!(o.db_name.as_deref(), Some("busbar"));
    assert!(o.compress);
    let o = Opts::from_url("mysql://u@[::1]/d").unwrap();
    assert_eq!(o.target(), "[::1]:3306");
    assert_eq!(o.address(), "::1:3306");
    assert!(o.credential_url.password().is_none());
    let o = Opts::from_url("mysql://u@localhost/d?socket=/run/mysqld/mysqld.sock").unwrap();
    assert_eq!(o.target(), "unix:/run/mysqld/mysqld.sock");
}

#[test]
fn what_the_driver_refused_is_refused_in_its_words() {
    let e = |u: &str| Opts::from_url(u).unwrap_err().to_string();
    assert_eq!(
        e("postgres://u@h/d"),
        "URL scheme `postgres' is not supported"
    );
    assert_eq!(e("mysql://u@h/d?bogus=1"), "Unknown URL parameter `bogus'");
    assert!(e("mysql://u@h/d?require_ssl=true").contains("TLS is not supported"));
    assert_eq!(
        e("mysql://u@h/d?port=x"),
        "Invalid value `x' for URL parameter `port'"
    );
    assert_eq!(
        e("mysql://u@h/d?compress=maybe"),
        "Invalid value `maybe' for URL parameter `compress'"
    );
    assert!(matches!(
        Opts::from_url("not a url"),
        Err(UrlError::ParseError(_))
    ));
    assert_eq!(
        e("not a url"),
        "URL ParseError { relative URL without a base }"
    );
}

/// An unencoded `?` in a password splits the URL there: the tail becomes a "parameter".
#[test]
fn a_url_refusal_never_carries_the_password() {
    for url in [
        "mysql://u:12?abc@h/db",
        "mysql://u:12?port=zz@h/db",
        "mysql://u:12?tlsCANARY@h/db",
        "mysql://u:12?sslCANARY@h/db",
        "mysql://u:p%40ss%3Fword@h/db?bogus=1",
        "mysql://u@h/db?password=hunter2&bogus=1",
        "mysql://u@h/db?password=hunter2&port=zz",
    ] {
        let e = Opts::from_url(url).unwrap_err().to_string();
        for secret in [
            "12?abc",
            "abc@h",
            "p@ss?word",
            "p%40ss%3Fword",
            "hunter2",
            "zz@h",
            "tlsCANARY",
            "sslCANARY",
        ] {
            assert!(!e.contains(secret), "{url}: {secret:?} leaked in {e:?}");
        }
    }
    let e = Opts::from_url("mysql://u:12?abc@h/db")
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("withheld") && e.contains("percent-encode"),
        "{e}"
    );
    for prefix in ["tls", "ssl"] {
        let e = Opts::from_url(&format!("mysql://u:12?{prefix}CANARY@h/db"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("withheld"), "{e}");
    }

    assert_eq!(
        Opts::from_url("mysql://u@h/d?bogus=1")
            .unwrap_err()
            .to_string(),
        "Unknown URL parameter `bogus'"
    );
}

#[test]
fn an_accepted_but_ignored_parameter_is_refused_never_silent() {
    let e = |u: &str| Opts::from_url(u).unwrap_err().to_string();
    for k in [
        "pool_min=1",
        "pool_max=5",
        "prefer_socket=true",
        "reset_connection=false",
        "check_health=false",
        "tcp_keepalive_time_ms=1000",
        "tcp_keepalive_probe_interval_secs=5",
        "tcp_keepalive_probe_count=3",
        "tcp_user_timeout_ms=1000",
        "stmt_cache_size=4",
    ] {
        let name = k.split('=').next().unwrap();
        let m = e(&format!("mysql://u@h/d?{k}"));
        assert!(
            m.starts_with(&format!(
                "mysql store: URL parameter `{name}` is not supported:"
            )),
            "{k}: {m}"
        );
    }
    assert_eq!(
        e("mysql://u@h/d?pool_max=5"),
        "mysql store: URL parameter `pool_max` is not supported: this store keeps 8 \
         connections over the host's connector"
    );
    for k in [
        "ssl",
        "ssl-mode",
        "ssl_mode",
        "require_ssl",
        "verify_ca",
        "verify_identity",
    ] {
        let m = e(&format!("mysql://u@h/d?{k}=true"));
        assert!(
            m.contains(&format!("`{k}`")) && m.contains("TLS is not supported by this store"),
            "{k}: {m}"
        );
    }

    let o = Opts::from_url(
        "mysql://u@h/d?tcp_connect_timeout_ms=500&max_allowed_packet=65536&compress=true\
         &secure_auth=true&enable_cleartext_plugin=false",
    )
    .unwrap();
    assert_eq!(o.tcp_connect_timeout_ms, Some(500));
    assert!(o.compress);
}

#[test]
fn scrub_redacts_every_spelling_of_the_password() {
    let o = Opts::from_url("mysql://u:p%40ss%3Aw@127.0.0.1:1/d").unwrap();
    assert_eq!(
        o.scrub("a p%40ss%3Aw b p@ss:w c p%40ss%3aw".into()),
        "a <redacted> b <redacted> c <redacted>"
    );
    assert_eq!(o.scrub("plain".into()), "plain");
    let unicode = Opts::from_url("mysql://u:p%C3%A9%3Fa@h/d").unwrap();
    assert_eq!(
        unicode.scrub("pé?a p%c3%a9%3fa p%C3%a9%3Fa P%c3%a9%3fa".into()),
        "<redacted> <redacted> <redacted> P%c3%a9%3fa",
        "only percent-escape hex digits are case-insensitive; password letters are not"
    );
    let debug = format!("{o:?}");
    for spelling in ["p@ss:w", "p%40ss%3Aw", "p%40ss%3aw"] {
        assert!(
            !debug.contains(spelling),
            "Debug must omit password spellings"
        );
    }
}

#[test]
fn compression_levels_are_honored_and_invalid_levels_are_refused() {
    for (setting, level) in [("0", 0), ("8", 8), ("fast", 1), ("best", 9), ("true", 6)] {
        let opts = Opts::from_url(&format!("mysql://u@h/d?compress={setting}")).unwrap();
        assert!(opts.compress);
        assert_eq!(opts.compression_level, level);
    }
    assert!(Opts::from_url("mysql://u@h/d?compress=10").is_err());
}

#[test]
fn a_failed_abandoned_rollback_discards_the_connection() {
    let (mut conn, server) = fake_server(|mut stream| {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).unwrap();
        let length =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(&body[1..], b"ROLLBACK");
        stream
            .write_all(&packet(1, &[0xff, 0x15, 0x04, b'x']))
            .unwrap();
    });
    conn.rollback_pending = true;
    assert!(run(conn.settle()).is_err());
    assert!(
        conn.broken,
        "a failed rollback must never return an active transaction to the pool"
    );
    assert!(conn.rollback_pending);
    server.join().unwrap();
}

#[test]
fn result_budget_refuses_the_first_row_or_byte_over_the_limit() {
    use super::{result_budget_exceeded, MAX_RESULT_BYTES, MAX_RESULT_ROWS};
    assert!(!result_budget_exceeded(MAX_RESULT_ROWS, MAX_RESULT_BYTES));
    assert!(result_budget_exceeded(MAX_RESULT_ROWS + 1, 0));
    assert!(result_budget_exceeded(1, MAX_RESULT_BYTES + 1));
}

#[test]
fn secret_values_are_wiped_before_their_storage_is_released() {
    let mut value = super::Value::Bytes(b"credential-canary".to_vec());
    super::wipe_value(&mut value);
    assert!(matches!(value, super::Value::Bytes(bytes) if bytes.is_empty()));
}

#[test]
fn result_metadata_requires_an_eof_terminator() {
    use mysql_common::constants::ColumnType;
    use mysql_common::packets::Column;
    use mysql_common::proto::MySerialize;
    let (mut conn, server) = fake_server(|mut stream| {
        let mut column = Vec::new();
        Column::new(ColumnType::MYSQL_TYPE_VAR_STRING).serialize(&mut column);
        stream.write_all(&packet(0, &[1])).unwrap();
        stream.write_all(&packet(1, &column)).unwrap();
        stream.write_all(&packet(2, &[1, b'x'])).unwrap();
    });
    assert!(run(conn.handle_result_set()).is_err());
    assert!(conn.broken);
    server.join().unwrap();
}

#[test]
fn surplus_result_sets_are_bounded_on_the_wire() {
    use mysql_common::constants::StatusFlags;
    let (mut conn, server) = fake_server(|mut stream| {
        let status = StatusFlags::SERVER_MORE_RESULTS_EXISTS.bits().to_le_bytes();
        for sequence in 0..=super::MAX_RESULT_SETS {
            let ok = [0, 0, 0, status[0], status[1], 0, 0];
            stream.write_all(&packet(sequence as u8, &ok)).unwrap();
        }
    });
    conn.st.caps = mysql_common::constants::CapabilityFlags::CLIENT_PROTOCOL_41;
    let meta = run(conn.handle_result_set()).unwrap();
    assert!(run(conn.rows_kept(meta, false, 0)).is_err());
    assert!(conn.broken);
    server.join().unwrap();
}

#[test]
fn guarded_rows_parse_text_and_binary_and_reject_partial_secret_rows() {
    use mysql_common::constants::ColumnType;
    use mysql_common::packets::Column;
    let columns: Arc<[Column]> = vec![Column::new(ColumnType::MYSQL_TYPE_VAR_STRING); 2].into();
    for (binary, packet) in [
        (false, b"\x03one\x03two".as_slice()),
        (true, b"\0\0\x03one\x03two".as_slice()),
    ] {
        let mut row = super::parse_row(packet, columns.clone(), binary).unwrap();
        assert_eq!(row.take::<Vec<u8>, _>(0).unwrap(), b"one");
        assert_eq!(row.take::<Vec<u8>, _>(1).unwrap(), b"two");
        assert!(super::parse_row(&packet[..packet.len() - 1], columns.clone(), binary).is_err());
    }
    assert!(super::parse_row(b"\x01\0\x03one\x03two", columns, true).is_err());
}

/// Exercise the selected production dependency, so a manifest heal cannot silently
/// restore the unwiped registry codec while the isolated vendor harness still passes.
#[test]
#[allow(unsafe_code)]
fn production_codec_consumed_plaintext_is_erased() {
    let secret = b"guarded-production-credential";
    let mut source = bytes::BytesMut::new();
    source.extend_from_slice(&[u8::try_from(secret.len()).unwrap(), 0, 0, 0]);
    source.extend_from_slice(secret);
    let tail = [1, 0, 0, 1, b'!'];
    source.extend_from_slice(&tail);
    let pointer = source.as_ptr();
    let consumed = 4 + secret.len();
    let mut decoded = Vec::new();
    let mut codec = mysql_common::proto::codec::PacketCodec::default();
    assert!(codec.decode(&mut source, &mut decoded).unwrap());
    assert_eq!(decoded, secret);
    assert_eq!(&source[..], &tail);
    // SAFETY: the untouched tail keeps the original allocation alive. The entire
    // consumed prefix was initialized before decoding; no freed memory is read.
    let consumed = unsafe { std::slice::from_raw_parts(pointer, consumed) };
    assert!(
        consumed.iter().all(|&byte| byte == 0),
        "the selected production codec must erase consumed plaintext"
    );
}
