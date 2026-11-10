// SPDX-License-Identifier: Apache-2.0
// Transferred protocol assertions from the SDK; the test-only host writer observes wire output.
use super::{CredUrl, MysqlAuth, MysqlHandshake};
use busbar_contract::abi::sdk::chip::{CredentialPart as Part, Digest, SealedValue};
use busbar_contract::abi::sdk::cred::{Seal, SealedWrite};
use busbar_contract::abi::sdk::test_support::chip::drive_sealed;
use std::task::Poll;
fn cred(s: &str) -> CredUrl {
    CredUrl::parse(&format!("mysql://u:{s}@h")).unwrap()
}
fn allowing(s: &str) -> CredUrl {
    CredUrl::parse(&format!(
        "mysql://u:{s}@h?secure_auth=false&enable_cleartext_plugin=true"
    ))
    .unwrap()
}
fn from_url(s: &str) -> CredUrl {
    CredUrl::parse(s).unwrap()
}
trait WireInspect {
    fn wire(&self) -> Vec<u8>;
}
impl WireInspect for Seal {
    fn wire(&self) -> Vec<u8> {
        let copy = SealedValue::compose(&[Part::Sealed(self)]).field();
        let mut writer = SealedWrite::message(copy);
        let mut out = Vec::new();
        assert!(matches!(
            drive_sealed::<()>(&mut writer, |bytes| {
                out.extend_from_slice(bytes);
                Poll::Ready(Ok(bytes.len()))
            }),
            Poll::Ready(Ok(()))
        ));
        out
    }
}
fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let inputs: Vec<_> = parts.iter().map(|part| Part::Public(part)).collect();
    SealedValue::compose(&inputs)
        .digest(Digest::Sha1)
        .field()
        .wire()
}
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let inputs: Vec<_> = parts.iter().map(|part| Part::Public(part)).collect();
    SealedValue::compose(&inputs)
        .digest(Digest::Sha256)
        .field()
        .wire()
        .try_into()
        .unwrap()
}
#[test]
fn mysql_scrambles_match_the_server_algorithms() {
    let c = cred("s3cr3t-pw");
    let nonce: Vec<u8> = (1..=20).collect();
    let native = c
        .mysql_auth_switch_response(2, MysqlAuth::Native, &nonce)
        .expect("native");
    assert_eq!(&native.wire()[..4], &[20, 0, 0, 2]);
    assert_eq!(
        hex::encode(&native.wire()[4..]),
        "568193bda62da86a7bd3e297f5d17dc3063744db"
    );
    let sha2 = c
        .mysql_auth_switch_response(3, MysqlAuth::CachingSha2, &nonce)
        .expect("sha2");
    assert_eq!(
        hex::encode(&sha2.wire()[4..]),
        "7256106a8256872cf1c750c6423a0c8aadcec0eeaec5b2c3c8219ef535b97049"
    );
    assert!(
        cred("")
            .mysql_auth_switch_response(2, MysqlAuth::Native, &nonce)
            .expect("empty")
            .wire()
            .len()
            == 4
    );
}

#[test]
fn mysql_handshake_response_lays_out_every_field() {
    let c = cred("s3cr3t-pw");
    let nonce: Vec<u8> = (1..=20).collect();
    let h = MysqlHandshake {
        seq: 1,
        capabilities: 0x0020_8000 | 0x0000_0200,
        max_packet: 16_777_216,
        collation: 45,
        user: b"alice",
        database: Some(b"db"),
        auth: MysqlAuth::Native,
        nonce: &nonce,
        attrs: &[(b"_client_name", b"busbar")],
    };
    let seal = c.mysql_handshake_response(&h).expect("response");
    let w = seal.wire();
    let len = u32::from_le_bytes([w[0], w[1], w[2], 0]) as usize;
    assert_eq!(len, w.len() - 4);
    assert_eq!(w[3], 1);
    let p = &w[4..];
    let caps = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    assert_eq!(caps & 0x0008_0000, 0x0008_0000, "plugin auth");
    assert_eq!(caps & 0x0000_0008, 0x0000_0008, "connect with db");
    assert_eq!(caps & 0x0010_0000, 0x0010_0000, "connect attrs");
    assert_eq!(&p[4..8], &16_777_216_u32.to_le_bytes());
    assert_eq!(p[8], 45);
    assert_eq!(&p[9..32], &[0; 23]);
    assert_eq!(&p[32..38], b"alice\0");
    assert_eq!(p[38], 20);
    assert_eq!(
        hex::encode(&p[39..59]),
        "568193bda62da86a7bd3e297f5d17dc3063744db"
    );
    assert_eq!(&p[59..62], b"db\0");
    assert_eq!(&p[62..84], b"mysql_native_password\0");
    assert_eq!(p[84], 1 + 12 + 1 + 6);
    assert_eq!(&p[85..], b"\x0c_client_name\x06busbar");
}

#[test]
fn mysql_clear_packet_is_nul_terminated() {
    let c = cred("pw");
    assert_eq!(
        c.mysql_clear_packet(5).expect("clear").wire(),
        b"\x03\0\0\x05pw\0"
    );
}

mod rsa_tests {
    use num_bigint::BigUint;

    use super::cred;
    use super::{sha1, WireInspect};

    /// A throwaway 1024-bit test key (generated for this test only): its public half as MySQL sends
    const PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAeGNPEkihhFwx9XuiW0X6VMAp
LuC5WLdzvwnpZSXfmzok6brqc60v9bnBiCl/T9O5m7/eLcck0usOyQ9eV5p9T4Y4
ijJ7b5W7pYuuReJdv9h481JKwwV75KY1M6dRf7kpYFOCA4Zo8xgdso69qxPTVUXL
9WgH5N2PTtsNkF6eCwIDAQAB
-----END PUBLIC KEY-----
";
    const D: &str = "24bd56479bb7dd8d04844cd5c2d2257379860cd673f32d6a27600a2651367f8e83f4d3e0e82c189d150cd652858955d59692927778c990cfea2ab25a8aa9b2457089a877e2b4980c55432d3cef569412f502c3d1a9a8e5b0f9e5ebb2a527b31b6a24a2ce35e7a7b47d74b1c07adacfcbd28b83dc30fa6614f9bf6bf19da166f1";
    const N: &str = "c078634f1248a1845c31f57ba25b45fa54c0292ee0b958b773bf09e96525df9b3a24e9baea73ad2ff5b9c188297f4fd3b99bbfde2dc724d2eb0ec90f5e579a7d4f86388a327b6f95bba58bae45e25dbfd878f3524ac3057be4a63533a7517fb929605382038668f3181db28ebdab13d35545cbf56807e4dd8f4edb0d905e9e0b";

    fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut c = 0_u32;
        while out.len() < len {
            out.extend_from_slice(&sha1(&[seed, &c.to_be_bytes()])[..]);
            c += 1;
        }
        out.truncate(len);
        out
    }

    #[test]
    fn rsa_public_api_accepts_pkcs1_or_one_spki_but_refuses_nested_spki() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let der = b64
            .decode(
                std::str::from_utf8(PEM)
                    .unwrap()
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();

        assert_eq!(&der[..4], &[0x30, 0x81, 0x9f, 0x30]);
        assert_eq!(&der[18..22], &[0x03, 0x81, 0x8d, 0x00]);
        let pem = |body: &[u8]| {
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                b64.encode(body)
            )
        };
        let direct = pem(&der[22..]);
        assert!(cred("pw")
            .mysql_rsa_packet(1, b"nonce", direct.as_bytes())
            .is_ok());
        assert!(cred("pw").mysql_rsa_packet(1, b"nonce", PEM).is_ok());

        let mut nested = vec![0x30, 0x81, 0xb5];
        nested.extend_from_slice(&der[3..18]);
        nested.extend_from_slice(&[0x03, 0x81, 0xa3, 0x00]);
        nested.extend_from_slice(&der);
        assert_eq!(nested.len(), 184);
        assert!(cred("pw")
            .mysql_rsa_packet(1, b"nonce", pem(&nested).as_bytes())
            .is_err());
        assert!(
            busbar_contract::abi::sdk::chip::rsa_public_key_sha256(pem(&nested).as_bytes())
                .is_err()
        );
        assert_eq!(
            busbar_contract::abi::sdk::chip::rsa_public_key_sha256(PEM).unwrap(),
            super::sha256(&[&der])
        );
    }

    /// RFC 8017 7.1.2 decryption, so the test checks what the server would read.
    fn decrypt(ct: &[u8]) -> Vec<u8> {
        let n = BigUint::parse_bytes(N.as_bytes(), 16).expect("n");
        let d = BigUint::parse_bytes(D.as_bytes(), 16).expect("d");
        let k = 128;
        let mut em = BigUint::from_bytes_be(ct).modpow(&d, &n).to_bytes_be();
        while em.len() < k {
            em.insert(0, 0);
        }
        assert_eq!(em[0], 0);
        let (masked_seed, masked_db) = em[1..].split_at(20);
        let seed: Vec<u8> = masked_seed
            .iter()
            .zip(mgf1(masked_db, 20))
            .map(|(a, b)| a ^ b)
            .collect();
        let db: Vec<u8> = masked_db
            .iter()
            .zip(mgf1(&seed, k - 21))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(&db[..20], &sha1(&[b""])[..], "lHash");
        let one = 20
            + db[20..]
                .iter()
                .position(|&b| b != 0)
                .expect("the 0x01 marker");
        assert_eq!(db[one], 1);
        db[one + 1..].to_vec()
    }

    #[test]
    fn the_rsa_packet_decrypts_to_the_password_xor_the_nonce() {
        let nonce: Vec<u8> = (1..=20).collect();
        let seal = cred("s3cr3t-pw")
            .mysql_rsa_packet(4, &nonce, PEM)
            .expect("encrypts");
        let w = seal.wire();
        assert_eq!(&w[..4], &[128, 0, 0, 4]);
        let plain = decrypt(&w[4..]);
        let want: Vec<u8> = b"s3cr3t-pw\0"
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ nonce[i % nonce.len()])
            .collect();
        assert_eq!(plain, want);
        let again = cred("s3cr3t-pw")
            .mysql_rsa_packet(4, &nonce, PEM)
            .expect("encrypts");
        assert_ne!(again.wire(), w, "a fresh OAEP seed each time");
    }

    #[test]
    fn a_bad_key_or_an_empty_nonce_is_refused() {
        assert!(cred("pw").mysql_rsa_packet(4, b"n", b"not a key").is_err());
        assert!(cred("pw").mysql_rsa_packet(4, b"", PEM).is_err());
    }

    /// `openssl pkey -pubin -outform der | sha256` of [`PEM`].
    const PIN: &str = "6ddde6e6398722551e6dd73f2c62f247560990a999022d11fc55198facec8e98";

    /// RULING S5: RSA full authentication goes to a server key the operator pinned, or over a unix
    #[test]
    fn rsa_full_auth_needs_a_pin_tls_or_a_unix_socket() {
        let nonce: Vec<u8> = (1..=20).collect();
        let open = super::from_url("mysql://u:pw@db/app")
            .mysql_rsa_packet(4, &nonce, PEM)
            .expect("built");
        assert!(
            open.secure_required(),
            "with no pin and no socket it goes out only on a secured connection"
        );
        let pinned = super::from_url(&format!(
            "mysql://u:pw@db/app?server_public_key_sha256={}",
            PIN.to_ascii_uppercase()
        ))
        .mysql_rsa_packet(4, &nonce, PEM)
        .expect("the pinned key");
        assert!(!pinned.secure_required());
        let socket = super::from_url("mysql://u:pw@localhost/app?socket=/run/mysqld/mysqld.sock")
            .mysql_rsa_packet(4, &nonce, PEM)
            .expect("a unix socket");
        assert!(!socket.secure_required());
        let other = format!(
            "mysql://u:pw@db/app?server_public_key_sha256={}",
            "ab".repeat(32)
        );
        let refused = super::from_url(&other)
            .mysql_rsa_packet(4, &nonce, PEM)
            .err()
            .expect("a key that is not the pinned one is refused");
        assert!(refused.0.contains("server_public_key_sha256"), "{refused}");

        let malformed = super::from_url("mysql://u:pw@db/app?server_public_key_sha256=zz")
            .mysql_rsa_packet(4, &nonce, PEM)
            .expect("built");
        assert!(malformed.secure_required());
    }
}

/// Byte for byte what `mysql_common` 0.37.3 (the 1.5.5 driver's codec) serializes for the same
#[test]
fn mysql_messages_match_the_driver_byte_for_byte() {
    let c = allowing("s3cr3t-pw");
    let nonce: Vec<u8> = (1..=20).collect();
    let h = MysqlHandshake {
        seq: 1,
        capabilities: 0x0020_8000 | 0x0000_0200,
        max_packet: 16_777_216,
        collation: 45,
        user: b"alice",
        database: Some(b"db"),
        auth: MysqlAuth::Native,
        nonce: &nonce,
        attrs: &[(b"_client_name", b"busbar")],
    };
    let seal = c.mysql_handshake_response(&h).expect("response");
    assert_eq!(
        hex::encode(&seal.wire()[4..]),
        "08823800000000012d0000000000000000000000000000000000000000000000616c6963650014568193bda62da86a7bd3e297f5d17dc3063744db6462006d7973716c5f6e61746976655f70617373776f726400140c5f636c69656e745f6e616d6506627573626172"
    );
    let old = c
        .mysql_auth_switch_response(3, MysqlAuth::Old, &nonce)
        .expect("old");
    assert_eq!(hex::encode(&old.wire()[4..]), "5e4f5a585d44525000");
    let clear = c
        .mysql_auth_switch_response(3, MysqlAuth::Clear, &nonce)
        .expect("clear");
    assert_eq!(&clear.wire()[4..], b"s3cr3t-pw\0");
    let empty = allowing("")
        .mysql_auth_switch_response(3, MysqlAuth::Clear, &nonce)
        .expect("empty");
    // Audit correction: cleartext always carries its NUL terminator, including empty passwords.
    assert_eq!(empty.wire(), &[1, 0, 0, 3, 0]);
}

/// RULING S4, MySQL: `mysql_clear_password` and `mysql_old_password` are refused unless the
#[test]
fn mysql_clear_and_old_are_refused_unless_the_operator_allows_them() {
    let nonce: Vec<u8> = (1..=20).collect();
    let h = |auth| MysqlHandshake {
        seq: 1,
        capabilities: 0x0020_8000,
        max_packet: 16_777_216,
        collation: 45,
        user: b"alice",
        database: None,
        auth,
        nonce: &nonce,
        attrs: &[],
    };
    let strict = from_url("mysql://u:pw@db/app");
    for auth in [MysqlAuth::Clear, MysqlAuth::Old] {
        let e = strict
            .mysql_handshake_response(&h(auth))
            .err()
            .expect("refused");
        let remedy = match auth {
            MysqlAuth::Clear => "enable_cleartext_plugin=true",
            _ => "secure_auth=false",
        };
        assert!(e.0.contains(remedy), "{e}");
        assert!(strict.mysql_auth_switch_response(3, auth, &nonce).is_err());
    }
    for auth in [MysqlAuth::Native, MysqlAuth::CachingSha2] {
        assert!(strict.mysql_handshake_response(&h(auth)).is_ok());
        assert!(strict.mysql_auth_switch_response(3, auth, &nonce).is_ok());
    }
    let clear = from_url("mysql://u:pw@db/app?enable_cleartext_plugin=true");
    assert!(clear
        .mysql_auth_switch_response(3, MysqlAuth::Clear, &nonce)
        .is_ok());
    assert!(clear
        .mysql_auth_switch_response(3, MysqlAuth::Old, &nonce)
        .is_err());
    let old = from_url("mysql://u:pw@db/app?secure_auth=false");
    assert!(old.mysql_handshake_response(&h(MysqlAuth::Old)).is_ok());
    assert!(old.mysql_handshake_response(&h(MysqlAuth::Clear)).is_err());

    let socket = from_url("mysql://u:pw@localhost/app?socket=/tmp/m.sock");
    assert!(socket
        .mysql_auth_switch_response(3, MysqlAuth::Clear, &nonce)
        .is_err());
}

/// RULING S5: the password in clear for `caching_sha2_password` full authentication goes out in the
#[test]
fn the_mysql_clear_packet_goes_out_in_the_open_only_on_a_socket() {
    assert!(from_url("mysql://u:pw@db/app")
        .mysql_clear_packet(5)
        .expect("built")
        .secure_required());
    assert!(!from_url("mysql://u:pw@localhost/app?socket=/tmp/m.sock")
        .mysql_clear_packet(5)
        .expect("built")
        .secure_required());
    assert!(
        !from_url("mysql://u:pw@db/app?enable_cleartext_plugin=true")
            .mysql_clear_packet(5)
            .expect("built")
            .secure_required()
    );
}

#[test]
fn empty_clear_password_is_nul_terminated_while_hashed_responses_stay_empty() {
    let c = allowing("");
    for auth in [MysqlAuth::Native, MysqlAuth::CachingSha2, MysqlAuth::Old] {
        assert_eq!(
            c.mysql_auth_switch_response(2, auth, &[1; 20])
                .unwrap()
                .wire(),
            [0, 0, 0, 2]
        );
    }
    assert_eq!(
        c.mysql_auth_switch_response(2, MysqlAuth::Clear, &[1; 20])
            .unwrap()
            .wire(),
        [1, 0, 0, 2, 0]
    );
}

#[test]
fn clear_password_one_byte_length_is_checked_before_framing() {
    let h = MysqlHandshake {
        seq: 1,
        capabilities: 0x0000_8000,
        max_packet: 16_777_216,
        collation: 45,
        user: b"u",
        database: None,
        auth: MysqlAuth::Clear,
        nonce: &[1; 20],
        attrs: &[],
    };
    let at_limit = allowing(&"p".repeat(254))
        .mysql_handshake_response(&h)
        .unwrap()
        .wire();
    assert_eq!(at_limit[38], 255);
    assert!(allowing(&"p".repeat(255))
        .mysql_handshake_response(&h)
        .is_err());
    let lenenc = MysqlHandshake {
        capabilities: h.capabilities | 0x0020_0000,
        ..h
    };
    let large = allowing(&"p".repeat(255))
        .mysql_handshake_response(&lenenc)
        .unwrap()
        .wire();
    assert_eq!(&large[38..41], &[0xfc, 0, 1]);
}
