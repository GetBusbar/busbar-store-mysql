// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MySQL settings capture, authentication policy and private derived-verifier custody.
//! URL parsing sees plaintext only during ingestion; every retained password is an SDK Cred.

use busbar_contract::abi::sdk::cred::{redact_encoded_echoes, Cred};
use zeroize::Zeroizing;

mod legacy_auth;
mod url_capture;
mod wire;
pub(crate) use wire::{MysqlAuth, MysqlHandshake};

type Bytes = Zeroizing<Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordAt {
    Userinfo,
    UserinfoUnencoded,
    Query(&'static str),
}

#[derive(Clone, PartialEq, Eq, Default)]
struct AuthPolicy {
    clear: bool,
    old: bool,
    local: bool,
    secure: bool,
    rsa_pin: Option<[u8; 32]>,
}

impl AuthPolicy {
    fn parse(public: &str) -> Self {
        let mut policy = Self::default();
        let Ok(url) = url::Url::parse(public) else {
            return policy;
        };
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "enable_cleartext_plugin" => policy.clear = value == "true",
                "secure_auth" => policy.old = value == "false",
                "socket" => policy.local = !value.is_empty(),
                "server_public_key_sha256" if value.len() == 64 => {
                    let mut bytes = [0; 32];
                    let valid = value
                        .as_bytes()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .zip(bytes.iter_mut())
                        .all(|(pair, out)| {
                            match (
                                char::from(pair[0]).to_digit(16),
                                char::from(pair[1]).to_digit(16),
                            ) {
                                (Some(hi), Some(lo)) => {
                                    *out = (hi << 4 | lo) as u8;
                                    true
                                }
                                _ => false,
                            }
                        });
                    if valid {
                        policy.rsa_pin = Some(bytes);
                    }
                }
                _ => {}
            }
            match key.to_ascii_lowercase().as_str() {
                "sslmode" | "ssl-mode" | "ssl_mode" => {
                    policy.secure |= matches!(
                        value.to_ascii_lowercase().as_str(),
                        "require"
                            | "verify-ca"
                            | "verify-full"
                            | "required"
                            | "verify_ca"
                            | "verify_identity"
                    )
                }
                "ssl" | "tls" => policy.secure |= value.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }
        // The owner chooses the actual socket endpoint. A TLS URL flag cannot turn that
        // local endpoint into a network stream; native option validation still rejects TLS.
        policy.secure &= !policy.local;
        policy
    }
}

#[derive(Clone)]
pub(crate) struct CredUrl {
    public: String,
    password: Option<Cred>,
    at: Option<PasswordAt>,
    policy: AuthPolicy,
    legacy: Option<legacy_auth::OldVerifier>,
}

impl PartialEq for CredUrl {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
            && self.password == other.password
            && self.at == other.at
            && self.policy == other.policy
    }
}
impl Eq for CredUrl {}

impl CredUrl {
    pub(crate) fn parse(text: &str) -> Result<Self, &'static str> {
        let (public, found) = match text.find("://") {
            Some(i) => url_capture::split_url(text, i, true)?,
            None => (text.to_owned(), None),
        };
        let policy = AuthPolicy::parse(&public);
        let legacy = if policy.old {
            let plaintext = found
                .as_ref()
                .map_or(&[][..], |(bytes, _)| bytes.as_slice());
            Some(
                legacy_auth::OldVerifier::capture_at_ingestion(plaintext, true, policy.secure)
                    .map_err(|error| error.0)?,
            )
        } else {
            None
        };
        let (password, at) = match found {
            Some((bytes, at)) => (
                Some(Cred::captured(bytes).require_secure_if(policy.secure)),
                Some(at),
            ),
            None => (None, None),
        };
        Ok(Self {
            public,
            password,
            at,
            policy,
            legacy,
        })
    }

    pub(crate) fn public(&self) -> &str {
        &self.public
    }
    pub(crate) fn password(&self) -> Option<&Cred> {
        self.password.as_ref()
    }
    pub(crate) fn password_at(&self) -> Option<PasswordAt> {
        self.at
    }
    pub(crate) fn redact_echo(&self, text: &str) -> String {
        redact_encoded_echoes(text, &self.password.iter().collect::<Vec<_>>())
    }
}

pub(crate) struct MysqlUrl(pub(crate) CredUrl);

impl<'de> serde::Deserialize<'de> for MysqlUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Capture;
        impl serde::de::Visitor<'_> for Capture {
            type Value = MysqlUrl;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<MysqlUrl, E> {
                CredUrl::parse(value.trim())
                    .map(MysqlUrl)
                    .map_err(|_| E::custom("invalid credential URL"))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<MysqlUrl, E> {
                self.visit_str(&Zeroizing::new(value))
            }
        }
        deserializer.deserialize_string(Capture)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_capture_and_native_tls_refusal_have_distinct_rules() {
        let url = CredUrl::parse("mysql://u:private@db/app?socket=/tmp/m.sock&ssl-mode=required")
            .unwrap();
        assert!(!url.password().unwrap().secure_required());
        let error = crate::mysqlwire::Opts::from_captured(url)
            .unwrap_err()
            .to_string();
        assert!(error.contains("TLS is not supported"));
        assert!(!error.contains("private"));
        let url = CredUrl::parse("mysql://u:private@db/app?ssl-mode=required").unwrap();
        assert!(url.password().unwrap().secure_required());
        let socket = CredUrl::parse("mysql://u:private@db/app?socket=/tmp/m.sock").unwrap();
        assert!(!socket.mysql_clear_packet(1).unwrap().secure_required());
        assert_eq!(
            crate::mysqlwire::Opts::from_captured(socket)
                .unwrap()
                .target(),
            "unix:/tmp/m.sock"
        );
    }
}

#[cfg(test)]
mod transferred_tests;

#[cfg(test)]
mod capture_tests;
