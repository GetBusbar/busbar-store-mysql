// SPDX-License-Identifier: Apache-2.0
use super::*;
use busbar_contract::abi::sdk::chip::{
    rsa_public_key_sha256, CredentialPart as Part, Digest, Refused, SealedValue,
};
use busbar_contract::abi::sdk::cred::Seal;
/// RULING S4: a MySQL server asked for `mysql_clear_password`.
pub const MYSQL_CLEAR_REFUSED: Refused = Refused(
    "the server asked for mysql_clear_password (the password in clear), which the operator's URL \
     does not allow: add `enable_cleartext_plugin=true` to allow it",
);

/// RULING S4: a MySQL server asked for `mysql_old_password`.
pub const MYSQL_OLD_REFUSED: Refused = Refused(
    "the server asked for mysql_old_password (the pre-4.1 scramble), which the operator's URL \
     does not allow: add `secure_auth=false` to allow it",
);

/// RULING S5: the server's RSA key is not the one the operator pinned.
pub const MYSQL_RSA_PIN_MISMATCH: Refused = Refused(
    "the MySQL server's RSA public key does not match the operator's `server_public_key_sha256` \
     pin, so the password was not sent: check the pin against the server's key",
);

/// Which MySQL auth plugin a handshake response answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlAuth {
    /// `mysql_native_password`: SHA-1 scramble.
    Native,
    /// `caching_sha2_password`: SHA-256 scramble.
    CachingSha2,
    /// `mysql_old_password` (pre-4.1; a plugin allows it only when the operator turned
    /// `secure_auth` off).
    Old,
    /// `mysql_clear_password`: the password itself (a plugin allows it only when the operator
    /// enabled the cleartext plugin).
    Clear,
}

impl MysqlAuth {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Native => b"mysql_native_password",
            Self::CachingSha2 => b"caching_sha2_password",
            Self::Old => b"mysql_old_password",
            Self::Clear => b"mysql_clear_password",
        }
    }
}

/// The public inputs of a MySQL `HandshakeResponse41`.
#[derive(Debug, Clone, Copy)]
pub struct MysqlHandshake<'a> {
    /// The packet's sequence id.
    pub seq: u8,
    /// The client capability flags as the client will send them.
    pub capabilities: u32,
    /// Max packet size.
    pub max_packet: u32,
    /// Collation id.
    pub collation: u8,
    /// The user name.
    pub user: &'a [u8],
    /// The database, when `CLIENT_CONNECT_WITH_DB`.
    pub database: Option<&'a [u8]>,
    /// The auth plugin answered.
    pub auth: MysqlAuth,
    /// The server's 20-byte nonce.
    pub nonce: &'a [u8],
    /// Connection attributes, when `CLIENT_CONNECT_ATTRS`.
    pub attrs: &'a [(&'a [u8], &'a [u8])],
}

const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

fn lenenc(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=250 => out.push(n as u8),
        251..=0xffff => {
            out.push(0xfc);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xff_ffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn lenenc_len(n: u64) -> u64 {
    match n {
        0..=250 => 1,
        251..=0xffff => 3,
        0x1_0000..=0xff_ffff => 4,
        _ => 9,
    }
}

fn mysql_packet(seq: u8, payload: &SealedValue) -> Result<Seal, Refused> {
    if payload.len() >= 0xff_ffff {
        return Err(Refused("the auth packet does not fit one MySQL packet"));
    }
    let mut header = (payload.len() as u32).to_le_bytes();
    header[3] = seq;
    Ok(SealedValue::compose(&[Part::Public(&header), Part::Value(payload)]).field())
}

impl CredUrl {
    fn value(&self) -> SealedValue {
        self.password
            .clone()
            .unwrap_or_else(Cred::empty)
            .require_secure_if(self.policy.secure)
            .sealed_value()
    }

    fn allows(&self, auth: MysqlAuth) -> Result<(), Refused> {
        match auth {
            MysqlAuth::Old if !self.policy.old => Err(MYSQL_OLD_REFUSED),
            MysqlAuth::Clear if !self.policy.clear => Err(MYSQL_CLEAR_REFUSED),
            _ => Ok(()),
        }
    }

    fn scramble(&self, auth: MysqlAuth, nonce: &[u8]) -> Result<SealedValue, Refused> {
        self.allows(auth)?;
        let value = self.value();
        if value.is_empty() && auth != MysqlAuth::Clear {
            return Ok(value);
        }
        match auth {
            MysqlAuth::Native => {
                let first = value.digest(Digest::Sha1);
                let second = first.digest(Digest::Sha1);
                let third = SealedValue::compose(&[Part::Public(nonce), Part::Value(&second)])
                    .digest(Digest::Sha1);
                first.xor(&third)
            }
            MysqlAuth::CachingSha2 => {
                let first = value.digest(Digest::Sha256);
                let second = first.digest(Digest::Sha256);
                let third = SealedValue::compose(&[Part::Value(&second), Part::Public(nonce)])
                    .digest(Digest::Sha256);
                first.xor(&third)
            }
            MysqlAuth::Old => {
                let legacy = self.legacy.as_ref().ok_or(Refused(
                    "mysql_old_password was not allowed at credential ingestion",
                ))?;
                let response = legacy.response(nonce, self.policy.secure)?;
                Ok(SealedValue::compose(&[Part::Sealed(&response)]))
            }
            MysqlAuth::Clear => Ok(SealedValue::compose(&[
                Part::Value(&value),
                Part::Public(&[0]),
            ])),
        }
    }

    pub(crate) fn mysql_handshake_response(&self, h: &MysqlHandshake<'_>) -> Result<Seal, Refused> {
        self.allows(h.auth)?;
        let mut caps = h.capabilities | CLIENT_PLUGIN_AUTH;
        if h.database.is_some() {
            caps |= CLIENT_CONNECT_WITH_DB;
        } else {
            caps &= !CLIENT_CONNECT_WITH_DB;
        }
        if h.attrs.is_empty() {
            caps &= !CLIENT_CONNECT_ATTRS;
        } else {
            caps |= CLIENT_CONNECT_ATTRS;
        }
        let scramble = self.scramble(h.auth, h.nonce)?;
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&caps.to_le_bytes());
        prefix.extend_from_slice(&h.max_packet.to_le_bytes());
        prefix.push(h.collation);
        prefix.extend_from_slice(&[0; 23]);
        prefix.extend_from_slice(h.user);
        prefix.push(0);
        let mut suffix = Vec::new();
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            lenenc(&mut prefix, scramble.len() as u64);
        } else if caps & CLIENT_SECURE_CONNECTION != 0 {
            let len = u8::try_from(scramble.len())
                .map_err(|_| Refused("the auth response does not fit a one-byte length"))?;
            prefix.push(len);
        } else {
            suffix.push(0);
        }
        if let Some(db) = h.database {
            suffix.extend_from_slice(db);
            suffix.push(0);
        }
        suffix.extend_from_slice(h.auth.name());
        suffix.push(0);
        if !h.attrs.is_empty() {
            let total: u64 = h
                .attrs
                .iter()
                .map(|(k, v)| {
                    lenenc_len(k.len() as u64)
                        + k.len() as u64
                        + lenenc_len(v.len() as u64)
                        + v.len() as u64
                })
                .sum();
            lenenc(&mut suffix, total);
            for (key, value) in h.attrs {
                lenenc(&mut suffix, key.len() as u64);
                suffix.extend_from_slice(key);
                lenenc(&mut suffix, value.len() as u64);
                suffix.extend_from_slice(value);
            }
        }
        mysql_packet(
            h.seq,
            &SealedValue::compose(&[
                Part::Public(&prefix),
                Part::Value(&scramble),
                Part::Public(&suffix),
            ]),
        )
    }

    pub(crate) fn mysql_auth_switch_response(
        &self,
        seq: u8,
        auth: MysqlAuth,
        nonce: &[u8],
    ) -> Result<Seal, Refused> {
        mysql_packet(seq, &self.scramble(auth, nonce)?)
    }

    pub(crate) fn mysql_clear_packet(&self, seq: u8) -> Result<Seal, Refused> {
        let value = self.value();
        let payload = SealedValue::compose(&[Part::Value(&value), Part::Public(&[0])])
            .require_secure_if(!self.policy.local && !self.policy.clear);
        mysql_packet(seq, &payload)
    }

    pub(crate) fn mysql_rsa_packet(
        &self,
        seq: u8,
        nonce: &[u8],
        server_key_pem: &[u8],
    ) -> Result<Seal, Refused> {
        if nonce.is_empty() {
            return Err(Refused("the server sent no nonce"));
        }
        let pinned = match self.policy.rsa_pin {
            Some(pin) => {
                let key = rsa_public_key_sha256(server_key_pem)?;
                if !busbar_contract::constant_time_eq(&pin, &key) {
                    return Err(MYSQL_RSA_PIN_MISMATCH);
                }
                true
            }
            None => false,
        };
        let value = self.value();
        let payload = SealedValue::compose(&[Part::Value(&value), Part::Public(&[0])])
            .xor_repeating(nonce)?
            .rsa_oaep_sha1(server_key_pem)?
            .require_secure_if(!pinned && !self.policy.local);
        mysql_packet(seq, &payload)
    }
}
