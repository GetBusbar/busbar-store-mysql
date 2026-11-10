// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MySQL's pre-4.1 verifier belongs to the MySQL owner. Construct only at initial settings
//! ingestion, before the plaintext input is sealed and wiped. This module cannot open a Cred.

use busbar_contract::abi::sdk::{
    chip::Refused,
    cred::{Cred, Seal},
};
use zeroize::Zeroizing;

/// Private custody of the derived verifier. No readable access, Debug or serialization.
#[derive(Clone)]
pub(super) struct OldVerifier {
    words: Zeroizing<[u32; 2]>,
    empty: bool,
    secure: bool,
}

impl OldVerifier {
    /// The owning settings parser must pass its validated `secure_auth=false` decision. The
    /// strict/default path produces no verifier and cannot later opt into the weak method.
    pub(super) fn capture_at_ingestion(
        password: &[u8],
        operator_allows: bool,
        secure_required: bool,
    ) -> Result<Self, Refused> {
        if !operator_allows {
            return Err(Refused("mysql_old_password requires secure_auth=false"));
        }
        Ok(Self {
            words: hash_323(password),
            empty: password.is_empty(),
            secure: secure_required,
        })
    }

    /// Produce only a sealed authentication payload. The plugin frames this payload, while
    /// SealedWrite retains the SDK's real connector check before the first protected byte.
    pub(super) fn response(&self, nonce: &[u8], secure_required: bool) -> Result<Seal, Refused> {
        if nonce.len() < 8 {
            return Err(Refused("mysql_old_password requires an eight-byte nonce"));
        }
        let mut out = Zeroizing::new(Vec::new());
        if !self.empty {
            const MAX: u32 = 0x3fff_ffff;
            let hm = hash_323(&nonce[..8]);
            let mut seeds =
                Zeroizing::new([(self.words[0] ^ hm[0]) % MAX, (self.words[1] ^ hm[1]) % MAX]);
            out.resize(9, 0);
            for byte in &mut out[..8] {
                let random = random_323(&mut seeds);
                *byte = ((*random * 31.0).floor() + 64.0) as u8;
            }
            let random = random_323(&mut seeds);
            let extra = Zeroizing::new((*random * 31.0).floor() as u8);
            for byte in &mut out[..8] {
                *byte ^= *extra;
            }
        }
        Ok(Cred::captured(out)
            .require_secure_if(self.secure || secure_required)
            .field())
    }
}

fn random_323(seeds: &mut [u32; 2]) -> Zeroizing<f64> {
    const MAX: u32 = 0x3fff_ffff;
    seeds[0] = (seeds[0] * 3 + seeds[1]) % MAX;
    seeds[1] = (seeds[0] + seeds[1] + 33) % MAX;
    Zeroizing::new(f64::from(seeds[0]) / f64::from(MAX))
}

fn hash_323(bytes: &[u8]) -> Zeroizing<[u32; 2]> {
    let mut state = Zeroizing::new([1_345_345_333_u32, 7_u32, 0x1234_5671_u32]);
    for &byte in bytes.iter().filter(|b| **b != b' ' && **b != b'\t') {
        let tmp = Zeroizing::new(u32::from(byte));
        state[0] ^= (state[0] & 63)
            .wrapping_add(state[1])
            .wrapping_mul(*tmp)
            .wrapping_add(state[0] << 8);
        state[2] = state[2].wrapping_add((state[2] << 8) ^ state[0]);
        state[1] = state[1].wrapping_add(*tmp);
    }
    Zeroizing::new([state[0] & 0x7fff_ffff, state[2] & 0x7fff_ffff])
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::sdk::chip::{CredentialPart, SealedValue};

    #[test]
    fn published_driver_payload_survives_owner_transfer() {
        let verifier = OldVerifier::capture_at_ingestion(b"s3cr3t-pw", true, false).unwrap();
        let nonce: Vec<u8> = (1..=20).collect();
        let response = verifier.response(&nonce, false).unwrap();
        assert!(SealedValue::compose(&[CredentialPart::Sealed(&response)])
            .hex_lower()
            .verify_eq(b"5e4f5a585d44525000"));
        assert!(!response.secure_required());
    }

    #[test]
    fn strict_default_refuses_and_security_requirement_cannot_be_relaxed() {
        assert!(OldVerifier::capture_at_ingestion(b"pw", false, false).is_err());
        let protected = OldVerifier::capture_at_ingestion(b"pw", true, true).unwrap();
        assert!(protected
            .response(b"12345678", false)
            .unwrap()
            .secure_required());
        let explicit = OldVerifier::capture_at_ingestion(b"pw", true, false).unwrap();
        assert!(explicit
            .response(b"12345678", true)
            .unwrap()
            .secure_required());
    }

    #[test]
    fn empty_password_and_short_nonce_keep_native_semantics() {
        let empty = OldVerifier::capture_at_ingestion(b"", true, false).unwrap();
        assert!(empty.response(b"12345678", false).unwrap().is_empty());
        for nonce in [&b""[..], &b"1234567"[..]] {
            assert!(empty.response(nonce, false).is_err());
        }
    }
}
