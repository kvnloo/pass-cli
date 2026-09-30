/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Proton Pass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{Result, anyhow};

trait ContextExt<T> {
    fn ctx(self, msg: &'static str) -> Result<T>;
}

impl<T, E: std::fmt::Display> ContextExt<T> for std::result::Result<T, E> {
    fn ctx(self, msg: &'static str) -> Result<T> {
        self.map_err(|e| anyhow::anyhow!("{msg}: {e}"))
    }
}
use crate::domain::crypto;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

pub const ARCHIVE_AAD: &[u8] = b"proton-pass-archive-v1";
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

pub const ARGON2_M_COST: u32 = 65536;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 4;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct ArchiveKdfParams {
    #[serde(rename = "m")]
    pub m_cost: u32,
    #[serde(rename = "t")]
    pub t_cost: u32,
    #[serde(rename = "p")]
    pub p_cost: u32,
}

impl ArchiveKdfParams {
    pub const fn current() -> Self {
        Self {
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArchiveEnvelope {
    pub version: u8,
    pub kdf: ArchiveKdfParams,
    pub salt: String,
    pub blob: String,
}

pub fn derive_key(password: &str, salt: &[u8], params: &ArchiveKdfParams) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .ctx("Invalid Argon2 parameters")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .ctx("Error deriving archive key with Argon2id")?;
    Ok(out)
}

pub fn encrypt_blob(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = crypto::random_bytes(NONCE_LEN);
    let nonce = Nonce::try_from(&nonce_bytes[..])
        .map_err(|_| anyhow!("Failed to build encryption nonce"))?;
    let payload = Payload {
        msg: plaintext,
        aad: ARCHIVE_AAD,
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| anyhow!("Error encrypting archive blob"))?;
    let mut result = nonce_bytes;
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

#[allow(dead_code)]
pub fn decrypt_blob(blob: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    if blob.len() <= NONCE_LEN {
        return Err(anyhow!("Archive blob is too short"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(key.into());
    let payload = Payload {
        msg: ciphertext,
        aad: ARCHIVE_AAD,
    };
    cipher
        .decrypt(
            &Nonce::try_from(nonce_bytes)
                .map_err(|_| anyhow!("Failed to build decryption nonce"))?,
            payload,
        )
        .map_err(|_| anyhow!("Wrong password or corrupted archive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_round_trip() {
        let password = "correct horse battery staple";
        let salt = crypto::random_bytes(SALT_LEN);
        let kdf = ArchiveKdfParams::current();
        let key = derive_key(password, &salt, &kdf).unwrap();
        let plaintext = br#"{"hello":"world"}"#;
        let encrypted = encrypt_blob(plaintext, &key).unwrap();

        // Structure: nonce (12) || ciphertext+tag(16)
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        let decrypted = decrypt_blob(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt = crypto::random_bytes(SALT_LEN);
        let kdf = ArchiveKdfParams::current();
        let key = derive_key("right", &salt, &kdf).unwrap();
        let encrypted = encrypt_blob(b"data", &key).unwrap();
        let wrong = derive_key("wrong", &salt, &kdf).unwrap();
        assert!(decrypt_blob(&encrypted, &wrong).is_err());
    }

    #[test]
    fn test_derived_key_is_deterministic() {
        let salt = vec![7u8; SALT_LEN];
        let kdf = ArchiveKdfParams::current();
        let a = derive_key("pw", &salt, &kdf).unwrap();
        let b = derive_key("pw", &salt, &kdf).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    #[ignore = "helper that dumps a fixture, not a test"]
    fn dump_cross_language_fixture() {
        let salt = vec![9u8; SALT_LEN];
        let kdf = ArchiveKdfParams::current();
        let key = derive_key("cross-check-pw", &salt, &kdf).unwrap();
        let ct = encrypt_blob(br#"{"payload":true}"#, &key).unwrap();
        let envelope = ArchiveEnvelope {
            version: 1,
            kdf,
            salt: hex::encode(&salt),
            blob: crate::domain::archive::base64_encode(&ct),
        };
        let out_dir = std::env::var("CARGO_TARGET_TMPDIR")
            .unwrap_or_else(|_| std::env::temp_dir().display().to_string());
        let path = std::path::Path::new(&out_dir).join("archive_fixture.json");
        std::fs::write(&path, serde_json::to_string(&envelope).unwrap()).unwrap();
    }
}
