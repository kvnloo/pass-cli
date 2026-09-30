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

use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier, Version};

use crate::domain::crypto;

pub const PASSWORD_HASH_M_COST: u32 = 65536;
pub const PASSWORD_HASH_T_COST: u32 = 3;
pub const PASSWORD_HASH_P_COST: u32 = 4;
const SALT_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordHasher {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self {
            m_cost: PASSWORD_HASH_M_COST,
            t_cost: PASSWORD_HASH_T_COST,
            p_cost: PASSWORD_HASH_P_COST,
        }
    }
}

impl PasswordHasher {
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> anyhow::Result<Self> {
        Params::new(m_cost, t_cost, p_cost, None)
            .map(|_| Self {
                m_cost,
                t_cost,
                p_cost,
            })
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {e}"))
    }

    fn argon2(&self) -> anyhow::Result<Argon2<'static>> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, None)
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {e}"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    pub fn hash_password(&self, password: &str) -> anyhow::Result<String> {
        let salt = crypto::random_bytes(SALT_LEN);
        let hash = self
            .argon2()?
            .hash_password_with_salt(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?;
        Ok(hash.to_string())
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> bool {
        Argon2::default()
            .verify_password(password.as_bytes(), hash)
            .is_ok()
    }
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    PasswordHasher::default().hash_password(password)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHasher::default().verify_password(password, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_hasher() -> PasswordHasher {
        PasswordHasher::new(64, 1, 1).unwrap()
    }

    #[test]
    fn hash_round_trip_with_default_params() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn hashes_are_salted() {
        let a = hash_password("same password").unwrap();
        let b = hash_password("same password").unwrap();
        assert_ne!(a, b, "two hashes of the same password must differ (salt)");
    }

    #[test]
    fn verify_rejects_malformed_hash() {
        assert!(!verify_password("anything", "not-a-phc-hash"));
        assert!(!verify_password("anything", ""));
    }

    #[test]
    fn custom_params_override_defaults() {
        let hasher = PasswordHasher::new(8192, 2, 1).unwrap();
        assert_ne!(hasher, PasswordHasher::default());

        let hash = hasher.hash_password("override params").unwrap();
        assert!(
            hash.contains("m=8192"),
            "hash must embed the custom memory cost: {hash}"
        );
        assert!(hasher.verify_password("override params", &hash));
    }

    #[test]
    fn fast_test_params_round_trip() {
        let hasher = fast_hasher();
        let hash = hasher.hash_password("fast").unwrap();
        assert!(hasher.verify_password("fast", &hash));
        assert!(!hasher.verify_password("slow", &hash));
    }

    #[test]
    fn verification_uses_params_embedded_in_the_hash() {
        // Hash with the weak test parameters, verify with the (irrelevant)
        // default configuration: verification must succeed because the
        // parameters come from the hash itself.
        let hash = fast_hasher().hash_password("embedded params").unwrap();
        assert!(verify_password("embedded params", &hash));
    }

    #[test]
    fn invalid_params_are_rejected() {
        // m_cost below the Argon2 minimum (8 KiB).
        assert!(PasswordHasher::new(4, 1, 1).is_err());
        // t_cost must be at least 1.
        assert!(PasswordHasher::new(8192, 0, 1).is_err());
    }
}
