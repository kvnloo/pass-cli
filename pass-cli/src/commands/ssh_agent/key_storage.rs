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

use anyhow::anyhow;
use pass::domain::password_hash::PasswordHasher as PasswordHasherKdf;
use pass::domain::{ItemId, ShareId};
use ssh_agent_lib::error::AgentError;
use ssh_key::public::KeyData;
use ssh_key::{
    certificate::Certificate, private::PrivateKey as SshPrivateKey,
    public::PublicKey as SshPublicKey,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone, PartialEq, Debug)]
pub enum IdentitySource {
    ProtonPass { share_id: ShareId, item_id: ItemId },
    User,
}

#[derive(Clone, PartialEq, Debug)]
pub struct SshIdentity {
    pub public_key: SshPublicKey,
    pub encrypted_private_key_bytes: Vec<u8>,
    pub xor_key: u8,
    pub comment: String,
    pub source: IdentitySource,
    pub certificate: Option<Certificate>,
    pub pubkey_data: KeyData,
    pub constraints: Option<IdentityConstraints>,
}

#[derive(Clone, PartialEq, Debug, Default)]
pub struct IdentityConstraints {
    pub expires_at: Option<Instant>,
    pub confirm: bool,
}

impl IdentityConstraints {
    pub fn lifetime_expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

impl SshIdentity {
    pub fn new(
        private_key: SshPrivateKey,
        comment: String,
        source: IdentitySource,
    ) -> anyhow::Result<Self> {
        Self::new_with_constraints(private_key, comment, source, None)
    }

    pub fn new_with_constraints(
        private_key: SshPrivateKey,
        comment: String,
        source: IdentitySource,
        constraints: Option<IdentityConstraints>,
    ) -> anyhow::Result<Self> {
        let public_key = SshPublicKey::from(&private_key);
        let pubkey_data = public_key.key_data().clone();
        Self::new_with_pubkey_data(private_key, pubkey_data, comment, source, None, constraints)
    }

    pub fn is_usable(&self, now: Instant) -> bool {
        match &self.constraints {
            Some(constraints) => !constraints.lifetime_expired(now),
            None => true,
        }
    }

    fn new_with_pubkey_data(
        private_key: SshPrivateKey,
        pubkey_data: KeyData,
        comment: String,
        source: IdentitySource,
        certificate: Option<Certificate>,
        constraints: Option<IdentityConstraints>,
    ) -> anyhow::Result<Self> {
        let public_key = SshPublicKey::from(&private_key);
        let xor_key = pass::domain::crypto::generate_random_byte();

        let private_key_bytes = private_key
            .to_bytes()
            .map_err(|e| anyhow!("Failed to serialize private key: {}", e))?;

        let encrypted_private_key_bytes = Self::xor_bytes(&private_key_bytes, xor_key);

        Ok(Self {
            public_key,
            encrypted_private_key_bytes,
            xor_key,
            comment,
            source,
            certificate,
            pubkey_data,
            constraints,
        })
    }

    pub fn decrypt_private_key(&self) -> anyhow::Result<SshPrivateKey> {
        let decrypted_bytes = Self::xor_bytes(&self.encrypted_private_key_bytes, self.xor_key);

        SshPrivateKey::from_bytes(&decrypted_bytes)
            .map_err(|e| anyhow!("Failed to deserialize private key: {}", e))
    }

    fn xor_bytes(data: &[u8], xor_key: u8) -> Vec<u8> {
        data.iter().map(|b| b ^ xor_key).collect()
    }
}

#[derive(Clone)]
pub struct KeyStorage {
    pub identities: Arc<RwLock<Vec<SshIdentity>>>,
    pub create_item_sender: UnboundedSender<SshIdentity>,
    lock_hash: Arc<RwLock<Option<String>>>,
    password_hasher: PasswordHasherKdf,
}

impl KeyStorage {
    pub fn new(create_item_sender: UnboundedSender<SshIdentity>) -> Self {
        Self {
            identities: Arc::new(RwLock::new(Vec::new())),
            create_item_sender,
            lock_hash: Arc::new(RwLock::new(None)),
            password_hasher: PasswordHasherKdf::default(),
        }
    }

    #[cfg(test)]
    pub fn new_with_password_hasher(
        create_item_sender: UnboundedSender<SshIdentity>,
        password_hasher: PasswordHasherKdf,
    ) -> Self {
        Self {
            identities: Arc::new(RwLock::new(Vec::new())),
            create_item_sender,
            lock_hash: Arc::new(RwLock::new(None)),
            password_hasher,
        }
    }

    pub async fn is_locked(&self) -> bool {
        self.lock_hash.read().await.is_some()
    }

    /// Locks the agent by storing an Argon2id hash of the given password.
    /// While locked, [`KeyStorage::is_locked`] returns `true` and the agent
    /// refuses to list identities or sign.
    ///
    /// Fails if the agent is already locked: allowing a re-lock would let
    /// anyone who reaches the socket overwrite the lock password with their
    /// own and immediately unlock the agent, bypassing the original lock.
    pub async fn lock_agent(&self, password: String) -> Result<(), AgentError> {
        if self.is_locked().await {
            warn!("Refusing lock request: agent is already locked");
            return Err(AgentError::Failure);
        }
        // Hash outside of the write lock: Argon2 is expensive.
        let hashed = self.password_hasher.hash_password(&password).map_err(|e| {
            error!("Failed to hash lock password: {e:#}");
            AgentError::Failure
        })?;
        *self.lock_hash.write().await = Some(hashed);
        Ok(())
    }

    /// Attempts to unlock the agent by verifying the given password against
    /// the stored lock hash. Returns `Err(AgentError::Failure)` if the agent
    /// is not locked or the password is wrong.
    pub async fn unlock_agent(&self, password: String) -> Result<(), AgentError> {
        let stored_hash = self.lock_hash.read().await.clone();
        let Some(stored_hash) = stored_hash else {
            warn!("Refusing unlock request: agent is not locked");
            return Err(AgentError::Failure);
        };

        if !self
            .password_hasher
            .verify_password(&password, &stored_hash)
        {
            warn!("Refusing unlock request: wrong password");
            return Err(AgentError::Failure);
        }

        *self.lock_hash.write().await = None;
        Ok(())
    }

    /// Removes every identity whose lifetime constraint has expired.
    /// Returns the number of removed identities.
    pub async fn remove_expired_identities(&self) -> usize {
        let mut identities = self.identities.write().await;
        let before = identities.len();
        identities.retain(|identity| identity.is_usable(Instant::now()));
        before - identities.len()
    }

    pub async fn identity_from_pubkey(&self, pubkey: &SshPublicKey) -> Option<SshIdentity> {
        let identities = self.identities.read().await;

        let index = Self::identity_index_from_pubkey(&identities, pubkey)?;
        Some(identities[index].clone())
    }

    pub async fn identity_add(&self, identity: SshIdentity) {
        let mut identities = self.identities.write().await;
        if Self::identity_index_from_pubkey(&identities, &identity.public_key).is_none() {
            if let Err(e) = self.create_item_sender.send(identity.clone()) {
                warn!("Failed to send identity add: {}", e);
            }
            identities.push(identity);
        }
    }

    pub async fn identity_remove(
        &self,
        pubkey: &SshPublicKey,
        fail_on_not_found: bool,
    ) -> anyhow::Result<(), AgentError> {
        let mut identities = self.identities.write().await;

        if let Some(index) = Self::identity_index_from_pubkey(&identities, pubkey) {
            identities.remove(index);
            Ok(())
        } else if fail_on_not_found {
            Err(std::io::Error::other("Failed to remove identity: identity not found").into())
        } else {
            warn!(
                "Asked to remove an identity, but we could not find it. Not erroring as fail_not_found is false"
            );
            Ok(())
        }
    }

    pub async fn replace_all_identities(&self, new_identities: Vec<SshIdentity>) {
        let mut self_identities = self.identities.write().await;

        let mut final_identities = HashMap::new();

        // Keep identities added manually by the user
        let user_added_identities: Vec<SshIdentity> = self_identities
            .iter()
            .filter(|i| i.source == IdentitySource::User)
            .cloned()
            .collect();
        for identity in user_added_identities {
            final_identities.insert(identity.public_key.key_data().clone(), identity);
        }

        // Add the new identities, using the hashmap to ensure we don't duplicate them
        for identity in new_identities {
            final_identities.insert(identity.public_key.key_data().clone(), identity);
        }

        let identities: Vec<SshIdentity> = final_identities.into_values().collect();
        *self_identities = identities;
    }

    fn identity_index_from_pubkey(
        identities: &[SshIdentity],
        pubkey: &SshPublicKey,
    ) -> Option<usize> {
        // Compare by key data instead of the full PublicKey object, since metadata might differ
        let target_key_data = pubkey.key_data();
        for (index, identity) in identities.iter().enumerate() {
            if identity.public_key.key_data() == target_key_data {
                return Some(index);
            }
        }
        None
    }

    // Update or add identity (for item updates)
    // If an identity with the same share_id and item_id exists, replace it.
    // Otherwise, add it as a new identity.
    pub async fn identity_upsert(&self, identity: SshIdentity) {
        let mut identities = self.identities.write().await;

        // Find existing by share_id + item_id
        if let IdentitySource::ProtonPass { share_id, item_id } = &identity.source
            && let Some(index) = identities.iter().position(|i| match &i.source {
                IdentitySource::ProtonPass {
                    share_id: s,
                    item_id: i,
                } => s == share_id && i == item_id,
                IdentitySource::User => false,
            })
        {
            info!("Updating existing SSH key: {}", identity.comment);
            identities[index] = identity;
            return;
        }

        // Add new
        info!("Adding new SSH key: {}", identity.comment);
        identities.push(identity);
    }

    // Remove identity by share_id and item_id (for deletes)
    // Only removes ProtonPass-sourced keys, preserves User-added keys
    pub async fn identity_remove_by_item_id(
        &self,
        share_id: &ShareId,
        item_id: &ItemId,
    ) -> anyhow::Result<()> {
        let mut identities = self.identities.write().await;

        if let Some(idx) = identities.iter().position(|i| match &i.source {
            IdentitySource::ProtonPass {
                share_id: s,
                item_id: i,
            } => s == share_id && i == item_id,
            IdentitySource::User => false,
        }) {
            let removed = &identities[idx];
            info!("Removing SSH key: {}", removed.comment);
            identities.remove(idx);
            Ok(())
        } else {
            Err(anyhow!("Identity not found or not from ProtonPass"))
        }
    }

    // Remove all ProtonPass-sourced identities for a given share (for share deletion / unsharing)
    // Only removes ProtonPass-sourced keys, preserves User-added keys
    pub async fn identity_remove_by_share_id(&self, share_id: &ShareId) {
        let mut identities = self.identities.write().await;
        let before = identities.len();
        identities.retain(|i| match &i.source {
            IdentitySource::ProtonPass { share_id: s, .. } => s != share_id,
            IdentitySource::User => true,
        });
        let removed = before - identities.len();
        if removed > 0 {
            info!(
                "Removed {} SSH key(s) for deleted share {}",
                removed, share_id
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::Algorithm;

    fn make_identity(share_id: &str, item_id: &str, comment: &str) -> SshIdentity {
        let private_key = SshPrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).unwrap();
        SshIdentity::new(
            private_key,
            comment.to_string(),
            IdentitySource::ProtonPass {
                share_id: ShareId::new(share_id.to_string()),
                item_id: ItemId::new(item_id.to_string()),
            },
        )
        .unwrap()
    }

    fn make_storage() -> KeyStorage {
        let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
        KeyStorage::new(sender)
    }

    #[tokio::test]
    async fn upsert_with_changed_public_key_replaces_old_identity() {
        let storage = make_storage();

        let key_a = make_identity("share-1", "item-1", "key-a");
        let key_a_pubkey = key_a.public_key.clone();
        storage.identity_upsert(key_a).await;

        let key_b = make_identity("share-1", "item-1", "key-b");
        let key_b_pubkey = key_b.public_key.clone();
        storage.identity_upsert(key_b).await;

        assert_eq!(storage.identities.read().await.len(), 1);
        assert!(storage.identity_from_pubkey(&key_a_pubkey).await.is_none());
        assert!(storage.identity_from_pubkey(&key_b_pubkey).await.is_some());
    }

    #[tokio::test]
    async fn upsert_with_unchanged_public_key_keeps_single_identity() {
        let storage = make_storage();

        let key_a = make_identity("share-1", "item-1", "key-a");
        storage.identity_upsert(key_a.clone()).await;
        storage.identity_upsert(key_a).await;

        assert_eq!(storage.identities.read().await.len(), 1);
    }
}
