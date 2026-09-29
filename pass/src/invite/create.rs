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

use crate::crypto::encrypt_invite_keys::{EncryptInviteKeysFlow, InviteKeyToPrepare};
use crate::folder::list::FolderResponse;
use crate::item::item_keys::OpenedItemKeys;
use crate::{PassClient, PassClientContext};
use anyhow::{Context, Result};
use pass_domain::{
    Address, DecryptedFolderKey, DecryptedShareKey, FolderId, ItemId, PublicKey, ShareId,
    ShareRole, ShareType, TargetType,
};
use std::collections::HashMap;

pub(crate) enum InviteRequest {
    ExistingUser(CreateInvitesRequest),
    NewUser(NewUserInvitesRequest),
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct NewUserInvitesRequest {
    #[serde(rename = "NewUserInvites")]
    invites: Vec<NewUserInviteRequest>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct NewUserInviteRequest {
    #[serde(rename = "Email")]
    email: String,
    #[serde(rename = "TargetType")]
    target_type: u8,
    #[serde(rename = "Signature")]
    signature: String,
    #[serde(rename = "ShareRoleID")]
    share_role_id: String,
    #[serde(rename = "ItemID")]
    item_id: Option<String>,
    #[serde(rename = "FolderID")]
    folder_id: Option<String>,
    #[serde(rename = "ExpirationTime")]
    expiration_time: Option<u64>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct CreateInvitesRequest {
    #[serde(rename = "Invites")]
    invites: Vec<CreateInviteRequest>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct CreateInviteRequest {
    #[serde(rename = "Keys")]
    keys: Vec<CreateInviteKey>,
    #[serde(rename = "Email")]
    email: String,
    #[serde(rename = "TargetType")]
    target_type: u8,
    #[serde(rename = "ShareRoleID")]
    share_role_id: String,
    #[serde(rename = "Data")]
    data: Option<String>,
    #[serde(rename = "ItemID")]
    item_id: Option<String>,
    #[serde(rename = "FolderID")]
    folder_id: Option<String>,
    #[serde(rename = "ExpirationTime")]
    expiration_time: Option<u64>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct CreateInviteKey {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "KeyRotation")]
    key_rotation: u8,
}

enum InviteUserMode {
    ExistingUser { keys: Vec<PublicKey> },
    NewUser,
}

enum InviteTarget {
    Vault {
        share_keys: Vec<DecryptedShareKey>,
    },
    Item {
        item_id: ItemId,
        item_keys: OpenedItemKeys,
    },
    Folder {
        folder_id: FolderId,
        folder_key: DecryptedFolderKey,
    },
}

impl InviteTarget {
    pub fn item_id(&self) -> Option<ItemId> {
        match self {
            Self::Vault { .. } | Self::Folder { .. } => None,
            Self::Item { item_id, .. } => Some(item_id.clone()),
        }
    }

    pub fn folder_id(&self) -> Option<FolderId> {
        match self {
            Self::Vault { .. } | Self::Item { .. } => None,
            Self::Folder { folder_id, .. } => Some(folder_id.clone()),
        }
    }

    pub fn target_type(&self) -> TargetType {
        match self {
            Self::Vault { .. } => TargetType::Vault,
            Self::Item { .. } => TargetType::Item,
            Self::Folder { .. } => TargetType::Folder,
        }
    }
}

impl<C: PassClientContext> PassClient<C> {
    /// Ensure that the given folder is `share_root_folder_id` itself or one of its descendants.
    async fn ensure_folder_in_folder_tree(
        &self,
        share_id: &ShareId,
        folder_id: &FolderId,
        share_root_folder_id: &FolderId,
    ) -> Result<()> {
        let revisions = self
            .list_all_folder_revisions(share_id)
            .await
            .context("Error listing folders")?;
        let revision_map: HashMap<&str, &FolderResponse> = revisions
            .iter()
            .map(|r| (r.folder_id.as_str(), r))
            .collect();

        let mut current_id = Some(folder_id.value().to_string());
        while let Some(id) = current_id {
            if id == share_root_folder_id.value() {
                return Ok(());
            }
            // If a parent is not in the share's folder listing, we cannot prove containment.
            let rev = revision_map.get(id.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "Trying to share a folder with a share that does not grant access to that folder"
                )
            })?;
            current_id = rev.parent_folder_id.clone();
        }

        Err(anyhow::anyhow!(
            "Trying to share a folder with a share that does not grant access to that folder"
        ))
    }

    /// Ensure that the given item lives inside the folder tree rooted at `share_root_folder_id`.
    async fn ensure_item_in_folder_tree(
        &self,
        share_id: &ShareId,
        item_id: &ItemId,
        share_root_folder_id: &FolderId,
    ) -> Result<()> {
        let revisions = self
            .get_item_revisions(share_id, item_id)
            .await
            .context("Error getting item revisions")?;
        let latest = revisions
            .iter()
            .max_by_key(|r| r.revision)
            .ok_or_else(|| anyhow::anyhow!("Item {} has no revisions", item_id))?;

        let item_folder_id = latest.folder_id.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Trying to share an item with a share that does not grant access to that item"
            )
        })?;

        self.ensure_folder_in_folder_tree(
            share_id,
            &FolderId::new(item_folder_id.clone()),
            share_root_folder_id,
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Trying to share an item with a share that does not grant access to that item"
            )
        })
    }

    pub(crate) async fn create_invites_request(
        &self,
        share_id: &ShareId,
        address_to_invite: &str,
        role: &ShareRole,
        item_id: Option<ItemId>,
        folder_id: Option<FolderId>,
    ) -> Result<InviteRequest> {
        let share = self
            .get_share(share_id)
            .await
            .context("Error getting share")?;
        share.can_share_guard()?;

        let mode = self
            .get_invite_user_mode(address_to_invite)
            .await
            .context("Error getting invite user mode")?;

        let user_address = self
            .get_address(&share.address_id)
            .await
            .context("Error getting address")?;

        debug!(
            "[create_invite] share [id={}] [address_id={}]",
            share.id, share.address_id
        );
        debug!(
            "[create_invite] user_address [id={}] [email={}]",
            user_address.id, user_address.email
        );
        debug!("[create_invite] address_to_invite: {address_to_invite}");

        let invite_target = match (item_id, folder_id) {
            (Some(_), Some(_)) => {
                return Err(anyhow::anyhow!(
                    "Cannot invite to an item and a folder at the same time"
                ));
            }
            (None, None) => match &share.share_type {
                ShareType::Vault { .. } => {
                    // User with vault access is sharing vault access
                    let share_keys = self
                        .get_all_opened_share_keys(share_id, true) // Force refresh as we want all the keys
                        .await
                        .context("Error getting opened share keys")?;
                    InviteTarget::Vault { share_keys }
                }
                ShareType::Item { .. } | ShareType::Folder { .. } => {
                    // User with item or folder access is trying to share a vault
                    return Err(anyhow::anyhow!(
                        "Share of type item or folder is not allowed to share a vault"
                    ));
                }
            },
            (Some(id), None) => match share.share_type {
                ShareType::Vault { .. } => {
                    // User with vault access is sharing a single item
                    let keys = self
                        .get_item_keys(share_id, &id)
                        .await
                        .context("Error getting item key")?;

                    let opened_keys = self
                        .open_item_keys(share_id, keys)
                        .await
                        .context("Error opening item keys")?;

                    InviteTarget::Item {
                        item_id: id,
                        item_keys: OpenedItemKeys::new(opened_keys),
                    }
                }
                ShareType::Item { ref item_id, .. } => {
                    // User with item access is sharing a single item
                    if !id.eq(item_id) {
                        return Err(anyhow::anyhow!(
                            "Trying to share an item with a share that does not grant access to that item"
                        ));
                    }

                    let key = self
                        .get_item_key_by_ids(share_id, &id)
                        .await
                        .context("Error getting item key")?;
                    InviteTarget::Item {
                        item_id: id,
                        item_keys: OpenedItemKeys::new(vec![key]),
                    }
                }
                ShareType::Folder {
                    folder_id: share_folder_id,
                    ..
                } => {
                    self.ensure_item_in_folder_tree(share_id, &id, &share_folder_id)
                        .await?;
                    let key = self
                        .get_item_key_by_ids(share_id, &id)
                        .await
                        .context("Error getting item key")?;
                    InviteTarget::Item {
                        item_id: id,
                        item_keys: OpenedItemKeys::new(vec![key]),
                    }
                }
            },
            (None, Some(id)) => match share.share_type {
                ShareType::Vault { .. } => {
                    let folder_rev = self
                        .get_folder_data(share_id, &id)
                        .await
                        .context("Error getting folder")?;

                    let folder_key = self
                        .get_opened_folder_key(share_id, &id, folder_rev.key_rotation)
                        .await
                        .context("Error opening folder key")?;

                    InviteTarget::Folder {
                        folder_id: id,
                        folder_key,
                    }
                }
                ShareType::Folder { ref folder_id, .. } => {
                    if !id.eq(folder_id) {
                        self.ensure_folder_in_folder_tree(share_id, &id, folder_id)
                            .await?;
                    }
                    let folder_rev = self
                        .get_folder_data(share_id, &id)
                        .await
                        .context("Error getting folder")?;

                    let folder_key = self
                        .get_opened_folder_key(share_id, &id, folder_rev.key_rotation)
                        .await
                        .context("Error opening folder key")?;

                    InviteTarget::Folder {
                        folder_id: id,
                        folder_key,
                    }
                }
                ShareType::Item { .. } => {
                    return Err(anyhow::anyhow!(
                        "Share of type item is not allowed to share a folder"
                    ));
                }
            },
        };

        match mode {
            InviteUserMode::ExistingUser { keys } => self
                .create_existing_user_invite(
                    user_address,
                    address_to_invite,
                    role,
                    invite_target,
                    keys,
                )
                .await
                .context("Error creating existing user invite"),
            InviteUserMode::NewUser => self
                .create_new_user_invite(user_address, address_to_invite, role, invite_target)
                .await
                .context("Error creating new user invite"),
        }
    }

    async fn create_existing_user_invite(
        &self,
        user_address: Address,
        address: &str,
        role: &ShareRole,
        invite_target: InviteTarget,
        invited_keys: Vec<PublicKey>,
    ) -> Result<InviteRequest> {
        let target_type = invite_target.target_type().value();
        let item_id = invite_target.item_id().map(|i| i.value().to_string());
        let folder_id = invite_target.folder_id().map(|i| i.value().to_string());
        let encrypted_keys = self
            .encrypt_share_keys_for_user(user_address, invite_target, invited_keys)
            .await
            .context("Error encrypting share keys for invited user")?;
        Ok(InviteRequest::ExistingUser(CreateInvitesRequest {
            invites: vec![CreateInviteRequest {
                keys: encrypted_keys,
                email: address.to_string(),
                share_role_id: role.value(),
                expiration_time: None,
                data: None,
                item_id,
                folder_id,
                target_type,
            }],
        }))
    }

    async fn create_new_user_invite(
        &self,
        user_address: Address,
        address_to_invite: &str,
        role: &ShareRole,
        invite_target: InviteTarget,
    ) -> Result<InviteRequest> {
        let target_type = invite_target.target_type().value();
        let item_id = invite_target.item_id().map(|i| i.value().to_string());
        let folder_id = invite_target.folder_id().map(|i| i.value().to_string());
        let key_to_encrypt = match &invite_target {
            InviteTarget::Vault { share_keys, .. } => {
                // Get the latest key (highest rotation)
                let latest = share_keys
                    .iter()
                    .max_by_key(|k| k.key_rotation)
                    .ok_or_else(|| anyhow::anyhow!("No share keys found"))?;
                latest.key().to_vec()
            }
            InviteTarget::Item { item_keys, .. } => {
                let latest = item_keys
                    .latest_or_err()
                    .context("Error getting latest item key")?;
                latest.key.clone().value()
            }
            InviteTarget::Folder { folder_key, .. } => folder_key.value(),
        };

        let signature_body = proton_pass_common::invite::create_signature_body(
            address_to_invite,
            key_to_encrypt.clone(),
        );
        let address_keys = self
            .open_address_keys(user_address.keys)
            .await
            .context("Error opening address keys")?;

        let address_key = address_keys.first_or_err()?;

        let pgp = self.client_features.get_pgp_crypto().await;
        let signed_data = pgp
            .sign(signature_body, address_key.private_key.clone())
            .await
            .context("Error signing new user invite body")?;

        Ok(InviteRequest::NewUser(NewUserInvitesRequest {
            invites: vec![NewUserInviteRequest {
                email: address_to_invite.to_string(),
                signature: crate::utils::b64_encode(signed_data),
                share_role_id: role.value(),
                expiration_time: None,
                target_type,
                item_id,
                folder_id,
            }],
        }))
    }

    async fn get_invite_user_mode(&self, address: &str) -> Result<InviteUserMode> {
        let keys = self
            .get_keys_for_email(address, false)
            .await
            .context("Error fetching keys for email")?;

        if keys.is_empty() {
            Ok(InviteUserMode::NewUser)
        } else {
            Ok(InviteUserMode::ExistingUser { keys })
        }
    }
    async fn encrypt_share_keys_for_user(
        &self,
        user_address: Address,
        invite_target: InviteTarget,
        invited_keys: Vec<PublicKey>,
    ) -> Result<Vec<CreateInviteKey>> {
        let user_address_keys = self
            .open_address_keys(user_address.keys)
            .await
            .context("Error opening address keys")?;

        let crypto = self.client_features.get_pgp_crypto().await;

        let flow = EncryptInviteKeysFlow::new(crypto, user_address_keys, invited_keys);

        let invite_keys = self
            .prepare_keys_to_invite(invite_target)
            .await
            .context("Error preparing keys to invite")?;
        let encrypted_keys = flow
            .encrypt(invite_keys)
            .await
            .context("Error encrypting invite keys")?;

        let keys = encrypted_keys
            .into_iter()
            .map(|k| CreateInviteKey {
                key: crate::utils::b64_encode(k.key.clone()),
                key_rotation: k.key_rotation,
            })
            .collect();

        Ok(keys)
    }

    async fn prepare_keys_to_invite(
        &self,
        invite_target: InviteTarget,
    ) -> Result<Vec<InviteKeyToPrepare>> {
        match invite_target {
            InviteTarget::Vault { share_keys, .. } => {
                let res = share_keys
                    .into_iter()
                    .map(|key| InviteKeyToPrepare {
                        decrypted_key: key.key().to_vec(),
                        key_rotation: key.key_rotation,
                    })
                    .collect();
                Ok(res)
            }
            InviteTarget::Item { item_keys, .. } => Ok(item_keys
                .keys
                .into_iter()
                .map(|k| InviteKeyToPrepare {
                    decrypted_key: k.key.clone().value(),
                    key_rotation: k.key_rotation,
                })
                .collect()),
            InviteTarget::Folder { folder_key, .. } => Ok(vec![InviteKeyToPrepare {
                decrypted_key: folder_key.value(),
                key_rotation: folder_key.key_rotation,
            }]),
        }
    }
}
