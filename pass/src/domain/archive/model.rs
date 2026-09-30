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

use crate::domain::models::item::{
    CreditCardItem, CustomSection, IdentityItem, ItemContent, ItemExtraField,
    ItemExtraFieldContent, LoginItem, SshKeyItem, WifiItem,
};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveData {
    pub version: u8,
    pub exported_at: String,
    pub vaults: Vec<ArchiveVault>,
    /// Folders across all exported vaults (v2+).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<ArchiveFolder>,
    pub items: Vec<ArchiveItem>,
    pub has_attachments: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveVault {
    pub id: String,
    pub share_id: String,
    pub name: String,
    pub description: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveFolder {
    pub id: String,
    pub share_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_folder_id: Option<String>,
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveItem {
    pub id: String,
    pub vault_id: String,
    pub share_id: String,
    /// note | login | alias | credit_card | identity | ssh_key | wifi | custom
    pub item_type: String,
    pub title: String,
    pub note: String,
    pub item_uuid: String,
    /// Alias address (only for alias items).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alias_email: Option<String>,
    pub content: ArchiveItemContent,
    pub extra_fields: Vec<ArchiveExtraField>,
    pub create_time: String,
    pub modify_time: String,
    pub attachments: Vec<ArchiveAttachment>,
    pub trashed: bool,
    /// Item carries file attachments (fetched only with `--include-attachments`).
    #[serde(skip_serializing, default)]
    pub has_files: bool,
    /// Folder the item belongs to, if any (v2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArchiveItemContent {
    Note,
    Login(ArchiveLogin),
    Alias,
    CreditCard(ArchiveCreditCard),
    Identity(Box<ArchiveIdentity>),
    SshKey(ArchiveSshKey),
    Wifi(ArchiveWifi),
    Custom { sections: Vec<ArchiveCustomSection> },
}

impl ArchiveItemContent {
    pub fn from(value: &ItemContent) -> Self {
        match value {
            ItemContent::Note(_) => Self::Note,
            ItemContent::Login(login) => Self::Login(ArchiveLogin::from(login)),
            ItemContent::Alias(_) => Self::Alias,
            ItemContent::CreditCard(cc) => Self::CreditCard(ArchiveCreditCard::from(cc)),
            ItemContent::Identity(identity) => {
                Self::Identity(Box::new(ArchiveIdentity::from((**identity).clone())))
            }
            ItemContent::SshKey(ssh) => Self::SshKey(ArchiveSshKey::from(ssh)),
            ItemContent::Wifi(wifi) => Self::Wifi(ArchiveWifi::from(wifi)),
            ItemContent::Custom(custom) => Self::Custom {
                sections: custom
                    .sections
                    .iter()
                    .map(ArchiveCustomSection::from)
                    .collect(),
            },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveLogin {
    pub email: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub totp_uri: String,
    pub passkeys: Vec<ArchivePasskey>,
}

impl From<&LoginItem> for ArchiveLogin {
    fn from(value: &LoginItem) -> Self {
        Self {
            email: value.email.clone(),
            username: value.username.clone(),
            password: value.password.clone(),
            urls: value.urls.clone(),
            totp_uri: value.totp_uri.clone(),
            passkeys: value.passkeys.iter().map(ArchivePasskey::from).collect(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchivePasskey {
    pub domain: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub note: String,
    pub create_time: u32,
}

impl From<&crate::domain::models::item::Passkey> for ArchivePasskey {
    fn from(value: &crate::domain::models::item::Passkey) -> Self {
        Self {
            domain: value.domain.clone(),
            rp_name: value.rp_name.clone(),
            user_name: value.user_name.clone(),
            user_display_name: value.user_display_name.clone(),
            note: value.note.clone(),
            create_time: value.create_time,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveCreditCard {
    pub cardholder_name: String,
    pub number: String,
    pub verification_number: String,
    pub expiration_date: String,
    pub pin: String,
    pub card_type: String,
}

impl From<&CreditCardItem> for ArchiveCreditCard {
    fn from(value: &CreditCardItem) -> Self {
        Self {
            cardholder_name: value.cardholder_name.clone(),
            number: value.number.clone(),
            verification_number: value.verification_number.clone(),
            expiration_date: value.expiration_date.clone(),
            pin: value.pin.clone(),
            card_type: format!("{:?}", value.card_type),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveIdentity {
    pub full_name: String,
    pub email: String,
    pub phone_number: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub birthdate: String,
    pub gender: String,
    pub extra_personal_details: Vec<ArchiveExtraField>,
    pub organization: String,
    pub street_address: String,
    pub zip_or_postal_code: String,
    pub city: String,
    pub state_or_province: String,
    pub country_or_region: String,
    pub floor: String,
    pub county: String,
    pub extra_address_details: Vec<ArchiveExtraField>,
    pub social_security_number: String,
    pub passport_number: String,
    pub license_number: String,
    pub website: String,
    pub x_handle: String,
    pub second_phone_number: String,
    pub linkedin: String,
    pub reddit: String,
    pub facebook: String,
    pub yahoo: String,
    pub instagram: String,
    pub extra_contact_details: Vec<ArchiveExtraField>,
    pub company: String,
    pub job_title: String,
    pub personal_website: String,
    pub work_phone_number: String,
    pub work_email: String,
    pub extra_work_details: Vec<ArchiveExtraField>,
    pub extra_sections: Vec<ArchiveCustomSection>,
}

impl From<IdentityItem> for ArchiveIdentity {
    fn from(value: IdentityItem) -> Self {
        Self {
            full_name: value.full_name,
            email: value.email,
            phone_number: value.phone_number,
            first_name: value.first_name,
            middle_name: value.middle_name,
            last_name: value.last_name,
            birthdate: value.birthdate,
            gender: value.gender,
            extra_personal_details: value
                .extra_personal_details
                .iter()
                .map(ArchiveExtraField::from)
                .collect(),
            organization: value.organization,
            street_address: value.street_address,
            zip_or_postal_code: value.zip_or_postal_code,
            city: value.city,
            state_or_province: value.state_or_province,
            country_or_region: value.country_or_region,
            floor: value.floor,
            county: value.county,
            extra_address_details: value
                .extra_address_details
                .iter()
                .map(ArchiveExtraField::from)
                .collect(),
            social_security_number: value.social_security_number,
            passport_number: value.passport_number,
            license_number: value.license_number,
            website: value.website,
            x_handle: value.x_handle,
            second_phone_number: value.second_phone_number,
            linkedin: value.linkedin,
            reddit: value.reddit,
            facebook: value.facebook,
            yahoo: value.yahoo,
            instagram: value.instagram,
            extra_contact_details: value
                .extra_contact_details
                .iter()
                .map(ArchiveExtraField::from)
                .collect(),
            company: value.company,
            job_title: value.job_title,
            personal_website: value.personal_website,
            work_phone_number: value.work_phone_number,
            work_email: value.work_email,
            extra_work_details: value
                .extra_work_details
                .iter()
                .map(ArchiveExtraField::from)
                .collect(),
            extra_sections: value
                .extra_sections
                .iter()
                .map(ArchiveCustomSection::from)
                .collect(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveSshKey {
    pub private_key: String,
    pub public_key: String,
    pub sections: Vec<ArchiveCustomSection>,
}

impl From<&SshKeyItem> for ArchiveSshKey {
    fn from(value: &SshKeyItem) -> Self {
        Self {
            private_key: value.private_key.clone(),
            public_key: value.public_key.clone(),
            sections: value
                .sections
                .iter()
                .map(ArchiveCustomSection::from)
                .collect(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveWifi {
    pub ssid: String,
    pub password: String,
    pub security: String,
    pub sections: Vec<ArchiveCustomSection>,
}

impl From<&WifiItem> for ArchiveWifi {
    fn from(value: &WifiItem) -> Self {
        Self {
            ssid: value.ssid.clone(),
            password: value.password.clone(),
            security: format!("{:?}", value.security),
            sections: value
                .sections
                .iter()
                .map(ArchiveCustomSection::from)
                .collect(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveCustomSection {
    pub section_name: String,
    pub section_fields: Vec<ArchiveExtraField>,
}

impl From<&CustomSection> for ArchiveCustomSection {
    fn from(value: &CustomSection) -> Self {
        Self {
            section_name: value.section_name.clone(),
            section_fields: value
                .section_fields
                .iter()
                .map(ArchiveExtraField::from)
                .collect(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveExtraField {
    pub name: String,
    pub content: ArchiveExtraFieldContent,
}

impl From<&ItemExtraField> for ArchiveExtraField {
    fn from(value: &ItemExtraField) -> Self {
        Self {
            name: value.name.clone(),
            content: ArchiveExtraFieldContent::from(&value.content),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ArchiveExtraFieldContent {
    Text { value: String },
    Hidden { value: String },
    Totp { uri: String },
    Timestamp { unix_seconds: i64 },
}

impl From<&ItemExtraFieldContent> for ArchiveExtraFieldContent {
    fn from(value: &ItemExtraFieldContent) -> Self {
        match value {
            ItemExtraFieldContent::Text(v) => Self::Text { value: v.clone() },
            ItemExtraFieldContent::Hidden(v) => Self::Hidden { value: v.clone() },
            ItemExtraFieldContent::Totp(uri) => Self::Totp { uri: uri.clone() },
            ItemExtraFieldContent::Timestamp(ts) => Self::Timestamp { unix_seconds: *ts },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArchiveAttachment {
    pub id: String,
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    /// Base64 (std) payload; empty when the attachment has not been
    /// downloaded (`--include-attachments` was not used).
    #[serde(default)]
    pub data_base64: String,
}

impl ArchiveAttachment {
    pub fn pending(id: String, name: String, mime_type: String, size: u64) -> Self {
        Self {
            id,
            name,
            mime_type,
            size,
            data_base64: String::new(),
        }
    }
}

#[cfg(test)]
mod alias_email_tests {
    use super::*;

    #[test]
    fn alias_email_round_trips_through_json() {
        let item = ArchiveItem {
            id: "i1".into(),
            vault_id: "v1".into(),
            share_id: "s1".into(),
            item_type: "alias".into(),
            title: "Alias for x".into(),
            note: String::new(),
            item_uuid: "u1".into(),
            alias_email: Some("prefix..abc@passdevfree.com".into()),
            content: ArchiveItemContent::Alias,
            extra_fields: vec![],
            create_time: String::new(),
            modify_time: String::new(),
            attachments: vec![],
            trashed: false,
            has_files: false,
            folder_id: None,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("prefix..abc@passdevfree.com"));
        let parsed: ArchiveItem = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.alias_email.as_deref(),
            Some("prefix..abc@passdevfree.com")
        );

        // Non-alias items omit the field entirely
        let mut login = item.clone();
        login.item_type = "login".into();
        login.alias_email = None;
        let json = serde_json::to_string(&login).unwrap();
        assert!(!json.contains("alias_email"));
    }
}
