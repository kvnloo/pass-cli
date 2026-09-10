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

use crate::archive::crypto::{ArchiveEnvelope, ArchiveKdfParams};
use anyhow::Result;

static ARGON2_KDF_JS: &str = include_str!("../../resources/argon2_kdf.js");
static VIEWER_TEMPLATE: &str = include_str!("../../resources/archive-viewer.html");

#[derive(serde::Serialize, serde::Deserialize)]
struct ViewerMeta {
    encrypted: bool,
    exported_at: String,
    has_attachments: bool,
    item_count: usize,
    vault_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    kdf: Option<ArchiveKdfParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
}

pub struct ViewerInput<'a> {
    pub data_json: &'a str,
    pub envelope: Option<&'a ArchiveEnvelope>,
    pub exported_at: &'a str,
    pub has_attachments: bool,
    pub item_count: usize,
    pub vault_count: usize,
}

pub fn render(options: ViewerInput) -> Result<String> {
    let meta = ViewerMeta {
        encrypted: options.envelope.is_some(),
        exported_at: options.exported_at.to_string(),
        has_attachments: options.has_attachments,
        item_count: options.item_count,
        vault_count: options.vault_count,
        kdf: options.envelope.map(|e| e.kdf),
        salt: options.envelope.map(|e| e.salt.clone()),
    };

    let payload = match options.envelope {
        Some(envelope) => serde_json::to_string(envelope)?,
        None => options.data_json.to_string(),
    };

    Ok(viewer_html(&serde_json::to_string(&meta)?, &payload))
}

fn viewer_html(meta_json: &str, payload: &str) -> String {
    // Embedded payloads are JSON strings; escape them once for safe inclusion
    // inside a JS double-quoted string literal.
    let meta_escaped = escape_js(meta_json);
    let payload_escaped = escape_js(payload);

    VIEWER_TEMPLATE
        .replace(
            "<!--{{META_JSON}}-->",
            &format!("const __META_JSON = \"{meta_escaped}\";"),
        )
        .replace(
            "<!--{{PAYLOAD_JSON}}-->",
            &format!("const __PAYLOAD_JSON = \"{payload_escaped}\";"),
        )
        .replace("<!--{{KDF_JS}}-->", ARGON2_KDF_JS)
}

/// Escape a JSON string for inclusion inside a JS double-quoted string literal.
fn escape_js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::model::*;

    fn sample_data() -> ArchiveData {
        ArchiveData {
            version: 1,
            exported_at: "2026-09-04T12:00:00Z".to_string(),
            folders: vec![],
            vaults: vec![
                ArchiveVault {
                    id: "v1".into(),
                    share_id: "s1".into(),
                    name: "Personal".into(),
                    description: "Main vault".into(),
                },
                ArchiveVault {
                    id: "v2".into(),
                    share_id: "s2".into(),
                    name: "Work".into(),
                    description: String::new(),
                },
            ],
            items: vec![ArchiveItem {
                id: "i1".into(),
                vault_id: "v1".into(),
                share_id: "s1".into(),
                item_type: "login".into(),
                title: "GitHub".into(),
                note: "Work account.".into(),
                item_uuid: "u1".into(),
                content: ArchiveItemContent::Login(ArchiveLogin {
                    email: "me@example.com".into(),
                    username: "username".into(),
                    password: "hunter2butlonger".into(),
                    urls: vec!["https://github.com/login".into()],
                    totp_uri:
                        "otpauth://totp/GitHub:username?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
                            .into(),
                    passkeys: vec![],
                }),
                extra_fields: vec![ArchiveExtraField {
                    name: "API key".into(),
                    content: ArchiveExtraFieldContent::Hidden {
                        value: "sk-123".into(),
                    },
                }],
                create_time: "2026-01-01T00:00:00Z".into(),
                modify_time: "2026-06-01T00:00:00Z".into(),
                attachments: vec![],
                trashed: false,
                has_files: false,
                folder_id: None,
                alias_email: None,
            }],
            has_attachments: false,
        }
    }

    #[test]
    fn test_render_plaintext() {
        let data = sample_data();
        let json = serde_json::to_string(&data).unwrap();
        let html = render(ViewerInput {
            data_json: &json,
            envelope: None,
            exported_at: &data.exported_at,
            has_attachments: false,
            item_count: data.items.len(),
            vault_count: data.vaults.len(),
        })
        .unwrap();
        assert!(html.contains("__PAYLOAD_JSON"));
        assert!(html.contains("GitHub"));
    }

    #[test]
    #[ignore = "helper that dumps a sample archive, not a test"]
    fn dump_sample_html() {
        use crate::archive::crypto;
        let mut data = sample_data();
        data.items.push(ArchiveItem {
            id: "i2".into(),
            vault_id: "v2".into(),
            share_id: "s2".into(),
            item_type: "credit_card".into(),
            title: "Visa Gold".into(),
            note: String::new(),
            item_uuid: "u2".into(),
            content: ArchiveItemContent::CreditCard(ArchiveCreditCard {
                cardholder_name: "username Surname".into(),
                number: "4012888888881881".into(),
                verification_number: "123".into(),
                expiration_date: "09/29".into(),
                pin: "4321".into(),
                card_type: "Other".into(),
            }),
            extra_fields: vec![],
            create_time: "2026-02-01T00:00:00Z".into(),
            modify_time: "2026-07-01T00:00:00Z".into(),
            attachments: vec![ArchiveAttachment {
                id: "a1".into(),
                name: "invoice.pdf".into(),
                mime_type: "application/pdf".into(),
                size: 9,
                data_base64: crate::archive::base64_encode(b"PDFDATA!!"),
            }],
            trashed: false,
            has_files: false,
            folder_id: None,
            alias_email: None,
        });
        let json = serde_json::to_string(&data).unwrap();
        let salt = crate::crypto::random_bytes(crypto::SALT_LEN);
        let kdf = crypto::ArchiveKdfParams::current();
        let key = crypto::derive_key("sample-pw-123", &salt, &kdf).unwrap();
        let blob = crypto::encrypt_blob(json.as_bytes(), &key).unwrap();
        let envelope = crypto::ArchiveEnvelope {
            version: 1,
            kdf,
            salt: hex::encode(salt),
            blob: crate::archive::base64_encode(&blob),
        };
        let html = render(ViewerInput {
            data_json: &json,
            envelope: Some(&envelope),
            exported_at: &data.exported_at,
            has_attachments: true,
            item_count: data.items.len(),
            vault_count: data.vaults.len(),
        })
        .unwrap();
        std::fs::write(
            std::path::Path::new(
                &std::env::var("CARGO_TARGET_TMPDIR")
                    .unwrap_or_else(|_| std::env::temp_dir().display().to_string()),
            )
            .join("pass_archive_sample.html"),
            &html,
        )
        .unwrap();
    }

    #[test]
    fn test_render_encrypted() {
        use crate::archive::crypto;
        let data = sample_data();
        let json = serde_json::to_string(&data).unwrap();
        let salt = crate::crypto::random_bytes(crypto::SALT_LEN);
        let kdf = crypto::ArchiveKdfParams::current();
        let key = crypto::derive_key("pw", &salt, &kdf).unwrap();
        let blob = crypto::encrypt_blob(json.as_bytes(), &key).unwrap();
        let envelope = crypto::ArchiveEnvelope {
            version: 1,
            kdf,
            salt: hex::encode(salt),
            blob: crate::archive::base64_encode(&blob),
        };
        let html = render(ViewerInput {
            data_json: &json,
            envelope: Some(&envelope),
            exported_at: &data.exported_at,
            has_attachments: false,
            item_count: data.items.len(),
            vault_count: data.vaults.len(),
        })
        .unwrap();
        // Encrypted archives must NOT contain the plaintext JSON
        assert!(!html.contains("hunter2butlonger"));
        assert!(!html.contains("JBSWY3DPEHPK3PXP"));
    }
}
