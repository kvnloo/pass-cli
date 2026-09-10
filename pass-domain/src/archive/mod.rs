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

mod crypto;
mod model;
mod viewer;

pub use crypto::{
    ARCHIVE_AAD, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, ArchiveEnvelope, ArchiveKdfParams,
    KEY_LEN, NONCE_LEN, SALT_LEN,
};
pub use crypto::{derive_key, encrypt_blob};
pub use model::{
    ArchiveAttachment, ArchiveCreditCard, ArchiveCustomSection, ArchiveData, ArchiveExtraField,
    ArchiveExtraFieldContent, ArchiveFolder, ArchiveIdentity, ArchiveItem, ArchiveItemContent,
    ArchiveLogin, ArchivePasskey, ArchiveSshKey, ArchiveVault, ArchiveWifi,
};
pub use viewer::{ViewerInput, render};

/// Hex encoding helper.
pub fn hex_encode(data: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// Base64 standard encoding helper (no external base64 dep needed by callers).
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
