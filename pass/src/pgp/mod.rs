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

//! Native PGP and account-key cryptography implementations, backed by
//! `proton-crypto` / `proton-crypto-account`.
//!
//! These are the default implementations of the [`crate::domain::PgpCrypto`] and
//! [`crate::domain::AccountCrypto`] extension-point traits. Consumers that want a
//! different engine (for example OpenPGP on mobile) can still provide their own via
//! [`crate::domain::ClientFeatures`].

mod account;
mod native;

pub use account::ProtonAccountCrypto;
pub use native::NativePgpCrypto;
