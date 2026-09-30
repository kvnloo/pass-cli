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

//! Concrete, FFI-facing handles for the SDK targets.
//!
//! Items across the crate marked `#[sdk_export]` are exported from here (for
//! methods) or next to their definition (for free functions and types), so SDK
//! crates only need to depend on `pass` with the right feature. See
//! `pass-derive` for the conversion rules.

use crate::client::PassClient as CorePassClient;

#[cfg(wasm_runtime)]
pub use wasm::*;

#[cfg(uniffi_runtime)]
pub use self::uniffi::*;

/// A logged-in Pass client. Its methods are the `PassClient` methods marked
/// `#[sdk_export]`.
#[cfg_attr(wasm_runtime, ::wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(uniffi_runtime, derive(::uniffi::Object))]
pub struct PassClient {
    pub(crate) inner: CorePassClient<SdkContext>,
}

impl From<CorePassClient<SdkContext>> for PassClient {
    fn from(inner: CorePassClient<SdkContext>) -> Self {
        Self { inner }
    }
}

#[cfg(wasm_runtime)]
mod wasm {
    use wasm_bindgen::JsError;

    /// The runtime context the exported handles are built on.
    pub type SdkContext = crate::auth::WasmContext;

    /// Converts errors returned by exported functions into JS `Error`s, keeping
    /// the whole `anyhow` context chain in the message.
    pub fn js_error(e: impl Into<anyhow::Error>) -> JsError {
        JsError::new(&format!("{:#}", e.into()))
    }
}

#[cfg(uniffi_runtime)]
mod uniffi {
    use jiff::civil::DateTime;

    /// The runtime context the exported handles are built on.
    pub type SdkContext = crate::auth::TokioContext;

    /// The error thrown by every fallible SDK call (`PassException` in
    /// Kotlin, `PassError` in Swift).
    #[derive(Debug, ::uniffi::Error)]
    pub enum PassError {
        /// `reason` holds the whole error chain, outermost context first.
        Generic { reason: String },
    }

    impl std::fmt::Display for PassError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Generic { reason } => f.write_str(reason),
            }
        }
    }

    impl std::error::Error for PassError {}

    impl From<anyhow::Error> for PassError {
        fn from(e: anyhow::Error) -> Self {
            Self::Generic {
                reason: format!("{e:#}"),
            }
        }
    }

    // Datetimes cross as ISO 8601 strings, as they do in JSON (and in the wasm SDK).
    ::uniffi::custom_type!(DateTime, String, {
        remote,
        lower: |value| value.to_string(),
        try_lift: |value| Ok(value.parse()?),
    });
}
