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

pub const ENVIRONMENT_ENV_VAR: &str = "PROTON_PASS_ENVIRONMENT";

pub fn proxy_config_from_env() -> pass::auth::ProxyConfig {
    pass::auth::ProxyConfig::from_env()
}

pub fn debug_config_from_env() -> Option<pass::auth::DebugConfig> {
    std::env::var("XDEBUG_SESSION")
        .ok()
        .map(|session| pass::auth::DebugConfig {
            xdebug_session: Some(session),
        })
}

pub fn detect_locale() -> String {
    for var in &["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(locale) = std::env::var(var) {
            let normalized = pass::domain::headers::normalize_locale(&locale);
            if !normalized.is_empty() {
                return normalized;
            }
        }
    }
    pass::domain::headers::DEFAULT_LOCALE.to_string()
}
