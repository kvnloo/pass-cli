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

use crate::helpers::CliPassClient as PassClient;
use anyhow::{Result, anyhow};
use pass::monitor::MAX_REASON_LENGTH;
use pass_domain::{EventAction, ItemId, ShareId};

const REASON_ENV_VAR: &str = "PROTON_PASS_AGENT_REASON";

fn validate_reason_string(reason: String) -> Result<String> {
    if reason.trim().is_empty() {
        return Err(anyhow!(
            "{REASON_ENV_VAR} is set but empty. Provide a non-empty reason describing why \
             this item operation is being performed."
        ));
    }

    if reason.chars().count() > MAX_REASON_LENGTH {
        return Err(anyhow!(
            "{REASON_ENV_VAR} is too long ({} characters). Keep it under {MAX_REASON_LENGTH} \
             characters.",
            reason.chars().count()
        ));
    }

    Ok(reason)
}

fn validate_reason() -> Result<String> {
    let reason = std::env::var(REASON_ENV_VAR).map_err(|_| {
        anyhow!(
            "Agent sessions must set the {REASON_ENV_VAR} environment variable before running \
             commands.\n\
             Example: {REASON_ENV_VAR}=\"Retrieving database credentials for deployment\" pass-cli item view --share-id {{YourShareId}} --item-id {{YourItemId}}"
        )
    })?;

    validate_reason_string(reason)
}

// For agent sessions, validates that the reason env var is set and valid before an operation.
// Useful for checking prerequirements before any action is performed.
// This method doesn't send any event to the backend.
// Does nothing for non-agent sessions.
pub fn ensure_reason_if_agent(client: &PassClient) -> Result<()> {
    if !client.is_agent_session() {
        return Ok(());
    }
    validate_reason().map(|_| ())
}

// For agent sessions, sends the reason and the action the agent performed to the backend.
// Does nothing for non-agent sessions.
pub async fn send_reason_if_agent(
    client: &PassClient,
    action: EventAction,
    share_id: &ShareId,
    item_id: Option<&ItemId>,
) -> Result<()> {
    if !client.is_agent_session() {
        return Ok(());
    }

    let reason = validate_reason()?;
    client
        .send_monitor_action(action, share_id, item_id, &reason)
        .await
}

// Like send_reason_if_agent but accepts a pre-fetched item name, avoiding a redundant view_item
// call when the caller already has the item content.
pub async fn send_reason_if_agent_with_name(
    client: &PassClient,
    action: EventAction,
    share_id: &ShareId,
    item_id: Option<&ItemId>,
    item_name: Option<&str>,
) -> Result<()> {
    if !client.is_agent_session() {
        return Ok(());
    }

    let reason = validate_reason()?;
    client
        .send_monitor_action_with_name(action, share_id, item_id, item_name, &reason)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reason_is_rejected() {
        let err =
            validate_reason_string("".to_string()).expect_err("empty reason must be rejected");
        assert!(err.to_string().contains("set but empty"));
    }

    #[test]
    fn whitespace_only_reason_is_rejected() {
        let err = validate_reason_string("   \t\n ".to_string())
            .expect_err("whitespace-only reason must be rejected");
        assert!(err.to_string().contains("set but empty"));
    }

    #[test]
    fn overlong_reason_is_rejected() {
        let long_reason = "a".repeat(MAX_REASON_LENGTH + 1);
        let err =
            validate_reason_string(long_reason).expect_err("overlong reason must be rejected");
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn max_length_reason_is_accepted() {
        let reason = "a".repeat(MAX_REASON_LENGTH);
        assert_eq!(
            validate_reason_string(reason.to_string()).expect("max-length reason must be accepted"),
            reason
        );
    }

    #[test]
    fn valid_reason_is_returned_verbatim() {
        let reason = "Rotating credentials before deployment".to_string();
        assert_eq!(
            validate_reason_string(reason.clone()).expect("valid reason must be accepted"),
            reason
        );
    }
}
