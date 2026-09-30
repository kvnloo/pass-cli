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

use crate::{PassClient, PassClientContext};
use anyhow::{Result, anyhow};
use pass_derive::sdk_export;

mod create;
mod delete;
mod grant;
mod list;
mod list_access;
mod renew;
mod revoke;

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct PersonalAccessTokenFlags {
    #[serde(rename = "PassAgent", default)]
    pub pass_agent: bool,
}

impl PersonalAccessTokenFlags {
    pub fn for_agent() -> Self {
        Self { pass_agent: true }
    }
}

const PERSONAL_ACCESS_TOKEN_OPERATION_ERROR: &str = "Cannot manage or act on personal access tokens while logged in with a personal access token or agent session";

impl<C: PassClientContext> PassClient<C> {
    pub(crate) fn personal_access_token_operation_guard(&self) -> Result<()> {
        if self.is_pat_account() || self.is_agent_session() {
            return Err(anyhow!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR));
        }

        Ok(())
    }
}

pub use create::{CreatePersonalAccessTokenArgs, CreatePersonalAccessTokenResponse};
pub use list::PersonalAccessToken;
pub use list_access::PersonalAccessTokenAccess;
pub use renew::RenewPersonalAccessTokenResponse;

/// A newly created personal access token.
#[sdk_export]
#[derive(Clone, Debug)]
pub struct CreatedPersonalAccessToken {
    pub id: String,
    pub name: String,
    pub expire_time: Option<i64>,
    pub create_time: i64,
    pub modify_time: i64,
    pub token: String,
    /// Value to set in `PROTON_PASS_PERSONAL_ACCESS_TOKEN` to log in with the token.
    pub env_var: String,
}

/// A personal access token of the user.
#[sdk_export]
#[derive(Clone, Debug)]
pub struct PersonalAccessTokenSummary {
    pub id: String,
    pub name: String,
    pub expire_time: Option<i64>,
    pub pass_agent: bool,
}

/// SDK-friendly wrappers for the operations whose originals expose key
/// material (`create_personal_access_token`, `list_personal_access_tokens`).
#[sdk_export]
impl<C: PassClientContext> PassClient<C> {
    /// Creates a personal access token named `name`, expiring at the unix
    /// timestamp `expiration_time`. If `pass_agent` is set the token is flagged
    /// as an agent session token.
    #[sdk_export]
    pub async fn create_personal_access_token_with_name(
        &self,
        name: &str,
        expiration_time: i64,
        pass_agent: bool,
    ) -> Result<CreatedPersonalAccessToken> {
        let mut args = CreatePersonalAccessTokenArgs::new(name.to_string(), expiration_time)?;
        if pass_agent {
            args = args.with_pass_agent_flag();
        }
        let res = self.create_personal_access_token(args).await?;
        Ok(CreatedPersonalAccessToken {
            id: res.personal_access_token_id.value().to_string(),
            name: res.name,
            expire_time: res.expire_time,
            create_time: res.create_time,
            modify_time: res.modify_time,
            token: res.token,
            env_var: res.env_var,
        })
    }

    /// Lists the personal access tokens of the user.
    #[sdk_export]
    pub async fn list_personal_access_token_summaries(
        &self,
    ) -> Result<Vec<PersonalAccessTokenSummary>> {
        Ok(self
            .list_personal_access_tokens()
            .await?
            .into_iter()
            .map(|pat| PersonalAccessTokenSummary {
                id: pat.pat_id.value().to_string(),
                name: pat.name,
                expire_time: pat.expire_time,
                pass_agent: pat.pass_agent,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::PERSONAL_ACCESS_TOKEN_OPERATION_ERROR;
    use crate::domain::{PersonalAccessTokenId, ShareId, ShareRole};
    use crate::test_tools::*;

    #[muon_test::test]
    async fn test_create_personal_access_token_blocked_for_pat_session(server: muon_test::Server) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_pat_client(raw_client, &api).await;
        let handled = api.handler("/account/v4/personal-access-token", |_| success_code());

        let error = client
            .create_personal_access_token(
                super::CreatePersonalAccessTokenArgs::new("test".to_string(), 1735689600).unwrap(),
            )
            .await
            .err()
            .expect("PAT sessions should not be able to create personal access tokens");

        assert_eq!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR, error.to_string());
        assert_not_hit!(handled);
    }

    #[muon_test::test]
    async fn test_list_personal_access_tokens_blocked_for_pat_session(server: muon_test::Server) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_pat_client(raw_client, &api).await;
        let handled = api.handler("/account/v4/personal-access-token", |_| success_code());

        let error = client
            .list_personal_access_tokens()
            .await
            .expect_err("PAT sessions should not be able to list personal access tokens");

        assert_eq!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR, error.to_string());
        assert_not_hit!(handled);
    }

    #[muon_test::test]
    async fn test_delete_personal_access_token_blocked_for_pat_session(server: muon_test::Server) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_pat_client(raw_client, &api).await;
        let handled = api.handler_with_method(
            Method::DELETE,
            "/account/v4/personal-access-token/test_pat",
            |_| success_code(),
        );

        let error = client
            .delete_personal_access_token(&PersonalAccessTokenId::new("test_pat".to_string()))
            .await
            .expect_err("PAT sessions should not be able to delete personal access tokens");

        assert_eq!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR, error.to_string());
        assert_not_hit!(handled);
    }

    #[muon_test::test]
    async fn test_renew_personal_access_token_blocked_for_pat_session(server: muon_test::Server) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_pat_client(raw_client, &api).await;
        let handled = api.handler_with_method(
            Method::POST,
            "/account/v4/personal-access-token/test_pat/renew",
            |_| success_code(),
        );

        let error = client
            .renew_personal_access_token(
                &PersonalAccessTokenId::new("test_pat".to_string()),
                1735689600,
            )
            .await
            .expect_err("PAT sessions should not be able to renew personal access tokens");

        assert_eq!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR, error.to_string());
        assert_not_hit!(handled);
    }

    #[muon_test::test]
    async fn test_list_personal_access_token_access_blocked_for_pat_session(
        server: muon_test::Server,
    ) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_pat_client(raw_client, &api).await;
        let handled = api.handler("/pass/v1/personal-access-token/test_pat/access", |_| {
            success_code()
        });

        let error = client
            .list_personal_access_token_access(&PersonalAccessTokenId::new("test_pat".to_string()))
            .await
            .expect_err("PAT sessions should not be able to list personal access token access");

        assert_eq!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR, error.to_string());
        assert_not_hit!(handled);
    }

    #[muon_test::test]
    async fn test_grant_personal_access_token_access_blocked_for_pat_session(
        server: muon_test::Server,
    ) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_pat_client(raw_client, &api).await;
        let handled = api.handler("/pass/v1/personal-access-token/test_pat/access", |_| {
            success_code()
        });

        let error = client
            .grant_personal_access_token_access(
                &PersonalAccessTokenId::new("test_pat".to_string()),
                &ShareId::new("test_share".to_string()),
                None,
                &ShareRole::Viewer,
            )
            .await
            .expect_err("PAT sessions should not be able to grant personal access token access");

        assert_eq!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR, error.to_string());
        assert_not_hit!(handled);
    }

    #[muon_test::test]
    async fn test_revoke_personal_access_token_access_blocked_for_pat_session(
        server: muon_test::Server,
    ) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_pat_client(raw_client, &api).await;
        let handled = api.handler_with_method(
            Method::DELETE,
            "/pass/v1/personal-access-token/test_pat/access/test_share",
            |_| success_code(),
        );

        let error = client
            .revoke_personal_access_token_access(
                &PersonalAccessTokenId::new("test_pat".to_string()),
                &ShareId::new("test_share".to_string()),
            )
            .await
            .expect_err("PAT sessions should not be able to revoke personal access token access");

        assert_eq!(PERSONAL_ACCESS_TOKEN_OPERATION_ERROR, error.to_string());
        assert_not_hit!(handled);
    }
}
