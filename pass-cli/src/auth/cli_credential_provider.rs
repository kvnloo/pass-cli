use anyhow::Result;
use pass_auth::CredentialProvider;

pub const PERSONAL_ACCESS_TOKEN_ENV_VAR: &str = "PROTON_PASS_PERSONAL_ACCESS_TOKEN";

pub struct CliCredentialProvider;

#[async_trait::async_trait]
impl CredentialProvider for CliCredentialProvider {
    async fn get_username(&self) -> Result<String> {
        crate::client::get_username()
    }

    async fn get_password(&self) -> Result<String> {
        crate::client::get_password()
    }

    async fn get_totp(&self) -> Result<String> {
        crate::client::get_totp()
    }

    async fn get_extra_password(&self) -> Result<String> {
        crate::client::get_extra_password()
    }

    async fn get_personal_access_token(&self) -> Result<String> {
        std::env::var(PERSONAL_ACCESS_TOKEN_ENV_VAR)
            .map_err(|_| anyhow::anyhow!(
                "Personal access token token not found. Set {PERSONAL_ACCESS_TOKEN_ENV_VAR} environment variable"
            ))
    }
}
