use crate::PassClient;
use anyhow::Result;
use muon::GET;
use muon::env::EnvId;

#[derive(Debug)]
pub struct UserInfo {
    pub user: UserInfoUser,
    pub env: EnvId,
}

#[derive(Debug)]
pub struct UserInfoUser {
    pub id: String,
    pub name: String,
    pub email: String,
}

impl From<UserResponse> for UserInfoUser {
    fn from(value: UserResponse) -> Self {
        Self {
            id: value.id,
            name: value.name.unwrap_or_else(|| value.email.clone()),
            email: value.email,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct GetUserResponse {
    #[serde(rename = "User")]
    user: UserResponse,
}

#[derive(Debug, serde::Deserialize)]
struct UserResponse {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Email")]
    pub email: String,
}

impl PassClient {
    pub async fn get_info(&self) -> Result<UserInfo> {
        let res = self.send(GET!("/core/v4/users")).await?;
        let response: GetUserResponse = assert_response!(res);
        Ok(UserInfo {
            user: UserInfoUser::from(response.user),
            env: self.client.env().clone(),
        })
    }

    pub async fn get_service_account_name(&self) -> Result<String> {
        let service_account_data = self.get_service_account_self().await?;
        Ok(service_account_data.name)
    }

    async fn get_service_account_self(&self) -> Result<PersonalAccessTokenSelfData> {
        let res = self
            .send(GET!("/account/v4/personal-access-token/self"))
            .await?;
        let response: PersonalAccessTokenSelfResponse = assert_response!(res);
        Ok(response.service_account)
    }
}

#[derive(Debug, serde::Deserialize)]
struct PersonalAccessTokenSelfResponse {
    #[serde(rename = "PersonalAccessToken")]
    service_account: PersonalAccessTokenSelfData,
}

#[derive(Debug, serde::Deserialize)]
struct PersonalAccessTokenSelfData {
    #[serde(rename = "PersonalAccessTokenID")]
    #[allow(dead_code)]
    pub service_account_id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ExpireTime")]
    #[allow(dead_code)]
    pub expire_time: Option<i64>,
}
