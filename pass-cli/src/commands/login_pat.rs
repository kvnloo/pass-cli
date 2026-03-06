use crate::auth::auth_helpers::create_authenticator;
use crate::features::CliClientFeatures;
use crate::helpers::{PassClientExt, SessionExt};
use anyhow::{Context, Result};
use pass::{Client, FirstTimeSetupKey};
use pass_auth::PassSessionStore;
use std::sync::Arc;
use tokio::sync::RwLock;

pub async fn run(
    token_string_arg: Option<String>,
    client: Client,
    client_features: Arc<CliClientFeatures>,
    store: Arc<RwLock<PassSessionStore>>,
) -> Result<()> {
    let authenticator = create_authenticator(client_features.clone())?;

    // Perform personal access token login
    let (pass_client, personal_access_token_key) = authenticator
        .login_personal_access_token(
            client,
            client_features.clone(),
            store.clone(),
            token_string_arg,
        )
        .await?;

    // Perform first-time setup with the personal access token key
    let user_id = store.get_user_id().await?;
    let client_features = pass_client.get_cli_client_features()?;
    client_features.set_user_id(Some(user_id)).await;

    pass_client
        .perform_first_time_setup_with_key(FirstTimeSetupKey::PersonalAccessToken(
            personal_access_token_key,
        ))
        .await
        .context("Error performing first time setup")?;

    // Get and display personal access token name
    let personal_access_token_name = pass_client
        .get_personal_access_token_name()
        .await
        .context("Error getting personal access token name")?;

    println!(
        "Successfully logged in as personal access token: {}",
        personal_access_token_name
    );
    Ok(())
}
