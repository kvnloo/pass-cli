use crate::PassClient;
use anyhow::{Context, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub enum FirstTimeSetupKey {
    Passphrase(Vec<u8>),
    UserPassword(String),
}

impl PassClient {
    pub async fn perform_first_time_setup(&self, pass: &str) -> Result<()> {
        self.setup_key_passphrases(pass)
            .await
            .context("Error setting up key passphrases")?;

        Ok(())
    }

    pub async fn perform_first_time_setup_with_key(&self, key: FirstTimeSetupKey) -> Result<()> {
        match key {
            FirstTimeSetupKey::Passphrase(ref passphrase) => {
                self.setup_key_passphrases_with_passphrase(passphrase)
                    .await
                    .context("Error setting up key passphrases")?;
                Ok(())
            }
            FirstTimeSetupKey::UserPassword(ref user_pass) => {
                self.perform_first_time_setup(user_pass.as_str()).await
            }
        }
    }
}
