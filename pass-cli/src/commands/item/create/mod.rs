mod credit_card;
mod login;
mod note;
mod wifi;

use anyhow::Result;
use clap::Subcommand;
use pass::PassClient;

#[derive(Subcommand)]
pub enum CreateCommands {
    /// Create a new login item
    Login {
        #[command(flatten)]
        args: login::LoginArgs,
    },
    /// Create a new note item
    Note {
        #[command(flatten)]
        args: note::NoteArgs,
    },
    /// Create a new credit card item (requires paid plan)
    #[command(name = "credit-card")]
    CreditCard {
        #[command(flatten)]
        args: credit_card::CreditCardArgs,
    },
    /// Create a new WiFi item (requires paid plan)
    Wifi {
        #[command(flatten)]
        args: wifi::WifiArgs,
    },
}

pub async fn run(command: CreateCommands, client: PassClient) -> Result<()> {
    match command {
        CreateCommands::Login { args } => login::run(args, client).await,
        CreateCommands::Note { args } => note::run(args, client).await,
        CreateCommands::CreditCard { args } => credit_card::run(args, client).await,
        CreateCommands::Wifi { args } => wifi::run(args, client).await,
    }
}
