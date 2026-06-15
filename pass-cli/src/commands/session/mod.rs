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
use anyhow::Result;
use clap::Subcommand;
use pass_auth::store::PassSessionStore;
use std::sync::{Arc, RwLock};

pub mod lock;

#[derive(Subcommand)]
pub enum SessionCommands {
    #[command(about = "Lock the current session with a PIN")]
    Lock {
        #[arg(help = "PIN code to lock the session")]
        pin: String,

        #[arg(
            long,
            help = "Time in seconds before the session auto-unlocks (min 30, max 900)",
            default_value = "300"
        )]
        lock_time: u32,
    },
}

pub async fn run(
    subcommand: SessionCommands,
    client: PassClient,
    store: Arc<RwLock<PassSessionStore>>,
) -> Result<()> {
    match subcommand {
        SessionCommands::Lock { pin, lock_time } => {
            lock::run(client, store, pin, Some(lock_time)).await
        }
    }
}
