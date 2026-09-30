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

use crate::SharedPassSessionStore;
use muon::common::GenericContext;
use muon::cookie_store::NoOpCookieStore;
use muon::{Client, NoInfo, Session};

#[cfg(tokio_runtime)]
pub type PassConnector<Os, Ex> =
    muon::transport::http::hyper::connector::HyperConnector<Os, muon::rt::SendExecutor<Ex>>;
#[cfg(wasm_runtime)]
pub type PassConnector<Sleeper> = muon::transport::http::reqwest::ReqwestConnector<Sleeper>;

#[cfg(tokio_runtime)]
pub type Context<Os, Ex> =
    GenericContext<PassConnector<Os, Ex>, SharedPassSessionStore, NoInfo, NoOpCookieStore>;
#[cfg(wasm_runtime)]
pub type Context<Sleeper> =
    GenericContext<PassConnector<Sleeper>, SharedPassSessionStore, NoInfo, NoOpCookieStore>;

#[cfg(tokio_runtime)]
pub type PassAuthClient<Os, Ex> = Client<Context<Os, Ex>>;
#[cfg(wasm_runtime)]
pub type PassAuthClient<Sleeper> = Client<Context<Sleeper>>;

#[cfg(tokio_runtime)]
pub type PassAuthSession<Os, Ex> = Session<Context<Os, Ex>>;
#[cfg(wasm_runtime)]
pub type PassAuthSession<Sleeper> = Session<Context<Sleeper>>;
