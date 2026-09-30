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

use crate::domain::TargetType;
use crate::domain::models::share::ShareId;
use crate::domain::models::share::role::ShareRole;
use pass_derive::sdk_export;

#[sdk_export]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ShareMember {
    pub member_share_id: ShareId,
    pub email: String,
    pub name: String,
    pub is_group_share: bool,
    pub role: ShareRole,
    pub target_type: TargetType,
}
