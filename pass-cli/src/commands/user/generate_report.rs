/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software; you can redistribute it and/or modify
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
use crate::commands::OutputFormat;
use crate::helpers::CliPassClient as PassClient;
use crate::utils::format_date;
use anyhow::{Context, Result};
use pass::{BreachCount, ItemsReport, MemberReport, MonitorReport, Report};

#[derive(serde::Serialize)]
struct BreachCountJsonOutput {
    breach_email_count: i64,
    total_breach_count: i64,
}

impl From<&BreachCount> for BreachCountJsonOutput {
    fn from(value: &BreachCount) -> Self {
        Self {
            breach_email_count: value.breach_email_count,
            total_breach_count: value.total_breach_count,
        }
    }
}

#[derive(serde::Serialize)]
struct ItemsReportJsonOutput {
    owned_vault_count: i64,
    owned_item_count: i64,
    accessible_vault_count: i64,
    accessible_item_count: i64,
}

impl From<&ItemsReport> for ItemsReportJsonOutput {
    fn from(value: &ItemsReport) -> Self {
        Self {
            owned_vault_count: value.owned_vault_count,
            owned_item_count: value.owned_item_count,
            accessible_vault_count: value.accessible_vault_count,
            accessible_item_count: value.accessible_item_count,
        }
    }
}

#[derive(serde::Serialize)]
struct MonitorReportJsonOutput {
    user_id: i64,
    organization_id: i64,
    reused_passwords: i64,
    inactive_2fa: i64,
    excluded_items: i64,
    weak_passwords: i64,
    compromised_passwords: i64,
    report_time: i64,
    client_version: String,
}

impl From<&MonitorReport> for MonitorReportJsonOutput {
    fn from(value: &MonitorReport) -> Self {
        Self {
            user_id: value.user_id,
            organization_id: value.organization_id,
            reused_passwords: value.reused_passwords,
            inactive_2fa: value.inactive_2fa,
            excluded_items: value.excluded_items,
            weak_passwords: value.weak_passwords,
            compromised_passwords: value.compromised_passwords,
            report_time: value.report_time,
            client_version: value.client_version.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct MemberReportJsonOutput {
    primary_email: String,
    custom_email_breach_count: BreachCountJsonOutput,
    address_breach_count: BreachCountJsonOutput,
    items_report: ItemsReportJsonOutput,
    monitor_report: MonitorReportJsonOutput,
    last_activity_time: i64,
}

impl From<&MemberReport> for MemberReportJsonOutput {
    fn from(value: &MemberReport) -> Self {
        Self {
            primary_email: value.primary_email.clone(),
            custom_email_breach_count: (&value.custom_email_breach_count).into(),
            address_breach_count: (&value.address_breach_count).into(),
            items_report: (&value.items_report).into(),
            monitor_report: (&value.monitor_report).into(),
            last_activity_time: value.last_activity_time,
        }
    }
}

#[derive(serde::Serialize)]
struct OrganizationReportJsonOutput {
    member_reports: Vec<MemberReportJsonOutput>,
    total_member_count: i64,
}

impl From<&Report> for OrganizationReportJsonOutput {
    fn from(value: &Report) -> Self {
        Self {
            member_reports: value.member_reports.iter().map(Into::into).collect(),
            total_member_count: value.total_member_count,
        }
    }
}

pub async fn run(client: PassClient, output_format: OutputFormat) -> Result<()> {
    let report = client
        .get_organization_report()
        .await
        .context("Error generating user report")?;

    match output_format {
        OutputFormat::Json => {
            let out: OrganizationReportJsonOutput = (&report).into();
            let json =
                serde_json::to_string_pretty(&out).context("Error serializing user report")?;
            println!("{json}");
        }
        OutputFormat::Human => {
            println!("Total members: {}", report.total_member_count);
            println!();
            if report.member_reports.is_empty() {
                println!("No members found");
            }
            for member in &report.member_reports {
                println!("User: {}", member.primary_email);
                println!(
                    "  Breaches (email aliases): {} emails / {} breaches",
                    member.custom_email_breach_count.breach_email_count,
                    member.custom_email_breach_count.total_breach_count
                );
                println!(
                    "  Breaches (addresses): {} emails / {} breaches",
                    member.address_breach_count.breach_email_count,
                    member.address_breach_count.total_breach_count
                );
                println!(
                    "  Owned vaults/items: {}/{}",
                    member.items_report.owned_vault_count, member.items_report.owned_item_count
                );
                println!(
                    "  Accessible vaults/items: {}/{}",
                    member.items_report.accessible_vault_count,
                    member.items_report.accessible_item_count
                );
                println!(
                    "  Reused passwords: {}",
                    member.monitor_report.reused_passwords
                );
                println!("  Weak passwords: {}", member.monitor_report.weak_passwords);
                println!(
                    "  Compromised passwords: {}",
                    member.monitor_report.compromised_passwords
                );
                println!("  Inactive 2FA: {}", member.monitor_report.inactive_2fa);
                let last_activity = if member.last_activity_time == 0 {
                    "never".to_string()
                } else {
                    format_date(member.last_activity_time)
                };
                println!("  Last activity: {last_activity}");
                println!();
            }
        }
    }

    Ok(())
}
