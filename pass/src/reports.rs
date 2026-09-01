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
use crate::pagination::Pagination;
use crate::{PassClient, PassClientContext};
use anyhow::{Context, Result};
use muon::GET;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Report {
    #[serde(rename = "MemberReports")]
    pub member_reports: Vec<MemberReport>,
    #[serde(rename = "TotalMemberCount")]
    pub total_member_count: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MemberReport {
    #[serde(rename = "PrimaryEmail")]
    pub primary_email: String,
    #[serde(rename = "CustomEmailBreachCount")]
    pub custom_email_breach_count: BreachCount,
    #[serde(rename = "AddressBreachCount")]
    pub address_breach_count: BreachCount,
    #[serde(rename = "ItemsReport")]
    pub items_report: ItemsReport,
    #[serde(rename = "MonitorReport")]
    pub monitor_report: MonitorReport,
    #[serde(rename = "LastActivityTime")]
    pub last_activity_time: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BreachCount {
    #[serde(rename = "BreachEmailCount")]
    pub breach_email_count: i64,
    #[serde(rename = "TotalBreachCount")]
    pub total_breach_count: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ItemsReport {
    #[serde(rename = "OwnedVaultCount")]
    pub owned_vault_count: i64,
    #[serde(rename = "OwnedItemCount")]
    pub owned_item_count: i64,
    #[serde(rename = "AccessibleVaultCount")]
    pub accessible_vault_count: i64,
    #[serde(rename = "AccessibleItemCount")]
    pub accessible_item_count: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MonitorReport {
    #[serde(rename = "UserID")]
    pub user_id: i64,
    #[serde(rename = "OrganizationID")]
    pub organization_id: i64,
    #[serde(rename = "ReusedPasswords")]
    pub reused_passwords: i64,
    #[serde(rename = "Inactive2FA")]
    pub inactive_2fa: i64,
    #[serde(rename = "ExcludedItems")]
    pub excluded_items: i64,
    #[serde(rename = "WeakPasswords")]
    pub weak_passwords: i64,
    #[serde(rename = "CompromisedPasswords")]
    pub compromised_passwords: i64,
    #[serde(rename = "ReportTime")]
    pub report_time: i64,
    #[serde(rename = "ClientVersion")]
    pub client_version: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct OrganizationReportResponse {
    #[serde(rename = "Report")]
    report: Report,
}

impl<C: PassClientContext> PassClient<C> {
    pub async fn get_organization_report(&self) -> Result<Report> {
        let mut report: Option<Report> = None;
        let mut pagination = Pagination::default_paginated();

        loop {
            let req = GET!("/pass/v1/organization/report")
                .query(("Page", format!("{}", pagination.page())))
                .query(("PageSize", format!("{}", pagination.page_size())));

            let res = self
                .send(req)
                .await
                .context("Error fetching organization report")?;

            let response: OrganizationReportResponse = assert_response!(res);
            let page = response.report;

            let page_len = page.member_reports.len();
            match &mut report {
                None => report = Some(page),
                Some(acc) => {
                    acc.total_member_count = page.total_member_count;
                    acc.member_reports.extend(page.member_reports);
                }
            }

            if page_len < pagination.page_size() {
                break;
            }
            pagination = pagination.next();
        }

        Ok(report.unwrap_or(Report {
            member_reports: Vec::new(),
            total_member_count: 0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_tools::*;

    #[muon_test::test]
    async fn fetches_and_parses_organization_report(server: muon_test::Server) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_client(raw_client, &api).await;

        let handled = api.handler("/pass/v1/organization/report", |_| {
            success(serde_json::json!({
                "Code": 1000,
                "Report": {
                    "MemberReports": [
                        {
                            "PrimaryEmail": "me@somewhere.net",
                            "CustomEmailBreachCount": {
                                "BreachEmailCount": 3,
                                "TotalBreachCount": 838
                            },
                            "AddressBreachCount": {
                                "BreachEmailCount": 1,
                                "TotalBreachCount": 12
                            },
                            "ItemsReport": {
                                "OwnedVaultCount": 2,
                                "OwnedItemCount": 145,
                                "AccessibleItemCount": 210,
                                "AccessibleVaultCount": 4
                            },
                            "MonitorReport": {
                                "UserID": 123,
                                "OrganizationID": 456,
                                "ReusedPasswords": 3,
                                "Inactive2FA": 1,
                                "ExcludedItems": 0,
                                "WeakPasswords": 5,
                                "CompromisedPasswords": 2,
                                "ReportTime": 1717584000,
                                "ClientVersion": "1.24.0"
                            },
                            "LastActivityTime": 1717584000
                        }
                    ],
                    "TotalMemberCount": 42
                }
            }))
        });

        let report = client.get_organization_report().await.unwrap();

        assert_hit!(handled);
        assert_eq!(report.total_member_count, 42);
        assert_eq!(report.member_reports.len(), 1);

        let member = &report.member_reports[0];
        assert_eq!(member.primary_email, "me@somewhere.net");
        assert_eq!(member.custom_email_breach_count.breach_email_count, 3);
        assert_eq!(member.address_breach_count.total_breach_count, 12);
        assert_eq!(member.items_report.owned_item_count, 145);
        assert_eq!(member.items_report.accessible_item_count, 210);
        assert_eq!(member.monitor_report.user_id, 123);
        assert_eq!(member.monitor_report.organization_id, 456);
        assert_eq!(member.monitor_report.reused_passwords, 3);
        assert_eq!(member.monitor_report.inactive_2fa, 1);
        assert_eq!(member.monitor_report.excluded_items, 0);
        assert_eq!(member.monitor_report.weak_passwords, 5);
        assert_eq!(member.monitor_report.compromised_passwords, 2);
        assert_eq!(member.monitor_report.client_version, "1.24.0");
        assert_eq!(member.last_activity_time, 1717584000);
    }

    #[muon_test::test]
    async fn aggregates_paginated_member_reports(server: muon_test::Server) {
        let (raw_client, api) = server.client::<()>();
        let client = make_test_pass_client(raw_client, &api).await;

        fn member(email: &str) -> serde_json::Value {
            serde_json::json!({
                "PrimaryEmail": email,
                "CustomEmailBreachCount": {
                    "BreachEmailCount": 0, "TotalBreachCount": 0
                },
                "AddressBreachCount": {
                    "BreachEmailCount": 0, "TotalBreachCount": 0
                },
                "ItemsReport": {
                    "OwnedVaultCount": 0, "OwnedItemCount": 0,
                    "AccessibleItemCount": 0, "AccessibleVaultCount": 0
                },
                "MonitorReport": {
                    "UserID": 1, "OrganizationID": 2,
                    "ReusedPasswords": 0, "Inactive2FA": 0,
                    "ExcludedItems": 0, "WeakPasswords": 0,
                    "CompromisedPasswords": 0, "ReportTime": 0,
                    "ClientVersion": "1.24.0"
                },
                "LastActivityTime": 0
            })
        }

        let handler_fn = |req: &muon_test::server::Request| {
            let page: i64 = req
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .find_map(|p| p.strip_prefix("Page="))
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);

            let reports: Vec<serde_json::Value> = if page == 0 {
                (0..100)
                    .map(|i| member(&format!("user-{i}@example.com")))
                    .collect()
            } else {
                vec![member("final@example.com")]
            };

            success(serde_json::json!({
                "Code": 1000,
                "Report": {
                    "MemberReports": reports,
                    "TotalMemberCount": 101
                }
            }))
        };

        // Each `api.handler` registration only serves a single request, so
        // register it once per page fetched (page 0, then page 1).
        let handled = api.handler("/pass/v1/organization/report", handler_fn);
        let handled_second_page = api.handler("/pass/v1/organization/report", handler_fn);

        let report = client.get_organization_report().await.unwrap();

        assert_hit!(handled);
        assert_hit!(handled_second_page);
        assert_eq!(report.total_member_count, 101);
        assert_eq!(report.member_reports.len(), 101);
        assert_eq!(report.member_reports[0].primary_email, "user-0@example.com");
        assert_eq!(
            report.member_reports[100].primary_email,
            "final@example.com"
        );
    }
}
