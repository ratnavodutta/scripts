# Phase 3 vWAN Compliance -- Report
Generated 2026-09-07T09:09:49.405336+00:00 by script version 1.1.0, identity `Ratnavo.Dutta@blackbaud.me` (tenant `31fa3fc8-0d67-4b00-8f5a-3a9a69c281b8`). Runtime: 668.5s.
## What was scanned
- CMDB export: `cmdb_ci_cloud_service_account.xlsx` (113 rows)
- Azure export: `(not supplied)`
- File-level reconciliation: IN_BOTH=0, ONLY_IN_CMDB(ACCESS_OR_TENANT_GAP)=0, ONLY_IN_AZURE=0, DISABLED=0, EXCLUDED=8
- Coverage: 72 subscription(s) with at least one evaluated subnet, 11 not evaluated, 67 with errors.

## What was skipped and why
- missing RBAC: 8 subscription(s)
- EXCLUDED_BY_NAME_PATTERN: 8 subscription(s)

## Compliance rollup
> pct_of_total_subnets divides by ALL subnets evaluated-or-not (3413). pct_of_evaluated_subnets divides by subnets with a conclusive verdict only -- COMPLIANT+NON_COMPLIANT+EXPECTED_BYPASS (257) -- and is None for NOT_EVALUATED/ERROR, which are never a % of 'evaluated' by definition. NOT_EVALUATED is never counted as compliant in either denominator.

Total subnets: 3413  |  Evaluated (conclusive verdict): 257

| Verdict | Count | % of total | % of evaluated |
|---|---|---|---|
| COMPLIANT | 2 | 0.1% | 0.8% |
| NON_COMPLIANT | 38 | 1.1% | 14.8% |
| EXPECTED_BYPASS | 217 | 6.4% | 84.4% |
| NOT_EVALUATED | 1856 | 54.4% | n/a |
| ERROR | 1300 | 38.1% | n/a |

**Remaining Phase 3 migration work (NON_COMPLIANT + NOT_EVALUATED): 1894**

## Highest-impact NON_COMPLIANT subnets
| Subscription | Organization | Environment | VNet/Subnet | Offending Routes |
|---|---|---|---|---|
| IT Production P01 | IT | Production | AUSTRALIA_EAST/app-dmz-nonprod-01 | 2 |
| IT Production P01 | IT | Production | AUSTRALIA_EAST/app-nondmz-prod-01 | 2 |
| IT Production P01 | IT | Production | AUSTRALIA_EAST/web-dmz-nonprod-01 | 2 |
| IT Production P01 | IT | Production | AUSTRALIA_EAST/inf-nondmz-prod-01 | 2 |
| IT Production P01 | IT | Production | AUSTRALIA_EAST/inf-nondmz-SW-prod-01 | 2 |
| IT Production P01 | IT | Production | WEST_EUROPE/app-dmz-prod-01 | 2 |
| IT Production P01 | IT | Production | WEST_EUROPE/inf-nondmz-prod-01 | 2 |
| IT Production P02 | IT | Production | p02-eus-spoke-vnet/nagarro-desktops-02 | 1 |
| IT Production P02 | IT | Production | p02-eus-spoke-vnet/citrixinf-nondmz-prod-01 | 1 |
| IT Production P02 | IT | Production | p02-eus-spoke-vnet/avd-desktops-02 | 1 |
| IT Production P01 | IT | Production | insights-pentest-kali-vnet/default | 1 |
| IT Production P01 | IT | Production | p01-ae-zsac-vnet-rlqak4hf/p01-ae-zsac-ac-subnet-1-rlqak4hf | 1 |
| IT Production P01 | IT | Production | p01-eus-zsac-vnet-789jb9vk/p01-eus-zsac-ac-subnet-1-789jb9vk | 1 |
| IT Production P01 | IT | Production | p01-zscc-vnet-b665anzu/p01-zscc-cc-subnet-1-b665anzu | 1 |
| IT Production P01 | IT | Production | p01-ae-zscc-vnet-of0v06ou/p01-ae-zscc-cc-subnet-1-of0v06ou | 1 |
| IT Production P01 | IT | Production | p01-weu-zscc-vnet-sbrp2icl/p01-weu-zscc-cc-subnet-1-sbrp2icl | 1 |
| IT Production P01 | IT | Production | p01-weu-zsac-vnet-88ken985/p01-weu-zsac-ac-subnet-1-88ken985 | 1 |
| IT Production P01 | IT | Production | EAST_US/app-nondmz-nonprod-sap-01 | 1 |
| IT Production P01 | IT | Production | AUSTRALIA_EAST/AZRAECSR-INTERNAL | 1 |
| IT Production P01 | IT | Production | AUSTRALIA_EAST/AZRAECSR-EXTERNAL | 1 |
| IT Production P01 | IT | Production | EAST_US/web-nondmz-nonprod-01 | 1 |
| IT Production P01 | IT | Production | EAST_US/app-nondmz-prod-sap-01 | 1 |
| IT Production P01 | IT | Production | EAST_US/inf-nondmz-SW-prod-01 | 1 |
| IT Production P01 | IT | Production | EAST_US/net-nondmz-prod-01 | 1 |
| IT Production P01 | IT | Production | EAST_US/app-nondmz-nonprod-01 | 1 |

## Open questions for a human
- Hub 'sec01pwehub-rt01' (sub 8cdb6f7a-9f1b-4288-87f4-ea52f902f536) has NO firewall/NVA detected -- config gap. Verdicts for subnets peered to this hub cannot be trusted as COMPLIANT/NON_COMPLIANT until this is resolved.
- Hub 'sec01peus2hub-rt01' (sub 8cdb6f7a-9f1b-4288-87f4-ea52f902f536) has NO firewall/NVA detected -- config gap. Verdicts for subnets peered to this hub cannot be trusted as COMPLIANT/NON_COMPLIANT until this is resolved.
- Hub 'd40acsr01vhub01' (sub 38dc1973-b3ec-4db8-8f42-f76fc59e65b0) has NO firewall/NVA detected -- config gap. Verdicts for subnets peered to this hub cannot be trusted as COMPLIANT/NON_COMPLIANT until this is resolved.
- Hub 'n01-wus-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-ne-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-we-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-cus-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-eus2-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-ae-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-as-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-cnc-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'n01-cne-vhub-1' (sub 150ea8a8-4006-49a6-8c11-b7d7c2942e61) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'e01-cus-vhub-1' (sub 7253b84c-2f1a-4b10-9046-1fbdcc4334f1) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- Hub 'e01-eus2-vhub-1' (sub 7253b84c-2f1a-4b10-9046-1fbdcc4334f1) has a Routing Intent with only a PrivateTraffic policy (no InternetTraffic policy). NON_COMPLIANT verdicts driven by the 0.0.0.0/0 route for subnets in this hub's scope may be legitimate internet breakout, not a real Phase 3 violation -- verify manually (see README).
- 1276 call(s) failed with 403 AuthorizationFailed (see 'coverage' and the Errors sheet) -- most commonly missing the Microsoft.Network/networkInterfaces/effectiveRouteTable/action permission. Affected subnets show verdict ERROR rather than a real compliance result until RBAC is granted.

## What to do next
1. Fix the highest-impact NON_COMPLIANT subnets above first (Production, most offending routes).
2. Resolve `open_questions` -- config gaps and RBAC gaps block a trustworthy verdict for their scope.
3. Re-run with `--retry-failed-only` once RBAC/API errors are fixed, or `--rescan-all` for a clean sweep.
4. See `phase3_report.json` for the complete machine-readable detail behind this summary.
