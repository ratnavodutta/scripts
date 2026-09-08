# Azure vWAN Transit Hub — Phase 3 Compliance Discovery

Read-only discovery tool for the Decentralized-to-Centralized network
modernization program. Finds every remaining subscription/VNet/subnet whose
traffic does **not** yet route through the Azure Virtual WAN (vWAN) transit
hub, and reports exactly which routes bypass it.

Scope is driven by a **ServiceNow CMDB export**, not "every subscription the
credential can see" — see Phase 0 below. This script never creates,
modifies, or deletes any Azure resource. It only calls `list`/`get`
operations plus the read-only
`network_interfaces.begin_get_effective_route_table` API (which computes and
returns a route table; it does not change anything).

## ⏭ Current status / next action (read this first)

**A two-account credential mixup on 2026-09-07 lost the N01 subscription's
real results, and there is no backup to recover them from.** What happened,
and the fix now in place:

- Two accounts hold different RBAC: `ratnavo.dutta-adm@blackbaud.me` has
  Contributor on N01 only; `ratnavo.dutta@blackbaud.me` has Contributor on
  E01 and Reader everywhere else.
- Run 1 (using only `-adm`) read N01 correctly (71 subnets, real
  COMPLIANT/NON_COMPLIANT verdicts).
- Run 2 (using only the non-adm account) correctly read E01 (16 subnets),
  but the non-adm account also has Reader on N01 — so N01 was *attempted*
  again with the wrong (insufficient) identity, every effective-route call
  403'd, and the old, unconditional `scan_state.record()` **overwrote** N01's
  good Run 1 data with an all-error result. `phase3_state.json` and
  `output/phase3_compliance.xlsx` as they stand right now both reflect the
  overwritten state: N01 shows 80 subnets, 0 COMPLIANT/NON_COMPLIANT, 47
  `EXPECTED_BYPASS`, 30 `ERROR`, 3 `NOT_EVALUATED` — the 71-subnet MEASURED
  result from Run 1 is gone from every file on disk. **I checked for a
  backup/prior copy of `phase3_state.json` or `phase3_compliance.xlsx` and
  found none — only the already-overwritten versions exist.** Per your
  instruction not to reconstruct it from memory, I have not fabricated
  replacement numbers; if you have a backup of either file from before Run
  2, send it and I'll merge it in. Otherwise the only path is a fresh
  re-scan of N01 with the correct (`-adm`) identity.
- **This is now fixed at the root cause, not patched around**: `--credential-map`
  (below) resolves the correct account **per subscription within one run**,
  so N01 and E01 (and everything else) are each read with the right identity
  in a single pass — there is no second run to silently clobber the first.
  A pre-flight probe also now confirms which account can actually read
  routes *before* burning the scan on guaranteed 403s, and a merge-forward
  safeguard in `state.py` means even if a future run somehow used the wrong
  account for a subscription, it would no longer silently overwrite a
  subscription's earlier real MEASURED results — see "Credential routing"
  and "Merge-forward state" below.

**To recover N01 and get a trustworthy full picture, run once with both
identities routed correctly:**

```bash
cp config/credential_map.example.json config/credential_map.json
# edit config/credential_map.json: confirm the "default" account and the N01 override
az login   # sign in as ratnavo.dutta@blackbaud.me (or whichever is not already signed in)
az login   # sign in as ratnavo.dutta-adm@blackbaud.me -- this ADDS to the CLI's signed-in
           # accounts, it does not replace the first login
python run.py --cmdb-file cmdb_ci_cloud_service_account.xlsx \
  --azure-file Subscriptions.csv --credential-map config/credential_map.json \
  --yes --rescan 150ea8a8-4006-49a6-8c11-b7d7c2942e61 --retry-failed-only
```

`--rescan 150ea8a8-...` forces N01 to be re-attempted even though state
currently (incorrectly) shows it as already-scanned; `--retry-failed-only`
additionally picks up every other subscription still sitting on a prior
`PARTIAL`/`ERROR`. Drop `--retry-failed-only` for a fully clean `--rescan-all`
sweep once you're confident every account/RBAC issue is resolved.

## Assumptions made (confirm before relying on results)

Carried over from an earlier round of clarification on this same
engagement, reused here rather than re-asked. Every one is overridable
without editing code:

1. **Secured-hub device: Azure Firewall.** Phase 2 looks for Routing Intent
   first (authoritative), then falls back to an `azureFirewalls` resource
   attached to the hub. If your hub instead uses a third-party NVA, the
   script still tries to resolve one from the Routing Intent next-hop
   resource (`networkVirtualAppliances`), but if that fails you must supply
   its private IP via `--expected-next-hop` or `config/expected_next_hops.json`.
2. **Hub firewall private IP: placeholder.** `config/expected_next_hops.example.json`
   ships with illustrative placeholder values. Phase 2 auto-discovers the
   real firewall private IP(s) per hub at runtime — the config file only
   *adds to* that, for cases Phase 2 can't reach (e.g. Reader-only RBAC on
   the firewall resource itself). Copy the example file, verify/replace the
   IPs, and pass it with `--config`.
3. **Naming conventions: none assumed.** Classification is 100% driven by
   Azure metadata (routing intent, effective routes, resource types, the
   built-in special subnet names) — nothing is inferred from a hub, route
   table, or VNet *name*.

### A specific routing nuance worth verifying

Some secured-hub deployments configure **Routing Intent with only a
`PrivateTraffic` policy** (no `InternetTraffic` policy). In that
configuration, RFC1918-bound traffic is force-tunneled through the firewall,
but internet-bound (0.0.0.0/0) traffic may legitimately take a different
path without that being a Phase 3 violation. This script always evaluates
the `0.0.0.0/0` effective route and records whatever next hop it finds; it
does **not** independently assume `0.0.0.0/0` must equal the firewall IP
unless an `InternetTraffic` Routing Intent policy is also present on that
hub. Check the `vWAN_Baseline` sheet's routing-intent rows for each hub
before treating `NON_COMPLIANT` verdicts for internet-bound egress as
certain.

## Phase 0b: cross-checking against an Azure portal export (optional)

Alongside the CMDB export, you can optionally supply the Azure portal's own
subscription-list export (Subscriptions blade -> Download CSV) via
`--azure-file <path>`. Same path handling as `--cmdb-file` (quotes/whitespace
stripped, `~` and relative paths expanded, Windows/Linux/WSL, up to 3
re-prompts on a bad path) -- except this file is optional, so pressing Enter
at the prompt skips it cleanly instead of erroring.

The file's first line is a literal `SEP=,` line (Excel's separator hint) --
skipped automatically. Expected columns (case-insensitive, any order):
`SUBSCRIPTION NAME`, `SUBSCRIPTION ID`, `MY ROLE`, `CURRENT COST`,
`SECURE SCORE`, `PARENT MANAGEMENT GROUP`, `STATUS`.

This is joined against the CMDB export on subscription ID (both files, no
Azure calls needed) and every CMDB row is tagged:

| File Scope Bucket | Meaning |
|---|---|
| `IN_BOTH` | In both files -- normal case. |
| `ONLY_IN_CMDB` | In ServiceNow but absent from the Azure export -- `ACCESS_OR_TENANT_GAP`. Cannot scan; investigate whether it's a stale CMDB record or a genuinely missing export row. |
| `ONLY_IN_AZURE` | In the Azure export but absent from ServiceNow -- a shadow/unmanaged subscription, reported (not scanned, consistent with "CMDB drives scope"). |

Also derived from the Azure export:
- **`STATUS != Active`** -> excluded from scanning by default (report-only). Pass `--include-disabled` to scan them anyway.
- **Blank CMDB `Organization`** + a populated `PARENT MANAGEMENT GROUP` -> the
  Organization is inferred from the management group and flagged
  `ORG_INFERRED` (the original CMDB value, even if blank, is never
  overwritten -- both are recorded).
- **`--exclude-name-pattern`** (regex, repeatable; default excludes
  `visual studio` / `msdn`-named subscriptions) drops licensing-only
  subscriptions from the scan regardless of which file they came from.

None of this is required -- omit `--azure-file` entirely and the script
behaves exactly as it did without this feature (only `--exclude-name-pattern`
still applies, against the CMDB name alone).

## Credential routing (`--credential-map`): different subscriptions, different identities

Most tenants can run with one identity (`DefaultAzureCredential`, no flag
needed). Use `--credential-map <path>` when different subscriptions need
different accounts' RBAC in the same run (see `config/credential_map.example.json`):

```json
{
  "default": "ratnavo.dutta@blackbaud.me",
  "overrides": { "150ea8a8-4006-49a6-8c11-b7d7c2942e61": "ratnavo.dutta-adm@blackbaud.me" }
}
```

Every account referenced (`default` plus every value in `overrides`) must
already be signed in via a separate `az login` call. Azure CLI keeps every
previously signed-in account in its local token cache — a second `az login`
does not remove the first, it only changes which one `az account show`
reports as "active". This script never relies on "active": it resolves a
token for a specific subscription via `AzureCliCredential(subscription=<id>)`,
which Azure CLI itself maps to whichever signed-in account actually has that
subscription.

**No silent fallback, ever:**
1. At startup, both accounts are verified as signed in (`az account list --all`).
   Missing either one aborts the run before any scanning starts.
2. Every in-scope subscription's assigned account is then cross-checked
   against Azure CLI's own record of which account can see it. Any mismatch
   or an assigned account that can't see the subscription at all aborts the
   run with the specific subscription(s) listed — it never substitutes a
   different identity to "make it work".
3. The resolved routing table (subscription → account) is printed before any
   Azure Resource Manager call is made, and every subnet finding carries an
   **Evaluated By Account** column (Subnets sheet, `phase3_report.json`) —
   a verdict is not interpretable without knowing which identity produced it.

## Pre-flight capability probe (before burning the scan on 403s)

Before the main scan, one cheap effective-route call is made per
subscription (using its assigned account) to test whether
`Microsoft.Network/networkInterfaces/effectiveRouteTable/action` is actually
permitted — **Reader is expected to fail this**, since Reader only grants
`*/read` and `effectiveRouteTable` is an action, not a read. Only
Contributor or a custom role explicitly carrying that action passes.

Results land in the **Capability_Matrix** sheet (subscription, account used,
best-effort RBAC role via `az role assignment list`, CAN_READ_ROUTES /
CANNOT_READ_ROUTES / UNKNOWN, reason) and in `phase3_report.json`'s
`capability_matrix`. Every subnet with a NIC in a `CANNOT_READ_ROUTES`
subscription is marked `NOT_EVALUATED` with a note prefixed
`INSUFFICIENT_ROLE:` **without** attempting the real (guaranteed-403) call —
so a Reader-only subscription with 500 subnets costs one probe call, not 500.
`UNKNOWN` means the subscription has no NIC anywhere to probe with (nothing
to skip either, in that case).

## Merge-forward state: a worse re-attempt never overwrites a better one

`state.py` will not let a subscription's previously MEASURED
(COMPLIANT/NON_COMPLIANT) results be silently replaced by a later attempt
that produced zero MEASURED results and errored out — the exact failure mode
described above under "Current status". If that happens, the prior result is
kept as-is, and the failed attempt is appended to that subscription's
`failed_attempts` list in `phase3_state.json` (timestamp, outcome, account
used, error summary) instead of overwriting `findings`. A console warning
(`MERGE-FORWARD: ...`) is printed whenever this triggers, so it's never
silent. This is a safety net, not a substitute for `--credential-map` --
getting the right identity into the *same* run is what actually prevents the
scenario, rather than papering over a second, wrong-identity run afterward.

## Incremental scanning (only re-evaluate what's changed or failed)

A state file (`--state-file`, default `./phase3_state.json`) tracks, per
subscription: last scan time, outcome (`SUCCESS`/`PARTIAL`/`ERROR`), verdict
counts, and a hash of everything that determines its scan scope (CMDB
Organization/Environment, Azure export status/management group, and the
active `--config`/`--expected-next-hop`/sampling flags).

By default, a run:
1. Skips subscriptions already `SUCCESS` with an unchanged input hash (`ALREADY_EVALUATED`) -- their prior results are still included in this run's output, just not re-fetched from Azure.
2. Always retries subscriptions that previously ended `PARTIAL` or `ERROR` (a 403/429/timeout, etc.), regardless of anything else.
3. Scans anything never attempted before, or whose input hash changed.

State is written the moment each subscription finishes (not at the end of
the run), so an interrupted run resumes cleanly instead of restarting.

```bash
--rescan-all              # ignore state entirely; full re-run
--rescan SUBID1,SUBID2    # force re-scan of specific subscription(s)
--max-age-days 7          # treat a successful scan older than N days as stale
--retry-failed-only       # only (re-)attempt subscriptions with a prior PARTIAL/ERROR outcome
```

## Phase 0: the CMDB export is the authority, not Azure visibility

The script reads a ServiceNow CMDB export (`.xlsx`/`.xls`) first and derives
the scan scope from it — a subscription being visible to your credential is
not enough on its own to be in scope, and a subscription being in the CMDB
export doesn't guarantee the credential can see it either. Both directions
are reconciled and reported (see "Reading the output" below).

Expected columns (detected by header name, case-insensitive, in any order —
column position doesn't matter):

| Column | Used as |
|---|---|
| `Name` | Friendly subscription name, carried through all output |
| `Account Id` | Azure subscription ID (GUID) — the key everything is driven from |
| `Organization` | Owning org (e.g. RDO, IT, Cybersecurity) — blank rows flagged as `OWNERSHIP_UNKNOWN` |
| `Environment` | Production/Development/Test/Training — blank rows also flagged |
| `Supported by` / `Owned by` | Ownership contacts, carried through |
| `Install Status` | Filtered to `Installed` by default (`--filter-install-status`) |
| `Datacenter Type` | Informational |

Rows with a missing or malformed `Account Id` (not a GUID) go to
`Invalid_Rows` — never silently dropped. Duplicate subscription IDs keep the
first occurrence and record the rest as duplicates in the same sheet.

### Supplying the file path (Windows or Linux, no platform-specific thinking required)

```bash
python run.py --cmdb-file "C:\Users\me\Downloads\cmdb_ci_cloud_service_account.xlsx"
python run.py --cmdb-file /home/me/exports/cmdb.xlsx
python run.py --cmdb-file ~/exports/cmdb.xlsx
python run.py                       # prompts interactively if --cmdb-file is omitted
```

The path resolver handles, transparently:

- Windows backslash paths with drive letters, and POSIX paths
- Surrounding quotes (Windows Explorer's "Copy as path" adds double quotes) — stripped
- Leading/trailing whitespace — stripped
- `~` expansion and relative paths
- **WSL**: if you paste a Windows-style path (`C:\...`) while the script
  itself is running under Linux, it retries as `/mnt/c/...` before failing

If the path is missing, wrong type, unreadable, or not `.xlsx`/`.xls`, you
get a clear message and are re-prompted (up to 3 attempts) rather than a
traceback.

### Filters and confirmation

```bash
--filter-org RDO "IT - VSAS"          # only these Organization values
--filter-environment Production        # only these Environment values
--filter-install-status Installed      # default; pass '' to disable
--yes                                   # skip the confirmation prompt (required for CI)
```

The script prints a scope summary (total rows, valid IDs, duplicates,
invalid rows, breakdown by Organization/Environment) and asks you to
confirm before making any Azure calls, unless `--yes` is passed.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate    # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
# Only if your export is legacy .xls rather than .xlsx:
# pip install xlrd
az login                     # or configure a service principal / managed identity for CI
```

### Required RBAC

Assign at minimum **Reader** (or your custom asset-configuration-reader
role) at the management-group or subscription scope covering everything
your CMDB export references. Specifically the identity needs read access to:

- `Microsoft.Network/virtualWans`, `virtualHubs`, `hubRouteTables`,
  `hubVirtualNetworkConnections`, `routingIntent`
- `Microsoft.Network/azureFirewalls`, `networkVirtualAppliances`
- `Microsoft.Network/expressRouteGateways`, `vpnGateways`, `p2sVpnGateways`
- `Microsoft.Network/virtualNetworks` (including subnets, peerings)
- `Microsoft.Network/networkInterfaces/effectiveRouteTable/action` — the
  permission behind `begin_get_effective_route_table`. Reader normally
  includes it; some locked-down custom roles omit action-only permissions.
  If missing, affected subnets show verdict `ERROR` with the 403 recorded in
  the `Errors` sheet — the run continues.
- `Microsoft.Resources/subscriptions/resourceGroups` (Resource Graph query scope)

If credentials are missing or entirely lack access, the script fails fast at
startup with an actionable message. A 403 on a *specific* call is instead
caught, recorded against that scope in the `Errors` sheet, and the run
continues.

## Running it

```bash
# See the CMDB-resolved scope only, no Azure calls at all
python run.py --cmdb-file cmdb_export.xlsx --dry-run

# Full run
cp config/expected_next_hops.example.json config/expected_next_hops.json
# ... edit config/expected_next_hops.json with your real values ...
python run.py --cmdb-file cmdb_export.xlsx --config config/expected_next_hops.json --verbose

# Non-interactive (CI), production RDO subscriptions only
python run.py --cmdb-file cmdb_export.xlsx --filter-org RDO --filter-environment Production --yes

# Resume a previous partial run (reuses cached effective-route results)
python run.py --cmdb-file cmdb_export.xlsx --config config/expected_next_hops.json --resume

# Cross-check against an Azure portal subscription export too
python run.py --cmdb-file cmdb_export.xlsx --azure-file Subscriptions.csv --yes

# Incremental re-run: only (re-)attempt what's new or previously failed
python run.py --cmdb-file cmdb_export.xlsx --azure-file Subscriptions.csv --yes
# ... a week later, re-run the same command; ALREADY_EVALUATED subscriptions
# are skipped automatically. Force specific behavior instead:
python run.py --cmdb-file cmdb_export.xlsx --yes --retry-failed-only
python run.py --cmdb-file cmdb_export.xlsx --yes --rescan-all
```

Run `python run.py --help` for the full flag reference; every flag has a
one-line description there. Everything after Phase 0 works identically on
Windows and Linux — the OS-specific handling is isolated to the CMDB file
path resolution.

## Output

Written to `--output-dir` (default `./output`). **Every output filename/folder
is stamped with this run's start date/time (`YYYYMMDD_HHMMSS`) by default**,
so re-running the script never overwrites a previous run's files:

```
output/
├── phase3_compliance_20260907_143022.xlsx
├── phase3_compliance_20260907_143022.json
├── phase3_report_20260907_143022.json
├── phase3_report_20260907_143022.md
├── csv_20260907_143022/
│   └── subnets.csv, offending_routes.csv, ...
└── .run_cache.json          # NOT timestamped -- persistent --resume cache
```

Pass `--no-timestamp-outputs` to go back to fixed filenames
(`phase3_compliance.xlsx`, `csv/`, `phase3_report.json`, etc.) if something
downstream (a dashboard, a scheduled task) always reads from a known path —
in that mode, each run overwrites the previous one's files, same as before.
`phase3_state.json` (`--state-file`) and the effective-route cache
(`--cache-file`) are never timestamped either way, since they're persistent
state the incremental scanner reads back on the next run, not a report.

- `phase3_compliance.xlsx` — the primary deliverable, with sheets:
  - **Summary** — counts/percentages by verdict, per-subscription and
    per-Organization breakdown, total remaining Phase 3 work, and the CMDB
    reconciliation counts.
  - **Subscription_Scope** — every CMDB row plus its reconciliation bucket
    (`IN_BOTH` / `IN_CMDB_NOT_VISIBLE`), plus every `VISIBLE_NOT_IN_CMDB`
    shadow subscription appended at the bottom.
  - **Subnets** — one row per subnet evaluated (with Organization/Environment
    and **Evaluated By Account** carried through), verdict color-coded.
  - **Offending_Routes** — one row per bypassing route, for remediation.
  - **vWAN_Baseline** — the hub topology and compliant next hops used.
  - **Capability_Matrix** — per-subscription pre-flight probe result (account
    used, best-effort role, CAN_READ_ROUTES/CANNOT_READ_ROUTES/UNKNOWN).
  - **Ownership_Gaps** — CMDB rows with a blank Organization or Environment.
  - **Invalid_Rows** / **Invalid_Azure_Rows** — rows with a missing/malformed subscription ID from the CMDB / Azure export respectively.
  - **Errors** — every failed call, with scope, operation, status code, and reason.
- `csv/*.csv` — the same data as CSV, mirrored 1:1 from the Excel data.
- `phase3_compliance.json` — the same data, for a dashboard.
- `phase3_report.json` / `phase3_report.md` — a single, self-contained report
  meant to be pasted into or uploaded to an AI assistant (e.g. Copilot) for
  follow-up analysis: run metadata (inputs, identity, flags, runtime),
  scope/coverage reconciliation with reasons for anything not evaluated,
  the vWAN baseline (flagging config gaps), findings nested
  subscription -> VNet -> subnet, ownership (with inference source),
  a summary rollup with **explicit percentage denominators** (`NOT_EVALUATED`
  is never counted as compliant, and every percentage states whether it's a
  share of *all* subnets or only *evaluated* ones), and an `open_questions`
  list for anything the script couldn't resolve on its own.

### Reconciliation buckets (Subscription_Scope sheet + console)

Two independent reconciliations run, each answering a different question:

**CMDB vs. the live credential** (always runs, needs Azure auth):

| Bucket | Meaning |
|---|---|
| `IN_BOTH` | In the CMDB export and visible to the credential. **Only these are scanned.** |
| `IN_CMDB_NOT_VISIBLE` | CMDB says it exists; the credential can't see it — missing RBAC, or a stale/decommissioned CMDB record. Investigate, don't ignore. |
| `VISIBLE_NOT_IN_CMDB` | Exists in Azure but absent from the CMDB export — an unmanaged/shadow subscription. This is a Phase 3 finding in its own right. |

**CMDB vs. the (optional) Azure portal export** (file-only, see Phase 0b above):
`IN_BOTH` / `ONLY_IN_CMDB` (`ACCESS_OR_TENANT_GAP`) / `ONLY_IN_AZURE`, plus
`DISABLED` and `ORG_INFERRED` flags — all carried in the same
Subscription_Scope sheet's extra columns.

### Reading the subnet verdicts

| Verdict | Meaning |
|---|---|
| `COMPLIANT` | Effective 0.0.0.0/0 route's next hop matches the compliant baseline (measured from a real NIC). |
| `NON_COMPLIANT` | Effective route bypasses the hub. Every offending route is listed with prefix, next-hop type/IP, and the route table + route name that introduced it. |
| `EXPECTED_BYPASS` | Infra subnet (`GatewaySubnet`, `AzureFirewallSubnet`, `AzureBastionSubnet`, `RouteServerSubnet`, `AzureFirewallManagementSubnet`), or manually flagged via config. Bypass by design. |
| `NOT_EVALUATED` | No NIC in the subnet to read effective routes from, **or** the pre-flight capability probe already determined the assigned account can't read routes in this subscription (`INSUFFICIENT_ROLE` in Notes). **Not** the same as compliant — the Notes column carries whatever weaker `INFERRED` evidence exists (UDR presence, hub peering, hub connection). |
| `ERROR` | The effective-route call (or a 403) failed; see the Errors sheet for the reason. |

## Worked example console output

```
=== Phase 0: CMDB Scope Summary ===
  Total data rows read:      113
  Valid subscription IDs:    108
  Duplicate rows:            2
  Invalid rows:              3

  By Organization:
    (blank)              14
    Cybersecurity        9
    IT                   22
    IT - VSAS            6
    RDO                  57

  By Environment:
    (blank)              8
    Development          31
    Production           61
    Test                 6
    Training             2

  OWNERSHIP_UNKNOWN (blank Organization/Environment): 14 row(s)

Proceed with this scope? [y/N]: y

=== Phase 2: vWAN Transit Hub Baseline ===
  [BB-N01-Prod] n01-eus2-vwan-1/n01-eus2-vhub-1 (eastus2, 10.193.0.0/23) - firewall: AzureFirewall 'AzureFirewall_n01-eus2-vhub-1' -> 10.193.0.4 - connections: 14 - gateways: 1
  [BB-N01-Prod] n01-eus2-vwan-1/n01-cus-vhub-1 (centralus, 10.193.8.0/23) - firewall: AzureFirewall 'AzureFirewall_n01-cus-vhub-1' -> 10.193.8.4 - connections: 6 - gateways: 0
  [BB-E01-NonProd] e01-eus2-vwan-1/e01-eus2-vhub-1 (eastus2, 10.194.0.0/23) - firewall: AzureFirewall 'AzureFirewall_e01-eus2-vhub-1' -> 10.194.0.4 - connections: 3 - gateways: 0

  Compliant next-hop IPs (3): 10.193.0.4, 10.193.8.4, 10.194.0.4

=== Phase 3 Compliance Discovery: Console Summary ===
Total subnets evaluated: 812
  COMPLIANT        601  (74.0%)
  NON_COMPLIANT     58  (7.1%)
  EXPECTED_BYPASS   22  (2.7%)
  NOT_EVALUATED    119  (14.7%)
  ERROR             12  (1.5%)

Remaining Phase 3 work (NON_COMPLIANT + NOT_EVALUATED): 177

CMDB reconciliation: IN_BOTH=105  IN_CMDB_NOT_VISIBLE=3  VISIBLE_NOT_IN_CMDB=2
OWNERSHIP_UNKNOWN (blank Organization/Environment): 14

Shadow subscriptions (visible in Azure, absent from CMDB):
  - BB-Sandbox-Temp (a1b2c3d4-1111-2222-3333-444455556666)
  - BB-DevTest-Legacy (f6e5d4c3-9999-8888-7777-666655554444)

Outputs written to: /path/to/output
Elapsed: 231.7s
```

## Engineering notes

- **Speed:** the broad VNet/subnet inventory sweep uses Azure Resource Graph
  (one paged KQL query across every IN_BOTH subscription) rather than
  walking resource-group → VNet → subnet with the management SDK. Effective
  routes are not available via Resource Graph, so that step still uses
  `azure-mgmt-network` per NIC, parallelized with a bounded thread pool
  (`--max-workers`, default 8) and cached per NIC (`--resume`/`--cache-file`).
- **Throttling:** every ARM call goes through an exponential-backoff retry
  wrapper that honors the `Retry-After` header on HTTP 429, and never
  retries a 403 (that's recorded as a finding instead).
- **Idempotent:** safe to re-run at any time; it only reads.

## Project layout

```
vwan-phase3-compliance-discovery/
├── README.md
├── requirements.txt
├── run.py                          # entry point: python run.py --help
├── config/
│   ├── expected_next_hops.example.json
│   └── credential_map.example.json
└── vwan_compliance/
    ├── __init__.py
    ├── main.py                     # CLI wiring, Phase 0 -> Phase 4
    ├── path_utils.py               # shared file-path resolution (CMDB + Azure export)
    ├── cmdb.py                     # Phase 0: CMDB xlsx/xls ingestion
    ├── azure_export.py             # Phase 0b: optional Azure portal export (csv) ingestion
    ├── reconcile.py                # Phase 0.5: CMDB vs. Azure export file-level reconciliation
    ├── auth.py                     # DefaultAzureCredential + fail-fast checks + identity description
    ├── credential_router.py        # --credential-map: per-subscription credential routing, no silent fallback
    ├── capability_probe.py         # pre-flight effectiveRouteTable/action probe per subscription
    ├── models.py                   # shared dataclasses / verdict + reconciliation + capability enums
    ├── retry.py                    # exponential backoff for 429/5xx
    ├── logging_config.py           # structured logging
    ├── cache.py                    # --resume / per-NIC cache
    ├── state.py                    # incremental scan state (--state-file) + merge-forward safeguard
    ├── serialize.py                # dict<->dataclass round-trip for state replay
    ├── baseline.py                 # Phase 2: vWAN/vHub topology + baseline
    ├── inventory.py                # Phase 1 live reconciliation + Phase 3 Resource Graph sweep (credential-routed)
    ├── compliance.py               # Phase 4: effective routes + verdict engine (credential-routed)
    ├── output.py                   # Excel/CSV/JSON/console output
    └── report.py                   # phase3_report.json/.md (AI-analysis report)
```

## What I could not verify in this environment

This script was written and syntax-checked (`python -m py_compile` on every
module) and the Phase 0 CMDB parser (path resolution, header detection,
GUID validation, dedup, filters, ownership-gap detection) was unit-tested
against a synthetic .xlsx in this sandbox. The Azure-facing phases (auth,
baseline discovery, Resource Graph sweep, effective routes) could **not** be
run against a live tenant here — this sandbox has no outbound access to
install `azure-*` SDKs or reach Azure. Before your first production run: `pip
install -r requirements.txt`, `az login`, then `python run.py --cmdb-file
<your export> --dry-run` followed by a small `--filter-org` run to confirm
the SDK call shapes match your `azure-mgmt-network` version.
