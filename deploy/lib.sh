#!/usr/bin/env bash
# Shared helpers for the deploy/*.sh scripts. Sourced, not run directly.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEPLOY_DIR/.." && pwd)"

CONFIG_FILE="${CONFIG_FILE:-$DEPLOY_DIR/config.env}"

info() { echo "==> $1"; }
ok()   { echo "  [OK] $1"; }
die()  { echo "ERROR: $1" >&2; exit 1; }

load_config() {
  [ -f "$CONFIG_FILE" ] || die "missing $CONFIG_FILE, copy deploy/config.env.example to it and fill it in."
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"

  : "${ENVN:=dev}"; : "${REGION:=westeurope}"; : "${REGION_CODE:=weu}"
  # Management/operations plane is production-plausible with NO honeypot marker in any name: it
  # co-hosts Log Analytics, Sentinel AND the SOAR playbooks, whose managed identities leak the
  # resource-id path (including the RG name) directory-wide. Ownership lives in tags + inventory.
  MGMT_RG="rg-core-ops-${REGION_CODE}"
  WORKSPACE="log-core-ops-${REGION_CODE}"
}

require_login() {
  az account show >/dev/null 2>&1 || die "not logged in, run 'az login' first."
  if [ -n "${SUBSCRIPTION_ID:-}" ]; then
    az account set --subscription "$SUBSCRIPTION_ID"
  fi
  CURRENT_SUB="$(az account show --query id -o tsv)"
  info "Subscription: $CURRENT_SUB"
}

# True (exit 0) if a Log Analytics table exists in the given workspace GUID. A table only
# resolves once it has ingested at least once, so this doubles as a "telemetry present" check.
# Used to gate detection rules whose KQL Sentinel validates at rule-creation time.
# Hard-bounded with `timeout`: a query for a not-yet-ingested table can hang indefinitely, so a
# timeout (exit 124) is treated the same as "table absent", the caller then skips those rules.
workspace_table_exists() {
  local ws_guid="$1" table="$2"
  timeout 30 az monitor log-analytics query -w "$ws_guid" --analytics-query "${table} | limit 1" -o none >/dev/null 2>&1
}

# True only if the table has actually ingested at least one row in the given window (default 30d).
# Use for tables whose schema can exist while empty (e.g. AzureActivity before the Activity Log
# export is wired), where table-existence alone would wrongly enable a rule against no data.
workspace_table_has_rows() {
  local ws_guid="$1" table="$2" window="${3:-30d}"
  local n
  n=$(timeout 40 az monitor log-analytics query -w "$ws_guid" \
    --analytics-query "${table} | where TimeGenerated > ago(${window}) | count" \
    --query "[0].Count" -o tsv 2>/dev/null || echo "")
  [ -n "$n" ] && [ "$n" != "0" ]
}
