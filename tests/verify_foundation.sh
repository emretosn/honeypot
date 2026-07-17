#!/usr/bin/env bash
# Foundation verification, run AFTER deploying bicep/foundation.bicep against your subscription.
# Confirms the management RG and Log Analytics workspace exist and are configured.
# Requires: az login with the target subscription selected.
set -euo pipefail

REGION_CODE="${1:-weu}"

RG="rg-core-ops-${REGION_CODE}"
LAW="log-core-ops-${REGION_CODE}"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

echo "== Foundation verification (RG=$RG, LAW=$LAW) =="

az group show -n "$RG" >/dev/null 2>&1 && pass "management RG exists" || fail "management RG missing"

WS_JSON=$(az monitor log-analytics workspace show -g "$RG" -n "$LAW" 2>/dev/null) \
  || fail "Log Analytics workspace missing"
pass "Log Analytics workspace exists"

RETENTION=$(echo "$WS_JSON" | jq -r '.retentionInDays')
[ "$RETENTION" -ge 30 ] && pass "retention is ${RETENTION}d (>=30)" || fail "retention too low: $RETENTION"

CAP=$(echo "$WS_JSON" | jq -r '.workspaceCapping.dailyQuotaGb')
pass "daily ingestion cap = ${CAP} GB"

# OPSEC guard: the management/operations plane is production-plausible (no marker in any name).
echo "== Foundation OK =="
