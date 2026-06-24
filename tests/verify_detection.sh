#!/usr/bin/env bash
# Detection verification — run AFTER deploying bicep/detection.bicep.
# Confirms Sentinel is onboarded and the honeypot analytics rules exist and are enabled.
# Requires: az login; jq; the Sentinel CLI surface via `az rest`.
set -euo pipefail

MGMT_RG="${1:-rg-hp-dev-weu-mgmt}"
WORKSPACE="${2:-log-hp-dev-weu}"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$MGMT_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights"

echo "== Detection verification (workspace=$WORKSPACE) =="

# 1. Sentinel onboarded.
az rest --method get --url "$BASE/onboardingStates/default?api-version=2024-09-01" >/dev/null 2>&1 \
  && pass "Microsoft Sentinel is onboarded" \
  || fail "Sentinel onboarding state 'default' not found"

# 2. Identity rules must always be present and enabled (the load-bearing detections).
RULES_JSON=$(az rest --method get --url "$BASE/alertRules?api-version=2024-09-01" 2>/dev/null)
EXPECTED=(
  "password reset on lure identity"
  "role assignment or PIM activation on lure identity"
  "sign-in as lure identity from non-allowlisted source"
)
for name in "${EXPECTED[@]}"; do
  MATCH=$(echo "$RULES_JSON" | jq -r --arg n "$name" '.value[] | select(.properties.displayName | test($n; "i")) | {enabled: .properties.enabled, sev: .properties.severity}' 2>/dev/null)
  if [ -n "$MATCH" ]; then
    EN=$(echo "$MATCH" | jq -r '.enabled')
    [ "$EN" = "true" ] && pass "rule present and enabled: $name" || fail "rule present but DISABLED: $name"
  else
    fail "expected rule missing: $name"
  fi
done

# Resource rules are optional (only present when enableResourceRules=true, after the network
# module is deployed). Report their status without failing.
for name in "decoy Key Vault secret accessed" "decoy storage accessed"; do
  if echo "$RULES_JSON" | jq -e --arg n "$name" '.value[] | select(.properties.displayName | test($n; "i"))' >/dev/null 2>&1; then
    pass "resource rule present: $name"
  else
    echo "NOTE: resource rule not deployed: $name (expected until the network module + enableResourceRules)"
  fi
done

# 3. Sign-in rule should reference an allowlist exclusion construct (defense-in-depth check).
echo "$RULES_JSON" | jq -r '.value[] | select(.properties.displayName | test("sign-in as lure"; "i")) | .properties.query' \
  | grep -q '!in' && pass "sign-in rule contains an allowlist exclusion" \
  || echo "NOTE: sign-in rule has no allowlist exclusion (ok if no agent configured)"

echo "== Detection OK =="
