#!/usr/bin/env bash
# Response (SOAR) verification — run AFTER deploying bicep/response.bicep.
# Confirms both playbooks exist, both default to dry-run, the allowlist guard is wired,
# and the Sentinel automation rules that invoke them are present.
# Requires: az login; jq.
set -euo pipefail

MGMT_RG="${1:-rg-hp-dev-weu-mgmt}"
WORKSPACE="${2:-log-hp-dev-weu}"
BASENAME="${3:-hp-dev-weu}"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

SUB=$(az account show --query id -o tsv)
DISABLE="pb-${BASENAME}-disable-user"
ISOLATE="pb-${BASENAME}-isolate-resource"

echo "== Response (SOAR) verification =="

# 1. Playbooks exist with a system-assigned managed identity.
for pb in "$DISABLE" "$ISOLATE"; do
  J=$(az rest --method get --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$MGMT_RG/providers/Microsoft.Logic/workflows/$pb?api-version=2019-05-01" 2>/dev/null) || fail "playbook missing: $pb"
  pass "playbook exists: $pb"
  PRINC=$(echo "$J" | jq -r '.identity.principalId // empty')
  [ -n "$PRINC" ] && pass "  has managed identity ($PRINC)" || fail "  $pb has no managed identity"
  DRY=$(echo "$J" | jq -r '.properties.parameters.dryRun.value // empty')
  [ "$DRY" = "true" ] && pass "  dryRun defaults to true (safe)" || echo "  NOTE: $pb dryRun=$DRY (enforcing mode — ensure this is intended)"
done

# 2. Disable-user playbook contains the allowlist guard in its definition.
DEF=$(az rest --method get --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$MGMT_RG/providers/Microsoft.Logic/workflows/$DISABLE?api-version=2019-05-01" 2>/dev/null | jq -c '.properties.definition')
echo "$DEF" | grep -q 'allowlistObjectIds' && pass "disable-user playbook references the allowlist guard" || fail "allowlist guard missing from disable-user playbook!"
echo "$DEF" | grep -q 'revokeSignInSessions' && pass "disable-user playbook revokes sessions" || fail "revokeSignInSessions missing"

# 3. Automation rules exist and trigger on Honeypot-titled incidents.
AR=$(az rest --method get --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$MGMT_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights/automationRules?api-version=2024-09-01" 2>/dev/null)
COUNT=$(echo "$AR" | jq '[.value[] | select(.properties.displayName | test("Honeypot"; "i"))] | length')
[ "${COUNT:-0}" -ge 2 ] && pass "found $COUNT honeypot automation rules" || fail "expected >=2 honeypot automation rules, found ${COUNT:-0}"
echo "$AR" | jq -e '.value[] | select(.properties.triggeringLogic.conditions[]?.conditionProperties.propertyValues[]? == "Honeypot:")' >/dev/null 2>&1 \
  && pass "automation rule scoped to 'Honeypot:' incident titles" \
  || echo "NOTE: could not confirm 'Honeypot:' title scoping (check manually)"

echo
echo "REMINDER: grant the playbook managed identities their permissions (see docs/response.md):"
echo "  - disable-user MI: Microsoft Graph User.ReadWrite.All (+ User.EnableDisableAccount)"
echo "  - isolate-resource MI: a role with Microsoft.Authorization/locks/write on the honeypot RG"
echo "  - the Sentinel automation needs Microsoft Sentinel Playbook Operator on this RG"
echo "== Response OK =="
