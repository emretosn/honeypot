#!/usr/bin/env bash
# Identity honeypot verification — run AFTER `terraform apply` in terraform/identity.
# Asserts the deception EXISTS and, more importantly, that it is CONTAINED:
#   - the lure holds the AU-scoped built-in role (privilege exists)
#   - the lure has NO Azure RBAC over any subscription (powerless over prod)
#   - the role assignment is scoped to the decoy AU, not tenant-wide
#   - decoy apps have NO app-role/Graph grants
#   - no honeypot marker leaks into any attacker-visible name
# Requires: az login; jq. Reads identifiers from inventory/decoy-inventory.json.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INV="$ROOT/inventory/decoy-inventory.json"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

[ -f "$INV" ] || fail "inventory not found — run tests/sync_inventory.sh first"

LURE_ID=$(jq -r '.identity.lure.objectId' "$INV")
LURE_UPN=$(jq -r '.identity.lure.upn' "$INV")
AU_ID=$(jq -r '.identity.decoyAdministrativeUnitId' "$INV")
ROLE_ID=$(jq -r '.identity.lureRoleDefinitionId' "$INV")
GROUP_ID=$(jq -r '.identity.decoyGroupIds[0]' "$INV")
[ -n "$LURE_ID" ] && [ "$LURE_ID" != "null" ] || fail "lure object ID missing from inventory"

echo "== Identity honeypot verification (lure=$LURE_UPN) =="

# 1. Lure exists and is enabled.
az ad user show --id "$LURE_ID" >/dev/null 2>&1 && pass "lure user exists" || fail "lure user missing"

# 2. Lure is a member of the decoy AU (containment boundary).
IN_AU=$(az rest --method get \
  --url "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$AU_ID/members?\$select=id" \
  2>/dev/null | jq -r --arg id "$LURE_ID" '[.value[]?.id] | index($id) // empty')
[ -n "$IN_AU" ] && pass "lure is a member of the decoy AU" || fail "lure not in decoy AU"

# 3. Lure holds the role, AU-SCOPED (not tenant-wide). This is the core containment check.
ASSIGN=$(az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$LURE_ID'" \
  2>/dev/null | jq -c '.value[]? | {roleDefinitionId, directoryScopeId}')
echo "$ASSIGN" | grep -q "/administrativeUnits/$AU_ID" \
  && pass "role assignment is AU-scoped to the decoy AU" \
  || echo "NOTE: no ACTIVE AU-scoped assignment found (expected if enable_pim=true — check eligible assignments)"
echo "$ASSIGN" | grep -q '"directoryScopeId":"/"' \
  && fail "lure has a TENANT-WIDE role assignment — containment broken!" \
  || pass "no tenant-wide role assignment on the lure"

# 4. Lure has NO Azure RBAC over any subscription (powerless over prod).
RBAC_COUNT=$(az role assignment list --assignee "$LURE_ID" --all -o json 2>/dev/null | jq 'length')
[ "${RBAC_COUNT:-0}" -eq 0 ] && pass "lure has no Azure RBAC role assignments" \
  || fail "lure has $RBAC_COUNT Azure RBAC assignment(s) — must be zero"

# 5. Decoy apps have no app-role assignments / Graph grants.
for APP_ID in $(jq -r '.identity.decoyAppIds[]' "$INV"); do
  SP=$(az ad sp list --filter "appId eq '$(az ad app show --id "$APP_ID" --query appId -o tsv 2>/dev/null)'" -o json 2>/dev/null | jq -r '.[0].id // empty')
  if [ -n "$SP" ]; then
    GRANTS=$(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP/appRoleAssignments" 2>/dev/null | jq '.value | length')
    [ "${GRANTS:-0}" -eq 0 ] && pass "decoy app $APP_ID has no app-role grants" || fail "decoy app $APP_ID has $GRANTS grant(s)"
  else
    pass "decoy app $APP_ID has no service principal (no grants possible)"
  fi
done

# 6. Reachable edge: the decoy SP exists, the foothold can take it over, the SP has
#    NO consented Graph app roles (the god-mode request is unconsented), and its Azure RBAC is
#    scoped ONLY to the decoy RG/KV — the contained payoff.
REACH_APP_ID=$(jq -r '.identity.reachableApp.appId // ""' "$INV")
REACH_SP_ID=$(jq -r '.identity.reachableApp.spObjectId // ""' "$INV")
if [ -n "$REACH_APP_ID" ] && [ -n "$REACH_SP_ID" ]; then
  az ad sp show --id "$REACH_SP_ID" >/dev/null 2>&1 && pass "reachable decoy SP exists" || fail "reachable decoy SP missing"
  # No CONSENTED Graph app roles (god-mode is requested, never granted).
  RGRANTS=$(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$REACH_SP_ID/appRoleAssignments" 2>/dev/null | jq '.value | length')
  [ "${RGRANTS:-0}" -eq 0 ] && pass "reachable SP has ZERO consented Graph app roles (god-mode unconsented)" \
    || fail "reachable SP has $RGRANTS consented app-role grant(s) — that is a real backdoor, not a decoy!"
  # Azure RBAC, if present, must be scoped ONLY to the decoy RG/KV (never a subscription/MG).
  RG_ID=$(jq -r '.network.honeypotResourceGroupId // ""' "$INV")
  BADSCOPE=$(az role assignment list --assignee "$REACH_SP_ID" --all -o json 2>/dev/null \
    | jq -r --arg rg "$RG_ID" '[.[] | select((.scope|startswith($rg))|not)] | length')
  if [ -n "$RG_ID" ]; then
    [ "${BADSCOPE:-0}" -eq 0 ] && pass "reachable SP Azure RBAC scoped ONLY to the decoy RG/KV (contained)" \
      || fail "reachable SP has $BADSCOPE RBAC assignment(s) OUTSIDE the decoy RG — containment broken!"
  else
    echo "NOTE: network not in inventory yet — reachable-edge RBAC not asserted (deploy network + re-apply identity)."
  fi
  # Foothold ownership (the takeover primitive) — informational.
  OWN=$(az ad app owner list --id "$REACH_APP_ID" -o json 2>/dev/null | jq 'length')
  [ "${OWN:-0}" -ge 1 ] && pass "reachable app has $OWN owner(s) (foothold takeover primitive)" \
    || echo "NOTE: reachable app has no owners (set foothold_principal_object_id to seed the edge)."
else
  echo "NOTE: reachable edge not in inventory — skipping its checks."
fi

# 7. OPSEC: no honeypot marker in attacker-visible names.
NAMES=$(az ad user show --id "$LURE_ID" --query '{u:userPrincipalName,d:displayName}' -o tsv; \
        az ad group show --group "$GROUP_ID" --query displayName -o tsv 2>/dev/null)
echo "$NAMES" | grep -iqE 'honey|decoy|\bhp\b|trap|fake' \
  && fail "honeypot marker leaked into an attacker-visible name!" \
  || pass "no honeypot marker in attacker-visible names"

echo "== Identity honeypot OK =="
