#!/usr/bin/env bash
# Identity honeypot verification, run AFTER `terraform apply` in terraform/identity.
# Asserts the two contained attacker-reachable paths EXIST and are CONTAINED:
#   Path A, reachable app/SP: the foothold OWNS the app (takeover primitive), the app requests
#            god-mode Graph but it is NEVER consented (SP has zero real Graph power), the app carries
#            pre-seeded credentials (realism), and the SP's Azure RBAC is scoped ONLY to the decoy RG/KV.
#   Path B, emergency-access decoy: a POWERLESS account (no directory role, no RBAC) alone in its
#            scoping AU, so the foothold's AU-scoped Privileged Authentication Administrator can reset
#            nothing else.
#   Plus: no honeypot marker leaks into any attacker-visible name.
# Requires: az login; jq. Reads identifiers from inventory/decoy-inventory.json.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INV="$ROOT/inventory/decoy-inventory.json"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

[ -f "$INV" ] || fail "inventory not found, run tests/sync_inventory.sh first"

echo "== Identity honeypot verification =="

# --- Path A. Reachable edge: the decoy app/SP the foothold owns and can take over. ---
REACH_APP_ID=$(jq -r '.identity.reachableApp.appId // ""' "$INV")
REACH_SP_ID=$(jq -r '.identity.reachableApp.spObjectId // ""' "$INV")
if [ -n "$REACH_APP_ID" ] && [ -n "$REACH_SP_ID" ]; then
  az ad sp show --id "$REACH_SP_ID" >/dev/null 2>&1 && pass "reachable decoy SP exists" || fail "reachable decoy SP missing"

  # The app REQUESTS god-mode (RoleManagement.ReadWrite.Directory), the enticing hook.
  REQ=$(az ad app show --id "$REACH_APP_ID" --query "requiredResourceAccess[?resourceAppId=='00000003-0000-0000-c000-000000000000'].resourceAccess[?id=='9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'] | [0]" -o json 2>/dev/null)
  [ -n "$REQ" ] && [ "$REQ" != "null" ] && pass "reachable app REQUESTS god-mode Graph (RoleManagement.ReadWrite.Directory)" \
    || fail "reachable app does not request the god-mode permission, the enticement hook is missing"

  # ...but it is NEVER consented: the SP must hold ZERO consented Graph app roles.
  RGRANTS=$(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$REACH_SP_ID/appRoleAssignments" 2>/dev/null | jq '.value | length')
  [ "${RGRANTS:-0}" -eq 0 ] && pass "reachable SP has ZERO consented Graph app roles (god-mode unconsented)" \
    || fail "reachable SP has $RGRANTS consented app-role grant(s), that is a real backdoor, not a decoy!"

  # Pre-seeded credentials (realism): the app should carry at least one secret and/or certificate.
  CREDS=$(az ad app show --id "$REACH_APP_ID" --query "length(passwordCredentials) + length(keyCredentials)" -o tsv 2>/dev/null || echo 0)
  [ "${CREDS:-0}" -ge 1 ] && pass "reachable app carries $CREDS pre-seeded credential(s) (looks like a real automation app)" \
    || echo "NOTE: reachable app has no pre-seeded credentials (enumeration will look bare)."

  # Azure RBAC, if present, must be scoped ONLY to the decoy RG/KV (never a subscription/MG).
  RG_ID=$(jq -r '.network.honeypotResourceGroupId // ""' "$INV")
  if [ -n "$RG_ID" ]; then
    BADSCOPE=$(az role assignment list --assignee "$REACH_SP_ID" --all -o json 2>/dev/null \
      | jq -r --arg rg "$RG_ID" '[.[] | select((.scope|startswith($rg))|not)] | length')
    [ "${BADSCOPE:-0}" -eq 0 ] && pass "reachable SP Azure RBAC scoped ONLY to the decoy RG/KV (contained)" \
      || fail "reachable SP has $BADSCOPE RBAC assignment(s) OUTSIDE the decoy RG, containment broken!"
    RG_COUNT=$(az role assignment list --assignee "$REACH_SP_ID" --all -o json 2>/dev/null | jq 'length')
    [ "${RG_COUNT:-0}" -ge 1 ] && pass "reachable SP has $RG_COUNT RBAC assignment(s) on the decoy RG/KV (KV path wired)" \
      || echo "NOTE: reachable SP has NO Azure RBAC yet, run deploy/edge.sh to wire the Key Vault path."
  else
    echo "NOTE: network not in inventory yet, reachable-edge RBAC not asserted (deploy network + run edge.sh)."
  fi

  # Foothold ownership (the takeover primitive), informational.
  OWN=$(az ad app owner list --id "$REACH_APP_ID" -o json 2>/dev/null | jq 'length')
  [ "${OWN:-0}" -ge 1 ] && pass "reachable app has $OWN owner(s) (foothold takeover primitive)" \
    || echo "NOTE: reachable app has no owners (set foothold_principal_object_id to seed the edge)."
else
  echo "NOTE: reachable edge not in inventory, skipping its checks."
fi

# --- Path B. Emergency-access decoy (standalone reset-me path). ---
EMERGENCY_OID=$(jq -r '.identity.emergencyAccess.objectId // ""' "$INV")
EMERGENCY_AU=$(jq -r '.identity.emergencyAccess.administrativeUnitId // ""' "$INV")
if [ -n "$EMERGENCY_OID" ] && [ "$EMERGENCY_OID" != "null" ]; then
  az ad user show --id "$EMERGENCY_OID" >/dev/null 2>&1 && pass "emergency-access decoy exists" || fail "emergency-access decoy missing"
  # No Azure RBAC anywhere (powerless over every subscription).
  E_RBAC=$(az role assignment list --assignee "$EMERGENCY_OID" --all -o json 2>/dev/null | jq 'length')
  [ "${E_RBAC:-0}" -eq 0 ] && pass "emergency-access decoy has no Azure RBAC" \
    || fail "emergency-access decoy has $E_RBAC Azure RBAC assignment(s), must be zero"
  # No directory role assignments (holds no admin power itself).
  E_ROLES=$(az rest --method get \
    --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$EMERGENCY_OID'" \
    2>/dev/null | jq '.value | length')
  [ "${E_ROLES:-0}" -eq 0 ] && pass "emergency-access decoy holds no directory role" \
    || fail "emergency-access decoy holds $E_ROLES directory role(s), it must be powerless"
  # The scoping AU must contain ONLY this decoy (blast radius of the reset power = 1 account).
  if [ -n "$EMERGENCY_AU" ] && [ "$EMERGENCY_AU" != "null" ]; then
    AU_COUNT=$(az rest --method get \
      --url "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$EMERGENCY_AU/members?\$select=id" \
      2>/dev/null | jq '.value | length')
    [ "${AU_COUNT:-0}" -eq 1 ] && pass "emergency AU contains exactly 1 member (reset blast radius = the decoy only)" \
      || fail "emergency AU contains ${AU_COUNT:-?} members, the reset power must scope to ONLY the decoy"
  fi
else
  echo "NOTE: emergency-access decoy not in inventory, skipping its checks."
fi

# --- OPSEC: no honeypot marker in any attacker-visible name. ---
NAMES=$(az ad app show --id "${REACH_APP_ID:-00000000-0000-0000-0000-000000000000}" --query displayName -o tsv 2>/dev/null; \
        az ad user show --id "${EMERGENCY_OID:-00000000-0000-0000-0000-000000000000}" --query '{u:userPrincipalName,d:displayName}' -o tsv 2>/dev/null)
echo "$NAMES" | grep -iqE 'honey|decoy|\bhp\b|trap|fake|lure|canary' \
  && fail "honeypot marker leaked into an attacker-visible name!" \
  || pass "no honeypot marker in attacker-visible names"

echo "== Identity honeypot OK =="
