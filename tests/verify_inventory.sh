#!/usr/bin/env bash
# Module-contract check for inventory/decoy-inventory.json, the single source of truth that
# producers (identity/spoke/canary) WRITE and consumers (detection/response/cleanup) READ.
# This is a STATIC check (no tenant needed): it validates structure, schema, referential
# integrity and OPSEC, so the "docs ahead of IaC" / silent-misconfig failure modes cannot ship.
#
# Usage:
#   tests/verify_inventory.sh            # structure + schema + OPSEC (post-deploy ids may be empty)
#   tests/verify_inventory.sh --strict   # additionally require post-deploy ids to be populated
#
# Exit 0 = contract satisfied. Non-zero = number of failures.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INV="$ROOT/inventory/decoy-inventory.json"
# Live inventory is gitignored; fall back to the tracked template for static checks on a fresh clone.
[ -f "$INV" ] || INV="$ROOT/inventory/decoy-inventory.template.json"
EXPECTED_SCHEMA=1
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

fails=0
ok()   { echo "  [OK]   $1"; }
bad()  { echo "  [FAIL] $1"; fails=$((fails+1)); }
warn() { echo "  [WARN] $1"; }

echo "### inventory contract: $INV"

# 1. Valid JSON.
if ! jq empty "$INV" 2>/dev/null; then
  echo "  [FAIL] not valid JSON (or file missing)"; exit 1
fi
ok "valid JSON"

# 2. Schema version.
sv=$(jq -r '.schemaVersion // empty' "$INV")
if [ "$sv" = "$EXPECTED_SCHEMA" ]; then ok "schemaVersion=$sv"; else bad "schemaVersion is '$sv', expected $EXPECTED_SCHEMA"; fi

# 3. Required keys must EXIST (presence is the contract; values may be filled post-deploy).
required_keys=(
  '.tenantId'
  '.identity.reachableApp.appId'
  '.identity.reachableApp.spObjectId'
  '.identity.emergencyAccess.upn'
  '.identity.emergencyAccess.objectId'
  '.network.honeypotResourceGroupId'
  '.network.keyVaultId'
  '.network.storageAccountId'
  '.allowlist.breakGlassObjectIds'
  '.allowlist.agentObjectIds'
  '.allowlist.agentNamedLocationCidrs'
)
for k in "${required_keys[@]}"; do
  if jq -e "$k != null" "$INV" >/dev/null 2>&1; then ok "key present: $k"; else bad "missing required key: $k"; fi
done

# 4. Allowlist arrays must be arrays (so detection/response can iterate safely).
for a in '.allowlist.breakGlassObjectIds' '.allowlist.agentObjectIds' '.allowlist.agentNamedLocationCidrs'; do
  t=$(jq -r "$a | type" "$INV" 2>/dev/null)
  [ "$t" = "array" ] && ok "array: $a" || bad "$a must be an array (is '$t')"
done

# 5. OPSEC: no honeypot marker may leak into any ATTACKER-VISIBLE name field.
#    (the reachable app + emergency-access display names/UPNs live here; the
#     'hp'/'honeypot'/'decoy' markers must NEVER appear in them.)
visible=$(jq -r '
  [ .identity.reachableApp.displayName, .identity.emergencyAccess.upn, .identity.emergencyAccess.displayName ]
  | map(select(. != null)) | .[]' "$INV" 2>/dev/null)
leak=0
while IFS= read -r v; do
  [ -z "$v" ] && continue
  if printf '%s' "$v" | grep -qiE 'honeypot|decoy|(^|[^a-z])hp([^a-z]|$)|lure|canary|trap'; then
    bad "OPSEC marker leak in attacker-visible field: '$v'"; leak=1
  fi
done <<< "$visible"
[ "$leak" -eq 0 ] && ok "no OPSEC marker in attacker-visible name fields"

# 6. Referential integrity for downstream consumers: the values detection/response key on
#    must be coherent. The emergency-access UPN, when populated, must look like a UPN.
upn=$(jq -r '.identity.emergencyAccess.upn // ""' "$INV")
if [ -n "$upn" ]; then
  printf '%s' "$upn" | grep -qE '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' \
    && ok "emergencyAccess.upn is well-formed ($upn)" || bad "emergencyAccess.upn malformed: '$upn'"
fi

# 7. Strict (post-deploy) checks: ids that MUST be populated once identity is applied.
if [ "$STRICT" -eq 1 ]; then
  echo "  -- strict: post-deploy population --"
  strict_nonempty=(
    '.tenantId'
    '.identity.reachableApp.appId'
    '.identity.reachableApp.spObjectId'
    '.identity.emergencyAccess.objectId'
    '.identity.emergencyAccess.upn'
  )
  for k in "${strict_nonempty[@]}"; do
    v=$(jq -r "$k // \"\"" "$INV")
    [ -n "$v" ] && ok "populated: $k" || bad "strict: $k is empty (run tests/sync_inventory.sh after apply)"
  done
  # Break-glass should be set so it is protected from remediation; warn (not fail) if missing.
  [ "$(jq '.allowlist.breakGlassObjectIds | length' "$INV")" -gt 0 ] \
    && ok "break-glass allowlist populated" \
    || warn "allowlist.breakGlassObjectIds empty (set break_glass_object_ids so break-glass is never disabled)."
else
  # Lenient mode: just inform if core ids are still unpopulated.
  [ -z "$(jq -r '.identity.reachableApp.spObjectId // ""' "$INV")" ] && warn "reachableApp.spObjectId empty (pre-deploy or before sync_inventory), fine for static checks."
fi

echo
if [ "$fails" -eq 0 ]; then echo "inventory contract OK"; else echo "$fails inventory contract failure(s)"; fi
exit "$fails"
