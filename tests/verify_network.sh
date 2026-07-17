#!/usr/bin/env bash
# Honeypot network verification, run AFTER deploying bicep/network.bicep.
# Asserts the spoke EXISTS and, critically, that it is CONTAINED:
#   - the honeypot spoke VNet and decoy resources exist,
#   - an explicit NSG rule DENIES egress to the production address space,
#   - the spoke peers to the hub but NOT to any production spoke (no lateral path),
#   - no honeypot marker leaks into attacker-visible resource names.
# Requires: az login; jq.
set -euo pipefail

SPOKE_RG="${1:-rg-core-prod-weu}"
PROD_PREFIX="${2:-10.10.0.0/16}"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

echo "== Honeypot network verification (rg=$SPOKE_RG) =="

az group show -n "$SPOKE_RG" >/dev/null 2>&1 && pass "spoke resource group exists" || fail "spoke RG missing"

VNET=$(az network vnet list -g "$SPOKE_RG" --query '[0].name' -o tsv 2>/dev/null)
[ -n "$VNET" ] && pass "spoke VNet exists ($VNET)" || fail "spoke VNet missing"

# Core containment check: an outbound DENY rule targeting the production prefix must exist.
DENY=$(az network nsg list -g "$SPOKE_RG" -o json 2>/dev/null | jq -r --arg p "$PROD_PREFIX" '
  [ .[].securityRules[]
    | select(.direction=="Outbound" and .access=="Deny")
    | select((.destinationAddressPrefixes // [.destinationAddressPrefix]) | index($p)) ] | length')
[ "${DENY:-0}" -ge 1 ] && pass "egress-to-production DENY rule present on $DENY NSG(s)" \
  || fail "no NSG denies egress to production ($PROD_PREFIX), containment broken!"

# No spoke-to-spoke peering (only hub peering allowed).
PEERINGS=$(az network vnet peering list -g "$SPOKE_RG" --vnet-name "$VNET" --query '[].name' -o tsv 2>/dev/null || true)
echo "$PEERINGS" | grep -iqE 'spoke|prod-spoke|workload-spoke' \
  && fail "spoke has a peering that looks like spoke-to-spoke transit: $PEERINGS" \
  || pass "no spoke-to-spoke peering (hub-only transit)"

# Decoy resources exist.
az keyvault list -g "$SPOKE_RG" --query '[0].name' -o tsv 2>/dev/null | grep -q . && pass "decoy Key Vault exists" || fail "decoy Key Vault missing"
az storage account list -g "$SPOKE_RG" --query '[0].name' -o tsv 2>/dev/null | grep -q . && pass "decoy storage account exists" || fail "decoy storage missing"
# Decoy VM (private workload host), always deployed.
az vm list -g "$SPOKE_RG" --query '[0].name' -o tsv 2>/dev/null | grep -q . \
  && pass "decoy VM present (private workload host)" || fail "decoy VM missing"

# OPSEC: no honeypot marker in attacker-visible resource names.
NAMES=$(az resource list -g "$SPOKE_RG" --query '[].name' -o tsv 2>/dev/null)
echo "$NAMES" | grep -iqE 'honey|decoy|\bhp\b|trap|fake' \
  && fail "honeypot marker leaked into an attacker-visible resource name!" \
  || pass "no honeypot marker in attacker-visible resource names"

echo "== Honeypot network OK =="
