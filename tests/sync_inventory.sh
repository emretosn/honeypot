#!/usr/bin/env bash
# Populate inventory/decoy-inventory.json — the single source of truth shared by detection
# (what to watch) and remediation (what it may act on). Pulls IDENTITY ids from the Terraform
# outputs and (if the network plane is deployed) NETWORK resource ids from the Bicep
# 'network' subscription deployment. Run after `terraform apply` and after deploy/05_network.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT/terraform/identity"
INV="$ROOT/inventory/decoy-inventory.json"

cd "$TF_DIR"
TF_JSON=$(terraform output -json)

tmp=$(mktemp)
jq \
  --argjson tf "$TF_JSON" '
  .tenantId = $tf.tenant_id.value
  | .identity.decoyAdministrativeUnitId = $tf.decoy_administrative_unit_id.value
  | .identity.lure = { upn: $tf.lure.value.upn, objectId: $tf.lure.value.object_id, displayName: $tf.lure.value.display_name }
  | .identity.decoyPersonas = $tf.decoy_persona_object_ids.value
  | .identity.lureRoleDefinitionId = $tf.lure_role_definition_id.value
  | .identity.decoyGroupIds = [ $tf.decoy_group_id.value ]
  | .identity.decoyAppIds = $tf.decoy_app_ids.value
  | .allowlist.breakGlassObjectIds = ($tf.break_glass_object_ids.value // [])
  | .allowlist.agentNamedLocationCidrs = (.allowlist.agentNamedLocationCidrs // [])
  ' "$INV" > "$tmp"
mv "$tmp" "$INV"
echo "Updated $INV identity section from Terraform outputs."

# NETWORK section: pull from the Bicep 'network' deployment outputs if it exists (needs az login).
if command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; then
  NET_JSON=$(az deployment sub show --name network --query properties.outputs -o json 2>/dev/null || echo "")
  if [ -n "$NET_JSON" ] && [ "$NET_JSON" != "null" ]; then
    SUB=$(az account show --query id -o tsv)
    tmp=$(mktemp)
    jq \
      --argjson net "$NET_JSON" \
      --arg sub "$SUB" '
      .network.honeypotSubscriptionId = $sub
      | .network.honeypotResourceGroupId = ("/subscriptions/" + $sub + "/resourceGroups/" + ($net.honeypotResourceGroupName.value // ""))
      | .network.keyVaultId = ($net.keyVaultId.value // "")
      | .network.storageAccountId = ($net.storageAccountId.value // "")
      | .network.decoyVmId = ($net.decoyVmId.value // "")
      ' "$INV" > "$tmp"
    mv "$tmp" "$INV"
    echo "Updated $INV network section from the 'network' deployment outputs."
  else
    echo "NOTE: no 'network' deployment found — network ids left empty (run deploy/05_network.sh first)."
  fi
else
  echo "NOTE: az not logged in — skipped network section (run after deploy/05_network.sh)."
fi

if [ "$(jq '.allowlist.breakGlassObjectIds | length' "$INV")" -eq 0 ]; then
  echo "WARNING: allowlist.breakGlassObjectIds is empty — set break_glass_object_ids in terraform.tfvars (the real break-glass GA) before enabling enforcement."
fi
