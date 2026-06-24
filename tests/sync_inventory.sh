#!/usr/bin/env bash
# Populate inventory/decoy-inventory.json from the identity module's Terraform outputs.
# The inventory is the single source of truth shared by detection (what to watch) and
# remediation (what it may act on). Run after `terraform apply` in terraform/identity.
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

echo "Updated $INV from Terraform outputs."
if [ "$(jq '.allowlist.breakGlassObjectIds | length' "$INV")" -eq 0 ]; then
  echo "WARNING: allowlist.breakGlassObjectIds is empty — set break_glass_object_ids in terraform.tfvars (the customer's real break-glass GA) before enabling enforcement."
fi
