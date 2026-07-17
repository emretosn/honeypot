#!/usr/bin/env bash
# Second stage of the identity plane: grant the reachable decoy service principal its CONTAINED Azure
# RBAC payoff, Owner on the decoy honeypot RG + Key Vault Secrets User on the decoy KV. Run AFTER
# deploy/network.sh (the RG/KV must exist; their IDs come from the inventory). This is the second,
# separate identity step so each deployment stage has its own script. Idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
require_login

[ "$VERIFIED_DOMAIN" != "REPLACE.onmicrosoft.com" ] || die "set VERIFIED_DOMAIN in config.env."

TF_DIR="$REPO_ROOT/terraform/identity"
INV="$REPO_ROOT/inventory/decoy-inventory.json"

RG_ID=$(jq -r '.network.honeypotResourceGroupId // ""' "$INV" 2>/dev/null)
KV_ID=$(jq -r '.network.keyVaultId // ""' "$INV" 2>/dev/null)
[ -n "$RG_ID" ] || die "decoy RG ID not in inventory, deploy the network first (deploy/network.sh)."

export TF_VAR_verified_domain="$VERIFIED_DOMAIN"
export TF_VAR_decoy_resource_group_id="$RG_ID"
export TF_VAR_decoy_key_vault_id="$KV_ID"

info "Granting the decoy SP Owner on $RG_ID + Key Vault Secrets User on the decoy KV"
terraform -chdir="$TF_DIR" apply -auto-approve -input=false

info "Syncing inventory"
"$REPO_ROOT/tests/sync_inventory.sh"

echo
ok "Reachable-edge RBAC in place. Verify: ./tests/verify_identity.sh (asserts SP RBAC scoped to decoy RG/KV only)."
echo "  Next: ./deploy/detection.sh then ./deploy/response.sh"
