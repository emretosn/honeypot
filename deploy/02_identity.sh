#!/usr/bin/env bash
# Deploy the identity honeypot (Terraform) with LOCAL state — no remote backend, no jump VM.
# Run from your workstation, logged in as a principal with directory-admin rights (the rights
# to create administrative units, custom roles and Conditional Access policies). State is
# written to terraform/identity/terraform.tfstate (gitignored, sensitive). Idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
require_login

[ "$VERIFIED_DOMAIN" != "REPLACE.onmicrosoft.com" ] || die "set VERIFIED_DOMAIN in config.env."

TF_DIR="$REPO_ROOT/terraform/identity"
export TF_VAR_verified_domain="$VERIFIED_DOMAIN"

# Reachable-edge RBAC payoff (Phase 04): if the network is already deployed, pass the decoy RG +
# Key Vault ids from the inventory so the decoy SP gets Owner-on-RG + KV-Secrets-User (contained).
# Empty on the first pass (before the network exists) — the role assignments are then skipped.
INV="$REPO_ROOT/inventory/decoy-inventory.json"
if [ -f "$INV" ]; then
  RG_ID=$(jq -r '.network.honeypotResourceGroupId // ""' "$INV")
  KV_ID=$(jq -r '.network.keyVaultId // ""' "$INV")
  [ -n "$RG_ID" ] && export TF_VAR_decoy_resource_group_id="$RG_ID"
  [ -n "$KV_ID" ] && export TF_VAR_decoy_key_vault_id="$KV_ID"
  if [ -n "$RG_ID" ]; then info "Reachable-edge RBAC will target decoy RG (and KV) from inventory"; else info "Network not yet in inventory — reachable-edge RBAC skipped this pass"; fi
fi

info "terraform init (local backend)"
terraform -chdir="$TF_DIR" init -input=false

info "terraform plan"
terraform -chdir="$TF_DIR" plan -input=false -out=tfplan

read -r -p "Apply this plan? [y/N] " ans
[ "$ans" = "y" ] || [ "$ans" = "Y" ] || die "aborted by user."

info "terraform apply"
terraform -chdir="$TF_DIR" apply -input=false tfplan

info "Syncing decoy inventory from outputs"
"$REPO_ROOT/tests/sync_inventory.sh"
ok "inventory synced"

echo
ok "Identity deployed. Next:"
echo "  - Fill inventory/decoy-inventory.json allowlist.breakGlassObjectIds (your break-glass GA)."
echo "  - Verify:        ./tests/verify_identity.sh"
echo "  - Attacker path: see docs/operations.md (attack scenarios)."
