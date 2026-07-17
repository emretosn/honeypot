#!/usr/bin/env bash
# Deploy the identity honeypot (Terraform) with LOCAL state
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

# First stage of the identity plane: the reachable app/SP (foothold-owned, god-mode requested but
# unconsented, pre-seeded credentials) and the emergency-access decoy + its single-member AU. The
# decoy SP's Azure RBAC payoff is granted later by deploy/edge.sh, once the network exists. We do
# NOT pass the decoy RG/KV here, so that step is cleanly separated.
unset TF_VAR_decoy_resource_group_id TF_VAR_decoy_key_vault_id

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
echo "  - Then deploy the network (./deploy/network.sh), then ./deploy/edge.sh for the SP RBAC."
