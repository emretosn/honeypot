#!/usr/bin/env bash
# FULL TEARDOWN, removes everything the deploy/* scripts created and resets local state so the
# repo looks freshly cloned. Destroys: decoy identities + SP RBAC (Terraform), Entra diagnostic
# settings, Sentinel rules/playbooks, and ALL resource groups (mgmt, hub, honeypot spoke,
# simulated production), then purges soft-deleted Key Vaults and clears local tfstate + the live
# inventory. DESTRUCTIVE and irreversible. Run as a directory admin.
#
# Usage:
#   deploy/teardown.sh            # prompts before destroying
#   deploy/teardown.sh --yes      # no prompt (CI)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
require_login

INV="$REPO_ROOT/inventory/decoy-inventory.json"
TF_DIR="$REPO_ROOT/terraform/identity"
SPOKE_RG="rg-core-prod-${REGION_CODE}"
PROD_RG="rg-erp-prod-${REGION_CODE}"
HUB_RG="rg-network-hub-${REGION_CODE}"
# The management/operations RG now also hosts the SOAR playbooks (no separate ops RG).
RGS=("$SPOKE_RG" "$PROD_RG" "$HUB_RG" "$MGMT_RG")

echo "This will PERMANENTLY DELETE:"
echo "  - decoy identities: reachable app/SP (+ its RBAC), emergency-access decoy + AU (terraform destroy)"
echo "  - Entra diagnostic setting 'honeypot-diag'"
echo "  - resource groups: ${RGS[*]} (Sentinel, rules, playbooks, KV, storage, network)"
echo "  - local terraform state + live inventory (reset to clean-clone state)"
if [ "${1:-}" != "--yes" ]; then
  read -r -p "Type 'destroy' to proceed: " ans
  [ "$ans" = "destroy" ] || die "aborted."
fi

# 1. Remove any isolation locks the response playbook may have applied (locks block RG delete).
#    Covers RG-scoped AND resource-scoped locks under the decoy/prod RGs (the isolate playbook locks
#    individual resources), so a live-fired remediation can never block teardown/redeploy.
info "Removing resource locks under the honeypot RGs"
for rg in "$SPOKE_RG" "$PROD_RG"; do
  az group show -n "$rg" >/dev/null 2>&1 || continue
  az lock list -g "$rg" --query "[].id" -o tsv 2>/dev/null | while read -r lid; do
    [ -n "$lid" ] && az lock delete --ids "$lid" 2>/dev/null && echo "  removed lock $lid"
  done
done

# 2. Terraform destroy the identity plane (reachable app/SP + its RBAC, emergency-access decoy + AU).
if [ -f "$TF_DIR/terraform.tfstate" ]; then
  info "terraform destroy (identity plane)"
  export TF_VAR_verified_domain="${VERIFIED_DOMAIN:-placeholder.onmicrosoft.com}"
  [ -f "$INV" ] && export TF_VAR_decoy_resource_group_id="$(jq -r '.network.honeypotResourceGroupId // ""' "$INV")"
  [ -f "$INV" ] && export TF_VAR_decoy_key_vault_id="$(jq -r '.network.keyVaultId // ""' "$INV")"
  terraform -chdir="$TF_DIR" destroy -auto-approve -input=false || echo "  (identity destroy reported errors, continuing)"
else
  info "no terraform state, skipping identity destroy"
fi

# 3. Delete the Entra diagnostic setting (tenant-level aadiam).
info "Deleting Entra diagnostic setting 'honeypot-diag'"
az rest --method delete \
  --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/honeypot-diag?api-version=2017-04-01" \
  -o none 2>/dev/null && echo "  deleted" || echo "  (not present)"

# 4. Delete all resource groups (removes Sentinel/rules/playbooks/workspace/KV/storage/network).
for rg in "${RGS[@]}"; do
  if az group show -n "$rg" >/dev/null 2>&1; then
    info "Deleting resource group $rg"
    az group delete -n "$rg" --yes --no-wait
  fi
done
info "RG deletions running in background (no-wait)"

# 5. Purge soft-deleted Key Vaults so names are reusable on redeploy.
info "Purging soft-deleted decoy Key Vaults"
az keyvault list-deleted --query "[?contains(name,'core-prod')].name" -o tsv 2>/dev/null | while read -r kv; do
  [ -n "$kv" ] && az keyvault purge --name "$kv" --no-wait 2>/dev/null && echo "  purged $kv"
done

# 6. Reset local state to clean-clone: drop tfstate, restore blank inventory from template.
info "Resetting local state"
rm -f "$TF_DIR/terraform.tfstate" "$TF_DIR/terraform.tfstate.backup" "$TF_DIR/tfplan"
[ -f "$REPO_ROOT/inventory/decoy-inventory.template.json" ] && cp "$REPO_ROOT/inventory/decoy-inventory.template.json" "$INV"

echo
ok "Teardown initiated. RG deletes finish in the background (check: az group list -o table)."
echo "  Optional: tests/attacker_test_user.sh delete   # remove the throwaway foothold"
echo "  Redeploy from scratch: deploy/foundation -> identity -> network -> edge -> detection -> response"
