#!/usr/bin/env bash
# Deploy RESPONSE (SOAR): the Disable-User and Isolate-Resource playbooks + Sentinel
# automation rules. Ships in DRY-RUN by default — playbooks only comment, never change
# anything — so it is safe to deploy before you trust the pipeline. Run from your
# workstation. Idempotent.
#
# After deploy you must (one-time, see docs/detection-and-response.md): grant the playbook managed
# identities their Graph / lock permissions and authorize the azuresentinel connection.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
require_login

# Honeypot spoke RG id (may not exist yet if the network module isn't deployed; the isolate
# playbook simply never matches until it does).
SPOKE_RG_NAME="${SPOKE_RG_NAME:-rg-core-prod-${REGION_CODE}}"
SPOKE_RG_ID="/subscriptions/$CURRENT_SUB/resourceGroups/$SPOKE_RG_NAME"

DRY_RUN="${DRY_RUN:-true}"

# Two-key safety guard, sourced from the single source of truth (inventory):
#   decoyObjectIds   = the decoy identities the playbook MAY disable (lure + personas).
#   allowlistObjectIds = real break-glass / agent IDs that must NEVER be disabled.
# The playbook disables an account only if it is in decoyObjectIds AND not in the allowlist.
INV="$REPO_ROOT/inventory/decoy-inventory.json"
DECOY_IDS='[]'
DECOY_SP_IDS='[]'
ALLOWLIST_IDS='[]'
if [ -f "$INV" ]; then
  DECOY_IDS=$(jq -c '[.identity.lure.objectId, (.identity.decoyPersonas[]?)] | map(select(. != null and . != ""))' "$INV")
  DECOY_SP_IDS=$(jq -c '[.identity.reachableApp.spObjectId] | map(select(. != null and . != ""))' "$INV")
  ALLOWLIST_IDS=$(jq -c '(.allowlist.breakGlassObjectIds // []) + (.allowlist.agentObjectIds // []) | map(select(. != null and . != ""))' "$INV")
fi
info "Guard from inventory: $(echo "$DECOY_IDS" | jq 'length') decoy user(s), $(echo "$DECOY_SP_IDS" | jq 'length') decoy SP(s), $(echo "$ALLOWLIST_IDS" | jq 'length') allowlisted id(s)"
if [ "$DRY_RUN" = "false" ] && [ "$(echo "$DECOY_IDS" | jq 'length')" -eq 0 ]; then
  die "refusing to enforce (dryRun=false) with an EMPTY decoyObjectIds list — the guard would disable nothing or, worse, be misconfigured. Run tests/sync_inventory.sh first."
fi

# Prerequisite: Microsoft Sentinel (the first-party "Azure Security Insights" app) must hold
# the "Microsoft Sentinel Automation Contributor" role on the resource group that contains
# the playbooks, or creating the automation rules fails with "Missing required permissions
# for Microsoft Sentinel on the playbook resource". Grant it here (idempotent).
SENTINEL_APP_ID="98785600-1bb7-4fb9-b9fa-19afe2c8a360"   # Azure Security Insights (well-known)
MGMT_RG_SCOPE="/subscriptions/$CURRENT_SUB/resourceGroups/$MGMT_RG"

info "Ensuring Microsoft Sentinel can run the playbooks (Automation Contributor on $MGMT_RG)"
SENTINEL_SP_ID=$(az ad sp show --id "$SENTINEL_APP_ID" --query id -o tsv 2>/dev/null || true)
[ -n "$SENTINEL_SP_ID" ] || die "could not resolve the Azure Security Insights service principal — ensure Microsoft Sentinel is onboarded (run deploy/detection.sh first)."

if az role assignment list --assignee "$SENTINEL_SP_ID" --scope "$MGMT_RG_SCOPE" \
      --query "[?roleDefinitionName=='Microsoft Sentinel Automation Contributor']" -o tsv 2>/dev/null | grep -q .; then
  ok "role already assigned"
else
  az role assignment create --assignee-object-id "$SENTINEL_SP_ID" --assignee-principal-type ServicePrincipal \
    --role "Microsoft Sentinel Automation Contributor" --scope "$MGMT_RG_SCOPE" -o none \
    || die "failed to grant the role (need Owner or User Access Administrator on $MGMT_RG)."
  info "Waiting for role propagation..."
  sleep 30
  ok "role granted"
fi

info "Deploying response (SOAR) to $MGMT_RG (dryRun=$DRY_RUN)"
az deployment group create \
  --resource-group "$MGMT_RG" \
  --template-file "$REPO_ROOT/bicep/response.bicep" \
  --parameters env="$ENVN" location="$REGION" regionCode="$REGION_CODE" marker="$MARKER" \
               workspaceName="$WORKSPACE" honeypotResourceGroupId="$SPOKE_RG_ID" dryRun="$DRY_RUN" \
               decoyObjectIds="$DECOY_IDS" decoySpObjectIds="$DECOY_SP_IDS" allowlistObjectIds="$ALLOWLIST_IDS" \
  -o none
ok "response deployed (dryRun=$DRY_RUN)"

echo
echo "  IMPORTANT one-time grants (see docs/detection-and-response.md), then re-test:"
echo "   - disable-user playbook MI  -> Microsoft Graph User.ReadWrite.All"
echo "   - isolate-resource playbook MI -> role with Microsoft.Authorization/locks/write on the spoke RG"
echo "   - authorize the azuresentinel API connection in the portal"
echo "  Fill inventory allowlist.breakGlassObjectIds and pass allowlistObjectIds before enforcing."
echo "  Verify: ./tests/verify_response.sh $MGMT_RG $WORKSPACE ${MARKER}-${ENVN}-${REGION_CODE}"
