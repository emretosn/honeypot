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

# Playbooks live in a PRODUCTION-PLAUSIBLE RG (no honeypot marker), NOT the mgmt RG: their managed
# identities are directory-visible (AzureHound surfaces the SP name + resource-id path), so the RG
# and playbook names must look like ordinary production automation. The workspace/Sentinel stay in
# the mgmt RG; the automation rules are created there cross-scope by the template.
PLAYBOOK_RG_NAME="${PLAYBOOK_RG_NAME:-rg-core-ops-${REGION_CODE}}"
PLAYBOOK_RG_SCOPE="/subscriptions/$CURRENT_SUB/resourceGroups/$PLAYBOOK_RG_NAME"

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
  DECOY_IDS=$(jq -c '[.identity.lure.objectId, (.identity.decoyPersonas[]?), .identity.emergencyAccess.objectId] | map(select(. != null and . != ""))' "$INV")
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
# for Microsoft Sentinel on the playbook resource". The playbooks live in the production-plausible
# PLAYBOOK RG (not the mgmt RG), so the grant is scoped there. Grant it here (idempotent).
SENTINEL_APP_ID="98785600-1bb7-4fb9-b9fa-19afe2c8a360"   # Azure Security Insights (well-known)
MGMT_RG_SCOPE="/subscriptions/$CURRENT_SUB/resourceGroups/$MGMT_RG"

# Create the production-plausible playbook RG (production-looking tags; honeypot ownership is
# tracked in the inventory, never in the name/tags here). Idempotent.
info "Ensuring playbook resource group $PLAYBOOK_RG_NAME exists"
az group create -n "$PLAYBOOK_RG_NAME" -l "$REGION" \
  --tags environment=production workload=platform-automation managedBy=iac -o none \
  || die "failed to create playbook RG $PLAYBOOK_RG_NAME."

info "Ensuring Microsoft Sentinel can run the playbooks (Automation Contributor on $PLAYBOOK_RG_NAME)"
SENTINEL_SP_ID=$(az ad sp show --id "$SENTINEL_APP_ID" --query id -o tsv 2>/dev/null || true)
[ -n "$SENTINEL_SP_ID" ] || die "could not resolve the Azure Security Insights service principal — ensure Microsoft Sentinel is onboarded (run deploy/detection.sh first)."

if az role assignment list --assignee "$SENTINEL_SP_ID" --scope "$PLAYBOOK_RG_SCOPE" \
      --query "[?roleDefinitionName=='Microsoft Sentinel Automation Contributor']" -o tsv 2>/dev/null | grep -q .; then
  ok "role already assigned"
else
  az role assignment create --assignee-object-id "$SENTINEL_SP_ID" --assignee-principal-type ServicePrincipal \
    --role "Microsoft Sentinel Automation Contributor" --scope "$PLAYBOOK_RG_SCOPE" -o none \
    || die "failed to grant the role (need Owner or User Access Administrator on $PLAYBOOK_RG_NAME)."
  info "Waiting for role propagation..."
  sleep 30
  ok "role granted"
fi

info "Deploying response (SOAR) to $PLAYBOOK_RG_NAME (dryRun=$DRY_RUN); automation rules -> $MGMT_RG"
az deployment group create \
  --resource-group "$PLAYBOOK_RG_NAME" \
  --name response \
  --template-file "$REPO_ROOT/bicep/response.bicep" \
  --parameters location="$REGION" regionCode="$REGION_CODE" \
               mgmtResourceGroupName="$MGMT_RG" \
               workspaceName="$WORKSPACE" honeypotResourceGroupId="$SPOKE_RG_ID" dryRun="$DRY_RUN" \
               decoyObjectIds="$DECOY_IDS" decoySpObjectIds="$DECOY_SP_IDS" allowlistObjectIds="$ALLOWLIST_IDS" \
  -o none
ok "response deployed (dryRun=$DRY_RUN)"

# Grant each playbook's managed identity "Microsoft Sentinel Responder" on the mgmt RG so it can
# post incident comments (the connection authenticates as the MI). Without this, even the dry-run
# comment fails with 403 and the playbook run errors. Idempotent.
DEPLOY_OUT=$(az deployment group show --resource-group "$PLAYBOOK_RG_NAME" --name response --query properties.outputs -o json 2>/dev/null || echo '{}')
for MI in $(echo "$DEPLOY_OUT" | jq -r '(.disableUserPrincipalId.value // empty), (.isolateResourcePrincipalId.value // empty)'); do
  [ -n "$MI" ] || continue
  if az role assignment list --assignee "$MI" --scope "$MGMT_RG_SCOPE" \
        --query "[?roleDefinitionName=='Microsoft Sentinel Responder']" -o tsv 2>/dev/null | grep -q .; then
    ok "playbook MI $MI already has Microsoft Sentinel Responder"
  else
    az role assignment create --assignee-object-id "$MI" --assignee-principal-type ServicePrincipal \
      --role "Microsoft Sentinel Responder" --scope "$MGMT_RG_SCOPE" -o none 2>/dev/null \
      && ok "granted Microsoft Sentinel Responder to playbook MI $MI" \
      || echo "  WARN: could not grant Sentinel Responder to $MI (need Owner/User Access Administrator on $MGMT_RG)"
  fi
done

echo
echo "  IMPORTANT one-time grants (see docs/detection-and-response.md), then re-test:"
echo "   - disable-user playbook MI  -> Microsoft Graph User.ReadWrite.All"
echo "   - isolate-resource playbook MI -> role with Microsoft.Authorization/locks/write on the spoke RG"
echo "   - authorize the azuresentinel API connection in the portal"
echo "  Fill inventory allowlist.breakGlassObjectIds and pass allowlistObjectIds before enforcing."
echo "  Verify: ./tests/verify_response.sh $MGMT_RG $WORKSPACE $PLAYBOOK_RG_NAME $REGION_CODE"
