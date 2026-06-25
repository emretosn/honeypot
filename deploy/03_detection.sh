#!/usr/bin/env bash
# Stand up DETECTION: (1) stream Entra AuditLogs + SignInLogs to the Log Analytics
# workspace (microsoft.aadiam diagnostic settings), then (2) onboard Microsoft Sentinel and
# deploy the honeypot analytics rules. Run from your workstation as Security/Global Admin.
# Idempotent. Requires foundation (workspace) already deployed and the inventory populated.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
require_login

INV="$REPO_ROOT/inventory/decoy-inventory.json"
LURE_UPN=$(jq -r '.identity.lure.upn' "$INV" 2>/dev/null)
[ -n "$LURE_UPN" ] && [ "$LURE_UPN" != "null" ] || die "lure UPN missing in inventory — run tests/sync_inventory.sh."

# Reachable-edge ids (Phase 04) — enable the invited-action rules only when they exist.
REACHABLE_APP_ID=$(jq -r '.identity.reachableApp.appId // ""' "$INV")
REACHABLE_SP_ID=$(jq -r '.identity.reachableApp.spObjectId // ""' "$INV")
ENABLE_REACHABLE_EDGE_RULES="false"
[ -n "$REACHABLE_APP_ID" ] && [ -n "$REACHABLE_SP_ID" ] && ENABLE_REACHABLE_EDGE_RULES="true"

WS_ID="/subscriptions/$CURRENT_SUB/resourceGroups/$MGMT_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE"

# Optional: decoy resource names (only meaningful once the network module is deployed). Derived
# from the inventory when present; the KV/storage rules deploy regardless and stay silent until
# those resources exist.
KV_NAME="${DECOY_KEY_VAULT_NAME:-$(basename "$(jq -r '.network.keyVaultId // ""' "$INV")")}"
SA_NAME="${DECOY_STORAGE_ACCOUNT_NAME:-$(basename "$(jq -r '.network.storageAccountId // ""' "$INV")")}"
[ -n "$KV_NAME" ] || KV_NAME="kv-not-deployed"
[ -n "$SA_NAME" ] || SA_NAME="stnotdeployed"

# --- 1. Entra ID -> Log Analytics diagnostic settings (tenant-level aadiam resource) --------
info "Configuring Entra diagnostic settings (AuditLogs + SignInLogs -> $WORKSPACE)"
BODY=$(jq -n --arg ws "$WS_ID" '{
  properties: {
    workspaceId: $ws,
    logs: [
      { category: "AuditLogs",  enabled: true },
      { category: "SignInLogs", enabled: true },
      { category: "ServicePrincipalSignInLogs", enabled: true }
    ]
  }
}')
az rest --method put \
  --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/honeypot-diag?api-version=2017-04-01" \
  --body "$BODY" -o none \
  || die "failed to set Entra diagnostic settings (need Security Administrator or Global Administrator)."
ok "Entra diagnostic settings configured (logs take up to ~15 min to flow)"

# --- 2. Sentinel onboarding + analytics rules ----------------------------------------------
# Resource rules (Key Vault / storage) reference tables/columns that only exist once the
# network module is deployed, so they are OFF unless you opt in. Enable after deploying the
# network:  ENABLE_RESOURCE_RULES=true ./deploy/03_detection.sh
ENABLE_RESOURCE_RULES="${ENABLE_RESOURCE_RULES:-false}"

info "Deploying detection (Sentinel + analytics rules) to $MGMT_RG"
az deployment group create \
  --resource-group "$MGMT_RG" \
  --template-file "$REPO_ROOT/bicep/detection.bicep" \
  --parameters workspaceName="$WORKSPACE" lureUpn="$LURE_UPN" \
               decoyKeyVaultName="$KV_NAME" decoyStorageAccountName="$SA_NAME" \
               enableResourceRules="$ENABLE_RESOURCE_RULES" \
               reachableAppId="$REACHABLE_APP_ID" reachableSpObjectId="$REACHABLE_SP_ID" \
               enableReachableEdgeRules="$ENABLE_REACHABLE_EDGE_RULES" \
  -o none
ok "detection deployed (resource rules: $ENABLE_RESOURCE_RULES, reachable-edge rules: $ENABLE_REACHABLE_EDGE_RULES)"

echo
ok "Detection is live. Verify (paths per Microsoft docs):"
echo "  - Microsoft Sentinel, after opening workspace '$WORKSPACE':"
echo "      Defender portal: Microsoft Sentinel > Configuration > Analytics > Active rules"
echo "      -> filter for 'Honeypot:' (3 rules now; more once resource rules are enabled)."
echo "  - CLI (no portal needed): ./tests/verify_detection.sh $MGMT_RG $WORKSPACE"
