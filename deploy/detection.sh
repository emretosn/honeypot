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

# Reachable-edge ids, enable the invited-action rules (credential-add, SP sign-in, consent) only
# when the app/SP exist in the inventory.
REACHABLE_APP_ID=$(jq -r '.identity.reachableApp.appId // ""' "$INV")
REACHABLE_APP_OBJECT_ID=$(jq -r '.identity.reachableApp.appObjectId // ""' "$INV")
REACHABLE_SP_ID=$(jq -r '.identity.reachableApp.spObjectId // ""' "$INV")
ENABLE_REACHABLE_EDGE_RULES="false"
[ -n "$REACHABLE_APP_ID" ] && [ -n "$REACHABLE_SP_ID" ] && ENABLE_REACHABLE_EDGE_RULES="true"

# Emergency-access decoy (standalone reset-me path), its sign-in rule auto-enables when it is in
# the inventory. Any compromised identity can reset it; resetting or signing in as it is a tripwire.
EMERGENCY_UPN=$(jq -r '.identity.emergencyAccess.upn // ""' "$INV")

# Privileged-auth allowlist: the real admins + service principals (AD Connect / password-hash-sync,
# provisioning) that are LEGITIMATELY allowed to reset OTHER users' passwords or authentication
# methods. The privileged-auth-abuse rule fires on any OTHER initiator that does so. Sourced from the
# inventory break-glass IDs; this is the known-good set the rule inverts against.
PRIV_AUTH_ALLOWLIST_JSON=$(jq -c '.allowlist.breakGlassObjectIds // []' "$INV" 2>/dev/null)
[ -n "$PRIV_AUTH_ALLOWLIST_JSON" ] && [ "$PRIV_AUTH_ALLOWLIST_JSON" != "null" ] || PRIV_AUTH_ALLOWLIST_JSON='[]'

# Decoy resource names (from the network deployment). The KV/storage/VM rules scope to these.
DECOY_VM_NAME=$(basename "$(jq -r '.network.decoyVmId // ""' "$INV")")
KV_NAME=$(basename "$(jq -r '.network.keyVaultId // ""' "$INV")")
SA_NAME=$(basename "$(jq -r '.network.storageAccountId // ""' "$INV")")
[ -n "$KV_NAME" ] || KV_NAME="kv-not-deployed"
[ -n "$SA_NAME" ] || SA_NAME="stnotdeployed"

WS_ID="/subscriptions/$CURRENT_SUB/resourceGroups/$MGMT_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE"

# --- 1. Entra ID -> Log Analytics diagnostic settings (tenant-level aadiam resource) --------
info "Configuring Entra diagnostic settings (AuditLogs + SignInLogs -> $WORKSPACE)"
BODY=$(jq -n --arg ws "$WS_ID" '{
  properties: {
    workspaceId: $ws,
    logs: [
      { category: "AuditLogs",  enabled: true },
      { category: "SignInLogs", enabled: true },
      { category: "NonInteractiveUserSignInLogs", enabled: true },
      { category: "ServicePrincipalSignInLogs", enabled: true },
      { category: "MicrosoftGraphActivityLogs", enabled: true }
    ]
  }
}')
az rest --method put \
  --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/honeypot-diag?api-version=2017-04-01" \
  --body "$BODY" -o none \
  || die "failed to set Entra diagnostic settings (need Security Administrator or Global Administrator)."
ok "Entra diagnostic settings configured (logs take up to ~15 min to flow)"

# --- 2. Sentinel onboarding + analytics rules ----------------------------------------------
# Resource rules (Key Vault / storage) query AzureDiagnostics (KV AuditEvent) and StorageBlobLogs.
# Those tables exist only AFTER the decoy KV/storage telemetry first ingests, and Sentinel validates
# the table at rule-creation time, so enabling them before the tables exist fails the deploy.
# Auto-enable once both are present; otherwise skip and re-run detection.sh after ingest.
WS_GUID=$(az monitor log-analytics workspace show -g "$MGMT_RG" -n "$WORKSPACE" --query customerId -o tsv 2>/dev/null || echo "")
if [ -n "$WS_GUID" ] \
   && workspace_table_exists "$WS_GUID" "AzureDiagnostics" \
   && workspace_table_exists "$WS_GUID" "StorageBlobLogs"; then
  ENABLE_RESOURCE_RULES="true"
  info "Resource-rule telemetry present (AzureDiagnostics + StorageBlobLogs), enabling decoy KV/storage rules"
else
  ENABLE_RESOURCE_RULES="false"
  info "Resource-rule telemetry not yet ingested, skipping decoy KV/storage rules (re-run detection.sh later)"
fi

# Decoy VM run-command rule: needs the AzureActivity table present (populated by the Activity
# connector). Auto-enable once it exists.
if [ -n "$WS_GUID" ] && workspace_table_exists "$WS_GUID" "AzureActivity"; then
  ENABLE_VM_RUNCOMMAND_RULE="true"
  info "AzureActivity present, enabling the decoy VM run-command rule ($DECOY_VM_NAME)"
else
  ENABLE_VM_RUNCOMMAND_RULE="false"
  info "AzureActivity not yet ingested, skipping the VM run-command rule (re-run detection.sh later)"
fi

# Incident grouping lookback. Default PT5H suits production; set GROUPING_LOOKBACK=PT5M during
# testing so each trigger opens its own incident (and re-fires the playbooks) instead of folding
# into a recent one.
GROUPING_LOOKBACK="${GROUPING_LOOKBACK:-PT5H}"

info "Deploying detection (Sentinel + analytics rules) to $MGMT_RG (grouping lookback: $GROUPING_LOOKBACK)"
az deployment group create \
  --resource-group "$MGMT_RG" \
  --template-file "$REPO_ROOT/bicep/detection.bicep" \
  --parameters workspaceName="$WORKSPACE" \
               decoyKeyVaultName="$KV_NAME" decoyStorageAccountName="$SA_NAME" \
               decoyVmName="$DECOY_VM_NAME" \
               enableResourceRules="$ENABLE_RESOURCE_RULES" \
               enableVmRunCommandRule="$ENABLE_VM_RUNCOMMAND_RULE" \
               reachableAppId="$REACHABLE_APP_ID" reachableAppObjectId="$REACHABLE_APP_OBJECT_ID" reachableSpObjectId="$REACHABLE_SP_ID" \
               enableReachableEdgeRules="$ENABLE_REACHABLE_EDGE_RULES" \
               emergencyAccessUpn="$EMERGENCY_UPN" \
               privilegedAuthAllowlistIds="$PRIV_AUTH_ALLOWLIST_JSON" \
               groupingLookbackDuration="$GROUPING_LOOKBACK" \
  -o none
ok "detection deployed (resource: $ENABLE_RESOURCE_RULES, reachable-edge: $ENABLE_REACHABLE_EDGE_RULES, vm-runcommand: $ENABLE_VM_RUNCOMMAND_RULE)"

echo
ok "Detection is live. Verify:"
echo "  - Defender portal: Microsoft Sentinel > Configuration > Analytics > Active rules -> filter 'Honeypot:'"
echo "  - CLI: ./tests/verify_detection.sh $MGMT_RG $WORKSPACE"
