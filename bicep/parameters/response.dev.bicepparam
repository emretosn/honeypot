using '../response.bicep'

param location = 'westeurope'
param regionCode = 'weu'

// The playbooks, workspace + Sentinel and the automation rules all live in the same production-
// plausible management/operations RG (rg-core-ops-*, no honeypot marker), set by the
// --resource-group of deploy/response.sh.
param workspaceName = 'log-core-ops-weu'

// PRIMARY SAFETY GUARD: the decoy identities the disable-user playbook may act on (the emergency-
// access decoy, from inventory.identity). The playbook disables an account ONLY if it is in this
// list, so it can never disable a real account. deploy/response.sh injects this from the
// inventory at deploy time; the value here is only for static validation.
param decoyObjectIds = []

// Decoy SERVICE PRINCIPAL object IDs (the reachable decoy SP). Disabled via /servicePrincipals.
// Injected by deploy/response.sh from inventory.identity.reachableApp.spObjectId.
param decoySpObjectIds = []

// CRITICAL SAFETY: object IDs that must never be disabled. deploy/response.sh injects break-glass
// (from inventory.allowlist.breakGlassObjectIds) PLUS every current Global Administrator (enumerated
// live at deploy time).
param allowlistObjectIds = []

// From the network deployment output (honeypotResourceGroupName -> full RG resource ID).
param honeypotResourceGroupId = '/subscriptions/REPLACE_SUB/resourceGroups/rg-core-prod-weu'
