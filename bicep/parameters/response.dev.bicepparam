using '../response.bicep'

param location = 'westeurope'
param regionCode = 'weu'

// The management RG that holds the Log Analytics workspace + Sentinel. The automation rules are
// created here cross-scope; the playbooks themselves deploy into the production-plausible playbook
// RG (rg-core-ops-*, set by the --resource-group of deploy/response.sh).
param mgmtResourceGroupName = 'rg-hp-dev-weu-mgmt'

param workspaceName = 'log-hp-dev-weu'

// PRIMARY SAFETY GUARD: the decoy identities the disable-user playbook may act on (lure +
// personas, from inventory.identity). The playbook disables an account ONLY if it is in this
// list, so it can never disable a real account. deploy/response.sh injects this from the
// inventory at deploy time; the value here is only for static validation.
param decoyObjectIds = []

// Decoy SERVICE PRINCIPAL object IDs (the reachable decoy SP). Disabled via /servicePrincipals.
// Injected by deploy/response.sh from inventory.identity.reachableApp.spObjectId.
param decoySpObjectIds = []

// CRITICAL SAFETY: object IDs that must never be disabled (real break-glass GA, the agent).
// Injected by deploy/response.sh from inventory.allowlist.breakGlassObjectIds.
param allowlistObjectIds = []

// From the network deployment output (honeypotResourceGroupName -> full RG resource ID).
param honeypotResourceGroupId = '/subscriptions/REPLACE_SUB/resourceGroups/rg-core-prod-weu'

// Keep TRUE for the soak period; set false only once verified safe.
param dryRun = true
