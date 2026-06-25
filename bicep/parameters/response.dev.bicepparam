using '../response.bicep'

param env = 'dev'
param location = 'westeurope'
param regionCode = 'weu'
param marker = 'hp'

param workspaceName = 'log-hp-dev-weu'

// PRIMARY SAFETY GUARD: the decoy identities the disable-user playbook may act on (lure +
// personas, from inventory.identity). The playbook disables an account ONLY if it is in this
// list, so it can never disable a real account. deploy/04_response.sh injects this from the
// inventory at deploy time; the value here is only for static validation.
param decoyObjectIds = []

// CRITICAL SAFETY: object IDs that must never be disabled (real break-glass GA, the agent).
// Injected by deploy/04_response.sh from inventory.allowlist.breakGlassObjectIds.
param allowlistObjectIds = []

// From the network deployment output (honeypotResourceGroupName -> full RG resource ID).
param honeypotResourceGroupId = '/subscriptions/REPLACE_SUB/resourceGroups/rg-core-prod-weu'

// Keep TRUE for the soak period; set false only once verified safe.
param dryRun = true
