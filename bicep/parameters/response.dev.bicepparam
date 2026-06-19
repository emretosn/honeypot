using '../response.bicep'

param env = 'dev'
param location = 'westeurope'
param regionCode = 'weu'
param marker = 'hp'

param workspaceName = 'log-hp-dev-weu'

// CRITICAL SAFETY: object IDs that must never be disabled (real break-glass GA, the agent).
// Fill from inventory/decoy-inventory.json allowlist.breakGlassObjectIds.
param allowlistObjectIds = []

// From the network deployment output (honeypotResourceGroupName -> full RG resource ID).
param honeypotResourceGroupId = '/subscriptions/REPLACE_SUB/resourceGroups/rg-core-prod-weu'

// Keep TRUE for the soak period; set false only once verified safe.
param dryRun = true
