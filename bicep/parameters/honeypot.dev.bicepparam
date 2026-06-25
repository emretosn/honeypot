using '../honeypot.bicep'

// REAL/standalone deployment of the honeypot ALONGSIDE an existing production hub-spoke.
// Supply the customer's hub VNet id + workspace + production address range as INPUTS.
param location = 'westeurope'
param regionCode = 'weu'

param workspaceId = '/subscriptions/REPLACE_SUB/resourceGroups/rg-hp-dev-weu-mgmt/providers/Microsoft.OperationalInsights/workspaces/log-hp-dev-weu'

// REQUIRED: the existing production hub the honeypot deploys alongside.
param hubVnetId = '/subscriptions/REPLACE_SUB/resourceGroups/REPLACE_HUB_RG/providers/Microsoft.Network/virtualNetworks/REPLACE_HUB_VNET'

// The production address space(s) the honeypot denies egress toward (containment).
param productionAddressPrefixes = ['10.10.0.0/16']

// Honeypot spoke (production-looking decoy names, NO honeypot marker).
param spokeNamePrefix = 'core-prod'
param spokeAddressPrefix = '10.20.0.0/16'
param keyVaultName = 'kv-core-prod-136d'
param storageAccountName = 'stcoreprod32548272'

param includeDecoyVm = false
