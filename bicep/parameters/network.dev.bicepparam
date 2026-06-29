using '../network.bicep'

param env = 'dev'
param location = 'westeurope'
param regionCode = 'weu'
param marker = 'hp'

// From the foundation deployment output. deploy/05_network.sh fills the subscription id for you.
param workspaceId = '/subscriptions/REPLACE_SUB/resourceGroups/rg-hp-dev-weu-mgmt/providers/Microsoft.OperationalInsights/workspaces/log-hp-dev-weu'

// DEMO: build the simulated production (hub + representative production spoke) and deploy the
// honeypot alongside it. A REAL deployment sets deployProduction=false and supplies
// existingHubVnetId (the customer's production hub) instead.
param deployProduction = true
param existingHubVnetId = ''

// Simulated production environment (production-sim only).
param hubAddressPrefix = '10.0.0.0/16'
param prodSpokeNamePrefix = 'erp-prod'
param prodSpokeAddressPrefix = '10.10.0.0/16'
param prodStorageAccountName = 'sterpprod32548273'

// Honeypot spoke (the product). Production-looking decoy names, NO honeypot marker.
param spokeNamePrefix = 'core-prod'
param spokeAddressPrefix = '10.20.0.0/16'
param productionAddressPrefixes = ['10.10.0.0/16']
param keyVaultName = 'kv-core-prod-136d'
param storageAccountName = 'stcoreprod32548272'

// Decoy VM (SSH lure) + App Gateway. OFF by default: spoke exposes only decoy KV + storage.
param includeDecoyVm = false
// param decoyVmSshPublicKey = 'ssh-rsa AAAA...'   // required only when includeDecoyVm = true
// param decoyVmCustomDataBase64 = '...'           // base64 -w0 bicep/assets/decoy-cloud-init.yaml
