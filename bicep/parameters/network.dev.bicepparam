using '../network.bicep'

param env = 'dev'
param location = 'westeurope'
param regionCode = 'weu'
param marker = 'hp'

// PRODUCTION-SIM stage: this project stands up a lightweight simulated *production*
// environment (thin hub) so the honeypot can be demonstrated deploying alongside it. A REAL
// deployment sets deployProduction=false and supplies existingHubVnetId (the customer's
// production hub) instead.
param deployProduction = true
param existingHubVnetId = ''

// From the foundation deployment output (logAnalyticsWorkspaceId).
param workspaceId = '/subscriptions/REPLACE_SUB/resourceGroups/rg-hp-dev-weu-mgmt/providers/Microsoft.OperationalInsights/workspaces/log-hp-dev-weu'

// Production-looking decoy spoke (NO honeypot marker). Names must look real to an attacker.
param spokeNamePrefix = 'core-prod'
param spokeAddressPrefix = '10.20.0.0/16'
param productionAddressPrefixes = ['10.10.0.0/16']

// Globally-unique, production-looking decoy resource names (fill with unique suffixes).
param keyVaultName = 'kv-core-prod-REPLACE'
param storageAccountName = 'stcoreprodREPLACE'

// SSH public key for the decoy VM (replace with your test key).
param decoyVmSshPublicKey = 'ssh-rsa REPLACE'

// Base64 of bicep/assets/decoy-cloud-init.yaml:
//   base64 -w0 bicep/assets/decoy-cloud-init.yaml
param decoyVmCustomDataBase64 = ''
