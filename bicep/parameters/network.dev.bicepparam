using '../network.bicep'

param env = 'dev'
param location = 'westeurope'
param regionCode = 'weu'
param marker = 'hp'

// PRODUCTION-SIM stage: stand up a lightweight simulated *production* hub so the honeypot can
// be demonstrated deploying alongside it. A REAL deployment sets deployProduction=false and
// supplies existingHubVnetId (the customer's production hub) instead.
param deployProduction = true
param existingHubVnetId = ''

// From the foundation deployment output. deploy/05_network.sh fills the subscription id for you.
param workspaceId = '/subscriptions/01169db8-9786-45a8-8878-de556ca253c4/resourceGroups/rg-hp-dev-weu-mgmt/providers/Microsoft.OperationalInsights/workspaces/log-hp-dev-weu'

// Production-looking decoy spoke (NO honeypot marker). Names must look real to an attacker.
param spokeNamePrefix = 'core-prod'
param spokeAddressPrefix = '10.20.0.0/16'
param productionAddressPrefixes = ['10.10.0.0/16']

// Globally-unique, production-looking decoy resource names. Change the suffixes if taken.
param keyVaultName = 'kv-core-prod-136d'
param storageAccountName = 'stcoreprod32548272'

// Decoy VM (SSH lure) + the App Gateway that fronts it. OFF by default: the spoke then exposes
// only the decoy Key Vault + storage (the resource tripwires), needs no SSH key, and skips the
// slow App Gateway provision. Set to true (and supply decoyVmSshPublicKey) to add the SSH lure.
param includeDecoyVm = false
// param decoyVmSshPublicKey = 'ssh-rsa AAAA...'   // required only when includeDecoyVm = true
// param decoyVmCustomDataBase64 = '...'           // base64 -w0 bicep/assets/decoy-cloud-init.yaml
