metadata description = 'Network ORCHESTRATOR. Builds a self-contained honeypot environment: production.bicep (a simulated existing environment, hub + representative production spoke) and honeypot.bicep (the product, the honeypot spoke) deployed alongside it. Portable: stands up the whole hub-spoke in any subscription with no external inputs. The honeypot spoke peers to the built hub for monitoring and denies egress to the production spoke.'

targetScope = 'subscription'

@description('Location for all network resources.')
param location string = 'westeurope'

@description('Region short code.')
param regionCode string = 'weu'

@description('Log Analytics workspace resource ID (from the foundation deployment).')
param workspaceId string

@description('Tenant ID for the decoy Key Vault.')
param tenantId string = subscription().tenantId

@description('Hub VNet address space.')
param hubAddressPrefix string = '10.0.0.0/16'

@description('Representative production spoke name prefix.')
param prodSpokeNamePrefix string = 'erp-prod'

@description('Representative production spoke address space. The honeypot denies egress toward it.')
param prodSpokeAddressPrefix string = '10.10.0.0/16'

@description('Globally-unique production storage account name.')
param prodStorageAccountName string = ''

@description('Decoy spoke name prefix. Production-looking, NO honeypot marker.')
param spokeNamePrefix string = 'core-prod'

@description('Decoy spoke VNet address space.')
param spokeAddressPrefix string = '10.20.0.0/16'

@description('SSH public key for the decoy VM admin user.')
@secure()
param decoyVmSshPublicKey string

@description('Base64 cloud-init planting fake-prod breadcrumbs on the decoy VM.')
param decoyVmCustomDataBase64 string = ''

@description('Globally-unique decoy Key Vault name.')
param keyVaultName string

@description('Globally-unique decoy storage account name.')
param storageAccountName string

// PRODUCTION (simulated existing environment), the hub the honeypot deploys alongside.
module production 'production.bicep' = {
  name: 'production-sim'
  params: {
    location: location
    regionCode: regionCode
    hubAddressPrefix: hubAddressPrefix
    prodSpokeNamePrefix: prodSpokeNamePrefix
    prodSpokeAddressPrefix: prodSpokeAddressPrefix
    prodStorageAccountName: prodStorageAccountName
  }
}

// HONEYPOT (the product), consumes the built hub as an input; denies egress to the built prod spoke.
module honeypot 'honeypot.bicep' = {
  name: 'honeypot'
  params: {
    location: location
    regionCode: regionCode
    workspaceId: workspaceId
    tenantId: tenantId
    hubVnetId: production.outputs.hubVnetId
    productionAddressPrefixes: [production.outputs.productionAddressPrefix]
    spokeNamePrefix: spokeNamePrefix
    spokeAddressPrefix: spokeAddressPrefix
    decoyVmSshPublicKey: decoyVmSshPublicKey
    decoyVmCustomDataBase64: decoyVmCustomDataBase64
    keyVaultName: keyVaultName
    storageAccountName: storageAccountName
  }
}

@description('The hub VNet the honeypot peers to.')
output hubVnetId string = production.outputs.hubVnetId

@description('Honeypot spoke resource group name.')
output honeypotResourceGroupName string = honeypot.outputs.honeypotResourceGroupName

@description('Decoy spoke VNet resource ID.')
output honeypotVnetId string = honeypot.outputs.honeypotVnetId

@description('Decoy VM resource ID.')
output decoyVmId string = honeypot.outputs.decoyVmId

@description('Decoy Key Vault resource ID.')
output keyVaultId string = honeypot.outputs.keyVaultId

@description('Decoy storage account resource ID.')
output storageAccountId string = honeypot.outputs.storageAccountId
