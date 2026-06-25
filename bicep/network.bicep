metadata description = 'Network ORCHESTRATOR for the demo. Composes the two independent modules: production.bicep (the simulated existing environment — hub + representative production spoke) and honeypot.bicep (the product — the honeypot spoke). With deployProduction=true it builds the simulated production and deploys the honeypot alongside it. With deployProduction=false (a real tenant) it builds NOTHING for production and deploys only the honeypot against the supplied existing hub. The honeypot and production modules are also deployable standalone.'

targetScope = 'subscription'

@description('Environment short name.')
param env string = 'dev'

@description('Location for all network resources.')
param location string = 'westeurope'

@description('Region short code.')
param regionCode string = 'weu'

@description('Honeypot marker for the internal plane (hub).')
param marker string = 'hp'

@description('Log Analytics workspace resource ID (from the foundation deployment).')
param workspaceId string

@description('Tenant ID for the decoy Key Vault.')
param tenantId string = subscription().tenantId

@description('PRODUCTION-SIMULATION switch. false (default, real deployment): build NO production; deploy the honeypot alongside the existing hub passed via existingHubVnetId. true (demo): build the simulated production (hub + representative spoke) and deploy the honeypot alongside it.')
param deployProduction bool = false

@description('Resource ID of a pre-existing (production) hub VNet. REQUIRED when deployProduction=false.')
param existingHubVnetId string = ''

@description('Hub VNet address space (production-sim only).')
param hubAddressPrefix string = '10.0.0.0/16'

@description('Representative production spoke name prefix (production-sim only).')
param prodSpokeNamePrefix string = 'erp-prod'

@description('Representative production spoke address space (production-sim only). Also what the honeypot denies egress toward when deployProduction=true.')
param prodSpokeAddressPrefix string = '10.10.0.0/16'

@description('Globally-unique production storage account name (production-sim only).')
param prodStorageAccountName string = ''

@description('Production address space the honeypot denies egress toward. Used directly when deployProduction=false; in production-sim mode it is taken from the built production spoke.')
param productionAddressPrefixes array = ['10.10.0.0/16']

@description('Decoy spoke name prefix. Production-looking, NO honeypot marker.')
param spokeNamePrefix string = 'core-prod'

@description('Decoy spoke VNet address space.')
param spokeAddressPrefix string = '10.20.0.0/16'

@description('Include the decoy VM (SSH lure) + the App Gateway that fronts it. Off by default.')
param includeDecoyVm bool = false

@description('SSH public key for the decoy VM. Required only when includeDecoyVm is true.')
@secure()
param decoyVmSshPublicKey string = ''

@description('Base64 cloud-init planting fake-prod breadcrumbs on the decoy VM.')
param decoyVmCustomDataBase64 string = ''

@description('Globally-unique decoy Key Vault name.')
param keyVaultName string

@description('Globally-unique decoy storage account name.')
param storageAccountName string

// PRODUCTION (simulated environment) — built only in demo mode.
module production 'production.bicep' = if (deployProduction) {
  name: 'production-sim'
  params: {
    env: env
    location: location
    regionCode: regionCode
    marker: marker
    hubAddressPrefix: hubAddressPrefix
    prodSpokeNamePrefix: prodSpokeNamePrefix
    prodSpokeAddressPrefix: prodSpokeAddressPrefix
    prodStorageAccountName: prodStorageAccountName
  }
}

// The hub the honeypot deploys alongside: the simulated one (demo) or the supplied real one.
var effectiveHubVnetId = deployProduction ? production!.outputs.hubVnetId : existingHubVnetId
// The production range the honeypot denies egress toward.
var effectiveProductionPrefixes = deployProduction ? [production!.outputs.productionAddressPrefix] : productionAddressPrefixes

// HONEYPOT (the product) — always deployed; consumes the hub as an input.
module honeypot 'honeypot.bicep' = {
  name: 'honeypot'
  params: {
    location: location
    regionCode: regionCode
    workspaceId: workspaceId
    tenantId: tenantId
    hubVnetId: effectiveHubVnetId
    productionAddressPrefixes: effectiveProductionPrefixes
    spokeNamePrefix: spokeNamePrefix
    spokeAddressPrefix: spokeAddressPrefix
    includeDecoyVm: includeDecoyVm
    decoyVmSshPublicKey: decoyVmSshPublicKey
    decoyVmCustomDataBase64: decoyVmCustomDataBase64
    keyVaultName: keyVaultName
    storageAccountName: storageAccountName
  }
}

@description('Whether the simulated production environment was built.')
output deployProduction bool = deployProduction

@description('Contract check: true if the honeypot was given a hub to deploy alongside.')
output hubContractSatisfied bool = honeypot.outputs.hubContractSatisfied

@description('The hub VNet the honeypot peers to (simulated or supplied).')
output effectiveHubVnetId string = effectiveHubVnetId

@description('Honeypot spoke resource group name.')
output honeypotResourceGroupName string = honeypot.outputs.honeypotResourceGroupName

@description('Decoy spoke VNet resource ID.')
output honeypotVnetId string = honeypot.outputs.honeypotVnetId

@description('Internet-facing decoy App Gateway public IP.')
output appGatewayPublicIp string = honeypot.outputs.appGatewayPublicIp

@description('Decoy VM resource ID.')
output decoyVmId string = honeypot.outputs.decoyVmId

@description('Decoy Key Vault resource ID.')
output keyVaultId string = honeypot.outputs.keyVaultId

@description('Decoy storage account resource ID.')
output storageAccountId string = honeypot.outputs.storageAccountId
