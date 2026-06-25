metadata description = 'HONEYPOT composition (the product). Deploys the isolated honeypot spoke (decoy Key Vault + storage, optional SSH-lure VM/App Gateway) ALONGSIDE an existing production hub-spoke. The hub is consumed as an INPUT (hubVnetId) — this template never creates a hub or any production resource, so it drops cleanly into a real tenant. Reusable: instantiate against any hub by supplying its VNet ID. Egress to the production address space is denied; the spoke peers to the hub for monitoring only.'

targetScope = 'subscription'

@description('Location for the honeypot spoke.')
param location string = 'westeurope'

@description('Region short code.')
param regionCode string = 'weu'

@description('Log Analytics workspace resource ID (from the foundation deployment) for decoy diagnostics.')
param workspaceId string

@description('Tenant ID for the decoy Key Vault.')
param tenantId string = subscription().tenantId

@description('Resource ID of the (production) hub VNet to peer to for monitoring. REQUIRED — this is the existing hub the honeypot deploys alongside.')
param hubVnetId string

@description('Production address space(s) the honeypot must NOT reach (egress deny / containment).')
param productionAddressPrefixes array = ['10.10.0.0/16']

@description('Decoy spoke name prefix. Production-looking, NO honeypot marker. e.g. "core-prod".')
param spokeNamePrefix string = 'core-prod'

@description('Decoy spoke VNet address space.')
param spokeAddressPrefix string = '10.20.0.0/16'

@description('Include the decoy VM (SSH lure) + the App Gateway that fronts it. Off by default: the spoke exposes only the decoy Key Vault + storage, needs no SSH key, and skips the slow App Gateway provision.')
param includeDecoyVm bool = false

@description('SSH public key for the decoy VM admin user. Required only when includeDecoyVm is true.')
@secure()
param decoyVmSshPublicKey string = ''

@description('Base64 cloud-init planting fake-prod breadcrumbs on the decoy VM.')
param decoyVmCustomDataBase64 string = ''

@description('Globally-unique decoy Key Vault name (3-24 chars, production-looking).')
param keyVaultName string

@description('Globally-unique decoy storage account name (3-24 lowercase alphanumeric, production-looking).')
param storageAccountName string

@description('Decoy-plane tags. Honeypot ownership lives here, NOT in names.')
param decoyTags object = {
  environment: 'production'
  workload: 'core-services'
  managedBy: 'iac'
}

// Contract: the honeypot must be told which hub it deploys alongside. Surfaced as an output
// asserted by tests/verify_network.sh, without depending on experimental Bicep assertions.
var hubContractSatisfied = !empty(hubVnetId)

// Decoy spoke RG: production-looking name, no marker.
var spokeRgName = 'rg-${spokeNamePrefix}-${regionCode}'

resource spokeRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: spokeRgName
  location: location
  tags: decoyTags
}

module spoke 'modules/spoke/honeypotSpoke.bicep' = {
  name: 'honeypot-spoke'
  scope: spokeRg
  params: {
    namePrefix: spokeNamePrefix
    location: location
    tags: decoyTags
    vnetAddressPrefix: spokeAddressPrefix
    productionAddressPrefixes: productionAddressPrefixes
    hubVnetId: hubVnetId
    workspaceId: workspaceId
    tenantId: tenantId
    includeDecoyVm: includeDecoyVm
    decoyVmSshPublicKey: decoyVmSshPublicKey
    decoyVmCustomDataBase64: decoyVmCustomDataBase64
    keyVaultName: keyVaultName
    storageAccountName: storageAccountName
  }
}

@description('Honeypot spoke resource group name.')
output honeypotResourceGroupName string = spokeRg.name

@description('Honeypot-only contract check: must be true. False means no hubVnetId was supplied, so the spoke has no monitoring peering.')
output hubContractSatisfied bool = hubContractSatisfied

@description('The hub VNet the honeypot spoke peers to.')
output hubVnetId string = hubVnetId

@description('Decoy spoke VNet resource ID.')
output honeypotVnetId string = spoke.outputs.vnetId

@description('Internet-facing decoy App Gateway public IP (empty when the VM lure is disabled).')
output appGatewayPublicIp string = spoke.outputs.appGatewayPublicIp

@description('Decoy VM resource ID (empty when the VM lure is disabled).')
output decoyVmId string = spoke.outputs.decoyVmId

@description('Decoy Key Vault resource ID.')
output keyVaultId string = spoke.outputs.keyVaultId

@description('Decoy storage account resource ID.')
output storageAccountId string = spoke.outputs.storageAccountId
