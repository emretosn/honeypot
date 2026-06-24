metadata description = 'Subscription-scope entrypoint for the hub-spoke network. Creates the hub VNet (internal plane) and the honeypot spoke (decoy plane, production-looking). The honeypot spoke is also deployable standalone against a pre-existing hub by passing existingHubVnetId. A minimal production spoke is optional and only for production-simulation realism.'

targetScope = 'subscription'

import * as naming from 'modules/naming/naming.bicep'

@description('Environment short name.')
param env string = 'dev'

@description('Location for all network resources.')
param location string = 'westeurope'

@description('Region short code for internal-plane names.')
param regionCode string = 'weu'

@description('Honeypot marker for the internal plane (hub). Never used on decoy spoke names.')
param marker string = 'hp'

@description('Log Analytics workspace resource ID (from the foundation deployment).')
param workspaceId string

@description('Tenant ID for the decoy Key Vault.')
param tenantId string = subscription().tenantId

@description('Hub VNet address space.')
param hubAddressPrefix string = '10.0.0.0/16'

@description('Production address space the honeypot must not reach (egress deny).')
param productionAddressPrefixes array = ['10.10.0.0/16']

@description('Production-simulation switch. false (default, HONEYPOT-ONLY mode): the platform creates NO hub and deploys the honeypot spoke alongside an EXISTING production hub supplied via existingHubVnetId — this is how the honeypot drops into a real hub-spoke. true (PRODUCTION-SIM mode): this project also stands up a lightweight simulated *production* environment (thin hub) so the honeypot can be demonstrated alongside it. A real deployment MUST use deployProduction=false and supply existingHubVnetId + workspaceId as inputs.')
param deployProduction bool = false

@description('Resource ID of a pre-existing (production) hub VNet to peer the honeypot spoke to (monitoring only). REQUIRED when deployProduction=false; ignored when deployProduction builds its own simulated hub.')
param existingHubVnetId string = ''

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

@description('Internal-plane tags (hub/management). Marker allowed.')
param internalTags object = {
  project: 'honeypot'
  plane: 'internal-mgmt'
  managedBy: 'iac'
}

@description('Decoy-plane tags. Honeypot ownership lives here, NOT in names.')
param decoyTags object = {
  environment: 'production'
  workload: 'core-services'
  managedBy: 'iac'
}

// PRODUCTION/HONEYPOT boundary: the hub belongs to the *production* environment, not the
// honeypot platform. The platform never creates it — only the production-simulation stage
// (deployProduction=true) does, and only if an existing production hub was not supplied. In
// honeypot-only mode the production hub MUST arrive as an input.
var createHub = deployProduction && empty(existingHubVnetId)

// Honeypot-only contract: a real deployment must supply the production hub it deploys
// alongside. Surfaced as an output so misconfiguration (deployProduction=false with no hub) is
// visible in deployment outputs and asserted by tests/verify_network.sh, without depending on
// experimental Bicep features.
var hubContractSatisfied = deployProduction || !empty(existingHubVnetId)
var hubRgName = 'rg-${naming.base(marker, env, regionCode)}-hub'
// Decoy spoke RG: production-looking name, no marker.
var spokeRgName = 'rg-${spokeNamePrefix}-${regionCode}'

resource hubRg 'Microsoft.Resources/resourceGroups@2024-03-01' = if (createHub) {
  name: hubRgName
  location: location
  tags: internalTags
}

module hubVnet 'modules/network/vnet.bicep' = if (createHub) {
  name: 'hub-vnet'
  scope: hubRg
  params: {
    name: 'vnet-${naming.base(marker, env, regionCode)}-hub'
    location: location
    tags: internalTags
    addressPrefixes: [hubAddressPrefix]
    subnets: [
      {
        name: 'monitoring-subnet'
        prefix: cidrSubnet(hubAddressPrefix, 24, 0)
        nsgId: ''
      }
    ]
  }
}

var effectiveHubVnetId = createHub ? hubVnet!.outputs.id : existingHubVnetId

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
    hubVnetId: effectiveHubVnetId
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

@description('Deployment mode: true if the production-simulation stage built a simulated hub, false if the honeypot consumed an existing production hub as an input.')
output deployProduction bool = deployProduction

@description('Honeypot-only contract check: must be true. False means deployProduction=false was deployed without an existingHubVnetId, so the spoke has no monitoring peering. tests/verify_network.sh asserts this is true.')
output hubContractSatisfied bool = hubContractSatisfied

@description('The production hub VNet the honeypot spoke peers to (created in production-sim mode, or the supplied input).')
output effectiveHubVnetId string = effectiveHubVnetId

@description('Decoy spoke VNet resource ID.')
output honeypotVnetId string = spoke.outputs.vnetId

@description('Internet-facing decoy App Gateway public IP.')
output appGatewayPublicIp string = spoke.outputs.appGatewayPublicIp

@description('Decoy VM resource ID — input to the response module isolation playbook.')
output decoyVmId string = spoke.outputs.decoyVmId

@description('Decoy Key Vault resource ID.')
output keyVaultId string = spoke.outputs.keyVaultId

@description('Decoy storage account resource ID.')
output storageAccountId string = spoke.outputs.storageAccountId
