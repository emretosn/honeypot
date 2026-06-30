metadata description = 'PRODUCTION-SIMULATION composition (simulated existing environment). Stands up a thin hub VNet (internal/monitoring plane) and a representative, REAL production spoke, so the honeypot can be demonstrated deploying alongside genuine production. This is SIMULATION ONLY — a real customer already has these and the honeypot consumes them as inputs instead (see honeypot.bicep). Outputs the hub VNet ID and the production address prefix that the honeypot peers to / denies egress toward.'

targetScope = 'subscription'

@description('Location for all resources.')
param location string = 'westeurope'

@description('Region short code for resource names.')
param regionCode string = 'weu'

@description('Hub resource group name. Production-plausible: the honeypot spoke peers to this hub, so its resource id (incl. this name) is readable from the spoke — NO honeypot marker.')
param hubResourceGroupName string = 'rg-network-hub-${regionCode}'

@description('Hub VNet name. Production-plausible: visible to the spoke via the peering resource id — NO honeypot marker.')
param hubVnetName string = 'vnet-hub-${regionCode}'

@description('Hub VNet address space.')
param hubAddressPrefix string = '10.0.0.0/16'

@description('Representative production spoke name prefix (production-looking, a DIFFERENT workload from the honeypot decoy). e.g. "erp-prod".')
param prodSpokeNamePrefix string = 'erp-prod'

@description('Representative production spoke VNet address space. The honeypot denies egress toward this range.')
param prodSpokeAddressPrefix string = '10.10.0.0/16'

@description('Globally-unique production storage account name (3-24 lowercase alphanumeric).')
param prodStorageAccountName string

@description('Hub tags. Production-plausible (shared network infra). NO honeypot marker — the spoke can read the hub resource id via peering, so nothing here may reveal the honeypot.')
param hubTags object = {
  environment: 'production'
  workload: 'shared-network'
  managedBy: 'iac'
}

@description('Production-plane tags (genuine production — NOT a decoy).')
param productionTags object = {
  environment: 'production'
  workload: 'erp'
  managedBy: 'iac'
}

var prodRgName = 'rg-${prodSpokeNamePrefix}-${regionCode}'

resource hubRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: hubResourceGroupName
  location: location
  tags: hubTags
}

module hubVnet 'modules/network/vnet.bicep' = {
  name: 'hub-vnet'
  scope: hubRg
  params: {
    name: hubVnetName
    location: location
    tags: hubTags
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

resource prodRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: prodRgName
  location: location
  tags: productionTags
}

module prodSpoke 'modules/production/productionSpoke.bicep' = {
  name: 'production-spoke'
  scope: prodRg
  params: {
    namePrefix: prodSpokeNamePrefix
    location: location
    tags: productionTags
    vnetAddressPrefix: prodSpokeAddressPrefix
    hubVnetId: hubVnet.outputs.id
    storageAccountName: prodStorageAccountName
  }
}

@description('Hub VNet resource ID — pass to honeypot.bicep as hubVnetId so the honeypot peers to it.')
output hubVnetId string = hubVnet.outputs.id

@description('Production spoke address prefix — pass to honeypot.bicep as productionAddressPrefixes so the honeypot denies egress toward real production.')
output productionAddressPrefix string = prodSpoke.outputs.addressPrefix

@description('Production spoke VNet resource ID.')
output productionVnetId string = prodSpoke.outputs.vnetId

@description('Production resource group name.')
output productionResourceGroupName string = prodRg.name
