metadata description = 'Representative PRODUCTION spoke — a lightweight but REAL (non-decoy) workload that simulates the customer existing environment, so the honeypot can be demonstrated deploying alongside genuine production. Contains a VNet + NSG + a storage account that looks like an ordinary line-of-business workload. It is NOT a honeypot: no breadcrumbs, no decoy diagnostics-for-detection, no tripwires. Its address space is what the honeypot spoke denies egress toward. Built only by the production-simulation stage.'

@description('Production workload name prefix (production-looking). e.g. "erp-prod".')
param namePrefix string

@description('Deployment location.')
param location string

@description('Production spoke VNet address space (the range the honeypot denies egress toward).')
param vnetAddressPrefix string = '10.10.0.0/16'

@description('Hub VNet resource ID for monitoring peering.')
param hubVnetId string

@description('Globally-unique production storage account name (3-24 lowercase alphanumeric).')
param storageAccountName string

@description('Resource tags (genuine production tags — this is not a decoy).')
param tags object = {}

var workloadSubnetPrefix = cidrSubnet(vnetAddressPrefix, 24, 0)

// Ordinary workload NSG: allow intra-VNet, deny direct inbound from the internet. Nothing
// special — this is meant to look like a normal production subnet.
module workloadNsg '../network/nsg.bicep' = {
  name: '${namePrefix}-nsg'
  params: {
    name: '${namePrefix}-nsg'
    location: location
    tags: tags
    securityRules: [
      {
        name: 'Allow-VNet-Inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: workloadSubnetPrefix
          destinationPortRange: '*'
        }
      }
      {
        name: 'Deny-Internet-Inbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

module vnet '../network/vnet.bicep' = {
  name: '${namePrefix}-vnet'
  params: {
    name: '${namePrefix}-vnet'
    location: location
    tags: tags
    addressPrefixes: [vnetAddressPrefix]
    subnets: [
      {
        name: 'workload-subnet'
        prefix: workloadSubnetPrefix
        nsgId: workloadNsg.outputs.id
      }
    ]
  }
}

// Production spoke -> hub peering (monitoring transit only).
module peerToHub '../network/peering.bicep' = if (!empty(hubVnetId)) {
  name: '${namePrefix}-to-hub'
  params: {
    localVnetName: vnet.outputs.name
    remoteVnetId: hubVnetId
    peeringName: 'to-hub'
  }
}

// A plausible production storage account (a real, ordinary workload resource — NOT a decoy).
resource sa 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

output vnetId string = vnet.outputs.id
output vnetName string = vnet.outputs.name
output addressPrefix string = vnetAddressPrefix
output storageAccountId string = sa.id
