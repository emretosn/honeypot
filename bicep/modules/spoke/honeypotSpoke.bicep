metadata description = 'Honeypot spoke — the isolated, production-looking decoy network. Ingress to the decoy surface is allowed; egress to production address space is DENIED (containment). Contains an Application Gateway fronting a decoy app, a decoy VM with controlled SSH and planted breadcrumbs, a decoy Key Vault and storage account. Peers to the hub for monitoring only; never to the production spoke.'

@description('Resource name prefix for the spoke. Decoy-plane: production-like, NO honeypot marker. e.g. "core-prod".')
param namePrefix string

@description('Deployment location.')
param location string

@description('Spoke VNet address space.')
param vnetAddressPrefix string = '10.20.0.0/16'

@description('Production address space(s) the spoke must NOT be able to reach (egress deny).')
param productionAddressPrefixes array = ['10.10.0.0/16']

@description('Hub VNet resource ID for monitoring peering.')
param hubVnetId string

@description('Log Analytics workspace resource ID for diagnostics.')
param workspaceId string

@description('Tenant ID (for Key Vault).')
param tenantId string

@description('SSH public key for the decoy VM admin user.')
@secure()
param decoyVmSshPublicKey string

@description('Base64 cloud-init planting fake-prod breadcrumbs on the decoy VM.')
param decoyVmCustomDataBase64 string = ''

@description('Globally-unique decoy Key Vault name (3-24 chars).')
param keyVaultName string

@description('Globally-unique decoy storage account name (3-24 lowercase alphanumeric).')
param storageAccountName string

@description('Resource tags. Honeypot ownership lives in a tag the decoy-scoped identity cannot read, never in names.')
param tags object = {}

var appGwSubnetPrefix = cidrSubnet(vnetAddressPrefix, 24, 0)
var workloadSubnetPrefix = cidrSubnet(vnetAddressPrefix, 24, 1)

// NSG for the workload subnet: allow ingress from the App Gateway subnet and SSH; deny
// egress to production; allow egress to internet for realism (sinkhole later if desired).
module workloadNsg '../network/nsg.bicep' = {
  name: '${namePrefix}-workload-nsg'
  params: {
    name: '${namePrefix}-workload-nsg'
    location: location
    tags: tags
    securityRules: [
      {
        name: 'Allow-AppGw-Inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appGwSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: workloadSubnetPrefix
          destinationPortRanges: ['80', '22']
        }
      }
      {
        name: 'Allow-VNet-SSH-Inbound'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: workloadSubnetPrefix
          destinationPortRange: '22'
        }
      }
      {
        name: 'Deny-Egress-To-Production'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefixes: productionAddressPrefixes
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// App Gateway subnet NSG: allow internet HTTP in + the GatewayManager ports App Gateway v2 requires.
module appGwNsg '../network/nsg.bicep' = {
  name: '${namePrefix}-appgw-nsg'
  params: {
    name: '${namePrefix}-appgw-nsg'
    location: location
    tags: tags
    securityRules: [
      {
        name: 'Allow-Internet-HTTP-Inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: appGwSubnetPrefix
          destinationPortRange: '80'
        }
      }
      {
        name: 'Allow-GatewayManager-Inbound'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'GatewayManager'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '65200-65535'
        }
      }
      {
        name: 'Deny-Egress-To-Production'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefixes: productionAddressPrefixes
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
        name: 'appgw-subnet'
        prefix: appGwSubnetPrefix
        nsgId: appGwNsg.outputs.id
      }
      {
        name: 'workload-subnet'
        prefix: workloadSubnetPrefix
        nsgId: workloadNsg.outputs.id
      }
    ]
  }
}

// Spoke -> hub peering (monitoring only; no gateway transit, no spoke-to-spoke).
module peerToHub '../network/peering.bicep' = if (!empty(hubVnetId)) {
  name: '${namePrefix}-to-hub'
  params: {
    localVnetName: vnet.outputs.name
    remoteVnetId: hubVnetId
    peeringName: 'to-hub'
  }
}

module decoyVm '../spoke/decoyVm.bicep' = {
  name: '${namePrefix}-decoy-vm'
  params: {
    name: '${namePrefix}-app01'
    location: location
    tags: tags
    subnetId: vnet.outputs.subnetIds['workload-subnet']
    adminSshPublicKey: decoyVmSshPublicKey
    customDataBase64: decoyVmCustomDataBase64
  }
}

module appGw '../spoke/appGateway.bicep' = {
  name: '${namePrefix}-appgw'
  params: {
    name: '${namePrefix}-appgw'
    location: location
    tags: tags
    subnetId: vnet.outputs.subnetIds['appgw-subnet']
    backendIp: decoyVm.outputs.privateIp
    workspaceId: workspaceId
  }
}

module keyVault '../spoke/keyVault.bicep' = {
  name: '${namePrefix}-kv'
  params: {
    name: keyVaultName
    location: location
    tags: tags
    tenantId: tenantId
    workspaceId: workspaceId
  }
}

module storage '../spoke/storage.bicep' = {
  name: '${namePrefix}-st'
  params: {
    name: storageAccountName
    location: location
    tags: tags
    workspaceId: workspaceId
  }
}

output vnetId string = vnet.outputs.id
output vnetName string = vnet.outputs.name
output appGatewayPublicIp string = appGw.outputs.publicIp
output decoyVmId string = decoyVm.outputs.id
output keyVaultId string = keyVault.outputs.id
output storageAccountId string = storage.outputs.id
