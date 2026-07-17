metadata description = 'Honeypot spoke, the isolated, production-looking decoy network. NOTHING is exposed to the internet (this is an internal-attacker honeypot): the spoke holds a private decoy VM, a decoy Key Vault and a decoy storage account, reachable to an internal attacker only via the taken-over reachable SP (Owner of the decoy RG). Egress to production is DENIED (containment). Peers to the hub for monitoring only; never to the production spoke.'

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

var workloadSubnetPrefix = cidrSubnet(vnetAddressPrefix, 24, 0)

// NSG for the workload subnet: allow SSH only from within the VNet (internal admin/monitoring
// realism, never from the internet, there is no public ingress), and DENY egress to production
// (containment). The decoy VM is reachable to an internal attacker only via the taken-over SP
// (Owner of the decoy RG -> run-command), which is exactly what the VM run-command rule detects.
module workloadNsg '../network/nsg.bicep' = {
  name: '${namePrefix}-workload-nsg'
  params: {
    name: '${namePrefix}-workload-nsg'
    location: location
    tags: tags
    securityRules: [
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

// Single workload subnet (hosts the decoy VM when enabled; otherwise stays empty). No App Gateway
// subnet: the spoke exposes NOTHING to the internet, this is an internal-attacker honeypot.
var spokeSubnets = [
  {
    name: 'workload-subnet'
    prefix: workloadSubnetPrefix
    nsgId: workloadNsg.outputs.id
  }
]

module vnet '../network/vnet.bicep' = {
  name: '${namePrefix}-vnet'
  params: {
    name: '${namePrefix}-vnet'
    location: location
    tags: tags
    addressPrefixes: [vnetAddressPrefix]
    subnets: spokeSubnets
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

// Private decoy VM (no public IP). Reachable to an internal attacker only via the SP takeover chain.
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
output decoyVmId string = decoyVm.outputs.id
output keyVaultId string = keyVault.outputs.id
output storageAccountId string = storage.outputs.id
