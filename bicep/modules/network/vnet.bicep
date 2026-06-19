metadata description = 'A virtual network with subnets. Reused for hub, production spoke and honeypot spoke. NSG association is handled by the caller so each subnet can have role-specific rules.'

@description('VNet name. Decoy-plane names must be production-like with no honeypot marker.')
param name string

@description('Deployment location.')
param location string

@description('Address space CIDRs.')
param addressPrefixes array

@description('Subnets: list of { name, prefix, nsgId? }. nsgId empty string = no NSG.')
param subnets array

@description('Resource tags.')
param tags object = {}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: addressPrefixes
    }
    subnets: [
      for s in subnets: {
        name: s.name
        properties: {
          addressPrefix: s.prefix
          networkSecurityGroup: empty(s.?nsgId ?? '') ? null : {
            id: s.nsgId
          }
        }
      }
    ]
  }
}

output id string = vnet.id
output name string = vnet.name
output subnetIds object = toObject(vnet.properties.subnets, s => s.name, s => s.id)
