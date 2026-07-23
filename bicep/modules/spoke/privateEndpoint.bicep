metadata description = 'A private endpoint for a PaaS resource (Key Vault / storage) plus its private DNS zone group. Keeps the decoy KV/storage reachable only from inside the honeypot spoke VNet (over a private IP), never over a public data-plane endpoint. The spoke-linked private DNS zone lets the decoy VM resolve the private IP, so an internal attacker who has taken over the reachable SP loots the resource from the VM, which is exactly the intended contained path.'

@description('Private endpoint name.')
param name string

@description('Deployment location.')
param location string

@description('Subnet resource ID the private endpoint NIC attaches to (PE network policies must be Disabled on it).')
param subnetId string

@description('Resource ID of the PaaS resource to privately connect to (the decoy KV or storage account).')
param privateLinkServiceId string

@description('Private-link group ID of the target sub-resource: "vault" for Key Vault, "blob" for storage blob.')
param groupId string

@description('Resource ID of the private DNS zone that resolves this resource type (privatelink.vaultcore.azure.net / privatelink.blob.<suffix>).')
param privateDnsZoneId string

@description('Resource tags.')
param tags object = {}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${name}-conn'
        properties: {
          privateLinkServiceId: privateLinkServiceId
          groupIds: [groupId]
        }
      }
    ]
  }
}

resource dnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: groupId
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

output id string = privateEndpoint.id
