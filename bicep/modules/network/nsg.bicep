metadata description = 'Network security group with explicit security rules. Used to make the honeypot spoke ingress-reachable but egress-to-production denied (containment).'

@description('NSG name.')
param name string

@description('Deployment location.')
param location string

@description('Security rules in priority order.')
param securityRules array = []

@description('Resource tags.')
param tags object = {}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    securityRules: securityRules
  }
}

output id string = nsg.id
output name string = nsg.name
