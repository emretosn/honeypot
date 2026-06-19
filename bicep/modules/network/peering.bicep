metadata description = 'One direction of a VNet peering. Call twice (hub->spoke and spoke->hub) to establish full peering. Spokes peer only to the hub for monitoring; spoke-to-spoke transit is never created, so the honeypot cannot reach production.'

@description('Name of the local VNet that owns this peering.')
param localVnetName string

@description('Resource ID of the remote VNet to peer with.')
param remoteVnetId string

@description('Peering resource name.')
param peeringName string

@description('Allow traffic forwarded from the remote VNet.')
param allowForwardedTraffic bool = false

@description('Allow the remote VNet to use this VNet gateway / route through it. Keep false for spokes (no transit).')
param allowGatewayTransit bool = false

@description('Use the remote VNet gateways.')
param useRemoteGateways bool = false

resource peering 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2023-11-01' = {
  name: '${localVnetName}/${peeringName}'
  properties: {
    remoteVirtualNetwork: {
      id: remoteVnetId
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: allowForwardedTraffic
    allowGatewayTransit: allowGatewayTransit
    useRemoteGateways: useRemoteGateways
  }
}

output id string = peering.id
