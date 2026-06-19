metadata description = 'Application Gateway fronting the decoy app — the internet-facing ingress that makes the honeypot spoke look like a real published workload. Standard_v2 small. Routes to the decoy VM private IP backend.'

@description('App Gateway name (decoy-plane: production-like, no honeypot marker).')
param name string

@description('Deployment location.')
param location string

@description('Subnet resource ID dedicated to the Application Gateway.')
param subnetId string

@description('Backend target private IP (the decoy VM).')
param backendIp string

@description('Log Analytics workspace resource ID for diagnostics.')
param workspaceId string

@description('Resource tags.')
param tags object = {}

resource pip 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${name}-pip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

var agwId = resourceId('Microsoft.Network/applicationGateways', name)

resource agw 'Microsoft.Network/applicationGateways@2023-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'Standard_v2'
      tier: 'Standard_v2'
      capacity: 1
    }
    gatewayIPConfigurations: [
      {
        name: 'appGatewayIpConfig'
        properties: {
          subnet: {
            id: subnetId
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'appGatewayFrontendIP'
        properties: {
          publicIPAddress: {
            id: pip.id
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port80'
        properties: {
          port: 80
        }
      }
    ]
    backendAddressPools: [
      {
        name: 'decoyBackendPool'
        properties: {
          backendAddresses: [
            {
              ipAddress: backendIp
            }
          ]
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'httpSettings'
        properties: {
          port: 80
          protocol: 'Http'
          cookieBasedAffinity: 'Disabled'
          requestTimeout: 30
        }
      }
    ]
    httpListeners: [
      {
        name: 'httpListener'
        properties: {
          frontendIPConfiguration: {
            id: '${agwId}/frontendIPConfigurations/appGatewayFrontendIP'
          }
          frontendPort: {
            id: '${agwId}/frontendPorts/port80'
          }
          protocol: 'Http'
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'routingRule'
        properties: {
          ruleType: 'Basic'
          priority: 100
          httpListener: {
            id: '${agwId}/httpListeners/httpListener'
          }
          backendAddressPool: {
            id: '${agwId}/backendAddressPools/decoyBackendPool'
          }
          backendHttpSettings: {
            id: '${agwId}/backendHttpSettingsCollection/httpSettings'
          }
        }
      }
    ]
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: agw
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        category: 'ApplicationGatewayAccessLog'
        enabled: true
      }
      {
        category: 'ApplicationGatewayFirewallLog'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

output id string = agw.id
output publicIp string = pip.properties.ipAddress
output fqdnIpResourceId string = pip.id
