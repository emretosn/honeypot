metadata description = 'Log Analytics workspace — central sink for Entra, Defender and resource diagnostics. Microsoft Sentinel is layered on this workspace by the detection module.'

@description('Workspace name.')
param name string

@description('Deployment location.')
param location string

@description('Interactive log retention in days (30–730).')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

@description('Daily ingestion cap in GB to bound Sentinel cost. -1 = uncapped.')
param dailyQuotaGb int = 2

@description('Resource tags. Honeypot ownership lives here, not in the name.')
param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

@description('Resource ID of the workspace, consumed by detection / diagnostics modules.')
output workspaceId string = workspace.id

@description('Customer/workspace ID (GUID) used by agents and connectors.')
output customerId string = workspace.properties.customerId

output name string = workspace.name
