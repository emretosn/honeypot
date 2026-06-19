metadata description = 'Decoy storage account for the honeypot spoke. Holds planted fake-prod breadcrumbs (NEVER real data). Diagnostics on blob reads flow to Log Analytics so access becomes a detection signal.'

@description('Storage account name (decoy-plane: production-like, no honeypot marker). 3-24 lowercase alphanumeric.')
param name string

@description('Deployment location.')
param location string

@description('Log Analytics workspace resource ID for diagnostics.')
param workspaceId string

@description('Resource tags.')
param tags object = {}

resource sa 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: name
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

resource blob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: sa
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blob
  name: 'backups'
  properties: {
    publicAccess: 'None'
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: blob
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        category: 'StorageRead'
        enabled: true
      }
      {
        category: 'StorageWrite'
        enabled: true
      }
    ]
  }
}

output id string = sa.id
output name string = sa.name
