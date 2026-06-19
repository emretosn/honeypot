metadata description = 'Decoy Key Vault for the honeypot spoke. Holds planted fake credentials / honeytokens (NEVER real secrets). RBAC-authorization enabled so access is auditable; diagnostics flow to Log Analytics so secret reads become detection signals.'

@description('Key Vault name (decoy-plane: production-like, no honeypot marker). 3-24 chars.')
param name string

@description('Deployment location.')
param location string

@description('Tenant ID for the vault.')
param tenantId string

@description('Log Analytics workspace resource ID for diagnostics.')
param workspaceId string

@description('Resource tags.')
param tags object = {}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'to-law'
  scope: vault
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        category: 'AuditEvent'
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

output id string = vault.id
output name string = vault.name
output uri string = vault.properties.vaultUri
