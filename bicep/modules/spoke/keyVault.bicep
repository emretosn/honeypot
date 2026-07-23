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

@description('Honeytoken secrets to plant in the decoy vault, name/value pairs. These are inert canaries (never real). Reading any of them is a tripwire (the decoy-kv-read rule). They are the "valuable assets" an internal attacker who takes over the reachable SP (Key Vault Secrets User) finds in the vault.')
param honeytokenSecrets array = [
  {
    name: 'core-prod-sql-connection'
    #disable-next-line no-hardcoded-env-urls
    value: 'Server=sql-core-prod.database.windows.net;Database=core;User Id=svc_app;Password=Wint3r-2026-Core!;'
  }
  {
    name: 'svc-deploy-credentials'
    value: 'svc-deploy@core-prod / Depl0y-Core-2026!'
  }
  {
    name: 'github-actions-pat'
    // Inert decoy GitHub personal access token (fine-grained shape). Never real, reading it is the
    // tripwire. Looks like a CI/CD deploy token for the core-prod org.
    value: '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'
  }
]

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
    // Private-only: reachable exclusively over the spoke private endpoint. Public data-plane access
    // is disabled (also enforced by governance policy in hardened tenants), so an attacker loots the
    // honeytokens only from inside the spoke via the taken-over reachable SP. Control-plane secret
    // planting at deploy time still works (it does not traverse the data plane).
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
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

// Plant the honeytoken secrets via the CONTROL plane (Microsoft.KeyVault/vaults/secrets), which
// works with the deployer's Contributor rights even on an RBAC-authorized vault, no data-plane
// role needed at deploy time. Values are inert canaries; reading any one is a tripwire.
resource secrets 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = [
  for s in honeytokenSecrets: {
    parent: vault
    name: s.name
    properties: {
      value: s.value
    }
  }
]

output id string = vault.id
output name string = vault.name
output uri string = vault.properties.vaultUri
