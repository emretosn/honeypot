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

@description('Name of the lure-credential honeytoken secret (e.g. "identity-admin-credentials"). Empty disables it. When set, the lure UPN + password are planted so recon (a KV secret read) LEADS to the lure: a sign-in attempt as the lure then trips the lure sign-in rule. MFA still blocks actual access — the attempt is the signal.')
param lureSecretName string = ''

@description('Value of the lure-credential honeytoken (UPN + password breadcrumb). Threaded from the identity Terraform output via network.sh; never written to the inventory. Empty disables it.')
@secure()
param lureSecretValue string = ''

@description('Honeytoken secrets to plant in the decoy vault — name/value pairs. These are inert canaries (never real). Reading any of them is a tripwire (the decoy-kv-read rule). Default plants a couple of credential-shaped breadcrumbs.')
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

// Plant the honeytoken secrets via the CONTROL plane (Microsoft.KeyVault/vaults/secrets), which
// works with the deployer's Contributor rights even on an RBAC-authorized vault — no data-plane
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

// Lure-credential honeytoken — planted only when supplied (identity stage has run and network.sh
// threaded the value). Same control-plane planting as above. Connects the recon path to the lure:
// reading this trips the KV-read rule, and trying the creds trips the lure sign-in rule.
resource lureSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(lureSecretName) && !empty(lureSecretValue)) {
  parent: vault
  name: lureSecretName
  properties: {
    value: lureSecretValue
  }
}

output id string = vault.id
output name string = vault.name
output uri string = vault.properties.vaultUri
