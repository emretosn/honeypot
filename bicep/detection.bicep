metadata description = 'Detection plane. Onboards Microsoft Sentinel and deploys high-fidelity analytics rules for the honeypot. Rules are anchored on write/auth events (password reset, role activation, sign-in, secret read, resource access) — the reliable signals — with enumeration treated as a best-effort bonus. Deploy scoped to the foundation management resource group.'

targetScope = 'resourceGroup'

@description('Name of the foundation Log Analytics workspace.')
param workspaceName string

@description('UPN of the primary lure identity (from inventory/decoy-inventory.json).')
param lureUpn string

@description('Decoy Key Vault name (from the network deployment).')
param decoyKeyVaultName string

@description('Decoy storage account name (from the network deployment).')
param decoyStorageAccountName string

@description('IP addresses allowlisted from sign-in detection (e.g. the activity agent). Empty = none.')
param signInAllowlistIps array = []

@description('Enable the best-effort enumeration-anomaly rule (noisier, P-licensed sources).')
param enableEnumerationRule bool = false

@description('Enable the decoy resource rules (Key Vault / storage). Turn on only AFTER the network module is deployed, so the referenced tables/columns exist. Off by default so the identity stage deploys cleanly.')
param enableResourceRules bool = false

module sentinel 'modules/detection/sentinelOnboarding.bicep' = {
  name: 'sentinel-onboarding'
  params: {
    workspaceName: workspaceName
  }
}

// Bicep multi-line strings do NOT interpolate, so each KQL query is assembled from
// interpolated single-quoted lines joined with newlines.
var allowlistLiteral = empty(signInAllowlistIps) ? '""' : '"${join(signInAllowlistIps, '","')}"'

var qPasswordReset = join([
  'AuditLogs'
  '| where OperationName has "password"'
  '| mv-expand TargetResources'
  '| extend targetUpn = tostring(TargetResources.userPrincipalName)'
  '| where targetUpn =~ "${lureUpn}"'
  '| extend Actor = tostring(InitiatedBy.user.userPrincipalName), ActorIp = tostring(InitiatedBy.user.ipAddress)'
  '| project TimeGenerated, OperationName, targetUpn, Actor, ActorIp'
], '\n')

var qRoleEscalation = join([
  'AuditLogs'
  '| where OperationName has_any ("Add member to role", "Add eligible member to role", "activate", "Add member to role in PIM")'
  '| mv-expand TargetResources'
  '| extend targetUpn = tostring(TargetResources.userPrincipalName)'
  '| extend initiator = tostring(InitiatedBy.user.userPrincipalName)'
  '| where targetUpn =~ "${lureUpn}" or initiator =~ "${lureUpn}"'
  '| extend ActorIp = tostring(InitiatedBy.user.ipAddress)'
  '| project TimeGenerated, OperationName, targetUpn, initiator, ActorIp'
], '\n')

var qSignIn = join([
  'SigninLogs'
  '| where UserPrincipalName =~ "${lureUpn}"'
  '| where IPAddress !in (${allowlistLiteral})'
  '| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, Location'
], '\n')

var qKvSecretRead = join([
  'AzureDiagnostics'
  '| where ResourceProvider == "MICROSOFT.KEYVAULT"'
  '| where Resource =~ "${decoyKeyVaultName}"'
  '| where OperationName in ("SecretGet", "SecretList", "VaultGet")'
  '| extend ActorIp = columnifexists("CallerIPAddress", ""), Actor = columnifexists("identity_claim_upn_s", "")'
  '| project TimeGenerated, OperationName, Resource, Actor, ActorIp'
], '\n')

var qResourceAccess = join([
  'StorageBlobLogs'
  '| where AccountName =~ "${decoyStorageAccountName}"'
  '| extend ActorIp = columnifexists("CallerIpAddress", "")'
  '| project TimeGenerated, AccountName, OperationName, Uri, ActorIp, AuthenticationType'
], '\n')

var qEnumeration = join([
  'MicrosoftGraphActivityLogs'
  '| where RequestUri has "${lureUpn}"'
  '| extend ActorAppId = AppId'
  '| project TimeGenerated, RequestMethod, RequestUri, ResponseStatusCode, ActorAppId, IPAddress'
], '\n')

// 1. Password reset / change targeting the lure — strong tripwire.
module rulePasswordReset 'modules/detection/scheduledRule.bicep' = {
  name: 'rule-lure-password-reset'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'lure-password-reset')
    displayName: 'Honeypot: password reset on lure identity'
    ruleDescription: 'A password reset/change was performed against the decoy lure identity. No legitimate process touches this account.'
    severity: 'High'
    tactics: ['CredentialAccess', 'Persistence']
    query: qPasswordReset
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [{ identifier: 'FullName', columnName: 'Actor' }]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 2. Role assignment / PIM activation targeting the lure — strong tripwire.
module ruleRoleEscalation 'modules/detection/scheduledRule.bicep' = {
  name: 'rule-lure-role-escalation'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'lure-role-escalation')
    displayName: 'Honeypot: role assignment or PIM activation on lure identity'
    ruleDescription: 'A directory role was assigned to, or activated by, the decoy lure identity. Indicates privilege-escalation activity against the honeypot.'
    severity: 'High'
    tactics: ['PrivilegeEscalation', 'Persistence']
    query: qRoleEscalation
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [{ identifier: 'FullName', columnName: 'initiator' }]
      }
    ]
  }
}

// 3. Interactive sign-in AS the lure from a non-allowlisted source — strong tripwire.
module ruleSignIn 'modules/detection/scheduledRule.bicep' = {
  name: 'rule-lure-signin'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'lure-signin')
    displayName: 'Honeypot: sign-in as lure identity from non-allowlisted source'
    ruleDescription: 'A sign-in occurred as the decoy lure identity from an IP that is not on the activity-agent allowlist. Any such sign-in is attacker-controlled.'
    severity: 'High'
    tactics: ['InitialAccess', 'CredentialAccess']
    query: qSignIn
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [{ identifier: 'FullName', columnName: 'UserPrincipalName' }]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'IPAddress' }]
      }
    ]
  }
}

// 4. Read of a decoy Key Vault secret — resource tripwire.
module ruleKvSecretRead 'modules/detection/scheduledRule.bicep' = if (enableResourceRules) {
  name: 'rule-decoy-kv-read'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-kv-read')
    displayName: 'Honeypot: decoy Key Vault secret accessed'
    ruleDescription: 'A secret in the decoy Key Vault was read or listed. The vault holds only honeytokens, so any access is malicious.'
    severity: 'High'
    tactics: ['CredentialAccess', 'Collection']
    query: qKvSecretRead
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 5. Any access to decoy storage — resource tripwire.
module ruleResourceAccess 'modules/detection/scheduledRule.bicep' = if (enableResourceRules) {
  name: 'rule-decoy-resource-access'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-resource-access')
    displayName: 'Honeypot: decoy storage accessed'
    ruleDescription: 'Data-plane access to the decoy storage account. This storage is unused by the organization and holds only breadcrumbs.'
    severity: 'Medium'
    tactics: ['Collection', 'Discovery']
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    query: qResourceAccess
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 6. OPTIONAL best-effort enumeration anomaly — noisier, depends on P-licensed sources.
module ruleEnumeration 'modules/detection/scheduledRule.bicep' = if (enableEnumerationRule) {
  name: 'rule-decoy-enumeration'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-enumeration')
    displayName: 'Honeypot: directory enumeration touching decoy objects (best-effort)'
    ruleDescription: 'Best-effort: reads that reference the lure. Read detection is inherently lower fidelity than write/auth events; tune before enforcing.'
    severity: 'Low'
    tactics: ['Discovery']
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    query: qEnumeration
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'IPAddress' }]
      }
    ]
  }
}

output sentinelWorkspaceId string = sentinel.outputs.workspaceId
