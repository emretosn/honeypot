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

@description('All decoy identity UPNs (lure + personas, from inventory). Used by the non-interactive sign-in rule.')
param decoyUpns array = []

@description('Object ID of the decoy security group the lure owns (from inventory.identity.decoyGroupIds[0]). Empty disables the group-change rule.')
param decoyGroupId string = ''

@description('Threshold for the directory-enumeration breadth anomaly: alert when a single non-allowlisted caller reads more than this many distinct directory objects in the window. Tune during soak.')
param enumerationBreadthThreshold int = 200

@description('App (client) ID of the reachable decoy app the foothold can take over (from inventory.identity.reachableApp.appId). Empty disables the credential-add rule.')
param reachableAppId string = ''

@description('Object ID of the reachable decoy service principal (from inventory.identity.reachableApp.spObjectId). Empty disables the SP sign-in rule.')
param reachableSpObjectId string = ''

@description('UPN of the emergency-access decoy (from inventory.identity.emergencyAccess.upn). Empty disables its reset + sign-in rules.')
param emergencyAccessUpn string = ''

@description('Object ID of the emergency-access decoy (from inventory.identity.emergencyAccess.objectId).')
param emergencyAccessObjectId string = ''

@description('Enable the best-effort enumeration-anomaly rule (noisier, P-licensed sources).')
param enableEnumerationRule bool = false

@description('Enable the expanded coverage rules (non-interactive sign-in, consent/app-role grant, group member/owner change). Inventory-scoped and deterministic.')
param enableCoverageRules bool = false

@description('Enable the reachable-edge invited-action rules (credential-add on the decoy app + sign-in as the decoy SP). Turn on once the reachable app/SP exist in the inventory.')
param enableReachableEdgeRules bool = false

@description('Enable the decoy resource rules (Key Vault / storage). Turn on only AFTER the network module is deployed, so the referenced tables/columns exist. Off by default so the identity stage deploys cleanly.')
param enableResourceRules bool = false

@description('Incident grouping lookback window (ISO8601) applied to every rule. Default PT5H suits production; pass a short value (e.g. PT5M) during testing so each trigger opens a fresh incident instead of folding into the previous one.')
param groupingLookbackDuration string = 'PT5H'

module sentinel 'modules/detection/sentinelOnboarding.bicep' = {
  name: 'sentinel-onboarding'
  params: {
    workspaceName: workspaceName
  }
}

// Bicep multi-line strings do NOT interpolate, so each KQL query is assembled from
// interpolated single-quoted lines joined with newlines.
var allowlistLiteral = empty(signInAllowlistIps) ? '""' : '"${join(signInAllowlistIps, '","')}"'
var decoyUpnLiteral = empty(decoyUpns) ? '""' : '"${join(decoyUpns, '","')}"'

var qPasswordReset = join([
  'AuditLogs'
  '| where OperationName has "password"'
  '| mv-expand TargetResources'
  '| extend targetUpn = tostring(TargetResources.userPrincipalName)'
  '| where targetUpn =~ "${lureUpn}"'
  '| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId, ""))'
  '| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName, "unknown"))'
  '| extend ActorIp = tostring(coalesce(InitiatedBy.user.ipAddress, ""))'
  '| extend targetId = tostring(TargetResources.id)'
  '| project TimeGenerated, OperationName, targetUpn, targetId, Actor, ActorId, ActorIp'
], '\n')

var qRoleEscalation = join([
  'AuditLogs'
  '| where OperationName has_any ("Add member to role", "Add eligible member to role", "activate", "Add member to role in PIM")'
  '| mv-expand TargetResources'
  '| extend targetUpn = tostring(TargetResources.userPrincipalName)'
  '| extend targetId = tostring(TargetResources.id)'
  '| extend initiator = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName, "unknown"))'
  '| extend initiatorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId, ""))'
  '| where targetUpn =~ "${lureUpn}" or initiator =~ "${lureUpn}"'
  '| extend ActorIp = tostring(coalesce(InitiatedBy.user.ipAddress, ""))'
  '| project TimeGenerated, OperationName, targetUpn, targetId, initiator, initiatorId, ActorIp'
], '\n')

var qSignIn = join([
  'SigninLogs'
  '| where UserPrincipalName =~ "${lureUpn}"'
  '| where IPAddress !in (${allowlistLiteral})'
  '| extend LureId = tostring(coalesce(UserId, ""))'
  '| extend LureUpn = tostring(coalesce(UserPrincipalName, Identity, "${lureUpn}"))'
  '| project TimeGenerated, LureUpn, LureId, IPAddress, AppDisplayName, ResultType, Location'
], '\n')

var qKvSecretRead = join([
  'AzureDiagnostics'
  '| where ResourceProvider == "MICROSOFT.KEYVAULT"'
  '| where Resource =~ "${decoyKeyVaultName}"'
  // Secret-plane reads only — the honeytokens. VaultGet/control-plane ops are platform/CLI noise.
  '| where OperationName in ("SecretGet", "SecretList")'
  '| extend ActorIp = columnifexists("CallerIPAddress", ""), Actor = columnifexists("identity_claim_upn_s", ""), ActorApp = columnifexists("identity_claim_appid_g", "")'
  '| project TimeGenerated, OperationName, Resource, Actor, ActorApp, ActorIp'
], '\n')

var qResourceAccess = join([
  'StorageBlobLogs'
  '| where AccountName =~ "${decoyStorageAccountName}"'
  // Only attacker-style data access (a stolen SAS token or account key). TrustedAccess = the
  // Azure platform/Defender scanning the account; not an attacker, so excluded.
  '| where AuthenticationType in ("SAS", "AccountKey")'
  '| extend ActorIp = columnifexists("CallerIpAddress", "")'
  '| project TimeGenerated, AccountName, OperationName, Uri, ActorIp, AuthenticationType'
], '\n')

// Reachable-edge invited actions. The decoy app/SP filters come from the inventory.
var qCredentialAdd = join([
  'AuditLogs'
  '| where OperationName has_any ("Add service principal credentials", "Update application – Certificates and secrets management", "Add password to application", "Add key to application", "Update application")'
  '| mv-expand TargetResources'
  '| extend targetId = tostring(TargetResources.id)'
  '| where targetId == "${reachableAppId}" or targetId == "${reachableSpObjectId}"'
  '| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName, "unknown"))'
  '| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId, ""))'
  '| extend ActorIp = tostring(coalesce(InitiatedBy.user.ipAddress, ""))'
  '| project TimeGenerated, OperationName, targetId, Actor, ActorId, ActorIp'
], '\n')

var qSpSignIn = join([
  'AADServicePrincipalSignInLogs'
  '| where ServicePrincipalId == "${reachableSpObjectId}"'
  '| extend SpName = tostring(coalesce(ServicePrincipalName, "decoy-sp"))'
  '| extend ActorIp = tostring(coalesce(IPAddress, ""))'
  '| project TimeGenerated, SpName, ServicePrincipalId, ActorIp, ResultType, AppId'
], '\n')

// --- Expanded coverage — modern kill-chain telemetry, inventory-scoped/deterministic.

// Token-based (non-interactive) sign-in AS a decoy identity — catches token replay / AiTM that
// the interactive SigninLogs rule misses.
var qNonInteractive = join([
  'NonInteractiveUserSignInLogs'
  '| where UserPrincipalName in~ (${decoyUpnLiteral})'
  '| where IPAddress !in (${allowlistLiteral})'
  '| extend LureId = tostring(coalesce(UserId, ""))'
  '| extend LureUpn = tostring(coalesce(UserPrincipalName, "unknown"))'
  '| extend ActorIp = tostring(coalesce(IPAddress, ""))'
  '| project TimeGenerated, LureUpn, LureId, ActorIp, AppDisplayName, ResultType'
], '\n')

// Consent / app-role grant involving the decoy app/SP — the tripwire for the unconsented
// "god-mode" permission the reachable app requests (an attacker trying to make it real).
var qConsentGrant = join([
  'AuditLogs'
  '| where OperationName has_any ("Consent to application", "Add app role assignment grant to service principal", "Add delegated permission grant", "Add OAuth2PermissionGrant")'
  '| mv-expand TargetResources'
  '| extend targetId = tostring(TargetResources.id), targetName = tostring(TargetResources.displayName)'
  '| where targetId == "${reachableAppId}" or targetId == "${reachableSpObjectId}" or targetName has "${reachableAppId}"'
  '| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName, "unknown"))'
  '| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId, ""))'
  '| extend ActorIp = tostring(coalesce(InitiatedBy.user.ipAddress, ""))'
  '| project TimeGenerated, OperationName, targetId, Actor, ActorId, ActorIp'
], '\n')

// Member/owner added to the decoy group the lure owns — a believable escalation primitive.
var qGroupChange = join([
  'AuditLogs'
  '| where OperationName has_any ("Add member to group", "Add owner to group")'
  '| mv-expand TargetResources'
  '| extend targetId = tostring(TargetResources.id)'
  '| where targetId == "${decoyGroupId}"'
  '| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName, "unknown"))'
  '| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId, ""))'
  '| extend ActorIp = tostring(coalesce(InitiatedBy.user.ipAddress, ""))'
  '| project TimeGenerated, OperationName, targetId, Actor, ActorId, ActorIp'
], '\n')

// Behavioural: directory-enumeration BREADTH anomaly — a single non-allowlisted caller reading
// many distinct directory objects (what AzureHound/ROADrecon actually do). Corroboration only,
// never a sole basis for auto-remediation.
var qEnumerationBreadth = join([
  'MicrosoftGraphActivityLogs'
  '| where RequestMethod == "GET"'
  '| where RequestUri has_any ("/users", "/servicePrincipals", "/applications", "/groups", "/directoryRoles", "/roleManagement")'
  '| where IPAddress !in (${allowlistLiteral})'
  '| summarize DistinctObjects = dcount(RequestUri), SampleUris = make_set(RequestUri, 5) by AppId, IPAddress, bin(TimeGenerated, 1h)'
  '| where DistinctObjects > ${enumerationBreadthThreshold}'
  '| extend ActorAppId = AppId'
  '| project TimeGenerated, ActorAppId, IPAddress, DistinctObjects'
], '\n')

// Emergency-access decoy: password reset targeting it — the invited escalation action. Any
// compromised identity holds Password Administrator over its single-member AU, but nothing
// legitimate ever resets this account, so a reset is a near-100% true positive.
var qEmergencyReset = join([
  'AuditLogs'
  '| where OperationName has "password"'
  '| mv-expand TargetResources'
  '| extend targetUpn = tostring(TargetResources.userPrincipalName)'
  '| extend targetId = tostring(TargetResources.id)'
  '| where targetUpn =~ "${emergencyAccessUpn}" or targetId == "${emergencyAccessObjectId}"'
  '| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName, "unknown"))'
  '| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId, ""))'
  '| extend ActorIp = tostring(coalesce(InitiatedBy.user.ipAddress, ""))'
  '| project TimeGenerated, OperationName, targetUpn, targetId, Actor, ActorId, ActorIp'
], '\n')

// Emergency-access decoy: sign-in AS it (after the attacker reset its password). The account has
// no legitimate use, so any sign-in from a non-allowlisted source is attacker-controlled.
var qEmergencySignIn = join([
  'SigninLogs'
  '| where UserPrincipalName =~ "${emergencyAccessUpn}"'
  '| where IPAddress !in (${allowlistLiteral})'
  '| extend DecoyId = tostring(coalesce(UserId, ""))'
  '| extend DecoyUpn = tostring(coalesce(UserPrincipalName, Identity, "${emergencyAccessUpn}"))'
  '| project TimeGenerated, DecoyUpn, DecoyId, IPAddress, AppDisplayName, ResultType, Location'
], '\n')

// 1. Password reset / change targeting the lure — strong tripwire.
module rulePasswordReset 'modules/detection/scheduledRule.bicep' = {
  name: 'rule-lure-password-reset'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'lure-password-reset')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: password reset on lure identity'
    ruleDescription: 'A password reset/change was performed against the decoy lure identity. No legitimate process touches this account.'
    severity: 'High'
    tactics: ['CredentialAccess', 'Persistence']
    query: qPasswordReset
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Actor' }
          { identifier: 'AadUserId', columnName: 'ActorId' }
        ]
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
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: role assignment or PIM activation on lure identity'
    ruleDescription: 'A directory role was assigned to, or activated by, the decoy lure identity. Indicates privilege-escalation activity against the honeypot.'
    severity: 'High'
    tactics: ['PrivilegeEscalation', 'Persistence']
    query: qRoleEscalation
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'initiator' }
          { identifier: 'AadUserId', columnName: 'initiatorId' }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'targetUpn' }
          { identifier: 'AadUserId', columnName: 'targetId' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
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
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: sign-in as lure identity from non-allowlisted source'
    ruleDescription: 'A sign-in occurred as the decoy lure identity from an IP that is not on the activity-agent allowlist. Any such sign-in is attacker-controlled.'
    severity: 'High'
    tactics: ['InitialAccess', 'CredentialAccess']
    query: qSignIn
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'LureUpn' }
          { identifier: 'AadUserId', columnName: 'LureId' }
        ]
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
    groupingLookbackDuration: groupingLookbackDuration
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
    groupingLookbackDuration: groupingLookbackDuration
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

// 6. Reachable edge: a credential was added to the decoy app the foothold owns — the invited
//    takeover action. Near-100% TP.
module ruleCredentialAdd 'modules/detection/scheduledRule.bicep' = if (enableReachableEdgeRules) {
  name: 'rule-reachable-credential-add'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'reachable-credential-add')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: credential added to decoy service principal/app'
    ruleDescription: 'A client secret or certificate was added to the decoy reachable app/SP. This is the invited takeover action — an attacker who owns the app adding a credential to act as the SP. No legitimate process does this.'
    severity: 'High'
    tactics: ['Persistence', 'PrivilegeEscalation']
    query: qCredentialAdd
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Actor' }
          { identifier: 'AadUserId', columnName: 'ActorId' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 7. Reachable edge: a sign-in AS the decoy service principal — the attacker has taken it over.
module ruleSpSignIn 'modules/detection/scheduledRule.bicep' = if (enableReachableEdgeRules) {
  name: 'rule-reachable-sp-signin'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'reachable-sp-signin')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: sign-in as decoy service principal'
    ruleDescription: 'A sign-in occurred as the decoy reachable service principal. The SP has no legitimate use, so any authentication as it is attacker-controlled (and MFA-immune, the realistic escalation path).'
    severity: 'High'
    tactics: ['PrivilegeEscalation', 'DefenseEvasion']
    query: qSpSignIn
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [{ identifier: 'AadUserId', columnName: 'ServicePrincipalId' }]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 8. Coverage: non-interactive (token-based) sign-in as a decoy identity — token replay / AiTM.
module ruleNonInteractive 'modules/detection/scheduledRule.bicep' = if (enableCoverageRules && !empty(decoyUpns)) {
  name: 'rule-decoy-noninteractive-signin'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-noninteractive-signin')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: non-interactive sign-in as a decoy identity'
    ruleDescription: 'A token-based (non-interactive) sign-in occurred as a decoy identity from a non-allowlisted IP. Catches token replay / AiTM that interactive sign-in logs miss. No legitimate non-interactive use of these accounts exists.'
    severity: 'High'
    tactics: ['DefenseEvasion', 'CredentialAccess']
    query: qNonInteractive
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'LureUpn' }
          { identifier: 'AadUserId', columnName: 'LureId' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 9. Coverage: consent / app-role grant involving the decoy app/SP — the tripwire for the
//     unconsented god-mode permission the reachable app requests.
module ruleConsentGrant 'modules/detection/scheduledRule.bicep' = if (enableCoverageRules && !empty(reachableSpObjectId)) {
  name: 'rule-decoy-consent-grant'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-consent-grant')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: consent or app-role grant on decoy app/service principal'
    ruleDescription: 'A consent or app-role/permission grant targeted the decoy reachable app/SP. This is an attacker trying to turn the app\'s unconsented permission request into real privilege.'
    severity: 'High'
    tactics: ['PrivilegeEscalation', 'Persistence']
    query: qConsentGrant
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Actor' }
          { identifier: 'AadUserId', columnName: 'ActorId' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 10. Coverage: member/owner added to the decoy group the lure owns.
module ruleGroupChange 'modules/detection/scheduledRule.bicep' = if (enableCoverageRules && !empty(decoyGroupId)) {
  name: 'rule-decoy-group-change'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-group-change')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: member or owner added to decoy group'
    ruleDescription: 'A member or owner was added to the decoy security group the lure owns. No legitimate process modifies this group.'
    severity: 'High'
    tactics: ['PrivilegeEscalation', 'Persistence']
    query: qGroupChange
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Actor' }
          { identifier: 'AadUserId', columnName: 'ActorId' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 11. Behavioural: directory-enumeration BREADTH anomaly (replaces the lure-UPN string match).
//     Low severity — corroboration only, never a sole basis for auto-remediation.
module ruleEnumerationBreadth 'modules/detection/scheduledRule.bicep' = if (enableEnumerationRule) {
  name: 'rule-decoy-enumeration-breadth'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-enumeration-breadth')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: directory enumeration breadth anomaly (best-effort)'
    ruleDescription: 'A single non-allowlisted caller read an unusually high number of distinct directory objects in one hour — the pattern of bulk recon tools (AzureHound/ROADrecon). Behavioural/best-effort: corroboration only, never a sole basis for remediation. Tune enumerationBreadthThreshold during soak.'
    severity: 'Low'
    tactics: ['Discovery']
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    query: qEnumerationBreadth
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'IPAddress' }]
      }
    ]
  }
}

// 12. Emergency-access decoy: password reset targeting it — the invited escalation action.
//     Auto-enabled when the decoy UPN is in the inventory. Near-100% true positive.
module ruleEmergencyReset 'modules/detection/scheduledRule.bicep' = if (!empty(emergencyAccessUpn)) {
  name: 'rule-emergency-access-reset'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'emergency-access-reset')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: password reset on emergency-access decoy'
    ruleDescription: 'A password reset/change targeted the standalone emergency-access decoy. Any compromised identity can reset this account (Password Administrator scoped to its single-member AU), but no legitimate process ever does — a reset is an attacker exercising the invited escalation primitive.'
    severity: 'High'
    tactics: ['PrivilegeEscalation', 'Persistence', 'CredentialAccess']
    query: qEmergencyReset
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'targetUpn' }
          { identifier: 'AadUserId', columnName: 'targetId' }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Actor' }
          { identifier: 'AadUserId', columnName: 'ActorId' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// 13. Emergency-access decoy: sign-in AS it (the attacker took it over after resetting it).
module ruleEmergencySignIn 'modules/detection/scheduledRule.bicep' = if (!empty(emergencyAccessUpn)) {
  name: 'rule-emergency-access-signin'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'emergency-access-signin')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: sign-in as emergency-access decoy'
    ruleDescription: 'A sign-in occurred as the emergency-access decoy from a non-allowlisted source. The account has no legitimate use, so any authentication as it is attacker-controlled (typically after resetting its password).'
    severity: 'High'
    tactics: ['InitialAccess', 'CredentialAccess']
    query: qEmergencySignIn
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'DecoyUpn' }
          { identifier: 'AadUserId', columnName: 'DecoyId' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'IPAddress' }]
      }
    ]
  }
}

output sentinelWorkspaceId string = sentinel.outputs.workspaceId
