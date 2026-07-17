metadata description = 'Detection plane. Onboards Microsoft Sentinel and deploys high-fidelity, inventory-scoped analytics rules for the honeypot (privileged-auth abuse, decoy sign-ins, credential-add, consent, Key Vault / storage / VM access). Deploy scoped to the foundation management resource group.'

targetScope = 'resourceGroup'

@description('Name of the foundation Log Analytics workspace.')
param workspaceName string

@description('Decoy Key Vault name (from the network deployment).')
param decoyKeyVaultName string

@description('Decoy storage account name (from the network deployment).')
param decoyStorageAccountName string

@description('Decoy VM name (from the network deployment). Empty disables the run-command rule.')
param decoyVmName string = ''

@description('IP addresses allowlisted from sign-in detection (e.g. the activity agent). Empty = none.')
param signInAllowlistIps array = []

@description('App (client) ID of the reachable decoy app the foothold can take over (from inventory.identity.reachableApp.appId). Empty disables the credential-add rule.')
param reachableAppId string = ''

@description('Object ID of the reachable decoy service principal (from inventory.identity.reachableApp.spObjectId). Empty disables the SP sign-in rule.')
param reachableSpObjectId string = ''

@description('UPN of the emergency-access decoy (from inventory.identity.emergencyAccess.upn). Empty disables its sign-in rule.')
param emergencyAccessUpn string = ''

@description('Object IDs of principals LEGITIMATELY allowed to perform privileged authentication writes (password / auth-method resets) against OTHER users: the real Password/Authentication/Privileged-Authentication/User/Helpdesk admins plus any service principals that write to users (AD Connect / password-hash-sync, provisioning). Any initiator NOT in this list that resets another principal fires the privileged-auth-abuse rule. Keep it small and curated; this is the known-good set the rule inverts against. Self-service (initiator == target, e.g. SSPR/MFA registration) is always excluded regardless of this list.')
param privilegedAuthAllowlistIds array = []

@description('Enable the decoy VM run-command rule (an internal attacker with RG Owner running commands on the decoy VM). deploy/detection.sh enables it once AzureActivity is ingesting.')
param enableVmRunCommandRule bool = false

@description('Enable the reachable-edge invited-action rules (credential-add on the decoy app + sign-in as the decoy SP). deploy/detection.sh enables them once the reachable app/SP are in the inventory.')
param enableReachableEdgeRules bool = false

@description('Enable the decoy resource rules (Key Vault / storage). deploy/detection.sh enables them once the referenced tables have ingested, so the rules validate against a live schema.')
param enableResourceRules bool = false

@description('Incident grouping lookback window (ISO8601) applied to every rule.')
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
var authAllowlistLiteral = empty(privilegedAuthAllowlistIds) ? '""' : '"${join(privilegedAuthAllowlistIds, '","')}"'

var qKvSecretRead = join([
  'AzureDiagnostics'
  '| where ResourceProvider == "MICROSOFT.KEYVAULT"'
  '| where Resource =~ "${decoyKeyVaultName}"'
  // Secret-plane reads only (the honeytokens). VaultGet/control-plane ops are platform/CLI noise.
  '| where OperationName in ("SecretGet", "SecretList")'
  '| extend ActorIp = columnifexists("CallerIPAddress", ""), Actor = columnifexists("identity_claim_upn_s", ""), ActorApp = columnifexists("identity_claim_appid_g", "")'
  '| extend ResourceId = columnifexists("ResourceId", "")'
  '| project TimeGenerated, OperationName, Resource, Actor, ActorApp, ActorIp, ResourceId'
], '\n')

var qResourceAccess = join([
  'StorageBlobLogs'
  '| where AccountName =~ "${decoyStorageAccountName}"'
  // Only attacker-style data access (a stolen SAS token or account key). TrustedAccess = the
  // Azure platform/Defender scanning the account; not an attacker, so excluded.
  '| where AuthenticationType in ("SAS", "AccountKey")'
  '| extend ActorIp = columnifexists("CallerIpAddress", "")'
  '| extend ResourceId = columnifexists("_ResourceId", "")'
  '| project TimeGenerated, AccountName, OperationName, Uri, ActorIp, AuthenticationType, ResourceId'
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

// Consent / app-role grant involving the decoy app/SP. The foothold cannot trip this: a non-admin
// consent attempt is denied at the API and writes no AuditLogs event. It fires only when a principal
// with consent authority (Global Admin / Privileged Role Admin) grants the decoy app's requested
// god-mode permission, i.e. an insider or a compromised admin making the dangling request real.
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

// Decoy VM run-command: an internal attacker who has taken over the reachable SP (Owner of the
// decoy RG) executing commands on the decoy VM (az vm run-command / runCommands). The VM has no
// legitimate operational use, so any run-command against it is attacker lateral movement. Sourced
// from AzureActivity (management-plane), scoped to the decoy VM by resource id.
var qVmRunCommand = join([
  'AzureActivity'
  '| where OperationNameValue in~ ("Microsoft.Compute/virtualMachines/runCommand/action", "Microsoft.Compute/virtualMachines/runCommands/write")'
  '| where _ResourceId has "/virtualMachines/${decoyVmName}" or Resource =~ "${decoyVmName}"'
  '| extend Actor = tostring(coalesce(Caller, "unknown"))'
  '| extend ActorIp = tostring(coalesce(CallerIpAddress, ""))'
  '| extend ResourceId = columnifexists("_ResourceId", "")'
  '| project TimeGenerated, OperationNameValue, Resource, Actor, ActorIp, ActivityStatusValue, ResourceId'
], '\n')

// PRIVILEGED-AUTH ABUSE rule. Detection by known-good exclusion, not by decoy-target match: a
// principal that is NOT on the admin/service allowlist performed a privileged authentication write
// (password / auth-method reset) against ANOTHER principal. Legitimate cross-principal auth resets
// come only from a small, known set of admins (plus sync/provisioning service principals); anything
// else is a compromised account exercising delegated auth power. Scales to N footholds without
// naming them.
//  - initiator != target: excludes SSPR / self-MFA registration (huge legit self-service volume).
//  - initiator not in allowlist: excludes the real admins and service principals.
//  - source IP not in allowlist: excludes the optional activity agent.
// AuditLogs-sourced. A denied (403) attempt on a real admin is not in AuditLogs (it never reaches
// the directory-change pipeline), so this fires on the first successful non-self privileged write,
// which given the attacker's AU-scoped role is a decoy.
var qPrivilegedAuthAbuse = join([
  'AuditLogs'
  '| where OperationName has_any ("password", "authentication method", "security info", "StrongAuthentication")'
  '| mv-expand TargetResources'
  '| extend targetUpn = tostring(TargetResources.userPrincipalName)'
  '| extend targetId = tostring(TargetResources.id)'
  '| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId, ""))'
  '| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName, "unknown"))'
  '| extend ActorIp = tostring(coalesce(InitiatedBy.user.ipAddress, ""))'
  // exclude self-service (SSPR / MFA registration): the initiator acting on its own object
  '| where isnotempty(targetId) and ActorId != targetId'
  // exclude the known-good admins + service principals
  '| where ActorId !in (${authAllowlistLiteral})'
  // exclude allowlisted source IPs (e.g. the activity agent)
  '| where ActorIp == "" or ActorIp !in (${allowlistLiteral})'
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

// Read of a decoy Key Vault secret (resource tripwire).
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
        entityType: 'AzureResource'
        fieldMappings: [{ identifier: 'ResourceId', columnName: 'ResourceId' }]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// Any access to decoy storage (resource tripwire).
module ruleResourceAccess 'modules/detection/scheduledRule.bicep' = if (enableResourceRules) {
  name: 'rule-decoy-resource-access'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-resource-access')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: decoy storage accessed'
    ruleDescription: 'SAS/AccountKey data-plane access to the decoy storage account. This storage is unused by the organization and holds only breadcrumb blobs, and the query excludes Azure platform/TrustedAccess scanning, so any hit is an attacker reading the decoy (near-100% true positive). Reachable only via the taken-over reachable SP (Owner of the decoy RG, list keys).'
    severity: 'High'
    tactics: ['Collection', 'Discovery']
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    query: qResourceAccess
    entityMappings: [
      {
        entityType: 'AzureResource'
        fieldMappings: [{ identifier: 'ResourceId', columnName: 'ResourceId' }]
      }
      {
        entityType: 'IP'
        fieldMappings: [{ identifier: 'Address', columnName: 'ActorIp' }]
      }
    ]
  }
}

// Reachable edge: a credential was added to the decoy app the foothold owns (the invited
//    takeover action). Near-100% TP.
module ruleCredentialAdd 'modules/detection/scheduledRule.bicep' = if (enableReachableEdgeRules) {
  name: 'rule-reachable-credential-add'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'reachable-credential-add')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: credential added to decoy service principal/app'
    ruleDescription: 'A client secret or certificate was added to the decoy reachable app/SP. This is the invited takeover action: an attacker who owns the app adding a credential to act as the SP. No legitimate process does this.'
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

// Reachable edge: a sign-in AS the decoy service principal (the attacker has taken it over).
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

// An admin-level consent / app-role grant made the decoy app's god-mode request real. Insider or
//    compromised-admin signal (the foothold cannot reach this, see the query comment).
module ruleConsentGrant 'modules/detection/scheduledRule.bicep' = if (enableReachableEdgeRules && !empty(reachableSpObjectId)) {
  name: 'rule-decoy-consent-grant'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-consent-grant')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: admin consent granted to decoy app/service principal (insider)'
    ruleDescription: 'A principal with consent authority (Global Administrator / Privileged Role Administrator) granted consent or an app-role to the decoy reachable app/SP, turning its deliberately-unconsented god-mode permission request into real privilege. The foothold cannot trigger this (a non-admin consent attempt is denied and writes no audit event), so this is an insider or compromised-admin signal, defense-in-depth rather than a foothold tripwire.'
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

// Decoy VM run-command: internal lateral movement by the taken-over SP (RG Owner).
module ruleVmRunCommand 'modules/detection/scheduledRule.bicep' = if (enableVmRunCommandRule && !empty(decoyVmName)) {
  name: 'rule-decoy-vm-runcommand'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'decoy-vm-runcommand')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: run-command on decoy VM'
    ruleDescription: 'A management-plane run-command was executed against the decoy VM. The VM has no legitimate operational use, so a run-command against it is an internal attacker (typically the taken-over reachable SP, which is Owner of the decoy resource group) moving laterally onto the host.'
    severity: 'High'
    tactics: ['Execution', 'LateralMovement']
    query: qVmRunCommand
    entityMappings: [
      {
        entityType: 'AzureResource'
        fieldMappings: [{ identifier: 'ResourceId', columnName: 'ResourceId' }]
      }
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

// Privileged-auth abuse: a non-allowlisted principal reset another principal's password or
//    authentication method. Always on, AuditLogs-sourced.
module rulePrivilegedAuthAbuse 'modules/detection/scheduledRule.bicep' = {
  name: 'rule-privileged-auth-abuse'
  dependsOn: [sentinel]
  params: {
    workspaceName: workspaceName
    ruleId: guid(workspaceName, 'privileged-auth-abuse')
    groupingLookbackDuration: groupingLookbackDuration
    displayName: 'Honeypot: privileged authentication action by a non-allowlisted principal'
    ruleDescription: 'A principal that is NOT on the privileged-auth allowlist reset the password or authentication method of ANOTHER user. Legitimate cross-principal auth resets come only from a small, known set of admins (and sync/provisioning service principals); self-service (SSPR/MFA registration, initiator == target) is excluded. Anything else is a compromised account exercising delegated authentication power over others, including any foothold that resets a decoy such as emergency-access. Scales to any number of compromised accounts without enumerating them. AuditLogs-sourced. A denied attempt against a real admin is not in AuditLogs, so this fires on the first successful non-self reset, which for an AU-scoped attacker is a decoy.'
    severity: 'High'
    tactics: ['PrivilegeEscalation', 'CredentialAccess', 'Persistence']
    query: qPrivilegedAuthAbuse
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

// Emergency-access decoy: sign-in AS it (the attacker took it over after resetting it).
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
