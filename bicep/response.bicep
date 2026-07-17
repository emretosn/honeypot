metadata description = 'Response plane (SOAR). Deploys two Logic App playbooks (Disable-User-And-Revoke-Sessions and Isolate-Honeypot-Resource) plus the Microsoft Sentinel automation rules that run them on honeypot incidents. A two-key guard restricts each playbook to the decoy inventory objects (never a real admin or non-honeypot resource), and the allowlist protects break-glass and every Global Administrator. Deployed into the same production-plausible management/operations resource group that hosts the workspace and Sentinel (no honeypot marker in any name, because a playbook managed identity leaks its resource-id path directory-wide). The automation rules are created in this same resource group.'

targetScope = 'resourceGroup'

import * as naming from 'modules/naming/naming.bicep'

@description('Location for the playbooks.')
param location string = 'westeurope'

@description('Region short code used to build the production-plausible playbook names.')
param regionCode string = 'weu'

@description('Name of the Log Analytics workspace Sentinel runs on (in this same resource group).')
param workspaceName string

@description('Decoy identity object IDs the disable-user playbook is allowed to act on (the emergency-access decoy, from inventory.identity). The playbook disables an account only if it is in this list, the primary guard that makes remediation incapable of touching a real account.')
param decoyObjectIds array = []

@description('Decoy SERVICE PRINCIPAL object IDs the disable-user playbook may disable (the reachable decoy SP). Disabling these uses the /servicePrincipals Graph endpoint.')
param decoySpObjectIds array = []

@description('Object IDs that must NEVER be disabled (break-glass Global Admins, every current Global Administrator, the activity agent).')
param allowlistObjectIds array = []

@description('Honeypot spoke resource group ID; only resources under this scope may be isolated.')
param honeypotResourceGroupId string

@description('Tags for the playbook RG resources. Production-plausible (NOT the internal-mgmt marker): these resources sit in the production-looking playbook RG and their managed identities are directory-visible, so honeypot ownership is tracked in the inventory, not in tags/names.')
param tags object = {
  environment: 'production'
  workload: 'platform-automation'
  managedBy: 'iac'
}

module sentinelConnection 'modules/response/sentinelConnection.bicep' = {
  name: 'sentinel-connection'
  params: {
    name: 'azuresentinel'
    location: location
    tags: tags
  }
}

// Playbook (Logic App) names are production-plausible and purpose-hidden because their managed
// identities are directory-visible. '01' = the disable-user playbook; '02' = isolate-resource.
module disableUser 'modules/response/playbookDisableUser.bicep' = {
  name: 'pb-disable-user'
  params: {
    name: naming.playbookName(regionCode, '01')
    location: location
    tags: tags
    sentinelConnectionId: sentinelConnection.outputs.id
    decoyObjectIds: decoyObjectIds
    decoySpObjectIds: decoySpObjectIds
    allowlistObjectIds: allowlistObjectIds
  }
}

module isolateResource 'modules/response/playbookIsolateResource.bicep' = {
  name: 'pb-isolate-resource'
  params: {
    name: naming.playbookName(regionCode, '02')
    location: location
    tags: tags
    sentinelConnectionId: sentinelConnection.outputs.id
    honeypotResourceGroupId: honeypotResourceGroupId
  }
}

// Automation rules are child resources of the Sentinel workspace, which now lives in THIS resource
// group, so they are created in-scope (no cross-scope hop).
module ruleDisableUser 'modules/response/automationRule.bicep' = {
  name: 'ar-disable-user'
  params: {
    workspaceName: workspaceName
    automationRuleId: guid(workspaceName, 'ar-disable-user')
    displayName: 'Honeypot: run Disable-User on identity incidents'
    order: 1
    playbookResourceId: disableUser.outputs.id
  }
}

module ruleIsolateResource 'modules/response/automationRule.bicep' = {
  name: 'ar-isolate-resource'
  params: {
    workspaceName: workspaceName
    automationRuleId: guid(workspaceName, 'ar-isolate-resource')
    displayName: 'Honeypot: run Isolate-Resource on resource incidents'
    order: 2
    playbookResourceId: isolateResource.outputs.id
  }
}

@description('Disable-user playbook managed identity, grant it Graph User.EnableDisableAccount + User.ReadWrite.All.')
output disableUserPrincipalId string = disableUser.outputs.principalId

@description('Isolate-resource playbook managed identity, grant it a role with Microsoft.Authorization/locks/write on the honeypot RG.')
output isolateResourcePrincipalId string = isolateResource.outputs.principalId
