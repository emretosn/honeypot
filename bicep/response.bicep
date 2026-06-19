metadata description = 'Response plane (SOAR). Deploys two Logic App playbooks — Disable-User-And-Revoke-Sessions and Isolate-Honeypot-Resource — plus the Microsoft Sentinel automation rules that run them on honeypot incidents. SAFETY by design: both playbooks default to dryRun=true and honor an allowlist / honeypot-scope guard so they can never action a real admin or a non-honeypot resource. Deploy scoped to the foundation management resource group.'

targetScope = 'resourceGroup'

import * as naming from 'modules/naming/naming.bicep'

@description('Environment short name.')
param env string = 'dev'

@description('Location for the playbooks.')
param location string = 'westeurope'

@description('Region short code for internal-plane names.')
param regionCode string = 'weu'

@description('Honeypot marker (internal plane).')
param marker string = 'hp'

@description('Name of the Log Analytics workspace Sentinel runs on.')
param workspaceName string

@description('Object IDs that must NEVER be disabled (real break-glass GA, the activity agent).')
param allowlistObjectIds array = []

@description('Honeypot spoke resource group ID — only resources under this scope may be isolated.')
param honeypotResourceGroupId string

@description('Dry-run for BOTH playbooks. Keep true for the initial soak; set false to enforce.')
param dryRun bool = true

@description('Internal-plane tags.')
param tags object = {
  project: 'honeypot'
  plane: 'internal-mgmt'
  managedBy: 'iac'
}

var baseName = naming.base(marker, env, regionCode)

module sentinelConnection 'modules/response/sentinelConnection.bicep' = {
  name: 'sentinel-connection'
  params: {
    name: 'azuresentinel'
    location: location
    tags: tags
  }
}

module disableUser 'modules/response/playbookDisableUser.bicep' = {
  name: 'pb-disable-user'
  params: {
    name: 'pb-${baseName}-disable-user'
    location: location
    tags: tags
    sentinelConnectionId: sentinelConnection.outputs.id
    allowlistObjectIds: allowlistObjectIds
    dryRun: dryRun
  }
}

module isolateResource 'modules/response/playbookIsolateResource.bicep' = {
  name: 'pb-isolate-resource'
  params: {
    name: 'pb-${baseName}-isolate-resource'
    location: location
    tags: tags
    sentinelConnectionId: sentinelConnection.outputs.id
    honeypotResourceGroupId: honeypotResourceGroupId
    dryRun: dryRun
  }
}

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

@description('Disable-user playbook managed identity — grant it Graph User.EnableDisableAccount + User.ReadWrite.All.')
output disableUserPrincipalId string = disableUser.outputs.principalId

@description('Isolate-resource playbook managed identity — grant it a role with Microsoft.Authorization/locks/write on the honeypot RG.')
output isolateResourcePrincipalId string = isolateResource.outputs.principalId
