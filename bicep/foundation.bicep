metadata description = 'Subscription-scope entrypoint for the foundation plane. Creates the internal management resource group and the shared Log Analytics workspace that the identity, network, detection and response modules consume.'

targetScope = 'subscription'

import * as naming from 'modules/naming/naming.bicep'

@description('Environment short name, e.g. dev / test / prod.')
param env string = 'dev'

@description('Azure region for all foundation resources.')
param location string = 'westeurope'

@description('Region short code used in resource names.')
param regionCode string = 'weu'

@description('Interactive log retention in days.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 90

@description('Daily Log Analytics ingestion cap (GB). Bounds Sentinel cost in non-prod.')
param dailyQuotaGb int = 2

@description('Common tags. project=honeypot is the internal ownership marker; safe here because the management plane is not attacker-visible.')
param tags object = {
  project: 'honeypot'
  plane: 'internal-mgmt'
  managedBy: 'iac'
}

@description('Honeypot marker for the internal plane. Never applied to decoy-plane resources.')
param marker string = 'hp'

resource mgmtRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: naming.mgmtResourceGroup(marker, env, regionCode)
  location: location
  tags: tags
}

module law 'modules/monitoring/logAnalytics.bicep' = {
  name: 'logAnalytics'
  scope: mgmtRg
  params: {
    name: naming.logAnalyticsWorkspace(marker, env, regionCode)
    location: location
    retentionInDays: retentionInDays
    dailyQuotaGb: dailyQuotaGb
    tags: tags
  }
}

@description('Management resource group name — input to the detection and response modules.')
output mgmtResourceGroupName string = mgmtRg.name

@description('Log Analytics workspace resource ID — input to the detection module and all diagnostics.')
output logAnalyticsWorkspaceId string = law.outputs.workspaceId

@description('Log Analytics workspace name.')
output logAnalyticsWorkspaceName string = law.outputs.name
