metadata description = 'Onboards Microsoft Sentinel onto the foundation Log Analytics workspace. Deploy this module scoped to the workspace resource group.'

@description('Name of the existing Log Analytics workspace to enable Sentinel on.')
param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource onboarding 'Microsoft.SecurityInsights/onboardingStates@2024-09-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

output workspaceId string = workspace.id
