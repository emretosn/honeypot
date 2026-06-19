metadata description = 'Microsoft Sentinel automation rule that runs a playbook when a honeypot incident is created. Scoped to incidents whose title starts with "Honeypot:" so only honeypot rules trigger remediation.'

@description('Name of the Log Analytics workspace Sentinel runs on.')
param workspaceName string

@description('Stable GUID for the automation rule resource name.')
param automationRuleId string

@description('Display name of the automation rule.')
param displayName string

@description('Order in which the rule runs.')
param order int = 1

@description('Resource ID of the Logic App playbook to run.')
param playbookResourceId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource automationRule 'Microsoft.SecurityInsights/automationRules@2024-09-01' = {
  scope: workspace
  name: automationRuleId
  properties: {
    displayName: displayName
    order: order
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentTitle'
            operator: 'StartsWith'
            propertyValues: [
              'Honeypot:'
            ]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: playbookResourceId
          tenantId: subscription().tenantId
        }
      }
    ]
  }
}

output id string = automationRule.id
