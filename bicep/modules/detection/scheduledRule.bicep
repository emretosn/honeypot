metadata description = 'A reusable Microsoft Sentinel scheduled (KQL) analytics rule, scoped to the Log Analytics workspace. Each honeypot rule is one instance of this module.'

@description('Name of the Log Analytics workspace Sentinel runs on.')
param workspaceName string

@description('Stable GUID for the rule resource name. Use guid(workspaceName, ruleKey).')
param ruleId string

@description('Alert display name shown in incidents.')
param displayName string

@description('What the rule detects and why it is high-fidelity.')
param ruleDescription string

@description('Severity: High, Medium, Low, Informational.')
@allowed([
  'High'
  'Medium'
  'Low'
  'Informational'
])
param severity string = 'High'

@description('KQL query body.')
param query string

@description('How often the rule runs, ISO8601 duration, e.g. PT5M.')
param queryFrequency string = 'PT5M'

@description('Lookback window, ISO8601 duration, e.g. PT5M. Must be >= queryFrequency.')
param queryPeriod string = 'PT5M'

@description('Trigger when result count is <operator> <threshold>.')
param triggerOperator string = 'GreaterThan'

@description('Result-count threshold the trigger compares against.')
param triggerThreshold int = 0

@description('MITRE ATT&CK tactics.')
param tactics array = []

@description('Entity mappings so incidents carry actionable entities (account, host, IP).')
param entityMappings array = []

@description('Whether the rule is enabled.')
param enabled bool = true

@description('Group all matches in a window into a single incident to avoid alert storms (ISO8601).')
param suppressionDuration string = 'PT1H'

@description('Incident grouping lookback window (ISO8601). New alerts sharing entities within this window fold into the existing incident. Default PT5H suits production; shorten (e.g. PT5M) during testing so each trigger opens a fresh incident.')
param groupingLookbackDuration string = 'PT5H'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource rule 'Microsoft.SecurityInsights/alertRules@2024-09-01' = {
  scope: workspace
  name: ruleId
  kind: 'Scheduled'
  properties: {
    displayName: displayName
    description: ruleDescription
    severity: severity
    enabled: enabled
    query: query
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: triggerOperator
    triggerThreshold: triggerThreshold
    tactics: tactics
    entityMappings: entityMappings
    suppressionEnabled: false
    suppressionDuration: suppressionDuration
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: groupingLookbackDuration
        matchingMethod: 'AllEntities'
      }
    }
  }
}

output ruleResourceId string = rule.id
