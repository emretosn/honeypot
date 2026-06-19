metadata description = 'API connection to the Microsoft Sentinel (azuresentinel) managed connector, authenticated with the playbook Logic Apps managed identity. Required for the Sentinel incident trigger and for adding incident comments.'

@description('Connection resource name.')
param name string

@description('Deployment location.')
param location string

@description('Resource tags.')
param tags object = {}

resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: name
  location: location
  tags: tags
  #disable-next-line BCP187
  kind: 'V1'
  properties: {
    displayName: name
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
    #disable-next-line BCP037
    parameterValueType: 'Alternative'
  }
}

output id string = sentinelConnection.id
output name string = sentinelConnection.name
