metadata description = 'SOAR playbook: on a Microsoft Sentinel incident involving a honeypot resource, apply a ReadOnly lock to the offending resource for evidence preservation and isolation, then comment on the incident. Only acts on resource IDs that sit under the configured honeypot resource group prefix; anything else is skipped.'

@description('Logic App (playbook) name.')
param name string

@description('Deployment location.')
param location string

@description('Resource ID of the azuresentinel API connection.')
param sentinelConnectionId string

@description('Honeypot resource group ID prefix. Only resources under this scope are isolated.')
param honeypotResourceGroupId string

@description('Resource tags.')
param tags object = {}

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnectionId
            connectionName: 'azuresentinel'
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
      honeypotResourceGroupId: {
        value: honeypotResourceGroupId
      }
    }
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          type: 'Object'
        }
        honeypotResourceGroupId: {
          type: 'String'
          defaultValue: ''
        }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            body: {
              callback_url: '@{listCallbackUrl()}'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        For_each_resource: {
          type: 'Foreach'
          foreach: '@triggerBody()?[\'object\']?[\'properties\']?[\'relatedEntities\']'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 1
            }
          }
          actions: {
            Guard_is_honeypot_resource: {
              type: 'If'
              expression: {
                and: [
                  {
                    equals: [
                      '@toLower(coalesce(items(\'For_each_resource\')?[\'kind\'], \'\'))'
                      'azureresource'
                    ]
                  }
                  {
                    startsWith: [
                      '@toLower(coalesce(items(\'For_each_resource\')?[\'properties\']?[\'resourceId\'], \'\'))'
                      '@toLower(parameters(\'honeypotResourceGroupId\'))'
                    ]
                  }
                ]
              }
              actions: {
                Apply_lock: {
                  type: 'Http'
                  inputs: {
                    method: 'PUT'
                    #disable-next-line no-hardcoded-env-urls
                    uri: 'https://management.azure.com@{items(\'For_each_resource\')?[\'properties\']?[\'resourceId\']}/providers/Microsoft.Authorization/locks/honeypot-isolation?api-version=2020-05-01'
                    body: {
                      properties: {
                        level: 'ReadOnly'
                        notes: 'Isolated by honeypot SOAR for evidence preservation.'
                      }
                    }
                    authentication: {
                      type: 'ManagedServiceIdentity'
                      #disable-next-line no-hardcoded-env-urls
                      audience: 'https://management.azure.com'
                    }
                  }
                }
                Comment_isolated: {
                  type: 'ApiConnection'
                  runAfter: {
                    Apply_lock: ['Succeeded']
                  }
                  inputs: {
                    host: {
                      connection: {
                        name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
                      }
                    }
                    method: 'post'
                    path: '/Incidents/Comment'
                    body: {
                      incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
                      message: 'Honeypot SOAR: applied ReadOnly isolation lock to honeypot resource @{items(\'For_each_resource\')?[\'properties\']?[\'resourceId\']}.'
                    }
                  }
                }
              }
              else: {
                actions: {
                  Comment_not_honeypot: {
                    type: 'ApiConnection'
                    inputs: {
                      host: {
                        connection: {
                          name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
                        }
                      }
                      method: 'post'
                      path: '/Incidents/Comment'
                      body: {
                        incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
                        message: 'Honeypot SOAR: NO isolation action on @{coalesce(items(\'For_each_resource\')?[\'properties\']?[\'resourceId\'], \'(non-resource entity)\')}, NOT under the honeypot resource group. Real resources are never locked by this playbook.'
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

output id string = playbook.id
output name string = playbook.name
output principalId string = playbook.identity.principalId
