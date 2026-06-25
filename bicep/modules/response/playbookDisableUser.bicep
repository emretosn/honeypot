metadata description = 'SOAR playbook: on a Microsoft Sentinel incident, disable the offending account and revoke its sessions via Microsoft Graph (managed identity). SAFETY: every account is checked against an allowlist (break-glass + agent) and a dryRun flag; an allowlisted account or dryRun mode performs NO change and only comments. This guarantees remediation never actions a real admin.'

@description('Logic App (playbook) name.')
param name string

@description('Deployment location.')
param location string

@description('Resource ID of the azuresentinel API connection.')
param sentinelConnectionId string

@description('SAFETY KEY 1 — the decoy identities this playbook is ALLOWED to disable (lure, personas, canary identities, from inventory.identity). An account is actioned ONLY if it is in this list. Anything not here (a real admin who fat-fingered into the trap, an attacker-controlled real account) is never disabled.')
param decoyObjectIds array = []

@description('SAFETY KEY 2 — object IDs that must NEVER be disabled even if somehow present in the decoy list (real break-glass GA, the activity agent).')
param allowlistObjectIds array = []

@description('Dry-run: when true the playbook only comments and makes no change. Recommended for the initial soak period.')
param dryRun bool = true

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
      allowlistObjectIds: {
        value: allowlistObjectIds
      }
      decoyObjectIds: {
        value: decoyObjectIds
      }
      dryRun: {
        value: dryRun
      }
    }
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          type: 'Object'
        }
        allowlistObjectIds: {
          type: 'Array'
          defaultValue: []
        }
        decoyObjectIds: {
          type: 'Array'
          defaultValue: []
        }
        dryRun: {
          type: 'Bool'
          defaultValue: true
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
        For_each_account: {
          type: 'Foreach'
          foreach: '@triggerBody()?[\'object\']?[\'properties\']?[\'relatedEntities\']'
          actions: {
            Check_is_account: {
              type: 'If'
              expression: {
                and: [
                  {
                    equals: [
                      '@toLower(coalesce(items(\'For_each_account\')?[\'kind\'], \'\'))'
                      'account'
                    ]
                  }
                ]
              }
              actions: {
                Guard_is_decoy: {
                  type: 'If'
                  expression: {
                    and: [
                      {
                        contains: [
                          '@parameters(\'decoyObjectIds\')'
                          '@items(\'For_each_account\')?[\'properties\']?[\'aadUserId\']'
                        ]
                      }
                    ]
                  }
                  actions: {
                    Guard_allowlist_and_dryrun: {
                      type: 'If'
                      expression: {
                        and: [
                          {
                            not: {
                              contains: [
                                '@parameters(\'allowlistObjectIds\')'
                                '@items(\'For_each_account\')?[\'properties\']?[\'aadUserId\']'
                              ]
                            }
                          }
                          {
                            equals: [
                              '@parameters(\'dryRun\')'
                              false
                            ]
                          }
                        ]
                      }
                      actions: {
                        Disable_user: {
                          type: 'Http'
                          inputs: {
                            method: 'PATCH'
                            uri: 'https://graph.microsoft.com/v1.0/users/@{items(\'For_each_account\')?[\'properties\']?[\'aadUserId\']}'
                            body: {
                              accountEnabled: false
                            }
                            authentication: {
                              type: 'ManagedServiceIdentity'
                              audience: 'https://graph.microsoft.com'
                            }
                          }
                        }
                        Revoke_sessions: {
                          type: 'Http'
                          runAfter: {
                            Disable_user: ['Succeeded']
                          }
                          inputs: {
                            method: 'POST'
                            uri: 'https://graph.microsoft.com/v1.0/users/@{items(\'For_each_account\')?[\'properties\']?[\'aadUserId\']}/revokeSignInSessions'
                            authentication: {
                              type: 'ManagedServiceIdentity'
                              audience: 'https://graph.microsoft.com'
                            }
                          }
                        }
                        Comment_remediated: {
                          type: 'ApiConnection'
                          runAfter: {
                            Revoke_sessions: ['Succeeded']
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
                              message: 'Honeypot SOAR: disabled DECOY @{items(\'For_each_account\')?[\'properties\']?[\'friendlyName\']} and revoked sessions.'
                            }
                          }
                        }
                      }
                      else: {
                        actions: {
                          Comment_decoy_skipped: {
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
                                message: 'Honeypot SOAR: @{items(\'For_each_account\')?[\'properties\']?[\'friendlyName\']} is a decoy but was NOT disabled (allowlisted break-glass/agent, or dry-run mode).'
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                  else: {
                    actions: {
                      Comment_not_a_decoy: {
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
                            message: 'Honeypot SOAR: NO action on @{items(\'For_each_account\')?[\'properties\']?[\'friendlyName\']} — NOT a decoy identity. Real accounts are never disabled by this playbook.'
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
  }
}

output id string = playbook.id
output name string = playbook.name
output principalId string = playbook.identity.principalId
