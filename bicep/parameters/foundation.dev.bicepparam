using '../foundation.bicep'

param env = 'dev'
param location = 'westeurope'
param regionCode = 'weu'
param retentionInDays = 90
param dailyQuotaGb = 2
param tags = {
  project: 'honeypot'
  plane: 'internal-mgmt'
  managedBy: 'iac'
  env: 'dev'
}
