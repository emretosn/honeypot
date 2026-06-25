using '../production.bicep'

// SIMULATED production environment (demo only) — a real customer already has this.
param env = 'dev'
param location = 'westeurope'
param regionCode = 'weu'
param marker = 'hp'

param hubAddressPrefix = '10.0.0.0/16'

// Representative production spoke — a DIFFERENT production-looking workload from the honeypot.
param prodSpokeNamePrefix = 'erp-prod'
param prodSpokeAddressPrefix = '10.10.0.0/16'
param prodStorageAccountName = 'sterpprod32548273'
