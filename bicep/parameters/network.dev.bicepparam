using '../network.bicep'

param location = 'westeurope'
param regionCode = 'weu'

// From the foundation deployment output. deploy/network.sh fills the subscription id for you.
param workspaceId = '/subscriptions/01169db8-9786-45a8-8878-de556ca253c4/resourceGroups/rg-hp-dev-weu-mgmt/providers/Microsoft.OperationalInsights/workspaces/log-hp-dev-weu'

// DEMO: build the simulated production (hub + representative production spoke) and deploy the
// honeypot alongside it. A REAL deployment sets deployProduction=false and supplies
// existingHubVnetId (the customer's production hub) instead.
param deployProduction = true
param existingHubVnetId = ''

// Simulated production environment (production-sim only).
param hubAddressPrefix = '10.0.0.0/16'
param prodSpokeNamePrefix = 'erp-prod'
param prodSpokeAddressPrefix = '10.10.0.0/16'
param prodStorageAccountName = 'sterpprod32548273'

// Honeypot spoke (the product). Production-looking decoy names, NO honeypot marker.
param spokeNamePrefix = 'core-prod'
param spokeAddressPrefix = '10.20.0.0/16'
param productionAddressPrefixes = ['10.10.0.0/16']
param keyVaultName = 'kv-core-prod-136d'
param storageAccountName = 'stcoreprod32548272'

// Decoy VM (SSH lure) + App Gateway. OFF by default: spoke exposes only decoy KV + storage.
param includeDecoyVm = true
param decoyVmSshPublicKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCS+n05++eZ+rzQS5zrjr+YXtFc2k+UxkTdzM/vo47fyyGc1rFLMfHT7waVmfIeFFx1hxWicdGETYnatvIn4PDPTAyFLoT4bFCBXJNb3r6nMStp/TrrGJysL27GOeGPbyxNnp2MJz94xn7sJJ1edAxc38CmnNPo+B+w/HxSG5WzPlHi50TL2hSrt6mAM6iYx+lW3PtYIjW4EgnQcMTplZYm6JOcbOtGndJFa3qSIyrzPxHfqVGx8rwtDx+Xctps+ynKYvpkNuUl4dCaZXIsZBSYkco3Tzc5nVx1lOmgZkgLPxz7DPnpR73ubbmHwJye7t/G3rSoKczGkujCXIUs7U3kgpMYyFNg22uF94YT3su4u69vTuA2AiBs8zAuz7f4dFIRLxGHB+5+FmhoUmxUxsNrBFyNBOY5WKBfTCI4SYpD6QzyHa8NUlkN+uahMC1tEgz9ll5AiFESv0GNMgjU6osD9p6ih2COmS5xjB66JLMF5JTTZCwiXoWV/QOlF4Gy23L6Sou0NGK+6zqxBh47x/NIozHdZBP3h3pB80yobS7mpkDO8/kxGcT6RUEM1TPDOExH8ik0uo/S3fF8uvQQgdXadJd8J7HKZBwpoTDnjIWcps/XvB73sx1tesjtfX/K0rHi6FqipVFE4yTRbMVccRxQdQ05FZfeLtB7A0ffZZ/l8w== sysadmin@core-prod-app01'   // required only when includeDecoyVm = true
param decoyVmCustomDataBase64 = 'I2Nsb3VkLWNvbmZpZwojIFBsYW50cyBmYWtlLXByb2QgYnJlYWRjcnVtYnMgb24gdGhlIGRlY295IFZNLiBOT05FIG9mIHRoZXNlIHJlc29sdmUgdG8gYW55dGhpbmcgcmVhbDsKIyBlYWNoIGlzIGEgdHJpcHdpcmUgdGhhdCBhZHZlcnRpc2VzIGEgcGF0aCB0byAicHJvZHVjdGlvbiIgdGhlIGF0dGFja2VyIGNhbm5vdCBhY3R1YWxseSB0YWtlLgp3cml0ZV9maWxlczoKICAtIHBhdGg6IC9ob21lL3N5c2FkbWluLy5zc2gvY29uZmlnCiAgICBwZXJtaXNzaW9uczogJzA2MDAnCiAgICBjb250ZW50OiB8CiAgICAgIEhvc3QgcHJvZC1qdW1wCiAgICAgICAgSG9zdE5hbWUganVtcC5jb3JlLXByb2QuaW50ZXJuYWwKICAgICAgICBVc2VyIHN2Yy1kZXBsb3kKICAgICAgICBJZGVudGl0eUZpbGUgfi8uc3NoL2lkX3Byb2QKICAtIHBhdGg6IC9vcHQvYXBwLy5lbnYKICAgIHBlcm1pc3Npb25zOiAnMDY0MCcKICAgIGNvbnRlbnQ6IHwKICAgICAgIyBBcHBsaWNhdGlvbiBjb25maWd1cmF0aW9uIChwcm9kdWN0aW9uKQogICAgICBEQl9DT05ORUNUSU9OPSJTZXJ2ZXI9c3FsLWNvcmUtcHJvZC5kYXRhYmFzZS53aW5kb3dzLm5ldDtEYXRhYmFzZT1jb3JlO1VzZXIgSWQ9YXBwX3J3O1Bhc3N3b3JkPVByMGQtREItRG9Ob3RVc2UtRGVjb3k7IgogICAgICBTVE9SQUdFX0NPTk5FQ1RJT049IkRlZmF1bHRFbmRwb2ludHNQcm90b2NvbD1odHRwcztBY2NvdW50TmFtZT1jb3JlYmFja3VwcztBY2NvdW50S2V5PVptRnJaUzFrWldOdmVTMXJaWGt0Ym05MExYSmxZV3c9OyIKICAgICAgS0VZVkFVTFRfVVJJPSJodHRwczovL2t2LWNvcmUtcHJvZC52YXVsdC5henVyZS5uZXQvIgogIC0gcGF0aDogL29wdC9hcHAvZGVwbG95L1JFQURNRS5tZAogICAgcGVybWlzc2lvbnM6ICcwNjQ0JwogICAgY29udGVudDogfAogICAgICAjIERlcGxveW1lbnQgcnVuYm9vawogICAgICBVc2UgdGhlIGlkZW50aXR5LWFkbWluIHNlcnZpY2UgYWNjb3VudCB0byByb3RhdGUgY3JlZGVudGlhbHMgaW4gS2V5IFZhdWx0LgogICAgICBKdW1wIGhvc3Q6IHByb2QtanVtcCAoc2VlIH4vLnNzaC9jb25maWcpLgo='           // base64 -w0 bicep/assets/decoy-cloud-init.yaml

// Lure-credential honeytoken. network.sh exports these from the identity Terraform output (the real
// lure UPN + password), so recon (a decoy KV secret read) leads to the lure and a sign-in attempt
// trips the lure rules. Empty when the identity stage has not run. Never written to the inventory.
param lureSecretName = readEnvironmentVariable('LURE_SECRET_NAME', '')
param lureSecretValue = readEnvironmentVariable('LURE_SECRET_VALUE', '')
