metadata description = 'Internal-plane naming helpers as compile-time functions. The honeypot marker is allowed here because these resources (Log Analytics, Sentinel, playbooks, management RGs) are never visible to an attacker. Decoy-plane names are produced separately by the network module and must NOT carry the marker.'

@description('Base token: <marker>-<env>-<regionCode>.')
@export()
func base(marker string, env string, regionCode string) string => '${marker}-${env}-${regionCode}'

@description('Internal management resource group.')
@export()
func mgmtResourceGroup(marker string, env string, regionCode string) string => 'rg-${base(marker, env, regionCode)}-mgmt'

@description('Log Analytics workspace.')
@export()
func logAnalyticsWorkspace(marker string, env string, regionCode string) string => 'log-${base(marker, env, regionCode)}'

@description('Automation account (SOAR / playbooks).')
@export()
func automationAccount(marker string, env string, regionCode string) string => 'aa-${base(marker, env, regionCode)}'
