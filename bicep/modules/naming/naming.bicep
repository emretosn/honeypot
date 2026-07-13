metadata description = 'Internal-plane naming helpers as compile-time functions. The honeypot marker is allowed on resources that are never surfaced to an attacker (Log Analytics, Sentinel, management RGs). EXCEPTION: Logic App playbooks own a managed-identity service principal that is readable directory-wide (AzureHound surfaces its name + resource-id path), so playbook names/RG must NOT carry the marker — use playbookName / playbookResourceGroup, which are production-plausible. Decoy-plane names are produced separately by the network module and must NOT carry the marker.'

@description('Base token: <marker>-<env>-<regionCode>.')
@export()
func base(marker string, env string, regionCode string) string => '${marker}-${env}-${regionCode}'

@description('Internal management resource group.')
@export()
func mgmtResourceGroup(marker string, env string, regionCode string) string => 'rg-${base(marker, env, regionCode)}-mgmt'

@description('Log Analytics workspace.')
@export()
func logAnalyticsWorkspace(marker string, env string, regionCode string) string => 'log-${base(marker, env, regionCode)}'

@description('Production-plausible resource group that HOSTS the SOAR playbooks. Deliberately carries NO honeypot marker: Logic App managed identities project a service principal into the directory that any member can read (surfaced by tools like AzureHound via displayName + the resource-id path in alternativeNames), so the playbook RG must look like ordinary production automation. Honeypot ownership for these resources lives in the inventory, not in the name.')
@export()
func playbookResourceGroup(regionCode string) string => 'rg-core-ops-${regionCode}'

@description('Production-plausible, purpose-hidden SOAR playbook (Logic App) name. Same directory-leak rationale as playbookResourceGroup — the name is visible via the managed identity, so it must NOT reveal "disable-user"/"isolate-resource" or the honeypot marker. Callers pass an opaque suffix (e.g. "01").')
@export()
func playbookName(regionCode string, suffix string) string => 'logic-core-ops-${regionCode}-${suffix}'
