metadata description = 'Internal-plane naming helpers as compile-time functions. The management plane (resource group, Log Analytics, Sentinel) and the SOAR playbooks now share ONE production-plausible resource group with NO honeypot marker in any name: Logic App playbooks own a managed-identity service principal that is readable directory-wide (AzureHound surfaces its displayName + the resource-id path, which includes the resource group name), so nothing that co-locates with a playbook may carry the marker. Honeypot ownership lives in non-readable tags + the inventory, never in names. Decoy-plane names are produced separately by the network module and must NOT carry the marker either.'

@description('Production-plausible management/operations resource group. Hosts Log Analytics, Sentinel AND the SOAR playbooks, no honeypot marker (a playbook managed identity leaks the resource-id path directory-wide).')
@export()
func mgmtResourceGroup(regionCode string) string => 'rg-core-ops-${regionCode}'

@description('Production-plausible Log Analytics / Sentinel workspace name. No marker (kept production-plausible for defense in depth).')
@export()
func logAnalyticsWorkspace(regionCode string) string => 'log-core-ops-${regionCode}'

@description('Production-plausible, purpose-hidden SOAR playbook (Logic App) name. The name is visible via the managed identity, so it must NOT reveal "disable-user"/"isolate-resource" or a honeypot marker. Callers pass an opaque suffix (e.g. "01").')
@export()
func playbookName(regionCode string, suffix string) string => 'logic-core-ops-${regionCode}-${suffix}'
