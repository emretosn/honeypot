using '../detection.bicep'

// Workspace from the foundation deployment.
param workspaceName = 'log-core-ops-weu'

// From the network deployment outputs.
param decoyKeyVaultName = 'kv-core-prod-REPLACE'
param decoyStorageAccountName = 'stcoreprodREPLACE'
param decoyVmName = 'core-prod-app01'

// Allowlist the activity-agent source IPs from sign-in detection (empty = none yet).
param signInAllowlistIps = []

// Privileged-auth allowlist: object IDs of the real admins + service principals allowed to reset
// OTHER users' passwords/auth methods. Anyone else doing so trips the privileged-auth-abuse rule.
// deploy/detection.sh injects this from inventory.allowlist.breakGlassObjectIds. Self-service
// (initiator == target) is always excluded.
param privilegedAuthAllowlistIds = []

// Reachable-edge, decoy app/SP ids from inventory.identity.reachableApp. Enables credential-add,
// SP sign-in and consent rules. deploy/detection.sh injects these; values here are for validation.
param reachableAppId = ''
param reachableSpObjectId = ''
param enableReachableEdgeRules = false

// Emergency-access decoy (standalone reset-me path), UPN from
// inventory.identity.emergencyAccess. Injected at deploy time; empty here disables its sign-in rule.
param emergencyAccessUpn = ''

// Decoy VM run-command rule; enabled by deploy/detection.sh once the VM + AzureActivity exist.
param enableVmRunCommandRule = false

// Incident grouping window.
param groupingLookbackDuration = 'PT5H'
