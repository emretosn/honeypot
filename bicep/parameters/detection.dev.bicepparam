using '../detection.bicep'

// Workspace from the foundation deployment.
param workspaceName = 'log-hp-dev-weu'

// From inventory/decoy-inventory.json (identity.lure.upn).
param lureUpn = 'identity-admin@REPLACE.onmicrosoft.com'

// From the network deployment outputs.
param decoyKeyVaultName = 'kv-core-prod-REPLACE'
param decoyStorageAccountName = 'stcoreprodREPLACE'

// Allowlist the activity-agent source IPs from sign-in detection (empty = none yet).
param signInAllowlistIps = []

// Reachable-edge — decoy app/SP ids from inventory.identity.reachableApp.
// deploy/detection.sh injects these from the inventory; values here are for static validation.
param reachableAppId = ''
param reachableSpObjectId = ''
param enableReachableEdgeRules = false

// Expanded coverage — decoy UPNs + group from the inventory. Injected at deploy time.
param decoyUpns = []
param decoyGroupId = ''
param enableCoverageRules = false
param enumerationBreadthThreshold = 200

// Enumeration breadth-anomaly rule is best-effort/behavioural; off by default.
param enableEnumerationRule = false
