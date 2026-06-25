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

// Reachable-edge (Phase 04) — decoy app/SP ids from inventory.identity.reachableApp.
// deploy/03_detection.sh injects these from the inventory; values here are for static validation.
param reachableAppId = ''
param reachableSpObjectId = ''
param enableReachableEdgeRules = false

// Enumeration rule is best-effort and noisier; off by default.
param enableEnumerationRule = false
