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

// Enumeration rule is best-effort and noisier; off by default.
param enableEnumerationRule = false
