#!/usr/bin/env bash
# Deploy the honeypot network plane (hub-spoke) via Bicep — subscription scope. Creates the
# honeypot spoke (decoy Key Vault + storage, NSGs with egress-to-prod denied, hub peering) and,
# in production-simulation mode, a thin hub to deploy alongside. Bicep keeps no state on Azure,
# so run from your workstation. Idempotent.
#
# The decoy VM / App Gateway are OFF by default (includeDecoyVm=false in the param file): no SSH
# key needed and no slow App Gateway provision. To add the SSH lure, set includeDecoyVm=true and
# decoyVmSshPublicKey in bicep/parameters/network.dev.bicepparam.
#
# Usage:
#   deploy/network.sh              # what-if preview, then prompt to deploy
#   deploy/network.sh --yes        # skip the prompt (still shows what-if)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
require_login

PARAM="$REPO_ROOT/bicep/parameters/network.dev.bicepparam"
[ -f "$PARAM" ] || die "missing $PARAM"

# Fill the subscription id into the workspaceId path (the one value that is tenant-specific).
if grep -q 'REPLACE_SUB' "$PARAM"; then
  info "Substituting your subscription id into workspaceId"
  sed -i "s#/subscriptions/REPLACE_SUB/#/subscriptions/$CURRENT_SUB/#" "$PARAM"
fi

# Guard: if the SSH lure is enabled, a public key must be present.
if grep -qiE '^\s*param\s+includeDecoyVm\s*=\s*true' "$PARAM"; then
  grep -qiE "^\s*param\s+decoyVmSshPublicKey\s*=\s*'ssh-" "$PARAM" \
    || die "includeDecoyVm=true but decoyVmSshPublicKey is not set in $PARAM (generate one: ssh-keygen -t rsa -b 4096 -f ./decoy_key -N '')."
fi

# Catch any leftover placeholders before the (slow) deploy.
if grep -q 'REPLACE' "$PARAM"; then
  die "unfilled REPLACE placeholder(s) in $PARAM — fix before deploying."
fi

# Lure-credential honeytoken: if the identity stage has run, plant the REAL lure UPN + password in
# the decoy Key Vault so recon leads to the lure and a sign-in attempt trips the lure rules. The
# value is read by the .bicepparam via readEnvironmentVariable and passed as a @secure() param — it
# is never written to the inventory. Skipped cleanly if the identity output is unavailable.
INV="$REPO_ROOT/inventory/decoy-inventory.json"
LURE_UPN=$(jq -r '.identity.lure.upn // ""' "$INV" 2>/dev/null)
LURE_PW=$(terraform -chdir="$REPO_ROOT/terraform/identity" output -raw lure_password 2>/dev/null || echo "")
if [ -n "$LURE_UPN" ] && [ "$LURE_UPN" != "null" ] && [ -n "$LURE_PW" ]; then
  export LURE_SECRET_NAME="identity-admin-credentials"
  export LURE_SECRET_VALUE="${LURE_UPN} / ${LURE_PW}"
  info "Planting lure-credential honeytoken '$LURE_SECRET_NAME' in the decoy Key Vault"
else
  export LURE_SECRET_NAME=""
  export LURE_SECRET_VALUE=""
  info "Lure credential not available (identity stage not applied) — skipping lure honeytoken"
fi

info "Preview (what-if)"
az deployment sub create \
  --location "$REGION" \
  --template-file "$REPO_ROOT/bicep/network.bicep" \
  --parameters "$PARAM" \
  --what-if

if [ "${1:-}" != "--yes" ]; then
  read -r -p "Deploy this network plane? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || die "aborted by user."
fi

info "Deploying network (subscription scope)"
az deployment sub create \
  --location "$REGION" \
  --name network \
  --template-file "$REPO_ROOT/bicep/network.bicep" \
  --parameters "$PARAM" \
  -o none

SPOKE_RG=$(az deployment sub show --name network --query "properties.outputs.honeypotResourceGroupName.value" -o tsv 2>/dev/null || echo "")
ok "network deployed${SPOKE_RG:+ (spoke RG=$SPOKE_RG)}"

# Auto-fill the inventory network section (KV/storage/RG IDs) from the deployment outputs, so the
# single source of truth is current before detection/response consume it.
info "Syncing decoy inventory from network outputs"
"$REPO_ROOT/tests/sync_inventory.sh" || die "inventory sync failed — run tests/sync_inventory.sh manually."
ok "inventory synced"

echo
ok "Next:"
echo "  - Grant the decoy SP its decoy-RG RBAC:  ./deploy/edge.sh"
echo "  - Verify:  ./tests/verify_network.sh ${SPOKE_RG:-rg-core-prod-weu}"
echo "  - Decoy KV/storage rules auto-enable once their telemetry has ingested; re-run detection.sh later if they were skipped (or force now: ENABLE_RESOURCE_RULES=true ./deploy/detection.sh)"
