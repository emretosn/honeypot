#!/usr/bin/env bash
# Deploy the honeypot network plane via Bicep, subscription scope. Builds a self-contained
# hub-spoke: a simulated production (hub + representative prod spoke) and the honeypot spoke
# alongside it (private decoy VM + KV + storage, NSGs with egress-to-prod denied, hub peering).
# Bicep keeps no state on Azure, so run from your workstation. Idempotent.
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

# The decoy VM always deploys; a public key must be present.
grep -qiE "^\s*param\s+decoyVmSshPublicKey\s*=\s*'ssh-" "$PARAM" \
  || die "decoyVmSshPublicKey is not set in $PARAM (generate one: ssh-keygen -t rsa -b 4096 -f ./decoy_key -N '')."

# Catch any leftover placeholders before the (slow) deploy.
if grep -q 'REPLACE' "$PARAM"; then
  die "unfilled REPLACE placeholder(s) in $PARAM, fix before deploying."
fi

INV="$REPO_ROOT/inventory/decoy-inventory.json"

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
"$REPO_ROOT/tests/sync_inventory.sh" || die "inventory sync failed, run tests/sync_inventory.sh manually."
ok "inventory synced"

# Seed breadcrumb blobs into the decoy storage 'backups' container, the "valuable assets" an
# internal attacker who takes over the reachable SP (RG Owner -> list keys) finds. Inert canaries;
# reading any of them via SAS/AccountKey trips the decoy-storage rule. Idempotent (overwrites).
SA_NAME=$(basename "$(jq -r '.network.storageAccountId // ""' "$INV" 2>/dev/null)")
if [ -n "$SA_NAME" ] && [ "$SA_NAME" != "null" ]; then
  info "Seeding breadcrumb blobs into $SA_NAME/backups"
  SA_KEY=$(az storage account keys list -n "$SA_NAME" -g "${SPOKE_RG:-rg-core-prod-$REGION_CODE}" --query '[0].value' -o tsv 2>/dev/null || echo "")
  if [ -n "$SA_KEY" ]; then
    TMPD=$(mktemp -d)
    cat > "$TMPD/db-backup-2026-06.sql.txt" <<'EOF'
-- core-prod database export (nightly). DO NOT DISTRIBUTE
-- connection: Server=sql-core-prod.database.windows.net;Database=core;User Id=svc_app;Password=<vaulted>
INSERT INTO app_config (k, v) VALUES ('storage.account', 'stcoreprod');
INSERT INTO app_config (k, v) VALUES ('keyvault.uri', 'https://kv-core-prod.vault.azure.net/');
EOF
    cat > "$TMPD/appsettings.Production.json" <<'EOF'
{
  "ConnectionStrings": {
    "Sql": "Server=sql-core-prod.database.windows.net;Database=core;User Id=app_rw;Password=mj5K9W3iGj22JzJNlid5;",
    "Storage": "DefaultEndpointsProtocol=https;AccountName=corebackups;AccountKey=J1qzkk7bx+g+Ml8bZBXxDnv7KNC7uLosBlx0pTaLP4fWlDm8bsOX5hbMggcM7jKoZpbboUZrdrllUn+OG6I5zQ==;"
  },
  "KeyVaultUri": "https://kv-core-prod.vault.azure.net/",
  "GitHub": {
    "Organization": "core-prod-platform",
    "DeployRepo": "core-prod-platform/infrastructure",
    "Pat": "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"
  }
}
EOF
    for f in "$TMPD"/*; do
      az storage blob upload --account-name "$SA_NAME" --account-key "$SA_KEY" \
        --container-name backups --file "$f" --name "$(basename "$f")" --overwrite -o none 2>/dev/null \
        && ok "seeded backups/$(basename "$f")" \
        || echo "  WARN: could not upload $(basename "$f") (check network rules / data-plane access)"
    done
    rm -rf "$TMPD"
  else
    echo "  WARN: could not list storage keys for $SA_NAME, skipping blob seeding (seed manually later)."
  fi
fi

echo
ok "Next:"
echo "  - Grant the decoy SP its decoy-RG RBAC:  ./deploy/edge.sh"
echo "  - Verify:  ./tests/verify_network.sh ${SPOKE_RG:-rg-core-prod-weu}"
echo "  - Decoy KV/storage/VM rules auto-enable once their telemetry has ingested; re-run detection.sh later if they were skipped on the first pass."
