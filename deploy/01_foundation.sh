#!/usr/bin/env bash
# Deploy the internal management plane (management RG + Log Analytics) via Bicep.
# Needed if you want to SEE ALERTS (detection lands here). Bicep keeps no state on Azure,
# so run from your workstation. Idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
load_config
require_login

info "Deploying foundation (subscription scope)"
az deployment sub create \
  --location "$REGION" \
  --template-file "$REPO_ROOT/bicep/foundation.bicep" \
  --parameters "$REPO_ROOT/bicep/parameters/foundation.dev.bicepparam" \
  -o none
ok "foundation deployed (RG=$MGMT_RG, workspace=$WORKSPACE)"

echo "  Verify: ./tests/verify_foundation.sh $ENVN $REGION_CODE $MARKER"
