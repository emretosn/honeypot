#!/usr/bin/env bash
# End-to-end validation orchestrator. Runs every per-module static/tenant verification in
# order and prints a single summary. Intended to be run after all modules are deployed.
# Pass tenant=1 to include the against-tenant checks (requires az login); default is static.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODE="${1:-static}"            # static | tenant
ENVN="${2:-dev}"
REGION_CODE="${3:-weu}"
MARKER="${4:-hp}"
SPOKE_RG="${5:-rg-core-prod-weu}"
WORKSPACE="${6:-log-${MARKER}-${ENVN}-${REGION_CODE}}"
MGMT_RG="rg-${MARKER}-${ENVN}-${REGION_CODE}-mgmt"

green() { echo "  [OK]   $1"; }
red()   { echo "  [FAIL] $1"; }
fails=0

section() { echo; echo "### $1"; }

run() {
  local label="$1"; shift
  if "$@" >/tmp/hp_step.log 2>&1; then green "$label"; else red "$label"; fails=$((fails+1)); sed 's/^/         /' /tmp/hp_step.log | tail -5; fi
}

section "Static validation (IaC builds)"
run "bicep: foundation" az bicep build-params --file bicep/parameters/foundation.dev.bicepparam --stdout
run "bicep: honeypot"   az bicep build-params --file bicep/parameters/honeypot.dev.bicepparam --stdout
run "bicep: network (orchestrator)" az bicep build-params --file bicep/parameters/network.dev.bicepparam --stdout
run "bicep: detection"  az bicep build-params --file bicep/parameters/detection.dev.bicepparam --stdout
run "bicep: response"   az bicep build-params --file bicep/parameters/response.dev.bicepparam --stdout
run "terraform: identity validate" bash -c 'cd terraform/identity && terraform init -backend=false -input=false >/dev/null && terraform validate'
run "inventory: contract"  ./tests/verify_inventory.sh
run "shell: verify scripts parse" bash -c 'for s in tests/verify_*.sh tests/sync_inventory.sh; do bash -n "$s" || exit 1; done'

if [ "$MODE" = "tenant" ]; then
  section "Against-tenant verification (deployed resources)"
  run "foundation" ./tests/verify_foundation.sh "$ENVN" "$REGION_CODE" "$MARKER"
  run "identity"   ./tests/verify_identity.sh
  run "network"    ./tests/verify_network.sh "$SPOKE_RG"
  run "detection"  ./tests/verify_detection.sh "$MGMT_RG" "$WORKSPACE"
  run "response"   ./tests/verify_response.sh "$MGMT_RG" "$WORKSPACE" "${MARKER}-${ENVN}-${REGION_CODE}"
fi

echo
if [ "$fails" -eq 0 ]; then echo "ALL CHECKS PASSED ($MODE mode)"; else echo "$fails CHECK(S) FAILED ($MODE mode)"; fi
rm -f /tmp/hp_step.log
exit "$fails"
