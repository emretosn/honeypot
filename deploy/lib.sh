#!/usr/bin/env bash
# Shared helpers for the deploy/*.sh scripts. Sourced, not run directly.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEPLOY_DIR/.." && pwd)"

CONFIG_FILE="${CONFIG_FILE:-$DEPLOY_DIR/config.env}"

info() { echo "==> $1"; }
ok()   { echo "  [OK] $1"; }
die()  { echo "ERROR: $1" >&2; exit 1; }

load_config() {
  [ -f "$CONFIG_FILE" ] || die "missing $CONFIG_FILE — copy deploy/config.env.example to it and fill it in."
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"

  : "${ENVN:=dev}"; : "${REGION:=westeurope}"; : "${REGION_CODE:=weu}"; : "${MARKER:=hp}"
  MGMT_RG="rg-${MARKER}-${ENVN}-${REGION_CODE}-mgmt"
  WORKSPACE="log-${MARKER}-${ENVN}-${REGION_CODE}"
}

require_login() {
  az account show >/dev/null 2>&1 || die "not logged in — run 'az login' first."
  if [ -n "${SUBSCRIPTION_ID:-}" ]; then
    az account set --subscription "$SUBSCRIPTION_ID"
  fi
  CURRENT_SUB="$(az account show --query id -o tsv)"
  info "Subscription: $CURRENT_SUB"
}
