#!/usr/bin/env bash
# Throwaway ATTACKER TEST identity for honeypot validation. Creates a plain, non-privileged
# member user with NO roles, NOT in the decoy AU, and NOT in any allowlist — i.e. exactly
# what an attacker's foothold looks like. Use it to enumerate (AzureHound) and to be the
# non-allowlisted actor in detection tests. DELETE it when done.
#
# Usage:
#   tests/attacker_test_user.sh create   # prints UPN + password
#   tests/attacker_test_user.sh delete
set -uo pipefail

ACTION="${1:-create}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INV="$ROOT/inventory/decoy-inventory.json"

die() { echo "ERROR: $1" >&2; exit 1; }

az account show >/dev/null 2>&1 || die "run 'az login' first."

# Derive the verified domain from the lure UPN in the inventory.
LURE_UPN=$(jq -r '.identity.lure.upn' "$INV" 2>/dev/null)
[ -n "$LURE_UPN" ] && [ "$LURE_UPN" != "null" ] || die "lure UPN not found in $INV (run tests/sync_inventory.sh)."
DOMAIN="${LURE_UPN#*@}"
UPN="attacker-test@${DOMAIN}"

case "$ACTION" in
  create)
    if az ad user show --id "$UPN" >/dev/null 2>&1; then
      echo "Attacker test user already exists: $UPN"
      echo "Reset its password with: az ad user update --id $UPN --password '<newpw>'"
      exit 0
    fi
    PW="Aa1!$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
    az ad user create \
      --display-name "Attacker Test" \
      --user-principal-name "$UPN" \
      --mail-nickname "attacker-test" \
      --password "$PW" \
      --force-change-password-next-sign-in false \
      -o none || die "failed to create user (need User Administrator / Global Admin)."
    echo "Created ATTACKER TEST user:"
    echo "  UPN:      $UPN"
    echo "  Password: $PW"
    echo
    echo "It has NO roles, is NOT in the decoy AU, and is NOT allowlisted."
    echo "Use it to enumerate (AzureHound) / act as the non-allowlisted attacker."
    echo "DELETE when finished:  tests/attacker_test_user.sh delete"
    ;;
  delete)
    az ad user delete --id "$UPN" -o none 2>/dev/null && echo "Deleted $UPN" || echo "User $UPN not found (nothing to delete)."
    ;;
  *)
    die "unknown action '$ACTION' (use: create | delete)"
    ;;
esac
