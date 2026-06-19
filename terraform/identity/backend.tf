# Remote state with locking. Provide the values at init time, e.g.:
#   terraform init -backend-config=backend.hcl   (see docs/foundation.md, step 3)
# Keep this block empty so the same config works for both interactive (use_azuread_auth)
# and CI/OIDC (use_oidc) auth. The backend storage account lives in the internal
# management plane, keeping decoy/identity state out of any attacker-reachable location.
terraform {
  backend "azurerm" {}
}
