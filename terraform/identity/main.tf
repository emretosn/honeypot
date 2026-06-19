# Identity-plane root module — decoy identity honeypot.
# Builds: a production-looking administrative unit, a privileged-LOOKING but fully
# contained lure identity (AU-scoped custom role, no real RBAC), supporting personas,
# escalation bait (owned group + powerful-sounding empty apps), optional PIM eligibility,
# and a Conditional Access policy targeting the decoys. All marker-free and attacker-facing.

data "azuread_client_config" "current" {}

locals {
  # Directory-scope string for AU-scoped role assignments.
  au_scope = "/administrativeUnits/${azuread_administrative_unit.decoy.object_id}"
}
