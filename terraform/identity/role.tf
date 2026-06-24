# The lure's apparent privilege: a BUILT-IN Entra role (User Administrator by default)
# assigned at AU scope. Entra enforces the scope, so this power applies ONLY to the
# non-admin decoy personas in the decoy AU — powerful over decoys, powerless over production,
# and it cannot reset admin passwords. This is the "prize" an attacker wants to steal.

# Active AU-scoped assignment (default). The lure HOLDS the role, scoped to decoys only.
# Used when PIM is not enabled.
resource "azuread_directory_role_assignment" "lure_active" {
  count = var.enable_pim ? 0 : 1

  role_id             = var.lure_role_definition_id
  principal_object_id = azuread_user.lure.object_id
  directory_scope_id  = local.au_scope
}

# PIM-eligible AU-scoped assignment (opt-in, requires Entra ID P2). The lure must ACTIVATE
# the role — that activation is a high-fidelity tripwire. Used instead of the active
# assignment when enable_pim = true.
resource "azuread_directory_role_eligibility_schedule_request" "lure_eligible" {
  count = var.enable_pim ? 1 : 0

  role_definition_id = var.lure_role_definition_id
  principal_id       = azuread_user.lure.object_id
  directory_scope_id = local.au_scope
  justification      = "Operational account management eligibility."
}
