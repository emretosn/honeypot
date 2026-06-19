# The lure's apparent privilege. A custom directory role whose actions are AU-scopable
# user-management only — powerful over decoy users, powerless over production. This is the
# "prize" an attacker wants to steal; every target it can act on is a decoy.
resource "azuread_custom_directory_role" "lure" {
  display_name = var.custom_role_name
  description  = "Manage service and operational accounts."
  enabled      = true
  version      = "1"

  permissions {
    allowed_resource_actions = var.custom_role_actions
  }
}

# Active AU-scoped assignment (default). The lure HOLDS the role, scoped to decoys only.
# Used when PIM is not enabled.
resource "azuread_directory_role_assignment" "lure_active" {
  count = var.enable_pim ? 0 : 1

  role_id             = azuread_custom_directory_role.lure.object_id
  principal_object_id = azuread_user.lure.object_id
  directory_scope_id  = local.au_scope
}

# PIM-eligible AU-scoped assignment (opt-in, requires Entra ID P2). The lure must ACTIVATE
# the role — that activation is a high-fidelity tripwire. Used instead of the active
# assignment when enable_pim = true.
resource "azuread_directory_role_eligibility_schedule_request" "lure_eligible" {
  count = var.enable_pim ? 1 : 0

  role_definition_id = azuread_custom_directory_role.lure.object_id
  principal_id       = azuread_user.lure.object_id
  directory_scope_id = local.au_scope
  justification      = "Operational account management eligibility."
}
