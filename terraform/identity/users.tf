# Strong random passwords for the decoy accounts. Kept in state only (sensitive),
# surfaced via the lure_password output for the manual sign-in validation scenario.
resource "random_password" "lure" {
  length           = 24
  special          = true
  override_special = "!@#$%^&*()-_"
}

resource "random_password" "persona" {
  for_each         = { for p in var.decoy_personas : p.upn_prefix => p }
  length           = 24
  special          = true
  override_special = "!@#$%^&*()-_"
}

# Primary lure: privileged-LOOKING human admin account. Holds an AU-scoped custom role
# (role.tf) and owns powerful-sounding bait (bait.tf) — but has NO real subscription RBAC.
resource "azuread_user" "lure" {
  user_principal_name   = "${var.lure_upn_prefix}@${var.verified_domain}"
  display_name          = var.lure_display_name
  mail_nickname         = var.lure_upn_prefix
  job_title             = var.lure_job_title
  account_enabled       = true
  password              = random_password.lure.result
  force_password_change = false
}

# Supporting personas — make the AU look populated and real.
resource "azuread_user" "persona" {
  for_each = { for p in var.decoy_personas : p.upn_prefix => p }

  user_principal_name   = "${each.value.upn_prefix}@${var.verified_domain}"
  display_name          = each.value.display_name
  mail_nickname         = each.value.upn_prefix
  job_title             = each.value.job_title
  account_enabled       = true
  password              = random_password.persona[each.key].result
  force_password_change = false
}

# Place every decoy account into the decoy AU (defines the containment boundary).
resource "azuread_administrative_unit_member" "lure" {
  administrative_unit_object_id = azuread_administrative_unit.decoy.object_id
  member_object_id              = azuread_user.lure.object_id
}

resource "azuread_administrative_unit_member" "persona" {
  for_each = azuread_user.persona

  administrative_unit_object_id = azuread_administrative_unit.decoy.object_id
  member_object_id              = each.value.object_id
}
