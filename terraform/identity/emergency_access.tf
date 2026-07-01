# Standalone "reset-me" deception — independent of the lure and its AU. A hollow, admin-named
# account that ANY compromised identity (here the foothold; production: everyone, via a
# role-assignable group) can reset the password of — and ONLY that account.
#
# Why a single-member AU: Entra has no single-USER scope for directory roles, and custom roles
# cannot hold the password-reset action, so the ONLY way to constrain "reset" to exactly one
# account is to isolate that account in its own administrative unit and scope a BUILT-IN
# Password Administrator role to that AU. The AU scopes the TARGET (this one decoy), NOT the
# assignees — no mass AU enrollment. The account is powerless (no roles, no RBAC, owns nothing);
# resetting it or signing in as it is a high-fidelity tripwire that leads nowhere real.

# Dedicated AU holding only the emergency-access decoy (defines the reset blast radius = 1 account).
resource "azuread_administrative_unit" "emergency" {
  display_name = var.emergency_au_name
  description  = "Privileged and emergency access accounts."
}

resource "random_password" "emergency" {
  length           = 24
  special          = true
  override_special = "!@#$%^&*()-_"
}

# The hollow admin-named decoy. Enticing name, ZERO privileges.
resource "azuread_user" "emergency" {
  user_principal_name   = "${var.emergency_upn_prefix}@${var.verified_domain}"
  display_name          = var.emergency_display_name
  mail_nickname         = var.emergency_upn_prefix
  job_title             = var.emergency_job_title
  account_enabled       = true
  password              = random_password.emergency.result
  force_password_change = false
}

resource "azuread_administrative_unit_member" "emergency" {
  administrative_unit_object_id = azuread_administrative_unit.emergency.object_id
  member_object_id              = azuread_user.emergency.object_id
}

# The reset power: the foothold holds built-in Password Administrator scoped to the single-member
# emergency AU, so it can reset the password of ONLY this decoy. Count-gated on the foothold id so
# identity still deploys without a foothold. In production, principal_object_id would be a
# role-assignable group representing "everyone".
resource "azuread_directory_role_assignment" "emergency_reset" {
  count               = var.foothold_principal_object_id == "" ? 0 : 1
  role_id             = var.emergency_reset_role_id
  principal_object_id = var.foothold_principal_object_id
  directory_scope_id  = "/administrativeUnits/${azuread_administrative_unit.emergency.object_id}"
}
