# Escalation bait — genuine, AzureHound/BloodHound-drawable edges that advertise a path,
# but resolve to nothing real. Touching any of these is a tripwire.

# Privileged-sounding security group the lure owns. An attacker who reaches the lure can
# manage its membership — a believable escalation primitive that grants nothing real.
resource "azuread_group" "decoy" {
  display_name     = var.decoy_group_name
  security_enabled = true
  description      = "Access group for identity administration."
  owners           = [azuread_user.lure.object_id]
}

# Lure is also a member, so the group looks legitimately populated.
resource "azuread_group_member" "lure" {
  group_object_id  = azuread_group.decoy.object_id
  member_object_id = azuread_user.lure.object_id
}

# Powerful-sounding applications with NO real grants/permissions. The lure owns them, so
# "owner can add a credential and act as the app" looks like an escalation route — but the
# apps can do nothing. Each owned app is an AzureHound edge and a tripwire.
resource "azuread_application" "decoy" {
  for_each = toset(var.decoy_app_names)

  display_name     = each.value
  sign_in_audience = "AzureADMyOrg"
  owners           = [azuread_user.lure.object_id]
}

# OPTIONAL explicit foothold -> lure edge for demos: make the chosen foothold principal an
# owner of the first decoy app, so AzureHound draws foothold --Owner--> app <--Owner-- lure.
resource "azuread_application_owner" "foothold_edge" {
  count = var.foothold_principal_object_id == "" ? 0 : 1

  application_id  = azuread_application.decoy[var.decoy_app_names[0]].id
  owner_object_id = var.foothold_principal_object_id
}
