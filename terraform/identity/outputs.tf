output "tenant_id" {
  value       = data.azuread_client_config.current.tenant_id
  description = "Tenant the identity plane is deployed into (sanity check)."
}

# --- Values consumed by inventory/decoy-inventory.json (detection + remediation allowlist). ---

output "decoy_administrative_unit_id" {
  value       = azuread_administrative_unit.decoy.object_id
  description = "Object ID of the decoy administrative unit."
}

output "lure" {
  value = {
    upn          = azuread_user.lure.user_principal_name
    object_id    = azuread_user.lure.object_id
    display_name = azuread_user.lure.display_name
  }
  description = "Primary lure identity identifiers."
}

output "decoy_persona_object_ids" {
  value       = [for u in azuread_user.persona : u.object_id]
  description = "Object IDs of the supporting decoy personas."
}

output "custom_role_definition_id" {
  value       = azuread_custom_directory_role.lure.object_id
  description = "Object ID of the lure's AU-scoped custom directory role."
}

output "decoy_group_id" {
  value       = azuread_group.decoy.object_id
  description = "Object ID of the privileged-sounding decoy group."
}

output "decoy_app_ids" {
  value       = [for a in azuread_application.decoy : a.object_id]
  description = "Object IDs of the powerful-sounding decoy applications."
}

output "agent_named_location_id" {
  value       = length(azuread_named_location.agent) > 0 ? azuread_named_location.agent[0].object_id : ""
  description = "Object ID of the agent named location (empty if no agent configured)."
}

output "lure_password" {
  value       = random_password.lure.result
  sensitive   = true
  description = "Lure password for the manual interactive sign-in validation scenario. Retrieve with: terraform output -raw lure_password"
}
