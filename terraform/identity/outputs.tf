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

output "lure_role_definition_id" {
  value       = var.lure_role_definition_id
  description = "Definition (template) ID of the built-in role assigned to the lure at AU scope."
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

output "break_glass_object_ids" {
  value       = var.break_glass_object_ids
  description = "Production break-glass/GA object IDs (input). Synced to inventory allowlist.breakGlassObjectIds so detection excludes and response never disables them."
}

output "deploy_production" {
  value       = var.deploy_production
  description = "Whether the identity plane was deployed in production-simulation mode (seeds simulated production identities)."
}

output "reachable_app" {
  value = {
    app_id        = azuread_application.reachable.client_id
    app_object_id = azuread_application.reachable.object_id
    sp_object_id  = azuread_service_principal.reachable.object_id
    display_name  = azuread_application.reachable.display_name
  }
  description = "Reachable decoy app/SP the foothold can take over. Consumed by detection (credential-add + SP sign-in rules)."
}

output "reachable_sp_rbac_scoped" {
  value = {
    rg_owner       = length(azurerm_role_assignment.sp_rg_owner) > 0
    kv_secrets_read = length(azurerm_role_assignment.sp_kv_secrets) > 0
  }
  description = "Whether the decoy SP's contained Azure RBAC (Owner on decoy RG, KV Secrets User) is in place. False until the network is deployed and the ids are passed."
}

output "lure_password" {
  value       = random_password.lure.result
  sensitive   = true
  description = "Lure password for the manual interactive sign-in validation scenario. Retrieve with: terraform output -raw lure_password"
}

output "emergency_access" {
  value = {
    upn                    = azuread_user.emergency.user_principal_name
    object_id              = azuread_user.emergency.object_id
    display_name           = azuread_user.emergency.display_name
    administrative_unit_id = azuread_administrative_unit.emergency.object_id
    reset_role_assigned    = length(azuread_directory_role_assignment.emergency_reset) > 0
  }
  description = "Standalone hollow admin the foothold can reset (Password Administrator scoped to a single-member AU). Consumed by detection (reset + sign-in rules) and response (disable-user guard)."
}

output "emergency_access_password" {
  value       = random_password.emergency.result
  sensitive   = true
  description = "Emergency-access decoy password (manual validation only). Retrieve with: terraform output -raw emergency_access_password"
}
