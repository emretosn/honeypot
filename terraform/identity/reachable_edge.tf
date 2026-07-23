# Reachable escalation edge, a decoy service principal the foothold can take over.
# Design + rationale: docs/design-notes.md ("Decoy SP: looks dangerous, isn't"). Combines:
#   Unconsented Graph "god-mode" REQUEST (Entra-visible hook, looks dangerous, grants nothing)
#   Real-but-contained Azure RBAC payoff (Owner of the decoy RG + KV Secrets read)
#   Takeover primitive: the foothold is a direct OWNER of the app, so it can add a credential.
# Every step (credential-add, SP sign-in, KV read, decoy-RG action) is a contained tripwire.

# Microsoft Graph well-known IDs (for the unconsented permission REQUEST only, never consented).
locals {
  ms_graph_app_id                      = "00000003-0000-0000-c000-000000000000"
  graph_rolemanagement_readwrite_dir   = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" # RoleManagement.ReadWrite.Directory (Application)
}

# The decoy app. Mundane, production-plausible name (a normal dev would own one app reg), but it
# REQUESTS a high Graph permission that is never consented, so it LOOKS enticing in enumeration
# while the SP has zero real Graph power.
resource "azuread_application" "reachable" {
  display_name     = var.reachable_app_name
  sign_in_audience = "AzureADMyOrg"

  # HOOK: request god-mode, but we deliberately create NO app_role_assignment / admin consent,
  # so appRoleAssignments stays empty. A self-consent ATTEMPT by the attacker is a tripwire.
  required_resource_access {
    resource_app_id = local.ms_graph_app_id
    resource_access {
      id   = local.graph_rolemanagement_readwrite_dir
      type = "Role"
    }
  }

  # Takeover primitive: the foothold owns the app, so it can add a client secret and act as the SP.
  owners = var.foothold_principal_object_id == "" ? [] : [var.foothold_principal_object_id]
}

resource "azuread_service_principal" "reachable" {
  client_id = azuread_application.reachable.client_id
}

# Pre-seeded credentials, realism bait. A genuine automation app almost always carries at least one
# active client secret and/or certificate, so enumeration that finds passwordCredentials +
# keyCredentials on this app reads as a real, actively-used service, not a bare honeypot husk. The
# values are held only in Terraform state (never surfaced), so an attacker cannot use them; the
# attacker still has to ADD its OWN credential to take over the SP, which is the credential-add
# tripwire. These pre-seeded ones only shape how the app looks in AzureHound/BloodHound.
resource "azuread_application_password" "reachable_seed" {
  application_id = azuread_application.reachable.id
  display_name   = "automation-runtime"
  end_date       = timeadd(timestamp(), "8760h") # ~1 year from apply

  lifecycle {
    # end_date is computed from apply time; ignore drift so the secret is not rotated every plan.
    ignore_changes = [end_date]
  }
}

resource "tls_private_key" "reachable_seed" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "reachable_seed" {
  private_key_pem = tls_private_key.reachable_seed.private_key_pem

  subject {
    common_name  = var.reachable_app_name
    organization = "Core Platform Automation"
  }

  validity_period_hours = 8760 # ~1 year
  allowed_uses          = ["digital_signature", "key_encipherment"]
}

resource "azuread_application_certificate" "reachable_seed" {
  application_id = azuread_application.reachable.id
  type           = "AsymmetricX509Cert"
  value          = tls_self_signed_cert.reachable_seed.cert_pem
  end_date       = tls_self_signed_cert.reachable_seed.validity_end_time
}

# PAYOFF (post-takeover, contained): the SP is Owner of the DECOY resource group. Looks like
# subscription-grade power; scoped to a decoy RG whose egress to production is denied. Count-gated
# so identity still deploys before the network exists (empty id = skip; set on the second pass).
resource "azurerm_role_assignment" "sp_rg_owner" {
  count                = var.decoy_resource_group_id == "" ? 0 : 1
  scope                = var.decoy_resource_group_id
  role_definition_name = "Owner"
  principal_id         = azuread_service_principal.reachable.object_id
  principal_type       = "ServicePrincipal"
}

# Frictionless honeytoken read: SP can read decoy KV secrets directly (the KV is RBAC-authorized).
resource "azurerm_role_assignment" "sp_kv_secrets" {
  count                = var.decoy_key_vault_id == "" ? 0 : 1
  scope                = var.decoy_key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azuread_service_principal.reachable.object_id
  principal_type       = "ServicePrincipal"
}

# Decoy storage data-plane read. The storage account has shared-key (account key / SAS) auth
# disabled, so the payoff is an Entra-token blob read; Owner on the RG is control-plane only and does
# NOT grant blob data access, so the SP needs an explicit data role. Storage Blob Data Reader is the
# minimum that lets the taken-over SP list/read the breadcrumb blobs (each read a tripwire), scoped
# to the decoy account only. Count-gated so identity still deploys before the network exists.
resource "azurerm_role_assignment" "sp_blob_reader" {
  count                = var.decoy_storage_account_id == "" ? 0 : 1
  scope                = var.decoy_storage_account_id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azuread_service_principal.reachable.object_id
  principal_type       = "ServicePrincipal"
}
