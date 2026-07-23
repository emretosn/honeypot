variable "env" {
  type        = string
  default     = "dev"
  description = "Environment short name."
}

# --- Decoy-plane realism. These names are attacker-visible: production-like, NO honeypot marker. ---

variable "verified_domain" {
  type        = string
  description = "A verified Entra domain for decoy UPNs, e.g. contoso.onmicrosoft.com."
}

variable "foothold_principal_object_id" {
  type        = string
  default     = ""
  description = "Object ID of the attacker foothold principal. If set, it is made owner of the reachable decoy app (reachable_edge.tf) so it can add a credential and take over the decoy SP, the genuine, contained escalation path."
}

# --- Reachable escalation edge. ---

variable "reachable_app_name" {
  type        = string
  default     = "core-automation-runner"
  description = "Production-plausible name of the decoy app the foothold can take over (a normal dev would own one app reg). NO honeypot marker."
}

variable "decoy_resource_group_id" {
  type        = string
  default     = ""
  description = "Resource ID of the decoy honeypot RG (from inventory.network.honeypotResourceGroupId). When set, the decoy SP is granted Owner on it (the contained payoff). Empty = skip (identity can deploy before the network exists)."
}

variable "decoy_key_vault_id" {
  type        = string
  default     = ""
  description = "Resource ID of the decoy Key Vault (from inventory.network.keyVaultId). When set, the decoy SP is granted Key Vault Secrets User so it can read the honeytoken secrets. Empty = skip."
}

variable "decoy_storage_account_id" {
  type        = string
  default     = ""
  description = "Resource ID of the decoy storage account (from inventory.network.storageAccountId). When set, the decoy SP is granted Storage Blob Data Reader so it can read the breadcrumb blobs over Entra auth (shared-key auth is disabled on the account). Empty = skip."
}

# --- Standalone reset-me deception (emergency-access decoy). See emergency_access.tf. ---

variable "emergency_au_name" {
  type        = string
  default     = "Privileged Access"
  description = "Display name of the dedicated single-member AU that holds only the emergency-access decoy (scopes the reset power to one account). Production-sounding, NO honeypot marker."
}

variable "emergency_upn_prefix" {
  type        = string
  default     = "emergency-access"
  description = "UPN/mail-nickname prefix of the emergency-access decoy. Enticing, break-glass-sounding."
}

variable "emergency_display_name" {
  type        = string
  default     = "Emergency Access Admin"
  description = "Display name of the emergency-access decoy. Privileged-sounding; the account has ZERO real power."
}

variable "emergency_job_title" {
  type        = string
  default     = "Emergency Access Administrator"
  description = "Job title reinforcing the decoy's apparent privilege."
}

variable "emergency_reset_role_id" {
  type = string
  # Privileged Authentication Administrator (well-known built-in template ID). AU-scopable; can reset
  # auth methods/passwords of ANY user (admin OR non-admin) but only for members IN the assigned AU.
  # SAFETY: never add a real admin to the emergency AU, PAA can reset in-AU admins.
  default     = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
  description = "Built-in directory role template ID granted to the foothold at the emergency AU scope. Default = Privileged Authentication Administrator."
}

# --- Production/honeypot boundary & response contract inputs ---

variable "deploy_production" {
  type        = bool
  default     = false
  description = "false (HONEYPOT-ONLY mode): decoy identities deploy alongside an existing production environment; the foothold and break-glass are supplied as INPUTS. true (PRODUCTION-SIM mode): this project also seeds a simulated *production* environment (e.g. a throwaway foothold + break-glass placeholder) so the honeypot can be demonstrated. A real deployment uses false."
}

variable "break_glass_object_ids" {
  type        = list(string)
  default     = []
  description = "Object IDs of the (production) real break-glass / Global Admin accounts. Supplied as an INPUT; flows to inventory allowlist.breakGlassObjectIds so detection excludes them and response never disables them. Empty only in early testing."
}
