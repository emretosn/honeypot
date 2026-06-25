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

variable "decoy_au_name" {
  type        = string
  default     = "IT Operations"
  description = "Innocuous, production-sounding administrative unit name. No honeypot marker."
}

variable "lure_upn_prefix" {
  type        = string
  default     = "identity-admin"
  description = "UPN/mail-nickname prefix of the primary lure. Enticing, role-descriptive."
}

variable "lure_display_name" {
  type        = string
  default     = "Identity Administrator"
  description = "Display name of the primary lure. Privileged-sounding, production-like."
}

variable "lure_job_title" {
  type        = string
  default     = "Senior Identity & Access Administrator"
  description = "Job title that reinforces the lure's apparent privilege."
}

variable "decoy_personas" {
  type = list(object({
    upn_prefix   = string
    display_name = string
    job_title    = string
  }))
  default = [
    { upn_prefix = "helpdesk-admin", display_name = "Helpdesk Administrator", job_title = "Service Desk Administrator" },
    { upn_prefix = "backup-admin", display_name = "Backup Administrator", job_title = "Backup & Recovery Administrator" },
  ]
  description = "Supporting decoy personas in the decoy AU (makes the AU look populated/real)."
}

# --- The lure's apparent privilege: an AU-scoped custom role over decoy users only. ---

# The lure's apparent privilege is a BUILT-IN Entra role assigned at AU scope. Custom roles
# cannot hold reset-password / enable-disable actions, so a built-in AU-scopable role is the
# only way to give the lure genuinely enticing (and Entra-enforced-contained) admin power.
variable "lure_role_definition_id" {
  type = string
  # User Administrator (well-known template ID). AU-scopable; manages users/groups and resets
  # passwords for non-admins in the AU only.
  default     = "fe930be7-5e62-47db-91af-98c3a49a38b1"
  description = "Built-in directory role definition (template) ID assigned to the lure at AU scope. Default = User Administrator."
}

variable "lure_role_name" {
  type        = string
  default     = "User Administrator"
  description = "Display name of the built-in role above (for documentation / outputs only)."
}

# --- Escalation bait ---

variable "decoy_group_name" {
  type        = string
  default     = "Identity Administrators"
  description = "Privileged-sounding security group the lure owns. AzureHound-drawable bait."
}

variable "decoy_app_names" {
  type        = list(string)
  default     = ["Privileged Identity Sync", "Directory Connector"]
  description = "Powerful-sounding owned apps with NO real grants. Each is a tripwire."
}

variable "enable_pim" {
  type        = bool
  default     = false
  description = "If true, grant the custom role to the lure as PIM-ELIGIBLE (requires Entra ID P2); activation is the tripwire. If false, the role is an active assignment. Both stay AU-scoped."
}

variable "foothold_principal_object_id" {
  type        = string
  default     = ""
  description = "OPTIONAL object ID of a likely attacker foothold principal. If set, it is made owner of a decoy app, seeding an explicit foothold->lure escalation edge for demos."
}

# --- Conditional Access ---

variable "enable_conditional_access" {
  type        = bool
  default     = true
  description = "Create a Conditional Access policy targeting the decoy users."
}

variable "ca_policy_state" {
  type        = string
  default     = "enabledForReportingButNotEnforced"
  description = "CA policy state: enabledForReportingButNotEnforced (report-only, safe default), enabled, or disabled."
  validation {
    condition     = contains(["enabled", "disabled", "enabledForReportingButNotEnforced"], var.ca_policy_state)
    error_message = "ca_policy_state must be enabled, disabled, or enabledForReportingButNotEnforced."
  }
}

# Source allowlist for the optional activity-generation agent. Excluded from detection AND remediation.
variable "agent_named_location_cidrs" {
  type        = list(string)
  default     = []
  description = "CIDRs of the (optional) activity agent. Empty = no agent yet."
}

# --- Reachable escalation edge (Phase 04). See docs/sp_path_alternatives.md. ---

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
