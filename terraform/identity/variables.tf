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

variable "custom_role_name" {
  type        = string
  default     = "Service Account Administrator"
  description = "Privileged-sounding custom directory role name. Powerful over decoys, powerless over prod."
}

variable "custom_role_actions" {
  type = list(string)
  default = [
    "microsoft.directory/users/standard/read",
    "microsoft.directory/users/basic/update",
    "microsoft.directory/users/password/update",
  ]
  description = "Allowed resource actions. MUST be AU-scopable user-management actions only (containment)."
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
