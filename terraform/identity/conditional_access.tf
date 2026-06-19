# Named location for the optional activity agent's source IPs. The CA policy and (later)
# detection/remediation exclude this location so the agent never triggers its own alerts.
resource "azuread_named_location" "agent" {
  count        = length(var.agent_named_location_cidrs) > 0 ? 1 : 0
  display_name = "Corporate Egress"

  ip {
    ip_ranges = var.agent_named_location_cidrs
    trusted   = true
  }
}

# Conditional Access policy targeting the decoy users. Defaults to report-only
# (enabledForReportingButNotEnforced) so it is safe to deploy and observe before enforcing.
# The agent named location is excluded so legitimate activity generation is never blocked.
resource "azuread_conditional_access_policy" "decoy" {
  count        = var.enable_conditional_access ? 1 : 0
  display_name = "Require MFA - Privileged Operations"
  state        = var.ca_policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = concat([azuread_user.lure.object_id], [for u in azuread_user.persona : u.object_id])
      excluded_groups = []
    }

    locations {
      included_locations = ["All"]
      excluded_locations = length(var.agent_named_location_cidrs) > 0 ? [azuread_named_location.agent[0].object_id] : []
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}
