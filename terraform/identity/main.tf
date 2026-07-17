# Identity-plane root module, decoy identity honeypot.
# Builds two contained, attacker-reachable escalation paths (all marker-free, attacker-facing):
#   1. A standalone hollow admin the foothold can reset via AU-scoped Privileged Authentication
#      Administrator (emergency_access.tf), AzureHound renders the AU-scoped role as tenant-root.
#   2. A reachable decoy app the foothold OWNS (reachable_edge.tf): it requests an unconsented
#      god-mode Graph permission and carries pre-seeded credentials, and its service principal is
#      the contained payoff (Owner of the decoy RG + Key Vault Secrets User).

data "azuread_client_config" "current" {}
