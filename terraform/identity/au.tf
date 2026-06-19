# Production-sounding administrative unit. Every decoy user lives here so the lure's
# privileged-looking role can be AU-scoped to decoys only (containment boundary).
resource "azuread_administrative_unit" "decoy" {
  display_name = var.decoy_au_name
  description  = "Operational administrative unit."
}
