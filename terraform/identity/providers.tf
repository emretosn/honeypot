provider "azuread" {
  # Tenant + auth supplied by environment (ARM_*/AZURE_* or az login).
  # In CI: use_oidc = true with a federated credential.
}

provider "azurerm" {
  features {}
  # subscription_id supplied by environment.
}
