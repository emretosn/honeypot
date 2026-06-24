# State is LOCAL during dev/test: Terraform keeps state in terraform.tfstate on the
# operator's machine. That file is gitignored and contains sensitive values (incl. the
# lure password), so protect the machine accordingly.
#
# A remote azurerm backend (private-network storage account) is introduced in the CI/CD
# stage, where shared state and locking actually matter. The hardened backend account is
# defined in bootstrap/ for that stage. To migrate later:
#   1. add a `terraform { backend "azurerm" {} }` block here,
#   2. run `terraform init -migrate-state -backend-config=backend.hcl`.
#
# No backend block here = local backend.
