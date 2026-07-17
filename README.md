# Identity & Infrastructure Honeypot

A portable Azure / Entra ID **deception platform**. A privileged-*looking* but fully
contained identity and an isolated honeypot spoke lure a post-compromise attacker
into touching decoy-only assets; any interaction is a confident signal that triggers
detection and automated remediation. It deploys *alongside* an existing hub-spoke
and creates no production resources.

## Repository layout
```
bicep/                 Resource / monitoring / SOAR plane
  foundation.bicep     mgmt RG + Log Analytics       network.bicep  orchestrator
  honeypot.bicep       the honeypot spoke            production.bicep  simulated prod (demo)
  detection.bicep      Sentinel + analytics rules    response.bicep    SOAR playbooks
  modules/ parameters/ reusable units + per-env params
terraform/identity/    Entra plane (azuread+azurerm): reachable SP edge (foothold-owned app→SP) + emergency-access reset-me decoy
deploy/                Deploy scripts (foundation→identity→network→edge→detection→response, teardown) + README
tests/                 Verification scripts + sync_inventory + attacker_test_user
inventory/             Module contract (blank template tracked; live ignored)
docs/                  architecture · operations · detection-and-response · design-notes
```

## Two planes, two tools
- **Bicep** — Azure resources, monitoring, SOAR (native what-if, no state).
- **Terraform azuread/azurerm** — identity-scoping (role assignments, app/SP/RBAC).

## Start
Prereqs, deploy order, verification, attack scenarios, and enforcement are in
**`docs/operations.md`**. Architecture and the production/honeypot boundary: `docs/architecture.md`.
