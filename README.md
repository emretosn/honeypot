# Identity & Infrastructure Honeypot

A portable Azure / Entra ID **deception platform**. A privileged-*looking* but fully contained
identity and an isolated honeypot spoke lure a post-compromise attacker into touching decoy-only
assets; any interaction is a near-100%-true-positive signal that triggers detection and
automated, dry-run-by-default remediation. It deploys *alongside* an existing hub-spoke and
creates no production resources.

## Repository layout
```
bicep/                 Resource / monitoring / SOAR plane
  foundation.bicep     mgmt RG + Log Analytics       network.bicep  orchestrator
  honeypot.bicep       the honeypot spoke            production.bicep  simulated prod (demo)
  detection.bicep      Sentinel + analytics rules    response.bicep    SOAR playbooks
  modules/ parameters/ reusable units + per-env params
terraform/identity/    Entra plane (azuread+azurerm): AU, lure, role, bait, reachable SP edge, CA
deploy/                Ordered deploy scripts (01_foundation … 05_network) + lib + config
tests/                 Verification scripts + sync_inventory + attacker_test_user
inventory/             Module contract (blank template tracked; live ignored)
docs/                  architecture · operations · detection-and-response · design-notes
```

## Two planes, two tools
- **Bicep** — Azure resources, monitoring, SOAR (native what-if, no state).
- **Terraform azuread/azurerm** — identity-scoping (AU, role assignments, CA, app/SP/RBAC).

## OPSEC
The `hp` marker appears only on internal-mgmt resources (never attacker-visible). Decoy names are
production-plausible; honeypot ownership lives only in non-readable tags + the inventory.

## Start
Prereqs, deploy order, verification, attack scenarios, and enforcement are in
**`docs/operations.md`**. Architecture and the production/honeypot boundary: `docs/architecture.md`.
