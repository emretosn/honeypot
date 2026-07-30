# Architecture

A portable Azure / Entra ID **deception platform**: a privileged-*looking* but fully contained
honeypot that deploys alongside an existing hub-spoke, lures a post-compromise attacker into
touching decoy-only assets, and turns any interaction into a high-confidence alert + automated
containment.

## Two planes
- **Management/operations plane** (production-plausible, **no marker in any name**; ownership lives
  in non-readable tags + inventory): `rg-core-ops-*` co-hosting Log Analytics, Sentinel and the SOAR
  playbooks, plus the hub. Named production-plausibly because a Logic App managed identity is a
  directory-readable SP that leaks its resource-id path (AzureHound), so nothing that co-locates with
  a playbook may carry a marker.
- **Decoy plane** (production-looking, no marker): the honeypot spoke, decoy identities, canaries.

## Production vs honeypot boundary
The honeypot composition (`honeypot.bicep`) never creates production; it consumes a hub VNet +
workspace as inputs, so it drops in alongside a real environment. The demo orchestrator
(`network.bicep`, used by `network.sh`) always stands up a thin simulated production (hub +
representative prod spoke) and deploys the honeypot alongside it, so the whole thing runs
self-contained in an empty subscription.

## Module contract — `inventory/decoy-inventory.json`
Single source of truth. Producers (identity, network) write object IDs; consumers (detection,
response, cleanup) read them. Detection/response params are generated from it. Live file is
gitignored; `inventory/decoy-inventory.template.json` is the blank tracked template,
seeded + filled by `tests/sync_inventory.sh`.

## Repository layout
- `bicep/` — resource/monitoring/SOAR plane.
  - `foundation.bicep` mgmt RG + Log Analytics. `network.bicep` orchestrator → `production.bicep`
    (sim) + `honeypot.bicep` (the spoke). `detection.bicep` Sentinel + rules. `response.bicep`
    playbooks + automation rules. `modules/` reusable units; `parameters/` per-env params.
- `terraform/identity/` — Entra plane (azuread + azurerm): the reachable escalation edge
  (`reachable_edge.tf`: foothold-owned app with an unconsented god-mode Graph request + pre-seeded
  cert/secret → contained decoy SP, Owner of the decoy RG + KV Secrets User) and the standalone
  emergency-access reset-me decoy (`emergency_access.tf`: Privileged Authentication Administrator
  scoped to a single-member AU).
- `deploy/` — deploy scripts (foundation → identity → network → edge → detection → response) + teardown + lib.sh + config.env.
- `tests/` — verification scripts + `sync_inventory.sh` + `attacker_test_user.sh`.
- `inventory/` — the module contract (template tracked, live ignored).

## Build order
foundation → identity → network → detection → response. See `docs/operations.md`.
