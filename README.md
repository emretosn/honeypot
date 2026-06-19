# Identity & Infrastructure Honeypot

Deception honeypot on Azure / Entra ID. A privileged-*looking* but fully contained
identity and an isolated honeypot network spoke lure a post-compromise attacker into
touching decoy-only assets; any interaction is a near-100%-true-positive signal that
triggers detection and automated remediation.

## Repository layout

```
bicep/        Resource / monitoring / SOAR plane (Bicep)
  foundation.bicep        Subscription-scope entrypoint (management RG + Log Analytics)
  modules/                Reusable modules (naming, monitoring, network, spoke, detection, response)
  parameters/             *.bicepparam per environment
terraform/
  identity/               Identity-scoping plane (Terraform azuread): AU, custom role, CA, named location
inventory/
  decoy-inventory.json    Single source of truth for decoy object IDs / allowlist (consumed by detection + remediation)
tests/                    Post-deploy verification scripts (az CLI / bash; run against your tenant)
```

## Two planes, two tools (and why)

| Plane | Tool | Reason |
|---|---|---|
| Azure resources, monitoring, SOAR | **Bicep** | Native, what-if, no state to manage. |
| Identity-scoping primitives (AU, custom role + assignment, Conditional Access, named location) | **Terraform `azuread`** | The Microsoft Graph Bicep extension cannot reliably author these today. |
| Plain directory objects (users, groups, apps/SPs) | **Microsoft Graph Bicep extension** or `az rest` Graph calls | No PowerShell dependency. |

## Dual naming convention (OPSEC)

Honeypot markers must **never** leak to anything an attacker can read.

* **Internal plane** (Log Analytics, Sentinel, playbooks, management RGs): attacker never
  sees these — the `hp` marker is allowed (e.g. `rg-hp-mgmt-dev-weu`).
* **Decoy plane** (honeypot spoke VNet/VM/KV/storage, decoy identities): must mimic
  production — **no** honeypot marker in any name, UPN, display name, group or role name.
  Honeypot identity lives only in (a) a tag the decoy-scoped identity cannot read and
  (b) `inventory/decoy-inventory.json`.

## Prerequisites

* Azure subscription + Entra tenant (Entra ID **P1** licensing for AU/CA/named location; **P2** for PIM/Identity Protection/UEBA — see `docs/foundation.md`).
* `az` CLI, `bicep` (`az bicep install`), `terraform` >= 1.5, `jq`.
* A deploy service principal with Graph admin consent (scopes listed in `docs/foundation.md`).

## Build order

Foundation → Identity → Network → Detection → Response → Validation →
Activity agent (optional) → CI/CD. Each module is independently deployable and has a
guide under `docs/`.
