# Design notes

## Key decisions
- **Bicep** for resource/monitoring/SOAR; **Terraform azuread/azurerm** for identity-scoping
  (role assignments, app/SP/RBAC) which Bicep can't reliably author.
- **Two contained, attacker-reachable paths** (no lure/personas/bait — they added no path the
  foothold could reach): (1) the reachable app/SP edge, (2) the emergency-access reset-me decoy.
- **Reachable, MFA-proof edge:** foothold owns a decoy app → adds secret → signs in as the SP.
  SPs bypass user MFA, so this is the realistic path; the SP is contained (see below).
- **Emergency-access reset-me:** the foothold holds Privileged Authentication Administrator scoped
  to a single-member AU, so it can reset only that hollow admin. AzureHound renders the AU-scoped
  role as tenant-wide, drawing a fake tenant-takeover path; live Graph proves the real scope is one AU.
- **No marker in any name / co-located mgmt plane:** a Logic App system-assigned MI is a
  directory-readable SP; AzureHound surfaces its `displayName` + resource-id path (which includes the
  RG name) even to a principal with no RBAC on that RG. So nothing that co-locates with a playbook may
  carry a marker. The whole management/operations plane is therefore production-plausible: one RG
  (`rg-core-ops-*`) co-hosts Log Analytics, Sentinel, the playbooks (`logic-core-ops-*-01/02`) and
  their automation rules. Honeypot ownership lives only in non-readable tags + the inventory.
- **Two-key guard:** remediation acts only on an object that is in the decoy inventory AND not
  allowlisted, so it can never touch a real identity or resource.

## Decoy SP: "looks dangerous, isn't"
Make an SP enticing to enumeration without granting it any real Graph power. Options:
1. **Unconsented Graph "god-mode" REQUEST** — the app *requests* a high permission
   (RoleManagement.ReadWrite.Directory, Application) but it is deliberately **never consented**, so
   `appRoleAssignments` stays empty and the SP has **zero** real Graph capability. It looks enticing
   in enumeration (a requested high permission). Note the foothold cannot make it real: a non-admin
   consent attempt is denied and writes no audit event, so the consent/app-role-grant rule fires only
   if a real admin actually grants it (insider signal). (Used here.) Rejected alternative: granting a
   *real* read-only permission (e.g. a consented User.Read.All) to pass an attacker's "is it actually
   granted?" check — that trades a canary-shaped dangling request for genuine tenant-wide read of all
   users, which is real attacker power and was judged not worth the realism gain.
2. **Pre-seeded credentials** — the app carries a client secret + self-signed cert so it looks like a
   real, actively-used automation app in enumeration (the values live only in Terraform state).
3. **Real Azure RBAC scoped to the decoy RG** — Owner on the honeypot RG + Key Vault Secrets User
   (used here; egress to production denied).
Current build = #1 + #2 + #3 + foothold owner. Verify asserts the SP has ZERO consented Graph app
roles (the god-mode request is unconsented) and RBAC only on the decoy RG/KV.

## Known gaps / future
- Resource + VM-run-command rules need their log tables to ingest before they deploy (auto-gated by
  deploy/detection.sh).
- Realism/aging (staggered dates, sign-in history, sprawl) and a CI/CD stage are not yet built.
  Remote tfstate backend (jump VM/private endpoint) deferred to the CI/CD stage.
