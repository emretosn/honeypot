# Detection & response

## Detection (Sentinel)
All rules are parameterised from the inventory and built in `bicep/detection.bicep`. They are
deterministic and inventory-scoped: any event touching a named decoy object is a near-100%
true-positive, so all are **High** and drive remediation without tuning.

| Kill-chain step | Rule | Table |
|---|---|---|
| Reset the emergency-access decoy | privileged auth action by non-allowlisted principal | AuditLogs |
| Sign-in as emergency-access | sign-in as emergency-access decoy | SigninLogs |
| Credential added to the decoy app/SP | credential added | AuditLogs |
| Sign-in as the decoy SP | sign-in as decoy SP | AADServicePrincipalSignInLogs |
| Admin makes the god-mode request real (insider) | admin consent granted to decoy app/SP | AuditLogs |
| Decoy KV honeytoken read | KV secret accessed | AzureDiagnostics |
| Decoy storage read | storage accessed | StorageBlobLogs |
| Run-command on the decoy VM | run-command on decoy VM | AzureActivity |

Notes: every rule maps `AadUserId` + coalesce fallbacks so entities are never empty;
`verify_detection.sh` runs each rule's query against the live schema and fails on a missing column
or empty entity. KV rule = secret reads only; storage = shared-key/SAS access plus Entra (OAuth)
reads by the decoy SP, scoped to the SP object id (excludes platform noise) — **attacker tooling
(CLI/PowerShell) is never excluded**. The privileged-auth rule is
allowlist-based (fires on any non-allowlisted cross-principal reset — curate the allowlist during
soak). The consent rule is opt-in and only fires on a real admin grant (the foothold cannot trigger
it). Resource/VM rules deploy only after their tables ingest (auto-gated by `deploy/detection.sh`).

## Canaries / honeytokens
The loot along the SP path is inert but production-plausible: the decoy Key Vault holds
credential-shaped secrets (`honeytokenSecrets`, incl. a decoy GitHub token), the decoy storage holds
breadcrumb blobs, and the decoy VM holds planted config/keys. They are **tripwires, not takeovers** —
a read just alerts, and any credential found simply fails auth if used. The decoy SP holds
`Key Vault Secrets User` + `Storage Blob Data Reader` + Owner on the decoy RG, so a taken-over SP
reads the KV honeytokens, reads the decoy blobs over Entra auth, and runs commands on the VM — each a
tripwire. The KV and storage are private-only (reachable over spoke private endpoints) and the storage
account has shared-key auth disabled, so the loot runs from inside the spoke via the VM, the intended
contained internal-attacker path.

## Response (SOAR, enforcing)
Built in `bicep/response.bicep`. Disable-user-and-revoke + isolate-resource playbooks, run by
Sentinel automation rules on `Honeypot:` incidents.
- **Two-key disable guard:** an account is disabled only if it is in the decoy inventory AND not
  allowlisted. Closes over-action (a real admin initiator is never disabled).
- Disables decoy **users and service principals** (dynamic /users vs /servicePrincipals); revokes
  user sessions. Fail-loud comments on every skip — no silent no-ops.
- Isolate-resource scopes to the honeypot RG (locks it). The disable-user MI needs Graph
  `User.ReadWrite.All` + `Application.ReadWrite.All`; the isolate MI needs lock-write on the RG;
  `response.sh` grants both automatically.
- **OPSEC — playbooks live in the same production-plausible management/operations RG
  (`rg-core-ops-*`) as the workspace + Sentinel, with no marker in any name.** A Logic App's
  system-assigned managed identity is a directory service principal any member can read (AzureHound
  surfaces its `displayName` + the resource-id path in `alternativeNames`, including the RG name), so
  nothing that co-locates with a playbook may carry a marker — hence the whole plane is
  production-plausible and the playbook names (`logic-core-ops-*-01/02`) hide their purpose.
  `verify_response.sh` asserts no marker/purpose leaks in the names/RG.
