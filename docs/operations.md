# Operations — deploy, verify, attack-test, enforce

## Prerequisites
- Azure subscription + Entra tenant. Entra **P1** (administrative units).
- Tools: `az`, `az bicep`, `terraform >= 1.5`, `jq`. A verified domain for decoy UPNs.
- Run as a directory-admin (testing: `az login`; prod: OIDC deploy SP).
- Inputs for a REAL deploy: existing hub VNet ID, Log Analytics workspace ID, foothold object
  ID, break-glass object ID(s). The deploy scripts stand up a self-contained hub-spoke (simulated
  production + honeypot) with no external inputs; to drop in alongside a real hub, deploy
  `bicep/honeypot.bicep` directly with the existing `hubVnetId` + `workspaceId`.

## Configure
```bash
cp deploy/config.env.example deploy/config.env   # set SUBSCRIPTION_ID + VERIFIED_DOMAIN
cp terraform/identity/terraform.tfvars.example terraform/identity/terraform.tfvars
# set verified_domain, foothold_principal_object_id, break_glass_object_ids
```

## Deploy (in order)
```bash
deploy/foundation.sh    # mgmt/ops RG (rg-core-ops-*, no marker) + Log Analytics
deploy/identity.sh      # reachable app/SP (foothold-owned) + emergency-access decoy; syncs inventory
deploy/network.sh       # hub (sim) + honeypot spoke (private VM + KV + storage, seeds blobs); auto-syncs inventory
deploy/edge.sh          # grants the decoy SP its decoy-RG RBAC (Owner + KV Secrets User)
deploy/detection.sh     # Entra log streaming + Sentinel + analytics rules
deploy/response.sh      # disable-user + isolate-resource playbooks (enforcing), in the mgmt/ops RG
```
The private decoy VM is always deployed; nothing is internet-facing. Resource (KV/storage) and
VM-run-command rules auto-enable once their tables ingest, re-run `detection.sh` later if they were
skipped. The consent (insider) rule enables automatically with the reachable-edge rules once the
decoy app/SP are in the inventory.

## Verify
```bash
./tests/verify_all.sh static                          # all IaC builds + inventory contract
./tests/verify_all.sh tenant dev weu rg-core-prod-weu # all live checks
```
Individually: `verify_foundation`, `verify_identity` (containment: SP no consented Graph, RBAC only
on the decoy RG/KV; emergency-access powerless + alone in its AU), `verify_network`
(egress-deny=prod, no spoke-to-spoke), `verify_detection` (schema contract: entities never empty),
`verify_response` (two-key guard + SP disable).

## Attack scenarios (each → alert → incident → playbook)
As `attacker-test` (create with `tests/attacker_test_user.sh create`):
1. Reset the `emergency-access` decoy → privileged-auth-abuse; sign in as it → emergency-access
   sign-in. 2. Add a secret to the owned decoy app → credential-add; sign in as the SP → SP-sign-in.
3. As the SP (Owner of the decoy RG + KV Secrets User): read a KV honeytoken → KV-read; read decoy
   storage → storage; run a command on the decoy VM → VM run-command.

## Enforcement (automatic)
`response.sh` deploys the playbooks **enforcing**. It enumerates every current Global Administrator
and merges them with break-glass into the never-disable allowlist, and grants the playbook managed
identities their permissions (disable-user MI: Graph `User.ReadWrite.All` + `Application.ReadWrite.All`;
isolate MI: lock-write on the honeypot RG). One manual step remains: authorize the `azuresentinel`
API connection in the portal (Sentinel > Playbooks > each Logic App > API connections > Authorize).

## Latency
Sign-in/audit logs take 5–30 min to ingest; rules run ~5-min cycles. Don't expect instant incidents.

## Teardown (clean-clone reset)
`deploy/teardown.sh` removes everything: terraform-destroys the identities + SP RBAC, deletes
the Entra diagnostic setting, deletes all RGs (mgmt/hub/spoke/prod/ops → Sentinel, rules, playbooks,
KV, storage, network), purges soft-deleted KVs, and resets local tfstate + inventory to template.
Prompts for confirmation (`--yes` to skip). Then `tests/attacker_test_user.sh delete` and redeploy
from `deploy/foundation.sh` (see `deploy/README.md` for order).

