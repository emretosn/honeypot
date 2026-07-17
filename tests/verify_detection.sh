#!/usr/bin/env bash
# Detection verification, run AFTER deploying bicep/detection.bicep.
# Confirms Sentinel is onboarded and the honeypot analytics rules exist and are enabled.
# Requires: az login; jq; the Sentinel CLI surface via `az rest`.
set -euo pipefail

MGMT_RG="${1:-rg-core-ops-weu}"
WORKSPACE="${2:-log-core-ops-weu}"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$MGMT_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights"

echo "== Detection verification (workspace=$WORKSPACE) =="

# 1. Sentinel onboarded.
az rest --method get --url "$BASE/onboardingStates/default?api-version=2024-09-01" >/dev/null 2>&1 \
  && pass "Microsoft Sentinel is onboarded" \
  || fail "Sentinel onboarding state 'default' not found"

# 2. Always-on rules must be present and enabled (the load-bearing detections that need no
#    optional telemetry gating): the consolidated privileged-auth-abuse rule (Path A/PAA reset).
RULES_JSON=$(az rest --method get --url "$BASE/alertRules?api-version=2024-09-01" 2>/dev/null)
EXPECTED=(
  "privileged authentication action by a non-allowlisted principal"
)
for name in "${EXPECTED[@]}"; do
  MATCH=$(echo "$RULES_JSON" | jq -r --arg n "$name" '.value[] | select(.properties.displayName | test($n; "i")) | {enabled: .properties.enabled, sev: .properties.severity}' 2>/dev/null)
  if [ -n "$MATCH" ]; then
    EN=$(echo "$MATCH" | jq -r '.enabled')
    [ "$EN" = "true" ] && pass "rule present and enabled: $name" || fail "rule present but DISABLED: $name"
  else
    fail "expected rule missing: $name"
  fi
done

# Inventory-scoped rules are present once their identity ids / telemetry exist. Report status
# without failing (they gate on the reachable edge, emergency-access decoy, and ingested tables).
for name in \
  "credential added to decoy service principal/app" \
  "sign-in as decoy service principal" \
  "consent or app-role grant on decoy app/service principal" \
  "sign-in as emergency-access decoy" \
  "decoy Key Vault secret accessed" \
  "decoy storage accessed" \
  "run-command on decoy VM"; do
  if echo "$RULES_JSON" | jq -e --arg n "$name" '.value[] | select(.properties.displayName | test($n; "i"))' >/dev/null 2>&1; then
    pass "rule present: $name"
  else
    echo "NOTE: rule not deployed: $name (expected until its ids/telemetry exist)"
  fi
done

# 3. The emergency-access sign-in rule should reference an allowlist exclusion (defense-in-depth).
echo "$RULES_JSON" | jq -r '.value[] | select(.properties.displayName | test("sign-in as emergency-access"; "i")) | .properties.query' \
  | grep -q '!in' && pass "emergency-access sign-in rule contains an allowlist exclusion" \
  || echo "NOTE: emergency-access sign-in rule not present or has no allowlist exclusion (ok if no agent configured)"

# 4. SCHEMA CONTRACT: for every Scheduled rule, run its KQL
#    against the live workspace and confirm (a) it binds to the real schema and (b) every
#    entity-mapping column the rule declares is actually PRODUCED by the query. A rule whose
#    entity column is absent would create incidents with empty entities, detection "fires" but
#    remediation silently no-ops. We catch that here.
#    SCHEMA_STRICT=true turns "table not found" (no ingestion yet) into a failure too.
SCHEMA_STRICT="${SCHEMA_STRICT:-false}"
WS_GUID=$(az monitor log-analytics workspace show -g "$MGMT_RG" -n "$WORKSPACE" --query customerId -o tsv 2>/dev/null || echo "")
if [ -z "$WS_GUID" ]; then
  echo "NOTE: could not resolve workspace GUID, skipping schema-contract check."
else
  echo "-- schema contract (entity columns must be produced by each rule's KQL) --"
  RULE_COUNT=$(echo "$RULES_JSON" | jq '[.value[] | select(.kind=="Scheduled")] | length')
  for i in $(seq 0 $((RULE_COUNT - 1))); do
    RNAME=$(echo "$RULES_JSON" | jq -r "[.value[] | select(.kind==\"Scheduled\")][$i].properties.displayName")
    RQ=$(echo "$RULES_JSON"    | jq -r "[.value[] | select(.kind==\"Scheduled\")][$i].properties.query")
    # entity-mapping column names declared by this rule
    RCOLS=$(echo "$RULES_JSON" | jq -r "[.value[] | select(.kind==\"Scheduled\")][$i].properties.entityMappings[]?.fieldMappings[]?.columnName" | sort -u)
    # Get the output schema of the query (column list), capturing errors.
    SCHEMA_OUT=$(az monitor log-analytics query --workspace "$WS_GUID" \
      --analytics-query "$RQ | getschema | project ColumnName" -o json 2>/tmp/hp_schema_err.log) || true
    if [ -z "$SCHEMA_OUT" ] || [ "$SCHEMA_OUT" = "[]" ]; then
      ERR=$(tr '\n' ' ' </tmp/hp_schema_err.log)
      if echo "$ERR" | grep -qiE "could not resolve table|unknown function|SemanticError.*table|Failed to resolve table"; then
        if [ "$SCHEMA_STRICT" = "true" ]; then
          fail "[$RNAME] source table not present (no ingestion yet): ${ERR:0:160}"
        else
          echo "  [WARN] [$RNAME] source table not present yet (no ingestion), connect the data source. ${ERR:0:120}"
        fi
        continue
      elif echo "$ERR" | grep -qiE "cannot resolve|SemanticError|column"; then
        fail "[$RNAME] KQL references a column/table the schema does not have: ${ERR:0:200}"
      else
        echo "  [WARN] [$RNAME] could not evaluate schema (${ERR:0:120})"
        continue
      fi
    fi
    OUTCOLS=$(echo "$SCHEMA_OUT" | jq -r '.[].ColumnName' 2>/dev/null | sort -u)
    miss=0
    for c in $RCOLS; do
      echo "$OUTCOLS" | grep -qx "$c" || { fail "[$RNAME] entity-mapping column '$c' is NOT produced by the rule query (would yield an empty entity → silent no-op)"; }
    done
    pass "[$RNAME] all entity columns produced ($(echo "$RCOLS" | tr '\n' ' '))"
  done
  rm -f /tmp/hp_schema_err.log
fi

echo "== Detection OK =="
