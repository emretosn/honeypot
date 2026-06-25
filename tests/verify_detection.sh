#!/usr/bin/env bash
# Detection verification — run AFTER deploying bicep/detection.bicep.
# Confirms Sentinel is onboarded and the honeypot analytics rules exist and are enabled.
# Requires: az login; jq; the Sentinel CLI surface via `az rest`.
set -euo pipefail

MGMT_RG="${1:-rg-hp-dev-weu-mgmt}"
WORKSPACE="${2:-log-hp-dev-weu}"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

SUB=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUB/resourceGroups/$MGMT_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE/providers/Microsoft.SecurityInsights"

echo "== Detection verification (workspace=$WORKSPACE) =="

# 1. Sentinel onboarded.
az rest --method get --url "$BASE/onboardingStates/default?api-version=2024-09-01" >/dev/null 2>&1 \
  && pass "Microsoft Sentinel is onboarded" \
  || fail "Sentinel onboarding state 'default' not found"

# 2. Identity rules must always be present and enabled (the load-bearing detections).
RULES_JSON=$(az rest --method get --url "$BASE/alertRules?api-version=2024-09-01" 2>/dev/null)
EXPECTED=(
  "password reset on lure identity"
  "role assignment or PIM activation on lure identity"
  "sign-in as lure identity from non-allowlisted source"
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

# Resource rules are optional (only present when enableResourceRules=true, after the network
# module is deployed). Report their status without failing.
for name in "decoy Key Vault secret accessed" "decoy storage accessed"; do
  if echo "$RULES_JSON" | jq -e --arg n "$name" '.value[] | select(.properties.displayName | test($n; "i"))' >/dev/null 2>&1; then
    pass "resource rule present: $name"
  else
    echo "NOTE: resource rule not deployed: $name (expected until the network module + enableResourceRules)"
  fi
done

# 3. Sign-in rule should reference an allowlist exclusion construct (defense-in-depth check).
echo "$RULES_JSON" | jq -r '.value[] | select(.properties.displayName | test("sign-in as lure"; "i")) | .properties.query' \
  | grep -q '!in' && pass "sign-in rule contains an allowlist exclusion" \
  || echo "NOTE: sign-in rule has no allowlist exclusion (ok if no agent configured)"

# 4. SCHEMA CONTRACT (the Phase 02 fail-loud check): for every Scheduled rule, run its KQL
#    against the live workspace and confirm (a) it binds to the real schema and (b) every
#    entity-mapping column the rule declares is actually PRODUCED by the query. A rule whose
#    entity column is absent would create incidents with empty entities — detection "fires" but
#    remediation silently no-ops. We catch that here.
#    SCHEMA_STRICT=true turns "table not found" (no ingestion yet) into a failure too.
SCHEMA_STRICT="${SCHEMA_STRICT:-false}"
WS_GUID=$(az monitor log-analytics workspace show -g "$MGMT_RG" -n "$WORKSPACE" --query customerId -o tsv 2>/dev/null || echo "")
if [ -z "$WS_GUID" ]; then
  echo "NOTE: could not resolve workspace GUID — skipping schema-contract check."
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
          echo "  [WARN] [$RNAME] source table not present yet (no ingestion) — connect the data source. ${ERR:0:120}"
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
