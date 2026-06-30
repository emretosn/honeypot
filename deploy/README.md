# Deploy scripts — run order

Each stage is one script; all source `lib.sh` and read `config.env` (copy from
`config.env.example`). Run from a directory admin (`az login`). Decoy IDs flow through
`inventory/decoy-inventory.json` automatically between stages.

| # | Script | Creates |
|---|---|---|---|
| 1 | `foundation.sh` | mgmt RG + Log Analytics |
| 2 | `identity.sh`   | decoy AU, lure, personas, role, bait, reachable app/SP |
| 3 | `network.sh`    | hub (sim) + honeypot spoke (KV + storage; VM/AppGw optional) |
| 4 | `edge.sh`       | decoy SP RBAC: Owner on decoy RG + KV Secrets User |
| 5 | `detection.sh`  | Entra log streaming + Sentinel + analytics rules |
| 6 | `response.sh`   | disable-user + isolate-resource playbooks (dry-run) |

```bash
cp config.env.example config.env       # set SUBSCRIPTION_ID + VERIFIED_DOMAIN
./foundation.sh && ./identity.sh && ./network.sh && ./edge.sh && ./detection.sh && ./response.sh
```

Optional: `tests/attacker_test_user.sh create` (foothold). Enable coverage/resource rules once
their tables ingest: `ENABLE_COVERAGE_RULES=true ENABLE_RESOURCE_RULES=true ./detection.sh`.

## Teardown
`./teardown.sh` removes everything (identities, RGs, Sentinel, playbooks, KV/storage) and resets
local state for a clean-clone redeploy. Then `tests/attacker_test_user.sh delete`.
