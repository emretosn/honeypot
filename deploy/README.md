# Deploy scripts, run order

Each stage is one script; all source `lib.sh` and read `config.env` (copy from
`config.env.example`). Run from a directory admin (`az login`). Decoy IDs flow through
`inventory/decoy-inventory.json` automatically between stages.

| # | Script | Creates |
|---|---|---|---|
| 1 | `foundation.sh` | mgmt/ops RG (production-plausible, no marker) + Log Analytics |
| 2 | `identity.sh`   | reachable app/SP (foothold-owned) + emergency-access decoy + AU |
| 3 | `network.sh`    | hub (sim) + honeypot spoke (private VM + KV + storage) |
| 4 | `edge.sh`       | decoy SP RBAC: Owner on decoy RG + KV Secrets User |
| 5 | `detection.sh`  | Entra log streaming + Sentinel + analytics rules |
| 6 | `response.sh`   | disable-user + isolate-resource playbooks (enforcing), in the mgmt/ops RG |

```bash
cp config.env.example config.env       # set SUBSCRIPTION_ID + VERIFIED_DOMAIN
./foundation.sh && ./identity.sh && ./network.sh && ./edge.sh && ./detection.sh && ./response.sh
```

Optional: `tests/attacker_test_user.sh create` (foothold). The decoy KV/storage/VM rules auto-enable
once their telemetry has ingested, just re-run `./detection.sh` later if they were skipped on the
first pass. The playbooks deploy ENFORCING; `response.sh` protects every current Global Administrator
(and break-glass) from being disabled, and only ever acts on the decoy identities/resources.

## Teardown
`./teardown.sh` removes everything (identities, RGs, Sentinel, playbooks, KV/storage) and resets
local state for a clean-clone redeploy. Then `tests/attacker_test_user.sh delete`.
