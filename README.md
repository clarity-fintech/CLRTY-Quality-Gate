# CLRTY-Quality-Gate

SonarQube-oriented quality gate for **CLRTY-1** (chain id `clrty-1` / numeric `1202`).

Runs static security rules and an optional L1 RPC probe before merge/deploy.

## What it checks

- No hardcoded private-key / mnemonic patterns in scanned sources
- `CLRTY_L1_RPC` must use **HTTPS** in production
- Chain id pinned to `clrty-1` / `1202`
- Optional live probe via `probeClrty1` (disabled when `CLRTY_RPC_SMOKE=0`)

## Quick start

```bash
npm ci
npm test          # CLRTY_RPC_SMOKE=0 recommended
npm run build
npm run gate      # rules + probe (respects CLRTY_RPC_SMOKE)
npm run smoke     # force network probe
```

## SonarQube

`sonar-project.properties` sets `sonar.projectKey=clarity-fintech_CLRTY-Quality-Gate` and `sonar.sources=src`.

## Environment

Copy `.env.example`. Key vars: `CLRTY_L1_RPC`, `CLRTY_L1_CHAIN_ID`, `CLRTY_L1_NUMERIC_CHAIN_ID`, `CLRTY_RPC_SMOKE`.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
