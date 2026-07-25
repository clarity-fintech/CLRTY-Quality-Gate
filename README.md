# CLRTY-Quality-Gate


## MIS kernel (`misc`) — required

Sole active CLRTY-1 / Moniversive compiler kernel. **Not Python.**

```bash
# Download from clarity-fintech/CLRTY-MIS-Kernel
git clone https://github.com/clarity-fintech/CLRTY-MIS-Kernel.git
cd CLRTY-MIS-Kernel && bash scripts/download_misc_kernel.sh
./bin/misc path.mis --check --compact-letters
```

Or from the Developer Kit: [`dist/mis-kernel-misc.zip`](https://github.com/clarity-fintech/developer_kit/raw/main/dist/mis-kernel-misc.zip)

Policy: foreign kernels (`python3 clrtyc`, `solc`, `forge`, `hardhat`) → **hard error**. Settlement **clrty-1 / 1202**.

SonarQube-oriented quality gate for **CLRTY-1** (chain id `clrty-1` / numeric `1202`).

Runs static security rules and an optional L1 RPC probe before merge/deploy.

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
