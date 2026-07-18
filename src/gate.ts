#!/usr/bin/env node
import { resolve } from "node:path";
import {
  loadClrty1Config,
  probeClrty1,
  rpcSmokeEnabled,
} from "./clrty1.js";
import { runRules, type RuleFinding } from "./rules.js";

export type GateReport = {
  ok: boolean;
  rulesOk: boolean;
  probeOk: boolean | null;
  findings: RuleFinding[];
  probe?: Awaited<ReturnType<typeof probeClrty1>>;
};

export async function runGate(opts: {
  rootDir?: string;
  smoke?: boolean;
  env?: NodeJS.ProcessEnv;
}): Promise<GateReport> {
  const env = opts.env ?? process.env;
  const rootDir = resolve(opts.rootDir ?? process.cwd());
  const wantSmoke = opts.smoke ?? rpcSmokeEnabled(env);

  const rules = runRules(rootDir, env);
  let probeOk: boolean | null = null;
  let probe: GateReport["probe"];

  if (wantSmoke) {
    const cfg = loadClrty1Config(env);
    probe = await probeClrty1(cfg);
    probeOk = probe.ok;
    if (!probe.ok) {
      rules.findings.push({
        rule: "clrty1_probe",
        severity: "error",
        message: probe.error || "CLRTY-1 probe failed",
      });
    }
  }

  const ok = rules.ok && (probeOk === null || probeOk === true);
  return {
    ok,
    rulesOk: rules.ok,
    probeOk,
    findings: rules.findings,
    probe,
  };
}

function printFindings(findings: RuleFinding[]) {
  for (const f of findings) {
    const loc = f.file ? ` [${f.file}]` : "";
    console.error(`${f.severity.toUpperCase()} ${f.rule}${loc}: ${f.message}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const smokeFlag = args.includes("--smoke");
  const noSmoke = args.includes("--no-smoke");
  const rootIdx = args.indexOf("--root");
  const rootDir =
    rootIdx >= 0 && args[rootIdx + 1] ? args[rootIdx + 1] : process.cwd();

  const env = { ...process.env };
  if (noSmoke) env.CLRTY_RPC_SMOKE = "0";
  if (smokeFlag) env.CLRTY_RPC_SMOKE = "1";

  const report = await runGate({
    rootDir,
    smoke: smokeFlag ? true : noSmoke ? false : undefined,
    env,
  });

  console.log(
    JSON.stringify(
      {
        ok: report.ok,
        rulesOk: report.rulesOk,
        probeOk: report.probeOk,
        findings: report.findings,
        probe: report.probe
          ? {
              ok: report.probe.ok,
              rpcUrl: report.probe.rpcUrl,
              chainId: report.probe.chainId,
              tipHeight: report.probe.tipHeight,
              source: report.probe.source,
              fallbacks_tried: report.probe.fallbacks_tried,
              error: report.probe.error,
            }
          : null,
      },
      null,
      2,
    ),
  );

  if (!report.ok) {
    printFindings(report.findings);
    process.exit(1);
  }
}

const isDirect =
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith("gate.ts") ||
  process.argv[1]?.endsWith("gate.js");

if (isDirect) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
