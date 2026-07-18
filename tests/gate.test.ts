import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  checkChainIdPin,
  checkEbpfPolicy,
  checkNoHardcodedPrivateKeys,
  checkRpcTlsInProd,
  runRules,
} from "../src/rules.js";
import { runGate } from "../src/gate.js";

beforeAll(() => {
  process.env.CLRTY_RPC_SMOKE = "0";
});

describe("security rules", () => {
  it("pins chain id to clrty-1 / 1202", () => {
    const ok = checkChainIdPin({
      CLRTY_L1_CHAIN_ID: "clrty-1",
      CLRTY_L1_NUMERIC_CHAIN_ID: "1202",
    });
    expect(ok.ok).toBe(true);

    const bad = checkChainIdPin({
      CLRTY_L1_CHAIN_ID: "wrong",
      CLRTY_L1_NUMERIC_CHAIN_ID: "1",
    });
    expect(bad.ok).toBe(false);
    expect(bad.findings.some((f) => f.rule === "chain_id_pin")).toBe(true);
  });

  it("requires https RPC in production", () => {
    const bad = checkRpcTlsInProd({
      NODE_ENV: "production",
      CLRTY_L1_RPC: "http://rpc.example.com",
    });
    expect(bad.ok).toBe(false);

    const good = checkRpcTlsInProd({
      NODE_ENV: "production",
      CLRTY_L1_RPC: "https://rpc.clarity-fintech.com",
    });
    expect(good.ok).toBe(true);
  });

  it("flags hardcoded private key patterns", () => {
    const dir = mkdtempSync(join(tmpdir(), "clrty-gate-"));
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(
      join(dir, "src", "leak.ts"),
      `export const PRIVATE_KEY = "0x${"ab".repeat(32)}";\n`,
    );
    const result = checkNoHardcodedPrivateKeys(dir);
    expect(result.ok).toBe(false);
    expect(result.findings[0]?.rule).toBe("no_hardcoded_private_keys");
  });

  it("requires eBPF filters.yaml with deny_by_default", () => {
    const dir = mkdtempSync(join(tmpdir(), "clrty-gate-no-ebpf-"));
    expect(checkEbpfPolicy(dir).ok).toBe(false);

    mkdirSync(join(dir, "security/ebpf"), { recursive: true });
    writeFileSync(
      join(dir, "security/ebpf/filters.yaml"),
      'version: "0.1.0"\nmode: deny_by_default\n',
    );
    expect(checkEbpfPolicy(dir).ok).toBe(true);
  });

  it("runRules passes clean fixture", () => {
    const dir = mkdtempSync(join(tmpdir(), "clrty-gate-clean-"));
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "ok.ts"), "export const x = 1;\n");
    mkdirSync(join(dir, "security/ebpf"), { recursive: true });
    const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
    copyFileSync(
      join(repoRoot, "security/ebpf/filters.yaml"),
      join(dir, "security/ebpf/filters.yaml"),
    );
    const result = runRules(dir, {
      NODE_ENV: "development",
      CLRTY_L1_RPC: "https://rpc.clarity-fintech.com",
      CLRTY_L1_CHAIN_ID: "clrty-1",
      CLRTY_L1_NUMERIC_CHAIN_ID: "1202",
      CLRTY_RPC_SMOKE: "0",
    });
    expect(result.ok).toBe(true);
  });
});

describe("runGate", () => {
  it("exits rules-only when CLRTY_RPC_SMOKE=0", async () => {
    const report = await runGate({
      rootDir: process.cwd(),
      smoke: false,
      env: {
        ...process.env,
        CLRTY_RPC_SMOKE: "0",
        NODE_ENV: "test",
        CLRTY_L1_RPC: "https://rpc.clarity-fintech.com",
        CLRTY_L1_CHAIN_ID: "clrty-1",
        CLRTY_L1_NUMERIC_CHAIN_ID: "1202",
      },
    });
    expect(report.probeOk).toBeNull();
    expect(report.rulesOk).toBe(true);
    expect(report.ok).toBe(true);
  });
});
