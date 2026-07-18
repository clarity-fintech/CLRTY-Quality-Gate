import { describe, it, expect, beforeAll } from "vitest";
import {
  CLRTY1_CHAIN_ID,
  CLRTY1_NUMERIC_CHAIN_ID,
  loadClrty1Config,
  probeClrty1,
  rpcSmokeEnabled,
} from "../src/clrty1.js";

beforeAll(() => {
  process.env.CLRTY_RPC_SMOKE = "0";
});

describe("clrty1 config", () => {
  it("loads defaults for CLRTY-1", () => {
    const cfg = loadClrty1Config({});
    expect(cfg.chainId).toBe(CLRTY1_CHAIN_ID);
    expect(cfg.numericChainId).toBe(CLRTY1_NUMERIC_CHAIN_ID);
    expect(cfg.rpcUrl).toMatch(/^https:\/\//);
  });

  it("rpcSmokeEnabled respects CLRTY_RPC_SMOKE=0", () => {
    expect(rpcSmokeEnabled({ CLRTY_RPC_SMOKE: "0" })).toBe(false);
    expect(rpcSmokeEnabled({ CLRTY_RPC_SMOKE: "1" })).toBe(true);
  });
});

describe("optional CLRTY-1 smoke", () => {
  it.skipIf(process.env.CLRTY_RPC_SMOKE === "0")(
    "probeClrty1 reaches configured RPC",
    async () => {
      const result = await probeClrty1(loadClrty1Config(process.env));
      expect(result.ok).toBe(true);
    },
    20_000,
  );
});
