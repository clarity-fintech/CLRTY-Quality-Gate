import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import {
  CLRTY1_CHAIN_ID,
  CLRTY1_NUMERIC_CHAIN_ID,
  loadClrty1Config,
  type Clrty1Config,
} from "./clrty1.js";
import { validateEbpfPolicy } from "./security/validate_ebpf.js";

export type RuleFinding = {
  rule: string;
  severity: "error" | "warn";
  message: string;
  file?: string;
};

export type RuleResult = {
  ok: boolean;
  findings: RuleFinding[];
};

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "coverage",
  ".turbo",
  "target",
]);

const SCAN_EXTS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".env",
  ".yml",
  ".yaml",
  ".toml",
  ".rs",
  ".sol",
  ".md",
  ".sh",
]);

/** Patterns that look like hardcoded private keys / mnemonics. */
const PRIVATE_KEY_PATTERNS: { name: string; re: RegExp }[] = [
  {
    name: "hex_private_key",
    re: /(?:private[_-]?key|secret[_-]?key|PRIVATE_KEY)\s*[:=]\s*["']?0x[a-fA-F0-9]{64}["']?/,
  },
  {
    name: "raw_hex_64",
    re: /(?:^|[^a-fA-F0-9])0x[a-fA-F0-9]{64}(?:[^a-fA-F0-9]|$)/,
  },
  {
    name: "bip39_mnemonic_assign",
    re: /(?:mnemonic|seed[_-]?phrase|MNEMONIC)\s*[:=]\s*["'][a-z]+(?:\s+[a-z]+){11,}["']/,
  },
];

function walkFiles(root: string, dir = root, out: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walkFiles(root, full, out);
    } else if (st.isFile()) {
      const ext = name.includes(".") ? `.${name.split(".").pop()}` : "";
      if (SCAN_EXTS.has(ext) || name.startsWith(".env")) {
        out.push(full);
      }
    }
  }
  return out;
}

/** Scan tree for hardcoded private-key / mnemonic patterns. */
export function checkNoHardcodedPrivateKeys(
  rootDir: string,
  ignoreRel: string[] = ["src/rules.ts", "tests/"],
): RuleResult {
  const findings: RuleFinding[] = [];
  const files = walkFiles(rootDir);
  for (const file of files) {
    const rel = relative(rootDir, file).replace(/\\/g, "/");
    if (ignoreRel.some((p) => rel === p || rel.startsWith(p))) continue;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const { name, re } of PRIVATE_KEY_PATTERNS) {
      if (re.test(text)) {
        findings.push({
          rule: "no_hardcoded_private_keys",
          severity: "error",
          message: `Possible hardcoded secret (${name}) in ${rel}`,
          file: rel,
        });
      }
    }
  }
  return { ok: findings.length === 0, findings };
}

/**
 * In production, CLRTY_L1_RPC must use TLS (https).
 * Non-prod may use http for local nodes.
 */
export function checkRpcTlsInProd(
  env: NodeJS.ProcessEnv = process.env,
  cfg: Clrty1Config = loadClrty1Config(env),
): RuleResult {
  const findings: RuleFinding[] = [];
  const nodeEnv = (env.NODE_ENV || "").toLowerCase();
  const isProd =
    nodeEnv === "production" ||
    env.CLRTY_ENV === "production" ||
    env.CLRTY_ENV === "prod";

  if (isProd) {
    if (!cfg.rpcUrl.startsWith("https://")) {
      findings.push({
        rule: "rpc_tls_required",
        severity: "error",
        message: `CLRTY_L1_RPC must use https in production (got ${cfg.rpcUrl})`,
      });
    }
  } else if (cfg.rpcUrl.startsWith("http://") && !cfg.rpcUrl.includes("localhost") && !cfg.rpcUrl.includes("127.0.0.1")) {
    findings.push({
      rule: "rpc_tls_recommended",
      severity: "warn",
      message: `CLRTY_L1_RPC is non-TLS outside localhost: ${cfg.rpcUrl}`,
    });
  }

  return { ok: findings.every((f) => f.severity !== "error"), findings };
}

/** Pin chain id to clrty-1 / 1202. */
export function checkChainIdPin(
  env: NodeJS.ProcessEnv = process.env,
  cfg: Clrty1Config = loadClrty1Config(env),
): RuleResult {
  const findings: RuleFinding[] = [];
  if (cfg.chainId !== CLRTY1_CHAIN_ID) {
    findings.push({
      rule: "chain_id_pin",
      severity: "error",
      message: `chainId must be ${CLRTY1_CHAIN_ID}, got ${cfg.chainId}`,
    });
  }
  if (cfg.numericChainId !== CLRTY1_NUMERIC_CHAIN_ID) {
    findings.push({
      rule: "chain_id_pin",
      severity: "error",
      message: `numericChainId must be ${CLRTY1_NUMERIC_CHAIN_ID}, got ${cfg.numericChainId}`,
    });
  }
  return { ok: findings.length === 0, findings };
}

/** Require security/ebpf/filters.yaml with deny_by_default. */
export function checkEbpfPolicy(rootDir: string): RuleResult {
  const findings: RuleFinding[] = [];
  const yamlPath = join(rootDir, "security/ebpf/filters.yaml");
  if (!existsSync(yamlPath)) {
    findings.push({
      rule: "ebpf_policy",
      severity: "error",
      message: "security/ebpf/filters.yaml is required",
      file: "security/ebpf/filters.yaml",
    });
    return { ok: false, findings };
  }
  const result = validateEbpfPolicy(rootDir);
  if (!result.ok) {
    findings.push({
      rule: "ebpf_policy",
      severity: "error",
      message: result.error || "eBPF policy invalid (deny_by_default required)",
      file: "security/ebpf/filters.yaml",
    });
  }
  return { ok: findings.length === 0, findings };
}

/** Run all static / config rules. */
export function runRules(
  rootDir: string,
  env: NodeJS.ProcessEnv = process.env,
): RuleResult {
  const parts = [
    checkNoHardcodedPrivateKeys(rootDir),
    checkRpcTlsInProd(env),
    checkChainIdPin(env),
    checkEbpfPolicy(rootDir),
  ];
  const findings = parts.flatMap((p) => p.findings);
  return {
    ok: parts.every((p) => p.ok),
    findings,
  };
}
