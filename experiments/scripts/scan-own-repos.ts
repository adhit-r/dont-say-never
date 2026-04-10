/**
 * Scan adhit-r GitHub Repos
 *
 * Scans Adhithya's own open-source repos to generate instruction files
 * and demonstrate the pipeline on real projects.
 *
 * Run: bun run research/experiments/scripts/scan-own-repos.ts
 */

import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { runStaleAiPatternScanner } from "../../../backend/src/lib/patchpilot/stale-ai-pattern-scanner";
import { runGhostDepScanner } from "../../../backend/src/lib/patchpilot/ghost-dep-scanner";
import { generateAgentRules, formatRulesSection } from "../../../backend/src/lib/patchpilot/rule-generator";

interface TargetRepo {
  name: string;
  url: string;
  description: string;
}

const REPOS: TargetRepo[] = [
  { name: "fairmind", url: "https://github.com/adhit-r/fairmind.git", description: "AI Governance & Bias Detection Platform" },
  { name: "aran-mcp", url: "https://github.com/adhit-r/aran-mcp.git", description: "MCP Security & Governance Framework" },
  { name: "aran", url: "https://github.com/adhit-r/aran.git", description: "API Security & Governance Platform" },
  { name: "Redact-ai", url: "https://github.com/adhit-r/Redact-ai.git", description: "Privacy & Compliance Automation" },
  { name: "RagaSense", url: "https://github.com/adhit-r/RagaSense.git", description: "AI Raga Detection" },
  { name: "audit-lens", url: "https://github.com/adhit-r/audit-lens.git", description: "Agentic Compliance Engine" },
  { name: "ChessForgeAI", url: "https://github.com/adhit-r/ChessForgeAI.git", description: "Chess Analysis App" },
];

interface RepoResult {
  repo: string;
  description: string;
  clone_success: boolean;
  stale_ai_findings: number;
  ghost_dep_findings: number;
  total_findings: number;
  rules_generated: number;
  compression_ratio: string;
  cwes_covered: string[];
  categories: Record<string, number>;
  scan_time_ms: number;
  error?: string;
}

async function scanRepo(repo: TargetRepo, baseDir: string): Promise<RepoResult> {
  const repoDir = path.join(baseDir, repo.name);
  const result: RepoResult = {
    repo: repo.name, description: repo.description, clone_success: false,
    stale_ai_findings: 0, ghost_dep_findings: 0, total_findings: 0,
    rules_generated: 0, compression_ratio: "0%", cwes_covered: [], categories: {}, scan_time_ms: 0,
  };

  try {
    if (!fs.existsSync(repoDir)) {
      console.log(`  Cloning ${repo.url}...`);
      execSync(`git clone --depth 1 --single-branch ${repo.url} ${repoDir}`, { timeout: 120_000, stdio: "pipe" });
    } else {
      console.log(`  Using cached: ${repoDir}`);
    }
    result.clone_success = true;
  } catch (e: any) {
    result.error = `Clone failed: ${e.message}`;
    return result;
  }

  const start = Date.now();

  try {
    console.log(`  Scanning stale AI patterns...`);
    const staleFindings = runStaleAiPatternScanner(repoDir);
    result.stale_ai_findings = staleFindings.length;

    console.log(`  Scanning ghost dependencies...`);
    const ghostFindings = await runGhostDepScanner(repoDir);
    result.ghost_dep_findings = ghostFindings.length;

    result.scan_time_ms = Date.now() - start;
    result.total_findings = result.stale_ai_findings + result.ghost_dep_findings;

    if (result.total_findings > 0) {
      const allFindings = [...staleFindings, ...ghostFindings];
      const rules = generateAgentRules(allFindings);
      result.rules_generated = rules.length;
      result.compression_ratio = `${((1 - rules.length / allFindings.length) * 100).toFixed(0)}%`;
      result.cwes_covered = [...new Set(rules.flatMap(r => r.cwes))];
      for (const r of rules) result.categories[r.category] = (result.categories[r.category] ?? 0) + 1;

      // Write instruction files
      const outDir = path.join(import.meta.dir, "..", "data", "own-repos", repo.name);
      fs.mkdirSync(outDir, { recursive: true });
      const section = formatRulesSection(rules, `adhit-r/${repo.name}`);
      fs.writeFileSync(path.join(outDir, "CLAUDE.md"), `# ${repo.name}\n\n${section}\n`);
      fs.writeFileSync(path.join(outDir, ".cursorrules"), `${section}\n`);
      fs.writeFileSync(path.join(outDir, "rules.json"), JSON.stringify(rules, null, 2));
    }
  } catch (e: any) {
    console.warn(`  Error: ${e.message}`);
  }

  return result;
}

async function main() {
  console.log("=".repeat(80));
  console.log("SCAN: adhit-r GitHub Repos");
  console.log("=".repeat(80));

  const tmpDir = path.join(import.meta.dir, "..", ".repos-cache");
  fs.mkdirSync(tmpDir, { recursive: true });

  const results: RepoResult[] = [];

  for (const repo of REPOS) {
    console.log(`\n[${results.length + 1}/${REPOS.length}] ${repo.name} — ${repo.description}`);
    const r = await scanRepo(repo, tmpDir);
    results.push(r);
    console.log(`  Result: ${r.stale_ai_findings} stale + ${r.ghost_dep_findings} ghost = ${r.total_findings} → ${r.rules_generated} rules (${r.scan_time_ms}ms)`);
  }

  // Summary
  console.log("\n" + "=".repeat(80));
  console.log("RESULTS: adhit-r Repos");
  console.log("=".repeat(80));
  console.log("\n| Repo | Stale AI | Ghost Deps | Total | Rules | Compression |");
  console.log("|------|----------|------------|-------|-------|-------------|");

  let ts = 0, tg = 0, tf = 0, tr = 0;
  for (const r of results) {
    if (!r.clone_success) { console.log(`| ${r.repo} | FAILED | | | | |`); continue; }
    console.log(`| ${r.repo} | ${r.stale_ai_findings} | ${r.ghost_dep_findings} | ${r.total_findings} | ${r.rules_generated} | ${r.compression_ratio} |`);
    ts += r.stale_ai_findings; tg += r.ghost_dep_findings; tf += r.total_findings; tr += r.rules_generated;
  }
  console.log(`| **Total** | **${ts}** | **${tg}** | **${tf}** | **${tr}** | **${tf > 0 ? ((1 - tr / tf) * 100).toFixed(0) : 0}%** |`);

  const outPath = path.join(import.meta.dir, "..", "data", "own-repos-results.json");
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log(`\nSaved to: ${outPath}`);
}

main().catch(console.error);
