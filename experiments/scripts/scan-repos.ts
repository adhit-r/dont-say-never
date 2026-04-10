/**
 * Real-World Repo Scanner
 *
 * Clones open-source repos, runs the pure-TypeScript scanners
 * (stale AI patterns + ghost deps), generates agent rules,
 * and outputs paper-ready metrics.
 *
 * Run: bun run experiments/scan-repos.ts
 *
 * Note: Ghost dep scanner makes network calls to npm/PyPI registries.
 * Stale AI pattern scanner is fully offline.
 */

import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { runStaleAiPatternScanner } from "../src/lib/patchpilot/stale-ai-pattern-scanner";
import { runGhostDepScanner } from "../src/lib/patchpilot/ghost-dep-scanner";
import { generateAgentRules, formatRulesSection } from "../src/lib/patchpilot/rule-generator";

// ─── Target repos ────────────────────────────────────────────────────────────

interface TargetRepo {
  name: string;
  url: string;
  description: string;
  language: string;
}

const REPOS: TargetRepo[] = [
  {
    name: "express",
    url: "https://github.com/expressjs/express.git",
    description: "Classic Node.js web framework",
    language: "JavaScript",
  },
  {
    name: "fastify",
    url: "https://github.com/fastify/fastify.git",
    description: "Fast web framework for Node.js",
    language: "JavaScript/TypeScript",
  },
  {
    name: "next-learn",
    url: "https://github.com/vercel/next-learn.git",
    description: "Next.js learning examples",
    language: "TypeScript",
  },
  {
    name: "hono",
    url: "https://github.com/honojs/hono.git",
    description: "Lightweight web framework",
    language: "TypeScript",
  },
  {
    name: "payload",
    url: "https://github.com/payloadcms/payload.git",
    description: "Headless CMS with auth, DB",
    language: "TypeScript",
  },
  {
    name: "cal.com",
    url: "https://github.com/calcom/cal.com.git",
    description: "Scheduling platform, production app",
    language: "TypeScript",
  },
  {
    name: "twenty",
    url: "https://github.com/twentyhq/twenty.git",
    description: "Open-source CRM",
    language: "TypeScript",
  },
  {
    name: "documenso",
    url: "https://github.com/documenso/documenso.git",
    description: "Open-source DocuSign alternative",
    language: "TypeScript",
  },
];

// ─── Scanner runner ──────────────────────────────────────────────────────────

interface RepoResult {
  repo: string;
  description: string;
  language: string;
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
    repo: repo.name,
    description: repo.description,
    language: repo.language,
    clone_success: false,
    stale_ai_findings: 0,
    ghost_dep_findings: 0,
    total_findings: 0,
    rules_generated: 0,
    compression_ratio: "0%",
    cwes_covered: [],
    categories: {},
    scan_time_ms: 0,
  };

  // Clone (shallow, single branch for speed)
  try {
    if (!fs.existsSync(repoDir)) {
      console.log(`  Cloning ${repo.url}...`);
      execSync(`git clone --depth 1 --single-branch ${repo.url} ${repoDir}`, {
        timeout: 120_000,
        stdio: "pipe",
      });
    } else {
      console.log(`  Using cached clone: ${repoDir}`);
    }
    result.clone_success = true;
  } catch (e: any) {
    result.error = `Clone failed: ${e.message}`;
    return result;
  }

  const start = Date.now();

  // Run stale AI pattern scanner
  try {
    console.log(`  Running stale AI pattern scanner...`);
    const staleFindings = runStaleAiPatternScanner(repoDir);
    result.stale_ai_findings = staleFindings.length;
  } catch (e: any) {
    console.warn(`  Stale AI scanner error: ${e.message}`);
  }

  // Run ghost dep scanner (async, makes network calls)
  try {
    console.log(`  Running ghost dependency scanner...`);
    const ghostFindings = await runGhostDepScanner(repoDir);
    result.ghost_dep_findings = ghostFindings.length;
  } catch (e: any) {
    console.warn(`  Ghost dep scanner error: ${e.message}`);
  }

  result.scan_time_ms = Date.now() - start;
  result.total_findings = result.stale_ai_findings + result.ghost_dep_findings;

  // Generate rules from combined findings
  if (result.total_findings > 0) {
    try {
      // Re-run scanners to get actual finding objects for rule generation
      const staleFindings = runStaleAiPatternScanner(repoDir);
      let ghostFindings: any[] = [];
      try {
        ghostFindings = await runGhostDepScanner(repoDir);
      } catch {}

      const allFindings = [...staleFindings, ...ghostFindings];
      const rules = generateAgentRules(allFindings);
      result.rules_generated = rules.length;
      result.compression_ratio = `${((1 - rules.length / allFindings.length) * 100).toFixed(0)}%`;
      result.cwes_covered = [...new Set(rules.flatMap(r => r.cwes))];

      for (const r of rules) {
        result.categories[r.category] = (result.categories[r.category] ?? 0) + 1;
      }

      // Write instruction files for this repo
      if (rules.length > 0) {
        const outDir = path.join(import.meta.dir, "output", "repos", repo.name);
        fs.mkdirSync(outDir, { recursive: true });

        const section = formatRulesSection(rules, repo.name);
        fs.writeFileSync(path.join(outDir, "CLAUDE.md"), `# ${repo.name}\n\n${section}\n`);
        fs.writeFileSync(path.join(outDir, ".cursorrules"), `${section}\n`);
        fs.writeFileSync(path.join(outDir, "rules.json"), JSON.stringify(rules, null, 2));
      }
    } catch (e: any) {
      console.warn(`  Rule generation error: ${e.message}`);
    }
  }

  return result;
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log("=".repeat(80));
  console.log("REAL-WORLD REPO SCANNING EXPERIMENT");
  console.log("=".repeat(80));
  console.log(`Target repos: ${REPOS.length}`);
  console.log(`Scanners: stale AI patterns (offline), ghost dependencies (registry queries)`);
  console.log();

  const tmpDir = path.join(import.meta.dir, ".repos-cache");
  fs.mkdirSync(tmpDir, { recursive: true });

  const results: RepoResult[] = [];

  for (const repo of REPOS) {
    console.log(`\n[${results.length + 1}/${REPOS.length}] ${repo.name} — ${repo.description}`);
    const result = await scanRepo(repo, tmpDir);
    results.push(result);
    console.log(`  Results: ${result.stale_ai_findings} stale AI + ${result.ghost_dep_findings} ghost deps = ${result.total_findings} findings → ${result.rules_generated} rules (${result.scan_time_ms}ms)`);
  }

  // ─── Summary tables ──────────────────────────────────────────────────────

  console.log("\n" + "=".repeat(80));
  console.log("PAPER-READY RESULTS TABLE");
  console.log("=".repeat(80));

  console.log("\nTable 1: Scan Results by Repository\n");
  console.log("| Repository | Language | Stale AI | Ghost Deps | Total | Rules | Compression | Time |");
  console.log("|------------|----------|----------|------------|-------|-------|-------------|------|");

  let totalStale = 0, totalGhost = 0, totalFindings = 0, totalRules = 0;

  for (const r of results) {
    if (!r.clone_success) {
      console.log(`| ${r.repo} | ${r.language} | CLONE FAILED | | | | | |`);
      continue;
    }
    console.log(`| ${r.repo} | ${r.language} | ${r.stale_ai_findings} | ${r.ghost_dep_findings} | ${r.total_findings} | ${r.rules_generated} | ${r.compression_ratio} | ${r.scan_time_ms}ms |`);
    totalStale += r.stale_ai_findings;
    totalGhost += r.ghost_dep_findings;
    totalFindings += r.total_findings;
    totalRules += r.rules_generated;
  }

  console.log(`| **Total** | | **${totalStale}** | **${totalGhost}** | **${totalFindings}** | **${totalRules}** | **${totalFindings > 0 ? ((1 - totalRules / totalFindings) * 100).toFixed(0) : 0}%** | |`);

  // CWE coverage across all repos
  const allCwes = new Set(results.flatMap(r => r.cwes_covered));
  console.log(`\nTable 2: CWE Coverage\n`);
  console.log(`| CWE | Repos Affected |`);
  console.log(`|-----|----------------|`);

  const cweCounts: Record<string, number> = {};
  for (const r of results) {
    for (const cwe of r.cwes_covered) {
      cweCounts[cwe] = (cweCounts[cwe] ?? 0) + 1;
    }
  }
  for (const [cwe, count] of Object.entries(cweCounts).sort((a, b) => b[1] - a[1])) {
    console.log(`| ${cwe} | ${count}/${results.length} |`);
  }

  // Category breakdown
  console.log(`\nTable 3: Rule Categories\n`);
  const catTotals: Record<string, number> = {};
  for (const r of results) {
    for (const [cat, count] of Object.entries(r.categories)) {
      catTotals[cat] = (catTotals[cat] ?? 0) + count;
    }
  }
  console.log(`| Category | Total Rules |`);
  console.log(`|----------|-------------|`);
  for (const [cat, count] of Object.entries(catTotals)) {
    console.log(`| ${cat} | ${count} |`);
  }

  // Summary stats
  console.log("\n" + "=".repeat(80));
  console.log("SUMMARY STATISTICS");
  console.log("=".repeat(80));
  console.log(`Repos scanned:       ${results.filter(r => r.clone_success).length}/${REPOS.length}`);
  console.log(`Total findings:      ${totalFindings}`);
  console.log(`Total rules:         ${totalRules}`);
  console.log(`Avg findings/repo:   ${(totalFindings / results.filter(r => r.clone_success).length).toFixed(1)}`);
  console.log(`Avg rules/repo:      ${(totalRules / results.filter(r => r.clone_success).length).toFixed(1)}`);
  console.log(`CWE classes covered: ${allCwes.size}`);
  console.log(`Overall compression: ${totalFindings > 0 ? ((1 - totalRules / totalFindings) * 100).toFixed(0) : 0}%`);

  // Save full results as JSON
  const outPath = path.join(import.meta.dir, "output", "repo-scan-results.json");
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log(`\nFull results saved to: ${outPath}`);
}

main().catch(console.error);
