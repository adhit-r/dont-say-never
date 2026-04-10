/**
 * MULTI-LANGUAGE SCANNER EVALUATION — PatchPilot Pipeline
 *
 * Clones 3 Python and 3 Go repositories and runs the full scanner pipeline
 * (stale AI patterns + Semgrep SAST + rule generation) to validate that the
 * system generalizes beyond JavaScript/TypeScript.
 *
 * For each repo we report:
 *   - Number of findings (stale AI + Semgrep)
 *   - CWEs detected
 *   - Rules generated
 *   - Rule category breakdown
 *
 * Run: bun run research/experiments/scripts/multi-language-scan.ts
 */

import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import { runStaleAiPatternScanner } from "../../../backend/src/lib/patchpilot/stale-ai-pattern-scanner";
import { isSemgrepAvailable, runSemgrep } from "../../../backend/src/lib/patchpilot/semgrep-scanner";
import { analyzeContext } from "../../../backend/src/lib/patchpilot/context-analyzer";
import { generateAgentRules, formatRulesSection } from "../../../backend/src/lib/patchpilot/rule-generator";
import type { AgentRule } from "../../../backend/src/lib/patchpilot/rule-generator";

// ─── Configuration ────────────────────────────────────────────────────────────

const REPOS_CACHE = path.resolve(__dirname, "../../../backend/experiments/.repos-cache");
const OUT_DIR = path.resolve(__dirname, "../data");

interface TargetRepo {
  language: "python" | "go";
  name: string;
  slug: string; // github owner/repo
  clone_depth: number;
}

// Chosen for popularity, diverse codebase sizes, and active maintenance.
const TARGETS: TargetRepo[] = [
  // Python repos
  { language: "python", name: "flask",    slug: "pallets/flask",      clone_depth: 1 },
  { language: "python", name: "fastapi",  slug: "fastapi/fastapi",    clone_depth: 1 },
  { language: "python", name: "requests", slug: "psf/requests",       clone_depth: 1 },
  // Go repos
  { language: "go",     name: "gin",      slug: "gin-gonic/gin",      clone_depth: 1 },
  { language: "go",     name: "echo",     slug: "labstack/echo",      clone_depth: 1 },
  { language: "go",     name: "cobra",    slug: "spf13/cobra",        clone_depth: 1 },
];

// ─── Types ────────────────────────────────────────────────────────────────────

interface RepoScanResult {
  language: "python" | "go";
  repo: string;
  slug: string;
  file_counts: {
    py: number;
    go: number;
    total: number;
  };
  stale_ai: {
    total_findings: number;
    by_rule: Record<string, number>;
    by_cwe: Record<string, number>;
  };
  semgrep: {
    available: boolean;
    configs_used: string[];
    total_findings: number;
    by_cwe: Record<string, number>;
  };
  rules_generated: {
    count: number;
    cwes_covered: string[];
    categories: Record<AgentRule["category"], number>;
    rule_ids: string[];
    rule_titles: string[];
  };
  formatted_section_chars: number;
  error?: string;
}

interface MultiLanguageResults {
  metadata: {
    run_at: string;
    semgrep_available: boolean;
    targets: TargetRepo[];
    new_patterns_added: string[];
  };
  results: RepoScanResult[];
  summary: {
    by_language: Record<string, {
      repos_scanned: number;
      avg_stale_ai_findings: number;
      avg_semgrep_findings: number;
      avg_rules: number;
      all_cwes_detected: string[];
      all_rule_ids_fired: string[];
    }>;
    overall: {
      total_repos: number;
      total_findings: number;
      total_rules_generated: number;
      new_rule_ids_fired: string[]; // AI-PYRAND-011, AI-SHELL-012, etc.
    };
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const NEW_RULE_IDS = [
  "AI-PYRAND-011",
  "AI-SHELL-012",
  "AI-YAML-013",
  "AI-GORAND-014",
  "AI-GOEXEC-015",
  "AI-GOTLS-016",
];

function ensureRepoCloned(target: TargetRepo): string {
  const repoDir = path.join(REPOS_CACHE, target.name);
  if (fs.existsSync(repoDir) && fs.existsSync(path.join(repoDir, ".git"))) {
    return repoDir;
  }
  fs.mkdirSync(REPOS_CACHE, { recursive: true });
  console.log(`  Cloning ${target.slug}...`);
  execSync(
    `git clone --depth ${target.clone_depth} https://github.com/${target.slug}.git "${repoDir}"`,
    { stdio: "pipe", timeout: 180_000 }
  );
  return repoDir;
}

function countFiles(dir: string): { py: number; go: number; total: number } {
  let py = 0, go = 0, total = 0;
  const SKIP = new Set(["node_modules", ".git", "vendor", "__pycache__", "dist", "build", ".cache"]);

  function walk(d: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (SKIP.has(e.name)) continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (e.isFile()) {
        total++;
        if (e.name.endsWith(".py")) py++;
        else if (e.name.endsWith(".go")) go++;
      }
    }
  }
  walk(dir);
  return { py, go, total };
}

function groupBy<T, K extends string>(items: T[], key: (item: T) => K | undefined): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const item of items) {
    const k = key(item);
    if (!k) continue;
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function categoryCounts(rules: AgentRule[]): Record<AgentRule["category"], number> {
  const counts: Record<AgentRule["category"], number> = {
    ghost_dep: 0,
    ai_pattern: 0,
    secret: 0,
    sast: 0,
  };
  for (const r of rules) counts[r.category]++;
  return counts;
}

// ─── Core scan ────────────────────────────────────────────────────────────────

async function scanRepo(target: TargetRepo, semgrepAvail: boolean): Promise<RepoScanResult> {
  const result: RepoScanResult = {
    language: target.language,
    repo: target.name,
    slug: target.slug,
    file_counts: { py: 0, go: 0, total: 0 },
    stale_ai: { total_findings: 0, by_rule: {}, by_cwe: {} },
    semgrep: { available: semgrepAvail, configs_used: [], total_findings: 0, by_cwe: {} },
    rules_generated: { count: 0, cwes_covered: [], categories: { ghost_dep: 0, ai_pattern: 0, secret: 0, sast: 0 }, rule_ids: [], rule_titles: [] },
    formatted_section_chars: 0,
  };

  try {
    const repoDir = ensureRepoCloned(target);
    result.file_counts = countFiles(repoDir);
    console.log(`    Files: ${result.file_counts.py} .py, ${result.file_counts.go} .go, ${result.file_counts.total} total`);

    // Stale AI scanner
    process.stdout.write("    Running stale AI pattern scanner... ");
    const staleFindings = runStaleAiPatternScanner(repoDir);
    console.log(`${staleFindings.length} findings`);
    result.stale_ai.total_findings = staleFindings.length;
    result.stale_ai.by_rule = groupBy(staleFindings, (f: any) => f.rule_id);
    result.stale_ai.by_cwe = groupBy(staleFindings, (f: any) => f.cwe);

    // Semgrep scanner
    let semgrepFindings: any[] = [];
    if (semgrepAvail) {
      process.stdout.write("    Running Semgrep... ");
      try {
        const ctx = analyzeContext(repoDir);
        result.semgrep.configs_used = ctx.semgrepConfigs;
        if (ctx.semgrepConfigs.length > 0) {
          semgrepFindings = runSemgrep(repoDir, ctx);
          console.log(`${semgrepFindings.length} findings (configs: ${ctx.semgrepConfigs.join(", ")})`);
        } else {
          console.log(`0 (no configs)`);
        }
      } catch (e: any) {
        console.log(`ERROR — ${e.message}`);
      }
    }
    result.semgrep.total_findings = semgrepFindings.length;
    result.semgrep.by_cwe = groupBy(semgrepFindings, (f: any) => f.cwe);

    // Generate rules
    const allFindings = [...staleFindings, ...semgrepFindings];
    const rules = generateAgentRules(allFindings);
    const cwes = [...new Set(rules.flatMap(r => r.cwes))].sort();
    result.rules_generated = {
      count: rules.length,
      cwes_covered: cwes,
      categories: categoryCounts(rules),
      rule_ids: rules.map(r => r.id),
      rule_titles: rules.map(r => r.title),
    };

    // Format the section
    const section = formatRulesSection(rules, target.name);
    result.formatted_section_chars = section.length;

    console.log(`    Rules generated: ${rules.length} (${cwes.length} CWEs: ${cwes.join(", ")})`);
  } catch (e: any) {
    result.error = e.message;
    console.log(`    ERROR: ${e.message}`);
  }

  return result;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("=".repeat(70));
  console.log("MULTI-LANGUAGE SCANNER EVALUATION");
  console.log("=".repeat(70));

  const semgrepAvail = isSemgrepAvailable();
  console.log(`Semgrep available: ${semgrepAvail}`);
  console.log(`Targets: ${TARGETS.length} repos (${TARGETS.filter(t => t.language === "python").length} Python, ${TARGETS.filter(t => t.language === "go").length} Go)`);

  fs.mkdirSync(OUT_DIR, { recursive: true });

  const results: RepoScanResult[] = [];
  for (const target of TARGETS) {
    console.log(`\n── ${target.language.toUpperCase()}: ${target.name} (${target.slug}) ──`);
    const result = await scanRepo(target, semgrepAvail);
    results.push(result);
  }

  // Build summary
  const byLang: MultiLanguageResults["summary"]["by_language"] = {};
  for (const lang of ["python", "go"]) {
    const langResults = results.filter(r => r.language === lang && !r.error);
    if (langResults.length === 0) continue;

    const allCwes = new Set<string>();
    const allRuleIds = new Set<string>();
    for (const r of langResults) {
      for (const cwe of r.rules_generated.cwes_covered) allCwes.add(cwe);
      for (const rid of r.rules_generated.rule_ids) allRuleIds.add(rid);
    }

    byLang[lang] = {
      repos_scanned: langResults.length,
      avg_stale_ai_findings: Math.round(langResults.reduce((a, r) => a + r.stale_ai.total_findings, 0) / langResults.length * 10) / 10,
      avg_semgrep_findings: Math.round(langResults.reduce((a, r) => a + r.semgrep.total_findings, 0) / langResults.length * 10) / 10,
      avg_rules: Math.round(langResults.reduce((a, r) => a + r.rules_generated.count, 0) / langResults.length * 10) / 10,
      all_cwes_detected: [...allCwes].sort(),
      all_rule_ids_fired: [...allRuleIds].sort(),
    };
  }

  const allRuleIdsFired = new Set<string>();
  for (const r of results) {
    for (const id of Object.keys(r.stale_ai.by_rule)) allRuleIdsFired.add(id);
  }
  const newRuleIdsFired = NEW_RULE_IDS.filter(id => allRuleIdsFired.has(id));

  const output: MultiLanguageResults = {
    metadata: {
      run_at: new Date().toISOString(),
      semgrep_available: semgrepAvail,
      targets: TARGETS,
      new_patterns_added: NEW_RULE_IDS,
    },
    results,
    summary: {
      by_language: byLang,
      overall: {
        total_repos: results.filter(r => !r.error).length,
        total_findings: results.reduce((a, r) => a + r.stale_ai.total_findings + r.semgrep.total_findings, 0),
        total_rules_generated: results.reduce((a, r) => a + r.rules_generated.count, 0),
        new_rule_ids_fired: newRuleIdsFired,
      },
    },
  };

  const outPath = path.join(OUT_DIR, "multi-language-results.json");
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));

  console.log("\n" + "=".repeat(70));
  console.log("SUMMARY");
  console.log("=".repeat(70));
  console.log(`Total repos scanned: ${output.summary.overall.total_repos}/${TARGETS.length}`);
  console.log(`Total findings: ${output.summary.overall.total_findings}`);
  console.log(`Total rules generated: ${output.summary.overall.total_rules_generated}`);
  console.log(`New Python/Go rule IDs fired: ${newRuleIdsFired.length > 0 ? newRuleIdsFired.join(", ") : "(none)"}`);
  console.log();
  for (const [lang, s] of Object.entries(byLang)) {
    console.log(`${lang.toUpperCase()}: ${s.repos_scanned} repos, avg ${s.avg_stale_ai_findings} stale-AI + ${s.avg_semgrep_findings} semgrep, ${s.avg_rules} rules`);
    console.log(`  CWEs: ${s.all_cwes_detected.join(", ") || "(none)"}`);
  }
  console.log(`\nResults saved to: ${outPath}`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
