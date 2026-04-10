/**
 * ABLATION STUDY — PatchPilot Rule Generation Pipeline
 *
 * Isolates and measures the contribution of each pipeline component WITHOUT
 * making any LLM API calls. This is a scan-only ablation.
 *
 * Three ablation dimensions:
 *
 *   1. Scanner type     — Stale-AI only vs Semgrep-SAST only vs Both combined
 *                         Metric: rules generated, CWEs covered, category mix
 *
 *   2. Instruction file format — CLAUDE.md vs .cursorrules vs copilot-instructions.md
 *                         Metric: are the formatted outputs identical or different?
 *                         Finding: formatRulesSection() is format-agnostic (same template
 *                         for all three files); this study confirms the hypothesis.
 *
 *   3. Rule count       — Full rule set vs Top-N subsets (50%, top-3, top-5)
 *                         Metric: CWE coverage retained at each subset size
 *
 * Run: bun run research/experiments/scripts/ablation-study.ts
 */

import fs from "fs";
import path from "path";
import { runStaleAiPatternScanner } from "../../../backend/src/lib/patchpilot/stale-ai-pattern-scanner";
import { isSemgrepAvailable, runSemgrep } from "../../../backend/src/lib/patchpilot/semgrep-scanner";
import { analyzeContext } from "../../../backend/src/lib/patchpilot/context-analyzer";
import { generateAgentRules, formatRulesSection } from "../../../backend/src/lib/patchpilot/rule-generator";
import type { AgentRule } from "../../../backend/src/lib/patchpilot/rule-generator";

// ─── Constants ────────────────────────────────────────────────────────────────

// Try the backend cache first (populated by prior experiments), fall back to research cache
const BACKEND_REPOS_CACHE = path.resolve(__dirname, "../../../backend/experiments/.repos-cache");
const RESEARCH_REPOS_CACHE = path.resolve(__dirname, "../.repos-cache");
const REPOS_CACHE = fs.existsSync(BACKEND_REPOS_CACHE) && fs.readdirSync(BACKEND_REPOS_CACHE).length > 0
  ? BACKEND_REPOS_CACHE
  : RESEARCH_REPOS_CACHE;
const OUT_DIR = path.resolve(__dirname, "../data");
const TARGET_REPOS = ["express", "hono", "documenso"];

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScannerConfig {
  id: "stale-ai-only" | "semgrep-only" | "combined";
  label: string;
  includeStaleAi: boolean;
  includeSemgrep: boolean;
}

interface ScanResult {
  repo: string;
  config: ScannerConfig["id"];
  config_label: string;
  stale_ai_findings: number;
  semgrep_findings: number;
  total_findings: number;
  rules_generated: number;
  cwes_covered: string[];
  cwe_count: number;
  categories: Record<AgentRule["category"], number>;
  rule_ids: string[];
}

interface FormatAblationResult {
  repo: string;
  rules_count: number;
  formats: {
    format: string;
    target_file: string;
    char_count: number;
    line_count: number;
    section_preview: string; // first 200 chars of the formatted section
  }[];
  are_identical: boolean;
  diff_note: string;
}

interface RuleCountAblationResult {
  repo: string;
  full_rule_count: number;
  full_cwe_count: number;
  full_cwes: string[];
  subsets: {
    label: string;
    rule_count: number;
    cwe_count: number;
    cwes_retained: string[];
    cwes_lost: string[];
    coverage_pct: number;
  }[];
}

interface AblationResults {
  metadata: {
    run_at: string;
    repos: string[];
    semgrep_available: boolean;
    ablation_dimensions: string[];
  };
  scanner_type_ablation: ScanResult[];
  format_ablation: FormatAblationResult[];
  rule_count_ablation: RuleCountAblationResult[];
  summary: {
    scanner_type: {
      stale_ai_unique_cwes: string[];
      semgrep_unique_cwes: string[];
      shared_cwes: string[];
      stale_ai_avg_rules: number;
      semgrep_avg_rules: number;
      combined_avg_rules: number;
    };
    format: {
      outputs_are_identical: boolean;
      conclusion: string;
    };
    rule_count: {
      avg_coverage_at_50pct: number;
      avg_coverage_at_top5: number;
      avg_coverage_at_top3: number;
    };
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function categoryCounts(rules: AgentRule[]): Record<AgentRule["category"], number> {
  const counts: Record<AgentRule["category"], number> = {
    ghost_dep: 0,
    ai_pattern: 0,
    secret: 0,
    sast: 0,
  };
  for (const r of rules) {
    counts[r.category]++;
  }
  return counts;
}

function avg(nums: number[]): number {
  if (nums.length === 0) return 0;
  return Math.round((nums.reduce((a, b) => a + b, 0) / nums.length) * 10) / 10;
}

// ─── Dimension 1: Scanner Type Ablation ───────────────────────────────────────

async function runScannerTypeAblation(semgrepAvail: boolean): Promise<ScanResult[]> {
  console.log("\n" + "─".repeat(70));
  console.log("DIMENSION 1: Scanner Type Ablation");
  console.log("─".repeat(70));

  const CONFIGS: ScannerConfig[] = [
    { id: "stale-ai-only", label: "Stale-AI patterns only (no Semgrep)", includeStaleAi: true, includeSemgrep: false },
    { id: "semgrep-only",  label: "Semgrep SAST only (no Stale-AI)",     includeStaleAi: false, includeSemgrep: true },
    { id: "combined",      label: "Both combined (default pipeline)",     includeStaleAi: true,  includeSemgrep: true },
  ];

  const results: ScanResult[] = [];

  for (const repo of TARGET_REPOS) {
    const repoDir = path.join(REPOS_CACHE, repo);
    if (!fs.existsSync(repoDir)) {
      console.log(`  [SKIP] ${repo} — not in cache at ${repoDir}`);
      continue;
    }

    console.log(`\n  Repo: ${repo}`);

    // Run stale-AI scanner once
    process.stdout.write(`    Running Stale-AI scanner... `);
    const staleFindings = runStaleAiPatternScanner(repoDir);
    console.log(`${staleFindings.length} findings`);

    // Run Semgrep once (if available), reused across configs
    let semgrepFindings: any[] = [];
    if (semgrepAvail) {
      process.stdout.write(`    Running Semgrep... `);
      try {
        const ctx = analyzeContext(repoDir);
        if (ctx.semgrepConfigs.length > 0) {
          semgrepFindings = runSemgrep(repoDir, ctx);
          console.log(`${semgrepFindings.length} findings (configs: ${ctx.semgrepConfigs.join(", ")})`);
        } else {
          console.log(`0 findings (no Semgrep configs detected)`);
        }
      } catch (e: any) {
        console.log(`ERROR — ${e.message}`);
      }
    } else {
      console.log(`    Semgrep: not available, skipping`);
    }

    // Evaluate each config
    for (const config of CONFIGS) {
      if (config.includeSemgrep && !semgrepAvail) {
        // Semgrep-only and combined configs are skipped if semgrep not available
        // but we still record them with 0 semgrep findings for combined
        if (config.id === "semgrep-only") continue;
      }

      const findings: any[] = [
        ...(config.includeStaleAi ? staleFindings : []),
        ...(config.includeSemgrep ? semgrepFindings : []),
      ];

      const rules = generateAgentRules(findings);
      const cwes = [...new Set(rules.flatMap(r => r.cwes))].sort();

      results.push({
        repo,
        config: config.id,
        config_label: config.label,
        stale_ai_findings: config.includeStaleAi ? staleFindings.length : 0,
        semgrep_findings: config.includeSemgrep ? semgrepFindings.length : 0,
        total_findings: findings.length,
        rules_generated: rules.length,
        cwes_covered: cwes,
        cwe_count: cwes.length,
        categories: categoryCounts(rules),
        rule_ids: rules.map(r => r.id),
      });

      const cats = categoryCounts(rules);
      console.log(`    [${config.id.padEnd(12)}] findings=${findings.length.toString().padStart(4)} → rules=${rules.length.toString().padStart(3)} | CWEs=[${cwes.join(", ")}] | cats={ai:${cats.ai_pattern},sast:${cats.sast},secret:${cats.secret},ghost:${cats.ghost_dep}}`);
    }
  }

  return results;
}

// ─── Dimension 2: Instruction File Format Ablation ────────────────────────────

/**
 * formatRulesSection() uses HTML comment markers (<!-- PATCHPILOT:START -->) and
 * Markdown syntax. It is intentionally format-agnostic — the same function produces
 * content written to CLAUDE.md, .cursorrules, and copilot-instructions.md.
 *
 * This ablation confirms whether the outputs are byte-identical or differ by format.
 * Since all three agent config formats are Markdown-compatible, we expect identical output.
 */
async function runFormatAblation(semgrepAvail: boolean): Promise<FormatAblationResult[]> {
  console.log("\n" + "─".repeat(70));
  console.log("DIMENSION 2: Instruction File Format Ablation");
  console.log("─".repeat(70));
  console.log("  Testing: CLAUDE.md vs .cursorrules vs copilot-instructions.md");
  console.log("  Hypothesis: formatRulesSection() produces identical content for all three");

  const FORMAT_CONFIGS = [
    { format: "CLAUDE.md",                   target_file: "CLAUDE.md" },
    { format: ".cursorrules",                target_file: ".cursorrules" },
    { format: "copilot-instructions.md",     target_file: ".github/copilot-instructions.md" },
  ];

  const results: FormatAblationResult[] = [];

  for (const repo of TARGET_REPOS) {
    const repoDir = path.join(REPOS_CACHE, repo);
    if (!fs.existsSync(repoDir)) continue;

    // Get a real set of rules from combined scan
    const staleFindings = runStaleAiPatternScanner(repoDir);
    let semgrepFindings: any[] = [];
    if (semgrepAvail) {
      try {
        const ctx = analyzeContext(repoDir);
        if (ctx.semgrepConfigs.length > 0) {
          semgrepFindings = runSemgrep(repoDir, ctx);
        }
      } catch {}
    }
    const allFindings = [...staleFindings, ...semgrepFindings];
    const rules = generateAgentRules(allFindings);

    // Call formatRulesSection() for each "format" — same function, same rules, same repo name.
    // The target_file list in AgentRule determines WHICH files to write to,
    // but formatRulesSection() itself does not vary by format.
    const formatOutputs = FORMAT_CONFIGS.map(fc => {
      const section = formatRulesSection(rules, repo);
      return {
        format: fc.format,
        target_file: fc.target_file,
        char_count: section.length,
        line_count: section.split("\n").length,
        section_preview: section.slice(0, 200),
        full_text: section,
      };
    });

    // Compare outputs
    const firstText = formatOutputs[0].full_text;
    const allIdentical = formatOutputs.every(f => f.full_text === firstText);

    const result: FormatAblationResult = {
      repo,
      rules_count: rules.length,
      formats: formatOutputs.map(({ full_text: _, ...rest }) => rest),
      are_identical: allIdentical,
      diff_note: allIdentical
        ? "All three formats receive identical content from formatRulesSection(). The function is format-agnostic by design — it emits Markdown with HTML comment markers compatible with all three agent config files."
        : "UNEXPECTED: outputs differ. Investigate formatRulesSection() parameterization.",
    };

    results.push(result);
    console.log(`\n  Repo: ${repo} (${rules.length} rules)`);
    for (const f of result.formats) {
      console.log(`    ${f.format.padEnd(32)} chars=${f.char_count}  lines=${f.line_count}`);
    }
    console.log(`    Identical: ${allIdentical ? "YES — format makes no difference" : "NO — outputs differ"}`);

    // Save the actual formatted sections for inspection
    const outDir = path.join(OUT_DIR, "ablation", "formats", repo);
    fs.mkdirSync(outDir, { recursive: true });
    for (const f of formatOutputs) {
      const fname = f.format.replace(/[/.]/g, "_").replace(/^_/, "") + ".md";
      fs.writeFileSync(path.join(outDir, fname), `# ${repo} — ${f.format}\n\n${f.full_text}\n`);
    }
  }

  return results;
}

// ─── Dimension 3: Rule Count Ablation ─────────────────────────────────────────

async function runRuleCountAblation(semgrepAvail: boolean): Promise<RuleCountAblationResult[]> {
  console.log("\n" + "─".repeat(70));
  console.log("DIMENSION 3: Rule Count Ablation");
  console.log("─".repeat(70));
  console.log("  Testing: how much CWE coverage is retained at subset sizes?");

  const results: RuleCountAblationResult[] = [];

  for (const repo of TARGET_REPOS) {
    const repoDir = path.join(REPOS_CACHE, repo);
    if (!fs.existsSync(repoDir)) continue;

    const staleFindings = runStaleAiPatternScanner(repoDir);
    let semgrepFindings: any[] = [];
    if (semgrepAvail) {
      try {
        const ctx = analyzeContext(repoDir);
        if (ctx.semgrepConfigs.length > 0) {
          semgrepFindings = runSemgrep(repoDir, ctx);
        }
      } catch {}
    }
    const allFindings = [...staleFindings, ...semgrepFindings];
    const fullRules = generateAgentRules(allFindings);
    const fullCwes = [...new Set(fullRules.flatMap(r => r.cwes))].sort();
    const N = fullRules.length;

    // Define subsets — we take from the front of the sorted list
    // (sort order: ghost_dep > ai_pattern > secret > sast — highest-signal first)
    const subsetDefs: { label: string; size: number }[] = [
      { label: "full set", size: N },
      { label: "top 75% (high-severity bias)", size: Math.max(1, Math.floor(N * 0.75)) },
      { label: "top 50%", size: Math.max(1, Math.floor(N * 0.5)) },
      { label: "top 5 rules", size: Math.min(5, N) },
      { label: "top 3 rules", size: Math.min(3, N) },
    ];

    const subsets = subsetDefs.map(def => {
      const subset = fullRules.slice(0, def.size);
      const subsetCwes = [...new Set(subset.flatMap(r => r.cwes))].sort();
      const lost = fullCwes.filter(c => !subsetCwes.includes(c));
      return {
        label: def.label,
        rule_count: def.size,
        cwe_count: subsetCwes.length,
        cwes_retained: subsetCwes,
        cwes_lost: lost,
        coverage_pct: fullCwes.length > 0 ? Math.round((subsetCwes.length / fullCwes.length) * 100) : 100,
      };
    });

    results.push({
      repo,
      full_rule_count: N,
      full_cwe_count: fullCwes.length,
      full_cwes: fullCwes,
      subsets,
    });

    console.log(`\n  Repo: ${repo} (${N} rules, ${fullCwes.length} CWEs: ${fullCwes.join(", ")})`);
    for (const s of subsets) {
      const bar = "█".repeat(Math.round(s.coverage_pct / 5)) + "░".repeat(20 - Math.round(s.coverage_pct / 5));
      console.log(`    ${s.label.padEnd(30)} ${s.rule_count.toString().padStart(3)} rules  ${s.cwe_count}/${fullCwes.length} CWEs [${bar}] ${s.coverage_pct}%`);
      if (s.cwes_lost.length > 0) {
        console.log(`      lost: ${s.cwes_lost.join(", ")}`);
      }
    }
  }

  return results;
}

// ─── Summary computation ──────────────────────────────────────────────────────

function computeSummary(
  scannerResults: ScanResult[],
  formatResults: FormatAblationResult[],
  ruleCountResults: RuleCountAblationResult[]
): AblationResults["summary"] {
  // Scanner type summary
  const staleOnlyResults = scannerResults.filter(r => r.config === "stale-ai-only");
  const semgrepOnlyResults = scannerResults.filter(r => r.config === "semgrep-only");
  const combinedResults = scannerResults.filter(r => r.config === "combined");

  const staleAllCwes = [...new Set(staleOnlyResults.flatMap(r => r.cwes_covered))].sort();
  const semgrepAllCwes = [...new Set(semgrepOnlyResults.flatMap(r => r.cwes_covered))].sort();

  const staleUnique = staleAllCwes.filter(c => !semgrepAllCwes.includes(c));
  const semgrepUnique = semgrepAllCwes.filter(c => !staleAllCwes.includes(c));
  const shared = staleAllCwes.filter(c => semgrepAllCwes.includes(c));

  // Format summary
  const allIdentical = formatResults.every(r => r.are_identical);

  // Rule count summary — average coverage at each subset size across repos
  const coverageAt50 = ruleCountResults.map(r => r.subsets.find(s => s.label === "top 50%")?.coverage_pct ?? 100);
  const coverageAt5 = ruleCountResults.map(r => r.subsets.find(s => s.label === "top 5 rules")?.coverage_pct ?? 100);
  const coverageAt3 = ruleCountResults.map(r => r.subsets.find(s => s.label === "top 3 rules")?.coverage_pct ?? 100);

  return {
    scanner_type: {
      stale_ai_unique_cwes: staleUnique,
      semgrep_unique_cwes: semgrepUnique,
      shared_cwes: shared,
      stale_ai_avg_rules: avg(staleOnlyResults.map(r => r.rules_generated)),
      semgrep_avg_rules: avg(semgrepOnlyResults.map(r => r.rules_generated)),
      combined_avg_rules: avg(combinedResults.map(r => r.rules_generated)),
    },
    format: {
      outputs_are_identical: allIdentical,
      conclusion: allIdentical
        ? "formatRulesSection() produces byte-identical content regardless of target file (CLAUDE.md / .cursorrules / copilot-instructions.md). The format dimension does not affect rule content."
        : "Unexpected format divergence detected — outputs differ across agent config files.",
    },
    rule_count: {
      avg_coverage_at_50pct: avg(coverageAt50),
      avg_coverage_at_top5: avg(coverageAt5),
      avg_coverage_at_top3: avg(coverageAt3),
    },
  };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("=".repeat(70));
  console.log("PATCHPILOT ABLATION STUDY — Scan-Only (No LLM API calls)");
  console.log("=".repeat(70));
  console.log(`Repos cache: ${REPOS_CACHE}`);
  console.log(`Target repos: ${TARGET_REPOS.join(", ")}`);

  // Validate repos exist
  const missingRepos = TARGET_REPOS.filter(r => !fs.existsSync(path.join(REPOS_CACHE, r)));
  if (missingRepos.length > 0) {
    console.warn(`\nWARNING: These repos are not in cache: ${missingRepos.join(", ")}`);
    console.warn(`Run the e2e-experiment.ts first to populate the cache, or clone them to ${REPOS_CACHE}`);
  }

  const semgrepAvail = isSemgrepAvailable();
  console.log(`\nSemgrep available: ${semgrepAvail}`);
  if (!semgrepAvail) {
    console.log("  NOTE: Semgrep configs not available — semgrep-only and combined results will reflect 0 Semgrep findings.");
    console.log("  Install: pip install semgrep   or   brew install semgrep");
  }

  // Run all three ablation dimensions
  const scannerResults = await runScannerTypeAblation(semgrepAvail);
  const formatResults = await runFormatAblation(semgrepAvail);
  const ruleCountResults = await runRuleCountAblation(semgrepAvail);

  // Compute summary
  const summary = computeSummary(scannerResults, formatResults, ruleCountResults);

  // ── Print summary tables ────────────────────────────────────────────────────

  console.log("\n" + "=".repeat(70));
  console.log("ABLATION RESULTS SUMMARY");
  console.log("=".repeat(70));

  console.log("\nTable 1: Scanner Type Ablation — Rules Generated per Repo");
  console.log("┌─────────────┬──────────────┬───────────────────┬────────────────────────────┐");
  console.log("│ Repo        │ Config       │ Findings → Rules  │ CWEs covered               │");
  console.log("├─────────────┼──────────────┼───────────────────┼────────────────────────────┤");
  for (const r of scannerResults) {
    const configLabel = r.config === "stale-ai-only" ? "stale-AI" : r.config === "semgrep-only" ? "semgrep" : "combined";
    console.log(`│ ${r.repo.padEnd(11)} │ ${configLabel.padEnd(12)} │ ${String(r.total_findings).padStart(6)} → ${String(r.rules_generated).padStart(5)} │ ${r.cwes_covered.join(", ").slice(0, 26).padEnd(26)} │`);
  }
  console.log("└─────────────┴──────────────┴───────────────────┴────────────────────────────┘");

  console.log(`\nScanner type summary:`);
  console.log(`  Stale-AI-only  avg rules: ${summary.scanner_type.stale_ai_avg_rules}`);
  console.log(`  Semgrep-only   avg rules: ${summary.scanner_type.semgrep_avg_rules}`);
  console.log(`  Combined       avg rules: ${summary.scanner_type.combined_avg_rules}`);
  console.log(`  CWEs only from Stale-AI:  [${summary.scanner_type.stale_ai_unique_cwes.join(", ")}]`);
  console.log(`  CWEs only from Semgrep:   [${summary.scanner_type.semgrep_unique_cwes.join(", ")}]`);
  console.log(`  CWEs covered by both:     [${summary.scanner_type.shared_cwes.join(", ")}]`);

  console.log("\nTable 2: Instruction File Format Ablation");
  console.log("  Q: Does the target file (CLAUDE.md vs .cursorrules vs copilot-instructions.md) change the content?");
  for (const r of formatResults) {
    console.log(`  ${r.repo}: identical=${r.are_identical}`);
  }
  console.log(`\n  Conclusion: ${summary.format.conclusion}`);

  console.log("\nTable 3: Rule Count Ablation — CWE Coverage Retained at Subset Sizes");
  console.log("┌─────────────┬────────────────────────────────┬───────────┬──────────────┐");
  console.log("│ Repo        │ Subset                         │ Rules     │ CWE coverage │");
  console.log("├─────────────┼────────────────────────────────┼───────────┼──────────────┤");
  for (const r of ruleCountResults) {
    for (const s of r.subsets) {
      console.log(`│ ${r.repo.padEnd(11)} │ ${s.label.padEnd(30)} │ ${String(s.rule_count).padStart(5)}     │ ${String(s.coverage_pct).padStart(3)}% (${s.cwe_count}/${r.full_cwe_count})   │`);
    }
  }
  console.log("└─────────────┴────────────────────────────────┴───────────┴──────────────┘");

  console.log(`\nRule count summary (avg across repos):`);
  console.log(`  Coverage at top 50% of rules:  ${summary.rule_count.avg_coverage_at_50pct}%`);
  console.log(`  Coverage at top 5 rules:        ${summary.rule_count.avg_coverage_at_top5}%`);
  console.log(`  Coverage at top 3 rules:        ${summary.rule_count.avg_coverage_at_top3}%`);

  // ── Save JSON results ───────────────────────────────────────────────────────

  fs.mkdirSync(OUT_DIR, { recursive: true });

  const ablationResults: AblationResults = {
    metadata: {
      run_at: new Date().toISOString(),
      repos: TARGET_REPOS.filter(r => fs.existsSync(path.join(REPOS_CACHE, r))),
      semgrep_available: semgrepAvail,
      ablation_dimensions: [
        "scanner_type: stale-ai-only vs semgrep-only vs combined",
        "instruction_file_format: CLAUDE.md vs .cursorrules vs copilot-instructions.md",
        "rule_count: full vs top-75% vs top-50% vs top-5 vs top-3",
      ],
    },
    scanner_type_ablation: scannerResults,
    format_ablation: formatResults,
    rule_count_ablation: ruleCountResults,
    summary,
  };

  const outPath = path.join(OUT_DIR, "ablation-results.json");
  fs.writeFileSync(outPath, JSON.stringify(ablationResults, null, 2));
  console.log(`\nResults saved to: ${outPath}`);

  // Also save per-format sections for manual inspection
  console.log(`Format samples saved to: ${path.join(OUT_DIR, "ablation", "formats")}/`);
}

main().catch(err => {
  console.error("Ablation study failed:", err);
  process.exit(1);
});
