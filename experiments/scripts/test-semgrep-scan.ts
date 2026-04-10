/**
 * Quick test: verify Semgrep SAST integration with the E2E pipeline.
 * Scans each cached repo and reports findings + generated rules.
 */
import { runSemgrep, isSemgrepAvailable } from "../../../backend/src/lib/patchpilot/semgrep-scanner";
import { analyzeContext } from "../../../backend/src/lib/patchpilot/context-analyzer";
import { runStaleAiPatternScanner } from "../../../backend/src/lib/patchpilot/stale-ai-pattern-scanner";
import { generateAgentRules } from "../../../backend/src/lib/patchpilot/rule-generator";
import path from "path";

const REPOS_DIR = path.join(import.meta.dir, "../../..", "backend/experiments/.repos-cache");
const REPOS = ["express", "hono", "documenso"];

async function main() {
  console.log("=== Semgrep SAST Integration Test ===\n");

  if (!isSemgrepAvailable()) {
    console.error("ERROR: Semgrep not available");
    process.exit(1);
  }
  console.log("Semgrep: available\n");

  for (const name of REPOS) {
    const repoDir = path.join(REPOS_DIR, name);
    console.log(`--- ${name} ---`);

    // Analyze context
    const ctx = analyzeContext(repoDir);
    console.log(`  Languages: ${ctx.languages.join(", ")}`);
    console.log(`  Semgrep configs: ${ctx.semgrepConfigs.join(", ")}`);

    if (ctx.semgrepConfigs.length === 0) {
      console.log(`  No Semgrep configs — skipping\n`);
      continue;
    }

    // Run Semgrep
    const startTime = Date.now();
    const findings = runSemgrep(repoDir, ctx);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`  SAST findings: ${findings.length} (${elapsed}s)`);

    // Show CWE breakdown
    const cweCounts: Record<string, number> = {};
    for (const f of findings) {
      cweCounts[f.cwe] = (cweCounts[f.cwe] ?? 0) + 1;
    }
    for (const [cwe, count] of Object.entries(cweCounts).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${cwe}: ${count} findings`);
    }

    // Also run stale AI patterns for comparison
    const staleFindings = runStaleAiPatternScanner(repoDir);
    console.log(`  Stale AI findings: ${staleFindings.length}`);

    // Generate combined rules
    const allFindings = [...staleFindings, ...findings];
    const rules = generateAgentRules(allFindings);
    const cwes = [...new Set(rules.flatMap(r => r.cwes))];
    console.log(`  Combined rules: ${rules.length} covering CWEs: ${cwes.join(", ")}`);
    for (const r of rules) {
      console.log(`    [${r.category}] ${r.title} (${r.cwes.join(",")}) — ${r.finding_ids.length} findings`);
    }
    console.log();
  }
}

main().catch(console.error);
