/**
 * Dump raw scanner findings to JSON for manual classification.
 * Used once to generate the source data for the precision/recall analysis.
 */
import { runSemgrep, isSemgrepAvailable } from "../../../backend/src/lib/patchpilot/semgrep-scanner";
import { analyzeContext } from "../../../backend/src/lib/patchpilot/context-analyzer";
import { runStaleAiPatternScanner } from "../../../backend/src/lib/patchpilot/stale-ai-pattern-scanner";
import path from "path";
import fs from "fs";

const REPOS_DIR = path.join(import.meta.dir, "../../..", "backend/experiments/.repos-cache");
const REPOS = ["express", "hono", "documenso"];
const OUT_PATH = path.join(import.meta.dir, "../data/findings-raw.json");

async function main() {
  const output: Record<string, { semgrep: any[]; stale_ai: any[] }> = {};

  for (const name of REPOS) {
    const repoDir = path.join(REPOS_DIR, name);
    const ctx = analyzeContext(repoDir);

    const semgrepFindings = ctx.semgrepConfigs.length > 0
      ? runSemgrep(repoDir, ctx)
      : [];

    const staleFindings = runStaleAiPatternScanner(repoDir);

    output[name] = {
      semgrep: semgrepFindings.map(f => ({
        file: f.file_path,
        line: f.line,
        rule: f.rule_id,
        cwe: f.cwe,
        severity: f.severity,
        code: f.vulnerable_code,
        msg: f.description,
      })),
      stale_ai: staleFindings.map(f => ({
        file: f.file_path,
        line: f.line,
        rule: f.rule_id,
        cwe: f.cwe,
        severity: f.severity,
        code: f.vulnerable_code,
        msg: f.description,
      })),
    };
  }

  fs.writeFileSync(OUT_PATH, JSON.stringify(output, null, 2));
  console.log(`Written to ${OUT_PATH}`);

  // Quick summary
  for (const [repo, data] of Object.entries(output)) {
    console.log(`\n=== ${repo} ===`);
    console.log(`  Semgrep: ${data.semgrep.length} findings`);
    console.log(`  Stale AI: ${data.stale_ai.length} findings`);
  }
}

main().catch(console.error);
