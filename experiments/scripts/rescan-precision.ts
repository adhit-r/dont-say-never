/**
 * Re-run the stale AI pattern scanner on the 3 eval repos with the new FP fixes
 * and compare before/after counts to quantify precision improvements.
 *
 * Fixes applied:
 *   - AI-EVAL-001:   lookbehind now excludes method calls (.exec())
 *   - AI-HTTP-004:   skip W3C namespaces + error message strings
 *   - AI-LOG-007:    require identifier (variable) not just a literal string
 *   - AI-RAND-003:   skip seed/fixture files
 *
 * Run: bun run research/experiments/scripts/rescan-precision.ts
 */

import fs from "fs";
import path from "path";
import { runStaleAiPatternScanner } from "../../../backend/src/lib/patchpilot/stale-ai-pattern-scanner";

const REPOS_CACHE = path.resolve(__dirname, "../../../backend/experiments/.repos-cache");
const OUT_PATH = path.resolve(__dirname, "../data/scanner-precision-after-fixes.json");

// Before numbers from research/experiments/data/scanner-precision-recall.json
const BEFORE: Record<string, { total: number; tp: number; fp: number; cd: number }> = {
  express:   { total: 1,  tp: 1, fp: 0,  cd: 0  },
  hono:      { total: 13, tp: 0, fp: 8,  cd: 5  },
  documenso: { total: 66, tp: 0, fp: 42, cd: 24 },
};

const REPOS = ["express", "hono", "documenso"];

function groupBy<T, K extends string>(items: T[], key: (item: T) => K | undefined): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const item of items) {
    const k = key(item);
    if (!k) continue;
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

async function main() {
  console.log("=".repeat(70));
  console.log("SCANNER PRECISION RE-EVALUATION — FP-FIX VALIDATION");
  console.log("=".repeat(70));

  const results: any[] = [];
  let totalBefore = 0;
  let totalAfter = 0;

  for (const repo of REPOS) {
    const repoDir = path.join(REPOS_CACHE, repo);
    if (!fs.existsSync(repoDir)) {
      console.log(`  ${repo}: NOT CACHED — skipping`);
      continue;
    }

    console.log(`\n── ${repo} ──`);
    const findings = runStaleAiPatternScanner(repoDir);
    const before = BEFORE[repo];
    const afterTotal = findings.length;

    console.log(`  Before: ${before.total} findings (${before.tp} TP, ${before.fp} FP, ${before.cd} CD)`);
    console.log(`  After:  ${afterTotal} findings`);

    const byRule = groupBy(findings, (f: any) => f.rule_id);
    const byCwe = groupBy(findings, (f: any) => f.cwe);

    console.log(`  By rule: ${JSON.stringify(byRule)}`);
    console.log(`  By CWE:  ${JSON.stringify(byCwe)}`);

    totalBefore += before.total;
    totalAfter += afterTotal;

    // Optimistic: assume all remaining findings after FP reduction are TP+CD
    // (requires manual re-classification for exact precision, but this bounds it)
    const delta = before.total - afterTotal;
    const fpReduced = Math.min(delta, before.fp); // can't remove more FPs than existed

    results.push({
      repo,
      before: {
        total: before.total,
        tp: before.tp,
        fp: before.fp,
        cd: before.cd,
        precision_conservative: before.total > 0 ? (before.tp + before.cd) / before.total : 0,
      },
      after: {
        total: afterTotal,
        by_rule: byRule,
        by_cwe: byCwe,
      },
      delta: {
        findings_removed: delta,
        fp_reduction_estimate: fpReduced,
        removal_pct: before.total > 0 ? delta / before.total : 0,
      },
    });
  }

  // Summary
  const overall = {
    total_before: totalBefore,
    total_after: totalAfter,
    removed: totalBefore - totalAfter,
    removal_pct: totalBefore > 0 ? (totalBefore - totalAfter) / totalBefore : 0,
  };

  const output = {
    metadata: {
      run_at: new Date().toISOString(),
      fixes_applied: [
        "AI-EVAL-001: lookbehind now excludes method calls (RegExp.exec)",
        "AI-HTTP-004: skip W3C/Adobe/Schema namespace URIs and error message strings",
        "AI-LOG-007: require identifier arg, not literal string",
        "AI-RAND-003/011/014: skip seed/fixture/mock/demo files",
      ],
      before_source: "research/experiments/data/scanner-precision-recall.json",
    },
    per_repo: results,
    overall,
  };

  fs.writeFileSync(OUT_PATH, JSON.stringify(output, null, 2));

  console.log("\n" + "=".repeat(70));
  console.log("SUMMARY");
  console.log("=".repeat(70));
  console.log(`Total findings before: ${totalBefore}`);
  console.log(`Total findings after:  ${totalAfter}`);
  console.log(`Removed: ${totalBefore - totalAfter} (${Math.round((totalBefore - totalAfter) / totalBefore * 100)}%)`);
  console.log(`\nSaved to: ${OUT_PATH}`);
}

main().catch(e => { console.error(e); process.exit(1); });
