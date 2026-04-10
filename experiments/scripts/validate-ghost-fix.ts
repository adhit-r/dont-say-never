/**
 * Validate ghost dep scanner precision improvement.
 * Runs the fixed scanner against the 3 E2E repos and reports findings.
 */
import { runGhostDepScanner } from "../../../backend/src/lib/patchpilot/ghost-dep-scanner";

const REPOS = [
  { name: "express", path: "../../../backend/experiments/.repos-cache/express" },
  { name: "hono", path: "../../../backend/experiments/.repos-cache/hono" },
  { name: "documenso", path: "../../../backend/experiments/.repos-cache/documenso" },
];

async function main() {
  console.log("=== Ghost Dep Scanner Precision Validation ===\n");

  let totalFindings = 0;
  const allFindings: Array<{ repo: string; name: string; risk: string; desc: string }> = [];

  for (const repo of REPOS) {
    const repoPath = new URL(repo.path, import.meta.url).pathname;

    try {
      const findings = await runGhostDepScanner(repoPath);
      console.log(`\n${repo.name}: ${findings.length} findings`);

      for (const f of findings) {
        console.log(`  [${f.risk}] ${f.package_name} — ${f.severity}`);
        allFindings.push({ repo: repo.name, name: f.package_name, risk: f.risk, desc: f.description });
      }

      totalFindings += findings.length;
    } catch (e: any) {
      console.log(`  ${repo.name}: ERROR — ${e.message}`);
    }
  }

  console.log(`\n=== SUMMARY ===`);
  console.log(`Total findings across 3 repos: ${totalFindings}`);
  console.log(`Previous total (before fix): 44`);
  console.log(`Reduction: ${44 - totalFindings} fewer findings (${Math.round((1 - totalFindings/44) * 100)}% reduction in FP)`);

  if (totalFindings > 0) {
    console.log(`\nRemaining findings to review:`);
    for (const f of allFindings) {
      console.log(`  ${f.repo}: ${f.name} [${f.risk}]`);
    }
  }
}

main().catch(console.error);
