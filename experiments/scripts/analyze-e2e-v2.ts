/**
 * Analyze E2E v2 results (with Semgrep SAST).
 * Computes statistics for paper v5.
 */
import fs from "fs";
import path from "path";

const data = JSON.parse(fs.readFileSync(path.join(import.meta.dir, "../data/e2e-v2-results.json"), "utf8"));
const results = data.results.filter((r: any) => !r.excluded);

console.log("=" .repeat(70));
console.log("E2E v2 ANALYSIS — With Semgrep SAST");
console.log("=" .repeat(70));

// ── Model breakdown ──────────────────────────────────────────────────
console.log("\n── By Model ──");
const models = [...new Set(results.map((r: any) => r.model))];
for (const m of models) {
  const mr = results.filter((r: any) => r.model === m);
  const cV = mr.reduce((s: number, r: any) => s + r.ctrl_vuln, 0);
  const cT = mr.reduce((s: number, r: any) => s + r.ctrl.filter((x: number) => x >= 0).length, 0);
  const tV = mr.reduce((s: number, r: any) => s + r.treat_vuln, 0);
  const tT = mr.reduce((s: number, r: any) => s + r.treat.filter((x: number) => x >= 0).length, 0);
  const red = cV > 0 ? ((1 - tV / cV) * 100).toFixed(0) : "N/A";
  console.log(`  ${m.padEnd(18)} ctrl: ${cV}/${cT} (${(cV/cT*100).toFixed(1)}%)  treat: ${tV}/${tT} (${(tV/tT*100).toFixed(1)}%)  reduction: ${red}%`);
}

// ── Claude Sonnet 4 detail (complete dataset) ────────────────────────
console.log("\n── Claude Sonnet 4 (complete across all 3 repos) ──");
const sonnet = results.filter((r: any) => r.model === "claude-sonnet");
const sCv = sonnet.reduce((s: number, r: any) => s + r.ctrl_vuln, 0);
const sCt = sonnet.reduce((s: number, r: any) => s + r.ctrl.filter((x: number) => x >= 0).length, 0);
const sTv = sonnet.reduce((s: number, r: any) => s + r.treat_vuln, 0);
const sTt = sonnet.reduce((s: number, r: any) => s + r.treat.filter((x: number) => x >= 0).length, 0);
console.log(`  Overall: ctrl ${sCv}/${sCt} (${(sCv/sCt*100).toFixed(1)}%) → treat ${sTv}/${sTt} (${(sTv/sTt*100).toFixed(1)}%)`);
console.log(`  Reduction: ${((1-sTv/sCv)*100).toFixed(1)}%`);

// ── Matched vs Unmatched (Sonnet) ────────────────────────────────────
console.log("\n── Matched vs Unmatched CWEs (Sonnet) ──");
const sMatched = sonnet.filter((r: any) => r.matched);
const sUnmatched = sonnet.filter((r: any) => !r.matched);

const mCv = sMatched.reduce((s: number, r: any) => s + r.ctrl_vuln, 0);
const mCt = sMatched.reduce((s: number, r: any) => s + r.ctrl.filter((x: number) => x >= 0).length, 0);
const mTv = sMatched.reduce((s: number, r: any) => s + r.treat_vuln, 0);
const mTt = sMatched.reduce((s: number, r: any) => s + r.treat.filter((x: number) => x >= 0).length, 0);
console.log(`  Matched:   ctrl ${mCv}/${mCt} (${(mCv/mCt*100).toFixed(1)}%) → treat ${mTv}/${mTt} (${(mTv/mTt*100).toFixed(1)}%)  reduction: ${((1-mTv/Math.max(mCv,1))*100).toFixed(1)}%`);

const uCv = sUnmatched.reduce((s: number, r: any) => s + r.ctrl_vuln, 0);
const uCt = sUnmatched.reduce((s: number, r: any) => s + r.ctrl.filter((x: number) => x >= 0).length, 0);
const uTv = sUnmatched.reduce((s: number, r: any) => s + r.treat_vuln, 0);
const uTt = sUnmatched.reduce((s: number, r: any) => s + r.treat.filter((x: number) => x >= 0).length, 0);
console.log(`  Unmatched: ctrl ${uCv}/${uCt} (${(uCv/uCt*100).toFixed(1)}%) → treat ${uTv}/${uTt} (${(uTv/uTt*100).toFixed(1)}%)`);

// ── Per-prompt detail (Sonnet) ───────────────────────────────────────
console.log("\n── Per-Prompt Detail (Sonnet) ──");
console.log("  Repo         Prompt           CWE      Match  Ctrl  Treat  Prevented?");
console.log("  " + "-".repeat(65));
for (const r of sonnet) {
  const prevented = r.ctrl_vuln > 0 && r.treat_vuln < r.ctrl_vuln ? "YES" :
    r.ctrl_vuln === 0 && r.treat_vuln === 0 ? "baseline safe" :
    r.ctrl_vuln === 0 && r.treat_vuln > 0 ? "WORSE" :
    r.treat_vuln >= r.ctrl_vuln ? "NO" : "partial";
  console.log(`  ${r.repo.padEnd(13)} ${r.prompt.padEnd(17)} ${r.cwe.padEnd(9)} ${(r.matched?"Y":"N").padEnd(6)} ${r.ctrl_vuln}/3   ${r.treat_vuln}/3    ${prevented}`);
}

// ── Nemotron (hono only) ─────────────────────────────────────────────
console.log("\n── Nemotron 120B (hono only — all other repos rate-limited) ──");
const nemo = results.filter((r: any) => r.model === "nemotron-120b");
for (const r of nemo) {
  console.log(`  ${r.prompt.padEnd(17)} ctrl: ${r.ctrl_vuln}/3  treat: ${r.treat_vuln}/3`);
}
const nCv = nemo.reduce((s: number, r: any) => s + r.ctrl_vuln, 0);
const nTv = nemo.reduce((s: number, r: any) => s + r.treat_vuln, 0);
console.log(`  Total: ctrl ${nCv}/9 → treat ${nTv}/9  reduction: ${((1-nTv/nCv)*100).toFixed(1)}%`);

// ── Combined usable data ─────────────────────────────────────────────
console.log("\n── Combined Usable Data (excl. errors + rate-limited) ──");
const allCv = results.reduce((s: number, r: any) => s + r.ctrl_vuln, 0);
const allCt = results.reduce((s: number, r: any) => s + r.ctrl.filter((x: number) => x >= 0).length, 0);
const allTv = results.reduce((s: number, r: any) => s + r.treat_vuln, 0);
const allTt = results.reduce((s: number, r: any) => s + r.treat.filter((x: number) => x >= 0).length, 0);
console.log(`  Total: ctrl ${allCv}/${allCt} (${(allCv/allCt*100).toFixed(1)}%) → treat ${allTv}/${allTt} (${(allTv/allTt*100).toFixed(1)}%)`);
console.log(`  Reduction: ${((1-allTv/Math.max(allCv,1))*100).toFixed(1)}%`);

// ── Fisher's exact test approximation ────────────────────────────────
// For Sonnet matched CWEs: 13/18 ctrl vs 5/18 treat
console.log("\n── Statistical Tests (Sonnet, matched CWEs) ──");
console.log(`  Control: ${mCv}/${mCt} vulnerable (${(mCv/mCt*100).toFixed(1)}%)`);
console.log(`  Treatment: ${mTv}/${mTt} vulnerable (${(mTv/mTt*100).toFixed(1)}%)`);
// Chi-squared for 2x2 table
const a = mCv, b = mCt - mCv, c = mTv, d = mTt - mTv;
const n = a + b + c + d;
const chi2 = n * (a * d - b * c) ** 2 / ((a+b) * (c+d) * (a+c) * (b+d));
console.log(`  Chi-squared: ${chi2.toFixed(2)}`);
console.log(`  (p < 0.05 if chi2 > 3.84, p < 0.01 if chi2 > 6.63, p < 0.001 if chi2 > 10.83)`);

// ── Key findings for paper ───────────────────────────────────────────
console.log("\n── KEY FINDINGS FOR PAPER v5 ──");
console.log("1. Semgrep SAST added: Express 0→2 rules, Hono 3→4, Documenso 3→5");
console.log("2. Claude Sonnet 4 (frontier model) complete data across 3 repos");
console.log(`3. Matched CWEs: ${mCv}/${mCt} → ${mTv}/${mTt} (${((1-mTv/Math.max(mCv,1))*100).toFixed(0)}% reduction)`);
console.log(`4. Unmatched CWEs: ${uCv}/${uCt} → ${uTv}/${uTt} (Sonnet already safe on Express prompts)`);
console.log("5. Nemotron 120B (hono): confirms pattern, 44% reduction");
console.log("6. GPT-OSS 120B: failed (rate limits) — excluded");
console.log("7. Nemotron on express/documenso: failed (rate limits) — excluded");
console.log("8. Notable: eval-dynamic (documenso) WORSENED with treatment (0/3→2/3)");
console.log("9. Notable: http-url (hono) NO CHANGE (3/3→3/3) — prompt specifies exact URL");
