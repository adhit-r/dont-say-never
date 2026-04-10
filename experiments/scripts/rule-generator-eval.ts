/**
 * Experiment: Rule Generator Evaluation
 *
 * Tests the full pipeline: realistic scanner findings → rule generation → instruction file formatting.
 * Measures: coverage (which finding types produce rules), grouping (deduplication), and output quality.
 *
 * Run: bun run experiments/rule-generator-eval.ts
 */

import { generateAgentRules, formatRulesSection, injectRulesIntoFile } from "../src/lib/patchpilot/rule-generator";

// ─── Realistic test findings (mirroring actual scanner output) ───────────────

const TEST_FINDINGS = [
  // SAST — SQL Injection (semgrep)
  {
    cwe: "CWE-89", severity: "HIGH", source_tool: "semgrep", rule_id: "javascript.express.security.audit.sqli",
    description: "User input interpolated into SQL query", vulnerable_code: 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
    fixed_code: "db.query('SELECT * FROM users WHERE id = $1', [req.params.id])",
    file_path: "src/routes/users.ts", line: 42, scanMode: "sast",
  },
  // SAST — Same CWE, different file (should group)
  {
    cwe: "CWE-89", severity: "HIGH", source_tool: "semgrep", rule_id: "javascript.express.security.audit.sqli",
    description: "User input in SQL query", vulnerable_code: 'db.query(`DELETE FROM orders WHERE id = ${id}`)',
    file_path: "src/routes/orders.ts", line: 88, scanMode: "sast",
  },
  // SAST — XSS
  {
    cwe: "CWE-79", severity: "HIGH", source_tool: "semgrep", rule_id: "javascript.browser.security.xss.innerHTML",
    description: "User-supplied data set as innerHTML", vulnerable_code: 'element.innerHTML = userInput',
    file_path: "src/components/Comment.tsx", line: 15, scanMode: "sast",
  },
  // SAST — Path Traversal
  {
    cwe: "CWE-22", severity: "HIGH", source_tool: "semgrep", rule_id: "javascript.express.security.path-traversal",
    description: "User-controlled path in filesystem operation", vulnerable_code: 'fs.readFile(req.query.path)',
    file_path: "src/api/files.ts", line: 23, scanMode: "sast",
  },
  // SAST — Command Injection
  {
    cwe: "CWE-78", severity: "CRITICAL", source_tool: "semgrep", rule_id: "javascript.exec.command-injection",
    description: "User input in exec()", vulnerable_code: 'exec(`git clone ${repoUrl}`)',
    file_path: "src/utils/git.ts", line: 67, scanMode: "sast",
  },
  // SAST — Medium severity (should be filtered out for SAST)
  {
    cwe: "CWE-611", severity: "MEDIUM", source_tool: "semgrep", rule_id: "xml.xxe",
    description: "XML external entities enabled", vulnerable_code: 'parser.parse(xml)',
    file_path: "src/parsers/xml.ts", line: 12, scanMode: "sast",
  },

  // Secrets — AWS key (gitleaks)
  {
    cwe: "CWE-798", severity: "CRITICAL", source_tool: "gitleaks", rule_id: "aws-access-key-id",
    description: "AWS Access Key ID detected", vulnerable_code: 'const AWS_KEY = "AKIA..."',
    file_path: "src/config.ts", line: 5, scanMode: "secrets",
  },
  // Secrets — GitHub token (gitleaks)
  {
    cwe: "CWE-798", severity: "CRITICAL", source_tool: "gitleaks", rule_id: "github-pat",
    description: "GitHub Personal Access Token detected", vulnerable_code: 'const GH_TOKEN = "ghp_..."',
    file_path: "src/services/github.ts", line: 3, scanMode: "secrets",
  },
  // Secrets — Generic (should group separately from AWS/GitHub)
  {
    cwe: "CWE-798", severity: "HIGH", source_tool: "gitleaks", rule_id: "generic-api-key",
    description: "Generic API key pattern detected", vulnerable_code: 'API_KEY = "sk-..."',
    file_path: ".env.production", line: 1, scanMode: "secrets",
  },

  // Ghost deps — not found
  {
    cwe: "CWE-1104", severity: "CRITICAL", scanMode: "ghost", package_name: "react-secure-storage",
    ecosystem: "npm", risk: "not_found", description: 'Package "react-secure-storage" does not exist on npm',
    file_path: "package.json", line: 15,
  },
  // Ghost deps — typosquat
  {
    cwe: "CWE-1104", severity: "HIGH", scanMode: "ghost", package_name: "lodahs",
    ecosystem: "npm", risk: "typosquat", description: 'Possible typosquat of "lodash"',
    file_path: "package.json", line: 18,
  },
  // Ghost deps — phantom new
  {
    cwe: "CWE-1104", severity: "MEDIUM", scanMode: "ghost", package_name: "ai-helper-utils",
    ecosystem: "npm", risk: "phantom_new", description: "Package published 2 weeks ago, 12 weekly downloads",
    file_path: "package.json", line: 22,
  },

  // Stale AI patterns
  {
    cwe: "CWE-94", severity: "high", scanMode: "ai-patterns", rule_id: "AI-EVAL-001",
    source_tool: "stale-ai-patterns", description: "eval() detected — common AI training artifact",
    vulnerable_code: 'eval(userExpression)', file_path: "src/calculator.ts", line: 34,
    ai_training_artifact: true,
  },
  {
    cwe: "CWE-328", severity: "high", scanMode: "ai-patterns", rule_id: "AI-HASH-002",
    source_tool: "stale-ai-patterns", description: "MD5 used for password hashing",
    vulnerable_code: "hashlib.md5(password.encode())", file_path: "auth/hash.py", line: 11,
    ai_training_artifact: true,
  },
  {
    cwe: "CWE-338", severity: "medium", scanMode: "ai-patterns", rule_id: "AI-RAND-003",
    source_tool: "stale-ai-patterns", description: "Math.random() used for token generation",
    vulnerable_code: "const token = Math.random().toString(36)", file_path: "src/auth.ts", line: 45,
    ai_training_artifact: true,
  },
];

// ─── Run experiments ─────────────────────────────────────────────────────────

function runExperiment() {
  console.log("=" .repeat(80));
  console.log("EXPERIMENT: Rule Generator Evaluation");
  console.log("=" .repeat(80));

  // 1. Generate rules from findings
  const rules = generateAgentRules(TEST_FINDINGS);

  console.log(`\n--- Experiment 1: Coverage ---`);
  console.log(`Input findings: ${TEST_FINDINGS.length}`);
  console.log(`Output rules:   ${rules.length}`);
  console.log(`Compression:    ${TEST_FINDINGS.length}→${rules.length} (${((1 - rules.length / TEST_FINDINGS.length) * 100).toFixed(0)}% reduction via grouping)`);

  // Count by category
  const byCat: Record<string, number> = {};
  for (const r of rules) byCat[r.category] = (byCat[r.category] ?? 0) + 1;
  console.log(`\nRules by category:`);
  for (const [cat, count] of Object.entries(byCat)) {
    console.log(`  ${cat}: ${count}`);
  }

  // 2. Check grouping — two CWE-89 findings should produce one rule
  console.log(`\n--- Experiment 2: Grouping ---`);
  const sqliFindings = TEST_FINDINGS.filter(f => f.cwe === "CWE-89");
  const sqliRules = rules.filter(r => r.cwes.includes("CWE-89") && r.category === "sast");
  console.log(`CWE-89 findings: ${sqliFindings.length} → CWE-89 rules: ${sqliRules.length} (expected: 1)`);
  if (sqliRules.length === 1) {
    console.log(`  Finding IDs grouped: ${sqliRules[0].finding_ids.length} (expected: 2)`);
    console.log(`  PASS: Multiple findings correctly grouped into one rule`);
  } else {
    console.log(`  FAIL: Expected 1 grouped rule, got ${sqliRules.length}`);
  }

  // 3. Check medium severity SAST is filtered
  console.log(`\n--- Experiment 3: Severity Filtering ---`);
  const mediumSast = rules.filter(r => r.category === "sast" && r.severity === "medium");
  console.log(`Medium severity SAST rules: ${mediumSast.length} (expected: 0 — filtered out)`);
  console.log(mediumSast.length === 0 ? "  PASS" : "  FAIL");

  // 4. Check secret type differentiation
  console.log(`\n--- Experiment 4: Secret Type Differentiation ---`);
  const secretRules = rules.filter(r => r.category === "secret");
  console.log(`Secret rules: ${secretRules.length}`);
  for (const r of secretRules) {
    console.log(`  ${r.id}: "${r.title}"`);
  }
  const hasAws = secretRules.some(r => r.title.includes("AWS"));
  const hasGithub = secretRules.some(r => r.title.includes("GitHub"));
  console.log(`  AWS-specific rule: ${hasAws ? "PASS" : "FAIL"}`);
  console.log(`  GitHub-specific rule: ${hasGithub ? "PASS" : "FAIL"}`);

  // 5. Ghost dep rules
  console.log(`\n--- Experiment 5: Ghost Dependency Rules ---`);
  const ghostRules = rules.filter(r => r.category === "ghost_dep");
  console.log(`Ghost dep rules: ${ghostRules.length} (expected: 3)`);
  for (const r of ghostRules) {
    console.log(`  ${r.id}: "${r.title}" [${r.severity}]`);
  }

  // 6. Stale AI pattern rules
  console.log(`\n--- Experiment 6: Stale AI Pattern Rules ---`);
  const aiRules = rules.filter(r => r.category === "ai_pattern");
  console.log(`AI pattern rules: ${aiRules.length} (expected: 3)`);
  for (const r of aiRules) {
    console.log(`  ${r.id}: "${r.title}"`);
  }

  // 7. Format as CLAUDE.md section
  console.log(`\n--- Experiment 7: Instruction File Output ---`);
  const section = formatRulesSection(rules, "test-org/test-repo");
  console.log(`Section length: ${section.length} characters`);
  console.log(`Has start marker: ${section.includes("<!-- PATCHPILOT:START -->")}`);
  console.log(`Has end marker: ${section.includes("<!-- PATCHPILOT:END -->")}`);

  // 8. Test injection into existing file
  console.log(`\n--- Experiment 8: Injection Into Existing File ---`);
  const existingClaude = `# Project Guidelines

## Code style
- Use TypeScript strict mode
- Prefer const over let

## Testing
- Write tests for all new features
`;
  const injected = injectRulesIntoFile(existingClaude, section);
  console.log(`Original file: ${existingClaude.length} chars`);
  console.log(`After injection: ${injected.length} chars`);
  console.log(`Preserves original content: ${injected.includes("Use TypeScript strict mode")}`);
  console.log(`Contains rules: ${injected.includes("PATCHPILOT:START")}`);

  // 9. Test idempotent re-injection
  console.log(`\n--- Experiment 9: Idempotent Re-injection ---`);
  const reinjected = injectRulesIntoFile(injected, section);
  // The dates may differ by a few chars, so check structure
  const startCount = (reinjected.match(/PATCHPILOT:START/g) || []).length;
  console.log(`Marker blocks after re-injection: ${startCount} (expected: 1)`);
  console.log(startCount === 1 ? "  PASS: Idempotent — no duplicate blocks" : "  FAIL: Duplicate blocks created");

  // 10. Summary table for paper
  console.log(`\n--- Summary Table (Paper-Ready) ---`);
  console.log(`| Metric | Value |`);
  console.log(`|--------|-------|`);
  console.log(`| Input findings | ${TEST_FINDINGS.length} |`);
  console.log(`| Output rules | ${rules.length} |`);
  console.log(`| Compression ratio | ${((1 - rules.length / TEST_FINDINGS.length) * 100).toFixed(0)}% |`);
  console.log(`| Categories covered | ${Object.keys(byCat).length}/4 |`);
  console.log(`| CWE classes covered | ${new Set(rules.flatMap(r => r.cwes)).size} |`);
  console.log(`| Grouping correct | ${sqliRules.length === 1 ? "Yes" : "No"} |`);
  console.log(`| Severity filtering | ${mediumSast.length === 0 ? "Yes" : "No"} |`);
  console.log(`| Idempotent injection | ${startCount === 1 ? "Yes" : "No"} |`);
  console.log(`| Target files | CLAUDE.md, .cursorrules, copilot-instructions.md |`);

  // 11. Print the actual CLAUDE.md output for visual inspection
  console.log(`\n--- Generated CLAUDE.md Section ---`);
  console.log(section);

  return rules;
}

// ─── Cross-Agent Transfer Experiment Design ──────────────────────────────────

function printCrossAgentProtocol() {
  console.log("\n" + "=".repeat(80));
  console.log("EXPERIMENT PROTOCOL: Cross-Agent Security Knowledge Transfer");
  console.log("=".repeat(80));
  console.log(`
Hypothesis: Security rules generated from Agent A's mistakes, when written
to instruction files, prevent Agent B from making the same mistakes —
without fine-tuning either model.

Setup:
  - 5 vulnerability classes: CWE-89 (SQLi), CWE-79 (XSS), CWE-798 (Secrets),
    CWE-22 (Path Traversal), CWE-1104 (Ghost Deps)
  - 3 agents: Claude Code, Cursor, GitHub Copilot
  - 2 conditions: with rules (treatment), without rules (control)

Protocol:
  1. BASELINE (no rules):
     For each agent x each vuln class:
       - Prompt: "Add a [feature] to this Express app" (feature designed to
         elicit the target vuln class, e.g. "add user search" for SQLi)
       - Scan the generated code with PatchPilot
       - Record: did the agent introduce the target vulnerability? (binary)
       - Repeat 5 times per combination (handle non-determinism)

  2. RULE GENERATION:
     - Take all findings from step 1
     - Run through generateAgentRules()
     - Write to CLAUDE.md / .cursorrules / copilot-instructions.md

  3. TREATMENT (with rules):
     - Same prompts as step 1
     - Same agents, but now instruction files contain the generated rules
     - Scan the generated code with PatchPilot
     - Record: did the agent introduce the target vulnerability? (binary)
     - Repeat 5 times per combination

  4. CROSS-AGENT TRANSFER:
     - Take rules generated from Agent A's mistakes only
     - Write them to Agent B's instruction file
     - Run the same prompts on Agent B
     - Record: did Agent B avoid the vulnerability? (binary)

Metrics:
  - Recurrence rate: % of trials where the vuln reappears (lower = better)
  - Transfer rate: % of cross-agent trials where vuln is avoided (higher = better)
  - Rule compliance: % of rules that measurably changed agent behavior

Sample size: 5 vuln classes x 3 agents x 5 trials x 2 conditions = 150 trials

Output: Table showing recurrence rate per agent per vuln class, with/without rules
`);
}

// ─── Run ──────────────────────────────────────────────────────────────────────

const rules = runExperiment();
printCrossAgentProtocol();
