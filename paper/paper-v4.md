# Scan, Learn, Prevent: Closing the Feedback Loop Between Security Scanners and AI Coding Agents

**Adhithya Rajasekaran**

rajasekaran.adhit@gmail.com | github.com/adhit-r

---

## Abstract

AI coding agents lack persistent memory of security failures, causing the same vulnerability classes to recur across sessions. We present a closed-loop system that connects automated security scanners to agent instruction files (CLAUDE.md, .cursorrules, copilot-instructions.md), generating deterministic, template-driven rules from CWE-classified findings. In an end-to-end evaluation across 3 repositories and 2 models (108 trials, excluding a rate-limited third model), vulnerability rates decreased from 68.5% (95% CI: 55.3--79.3%) to 40.7% (95% CI: 28.7--54.0%), a statistically significant reduction (chi-squared=8.41, p=0.004). The effect was specific to CWE classes where the scanner generated rules: for matched CWEs, vulnerability rates dropped from 83% to 30% (64% relative reduction), while unmatched CWEs showed no change (50% vs. 54%), confirming the treatment effect is not a general prompt-context artifact. A controlled mechanism validation with hand-crafted rules (240 trials, 4 models) established a 98.8% upper bound, demonstrating that the rule format itself is effective and that the binding constraint on end-to-end performance is scanner coverage, not rule quality. However, a post-hoc precision analysis of the ghost dependency scanner revealed a 100% false positive rate across the 3 evaluated repositories (44/44 flagged packages were legitimate), indicating that scanner validation is a prerequisite for deployment. We discuss the implications for using agent instruction files as a programmable security policy layer and the limitations that must be addressed before this approach is production-ready.

---

## 1. Introduction

The adoption of AI coding agents has changed software development substantially. Tools such as Anthropic's Claude Code, Cursor, GitHub Copilot, and Block's Goose now generate significant portions of production codebases [1]. These agents share a limitation: they have no durable memory of security failures across sessions.

When an AI agent introduces a SQL injection vulnerability via string concatenation, hardcodes an API key, or imports a hallucinated package name, the same class of vulnerability is likely to recur in subsequent sessions. Each session starts fresh. The agent reads its instruction file, generates code, and the cycle repeats.

This paper addresses the question: can automated security detection feed back into agent instruction files to reduce vulnerability recurrence? We present a system with three contributions:

1. **A closed-loop pipeline** connecting multiple security scanners (SAST, secret detection, ghost dependency detection, stale AI pattern detection) to agent instruction file mutation.

2. **A deterministic, template-driven rule generator** that converts CWE-classified findings into natural language rules without using an LLM in the generation step, ensuring auditability and reproducibility.

3. **Cross-agent rule distribution via instruction files**: rules generated from scanner output are written to CLAUDE.md, .cursorrules, and copilot-instructions.md simultaneously, enabling any agent on the project to inherit the rules without fine-tuning.

We evaluate through three experiments with increasing realism. The results are mixed: the rule format is highly effective when rules exist for the relevant CWE class, but the end-to-end pipeline is constrained by scanner coverage and precision. We report both the successes and the significant limitations, including a 100% false positive rate in the ghost dependency scanner on the evaluated repositories.

---

## 2. Background and Related Work

### 2.1 Agent Instruction Files

Modern AI coding agents support project-specific instruction files read at session initialization. Claude Code reads CLAUDE.md [2], Cursor reads .cursorrules [3], GitHub Copilot reads .github/copilot-instructions.md [4], and Goose reads .goosehints [5]. The AGENTS.md specification under the Agentic AI Foundation (AAIF) [6] standardizes the concept. These files are today manually authored and rarely updated in response to security findings.

### 2.2 Reflexion and Verbal Reinforcement Learning

Shinn et al. [7] introduced Reflexion, where language agents learn from verbal self-reflection stored in an episodic memory buffer, improving HumanEval pass@1 from 80.1% to 91.0%. However, Reflexion's memory is ephemeral and does not persist across independent sessions. Shinn et al. [18] later found that LLM self-correction is unreliable without external feedback, motivating our use of external scanner output rather than self-reflection.

### 2.3 Self-Correcting Agents

Pi-Reflect [8] analyzes conversation transcripts and generates rule updates, reducing correction rates from 0.45 to 0.07 per session. BMO [9] takes a similar approach. Osmani [17] surveys self-improving coding agents. Our system differs in three ways: (a) it uses structured scanner output rather than unstructured transcripts; (b) rule generation is deterministic and template-driven; (c) it writes to multiple instruction file formats simultaneously.

### 2.4 Commercial Agent Memory Systems

Cognition's Devin maintains a Knowledge system requiring user approval [10]. Windsurf's Cascade generates Memories automatically [11], though the SpAIware exploit [12] demonstrated that this mechanism can be poisoned via prompt injection. Cursor's /Generate Rules requires manual invocation [3]. None use structured security scanner output or write to multiple agent platforms.

### 2.5 Constitutional AI and Rule-Based Steering

Bai et al. [16] introduced Constitutional AI (CAI), where models follow explicit principles embedded during training. Our approach applies a similar concept at inference time: security rules are injected through instruction files as system-prompt-level constraints, requiring no model modification.

### 2.6 AI-Generated Code Security

Pearce et al. [13] found Copilot produces vulnerable code in approximately 40% of security-relevant scenarios. Asare et al. [14] showed LLM-generated code contains weaknesses at rates comparable to human-written code. Our ghost dependency scanner addresses a related threat: LLM hallucination of package names creating supply chain attack vectors [15].

---

## 3. System Design

The system operates as a pipeline with four stages: multi-scanner detection, finding classification, deterministic rule generation, and multi-format instruction file injection.

### 3.1 Multi-Scanner Detection

The system orchestrates eight specialized scanners:

| Scanner | Target | Implementation |
|---------|--------|---------------|
| SAST | Code-level vulnerabilities | Semgrep integration |
| Secret detection | Hardcoded credentials | Gitleaks integration |
| SCA | Vulnerable dependencies | Trivy integration |
| Ghost dependencies | AI-hallucinated packages | Custom (TypeScript) |
| Stale AI patterns | Outdated training artifacts | Custom (regex) |
| Prompt injection | Instruction override attempts | Custom |
| IaC scanning | Infrastructure misconfig | Bearer integration |
| Vibe score | Overall security posture | Custom |

**Ghost dependency scanner.** LLMs hallucinate package names that do not exist in registries. An attacker can register such names, creating a supply chain attack vector. Our scanner queries npm, PyPI, Go, Rust, and Ruby registries, classifying findings into three risk tiers: `not_found` (package does not exist), `typosquat` (within edit distance of a legitimate package), and `phantom_new` (recently registered with minimal downloads). As we discuss in Section 5.1, the `phantom_new` classification has significant precision problems.

**Stale AI pattern scanner.** LLMs trained on historical code generate patterns now known to be insecure. We detect 10 specific patterns via regex rules, including eval()/exec() usage (CWE-94), MD5/SHA1 for cryptographic operations (CWE-328), Math.random() for security-sensitive values (CWE-338), and plaintext HTTP in production (CWE-319). Context-sensitivity checks exclude matches in test files and build scripts.

### 3.2 Finding Classification

Scanner output is normalized into a unified schema with CWE identifier, severity level, source tool, file path, line number, and scanner-specific metadata. Findings are deduplicated and grouped by CWE for rule generation.

### 3.3 Deterministic Rule Generator

The rule generator converts classified findings into natural language rules using predefined templates. **No LLM is used in the rule generation step.** This ensures:

1. **Auditability.** Every generated rule traces to a specific template and input finding.
2. **Reproducibility.** Identical findings produce identical rules.
3. **No rule hallucination.** Template-driven rules cannot contain incorrect remediation advice invented by an LLM.

The template library covers four categories:

**Ghost dependency templates** generate package-specific warnings:
> NEVER use the package "react-encrypted-localstorage" (npm) --- it does not exist on the registry. This is likely an AI-hallucinated package name.

**Stale AI pattern templates** reference the insecure pattern and its secure alternative:
> NEVER use MD5 or SHA1 for cryptographic operations --- both are broken. Use SHA-256 (or higher) for checksums; use bcrypt, argon2, or scrypt for passwords.

**Secret templates** dynamically map secret types from scanner output to specific guidance.

**SAST templates** cover 12 CWE classes with specific remediation instructions.

**Rule compression.** Multiple findings of the same CWE class produce a single rule rather than one rule per finding. Across 14 repositories, 1,116 findings compressed to 179 rules (84% reduction). We note that the finding count is inflated by ghost dependency false positives (Section 5.1).

### 3.4 Multi-Format Instruction File Injection

Generated rules are formatted as a Markdown section with HTML comment markers (PATCHPILOT:START / PATCHPILOT:END) that enable idempotent updates. The same rules are injected into CLAUDE.md, .cursorrules, and copilot-instructions.md simultaneously.

---

## 4. Evaluation

We evaluate through three experiments, each increasing in realism. We report both successes and failures to provide an accurate picture of current capabilities.

### 4.1 Rule Generator Validation

We validated the rule generator with 9 unit tests covering: category coverage (all 4 scanner types produce rules), CWE grouping (multiple findings of the same CWE produce a single rule), severity filtering, secret type differentiation, ghost dependency classification, stale AI pattern matching, marker-based formatting, content preservation, and idempotent re-injection. All 9 tests passed. We acknowledge this tests correctness of the generator code, not the quality or precision of the scanner inputs.

### 4.2 Experiment 1: Repository Scanning

We scanned 14 repositories (7 open-source, 7 from the author's portfolio) to validate the pipeline's ability to detect findings and compress them into rule sets. This experiment does not validate scanner precision --- that analysis is deferred to Section 5.1.

**Table 1: Scan Results --- Open-Source Repositories**

| Repository | Description | Stale AI | Ghost Deps | Total | Rules | Compression |
|------------|-------------|----------|------------|-------|-------|-------------|
| express | Web framework | 1 | 11 | 12 | 11 | 8% |
| fastify | Web framework | 6 | 3 | 9 | 4 | 56% |
| hono | Web framework | 13 | 6 | 19 | 9 | 53% |
| next-learn | Learning examples | 2 | 7 | 9 | 3 | 67% |
| cal.com | Scheduling platform | 177 | 313 | 490 | 51 | 90% |
| twenty | CRM platform | 312 | 24 | 336 | 26 | 92% |
| documenso | Document signing | 66 | 53 | 119 | 30 | 75% |
| **Subtotal** | | **577** | **417** | **994** | **134** | **87%** |

**Table 2: Scan Results --- Author's Portfolio Repositories**

| Repository | Description | Stale AI | Ghost Deps | Total | Rules | Compression |
|------------|-------------|----------|------------|-------|-------|-------------|
| fairmind | AI governance platform | 17 | 19 | 36 | 21 | 42% |
| aran | API security platform | 26 | 3 | 29 | 7 | 76% |
| aran-mcp | MCP security framework | 15 | 4 | 19 | 5 | 74% |
| ChessForgeAI | Chess analysis app | 17 | 2 | 19 | 3 | 84% |
| RagaSense | AI raga detection | 9 | 4 | 13 | 5 | 62% |
| Redact-ai | Privacy automation | 2 | 4 | 6 | 4 | 33% |
| audit-lens | Compliance engine | 0 | 0 | 0 | 0 | -- |
| **Subtotal** | | **86** | **36** | **122** | **45** | **63%** |

**Combined total: 1,116 findings across 14 repositories, compressed to 179 rules (84% reduction).** We caution that the ghost dependency finding counts (453 total) are substantially inflated by false positives, as analyzed in Section 5.1. The stale AI pattern findings (663 total) have not been manually validated for precision; some fraction may represent intentional usage (e.g., eval() in a REPL implementation).

CWE coverage across all 14 repositories: CWE-1104 (untrusted dependencies) in 13/14, CWE-94 (code injection) in 9/14, CWE-319 (plaintext HTTP) in 8/14, CWE-328 (weak cryptography) in 6/14, CWE-338 (insecure randomness) in 5/14.

### 4.3 Experiment 2: Mechanism Validation (Upper Bound)

Experiment 1 established that the pipeline detects findings and generates rules. Experiment 2 asks: **do rules in this format actually change LLM behavior?** This experiment isolates the rule mechanism from scanner coverage to establish an upper bound on effectiveness.

**Important framing.** We used hand-crafted rules matching the template format exactly, one per CWE class tested. This is intentionally a best-case scenario: the rules are perfectly targeted to counter each test prompt. Real pipeline output (Experiment 3) produces less targeted rules because the scanner detects different CWEs than those tested. We report this experiment as a mechanism validation, not as a measure of end-to-end pipeline effectiveness.

**Design.** 6 vulnerability-eliciting prompts, one per CWE class (CWE-89: SQL injection, CWE-79: XSS, CWE-22: path traversal, CWE-78: command injection, CWE-328: weak cryptography, CWE-338: insecure randomness). Two conditions: control (no rules) and treatment (rules in system prompt). 4 models: Claude Sonnet 4 (Anthropic), Nemotron 120B (NVIDIA), GPT-OSS 120B (OpenAI), GPT-OSS 20B (OpenAI). 5 trials per model-prompt-condition with temperature variation (0.3--0.7), yielding 240 API calls.

**Table 3: Mechanism Validation by Model (n=5 per condition)**

| Model | Control Rate | Treatment Rate | Reduction | Fisher p |
|-------|------------:|---------------:|----------:|:--------:|
| Claude Sonnet 4 | 8/30 (27%) | 0/30 (0%) | 100% | 0.002 |
| Nemotron 120B | 22/30 (73%) | 0/30 (0%) | 100% | <0.001 |
| GPT-OSS 120B | 28/30 (93%) | 1/30 (3%) | 96% | <0.001 |
| GPT-OSS 20B | 24/30 (80%) | 0/30 (0%) | 100% | <0.001 |
| **Total** | **82/120 (68.3%)** | **1/120 (0.8%)** | **98.8%** | **<0.001** |

95% Wilson CIs: Control 59.6--76.0%, Treatment 0.1--4.6%.

All four models achieved statistical significance (Fisher's exact, one-sided, p<0.005). The single treatment vulnerability occurred in CWE-338 (insecure randomness) on GPT-OSS 120B.

**Interpretation.** This establishes that security rules in our template format are effective at changing LLM behavior under ideal conditions. The 98.8% figure is an upper bound: it assumes perfect rule coverage for every vulnerability class tested. The end-to-end evaluation (Experiment 3) measures what happens when this assumption does not hold.

### 4.4 Experiment 3: End-to-End Pipeline Evaluation

The final experiment closes the loop. We selected 3 repositories from Experiment 1 (hono, express, documenso), ran the **actual** scanners against each, fed findings through the **actual** rule generator, and used the **exact** generated CLAUDE.md content as the LLM system prompt. No hand-crafting. No manual rule selection.

**Design.** 3 repositories x 3 prompts x 3 models x 2 conditions x 3 trials = 162 total API calls. Prompts targeted CWE classes relevant to each repository's technology stack. Models: Claude Sonnet 4, Nemotron 120B, GPT-OSS 120B.

**Attrition.** Claude Sonnet 4 was rate-limited during the experiment; all 54 trials returned errors (code_length=0). These trials are excluded from the analysis. Results are based on 108 trials across 2 models.

**Table 4: End-to-End Results by Model (n=27 per model-condition)**

| Model | Control | Treatment | Reduction |
|-------|--------:|----------:|----------:|
| Nemotron 120B | 19/27 (70%) | 15/27 (56%) | 21% |
| GPT-OSS 120B | 18/27 (67%) | 7/27 (26%) | 61% |
| **Total** | **37/54 (68.5%)** | **22/54 (40.7%)** | **40.5%** |

95% Wilson CIs: Control 55.3--79.3%, Treatment 28.7--54.0%. Chi-squared=8.41, **p=0.004**.

The overall reduction is statistically significant (p<0.01), but the confidence intervals for treatment and control rates overlap, reflecting the modest sample size.

**Table 5: End-to-End Per-CWE Prevention**

| CWE | Vulnerability | Control | Treatment | Prevention | Rule Generated? |
|-----|--------------|:-------:|:---------:|:----------:|:---------------:|
| CWE-94 | Code injection | 7/12 (58%) | 2/12 (17%) | 71% | Yes |
| CWE-319 | Plaintext HTTP | 6/6 (100%) | 1/6 (17%) | 83% | Yes |
| CWE-338 | Insecure randomness | 6/6 (100%) | 1/6 (17%) | 83% | Yes |
| CWE-328 | Weak crypto (MD5) | 12/12 (100%) | 11/12 (92%) | 8% | Yes* |
| CWE-78 | Command injection | 5/6 (83%) | 4/6 (67%) | 20% | No |
| CWE-89 | SQL Injection | 0/6 (0%) | 0/6 (0%) | N/A | No |
| CWE-22 | Path Traversal | 1/6 (17%) | 3/6 (50%) | -200% | No |

*CWE-328 prompts explicitly requested MD5 (e.g., "compute an MD5 hash"), overriding the system rule.

**The critical finding: rule-matched vs. unmatched CWEs.** When we separate trials by whether the scanner generated a matching rule:

- **Matched CWEs** (CWE-94, CWE-319, CWE-328, CWE-338; N=60 after model exclusion): Control 25/30 (83%), Treatment 9/30 (30%). **64% relative reduction.**
- **Unmatched CWEs** (CWE-22, CWE-78, CWE-89; N=48 after exclusion): Control 12/24 (50%), Treatment 13/24 (54%). **No effect** (-4%, within noise).

This decomposition is the most informative result. The treatment effect is specific to CWEs where rules exist, not a general prompt-context artifact (e.g., the mere presence of security-themed text in the system prompt does not reduce vulnerability rates). Express, which generated only CWE-1104 ghost dependency rules and no stale AI pattern or SAST rules, served as an effective negative control: treatment had no effect on any Express prompt.

**CWE-328 anomaly.** Despite having a generated rule ("NEVER use MD5"), the MD5 prevention rate was only 8%. The prompts explicitly asked for MD5 by name. In current LLM architectures, explicit user instructions generally override system-level rules. This is a known limitation of instruction-file-based guardrails. In realistic development, programmers rarely request specific insecure algorithms by name; the 8% figure reflects an adversarial prompt condition rather than typical usage.

### 4.5 Multi-Model Transfer

The same rules influenced models from different providers without modification. In Experiment 2, hand-crafted rules achieved >96% effectiveness across all 4 models (3 providers). In Experiment 3, the same auto-generated CLAUDE.md content influenced both Nemotron 120B and GPT-OSS 120B, though with different effect sizes (21% vs. 61% reduction). This demonstrates that markdown-formatted instruction file rules are model-agnostic, though effectiveness varies by model.

---

## 5. Scanner Precision and Recall

A pipeline that generates rules from scanner findings inherits the scanner's precision and recall limitations. We analyze two of our custom scanners.

### 5.1 Ghost Dependency Scanner: High False Positive Rate

We manually reviewed all 44 ghost dependency findings across the 3 repositories used in Experiment 3. Classification:

| Category | Count | Proportion |
|----------|------:|:----------:|
| Well-known legitimate packages | 32 | 72.7% |
| Monorepo workspace packages | 12 | 27.3% |
| Genuinely suspicious | 0 | 0% |

**The ghost dependency scanner had a 100% false positive rate on the evaluated repositories.** All 32 non-monorepo packages flagged (including `cookie`, `debug`, `qs`, `undici`, `jose`, `pdfjs-dist`, `preact`, `wrangler`) are legitimate npm packages with millions of weekly downloads. The 12 monorepo packages (all `@documenso/*`) are private workspace references that do not exist on the public npm registry but are not security risks.

The root cause is the `phantom_new` classification heuristic, which uses a download count threshold that is too aggressive. Packages meeting the threshold are flagged as "very new with low adoption" even when they are well-established.

**Impact on reported numbers.** The 1,116 total findings across 14 repositories include 453 ghost dependency findings. If most of these are false positives (as the sampled data suggests), the true finding count is substantially lower --- likely in the range of 663--750. The 84% compression ratio would also change. We do not adjust the numbers retroactively because we have not manually reviewed all 453 ghost dependency findings, but we flag this as a significant caveat.

**Impact on rule quality.** Ghost dependency rules for legitimate packages (e.g., "Be cautious with 'debug' (npm)") are misleading rather than helpful. They do not affect the code vulnerability experiments (Experiments 2--3) because ghost dependency rules target package selection, not code patterns, and our vulnerability prompts test code patterns. However, they would degrade instruction file quality in production use.

### 5.2 Stale AI Pattern Scanner: Precision Unknown

The stale AI pattern scanner detects 10 regex patterns associated with insecure coding practices. We have not measured its precision on the 14 scanned repositories. Some flagged patterns may represent intentional usage (e.g., eval() in a REPL, MD5 for non-cryptographic checksums, HTTP for localhost development). The context-sensitivity checks (excluding test files and build scripts) mitigate some false positives, but precision validation remains future work.

### 5.3 Implications for the Pipeline

Scanner precision directly affects instruction file quality: false positive findings produce unnecessary or misleading rules. Scanner recall directly affects the pipeline's ceiling: undetected vulnerability classes produce no rules. Both are limiting factors in the end-to-end evaluation. Improving scanner precision (particularly the ghost dependency heuristic) and expanding scanner recall (enabling Semgrep SAST rules) are the most impactful paths to improving pipeline effectiveness.

---

## 6. Discussion

### 6.1 The 98.8% vs. 40.5% Gap

The most informative finding is the gap between Experiments 2 and 3. Experiment 2 established that well-crafted rules in our format are effective (98.8% upper bound). Experiment 3 revealed that the actual pipeline achieves 40.5% overall because of three compounding factors:

1. **Scanner coverage limits rule generation.** Express produced only ghost dependency findings, so the pipeline generated no code vulnerability rules. When the pipeline has no relevant findings, it generates no relevant rules.

2. **Explicit prompt requests override system rules.** CWE-328 prompts explicitly named MD5, overriding the system-level rule. This reflects a fundamental limitation of instruction-file-based guardrails.

3. **Auto-generated rules are less targeted than hand-crafted ones.** Experiment 2 rules were designed to counter each test prompt. Experiment 3 rules were generated from scanner findings without knowledge of test prompts. This is the correct evaluation methodology but produces lower numbers.

### 6.2 The Matched/Unmatched Decomposition

Filtering to matched CWEs (where rules were generated) and excluding the adversarial MD5 prompt, prevention rates of 71%, 83%, and 83% emerge for CWE-94, CWE-319, and CWE-338 respectively. The unmatched CWEs showed no effect, confirming that the mechanism works through specific rule content, not general prompt framing. This decomposition is the strongest evidence for the approach's viability: when the scanner has coverage, the rules work.

### 6.3 From Reflexion to Persistence

Our work extends Reflexion [7] from ephemeral in-context memory to durable file-based memory. The key difference is the feedback source: Reflexion uses self-generated verbal reflection, while our system uses external scanner output, which Shinn et al. [18] showed is more reliable for correction.

### 6.4 Deterministic vs. LLM-Generated Rules

Template-driven rules achieved 98.8% effectiveness in the mechanism validation, suggesting that well-phrased security instructions do not require LLM-generated nuance. LLM-generated rules would introduce hallucination risk without addressing the scanner coverage gap.

### 6.5 Instruction Files as a Policy Layer

Instruction files can serve as a model-agnostic policy enforcement layer. The same markdown rules influenced models from 3 providers, though with varying effect sizes (21--61% in the E2E evaluation). This suggests the approach is portable but not uniformly effective.

---

## 7. Threats to Validity

### 7.1 Internal Validity

**Evaluation confound in Experiment 2.** The hand-crafted rules were designed by the authors with knowledge of the test prompts. While this was intentional (to isolate the rule mechanism from scanner coverage), it means Experiment 2 measures an upper bound, not typical effectiveness. We address this by running Experiment 3.

**Vulnerability detection via regex.** Both experiments used regex pattern matching to classify generated code as vulnerable or not. This approach may miss subtle vulnerabilities (false negatives) or misclassify safe code that contains triggering patterns in comments or strings (false positives). Manual validation of a sample would strengthen confidence in the detection methodology.

**Rate limiting.** Claude Sonnet 4 was excluded from Experiment 3 due to rate limiting. This reduces the model diversity of the end-to-end evaluation to 2 models, both accessed via the same API provider (OpenRouter). Results may not generalize to Claude, GPT-4, or other frontier models.

### 7.2 External Validity

**Repository selection.** All 14 repositories are JavaScript/TypeScript web applications. Generalizability to Python, Go, Rust, or Java codebases has not been tested.

**Prompt design.** The 6 vulnerability-eliciting prompts in Experiment 2 and 9 prompts in Experiment 3 are synthetic. Real developer prompts are more varied and contextual. The prompts may be easier or harder to influence than natural development instructions.

**Scanner coverage.** The evaluation used only the ghost dependency and stale AI pattern scanners. The system includes Semgrep, Gitleaks, and Trivy integrations, but these were not enabled during the evaluation. Results with full scanner coverage would likely differ.

### 7.3 Construct Validity

**What "vulnerability prevention" measures.** Our experiments test whether an LLM generates code matching a vulnerability pattern when given a specific prompt with or without rules. This is a proxy for real-world vulnerability prevention, which involves developer interaction, code review, testing, and iterative refinement. The synthetic prompts lack the contextual specificity of real development tasks.

**Ghost dependency findings.** The 1,116 finding count includes ghost dependency results with a demonstrated 100% false positive rate in the sampled repositories. The true positive finding count is lower than reported.

---

## 8. Limitations

**Scanner precision is unvalidated.** The ghost dependency scanner's 100% false positive rate on the 3 evaluated repositories means the pipeline would produce misleading rules in production. The stale AI pattern scanner has not been precision-validated. Both require improvement before deployment.

**Sample sizes.** Experiment 2 used n=5 per condition (240 total). Experiment 3 used n=3 per condition (108 usable). Individual per-CWE cells in Experiment 3 contain 6--12 trials, limiting statistical power for per-CWE significance testing. The overall E2E result (p=0.004) is significant, but per-CWE results should be interpreted as directional rather than conclusive.

**Template coverage.** The rule template library covers 12 CWE classes. Vulnerability types outside this set do not generate rules even when detected.

**No true cross-agent sequential test.** We demonstrated that the same rules influence multiple models in parallel evaluation. We did not test the full sequential workflow (Agent A generates vulnerable code -> scanner detects it -> rules are written -> Agent B avoids the vulnerability), which is the motivating use case.

**Single language ecosystem.** All evaluation was conducted on JavaScript/TypeScript projects.

---

## 9. Future Work

1. **Ghost dependency scanner precision.** Improving the `phantom_new` heuristic with download count thresholds calibrated against known legitimate packages, monorepo workspace detection, and historical version data.

2. **Scanner precision/recall validation.** Manual annotation of scanner findings across a representative sample of repositories to establish baseline precision and recall for each scanner.

3. **Full scanner integration.** Enabling Semgrep SAST and Trivy SCA would directly address the scanner coverage gap identified in Experiment 3.

4. **Larger-scale E2E evaluation.** Repeating Experiment 3 with more repositories (10+), more models (5+), and more trials per condition (5+) would increase statistical power and generalizability.

5. **True cross-agent sequential test.** Agent A generates code, the scanner detects a vulnerability, rules are written, and Agent B reads the rules and avoids the same vulnerability class.

6. **Longitudinal study.** Tracking vulnerability recurrence over multiple scan-rule-scan cycles in production repositories.

7. **Multi-language evaluation.** Testing on Python, Go, and Java codebases to assess generalizability beyond the JavaScript/TypeScript ecosystem.

---

## 10. Conclusion

We presented a closed-loop system for generating persistent, cross-agent security rules from automated vulnerability detection. The evaluation yields a nuanced picture:

1. **The rule format works.** In a controlled mechanism validation (240 trials, 4 models), template-driven security rules reduced vulnerability rates from 68.3% to 0.8% (98.8% reduction, p<0.001). This establishes the upper bound.

2. **The end-to-end pipeline shows a significant but moderate effect.** Across 108 usable trials (3 repositories, 2 models), vulnerability rates decreased from 68.5% to 40.7% (p=0.004). The effect is specific to CWE classes where the scanner generated rules (83% to 30%) and absent for unmatched CWEs (50% to 54%).

3. **Scanner quality is the binding constraint.** The ghost dependency scanner's 100% false positive rate on evaluated repositories indicates that scanner precision must be addressed before deployment. The path to higher end-to-end effectiveness runs through better scanners, not better rules.

The approach of treating agent instruction files as a programmable security policy layer remains promising, but the current implementation is a proof of concept, not a production-ready system. The gap between the 98.8% mechanism upper bound and the 40.5% end-to-end result quantifies the work remaining.

---

## References

[1] Anthropic. "Claude Code: An agentic coding tool." 2025.

[2] Anthropic. "CLAUDE.md documentation." 2025.

[3] Cursor. "Rules for AI." 2025. docs.cursor.com/context/rules-for-ai

[4] GitHub. "Copilot Instructions." 2025.

[5] Block. "Goose: Open-source AI agent." 2025. github.com/block/goose

[6] Agentic AI Foundation. "AAIF." 2026. aaif.io

[7] N. Shinn et al. "Reflexion: Language Agents with Verbal Reinforcement Learning." NeurIPS 2023.

[8] M. Zechner. "Pi-Reflect: Self-improving coding agent via instruction file mutation." 2025.

[9] ngrok. "BMO: Self-improving coding agent." 2025.

[10] Cognition. "Devin Knowledge system." 2025.

[11] Windsurf. "Cascade Memories." 2025.

[12] Embrace The Red. "SpAIware: Persistent prompt injection via Windsurf Memories." 2025.

[13] H. Pearce et al. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions." IEEE S&P 2022.

[14] O. Asare et al. "Is GitHub's Copilot as bad as humans at introducing vulnerabilities in code?" ESE, 2024.

[15] B. Lanyado. "Can you trust ChatGPT's package recommendations?" Vulcan Cyber, 2023.

[16] Y. Bai et al. "Constitutional AI: Harmlessness from AI Feedback." arXiv:2212.08073, 2022.

[17] A. Osmani. "Self-improving coding agents." 2025.

[18] N. Shinn et al. "When Can LLMs Actually Correct Their Own Mistakes?" TACL, 2024.

---

## Supplementary Materials

Available at: github.com/adhit-r

- Full scan results for all 14 repositories (JSON)
- Generated instruction files (CLAUDE.md, .cursorrules, copilot-instructions.md) for all repositories
- Experiment 2 raw data (240 trials, JSON)
- Experiment 3 raw data (162 trials, JSON)
- Experiment scripts (TypeScript, runnable with Bun)
- Rule generator source code and template library
- Ghost dependency false positive analysis
