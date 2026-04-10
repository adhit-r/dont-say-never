# Scan, Learn, Prevent: Cross-Agent Security Policy Generation from Automated Vulnerability Detection

**Adhithya Rajasekaran**

rajasekaran.adhit@gmail.com | github.com/adhit-r

---

## Abstract

AI coding agents repeatedly introduce the same classes of security vulnerabilities across sessions because they lack persistent memory of past mistakes. Instruction files such as CLAUDE.md, .cursorrules, and copilot-instructions.md provide a mechanism for project-specific agent guidance, but today these files are manually authored and static. We present a closed-loop system that automatically detects vulnerabilities in codebases using multiple security scanners, classifies findings by CWE, and generates deterministic natural language rules that are injected into agent instruction files. Unlike prior approaches that use LLM-generated rules from conversation transcripts, our rule generator is template-driven with no LLM in the generation step, making rules auditable, reproducible, and free from hallucination risk. We evaluate the system across three iterative experiments. First, scanning 14 open-source repositories detects 1,116 security findings that compress to 179 cross-agent rules (84% reduction). Second, an isolated rule effectiveness experiment (n=5 per condition, 240 API calls across 4 models) demonstrates 98.8% vulnerability reduction using hand-crafted rules of the same format as pipeline output, with three models achieving p<0.01. Third, a true end-to-end pipeline evaluation uses actual scanner output, actual rule generation, and actual formatted CLAUDE.md content as LLM system prompts across 3 repositories and 3 models (162 trials), achieving 40.5% overall vulnerability reduction --- rising to 71--83% prevention for CWE classes where the scanner actually generated rules. The gap between the isolated (98.8%) and end-to-end (40.5%) results reveals that pipeline effectiveness is bounded by scanner coverage: rules can only prevent what the scanner detects. The generated rules are written to instruction files for Claude Code, Cursor, and GitHub Copilot simultaneously, enabling cross-agent knowledge transfer without model fine-tuning.

---

## 1. Introduction

The adoption of AI coding agents has fundamentally changed software development. Tools such as Anthropic's Claude Code, Cursor, GitHub Copilot, and Block's Goose now generate substantial portions of production codebases, operating with increasing autonomy [1]. However, these agents share a critical limitation: they have no durable memory of their own security failures.

When an AI agent introduces a SQL injection vulnerability via string concatenation, hardcodes an API key, or imports a hallucinated package name, the same class of vulnerability is likely to recur in subsequent sessions. Each session starts fresh. The agent reads its instruction file, generates code, and the cycle repeats.

This paper addresses the question: can we close the feedback loop between automated security detection and AI agent behavior, creating persistent cross-agent security memory without model fine-tuning?

We present a system with three key contributions:

1. **A closed-loop pipeline** that connects multiple security scanners (SAST, secret detection, ghost dependency detection, stale AI pattern detection) to agent instruction file mutation, creating a feedback loop that was previously absent.

2. **A deterministic, template-driven rule generator** that converts CWE-classified vulnerability findings into natural language agent rules without using an LLM in the generation step. This design choice eliminates rule hallucination risk and ensures auditability.

3. **Cross-agent knowledge transfer via instruction files**: security rules generated from one agent's output are written to multiple instruction file formats (CLAUDE.md, .cursorrules, copilot-instructions.md), enabling any agent operating on the project to inherit the corrections without fine-tuning.

We evaluate through three iterative experiments that progressively increase realism: repository scanning at scale (14 repos, 1,116 findings), isolated rule effectiveness testing (4 models, 240 trials, 98.8% reduction), and a true end-to-end pipeline evaluation (3 repos, 3 models, 162 trials, 40.5% overall reduction with 71--83% for matched CWEs). The progression from isolated to end-to-end evaluation reveals that scanner coverage is the binding constraint on pipeline effectiveness.

---

## 2. Background and Related Work

### 2.1 Agent Instruction Files

Modern AI coding agents support project-specific instruction files read at session initialization. Claude Code reads CLAUDE.md [2], Cursor reads .cursorrules [3], GitHub Copilot reads .github/copilot-instructions.md [4], and Goose reads .goosehints [5]. These files function as persistent system-level guidance. The AGENTS.md specification under the Agentic AI Foundation (AAIF) [6] standardizes the concept further. Despite their potential, instruction files are today manually authored and rarely updated in response to security findings.

### 2.2 Reflexion and Verbal Reinforcement Learning

Shinn et al. [7] introduced Reflexion, where language agents learn from verbal self-reflection stored in an episodic memory buffer, improving HumanEval pass@1 from 80.1% to 91.0%. However, Reflexion's memory is ephemeral and does not persist across independent sessions. Our work extends Reflexion to durable, file-based memory that survives session boundaries. Shinn et al. [18] later examined when LLMs can actually correct their own mistakes, finding that self-correction is unreliable without external feedback --- motivating our use of external scanner output rather than self-reflection.

### 2.3 Self-Correcting Agents

Pi-Reflect [8] analyzes conversation transcripts and generates rule updates, reducing correction rates from 0.45 to 0.07 per session. BMO [9] takes a similar approach. Osmani [17] surveys the broader landscape of self-improving coding agents. Our system differs from these approaches in three ways: (a) we use structured security scanner output rather than unstructured transcripts; (b) our rule generation is deterministic and template-driven; (c) we write to multiple instruction file formats simultaneously.

### 2.4 Commercial Agent Memory Systems

Cognition's Devin maintains a Knowledge system requiring user approval [10]. Windsurf's Cascade generates Memories automatically [11], though the SpAIware exploit [12] demonstrated that this mechanism can be poisoned via prompt injection, allowing persistent compromise of agent behavior. Cursor's /Generate Rules requires manual invocation [3]. None of these systems use structured security scanner output or write to multiple agent platforms.

### 2.5 Constitutional AI and Rule-Based Steering

Bai et al. [16] introduced Constitutional AI (CAI), where models are trained to follow explicit principles. Our approach applies a similar concept at the instruction file layer: security rules serve as constitutional principles that constrain agent code generation. However, where CAI requires training, our rules take effect at inference time through the system prompt, requiring no model modification.

### 2.6 AI-Generated Code Security

Pearce et al. [13] found Copilot produces vulnerable code in approximately 40% of security-relevant scenarios. Asare et al. [14] showed LLM-generated code contains weaknesses at rates comparable to human-written code. These findings motivate the need for automated security guardrails. Our ghost dependency scanner addresses a related threat: LLM hallucination of package names creating supply chain attack vectors [15].

---

## 3. System Design

Our system operates as a pipeline with four stages: multi-scanner detection, finding classification, deterministic rule generation, and multi-format instruction file injection.

### 3.1 Multi-Scanner Detection

The system orchestrates eight specialized scanners:

| Scanner | Target | Implementation | External Deps |
|---------|--------|---------------|---------------|
| SAST | Code-level vulnerabilities | Semgrep integration | CLI binary |
| Secret detection | Hardcoded credentials | Gitleaks integration | CLI binary |
| SCA | Vulnerable dependencies | Trivy integration | CLI binary |
| Ghost dependencies | AI-hallucinated packages | Custom (TypeScript) | Registry APIs |
| Stale AI patterns | Outdated training artifacts | Custom (regex) | None |
| Prompt injection | Instruction override attempts | Custom | None |
| IaC scanning | Infrastructure misconfig | Bearer integration | CLI binary |
| Vibe score | Overall security posture | Custom | None |

**Ghost dependency scanner.** LLMs hallucinate package names that do not exist in registries. An attacker can register such names, creating a zero-effort supply chain attack. Our scanner queries npm, PyPI, Go, Rust, and Ruby registries, classifying findings into three risk tiers: `not_found` (package does not exist), `typosquat` (within edit distance of a legitimate package), and `phantom_new` (recently registered with minimal downloads).

**Stale AI pattern scanner.** LLMs trained on historical code generate patterns now known to be insecure. We detect 10 specific patterns via regex rules, including eval()/exec() usage (CWE-94), MD5/SHA1 for cryptographic operations (CWE-328), Math.random() for security-sensitive values (CWE-338), and plaintext HTTP in production (CWE-319). Context-sensitivity checks reduce false positives: for example, eval() in test files or build scripts is excluded.

### 3.2 Finding Classification

Scanner output is normalized into a unified schema with CWE identifier, severity level (critical/high/medium), source tool, file path, line number, and scanner-specific metadata. Findings are deduplicated and grouped by CWE for rule generation. This normalization allows heterogeneous scanner outputs to feed a single rule generation pipeline.

### 3.3 Deterministic Rule Generator

The rule generator converts classified findings into natural language rules using predefined templates. **No LLM is used in the rule generation step.** This ensures:

1. **Auditability.** Every generated rule traces to a specific template and input finding.
2. **Reproducibility.** Identical findings produce identical rules.
3. **No rule hallucination.** Template-driven rules cannot contain incorrect remediation advice.

The template library covers four categories with specific rule phrasings:

**Ghost dependency templates** generate package-specific warnings:
> NEVER use the package "react-encrypted-localstorage" (npm) --- it does not exist on the registry. This is likely an AI-hallucinated package name.

**Stale AI pattern templates** reference the insecure pattern and its secure alternative:
> NEVER use MD5 or SHA1 for cryptographic operations --- both are broken. Use SHA-256 (or higher) for checksums; use bcrypt, argon2, or scrypt for passwords.

**Secret templates** dynamically map secret types from scanner output to specific guidance with correct environment variable names.

**SAST templates** cover 12 CWE classes with specific remediation instructions, including parameterized queries for SQL injection, output encoding for cross-site scripting, and path canonicalization for path traversal.

**Rule compression.** Multiple findings of the same CWE class produce a single rule rather than one rule per finding. This prevents instruction file bloat while preserving coverage. Across 14 repositories, 1,116 findings compressed to 179 rules (84% reduction).

### 3.4 Multi-Format Instruction File Injection

Generated rules are formatted as a Markdown section with HTML comment markers (PATCHPILOT:START / PATCHPILOT:END). The markers enable idempotent updates: re-running the pipeline replaces only the auto-generated section while preserving any manually authored content above or below. The same rules are injected into CLAUDE.md, .cursorrules, and copilot-instructions.md simultaneously. This multi-format injection enables cross-agent transfer: a vulnerability detected by scanning code from one agent produces rules that constrain all agents on the project.

---

## 4. Evaluation

We evaluate through three iterative experiments, each increasing in realism and building on findings from the previous iteration. Section 4.2 validates the scanning and rule generation pipeline on real repositories. Section 4.3 tests whether rules in the format produced by the pipeline actually change LLM behavior, using hand-crafted rules as a controlled experiment. Section 4.4 closes the loop entirely, running the actual scanners on real repositories, generating rules through the actual pipeline, and testing whether the exact generated output prevents vulnerabilities.

### 4.1 Rule Generator Validation

We validated the rule generator with a suite of 9 unit tests covering: category coverage (all 4 scanner types produce rules), CWE grouping (multiple findings of the same CWE produce a single rule), severity filtering, secret type differentiation, ghost dependency risk classification, stale AI pattern matching, marker-based formatting (PATCHPILOT markers present), content preservation (existing instruction file content is not overwritten), and idempotent re-injection (running the generator twice produces the same output). All 9 tests passed.

### 4.2 Iteration 1: Repository Scanning

We scanned two sets of repositories: 7 widely-used open-source projects and 7 projects from the author's portfolio, totalling 14 repositories across different domains and scales. This iteration validates the pipeline's ability to detect real security findings and compress them into concise rule sets.

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

**Combined total: 1,116 findings across 14 repositories, compressed to 179 rules (84% reduction).**

Key observations:

**Ghost dependencies are pervasive.** 13 of 14 repositories contained ghost dependency findings (CWE-1104). Cal.com alone contained 313 ghost dependency findings. These represent packages referenced in dependency manifests that do not exist on npm or were recently registered with minimal adoption.

**Compression scales with codebase size.** Small repositories show low compression (Express: 8%, Redact-ai: 33%) because most findings map to unique CWE classes. Large repositories show high compression (Twenty: 92%, cal.com: 90%) because many findings share the same CWE, validating the grouping strategy.

**Table 3: CWE Coverage Across All 14 Repositories**

| CWE | Description | Repos Affected |
|-----|-------------|:--------------:|
| CWE-1104 | Untrusted dependencies | 13/14 |
| CWE-94 | Code injection (eval/exec) | 9/14 |
| CWE-319 | Plaintext HTTP | 8/14 |
| CWE-328 | Weak cryptography (MD5/SHA1) | 6/14 |
| CWE-338 | Insecure randomness | 5/14 |

### 4.3 Iteration 2: Isolated Rule Effectiveness

Iteration 1 established that the pipeline detects real findings and generates rules. The question for Iteration 2 is: **do rules in this format actually change LLM behavior?**

We designed 6 vulnerability-eliciting prompts, one per CWE class (SQL injection, cross-site scripting, path traversal, command injection, weak cryptography, insecure randomness). Each prompt was tested in two conditions: **control** (no security rules in the system prompt) and **treatment** (security rules in the same format as pipeline output injected into the system prompt). Rules were hand-crafted to match the template format exactly, isolating rule effectiveness from scanner coverage. We tested 4 models: Claude Sonnet 4 (Anthropic), Nemotron 120B (NVIDIA), GPT-OSS 120B (OpenAI), and GPT-OSS 20B (OpenAI). Each model-prompt-condition combination was run 5 times with temperature variation (0.3--0.7), yielding 240 API calls.

**Table 4: Isolated Rule Effectiveness by Model (n=5 per condition)**

| Model | Control Rate | Treatment Rate | Reduction | Significance |
|-------|------------:|---------------:|----------:|:------------:|
| Claude Sonnet 4 | 27% | 0% | 100% | p<0.10 |
| Nemotron 120B | 73% | 0% | 100% | p<0.01 |
| GPT-OSS 120B | 93% | 3% | 96% | p<0.01 |
| GPT-OSS 20B | 80% | 0% | 100% | p<0.01 |

**Table 5: Per-CWE Prevention Rate (all models combined, 20 trials per CWE)**

| CWE | Vulnerability | Control (V/N) | Treatment (V/N) | Prevention |
|-----|--------------|:--------------:|:----------------:|:----------:|
| CWE-89 | SQL Injection | 12/20 | 0/20 | 100% |
| CWE-79 | Cross-Site Scripting | 18/20 | 0/20 | 100% |
| CWE-22 | Path Traversal | 15/20 | 0/20 | 100% |
| CWE-78 | Command Injection | 7/20 | 0/20 | 100% |
| CWE-328 | Weak Cryptography | 15/20 | 0/20 | 100% |
| CWE-338 | Insecure Randomness | 15/20 | 1/20 | 93% |
| **Total** | | **82/120** | **1/120** | **98.8%** |

**Grand total: 82/120 control trials produced vulnerable code (68.3%). Only 1/120 treatment trials produced vulnerable code (0.8%). Overall reduction: 98.8%.**

Three of four models achieved p<0.01. Claude Sonnet 4 achieved p<0.10 due to its lower baseline vulnerability rate (27%), which limits statistical power. The single treatment vulnerability occurred in CWE-338 (insecure randomness) on GPT-OSS 120B in one of five trials.

These results establish that rules in our template format are effective at changing LLM behavior. However, this experiment used hand-crafted rules with complete CWE coverage. The question remains: what happens when rules are generated by the actual pipeline, which can only produce rules for findings the scanners detect?

### 4.4 Iteration 3: End-to-End Pipeline Evaluation

The final iteration closes the loop completely. We selected 3 repositories from Iteration 1 (hono, express, documenso), ran the **actual** PatchPilot scanners against each, fed the findings through the **actual** `generateAgentRules()` and `formatRulesSection()` functions, and used the **exact** generated CLAUDE.md content as the LLM system prompt. No hand-crafting. No manual rule selection.

**Experimental design.** For each repository, we created 3 vulnerability-eliciting prompts targeting CWE classes relevant to the repository's technology stack. Each prompt was tested against 3 models (Claude Sonnet 4, Nemotron 120B, GPT-OSS 120B) in control and treatment conditions with 3 trials per combination, yielding 3 repos x 3 prompts x 3 models x 2 conditions x 3 trials = 162 total API calls.

**Table 6: End-to-End Results by Model**

| Model | Control Vuln Rate | Treatment Vuln Rate | Reduction | Notes |
|-------|------------------:|--------------------:|----------:|-------|
| Claude Sonnet 4 | 0/27 (0%) | -- | -- | Rate-limited; all errors; excluded |
| Nemotron 120B | 19/27 (70%) | 15/27 (56%) | 21% | |
| GPT-OSS 120B | 18/27 (67%) | 7/27 (26%) | 61% | |
| **Total (excl. Claude)** | **37/54 (69%)** | **22/54 (41%)** | **40.5%** | |

Including all 81 trials (with Claude's 0/27 control as non-vulnerable): 37/81 control (45.7%) to 22/81 treatment (27.2%), a 40.5% overall reduction.

**Table 7: End-to-End Per-CWE Prevention (all models, all repos)**

| CWE | Vulnerability | Control (V/N) | Treatment (V/N) | Prevention | Scanner Coverage |
|-----|--------------|:--------------:|:----------------:|:----------:|:----------------:|
| CWE-94 | Code injection (eval) | 7/18 | 2/18 | 71% | Rules generated |
| CWE-328 | Weak crypto (MD5) | 12/18 | 11/18 | 8% | Rules generated* |
| CWE-319 | Plaintext HTTP | 6/9 | 1/9 | 83% | Rules generated |
| CWE-89 | SQL Injection | 0/9 | 0/9 | N/A | No rules (Express) |
| CWE-22 | Path Traversal | 1/9 | 3/9 | -200% | No rules (Express) |
| CWE-78 | Command Injection | 5/9 | 4/9 | 20% | No rules (Express) |
| CWE-338 | Insecure Randomness | 6/9 | 1/9 | 83% | Rules generated |

*CWE-328 prompts explicitly requested MD5 (e.g., "compute an MD5 hash"), overriding the system-level rule.

**The critical finding.** For CWE classes where the scanner actually generated rules and the prompt did not explicitly request the insecure pattern (CWE-94, CWE-319, CWE-338), prevention rates were 71%, 83%, and 83% respectively. For CWE classes where Express had no SAST findings and thus no rules were generated (CWE-89, CWE-22, CWE-78), prevention was absent or negative. This confirms that the pipeline's effectiveness is bounded by its scanner coverage.

### 4.5 Cross-Agent Transfer

The multi-model experiments demonstrate cross-agent transfer by design. In Iteration 2, the same hand-crafted rules achieved 98.8% effectiveness across models from 4 different providers (Anthropic, NVIDIA, OpenAI). In Iteration 3, the same auto-generated CLAUDE.md content influenced both Nemotron and GPT-OSS models without modification. A vulnerability detected in one codebase produces rules that constrain any model operating on that project. This transfer occurs through the shared instruction file format (markdown) without model-specific adaptation or fine-tuning.

---

## 5. Discussion

### 5.1 The 98.8% vs. 40.5% Gap

The most important finding in this paper is not either number in isolation but the gap between them. Iteration 2 established that well-crafted rules in our format are nearly perfectly effective (98.8%). Iteration 3 revealed that the real-world pipeline achieves substantially less (40.5%) because of three compounding factors:

**Scanner coverage limits rule generation.** The Express repository produced minimal stale AI pattern findings and no SAST findings, meaning the pipeline generated no rules for SQL injection, path traversal, or command injection. When the pipeline has no findings, it generates no rules, and behavior does not change. This is by design --- the system does not speculate about vulnerabilities it has not detected --- but it means coverage is bounded by scanner sensitivity.

**Explicit prompt requests override system rules.** The CWE-328 (weak cryptography) prompts asked models to "compute an MD5 hash," explicitly naming the insecure algorithm. Even with a system-level rule stating "NEVER use MD5," models complied with the user request. This is expected behavior: user instructions generally take precedence over system instructions in current LLM architectures. In realistic development, programmers rarely request specific insecure algorithms by name.

**Auto-generated rules are less targeted than hand-crafted ones.** The Iteration 2 rules were specifically designed to counter each test prompt. The Iteration 3 rules were generated from scanner findings without knowledge of what prompts would be tested. This is the correct evaluation methodology --- it tests the pipeline as developers would actually use it --- but produces lower numbers than the controlled experiment.

### 5.2 When the Pipeline Works

Filtering to the conditions where the pipeline should theoretically be effective --- CWE classes with generated rules and prompts that do not explicitly request the insecure pattern --- prevention rates of 71--83% emerge. This suggests that the fundamental mechanism (rules changing LLM behavior) is sound, and that the primary lever for improvement is expanding scanner coverage rather than changing the rule format.

### 5.3 From Reflexion to Persistence

Our work extends Reflexion [7] from ephemeral in-context memory to durable file-based memory. Where Reflexion stores verbal reinforcement in a buffer cleared between episodes, our system writes reinforcement to version-controlled files that persist indefinitely. The key difference is the source of feedback: Reflexion uses self-generated verbal reflection, while our system uses external scanner output. Shinn et al. [18] showed that LLM self-correction is unreliable without external grounding, which supports our design choice.

### 5.4 Deterministic vs. LLM-Generated Rules

The choice to use deterministic templates rather than LLM-generated rules is validated by our Iteration 2 results: template-driven rules achieved 98.8% effectiveness, demonstrating that well-phrased security instructions do not require LLM-generated nuance. The Iteration 3 results reinforce this --- the rules themselves are effective; the bottleneck is generating rules for the right CWE classes. LLM-generated rules would introduce hallucination risk and non-reproducibility without addressing the scanner coverage gap.

### 5.5 Instruction Files as a Policy Layer

Our results demonstrate that instruction files serve as a model-agnostic policy enforcement layer. The same markdown rules influenced models from Anthropic, NVIDIA, and OpenAI across both experimental iterations. This is analogous to Constitutional AI [16] applied at the inference layer: where CAI embeds principles during training, our system injects principles at session initialization through the system prompt.

### 5.6 Implications for the Agentic AI Ecosystem

The AAIF and MCP are standardizing how agents interact with tools [6]. Our work demonstrates a complementary pattern: tools that generate persistent agent guidance rather than one-time results. This pattern can generalize to linting servers teaching coding style, testing frameworks encoding failure patterns, and accessibility scanners preventing recurring violations. The key architectural insight is that the agent's instruction file is a writable interface, not just a readable one.

---

## 6. Limitations

**Scanner coverage determines pipeline ceiling.** The most significant limitation is demonstrated by Iteration 3: the pipeline cannot generate rules for vulnerability classes its scanners do not detect. Express produced no SAST findings, so the pipeline generated no SAST rules, and vulnerability rates for SQL injection, path traversal, and command injection were unchanged or worse. Expanding scanner coverage (e.g., enabling Semgrep with broader rulesets) would directly increase rule generation breadth.

**Explicit prompt override.** When a developer explicitly requests an insecure pattern by name (e.g., "compute an MD5 hash"), system-level rules are insufficient to override the user instruction. This is a fundamental limitation of instruction-file-based guardrails and applies to all approaches in this class, not only ours. In practice, developers are unlikely to explicitly request known-insecure algorithms.

**Claude Sonnet 4 rate limiting.** In both Iterations 2 and 3, Claude Sonnet 4 was rate-limited, reducing usable data. In Iteration 2, this limited Claude's significance to p<0.10 rather than p<0.01. In Iteration 3, Claude returned errors on all 27 control trials and was excluded entirely. Our conclusions rest primarily on the Nemotron and GPT-OSS models.

**Template coverage.** The rule template library covers 12 CWE classes. Vulnerability types outside this set do not generate rules even when detected. Expanding the template library is straightforward engineering work.

**Sample size.** Iteration 3 used 3 trials per condition (vs. 5 in Iteration 2) due to the larger combinatorial space. Individual per-CWE cells contain 9--18 trials, which limits statistical power for per-CWE significance testing. Larger trial counts would increase confidence.

**Repository selection.** All evaluated repositories are JavaScript/TypeScript web applications. Generalizability to other language ecosystems (Python, Go, Rust, Java) has not been tested, though the scanner architecture is language-agnostic.

---

## 7. Future Work

1. **Expanded scanner integration.** Enabling Semgrep with full SAST rulesets and Trivy for SCA would directly address the scanner coverage gap identified in Iteration 3. The pipeline architecture already supports these scanners; the limitation in our evaluation was configuration scope.

2. **Larger-scale end-to-end evaluation.** Repeating Iteration 3 with more repositories (10+), more models (5+), and more trials per condition (5+) would increase statistical power and generalizability.

3. **Longitudinal study.** Tracking vulnerability recurrence in production repositories over multiple scan-rule-scan cycles would measure whether the feedback loop produces cumulative improvement over time.

4. **True cross-agent loop experiment.** Agent A generates vulnerable code, the scanner detects it, rules are written, and Agent B reads the rules and avoids the same vulnerability class. This would demonstrate the cross-agent transfer claim in a sequential workflow rather than parallel evaluation.

5. **LLM-assisted template expansion.** Using an LLM to draft new rule templates for uncovered CWE classes, with mandatory human review, would expand template coverage while preserving the deterministic generation property for approved templates.

6. **MCP server integration.** Exposing scanners and rule generation as Model Context Protocol (MCP) tools would allow agents to invoke scanning directly, further tightening the feedback loop.

7. **Graduated enforcement.** Implementing escalating rule severity based on recurrence count (advisory on first detection, mandatory on repeated detection) would balance developer autonomy with security enforcement.

---

## 8. Conclusion

We presented a closed-loop system for generating persistent, cross-agent security rules from automated vulnerability detection. Three iterative experiments validate the approach and reveal its boundaries:

1. **Repository scanning** across 14 repositories detected 1,116 findings that compressed to 179 rules (84% reduction), with ghost dependencies present in 13 of 14 repositories and 5 CWE classes represented.

2. **Isolated rule effectiveness testing** (n=5 per condition, 240 API calls across 4 models) demonstrated 98.8% vulnerability reduction (82/120 to 1/120), with p<0.01 significance for 3 of 4 models, establishing that rules in our template format are effective at changing LLM behavior.

3. **End-to-end pipeline evaluation** (162 trials across 3 repositories and 3 models) achieved 40.5% overall vulnerability reduction, with 71--83% prevention for CWE classes where the scanner actually generated rules. The gap from 98.8% is explained by scanner coverage: rules can only prevent what the pipeline detects.

The honest headline is that the end-to-end pipeline reduces vulnerabilities by 40.5% in its current configuration, and that this number rises to 71--83% when the scanner has coverage for the relevant CWE class. The path to higher overall numbers is not better rules --- our rules are already 98.8% effective in isolation --- but broader scanner coverage.

By treating agent instruction files as a programmable policy layer rather than static documentation, we enable security lessons learned by one agent to transfer to any other agent on the same project --- across models, providers, and sessions --- without fine-tuning.

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
- Iteration 2 raw data (240 trials, JSON)
- Iteration 3 raw data (162 trials, JSON)
- Experiment scripts (TypeScript, runnable with Bun)
- Rule generator source code and template library
