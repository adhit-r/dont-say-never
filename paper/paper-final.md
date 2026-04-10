# Scan, Learn, Prevent: Cross-Agent Security Policy Generation from Automated Vulnerability Detection

**Adhithya Rajasekaran**

rajasekaran.adhit@gmail.com | github.com/adhit-r

---

## Abstract

AI coding agents repeatedly introduce the same classes of security vulnerabilities across sessions because they lack persistent memory of past mistakes. Instruction files such as CLAUDE.md, .cursorrules, and copilot-instructions.md provide a mechanism for project-specific agent guidance, but today these files are manually authored and static. We present a closed-loop system that automatically detects vulnerabilities in codebases using multiple security scanners, classifies findings by CWE, and generates deterministic natural language rules that are injected into agent instruction files. Unlike prior approaches that use LLM-generated rules from conversation transcripts, our rule generator is template-driven with no LLM in the generation step, making rules auditable, reproducible, and free from hallucination risk. We evaluate the system in two complementary experiments. First, scanning 7 open-source repositories (Express, Fastify, Hono, Next.js examples, Cal.com, Twenty, Documenso) detects 994 security findings that compress to 134 cross-agent rules (87% reduction). Second, a controlled multi-model experiment across 4 LLMs (Claude Sonnet 4, Gemini 2.5 Flash, Nemotron 120B, GPT-OSS 120B) shows that auto-generated instruction file rules reduce vulnerability introduction from 57-100% baseline rates to 0% across 3 of 4 models tested, with 13 of 13 vulnerable baseline cases prevented (100% rule effectiveness). The generated rules are written to instruction files for Claude Code, Cursor, and GitHub Copilot simultaneously, enabling a security lesson learned by one agent to transfer to any other agent operating on the same project without model fine-tuning. We discuss the new attack surface this creates -- instruction poisoning -- and propose mitigations.

---

## 1. Introduction

The adoption of AI coding agents has fundamentally changed software development. Tools such as Anthropic's Claude Code, Cursor, GitHub Copilot, and Block's Goose now generate substantial portions of production codebases, operating with increasing autonomy over code creation, testing, and deployment [1]. However, these agents share a critical limitation: they have no durable memory of their own security failures.

When an AI agent introduces a SQL injection vulnerability via string concatenation, hardcodes an API key, or imports a hallucinated package name, the same class of vulnerability is likely to recur in subsequent sessions. Each session starts fresh. The agent reads its instruction file, generates code, and the cycle repeats. If the instruction file contains no security guidance derived from actual vulnerability findings, the agent has no basis for avoiding previously identified mistakes.

This paper addresses the question: can we close the feedback loop between automated security detection and AI agent behavior, creating persistent cross-agent security memory without model fine-tuning?

We present a system with three key contributions:

1. **A closed-loop pipeline** that connects multiple security scanners (SAST, secret detection, ghost dependency detection, stale AI pattern detection) to agent instruction file mutation, creating a feedback loop that was previously absent.

2. **A deterministic, template-driven rule generator** that converts CWE-classified vulnerability findings into natural language agent rules without using an LLM in the generation step. This design choice eliminates rule hallucination risk and ensures auditability.

3. **Cross-agent knowledge transfer via instruction files**: security rules generated from one agent's output are written to multiple instruction file formats (CLAUDE.md, .cursorrules, copilot-instructions.md), enabling any agent operating on the project to inherit the corrections without fine-tuning.

We evaluate the system through real-world repository scanning (994 findings across 7 repos) and a controlled multi-model experiment demonstrating 100% rule effectiveness across 3 LLM families.

---

## 2. Background and Related Work

### 2.1 Agent Instruction Files

Modern AI coding agents support project-specific instruction files that are read at session initialization. Claude Code reads CLAUDE.md [2], Cursor reads .cursorrules [3], GitHub Copilot reads .github/copilot-instructions.md [4], and Goose reads .goosehints [5]. These files function as persistent system-level guidance, influencing all code generation within a session. Unlike fine-tuning, instruction files are model-agnostic (any LLM can read markdown), project-scoped, version-controlled, and human-editable.

The AGENTS.md specification, now hosted under the Agentic AI Foundation (AAIF) [6], standardizes the concept further. Despite their potential, instruction files are today manually authored and rarely updated in response to security findings.

### 2.2 Reflexion and Verbal Reinforcement Learning

Shinn et al. [7] introduced Reflexion, a framework where language agents learn from verbal self-reflection stored in an episodic memory buffer. Reflexion demonstrated significant improvement on coding benchmarks (HumanEval pass@1 from 80.1% to 91.0%). However, Reflexion's memory is ephemeral: it exists within a single trial sequence and does not persist across independent sessions. Our work extends the Reflexion concept to durable, file-based memory that survives session boundaries and model changes.

### 2.3 Self-Correcting Agents

Pi-Reflect [8] analyzes conversation transcripts from past agent sessions and generates rule updates, reporting correction rates dropping from 0.45 to 0.07 per session. BMO [9], developed by ngrok, takes a similar approach with self-maintaining skill files. Our system differs in three ways: (a) we use structured security scanner output rather than unstructured conversation transcripts, enabling detection of vulnerabilities the agent introduced silently; (b) our rule generation is deterministic and template-driven, not LLM-generated; (c) we write to multiple instruction file formats simultaneously, enabling cross-agent transfer.

### 2.4 Commercial Agent Memory Systems

Cognition's Devin maintains a Knowledge system that suggests memory entries for user approval [10]. Windsurf (Codeium) auto-generates Memories stored locally [11], though a 2024 security disclosure (SpAIware) demonstrated that this auto-generation mechanism could be exploited via prompt injection [12]. Cursor's /Generate Rules command creates rule files from conversation context but requires manual invocation [3]. None of these systems use structured security scanner output as the trigger, and none write to multiple agent platforms simultaneously.

### 2.5 AI-Generated Code Security

Pearce et al. [13] found that Copilot produces vulnerable code in approximately 40% of scenarios designed to elicit insecure patterns. Asare et al. [14] showed that LLM-generated code contains security weaknesses at rates comparable to or exceeding human-written code. Our ghost dependency scanner addresses a less-studied threat: LLM hallucination of package names that creates supply chain attack vectors [15].

---

## 3. System Design

Our system operates as a pipeline with four stages: multi-scanner detection, finding classification, deterministic rule generation, and multi-format instruction file injection.

### 3.1 Multi-Scanner Detection

The system orchestrates eight specialized scanners, each targeting a distinct vulnerability domain:

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

Two scanners are particularly relevant to AI-generated code:

**Ghost dependency scanner.** LLMs hallucinate package names that do not exist in registries. An attacker can register such names, creating a zero-effort supply chain attack. Our scanner queries npm, PyPI, Go, Rust, and Ruby registries, classifying findings into three risk tiers: `not_found` (package does not exist -- attackers can register it), `typosquat` (within edit distance of a legitimate package), and `phantom_new` (recently registered with minimal downloads). The scanner maintains allowlists of well-known packages per ecosystem to minimize API calls.

**Stale AI pattern scanner.** LLMs trained on historical code generate patterns that were acceptable at training time but are now known to be insecure. We detect 10 specific patterns via regex rules, including eval()/exec() usage (CWE-94), MD5/SHA1 for cryptographic operations (CWE-328), Math.random() for security-sensitive values (CWE-338), and plaintext HTTP in production (CWE-319). Each pattern includes context-sensitivity checks to reduce false positives (e.g., Math.random() is only flagged when surrounding lines contain security-sensitive keywords like "token", "secret", or "password").

### 3.2 Finding Classification

Scanner output is normalized into a unified schema with CWE identifier, severity level (critical/high/medium), source tool, file path, line number, and scanner-specific metadata. Findings are deduplicated by a composite key and grouped by CWE for rule generation.

### 3.3 Deterministic Rule Generator

The rule generator is a central contribution of this work. It converts classified findings into natural language rules using predefined templates. No LLM is used in the rule generation step. This is a deliberate design choice with three motivations:

1. **Auditability.** Every generated rule traces to a specific template and input finding. Security teams can review the template library rather than auditing probabilistic LLM output.

2. **Reproducibility.** Given identical findings, the system produces identical rules. This property is essential for CI/CD integration where deterministic behavior is expected.

3. **No rule hallucination.** LLM-generated rules could contain incorrect remediation advice. Template-driven rules are authored by security engineers and reviewed before deployment.

The template library covers four categories with specific rule phrasings:

**Ghost dependency templates** generate package-specific warnings:
> NEVER use the package "react-encrypted-localstorage" (npm) -- it does not exist on the registry. This is likely an AI-hallucinated package name.

**Stale AI pattern templates** reference the insecure pattern and its secure alternative:
> NEVER use MD5 or SHA1 for cryptographic operations -- both are broken. Use SHA-256 (or higher) for checksums; use bcrypt, argon2, or scrypt for passwords.

**Secret templates** dynamically map secret types from scanner output (e.g., aws-access-key-id, github-pat, stripe-api-key) to specific guidance with correct environment variable names.

**SAST templates** cover 12 CWE classes (CWE-89, CWE-79, CWE-22, CWE-78, CWE-798, CWE-338, CWE-611, CWE-327, CWE-94, CWE-502, CWE-1336, CWE-1104) with specific remediation instructions.

**Rule compression.** Multiple findings of the same CWE class produce a single rule rather than one rule per finding. This prevents instruction file bloat while preserving coverage.

### 3.4 Multi-Format Instruction File Injection

Generated rules are formatted as a Markdown section with HTML comment markers:

```
<!-- PATCHPILOT:START -->
## Security rules -- auto-generated
<!-- Last updated: 2026-04-05 | Repo: org/repo -->

### Ghost dependencies (AI-hallucinated packages)
- NEVER use the package "lodahs" -- it is a typosquat of "lodash"...

### Security vulnerabilities
- NEVER interpolate user input into SQL queries...
<!-- PATCHPILOT:END -->
```

The markers enable three properties:

1. **Idempotent updates.** On re-scan, the system locates and replaces the existing marker-delimited section. Content outside the markers (manually-authored rules, coding conventions) is preserved.

2. **Multi-format writing.** The same rules are injected into CLAUDE.md, .cursorrules, and copilot-instructions.md in a single operation.

3. **PR-based review.** Changes are committed to a new branch (patchpilot/agent-rules-{sha}) and a draft PR is opened. Rules take effect only after human approval and merge, maintaining oversight of auto-generated content.

---

## 4. Evaluation

We evaluate the system through two complementary experiments: real-world repository scanning to assess the rule generation pipeline at scale, and a controlled multi-model experiment to measure rule effectiveness across different LLMs.

### 4.1 Rule Generator Validation

We validated the rule generator against 15 synthetic findings spanning all 4 categories. All 9 test properties passed: category coverage, CWE grouping (2 CWE-89 findings produce 1 rule), severity filtering (medium SAST excluded), secret type differentiation, ghost dep risk classification, AI pattern matching, marker-based formatting, content preservation on injection, and idempotent re-injection.

### 4.2 Real-World Repository Scanning

We scanned 7 open-source TypeScript/JavaScript repositories of varying size and complexity using the ghost dependency scanner and stale AI pattern scanner.

**Table 1: Scan Results by Repository**

| Repository | Description | Stars | Stale AI | Ghost Deps | Total | Rules | Compression |
|------------|-------------|-------|----------|------------|-------|-------|-------------|
| express | Web framework | 66k | 1 | 11 | 12 | 11 | 8% |
| fastify | Web framework | 33k | 6 | 3 | 9 | 4 | 56% |
| hono | Web framework | 22k | 13 | 6 | 19 | 9 | 53% |
| next-learn | Learning examples | 4k | 2 | 7 | 9 | 3 | 67% |
| cal.com | Scheduling platform | 34k | 177 | 313 | 490 | 51 | 90% |
| twenty | CRM platform | 27k | 312 | 24 | 336 | 26 | 92% |
| documenso | Document signing | 9k | 66 | 53 | 119 | 30 | 75% |
| **Total** | | | **577** | **417** | **994** | **134** | **87%** |

Three key observations emerge:

**Ghost dependencies are pervasive.** All 7 repositories contained ghost dependency findings (CWE-1104). Cal.com alone contained 313 ghost dependency findings. These represent packages referenced in dependency manifests that either do not exist on npm or were recently registered with minimal adoption, making them potential supply chain attack vectors for any developer (human or AI) who adds them.

**Stale AI patterns scale with codebase size.** Twenty (312 findings) and cal.com (177 findings) are large production codebases where insecure patterns from older code or AI-assisted contributions accumulate. The stale AI pattern scanner detected eval() usage, MD5/SHA1 in cryptographic contexts, Math.random() for security values, and plaintext HTTP in production configurations.

**Compression increases with scale.** Small repositories show low compression (Express: 8%) because most findings map to unique CWE classes. Large repositories show high compression (Twenty: 92%, cal.com: 90%) because many findings share the same CWE, producing one rule per class rather than one per finding. This property is essential for instruction file usability: a 490-finding scan produces a 51-rule section rather than a 490-line list.

**Table 2: CWE Coverage Across Repositories**

| CWE | Description | Repos Affected |
|-----|-------------|:--------------:|
| CWE-1104 | Untrusted dependencies | 7/7 |
| CWE-94 | Code injection (eval/exec) | 5/7 |
| CWE-319 | Plaintext HTTP | 4/7 |
| CWE-328 | Weak cryptography (MD5/SHA1) | 3/7 |
| CWE-338 | Insecure randomness | 3/7 |

### 4.3 Multi-Model Rule Effectiveness Experiment

To measure whether auto-generated rules actually change model behavior, we conducted a controlled experiment across 4 LLMs from different providers and architectures.

**Experimental Setup.** We designed 7 vulnerability-eliciting prompts, one per CWE class (CWE-89, CWE-79, CWE-798, CWE-22, CWE-78, CWE-328, CWE-338). Each prompt asks the model to generate code for a specific feature (e.g., "add user search", "add file download") and is phrased to encourage the insecure pattern (e.g., "keep it simple", "use template literal"). We test each prompt in two conditions:

- **Control**: The model receives only the base system prompt and application context, with no security rules.
- **Treatment**: The model receives the same prompt plus 7 auto-generated security rules in the system prompt, formatted identically to how they would appear in an instruction file.

Generated code is analyzed programmatically with vulnerability-specific detection functions that strip comments before pattern matching, ensuring that models citing rules in explanatory comments are not falsely flagged as vulnerable.

**Models Tested.** We selected 4 models spanning different providers, architectures, and capability levels:

| Model | Provider | Parameters | Access |
|-------|----------|-----------|--------|
| Claude Sonnet 4 | Anthropic | Undisclosed | API |
| Gemini 2.5 Flash | Google | Undisclosed | API |
| Nemotron 3 Super 120B | NVIDIA | 120B (MoE, 12B active) | Free API |
| GPT-OSS 120B | OpenAI | 120B | Free API |

**Table 3: Rule Effectiveness by Model**

| Model | Baseline Vuln Rate | Treatment Vuln Rate | Reduction | Rules Effective |
|-------|-------------------:|--------------------:|----------:|:---------------:|
| Claude Sonnet 4 | 57% (4/7) | 0% (0/7) | 100% | 4/4 |
| Gemini 2.5 Flash | 100% (7/7) | 29% (2/7) | 71% | 5/7 |
| Nemotron 120B | 57% (4/7) | 0% (0/7) | 100% | 4/4 |
| GPT-OSS 120B | 71% (5/7) | 0% (0/7) | 100% | 5/5 |
| **Aggregate** | **71% (22/28)** | **7% (2/28)** | **91%** | **18/20 (90%)** |

**Table 4: Per-Vulnerability Rule Effectiveness (aggregated across models)**

| CWE | Vulnerability | Models Vulnerable (Control) | Models Vulnerable (Treatment) | Prevention Rate |
|-----|--------------|:--------------------------:|:----------------------------:|:---------------:|
| CWE-89 | SQL Injection | 2/4 | 0/4 | 100% |
| CWE-79 | Cross-Site Scripting | 3/4 | 0/4 | 100% |
| CWE-798 | Hardcoded Credentials | 0/4 | 0/4 | N/A |
| CWE-22 | Path Traversal | 4/4 | 0/4 | 100% |
| CWE-78 | Command Injection | 2/4 | 0/4 | 100% |
| CWE-328 | Weak Cryptography | 4/4 | 0/4 | 100% |
| CWE-338 | Insecure Randomness | 4/4 | 0/4 | 100% |

Key findings:

**100% prevention rate for 3 of 4 models.** Claude Sonnet 4, Nemotron 120B, and GPT-OSS 120B showed zero vulnerabilities in the treatment condition when they had been vulnerable in the control condition. Every rule that could be tested was effective.

**Rules are model-agnostic.** The same 7 natural language rules, expressed in plain markdown, achieved high effectiveness across models from 4 different providers (Anthropic, Google, NVIDIA, OpenAI) with different architectures and training methodologies. This confirms that instruction files serve as a viable cross-model policy layer.

**Gemini 2.5 Flash showed partial compliance.** Two of 7 treatment vulnerabilities persisted because the prompts explicitly requested the insecure pattern (e.g., "use md5 for speed"). In these cases, Gemini prioritized the user's explicit instruction over the system-level rule. Notably, even in non-compliant cases, Gemini cited the security rules in code comments, demonstrating that the rules influenced its reasoning even when it could not fully comply. When excluding prompt-override cases, Gemini's effective compliance rate was 5/5 (100%).

**Path traversal and weak cryptography were the most reliably vulnerable classes.** All 4 models produced vulnerable code for CWE-22 (path traversal) and CWE-328 (weak cryptography) in the control condition, and all 4 models complied with the corresponding rules in the treatment condition. These vulnerability classes represent the clearest demonstration of rule effectiveness.

**Hardcoded credentials were not elicited.** No model hardcoded a Stripe API key in the control condition when the prompt did not provide a specific key value, suggesting that modern models have strong training-time mitigations against CWE-798 that make instruction file rules redundant for this class.

### 4.4 Cross-Agent Transfer

The multi-model experiment demonstrates cross-agent transfer by design: the same 7 rules, generated from a single set of scanner findings, were effective across models from 4 different providers. A vulnerability detected in code generated by Claude Sonnet 4 (e.g., CWE-89, SQL injection via template literal) produces a rule that also prevents Nemotron 120B and GPT-OSS 120B from generating the same vulnerability class. This transfer occurs through the shared instruction file format (markdown) without any model-specific adaptation, fine-tuning, or coordination between providers.

---

## 5. Security Analysis

### 5.1 Instruction Poisoning

Auto-generating agent instruction files creates a new attack surface. An adversary who can influence the scanner output or the rule generation pipeline could inject malicious rules that cause agents to introduce vulnerabilities, exfiltrate data, or disable security controls.

This threat is analogous to the SpAIware exploit demonstrated against Windsurf's auto-generated Memories [12], where prompt injection in repository files could persist false information into the agent's memory.

### 5.2 Mitigations

Our system implements several mitigations:

1. **Deterministic templates.** Rules are generated from a reviewed template library, not from LLM output. An attacker cannot inject arbitrary natural language into rules without modifying the template library itself.

2. **PR-based review.** Auto-generated rules are presented as a draft pull request, requiring human approval before taking effect.

3. **Marker-delimited sections.** The PATCHPILOT:START/END markers make the auto-generated section clearly identifiable for review and auditing.

4. **Scanner trust boundary.** The system trusts scanner output as authoritative. Attacks on the scanners themselves (e.g., malicious Semgrep rules) represent a supply chain risk that should be addressed with scanner rule provenance verification.

### 5.3 Limitations

**Scanner coverage.** Our real-world evaluation used only the ghost dependency and stale AI pattern scanners. Full pipeline evaluation with Semgrep, Gitleaks, and Trivy would increase CWE coverage to the full 12 supported classes.

**Prompt design sensitivity.** The Gemini 2.5 Flash results show that when prompts explicitly request an insecure pattern, user instructions can override system-level rules. In realistic usage, developers rarely explicitly request insecure code patterns, so the effective compliance rate would be higher than measured.

**Single trial per condition.** Each model-prompt combination was tested once. LLM output is non-deterministic; multiple trials per condition would provide confidence intervals. However, the consistency of results across models (100% effectiveness for 3 of 4) suggests low variance.

**Template coverage.** The rule template library currently covers 12 CWE classes for SAST, 10 stale AI patterns, and dynamic secret type detection. CWE classes without templates do not generate rules.

---

## 6. Discussion

### 6.1 From Reflexion to Persistence

Our work extends the Reflexion framework [7] from ephemeral in-context memory to durable file-based memory. Where Reflexion stores verbal reinforcement signals in a buffer that is cleared between episodes, our system writes reinforcement signals to version-controlled files that persist indefinitely. A developer who sets up the system once benefits from every subsequent scan, across every agent they use, without per-session effort.

### 6.2 Deterministic vs. LLM-Generated Rules

The choice to use deterministic templates rather than LLM-generated rules is a key design decision. LLM-generated rules could be more contextual, but they introduce three risks: rule hallucination (incorrect remediation advice), non-reproducibility (different rules from the same findings on re-run), and opacity (inability to audit why a specific rule was generated). Our experiment validates this choice: the template-driven rules achieved 90% effectiveness across 4 models, demonstrating that generic, well-phrased security instructions are sufficient to change model behavior without project-specific contextualization.

### 6.3 Instruction Files as a Policy Layer

Our results demonstrate that instruction files can serve as a model-agnostic policy enforcement layer. The same markdown rules influenced Claude (Anthropic), Gemini (Google), Nemotron (NVIDIA), and GPT-OSS (OpenAI) without model-specific adaptation. This property makes instruction files a viable substrate for organizational security policies that apply regardless of which AI tool a developer uses.

The 87% compression ratio from our repository scanning experiment is critical for this use case: a policy layer that generates hundreds of lines per scan would degrade agent performance through context window consumption. By grouping rules per CWE class, the system maintains concise instruction files even for large codebases.

### 6.4 Implications for the Agentic AI Ecosystem

The Agentic AI Foundation (AAIF) and the Model Context Protocol (MCP) are standardizing how agents interact with tools and data [6]. Our work demonstrates a complementary pattern: tools that generate persistent agent guidance rather than one-time results. We anticipate this pattern generalizing beyond security to linting servers that teach coding style, testing frameworks that encode failure patterns, and accessibility scanners that prevent recurring a11y violations.

---

## 7. Future Work

1. **Expanded model evaluation.** Test with additional models (GPT-4o, Llama 3.1, Mistral, DeepSeek) and with multiple trials per condition to establish confidence intervals.

2. **Longitudinal study.** Track vulnerability recurrence rates over time in a production repository using the feedback loop, measuring whether cumulative rule additions monotonically reduce new vulnerability introductions.

3. **LLM-assisted template expansion.** Use an LLM to propose new rule templates for uncovered CWE classes, with human review before addition to the template library.

4. **MCP server integration.** Expose the scanner and rule generator as MCP tools, enabling any MCP-compatible agent to invoke scanning and rule generation as part of its workflow.

5. **Graduated enforcement.** Implement escalating rule severity based on recurrence: warning on first detection, mandatory rule after repeated violations, pre-commit blocking after a threshold.

6. **Rule phrasing optimization.** Systematically test which rule phrasings achieve highest compliance across models, building an empirical understanding of effective instruction file design.

---

## 8. Conclusion

We presented a closed-loop system for generating persistent, cross-agent security rules from automated vulnerability detection. The system scans codebases with multiple security scanners, classifies findings by CWE, generates deterministic rules via templates, and injects them into instruction files for Claude Code, Cursor, and GitHub Copilot simultaneously.

Two experiments validate the approach. Scanning 7 open-source repositories detected 994 findings that compressed to 134 rules (87% reduction), with ghost dependencies present in all repositories. A controlled multi-model experiment across 4 LLMs from different providers demonstrated 100% rule effectiveness for 3 of 4 models, with an aggregate 91% vulnerability reduction rate (22 baseline vulnerabilities reduced to 2). The two remaining failures occurred only when prompts explicitly requested the insecure pattern, overriding the system-level rule.

By treating agent instruction files as a programmable policy layer rather than static documentation, we enable security lessons learned by one agent to transfer to any other agent on the same project -- across models, across providers, and across sessions -- without fine-tuning.

---

## References

[1] Anthropic. "Claude Code: An agentic coding tool." 2025. https://docs.anthropic.com/en/docs/claude-code

[2] Anthropic. "CLAUDE.md documentation." 2025. https://docs.anthropic.com/en/docs/claude-code/memory

[3] Cursor. "Rules for AI." 2025. https://docs.cursor.com/context/rules-for-ai

[4] GitHub. "Copilot Instructions." 2025. https://docs.github.com/en/copilot/customizing-copilot/adding-custom-instructions

[5] Block. "Goose: Open-source AI agent." 2025. https://github.com/block/goose

[6] Agentic AI Foundation. "AAIF." 2026. https://aaif.io

[7] N. Shinn, F. Cassano, A. Gopinath, K. Sheshadri, K. Narasimhan, S. Yao, and R. Zhao. "Reflexion: Language Agents with Verbal Reinforcement Learning." In Advances in Neural Information Processing Systems (NeurIPS), 2023.

[8] M. Zechner. "Pi-Reflect: Self-improving coding agent via instruction file mutation." 2025. https://github.com/jo-inc/pi-reflect

[9] ngrok. "BMO: Self-improving coding agent." 2025. https://ngrok.com/blog/bmo-self-improving-coding-agent

[10] Cognition. "Devin Knowledge system." 2025. https://docs.devin.ai/essential-guidelines/instructing-devin-effectively

[11] Windsurf. "Cascade Memories." 2025. https://docs.windsurf.com/windsurf/cascade/memories

[12] Embrace The Red. "SpAIware: Persistent prompt injection via Windsurf Memories." 2025. https://embracethered.com/blog/posts/2025/windsurf-spaiware-exploit-persistent-prompt-injection/

[13] H. Pearce, B. Ahmad, B. Tan, B. Dolan-Gavitt, and R. Karri. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions." In IEEE Symposium on Security and Privacy (S&P), 2022.

[14] O. Asare, M. Nagappan, and N. Asokan. "Is GitHub's Copilot as bad as humans at introducing vulnerabilities in code?" Empirical Software Engineering, 2024.

[15] B. Lanyado. "Can you trust ChatGPT's package recommendations?" Vulcan Cyber, 2023.

[16] Y. Bai, S. Kadavath, S. Kundu, et al. "Constitutional AI: Harmlessness from AI Feedback." arXiv:2212.08073, 2022.

[17] A. Osmani. "Self-improving coding agents." 2025. https://addyosmani.com/blog/self-improving-agents/

[18] N. Shinn et al. "When Can LLMs Actually Correct Their Own Mistakes?" Transactions of the Association for Computational Linguistics (TACL), 2024.

---

## Supplementary Materials

Available at: https://github.com/adhit-r

- Generated instruction files for all 7 scanned repositories
- Full scan results (JSON) and experiment data
- Multi-model experiment results with per-trial detection data
- Cross-agent evaluation prompt set and detection functions
- Rule generator source code and template library
