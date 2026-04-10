# Scan, Learn, Prevent: Cross-Agent Security Policy Generation from Automated Vulnerability Detection

**Adhithya Rajasekaran**
rajasekaran.adhit@gmail.com | github.com/adhit-r

---

## Abstract

AI coding agents repeatedly introduce the same classes of security vulnerabilities across sessions because they lack persistent memory of past mistakes. Instruction files such as CLAUDE.md, .cursorrules, and copilot-instructions.md provide a mechanism for project-specific agent guidance, but today these files are manually authored and static. We present a closed-loop system that automatically detects vulnerabilities in codebases using multiple security scanners, classifies findings by CWE, and generates deterministic natural language rules that are injected into agent instruction files. Unlike prior approaches that use LLM-generated rules from conversation transcripts, our rule generator is template-driven with no LLM in the generation step, making rules auditable, reproducible, and free from hallucination risk. We evaluate the system on 7 open-source repositories (Express, Fastify, Hono, Next.js, Cal.com, Twenty, Documenso), detecting 994 security findings that compress to 134 cross-agent rules (87% reduction). The generated rules are written to instruction files for Claude Code, Cursor, and GitHub Copilot simultaneously, enabling a security lesson learned by one agent to transfer to any other agent operating on the same project without model fine-tuning. We discuss the new attack surface this creates, instruction poisoning, and propose mitigations.

---

## 1. Introduction

The adoption of AI coding agents has fundamentally changed software development. Tools such as Anthropic's Claude Code, Cursor, GitHub Copilot, and Block's Goose now generate substantial portions of production codebases, operating with increasing autonomy over code creation, testing, and deployment [1]. However, these agents share a critical limitation: they have no durable memory of their own security failures.

When an AI agent introduces a SQL injection vulnerability via string concatenation, hardcodes an API key, or imports a hallucinated package name, the same class of vulnerability is likely to recur in subsequent sessions. Each session starts fresh. The agent reads its instruction file, generates code, and the cycle repeats. If the instruction file contains no security guidance derived from actual vulnerability findings, the agent has no basis for avoiding previously identified mistakes.

This paper addresses the question: **can we close the feedback loop between automated security detection and AI agent behavior, creating persistent cross-agent security memory without model fine-tuning?**

We present a system with three key contributions:

1. **A closed-loop pipeline** that connects multiple security scanners (SAST, secret detection, ghost dependency detection, stale AI pattern detection) to agent instruction file mutation, creating a feedback loop that was previously absent.

2. **A deterministic, template-driven rule generator** that converts CWE-classified vulnerability findings into natural language agent rules without using an LLM in the generation step. This design choice eliminates rule hallucination risk and ensures auditability.

3. **Cross-agent knowledge transfer via instruction files**: security rules generated from one agent's output are written to multiple instruction file formats (CLAUDE.md, .cursorrules, copilot-instructions.md), enabling any agent operating on the project to inherit the corrections without fine-tuning.

---

## 2. Background and Related Work

### 2.1 Agent Instruction Files

Modern AI coding agents support project-specific instruction files that are read at session initialization. Claude Code reads CLAUDE.md [2], Cursor reads .cursorrules [3], GitHub Copilot reads .github/copilot-instructions.md [4], and Goose reads .goosehints [5]. These files function as persistent system-level guidance, influencing all code generation within a session. Unlike fine-tuning, instruction files are model-agnostic (any LLM can read markdown), project-scoped, version-controlled, and human-editable.

The AGENTS.md specification, now hosted under the Agentic AI Foundation (AAIF) [6], standardizes the concept further, providing a single location for AI agent instructions across platforms. Despite their potential, instruction files are today manually authored and rarely updated in response to security findings.

### 2.2 Reflexion and Verbal Reinforcement Learning

Shinn et al. [7] introduced Reflexion, a framework where language agents learn from verbal self-reflection. An evaluator scores the agent's output, a self-reflection module generates natural language feedback, and this feedback is stored in an episodic memory buffer for subsequent trials. Reflexion demonstrated significant improvement on coding benchmarks (HumanEval pass@1 from 80.1% to 91.0%).

However, Reflexion's memory is ephemeral: it exists within a single trial sequence and does not persist to disk across independent sessions. Our work extends the Reflexion concept to durable, file-based memory that survives session boundaries, context window resets, and model changes.

### 2.3 Self-Correcting Agents and Pi-Reflect

Pi-Reflect [8] analyzes conversation transcripts from past AI agent sessions, sends them alongside current instruction files to an LLM, and generates rule updates. The reported correction rate dropped from 0.45 to 0.07 corrections per session. BMO [9], developed by ngrok, takes a similar approach with self-maintaining skill files.

Our system differs in three key ways: (a) we use structured security scanner output rather than unstructured conversation transcripts, enabling detection of vulnerabilities the agent introduced silently without discussion; (b) our rule generation is deterministic and template-driven, not LLM-generated, eliminating rule hallucination; (c) we write to multiple instruction file formats simultaneously, enabling cross-agent transfer.

### 2.4 Commercial Agent Memory Systems

Cognition's Devin maintains a Knowledge system that suggests memory entries for user approval [10]. Windsurf (Codeium) auto-generates Memories stored locally [11], though a 2024 security disclosure (SpAIware) demonstrated that this auto-generation mechanism could be exploited via prompt injection to persist false information [12]. Cursor's /Generate Rules command creates rule files from conversation context but requires manual invocation [3].

None of these systems use structured security scanner output as the trigger, and none write to multiple agent platforms simultaneously.

### 2.5 Constitutional AI and RLHF

Bai et al. [13] introduced Constitutional AI, where models self-critique against a set of principles and are fine-tuned on improved outputs. While conceptually related to our rule-based approach, CAI operates at training time and modifies model weights globally, rather than providing project-specific guidance at inference time through instruction files.

### 2.6 AI-Generated Code Security

Prior work has examined the security properties of AI-generated code. Pearce et al. [14] found that Copilot produces vulnerable code in approximately 40% of scenarios designed to elicit insecure patterns. Asare et al. [15] showed that LLM-generated code contains security weaknesses at rates comparable to or exceeding human-written code. Our ghost dependency scanner addresses a less-studied threat: LLM hallucination of package names that creates supply chain attack vectors [16].

---

## 3. System Design

Our system operates as a pipeline with four stages: multi-scanner detection, finding classification, deterministic rule generation, and multi-format instruction file injection.

### 3.1 Multi-Scanner Detection

The system orchestrates eight specialized scanners, each targeting a distinct vulnerability domain:

| Scanner | Target | Tool | External Deps |
|---------|--------|------|---------------|
| SAST | Code-level vulnerabilities | Semgrep | CLI binary |
| Secret detection | Hardcoded credentials | Gitleaks | CLI binary |
| SCA | Vulnerable dependencies | Trivy | CLI binary |
| Ghost dependencies | AI-hallucinated packages | Custom | Registry APIs |
| Stale AI patterns | Outdated training artifacts | Custom | None (regex) |
| Prompt injection | Instruction override attempts | Custom | None |
| IaC scanning | Infrastructure misconfig | Bearer | CLI binary |
| Vibe score | Overall security posture | Custom | None |

The ghost dependency scanner and stale AI pattern scanner are particularly relevant to AI-generated code:

**Ghost dependency scanner.** LLMs hallucinate package names that do not exist in registries. An attacker can register such names, creating a zero-effort supply chain attack. Our scanner queries npm, PyPI, Go, Rust, and Ruby registries, classifying findings into three risk tiers: `not_found` (package does not exist), `typosquat` (within edit distance of a legitimate package), and `phantom_new` (recently registered with minimal downloads). The scanner maintains allowlists of well-known packages to minimize API calls.

**Stale AI pattern scanner.** LLMs trained on historical code generate patterns that were acceptable at the time of training but are now known to be insecure. We detect 10 specific patterns via regex rules, including eval()/exec() usage (CWE-94), MD5/SHA1 for cryptographic operations (CWE-328), Math.random() for security-sensitive values (CWE-338), plaintext HTTP in production (CWE-319), and pickle deserialization of untrusted data (CWE-502). Each pattern includes a sensitivity context check to reduce false positives.

### 3.2 Finding Classification

Scanner output is normalized into a unified schema with CWE identifier, severity level (critical/high/medium), source tool, file path, line number, and scanner-specific metadata. Findings are deduplicated by a composite key and grouped by CWE for rule generation.

### 3.3 Deterministic Rule Generator

The rule generator is a central contribution of this work. It converts classified findings into natural language rules using predefined templates. Critically, **no LLM is used in the rule generation step**. This is a deliberate design choice with three motivations:

1. **Auditability.** Every generated rule traces to a specific template and input finding. Security teams can review the template library rather than auditing probabilistic LLM output.

2. **Reproducibility.** Given identical findings, the system produces identical rules. This property is essential for CI/CD integration where deterministic behavior is expected.

3. **No rule hallucination.** LLM-generated rules could contain incorrect remediation advice (e.g., suggesting a deprecated API as a fix). Template-driven rules are authored by security engineers and reviewed before deployment.

The template library covers four categories:

**Ghost dependency templates** generate package-specific warnings:
> NEVER use the package "react-encrypted-localstorage" (npm) -- it does not exist on the registry. This is likely an AI-hallucinated package name. An attacker can register it at any time.

**Stale AI pattern templates** reference the insecure pattern and its secure alternative:
> NEVER use MD5 or SHA1 for cryptographic operations -- both are broken. Use SHA-256 (or higher) for checksums; use bcrypt, argon2, or scrypt for passwords.

**Secret templates** dynamically map secret types from scanner output to specific guidance:
> NEVER hardcode AWS credentials in source code. Load them from environment variables (process.env.AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) or a secrets manager.

**SAST templates** cover 12 CWE classes with specific remediation instructions.

**Rule compression.** Multiple findings of the same CWE class produce a single rule. In our evaluation, this achieves 87% compression across 7 repositories (994 findings to 134 rules), preventing instruction file bloat while preserving coverage.

### 3.4 Multi-Format Instruction File Injection

Generated rules are formatted as a Markdown section with HTML comment markers:

```markdown
<!-- PATCHPILOT:START -->
## Security rules -- auto-generated
<!-- Last updated: 2026-04-05 | Repo: org/repo -->

### Ghost dependencies (AI-hallucinated packages)
- NEVER use the package "lodahs" -- it is a typosquat of "lodash"...

### Security vulnerabilities
- NEVER interpolate user input into SQL queries...
<!-- PATCHPILOT:END -->
```

The markers serve three functions:

1. **Idempotent updates.** On re-scan, the system locates and replaces the existing marker-delimited section. Content outside the markers (manually-authored rules, coding conventions) is preserved.

2. **Multi-format writing.** The same rules are injected into CLAUDE.md, .cursorrules, and copilot-instructions.md in a single operation.

3. **PR-based review.** Changes are committed to a new branch (patchpilot/agent-rules-{sha}) and a draft PR is opened. Rules take effect only after human approval and merge, maintaining oversight of auto-generated content.

---

## 4. Evaluation

### 4.1 Rule Generator Validation

We validated the rule generator against 15 synthetic findings spanning all 4 categories (SAST, secrets, ghost deps, stale AI patterns). All 9 test properties passed:

| Property | Result |
|----------|--------|
| Coverage: all 4 categories produce rules | Pass |
| Grouping: 2 CWE-89 findings produce 1 rule | Pass |
| Severity filtering: medium SAST findings excluded | Pass |
| Secret type differentiation: AWS vs GitHub vs generic | Pass |
| Ghost dep risk tiers: not_found, typosquat, phantom_new | Pass |
| Stale AI pattern matching: 3/3 patterns detected | Pass |
| Instruction file formatting with markers | Pass |
| Content preservation on injection | Pass |
| Idempotent re-injection: no duplicate blocks | Pass |

### 4.2 Real-World Repository Scanning

We evaluated the system on 7 open-source TypeScript/JavaScript repositories of varying size and complexity, using the ghost dependency scanner and stale AI pattern scanner (both pure TypeScript, no external tool dependencies).

**Table 1: Scan Results by Repository**

| Repository | Description | Stale AI | Ghost Deps | Total | Rules | Compression |
|------------|-------------|----------|------------|-------|-------|-------------|
| express | Web framework | 1 | 11 | 12 | 11 | 8% |
| fastify | Web framework | 6 | 3 | 9 | 4 | 56% |
| next-learn | Learning examples | 2 | 7 | 9 | 3 | 67% |
| hono | Web framework | 13 | 6 | 19 | 9 | 53% |
| cal.com | Scheduling platform | 177 | 313 | 490 | 51 | 90% |
| twenty | CRM platform | 312 | 24 | 336 | 26 | 92% |
| documenso | Document signing | 66 | 53 | 119 | 30 | 75% |
| **Total** | | **577** | **417** | **994** | **134** | **87%** |

Key observations:

**Ghost dependencies are pervasive.** All 7 repositories contained ghost dependency findings (CWE-1104), with cal.com containing 313 ghost dependency findings alone. These represent packages referenced in dependency manifests that either do not exist on npm or were recently registered with minimal adoption, making them potential supply chain attack vectors.

**Stale AI patterns scale with codebase size.** Twenty (312 findings) and cal.com (177 findings) are large production codebases where insecure patterns from older code or AI-assisted contributions accumulate. The stale AI pattern scanner detected eval() usage, MD5/SHA1 in cryptographic contexts, Math.random() for security values, and plaintext HTTP in production configurations.

**Compression increases with scale.** Small repositories show low compression (Express: 8%) because most findings map to unique CWE classes. Large repositories show high compression (Twenty: 92%, cal.com: 90%) because many findings share the same CWE, producing one rule per class rather than one per finding. This property is essential for instruction file usability: a 490-finding scan produces a 51-rule section rather than a 490-line list.

**Table 2: CWE Coverage Across Repositories**

| CWE | Description | Repos Affected |
|-----|-------------|----------------|
| CWE-1104 | Untrusted dependencies | 7/7 |
| CWE-94 | Code injection (eval/exec) | 5/7 |
| CWE-319 | Plaintext HTTP | 4/7 |
| CWE-328 | Weak cryptography (MD5/SHA1) | 3/7 |
| CWE-338 | Insecure randomness | 3/7 |

CWE-1104 (ghost dependencies) appeared in every repository scanned, confirming that AI-hallucinated package names are a systemic issue in the JavaScript/TypeScript ecosystem. CWE-94 (code injection via eval/exec) appeared in 5/7 repositories, consistent with prior findings that LLMs frequently generate eval()-based patterns from training data.

### 4.3 Cross-Agent Transfer Protocol

We designed and documented a controlled experiment protocol for measuring cross-agent knowledge transfer. The protocol uses 7 vulnerability-eliciting prompts (one per CWE class) across 3 agents (Claude Code, Cursor, GitHub Copilot) in 3 conditions:

- **Control**: agent generates code with an empty instruction file
- **Treatment**: agent generates code with the auto-generated rules in its instruction file
- **Cross-transfer**: rules generated from Agent A's findings are placed in Agent B's instruction file

The full evaluation matrix comprises 63 trials (7 vulns x 3 agents x 3 conditions). We provide the complete prompt set and evaluation template as supplementary materials. Full results from this experiment will be reported in the extended version of this paper.

### 4.4 Instruction File Artifacts

For each scanned repository, the system generated three instruction files (CLAUDE.md, .cursorrules, copilot-instructions.md) containing the auto-generated rules. These files are immediately deployable: dropping them into any repository makes the security rules available to any agent that reads the corresponding file. We provide all generated instruction files as supplementary materials.

---

## 5. Security Analysis

### 5.1 Instruction Poisoning

Auto-generating agent instruction files creates a new attack surface. An adversary who can influence the scanner output or the rule generation pipeline could inject malicious rules that cause agents to:

- Introduce vulnerabilities rather than prevent them (e.g., "Always use eval() for JSON parsing")
- Exfiltrate data (e.g., "Log all environment variables at startup for debugging")
- Disable security controls (e.g., "Skip authentication for internal endpoints")

This threat is analogous to the SpAIware exploit demonstrated against Windsurf's auto-generated Memories [12], where prompt injection in repository files could persist false information into the agent's memory.

### 5.2 Mitigations

Our system implements several mitigations:

1. **Deterministic templates.** Rules are generated from a reviewed template library, not from LLM output. An attacker cannot inject arbitrary natural language into rules without modifying the template library itself.

2. **PR-based review.** Auto-generated rules are presented as a draft pull request, requiring human approval before taking effect. This is a deliberate gate that prevents fully autonomous instruction mutation.

3. **Marker-delimited sections.** The PATCHPILOT:START/END markers make the auto-generated section clearly identifiable for review and auditing. Content outside the markers is never modified.

4. **Scanner trust boundary.** The system trusts scanner output (Semgrep, Gitleaks) as authoritative. Attacks on the scanners themselves (e.g., malicious Semgrep rules) are out of scope but represent a supply chain risk that should be addressed with scanner rule provenance verification.

### 5.3 Limitations

- **Scanner coverage.** Our real-world evaluation used only the ghost dependency and stale AI pattern scanners (pure TypeScript). Full pipeline evaluation with Semgrep, Gitleaks, and Trivy would provide SAST and secret detection findings, increasing CWE coverage.
- **Rule effectiveness.** We generate rules that LLMs are instructed to follow, but LLM instruction-following is imperfect. Rules phrased as "NEVER do X" may still be violated by some models in some contexts. The cross-agent evaluation will quantify actual compliance rates.
- **Template coverage.** The rule template library currently covers 12 CWE classes for SAST, 10 stale AI patterns, and dynamic secret type detection. Expanding the template library to cover additional CWE classes is straightforward but requires security engineering effort.

---

## 6. Discussion

### 6.1 From Reflexion to Persistence

Our work can be viewed as extending the Reflexion framework [7] from ephemeral in-context memory to durable file-based memory. Where Reflexion stores verbal reinforcement signals in a buffer that is cleared between episodes, our system writes reinforcement signals (security rules) to version-controlled files that persist indefinitely. This distinction matters in practice: a developer who sets up the system once benefits from every subsequent scan, across every agent they use, without any per-session effort.

### 6.2 Deterministic vs. LLM-Generated Rules

The choice to use deterministic templates rather than LLM-generated rules is a key design decision. LLM-generated rules could be more contextual (referencing specific code patterns in the project), but they introduce three risks: rule hallucination (incorrect remediation advice), non-reproducibility (different rules from the same findings on re-run), and opacity (inability to audit why a specific rule was generated). For security-critical rules that govern agent behavior, we argue that auditability and reproducibility outweigh contextual specificity.

### 6.3 Instruction Files as a Policy Layer

Our results suggest that instruction files can serve as a model-agnostic policy enforcement layer. The same markdown rules influence Claude (Anthropic), GPT-4 (OpenAI), and other models (via Cursor's model selection) without any model-specific adaptation. This property makes instruction files a viable substrate for organizational security policies that apply regardless of which AI tool a developer uses.

### 6.4 Implications for the Agentic AI Ecosystem

The Agentic AI Foundation (AAIF) and the Model Context Protocol (MCP) are standardizing how agents interact with tools and data [6]. Our work demonstrates a complementary pattern: tools (scanners) that generate persistent agent guidance rather than one-time results. We anticipate that this pattern will generalize beyond security to other domains, such as linting servers that teach coding style, testing frameworks that encode failure patterns, and accessibility scanners that prevent recurring a11y violations.

---

## 7. Future Work

1. **Full cross-agent evaluation.** Execute the 63-trial evaluation matrix across Claude Code, Cursor, and GitHub Copilot to quantify recurrence prevention rates and cross-agent transfer effectiveness.

2. **LLM-assisted template expansion.** Use an LLM to propose new rule templates for CWE classes not yet covered, with human review before addition to the template library. This hybrid approach preserves auditability while scaling coverage.

3. **MCP server integration.** Expose the scanner and rule generator as MCP tools, enabling any MCP-compatible agent to invoke scanning and rule generation as part of its workflow.

4. **Graduated enforcement.** Implement escalating rule severity based on recurrence: warning on first detection, mandatory rule after repeated violations, pre-commit blocking after a threshold.

5. **Rule effectiveness benchmarking.** Systematically test which rule phrasings achieve highest compliance across different LLMs, building an empirical understanding of effective instruction file design.

---

## 8. Conclusion

We presented a closed-loop system for generating persistent, cross-agent security rules from automated vulnerability detection. The system scans codebases with multiple security scanners, classifies findings by CWE, generates deterministic rules via templates, and injects them into instruction files for Claude Code, Cursor, and GitHub Copilot simultaneously. Evaluation on 7 open-source repositories detected 994 findings that compressed to 134 rules (87% reduction), with ghost dependencies (CWE-1104) present in all repositories scanned. The system creates a form of durable, cross-agent security memory that was previously absent from AI-assisted development workflows. By treating agent instruction files as a programmable policy layer rather than static documentation, we enable security lessons learned by one agent to transfer to any other agent on the same project without model fine-tuning.

---

## References

[1] Anthropic. "Claude Code: An agentic coding tool." 2025. https://docs.anthropic.com/en/docs/claude-code

[2] Anthropic. "CLAUDE.md documentation." 2025. https://docs.anthropic.com/en/docs/claude-code/memory

[3] Cursor. "Rules for AI." 2025. https://docs.cursor.com/context/rules-for-ai

[4] GitHub. "Copilot Instructions." 2025. https://docs.github.com/en/copilot/customizing-copilot/adding-custom-instructions

[5] Block. "Goose: Open-source AI agent." 2025. https://github.com/block/goose

[6] Agentic AI Foundation. "AAIF." 2026. https://aaif.io

[7] Shinn, N., Cassano, F., Gopinath, A., Sheshadri, K., Narasimhan, K., Yao, S., and Zhao, R. "Reflexion: Language Agents with Verbal Reinforcement Learning." NeurIPS 2023.

[8] Zechner, M. "Pi-Reflect: Self-improving coding agent via instruction file mutation." 2025. https://github.com/jo-inc/pi-reflect

[9] ngrok. "BMO: Self-improving coding agent." 2025. https://ngrok.com/blog/bmo-self-improving-coding-agent

[10] Cognition. "Devin Knowledge system." 2025. https://docs.devin.ai/essential-guidelines/instructing-devin-effectively

[11] Windsurf. "Cascade Memories." 2025. https://docs.windsurf.com/windsurf/cascade/memories

[12] Embrace The Red. "SpAIware: Persistent prompt injection via Windsurf Memories." 2025. https://embracethered.com/blog/posts/2025/windsurf-spaiware-exploit-persistent-prompt-injection/

[13] Bai, Y., Kadavath, S., Kundu, S., et al. "Constitutional AI: Harmlessness from AI Feedback." 2022. arXiv:2212.08073.

[14] Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., and Karri, R. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions." IEEE S&P 2022.

[15] Asare, O., Nagappan, M., and Asokan, N. "Is GitHub's Copilot as bad as humans at introducing vulnerabilities in code?" Empirical Software Engineering, 2024.

[16] Lanyado, B. "Can you trust ChatGPT's package recommendations?" Vulcan Cyber, 2023. https://vulcan.io/blog/ai-hallucinations-package-risk

---

## Supplementary Materials

Available at: https://github.com/adhit-r

- Generated instruction files for all 7 repositories (CLAUDE.md, .cursorrules, copilot-instructions.md)
- Full scan results (JSON)
- Cross-agent evaluation prompt set and matrix template
- Rule generator source code and template library
