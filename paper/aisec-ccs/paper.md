# Don't Say Never: How Prohibition-Framed Security Rules Backfire in LLM Coding Agents

**Adhithya Rajasekaran**

adhithya@axonome.xyz

## Abstract

While developing a closed-loop system that automatically generates security rules from scanner output and injects them into AI coding agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules), we observed a paradoxical effect: a prohibition-framed rule ("NEVER use eval()") *increased* vulnerability rates on one prompt compared to having no rule at all --- the opposite of the rule's intent. This paper systematically investigates that effect across 645 trials spanning three models (Claude Sonnet 4, GPT-5, Gemma 4 31B), six vulnerability-eliciting prompts, and four CWE classes, comparing prohibition framing ("NEVER use eval()") against alternative-suggestion framing ("Always use JSON.parse()"). We find three principal results. First, both framings substantially reduce vulnerabilities on aggregate (baseline 58% to 13--23%), confirming that auto-generated rules work. Second, which framing backfires is model-dependent: prohibition framing increases vulnerability on Claude Sonnet 4 (50% vs. 20% control, p=0.016), while alternative-suggestion framing backfires on Gemma 4 31B across three prompts (aggregate: 47% vs. 40% control). GPT-5 exhibits no backfire under either framing. Third, the backfire requires a *double-priming interaction* --- when user prompts do not name the insecure API, neither framing causes harm (0/225 trials). We connect this finding to Wegner's Ironic Process Theory and to recent work on adversarial priming attacks, observing that well-intentioned prohibition rules inadvertently create the same activation pattern an adversary would deliberately construct. These findings have direct implications for the design of auto-generated security policies in AI coding agent workflows.

## 1 Introduction

AI coding agents --- Claude Code, Codex, Cursor, GitHub Copilot --- increasingly operate with full repository access, executing multi-step tasks guided by persistent instruction files [1, 2, 3]. These markdown-based files (CLAUDE.md, AGENTS.md, .cursorrules) function as a static constitution consulted before every generation step, providing security guardrails that ephemeral prompts cannot maintain. AI-generated code contains vulnerabilities at concerning rates: Pearce et al. [10] found approximately 40% in security-relevant scenarios, and Perry et al. [11] demonstrated that AI assistance increases both vulnerability rates and developer confidence. Instruction files represent the primary line of defense.

While developing a system that automatically scans codebases for vulnerabilities, classifies findings by CWE, and generates deterministic security rules for injection into these instruction files, we observed a paradoxical result during evaluation. The system generated prohibition-framed rules --- following the natural pattern of security guidance ("NEVER use eval()") --- and injected them into a CLAUDE.md file. On most prompts, the rules reduced vulnerability rates as expected. But on one prompt that asked the model to build a formula evaluator, the prohibition rule *increased* the rate of `eval()` usage from 20% (no rules) to 50% (with the "NEVER use eval()" rule). Telling the model not to use the function made it use the function more often.

This observation prompted a systematic investigation. We hypothesized that the effect might be analogous to Wegner's Ironic Process Theory [2, 3], which demonstrates that attempting to suppress a thought paradoxically increases its accessibility --- the canonical "white bear" effect. We tested whether rephrasing rules as alternative suggestions ("Always use JSON.parse()") would avoid this priming, and whether the effect would replicate across models. Our results reveal a picture more complex than simple ironic rebound:

1. **Model-dependent backfire direction.** Which framing backfires is not universal: prohibition framing is worse on Claude, alternative-suggestion framing is worse on Gemma, GPT-5 is robust to both.
2. **Double-priming requirement.** The backfire requires both the rule and the user prompt to name the insecure API. When prompts omit the API name, neither framing causes harm (0/225 vulnerable trials).
3. **Unintentional priming.** Well-intentioned prohibition rules create the same activation pattern an adversary would deliberately construct in a priming attack [7], differing only in intent.

## 2 Related Work

**Negation in LLMs.** Elkins et al. [4] audit negation sensitivity across 16 models, finding open-source models endorse prohibited actions 77% of the time under simple negation. The "Pink Elephant" problem --- where naming a forbidden concept activates rather than suppresses it --- has been studied by Biderman et al. [5], who propose Direct Principle Feedback as a fine-tuning mitigation, and characterized cross-linguistically by Truong et al. [6]. Our work extends these findings from general NLU to code generation security outcomes.

**Priming attacks.** Maus et al. [7] demonstrate that psychological priming strategies achieve 100% attack success on open-source models and 95% on commercial models. We observe that prohibition-framed safety rules create the same priming mechanism *unintentionally*.

**Instruction hierarchy.** Wallace et al. [8] propose training LLMs to prioritize system-level instructions over user messages. Our `http-url` results (where explicit URLs in user prompts override system rules regardless of framing) demonstrate the practical limits of this hierarchy.

**Aesthetic anchoring.** In prior work [9], we demonstrated that persistent stylistic defaults in LLMs resist user override, with compliance governed by topic context rather than instruction intensity. Our "constraint synergy" effect for formatting constraints contrasts with the backfire effects we observe for security prohibitions in the present study, suggesting structurally different compliance dynamics between stylistic and semantic constraints.

**AI code security.** Pearce et al. [10] established that Copilot produces vulnerable code in ~40% of security-relevant scenarios. Perry et al. [11] found developers using AI assistants wrote more insecure code with higher confidence. Our baseline vulnerability rates (20--100% depending on prompt) are consistent with these findings.

## 3 Methodology

### 3.1 Experimental Design

We employ a 3 (framing) x 6 (prompt) x 3 (model) between-subjects design with 10 trials per cell. The three framing conditions are:

- **Control**: No security rules. Base system prompt only.
- **Negative (prohibition)**: e.g., "NEVER use eval() or exec() to execute dynamic strings as code --- it enables remote code execution."
- **Positive (alternative-suggestion)**: e.g., "Always parse dynamic data with JSON.parse() and always invoke subprocesses with a fixed argument list."

Rules are injected via the mechanism native to each agent: system prompt for Claude, AGENTS.md for Codex (GPT-5), and system_instruction for Gemma via the Gemini API.

### 3.2 Models

| Model | Provider | Access | Rule Injection |
|-------|----------|--------|----------------|
| Claude Sonnet 4 | Anthropic | Claude CLI | System prompt |
| GPT-5 (gpt-5.3-codex) | OpenAI | Codex CLI | AGENTS.md |
| Gemma 4 31B | Google | Gemini API | system_instruction |

### 3.3 Prompts

Six prompts target four CWE classes. Each prompt explicitly requests the insecure API pattern (e.g., "Use eval() to handle expressions") to create the double-priming condition:

| Prompt ID | CWE | Target Vulnerability |
|-----------|-----|---------------------|
| eval-usage | CWE-94 | eval() in template engine |
| eval-dynamic | CWE-94 | eval() in formula evaluator |
| md5-hash | CWE-328 | MD5 for ETag generation |
| weak-hash | CWE-328 | MD5 for document fingerprinting |
| http-url | CWE-319 | Plaintext HTTP for health check |
| insecure-random | CWE-338 | Math.random() for signing tokens |

### 3.4 Non-API-Naming Experiment

To isolate the double-priming interaction, we created three additional prompts that request the *same functionality* without naming the insecure API (e.g., "Write a formula evaluator for document templates" with no mention of eval). These were tested across all three models (10 trials/cell for Claude and Gemma, 5 for GPT-5; 225 total trials).

### 3.5 Detection

Vulnerability detection uses regex patterns on comment-stripped code (e.g., `/\beval\s*\(/` for CWE-94). Comments are stripped before matching to avoid false positives from models citing rules in explanatory text.

## 4 Results

### 4.1 Rules Reduce Vulnerabilities Regardless of Framing

Across all three models, both framing conditions substantially reduce vulnerability rates compared to control. The dominant effect is rule injection itself.

**Table 1: Aggregate vulnerability rates by model and condition**

| Model | Control | Negative | Positive |
|-------|--------:|----------:|----------:|
| Claude Sonnet 4 | 35/60 (58%) | 8/60 (13%) | 12/60 (20%) |
| GPT-5 | 38/50 (76%) | 8/50 (16%) | 5/50 (10%) |
| Gemma 4 31B | 24/60 (40%) | 14/60 (23%) | 28/60 (47%) |

Note: GPT-5 excludes `weak-hash` (API quota errors on all 30 trials).

### 4.2 Backfire Direction Is Model-Dependent

**Claude Sonnet 4** exhibits prohibition backfire on `eval-dynamic` in Phase 1 (isolated replication): control 2/10, negative 5/10, positive 0/10 (Fisher's exact: p=0.016 for negative vs. positive). In Phase 2, `http-url` shows positive framing performing worse than negative (9/10 vs. 5/10).

**GPT-5** shows no backfire on any prompt. Both framings reduce vulnerability, with positive framing slightly more effective. The `http-url` prompt reveals a gradient (control 8/10 → negative 6/10 → positive 4/10) where neither framing fully overcomes the explicit URL in the prompt.

**Gemma 4 31B** exhibits *positive* backfire on three prompts:

| Prompt | Control | Negative | Positive |
|--------|--------:|----------:|----------:|
| eval-usage | 5/10 | 1/10 | **9/10** |
| eval-dynamic | 4/10 | 3/10 | **7/10** |
| weak-hash | 1/10 | 2/10 | **6/10** |

On Gemma, positive framing produces *more* vulnerable code than no rules at all (aggregate: 47% vs. 40%).

### 4.3 The Double-Priming Requirement

When prompts do not name the insecure API, neither framing condition produces any vulnerable code across all three models: **0/225 trials** (0/90 Claude, 0/90 Gemma, 0/45 GPT-5). This null result is critical: prohibition rules do not prime the forbidden concept independently. The backfire requires the user prompt to co-activate the same API the rule addresses.

### 4.4 Per-Prompt Analysis

**Table 2: Full results matrix (vulnerable/total per cell)**

| Prompt | | Claude | | | GPT-5 | | | Gemma | |
|--------|---------|--------|---------|---------|-------|---------|---------|-------|---------|
| | Ctrl | Neg | Pos | Ctrl | Neg | Pos | Ctrl | Neg | Pos |
| eval-usage | 2/10 | 1/10 | 0/10 | 4/10 | 0/10 | 0/10 | 5/10 | 1/10 | **9/10** |
| md5-hash | 8/10 | 0/10 | 0/10 | 8/10 | 2/10 | 1/10 | 10/10 | 8/10 | 6/10 |
| http-url | 4/10 | 5/10 | **9/10** | 8/10 | 6/10 | 4/10 | 0/10 | 0/10 | 0/10 |
| insecure-random | 10/10 | 0/10 | 0/10 | 10/10 | 0/10 | 0/10 | 4/10 | 0/10 | 0/10 |
| eval-dynamic | 1/10 | 2/10 | 0/10 | 8/10 | 0/10 | 0/10 | 4/10 | 3/10 | **7/10** |
| weak-hash | 10/10 | 0/10 | 3/10 | -- | -- | -- | 1/10 | 2/10 | **6/10** |

Bold indicates backfire: treatment vulnerability exceeding control.

## 5 Discussion

### 5.1 No Universal Safe Framing

Our central finding is negative: **no single framing strategy is universally safer**. Prohibition framing backfires on Claude (eval-dynamic), while alternative-suggestion framing backfires on Gemma (eval-usage, eval-dynamic, weak-hash). GPT-5 is robust to both. This model-dependence means that framing recommendations must be qualified by the target model --- a finding that complicates practical deployment.

### 5.2 The Unintentional Priming Mechanism

We propose a *double-priming interaction* model: the backfire effect arises when two independent sources --- the rule and the prompt --- both activate the same concept in the model's latent space. Neither source alone is sufficient (non-API experiment: 0/225). This mechanism is structurally identical to the priming attacks documented by Maus et al. [7], differing only in intent: safety rules that name the forbidden API inadvertently create the same activation pattern an adversary would deliberately construct.

The structural asymmetry between framings explains why the direction varies by model. Positive framing ("Always use JSON.parse()") activates the safe alternative without naming the unsafe one. Negative framing ("NEVER use eval()") activates the unsafe concept to suppress it. Different models resolve this activation differently depending on their safety training, instruction hierarchy weighting, and attention architecture.

### 5.3 Instruction Hierarchy Limits

The `http-url` prompt contains a hardcoded URL (`http://monitor.internal:8080/ping`). On GPT-5, this creates a gradient where framing helps but cannot fully override the explicit user instruction (control 80% → negative 60% → positive 40%). This is an instruction hierarchy conflict [8], not a priming effect --- the model follows the user's explicit request over the system-level rule. This failure mode is orthogonal to framing and affects all rule-based approaches.

### 5.4 Practical Implications

For practitioners deploying instruction file security rules:

1. **Any rule is better than no rule.** Both framings reduce vulnerabilities substantially on aggregate across all models.
2. **Consider the target model.** Test rule effectiveness on the specific model in use; do not assume cross-model transfer of framing efficacy.
3. **Avoid naming insecure APIs in rules when possible.** If the CWE involves a specific API name (eval, exec), prefer framing that names only the safe alternative.
4. **Rules cannot override explicit user requests.** When prompts explicitly request insecure patterns, no framing reliably prevents vulnerable output.

## 6 Limitations

**Sample size.** Ten trials per cell limits statistical power for individual cells. We mitigate this through cross-model replication and the clear 0/225 null result for non-API prompts.

**Prompt design.** All API-naming prompts explicitly request the insecure pattern, which is uncommon in realistic development workflows. Our non-API experiment partially addresses this but uses only three prompts.

**Detection granularity.** Regex-based detection does not distinguish between `eval()` in production code versus sandboxed contexts, and may miss alternative insecure patterns (e.g., `new Function()`).

**Information asymmetry.** Positive and negative framings differ not only in framing but in information content (positive rules name specific safe alternatives). A future "negative + alternative" condition (e.g., "NEVER use eval() --- use JSON.parse() instead") would isolate the framing variable from the information variable.

**Model coverage.** Three models from three providers is broader than most studies but does not cover all production-relevant models (e.g., GPT-4o, Llama, Mistral).

## 7 Conclusion

We present preliminary evidence that security rule framing in LLM coding agent instruction files produces model-dependent backfire effects consistent with a double-priming interaction mechanism. The practical import is clear: there is no universally safe way to phrase a security rule. Rule authors must test their phrasings against target models, prefer naming safe alternatives over forbidden APIs, and recognize that instruction file rules cannot substitute for static analysis or runtime enforcement when user prompts explicitly request insecure patterns.

## References

[1] Anthropic. "Claude Code: An agentic coding tool." 2025.

[2] D. M. Wegner, D. J. Schneider, S. R. Carter, and T. L. White. "Paradoxical effects of thought suppression." *JPSP*, 53(1):5--13, 1987.

[3] D. M. Wegner. "Ironic processes of mental control." *Psychological Review*, 101(1):34--52, 1994.

[4] K. Elkins et al. "When Prohibitions Become Permissions: Auditing Negation Sensitivity in Language Models." *arXiv:2601.21433*, 2026.

[5] S. Biderman et al. "Suppressing Pink Elephants with Direct Principle Feedback." *arXiv:2402.07896*, 2024.

[6] L. Truong et al. "Negation: A Pink Elephant in the Large Language Models' Room?" *arXiv:2503.22395*, 2025.

[7] N. Maus et al. "Intrinsic Model Weaknesses: How Priming Attacks Unveil Vulnerabilities in Large Language Models." *Findings of NAACL*, 2025.

[8] E. Wallace et al. "The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions." *ICLR*, 2025.

[9] A. Rajasekaran, Kishore B, Lakshman S, Dhinakaran T, and Balaji P. "Aesthetic Anchoring: Persistent Stylistic Defaults in Large Language Models Resist User Override." SSRN Preprint, 2026. https://papers.ssrn.com/abstract=6525339

[10] H. Pearce et al. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions." *IEEE S&P*, 2022.

[11] N. Perry et al. "Do Users Write More Insecure Code with AI Assistants?" *CCS*, 2023.

## Acknowledgments

The author designed all experiments, formulated hypotheses, interpreted results, and drew all scientific conclusions. Claude Code (Anthropic) was used as a programming assistant for writing experiment automation scripts and as a drafting aid during manuscript preparation. All generated text was reviewed and substantially revised by the author.
