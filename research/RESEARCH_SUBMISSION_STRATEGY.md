# Research Submission Strategy

## Current Assessment

This project is now a full empirical paper, not a poster-first project.

Detailed strengthening plan: `research/STRENGTHENING_ROADMAP.md`.

The strongest current framing is:

**Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing**

Contribution type:

- empirical security measurement;
- replication/null result;
- secure-code-generation guardrail evaluation;
- optional methodological case study on instruction decay in long-running agent workflows.

## Research Strengths

| Strength | Why it matters |
| --- | --- |
| Clean main result | Rule injection reduces detector-counted insecure API use in all 6 tested models. This is easy to explain and actionable. |
| Balanced provider design | 3 OpenAI Codex/GPT models and 3 Anthropic Claude models make the paper stronger than a single-provider study. |
| Full cell balance | 6 models x 6 prompts x 3 conditions x 20 trials = 2,160 valid orchestration rows with zero final route errors. |
| Security relevance | Prompts map to recognizable CWE classes: dynamic execution, weak hashing, cleartext HTTP, insecure randomness. |
| Self-correcting science | The paper explicitly supersedes the author's own pilot. This is a reviewer-positive story if written carefully. |
| Reproducible artifacts | Data, runner, figures, and incident evidence exist locally and can be released. |

## Research Weaknesses

| Weakness | Risk | Fix |
| --- | --- | --- |
| Prompt-engineering framing risk | Reviewers may dismiss it as prompt wording rather than security research. | Frame as persistent instruction-policy evaluation for coding agents. |
| Explicit insecure API prompts | Ecological validity is limited because every prompt names the risky construct. | Add or clearly discuss non-API prompts as future work unless already fully run. |
| Regex detectors | Could miss semantic variants such as `new Function`. | Add a detector appendix and manually audit a stratified sample. |
| No four-arm decomposition | Positive and negative rules differ in both polarity and information content. | Either run four-arm decomposition or state this as the key limitation. |
| Case-study section is heavy | The Copilot quota incident may distract from the clean empirical paper. | For AISec/JISA, move it to appendix or separate paper. For TMLR, keep only if framed as secondary evidence, not a main claim. |
| Citation fragility | Some fast-moving 2025/2026 references may be preprints or need verification. | Verify every citation before submission; replace weak citations with stable venues where possible. |
| README/draft drift | Some public materials previously referenced the older 2,004-trial Gemma dataset. | Fixed in README; recheck all public artifacts before release. |

## Venue Recommendation

### 1. AISec @ CCS 2026

**Recommendation: strongest near-term archival AI-security target.**

Why it fits:

- It is directly about AI and security.
- It accepts empirical and critical papers at the AI/security boundary.
- The paper has a concrete security takeaway: add targeted agent rules, but do not rely on polarity folklore.
- The dataset/resource angle helps.

How to shape it:

- Keep the main paper focused on the 2,160-trial replication.
- Move the Copilot quota/instruction-decay incident to an appendix or a short "methodological note."
- Put the two main figures early: aggregate bars and polarity heatmap.
- Emphasize reproducibility, artifact link, detector protocol, and CWE mapping.

Risk:

- AISec is a workshop co-located with CCS, not CCS main. It is still archival and a credible first peer-reviewed venue for this paper.
- If the paper reads as "prompt engineering," it weakens. Use "persistent instruction-policy guardrails" language.

### 2. ACSAC 2027 or Similar Applied-Security Conference

**Recommendation: strongest proper-conference direction, but not available for 2026 unless a late track opens.**

Why it fits:

- ACSAC explicitly values applied security and practical lessons.
- The current paper is a replication/clarification study with artifacts, which aligns with applied-security reproducibility expectations.
- "Security and Privacy of Agentic Systems" and "Security Applications of Generative AI" are natural topic labels.

How to shape it:

- Add detector validation and a stronger threat model.
- Add at least one ecological-validity extension: non-API prompts, real repo tasks, or multi-turn agent repair.
- Move the Copilot quota incident to an appendix or separate paper unless the submission is specifically about agentic-system governance.

Risk:

- The 2026 ACSAC technical-paper deadline has already passed as of May 28, 2026.
- For a future proper-conference submission, the paper needs more than the current clean measurement result: artifact validation, threat model, and stronger practical deployment story.

### 3. TMLR

**Recommendation: possible journal-style path, but only after tightening the ML/instruction-following framing.**

Why it fits:

- Rolling review.
- TMLR values technical correctness and empirical insight.
- A negative result is acceptable if the hypothesis is meaningful and the evidence is clean.

How to shape it:

- Reframe from "secure coding paper" to "instruction-following behavior of learning systems under persistent rule framing."
- Keep security as the application domain.
- Anonymize the paper and supplement.
- Be careful with the already-public Zenodo DOI and GitHub repo; TMLR permits preprints, but the submission itself must be anonymized and not link to author-identifying material.

Risk:

- TMLR may see the work as too applied/security-specific unless the instruction-following contribution is made central.
- The single-case incident section should probably be appendix-only or split out unless a controlled decay experiment is added.

### 4. Journal of Information Security and Applications

**Recommendation: best conventional journal fallback.**

Why it fits:

- Applied information security and secure development practice are in scope.
- The paper's practitioner takeaway is strong.
- Journal format gives space for detector details, artifact documentation, and the incident appendix.

How to shape it:

- Expand the secure-code-generation and developer-tooling literature review.
- Add a reproducibility appendix.
- Add manual validation of detector precision on a sample.
- Present CodeCoach origin as motivation, not the main system contribution.

Risk:

- Review cycle may be slower.
- The paper may need more engineering/practice grounding than the current draft.

## Not Recommended as Primary Path

| Venue/path | Reason |
| --- | --- |
| SOUPS poster | Too small for the current artifact. Good for feedback, but not the main publication path. |
| ACM CCS main | The contribution is likely too narrow without a broader threat model, real-world deployment, or stronger attack/defense system. |
| IEEE TDSC | Possible only after adding a more dependable-security systems evaluation. Current draft is too measurement/prompt-policy focused. |
| IEEE TIFS | Weak fit; the work is not primarily forensics, signal security, biometrics, or multimedia security. |

## Recommended Next Work

### Immediate polish pass

1. Verify citations.
2. Rebuild `paper/arxiv/paper.pdf`.
3. Decide whether Section 6 remains in the main paper.
4. Add detector validation: manually audit a stratified sample of outputs.
5. Freeze final data and publish Zenodo v2.

### If targeting AISec

1. Convert to ACM format.
2. Compress to the workshop page limit.
3. Move the instruction-decay case study to appendix.
4. Submit as an empirical security measurement paper with artifact.

### If targeting TMLR

1. Convert to TMLR template.
2. Anonymize author, repo, Zenodo, and incident references.
3. Reframe title/abstract around instruction-following behavior.
4. Either remove the incident case study or add a controlled instruction-decay experiment.

### If targeting JISA

1. Keep full length.
2. Expand secure-code-generation literature.
3. Add detector-validation table.
4. Include stronger practitioner guidance for maintaining `AGENTS.md`, `CLAUDE.md`, and `.cursorrules`.

## Current Recommendation

Submit first to **AISec @ CCS 2026** if the goal is peer-reviewed archival publication this year. If the goal is a stricter proper-conference paper, use this dataset as the base for an **ACSAC 2027 / applied-security** submission and add detector validation plus one ecological-validity extension. In parallel, prepare a cleaner **TMLR** version only if the paper is reframed around instruction-following behavior rather than secure-code practice.
