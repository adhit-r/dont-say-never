# Canva Redesign Brief

Use this brief if rebuilding the poster directly in Canva.

## Poster Setup

- Format: A4 landscape for SOUPS submission review.
- Title: Security Rules Work: A Multi-Model Study of LLM Coding Agent Guardrails
- Author line: Adhithya Rajasekaran · Axonome · adhithya@axonome.xyz · ORCID 0009-0004-1682-7958
- Style: clean academic security poster, high contrast, practical, not marketing-like.

## Visual System

- Background: white.
- Main text: charcoal `#111827`.
- Muted text: slate `#475569`.
- Borders: light blue-gray `#d9e1e8`.
- Accent: teal `#0f766e` / dark teal `#134e4a`.
- Warning/accent labels only where needed: amber `#92400e`, red `#b91c1c`, green `#166534`.
- Font: simple sans-serif such as Arial, Inter, Helvetica, or Source Sans.
- Avoid gradients, purple, decorative blobs, or generic AI imagery.

## Layout

Top header:

- Large title left.
- Small SOUPS 2026 badge right.
- Teal horizontal divider below header.

Three-column body:

1. Left column: Problem, Experiment, Model Set.
2. Middle column: Main finding figure and compact rule-effect table.
3. Right column: Polarity heatmap, interpretation, practitioner takeaways.

Footer:

- Ethics note.
- Detection note.
- Artifact availability note.

## Required Figures

- `../../figures/fig-pro-gpt-vs-claude-bars.png`
- `../../figures/fig-pro-polarity-heatmap.png`

## Core Copy

Main claim:

Security rules reduced vulnerable code on every model. Positive framing was not reliably safer than prohibition framing.

Practitioner takeaways:

- Add targeted rules for known CWE classes.
- Measure prompts against your actual agent stack.
- Treat instruction files as security-critical artifacts.

Ethics:

No human subjects were studied. The experiment uses synthetic prompts and model-generated code.
