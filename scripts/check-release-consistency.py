#!/usr/bin/env python3
"""Cheap release-surface consistency checks for the current paper package."""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TITLE = (
    "Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: "
    "A Multi-Model Study of Positive vs. Prohibition Framing"
)

ACTIVE_TITLE_CHECKS = {
    "README.md": "# " + TITLE,
    "ARTIFACT_README.md": TITLE,
    "paper/arxiv/paper.tex": "Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents",
    "paper/arxiv/abstract.txt": "2,160 valid orchestration rows",
}

FORBIDDEN_RELEASE_PATHS = {
    "paper/arxiv/Archive.zip",
    "paper/framing-paper.tex",
    "paper/paper-draft.md",
    "paper/paper-final.md",
    "paper/paper-v3.md",
    "paper/paper-v4.html",
    "paper/paper-v4.md",
    "paper/paper-v4.pdf",
    "paper/paper-v4.tex",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def check_active_titles() -> None:
    for rel_path, expected in ACTIVE_TITLE_CHECKS.items():
        text = read(rel_path)
        if expected not in text:
            fail(f"{rel_path} does not contain expected current title text")

    metadata = json.loads(read(".zenodo.json"))
    if metadata.get("title") != TITLE:
        fail(".zenodo.json title does not match current paper title")


def check_manifest_surface() -> None:
    manifest = read("SHA256SUMS")
    for forbidden in sorted(FORBIDDEN_RELEASE_PATHS):
        if forbidden in manifest:
            fail(f"SHA256SUMS includes non-release path: {forbidden}")


def check_stale_archives_absent() -> None:
    archive = ROOT / "paper" / "arxiv" / "Archive.zip"
    if archive.exists():
        with zipfile.ZipFile(archive) as zf:
            names = "\n".join(zf.namelist())
            sample = ""
            for name in zf.namelist():
                if name.endswith((".tex", ".bib", ".md", ".txt")):
                    sample += zf.read(name).decode("utf-8", errors="replace")[:5000]
            fail(
                "paper/arxiv/Archive.zip exists; remove or rebuild it before release. "
                f"Members: {names[:500]} Sample: {sample[:500]}"
            )


def check_dist_zip_surface() -> None:
    zip_path = ROOT / "dist" / "dont-say-never-zenodo-v2-artifact.zip"
    if not zip_path.exists():
        return
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    for forbidden in sorted(FORBIDDEN_RELEASE_PATHS):
        if forbidden in names:
            fail(f"dist zip includes non-release path: {forbidden}")


def main() -> int:
    check_active_titles()
    check_manifest_surface()
    check_stale_archives_absent()
    check_dist_zip_surface()
    print("Release consistency checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
