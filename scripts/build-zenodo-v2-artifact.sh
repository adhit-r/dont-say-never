#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import zipfile

repo_root = Path.cwd()
dist_dir = repo_root / "dist"
zip_path = dist_dir / "dont-say-never-zenodo-v2-artifact.zip"
sha_path = dist_dir / "dont-say-never-zenodo-v2-artifact.zip.sha256"
sha256sums = repo_root / "SHA256SUMS"

exclude_exact = {
    ".DS_Store",
    "paper/arxiv/Archive.zip",
}


def should_skip(path: str) -> bool:
    parts = Path(path).parts
    return path in exclude_exact or "__pycache__" in parts or ".DS_Store" in parts


members: list[str] = []
for line in sha256sums.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split(None, 1)
    if len(parts) != 2:
        raise SystemExit(f"Malformed SHA256SUMS line: {line!r}")
    path = parts[1].lstrip("*")
    if should_skip(path):
        continue
    members.append(path)

members = sorted(dict.fromkeys(members))

missing = [path for path in members if not (repo_root / path).is_file()]
if missing:
    raise SystemExit("Missing files referenced by SHA256SUMS:\n" + "\n".join(missing))

dist_dir.mkdir(parents=True, exist_ok=True)
if zip_path.exists():
    zip_path.unlink()
if sha_path.exists():
    sha_path.unlink()

fixed_dt = (1980, 1, 1, 0, 0, 0)
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
    for rel_path in members:
        abs_path = repo_root / rel_path
        data = abs_path.read_bytes()
        info = zipfile.ZipInfo(rel_path, date_time=fixed_dt)
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        zf.writestr(info, data)

with zipfile.ZipFile(zip_path) as zf:
    zipped_members = [info.filename for info in zf.infolist() if not info.is_dir()]
    if zipped_members != members:
        raise SystemExit(
            "Zip members do not match the SHA256SUMS surface:\n"
            f"expected: {len(members)}\n"
            f"actual:   {len(zipped_members)}"
        )

digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
sha_path.write_text(
    f"{digest}  dist/dont-say-never-zenodo-v2-artifact.zip\n",
    encoding="utf-8",
)

print(f"Wrote {zip_path} ({len(members)} files)")
print(f"Wrote {sha_path}")
PY
