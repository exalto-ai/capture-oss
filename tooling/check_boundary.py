#!/usr/bin/env python3
"""Reject runtime dependencies that escape the publishable subtree."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH_DEPENDENCY = re.compile(r"\bpath\s*=\s*['\"]([^'\"]+)['\"]")
SOURCE_INCLUDE = re.compile(
    r"\b(?:include_str|include_bytes)!\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
)
IGNORED_DIRECTORIES = {".git", "target", "node_modules", ".vitest-attachments", ".venv", "__pycache__"}
SENSITIVE_SUFFIXES = {".key", ".llmcapture", ".llmbundle", ".sqlite"}


def publishable_paths():
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in IGNORED_DIRECTORIES for part in relative.parts):
            continue
        yield path


def inside_runtime(path: pathlib.Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(ROOT)
    except (FileNotFoundError, ValueError):
        return False
    return True


def git_repository_and_pathspec(root: pathlib.Path) -> tuple[pathlib.Path, str]:
    """Locate the containing checkout and address root from that checkout."""
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    )
    repository = pathlib.Path(result.stdout.strip()).resolve()
    try:
        relative = root.resolve().relative_to(repository)
    except ValueError as error:
        raise RuntimeError(f"runtime root {root} is outside Git checkout {repository}") from error
    return repository, "." if relative == pathlib.Path(".") else relative.as_posix()


def main() -> int:
    failures: list[str] = []
    for required in ["LICENSE-MIT", "THIRD-PARTY-NOTICES.md", "vendor/tlsn/LICENSE-APACHE", "vendor/tlsn/LICENSE-MIT"]:
        if not (ROOT / required).is_file():
            failures.append(f"required publication notice is missing: {required}")

    for path in publishable_paths():
        if path.is_symlink():
            failures.append(f"symlink is not publishable: {path.relative_to(ROOT)}")
        if path.is_file() and (path.name == ".env" or path.suffix in SENSITIVE_SUFFIXES):
            failures.append(f"sensitive artifact is not publishable: {path.relative_to(ROOT)}")

    for manifest in (path for path in publishable_paths() if path.name == "Cargo.toml"):
        for relative in PATH_DEPENDENCY.findall(manifest.read_text(encoding="utf-8")):
            target = manifest.parent / relative
            if not inside_runtime(target):
                failures.append(
                    f"path dependency escapes or is missing: {manifest.relative_to(ROOT)} -> {relative}"
                )

    for source in (path for path in publishable_paths() if path.suffix == ".rs"):
        for relative in SOURCE_INCLUDE.findall(source.read_text(encoding="utf-8")):
            target = source.parent / relative
            if not inside_runtime(target):
                failures.append(
                    f"source include escapes or is missing: {source.relative_to(ROOT)} -> {relative}"
                )

    try:
        repository, pathspec = git_repository_and_pathspec(ROOT)
        staged = subprocess.run(
            ["git", "-C", str(repository), "ls-files", "--stage", "--", pathspec],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        for line in staged.splitlines():
            if line.startswith("160000 "):
                failures.append(f"git submodule is not publishable: {line.split(chr(9), 1)[-1]}")
    except (FileNotFoundError, RuntimeError, subprocess.CalledProcessError) as error:
        failures.append(f"could not inspect the Git index: {error}")

    forbidden = ["../platform", "../.github"]
    for path in publishable_paths():
        if path == pathlib.Path(__file__).resolve():
            continue
        if not path.is_file() or path.is_symlink() or path.suffix in {".png", ".woff", ".woff2"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        has_private_key_block = (
            "-----BEGIN PRIVATE KEY-----" in text and "-----END PRIVATE KEY-----" in text
        ) or (
            "-----BEGIN OPENSSH PRIVATE KEY-----" in text
            and "-----END OPENSSH PRIVATE KEY-----" in text
        )
        if has_private_key_block:
            failures.append(f"private key material in {path.relative_to(ROOT)}")
        for marker in forbidden:
            if marker in text:
                failures.append(f"private-tree reference in {path.relative_to(ROOT)}: {marker}")

    if failures:
        print("Runtime boundary check failed:", file=sys.stderr)
        for failure in sorted(set(failures)):
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Runtime boundary is self-contained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
