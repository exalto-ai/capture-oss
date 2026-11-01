#!/usr/bin/env python3
"""Run the bounded OpenCode + OpenRouter production canary."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESULT_FORMAT = "ecp/opencode-e2e-result/v1"
MANIFEST_NAME = "fixture.json"
DEFAULT_MODEL = "openrouter/cohere/north-mini-code:free"
SHARE_VISIBILITY = "listed"
PLAIN_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")
TERMINAL_OPERATION_STATES = {"succeeded", "failed", "interrupted"}
TERMINAL_SHARE_STATES = {"shared", "rejected", "failed"}
SENSITIVE_ENV_NAME = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|COOKIE|WEBHOOK|CREDENTIAL|AUTH)", re.IGNORECASE
)
DISCLOSURE_RULES = {
    "api_key": re.compile(
        r"\b(?:sk-(?:or-)?v?\d?[-_A-Za-z0-9]{16,}|(?:llmn_v1_|notary_key_)[A-Za-z0-9_]{24,})\b",
        re.IGNORECASE,
    ),
    "authorization_value": re.compile(
        r"\bauthorization\s*[:=]\s*(?:bearer|basic)\s+\S+", re.IGNORECASE
    ),
    "cookie_value": re.compile(
        r"\b(?:cookie|set-cookie)\s*[:=]\s*\S+", re.IGNORECASE
    ),
    "private_key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "home_or_runner_path": re.compile(
        r"(?:/Users/[^/\s]+/|/home/runner/|[A-Z]:\\Users\\[^\\\s]+\\|RUNNER_TEMP)",
        re.IGNORECASE,
    ),
    "email_address": re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE
    ),
    "environment_dump": re.compile(
        r"(?m)^(?:OPENROUTER|NOTARYD|NOTARY_API|NOTARY_SERVER|GITHUB|ACTIONS|AWS|AZURE)_[A-Z0-9_]+="
    ),
}


class CanaryFailure(RuntimeError):
    def __init__(self, stage: str, code: str):
        super().__init__(f"{stage}: {code}")
        self.stage = stage
        self.code = code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def elapsed_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def private_write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(value)


def private_write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)


def cleanup_private_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def scrub_agent_environment(source: dict[str, str], provider_key: str) -> dict[str, str]:
    environment = scrub_sensitive_environment(source)
    environment.update(
        {
            "OPENROUTER_FREE_TIER_API_KEY": provider_key,
            # OpenCode's built-in provider may consult this conventional name.
            # It is deliberately mapped to the free-tier key only in the child.
            "OPENROUTER_API_KEY": provider_key,
        }
    )
    return environment


def scrub_sensitive_environment(source: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in source.items()
        if not SENSITIVE_ENV_NAME.search(name)
    }


def command_version(command: str, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            [command, *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    lines = completed.stdout.strip().splitlines()
    return lines[0][:120] if lines else "unknown"


def safe_run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def run_json(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    stage: str,
    code: str,
) -> dict[str, Any]:
    try:
        completed = safe_run(command, cwd=cwd, env=env, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise CanaryFailure(stage, code) from error
    if completed.returncode != 0:
        raise CanaryFailure(stage, code)
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanaryFailure(stage, code) from error
    if not isinstance(value, dict):
        raise CanaryFailure(stage, code)
    return value


def http_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Accept": "application/json", **(headers or {})},
        method=method,
    )
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("expected an object response")
    return value


def validate_model_metadata(payload: dict[str, Any], expected_slug: str) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict) or data.get("id") != expected_slug:
        raise CanaryFailure("model_preflight", "model_unavailable")
    supported = data.get("supported_parameters")
    if not isinstance(supported, list) or "tools" not in supported:
        raise CanaryFailure("model_preflight", "model_missing_tool_support")
    pricing = data.get("pricing")
    if not isinstance(pricing, dict):
        raise CanaryFailure("model_preflight", "model_pricing_unknown")
    for field in ("prompt", "completion"):
        try:
            zero = float(pricing.get(field)) == 0
        except (TypeError, ValueError):
            zero = False
        if not zero:
            raise CanaryFailure("model_preflight", "model_not_free")
    request_price = pricing.get("request")
    if request_price is not None:
        try:
            request_is_zero = float(request_price) == 0
        except (TypeError, ValueError):
            request_is_zero = False
        if not request_is_zero:
            raise CanaryFailure("model_preflight", "model_not_free")
    return {
        "id": data["id"],
        "canonical_slug": data.get("canonical_slug"),
        "supports_tools": True,
        "pricing": {"prompt": "0", "completion": "0", "request": "0"},
    }


def preflight_model(model: str, provider_key: str) -> dict[str, Any]:
    prefix = "openrouter/"
    if not model.startswith(prefix) or not model.endswith(":free"):
        raise CanaryFailure("model_preflight", "model_not_free")
    slug = model.removeprefix(prefix)
    url = "https://openrouter.ai/api/v1/model/" + urllib.parse.quote(
        slug, safe="/:"
    )
    try:
        payload = http_json(
            url,
            headers={"Authorization": f"Bearer {provider_key}"},
            timeout=30,
        )
    except urllib.error.HTTPError as error:
        code = "provider_auth_failed" if error.code in (401, 403) else "model_unavailable"
        raise CanaryFailure("model_preflight", code) from error
    except (OSError, ValueError) as error:
        raise CanaryFailure("model_preflight", "model_unavailable") from error
    return validate_model_metadata(payload, slug)


def parse_opencode_events(raw: bytes) -> dict[str, Any]:
    if len(raw) > 32 * 1024 * 1024:
        raise CanaryFailure("agent", "agent_output_too_large")
    summary = {
        "event_count": 0,
        "event_types": {},
        "part_types": {},
        "finish_reasons": {},
        "agent_steps": 0,
        "tool_calls": 0,
        "text_characters": 0,
        "error_events": 0,
        "tokens": {
            "input": 0,
            "output": 0,
            "reasoning": 0,
            "cache_read": 0,
            "cache_write": 0,
        },
    }
    for encoded_line in raw.splitlines():
        try:
            event = json.loads(encoded_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(event, dict):
            continue
        summary["event_count"] += 1
        event_type = str(event.get("type", ""))
        part = event.get("part") if isinstance(event.get("part"), dict) else {}
        part_type = str(part.get("type", ""))
        if event_type:
            summary["event_types"][event_type] = summary["event_types"].get(event_type, 0) + 1
        if part_type:
            summary["part_types"][part_type] = summary["part_types"].get(part_type, 0) + 1
        reason = part.get("reason")
        if isinstance(reason, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", reason):
            summary["finish_reasons"][reason] = summary["finish_reasons"].get(reason, 0) + 1
        text_value = part.get("text")
        if isinstance(text_value, str):
            summary["text_characters"] += len(text_value)
        if event_type in ("step_finish", "step-finish") or part_type == "step-finish":
            summary["agent_steps"] += 1
            tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else {}
            for field in ("input", "output", "reasoning", "cache_read", "cache_write"):
                value = tokens.get(field, 0)
                if isinstance(value, int) and value >= 0:
                    summary["tokens"][field] += value
        if event_type in ("tool_use", "tool-use") or part_type == "tool":
            summary["tool_calls"] += 1
        if "error" in event_type.lower() or part_type == "error":
            summary["error_events"] += 1
    return summary


def extract_retry_after_seconds(raw: bytes) -> int:
    text = raw.decode("utf-8", errors="ignore")
    match = re.search(
        r"retry[- ]after[^0-9]{0,40}([0-9]{1,4})", text, re.IGNORECASE
    )
    return min(int(match.group(1)), 300) if match else 60


def scan_disclosure(value: Any) -> dict[str, int]:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return {
        name: len(pattern.findall(encoded))
        for name, pattern in DISCLOSURE_RULES.items()
        if pattern.search(encoded)
    }


def validate_changed_files(files: list[str], allowed: set[str]) -> bool:
    return bool(files) and set(files) == allowed and len(files) == len(set(files))


def load_fixture(path: Path) -> dict[str, Any]:
    """Read and strictly validate one fixture manifest.

    The allowlist is a safety gate, not configuration: a malformed manifest must fail the run
    rather than fall back to a permissive default, because these traces are published publicly.
    """

    manifest_path = path / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CanaryFailure("fixture", "fixture_manifest_unreadable") from error
    if not isinstance(manifest, dict):
        raise CanaryFailure("fixture", "fixture_manifest_invalid")

    version = manifest.get("version")
    summary = manifest.get("summary")
    allowed = manifest.get("allowed_files")
    command = manifest.get("test_command")
    if not isinstance(version, str) or not version.strip():
        raise CanaryFailure("fixture", "fixture_manifest_invalid")
    if not isinstance(summary, str) or not summary.strip():
        raise CanaryFailure("fixture", "fixture_manifest_invalid")
    if not isinstance(allowed, list) or not allowed:
        raise CanaryFailure("fixture", "fixture_manifest_invalid")
    if not isinstance(command, list) or not command:
        raise CanaryFailure("fixture", "fixture_manifest_invalid")
    if any(not isinstance(item, str) or not item for item in command):
        raise CanaryFailure("fixture", "fixture_manifest_invalid")
    for name in allowed:
        # A path separator, parent reference, or glob would widen the exact-diff gate.
        if not isinstance(name, str) or not PLAIN_FILENAME.match(name) or name in {".", ".."}:
            raise CanaryFailure("fixture", "fixture_manifest_invalid")
        if not (path / name).is_file():
            raise CanaryFailure("fixture", "fixture_manifest_invalid")
    if len(set(allowed)) != len(allowed):
        raise CanaryFailure("fixture", "fixture_manifest_invalid")

    return {
        "name": path.name,
        "path": path,
        "version": version,
        "summary": summary,
        "allowed_files": set(allowed),
        "test_command": list(command),
    }


def discover_fixtures(root: Path) -> list[Path]:
    return sorted(
        child for child in root.iterdir() if child.is_dir() and (child / MANIFEST_NAME).is_file()
    )


def select_fixture(arguments: argparse.Namespace) -> dict[str, Any]:
    """Pin the requested fixture, or pick one uniformly at random from the library."""

    if arguments.fixture:
        return load_fixture(Path(arguments.fixture).resolve())
    root = Path(arguments.fixtures).resolve()
    if not root.is_dir():
        raise CanaryFailure("fixture", "fixture_library_missing")
    candidates = discover_fixtures(root)
    if not candidates:
        raise CanaryFailure("fixture", "fixture_library_missing")
    seed = os.environ.get("CAPTURED_E2E_FIXTURE_SEED")
    chooser = random.Random(seed) if seed else random.SystemRandom()
    return load_fixture(chooser.choice(candidates))


def classify_provider_failure(traces: list[dict[str, Any]]) -> str | None:
    statuses = {item.get("http_status") for item in traces}
    if 429 in statuses:
        return "provider_rate_limited"
    if 503 in statuses:
        return "model_unavailable"
    if statuses.intersection({401, 403}):
        return "provider_auth_failed"
    return None


def classify_attempt_failure(
    traces: list[dict[str, Any]],
    exit_code: int,
    tool_calls: int,
    task_completed: bool,
) -> tuple[str, bool]:
    provider_failure = classify_provider_failure(traces)
    if provider_failure is not None:
        return provider_failure, provider_failure in {
            "provider_rate_limited",
            "model_unavailable",
        }
    if (
        exit_code != 0
        and task_completed
        and traces
        and all(
            item.get("http_status") == 200 and item.get("notarization_eligible")
            for item in traces
        )
    ):
        return "agent_post_task_error", True
    if exit_code == 0 and tool_calls == 0 and traces:
        return "agent_no_tool_call", True
    return "agent_task_failed", False


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def toml_string(value: Path | str) -> str:
    return json.dumps(str(value))


def write_daemon_config(root: Path, proxy_port: int, admin_port: int) -> Path:
    config = root / "daemon" / "config.toml"
    source = f"""format = "ecp/captured-config/v1"

[proxy]
listen = "127.0.0.1:{proxy_port}"
max_attestable_http_bytes = 16777216

[admin]
listen = "127.0.0.1:{admin_port}"

[storage]
checkpoint_dir = {toml_string(root / "private" / "capture-checkpoints")}
package_dir = {toml_string(root / "private" / "trace-packages")}

[metadata]
path = {toml_string(root / "private" / "metadata.db")}
prompt_preview_chars = 0
output_preview_chars = 0
full_text_search = false
"""
    private_write(config, source)
    return config


def wait_for_daemon(origin: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CanaryFailure("daemon_start", "daemon_start_failed")
        try:
            health = http_json(f"{origin}/healthz", timeout=2)
            if health.get("service") == "captured":
                return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise CanaryFailure("daemon_start", "daemon_start_failed")


def git_output(repository: Path, *arguments: str) -> bytes:
    completed = safe_run(["git", *arguments], cwd=repository, timeout=30)
    if completed.returncode != 0:
        raise CanaryFailure("fixture", "fixture_git_failed")
    return completed.stdout


def initialize_fixture(fixture: Path, destination: Path) -> None:
    shutil.copytree(fixture, destination)
    git_output(destination, "init", "--quiet")
    git_output(destination, "config", "user.name", "Notary Canary")
    git_output(destination, "config", "user.email", "canary@example.invalid")
    git_output(destination, "add", "--all")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Notary Canary",
            "GIT_AUTHOR_EMAIL": "canary@example.invalid",
            "GIT_COMMITTER_NAME": "Notary Canary",
            "GIT_COMMITTER_EMAIL": "canary@example.invalid",
            "GIT_AUTHOR_DATE": "2025-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2025-01-01T00:00:00Z",
        }
    )
    committed = safe_run(
        ["git", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture"],
        cwd=destination,
        env=environment,
        timeout=30,
    )
    if committed.returncode != 0:
        raise CanaryFailure("fixture", "fixture_git_failed")


def changed_files(repository: Path) -> tuple[list[str], dict[str, int]]:
    changed = git_output(repository, "diff", "--name-only", "--diff-filter=ACMRTUXB")
    untracked = git_output(repository, "ls-files", "--others", "--exclude-standard")
    files = sorted(
        {
            line
            for line in (changed + untracked).decode("utf-8", errors="strict").splitlines()
            if line
        }
    )
    stats = {"added_lines": 0, "deleted_lines": 0}
    numstat = git_output(repository, "diff", "--numstat")
    for line in numstat.decode("utf-8", errors="strict").splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        stats["added_lines"] += int(parts[0])
        stats["deleted_lines"] += int(parts[1])
    return files, stats


def trace_record(item: dict[str, Any], attempt: int) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "trace_id": item.get("trace_id"),
        "created_at_unix_ms": item.get("created_at_unix_ms"),
        "capture_status": item.get("capture_status"),
        "notarization_eligible": bool(item.get("notarization_eligible")),
        "notarization_ineligibility_code": item.get("notarization_ineligibility_code"),
        "failure_code": item.get("failure_code"),
        "http_status": item.get("http_status"),
        "streaming": bool(item.get("streaming")),
        "requested_model": item.get("requested_model"),
        "response_model": item.get("response_model"),
        "request_bytes": item.get("request_bytes"),
        "response_bytes": item.get("response_bytes"),
        "capture_duration_ms": item.get("duration_ms"),
    }


class Canary:
    def __init__(self, arguments: argparse.Namespace, root: Path, fixture: dict[str, Any]):
        self.arguments = arguments
        self.root = root
        self.fixture = fixture
        self.provider_key = os.environ.get("OPENROUTER_FREE_TIER_API_KEY", "")
        self.platform_key = os.environ.get("CAPTURED_E2E_API_KEY", "")
        self.proxy_port = free_port()
        self.admin_port = free_port()
        self.admin_origin = f"http://127.0.0.1:{self.admin_port}"
        self.config = write_daemon_config(root, self.proxy_port, self.admin_port)
        self.daemon: subprocess.Popen[bytes] | None = None
        # The daemon only needs the dedicated platform credential below. Do not
        # let unrelated credentials from a developer shell or Actions runner
        # enter its process environment.
        self.environment = scrub_sensitive_environment(os.environ)
        self.environment.update(
            {
                "XDG_CONFIG_HOME": str(root / "xdg" / "config"),
                "XDG_DATA_HOME": str(root / "xdg" / "data"),
                "XDG_CACHE_HOME": str(root / "xdg" / "cache"),
                # ProjectDirs does not honor XDG_CONFIG_HOME on macOS. This
                # explicit override also prevents a personal OS-keychain vault
                # from being opened during a local canary.
                "CAPTURED_CONFIG_DIR": str(root / "xdg" / "vault"),
                "CAPTURED_VAULT_PASSPHRASE_FILE": str(root / "private" / "vault-passphrase"),
                "CAPTURED_PLATFORM_API_KEY_FILE": str(root / "private" / "platform-api-key"),
            }
        )
        self.cli = [
            arguments.capture,
            "--json",
            "--config",
            str(self.config),
        ]

    def start_daemon(self) -> None:
        if not self.provider_key:
            raise CanaryFailure("configuration", "provider_key_missing")
        if not self.platform_key:
            raise CanaryFailure("configuration", "platform_key_missing")
        private_write(self.root / "private" / "vault-passphrase", os.urandom(32).hex())
        private_write(self.root / "private" / "platform-api-key", self.platform_key)
        try:
            self.daemon = subprocess.Popen(
                [self.arguments.captured, "--config", str(self.config)],
                env=self.environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise CanaryFailure("daemon_start", "daemon_start_failed") from error
        wait_for_daemon(self.admin_origin, self.daemon)
        account = run_json(
            [*self.cli, "account", "show"],
            env=self.environment,
            stage="daemon_start",
            code="platform_auth_failed",
        )
        if not account.get("signed_in") or account.get("credential_kind") != "api_key":
            raise CanaryFailure("daemon_start", "platform_auth_failed")

    def stop_daemon(self) -> None:
        if self.daemon is None or self.daemon.poll() is not None:
            return
        self.daemon.terminate()
        try:
            self.daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.daemon.kill()
            self.daemon.wait(timeout=5)

    def traces(self) -> list[dict[str, Any]]:
        response = run_json(
            [*self.cli, "traces", "list", "--provider", "openrouter", "--limit", "100"],
            env=self.environment,
            stage="trace",
            code="trace_list_failed",
        )
        items = response.get("items")
        if not isinstance(items, list):
            raise CanaryFailure("trace", "trace_list_failed")
        return [item for item in items if isinstance(item, dict)]

    def wait_for_new_traces(self, previous_ids: set[str]) -> list[dict[str, Any]]:
        deadline = time.monotonic() + 30
        current: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            current = [
                item
                for item in self.traces()
                if item.get("trace_id") not in previous_ids
            ]
            if current and all(
                item.get("capture_status") not in {"capturing", "running"}
                for item in current
            ):
                return current
            time.sleep(1)
        return current

    def run_attempt(self, number: int, result: dict[str, Any]) -> dict[str, Any]:
        repository = self.root / f"fixture-attempt-{number}"
        initialize_fixture(self.fixture["path"], repository)
        test_command = self.fixture["test_command"]
        tests = safe_run(test_command, cwd=repository, timeout=30)
        if tests.returncode == 0:
            raise CanaryFailure("fixture", "fixture_did_not_fail_initially")
        before_ids = {
            str(item.get("trace_id"))
            for item in self.traces()
            if item.get("trace_id")
        }
        task = (repository / "TASK.md").read_text(encoding="utf-8")
        agent_environment = scrub_agent_environment(self.environment, self.provider_key)
        agent_environment.update(
            {
                "OPENCODE_CONFIG": str(repository / "opencode.json"),
                "OPENCODE_CONFIG_DIR": str(self.root / "opencode" / f"attempt-{number}" / "config"),
                "OPENCODE_DISABLE_AUTOUPDATE": "true",
                "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
                "OPENCODE_DISABLE_LSP_DOWNLOAD": "true",
                "OPENCODE_DISABLE_MODELS_FETCH": "true",
                "OPENCODE_DISABLE_CLAUDE_CODE": "true",
                "CAPTURED_E2E_OPENROUTER_BASE_URL": f"http://127.0.0.1:{self.proxy_port}/openrouter/api/v1",
            }
        )
        started = time.monotonic()
        try:
            opencode = safe_run(
                [
                    self.arguments.opencode,
                    "--pure",
                    "run",
                    "--format",
                    "json",
                    "--auto",
                    "--model",
                    self.arguments.model,
                    "--agent",
                    "canary",
                    "--dir",
                    str(repository),
                    "--title",
                    f"Notary {self.fixture['name']} canary",
                    task,
                ],
                cwd=repository,
                env=agent_environment,
                timeout=self.arguments.agent_timeout,
            )
            exit_code = opencode.returncode
            event_summary = parse_opencode_events(opencode.stdout)
            retry_after = extract_retry_after_seconds(opencode.stdout + opencode.stderr)
        except subprocess.TimeoutExpired:
            exit_code = 124
            event_summary = parse_opencode_events(b"")
            retry_after = 60
        opencode_wall_ms = elapsed_ms(started)
        final_tests = safe_run(test_command, cwd=repository, timeout=30)
        files, stats = changed_files(repository)
        new_traces = self.wait_for_new_traces(before_ids)
        new_traces.sort(key=lambda item: int(item.get("created_at_unix_ms") or 0))
        records = [trace_record(item, number) for item in new_traces]
        result["traces"].extend(records)
        task_completed = final_tests.returncode == 0 and validate_changed_files(
            files, self.fixture["allowed_files"]
        )
        functional_pass = exit_code == 0 and task_completed
        eligible = [item for item in new_traces if item.get("notarization_eligible")]
        summary = {
            "attempt": number,
            "initial_tests_failed": True,
            "opencode_exit_code": exit_code,
            "opencode_wall_ms": opencode_wall_ms,
            "final_tests_passed": final_tests.returncode == 0,
            "changed_files": files,
            "diff_allowlist_passed": validate_changed_files(
                files, self.fixture["allowed_files"]
            ),
            "diff_stats": stats,
            "trace_count": len(new_traces),
            "eligible_trace_count": len(eligible),
            **event_summary,
        }
        result["attempts"].append(summary)
        if not functional_pass:
            code, retryable = classify_attempt_failure(
                new_traces,
                exit_code,
                event_summary["tool_calls"],
                task_completed,
            )
            return {
                "passed": False,
                "transient": retryable,
                "failure_code": code,
                "retry_after": 0 if code == "agent_post_task_error" else retry_after,
                "traces": new_traces,
            }
        if not new_traces:
            return {
                "passed": False,
                "transient": False,
                "failure_code": "no_trace",
                "retry_after": retry_after,
                "traces": [],
            }
        if not eligible:
            transient = classify_provider_failure(new_traces)
            return {
                "passed": False,
                "transient": transient is not None,
                "failure_code": transient or "no_eligible_trace",
                "retry_after": retry_after,
                "traces": new_traces,
            }
        return {"passed": True, "traces": new_traces, "eligible": eligible}

    def validate_provenance(
        self, traces: list[dict[str, Any]], preflight: dict[str, Any]
    ) -> None:
        expected = self.arguments.model.removeprefix("openrouter/")
        returned = {expected}
        canonical = preflight.get("canonical_slug")
        if isinstance(canonical, str):
            returned.add(canonical)
        for trace in traces:
            if trace.get("provider") != "openrouter":
                raise CanaryFailure("provenance", "unexpected_provider")
            if trace.get("requested_model") != expected:
                raise CanaryFailure("provenance", "unexpected_model")
            response_model = trace.get("response_model")
            if response_model is not None and response_model not in returned:
                raise CanaryFailure("provenance", "unexpected_model")

    def seal_verify_share(
        self, eligible: list[dict[str, Any]], result: dict[str, Any]
    ) -> None:
        for trace in eligible:
            trace_id = trace.get("trace_id")
            if not isinstance(trace_id, str):
                raise CanaryFailure("notarization", "notarization_failed")
            queued = run_json(
                [*self.cli, "traces", "seal", trace_id, "--wait"],
                env=self.environment,
                timeout=self.arguments.notarization_timeout,
                stage="notarization",
                code="notarization_failed",
            )
            operation = queued.get("operation")
            if not isinstance(operation, dict) or not isinstance(
                operation.get("operation_id"), str
            ):
                raise CanaryFailure("notarization", "notarization_failed")
            operation_id = operation["operation_id"]
            if operation.get("state") != "succeeded":
                raise CanaryFailure(
                    "notarization", operation.get("failure_code") or "notarization_failed"
                )
            created = operation.get("created_at_unix_ms")
            started = operation.get("started_at_unix_ms")
            completed = operation.get("completed_at_unix_ms")
            queue_wait = (
                max(0, started - created)
                if isinstance(created, int) and isinstance(started, int)
                else None
            )
            proof_wall = (
                max(0, completed - started)
                if isinstance(started, int) and isinstance(completed, int)
                else None
            )
            verified = run_json(
                [*self.cli, "traces", "verify", trace_id],
                env=self.environment,
                timeout=120,
                stage="private_verification",
                code="private_verify_failed",
            )
            if verified.get("outcome") != "passed":
                raise CanaryFailure("private_verification", "private_verify_failed")
            trace = run_json(
                [*self.cli, "traces", "show", trace_id],
                env=self.environment,
                timeout=120,
                stage="disclosure_gate",
                code="disclosure_gate_failed",
            )
            violations = scan_disclosure(trace)
            if violations:
                result["disclosure_violations"] = violations
                raise CanaryFailure("disclosure_gate", "disclosure_gate_failed")
            result["notarizations"].append(
                {
                    "trace_id": trace_id,
                    "operation_id": operation_id,
                    "queue_wait_ms": queue_wait,
                    "proof_wall_ms": proof_wall,
                    "locally_verified": True,
                    "disclosure_gate_passed": True,
                }
            )
            submitted_at = time.monotonic()
            share = run_json(
                [
                    *self.cli,
                    "traces",
                    "share",
                    trace_id,
                    "--visibility",
                    SHARE_VISIBILITY,
                    "--force",
                ],
                env=self.environment,
                timeout=120,
                stage="sharing",
                code="share_failed",
            )
            if share.get("trace_id") != trace_id:
                raise CanaryFailure("sharing", "share_failed")
            deadline = time.monotonic() + self.arguments.share_timeout
            status = share
            while status.get("progress") not in TERMINAL_SHARE_STATES:
                if time.monotonic() >= deadline:
                    raise CanaryFailure("sharing", "share_timeout")
                time.sleep(2)
                try:
                    status = http_json(
                        f"{self.admin_origin}/v1/traces/{urllib.parse.quote(trace_id)}/share",
                        timeout=15,
                    )
                except urllib.error.HTTPError as error:
                    if error.code == 503:
                        continue
                    raise CanaryFailure("sharing", "share_failed") from error
                except (OSError, ValueError) as error:
                    raise CanaryFailure("sharing", "share_failed") from error
            if status.get("progress") != "shared":
                raise CanaryFailure(
                    "sharing", status.get("failure_code") or "share_failed"
                )
            package_url = status.get("package_url")
            share_url = status.get("share_url")
            if not isinstance(package_url, str) or not isinstance(share_url, str):
                raise CanaryFailure("sharing", "share_failed")
            package_path = self.root / "public-downloads" / f"{trace_id}.llmtrace"
            package_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                with urllib.request.urlopen(package_url, timeout=60) as response:
                    package = response.read(32 * 1024 * 1024 + 1)
            except OSError as error:
                raise CanaryFailure("public_verification", "public_verify_failed") from error
            if not package or len(package) > 32 * 1024 * 1024:
                raise CanaryFailure("public_verification", "public_verify_failed")
            private_write_bytes(package_path, package)
            public_verified = run_json(
                [*self.cli, "traces", "verify", str(package_path)],
                env=self.environment,
                timeout=120,
                stage="public_verification",
                code="public_verify_failed",
            )
            if public_verified.get("outcome") != "passed":
                raise CanaryFailure("public_verification", "public_verify_failed")
            result["shares"].append(
                {
                    "trace_id": trace_id,
                    "visibility": SHARE_VISIBILITY,
                    "high_entropy_force_requested": True,
                    "share_wall_ms": elapsed_ms(submitted_at),
                    "share_url": share_url,
                    "package_url": package_url,
                    "publicly_verified": True,
                }
            )


def source_commit() -> str:
    github_sha = os.environ.get("GITHUB_SHA")
    if github_sha:
        return github_sha
    return command_version("git", "rev-parse", "HEAD")


def fixture_record(fixture: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": fixture["name"],
        "version": fixture["version"],
        "summary": fixture["summary"],
        "allowed_files": sorted(fixture["allowed_files"]),
        "test_command": list(fixture["test_command"]),
    }


def runner_failure_detail(error: BaseException) -> dict[str, Any]:
    """Locate an unexpected runner failure without disclosing anything it touched.

    Exception messages can quote prompts, paths, or provider payloads, so only the type and the
    deepest frame inside this file are recorded.
    """

    module = Path(__file__).resolve()
    location = None
    trace = error.__traceback__
    while trace is not None:
        frame = trace.tb_frame
        try:
            same_file = Path(frame.f_code.co_filename).resolve() == module
        except OSError:
            same_file = False
        if same_file:
            location = f"{module.name}:{trace.tb_lineno}"
        trace = trace.tb_next
    return {"type": type(error).__name__, "location": location}


def base_result(arguments: argparse.Namespace, fixture: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": RESULT_FORMAT,
        "status": "running",
        "failure_stage": None,
        "failure_code": None,
        "started_at_utc": utc_now(),
        "completed_at_utc": None,
        "source": {
            "commit": source_commit(),
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
            "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "runner_image": os.environ.get("ImageOS", sys.platform),
            "runtime_build_id": os.environ.get("CAPTURE_RUNTIME_BUILD_ID"),
            "hosted_rollout_id": os.environ.get("CAPTURE_HOSTED_ROLLOUT_ID"),
        },
        "versions": {
            "capture": command_version(arguments.capture, "--version"),
            "captured": command_version(arguments.captured, "--version"),
            "opencode": command_version(arguments.opencode, "--version"),
            "node": command_version("node", "--version"),
        },
        "model": {
            "requested_opencode_model": arguments.model,
            "requested_openrouter_model": arguments.model.removeprefix("openrouter/"),
            "preflight": None,
        },
        "fixture": fixture_record(fixture),
        "attempts": [],
        "traces": [],
        "notarizations": [],
        "shares": [],
        "failure_detail": None,
        "disclosure_violations": {},
        "total_wall_ms": None,
    }


def aggregate_result(result: dict[str, Any]) -> None:
    attempts = result["attempts"]
    tokens = {field: 0 for field in ("input", "output", "reasoning", "cache_read", "cache_write")}
    for attempt in attempts:
        for field, value in attempt.get("tokens", {}).items():
            if field in tokens and isinstance(value, int):
                tokens[field] += value
    result["summary"] = {
        "attempt_count": len(attempts),
        "agent_steps": sum(int(item.get("agent_steps", 0)) for item in attempts),
        "model_turns": len(result["traces"]),
        "eligible_traces": sum(
            1 for item in result["traces"] if item.get("notarization_eligible")
        ),
        "tokens": tokens,
        "opencode_wall_ms": sum(int(item.get("opencode_wall_ms", 0)) for item in attempts),
        "proof_wall_ms": sum(
            int(item.get("proof_wall_ms") or 0) for item in result["notarizations"]
        ),
        "share_wall_ms": sum(
            int(item.get("share_wall_ms") or 0) for item in result["shares"]
        ),
    }


def write_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + ".tmp")
    pending.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(pending, 0o600)
    pending.replace(path)


def write_step_summary(result: dict[str, Any]) -> None:
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    icon = "✅" if result["status"] == "passed" else "❌"
    summary = result.get("summary", {})
    lines = [
        f"## {icon} OpenCode E2E canary",
        "",
        f"- Status: `{result['status']}`",
        f"- Model: `{result['model']['requested_openrouter_model']}`",
        f"- Attempts / traces / eligible: {summary.get('attempt_count', 0)} / {summary.get('model_turns', 0)} / {summary.get('eligible_traces', 0)}",
        f"- Agent / proof / share / total: {summary.get('opencode_wall_ms', 0)} ms / {summary.get('proof_wall_ms', 0)} ms / {summary.get('share_wall_ms', 0)} ms / {result.get('total_wall_ms', 0)} ms",
        f"- Runtime build / hosted rollout: `{result['source'].get('runtime_build_id') or 'unknown'}` / `{result['source'].get('hosted_rollout_id') or 'unknown'}`",
    ]
    if result.get("failure_code"):
        lines.append(
            f"- Failure: `{result.get('failure_stage')}` / `{result.get('failure_code')}`"
        )
    for share in result.get("shares", []):
        lines.append(f"- [{share['trace_id']}]({share['share_url']})")
    with open(destination, "a", encoding="utf-8") as output:
        output.write("\n".join(lines) + "\n")


def parse_arguments() -> argparse.Namespace:
    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixtures",
        default=str(directory / "fixtures"),
        help="Directory of fixtures; one is chosen at random unless --fixture pins it",
    )
    parser.add_argument(
        "--fixture",
        default=None,
        help="Pin one fixture directory instead of choosing at random",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--opencode", default="opencode")
    parser.add_argument("--capture", default="capture")
    parser.add_argument("--captured", default="captured")
    parser.add_argument(
        "--result",
        default=os.environ.get(
            "CAPTURED_E2E_RESULT", "/tmp/notary-opencode-e2e-result.json"
        ),
    )
    parser.add_argument("--agent-timeout", type=int, default=600)
    parser.add_argument("--notarization-timeout", type=int, default=600)
    parser.add_argument("--share-timeout", type=int, default=300)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    result_path = Path(arguments.result).resolve()
    try:
        fixture = select_fixture(arguments)
    except CanaryFailure as failure:
        sys.stderr.write(f"{failure.stage}: {failure.code}\n")
        return 1
    result = base_result(arguments, fixture)
    started = time.monotonic()
    temporary_base = Path(os.environ.get("CAPTURED_E2E_TMPDIR", "/tmp"))
    root = Path(tempfile.mkdtemp(prefix="notary-opencode-e2e-", dir=temporary_base))
    os.chmod(root, 0o700)
    canary = Canary(arguments, root, fixture)
    try:
        if not canary.provider_key:
            raise CanaryFailure("configuration", "provider_key_missing")
        preflight = preflight_model(arguments.model, canary.provider_key)
        result["model"]["preflight"] = preflight
        canary.start_daemon()
        successful: dict[str, Any] | None = None
        for attempt_number in (1, 2):
            attempt = canary.run_attempt(attempt_number, result)
            if attempt["passed"]:
                successful = attempt
                break
            if not attempt["transient"] or attempt_number == 2:
                raise CanaryFailure("agent", attempt["failure_code"])
            time.sleep(attempt["retry_after"])
        if successful is None:
            raise CanaryFailure("agent", "agent_task_failed")
        canary.validate_provenance(successful["traces"], preflight)
        canary.seal_verify_share(successful["eligible"], result)
        result["status"] = "passed"
    except CanaryFailure as error:
        result["status"] = "failed"
        result["failure_stage"] = error.stage
        result["failure_code"] = error.code
    except Exception as error:
        result["status"] = "failed"
        result["failure_stage"] = "runner"
        result["failure_code"] = "unexpected_runner_failure"
        result["failure_detail"] = runner_failure_detail(error)
    finally:
        canary.stop_daemon()
        cleanup_private_path(root)
        result["completed_at_utc"] = utc_now()
        result["total_wall_ms"] = elapsed_ms(started)
        aggregate_result(result)
        write_result(result_path, result)
        write_step_summary(result)
    if result["status"] == "passed":
        print(f"OpenCode E2E passed; sanitized result: {result_path}")
        return 0
    print(
        f"OpenCode E2E failed at {result['failure_stage']} ({result['failure_code']}); sanitized result: {result_path}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
