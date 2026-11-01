#!/usr/bin/env python3
"""Post a compact, sanitized OpenCode canary result to Slack."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


RESULT_FORMAT = "ecp/opencode-e2e-result/v1"


def duration(value: Any) -> str:
    milliseconds = value if isinstance(value, int) and value >= 0 else 0
    if milliseconds < 1000:
        return f"{milliseconds} ms"
    return f"{milliseconds / 1000:.1f} s"


def fallback_result() -> dict[str, Any]:
    return {
        "format": RESULT_FORMAT,
        "status": "failed",
        "failure_stage": "workflow",
        "failure_code": "result_missing",
        "model": {"requested_openrouter_model": "unknown"},
        "summary": {},
        "shares": [],
        "total_wall_ms": 0,
    }


def load_result(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback_result()
    if not isinstance(value, dict) or value.get("format") != RESULT_FORMAT:
        return fallback_result()
    return value


def slack_payload(result: dict[str, Any]) -> dict[str, Any]:
    passed = result.get("status") == "passed"
    icon = ":white_check_mark:" if passed else ":x:"
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    tokens = summary.get("tokens") if isinstance(summary.get("tokens"), dict) else {}
    model = result.get("model") if isinstance(result.get("model"), dict) else {}
    source = result.get("source") if isinstance(result.get("source"), dict) else {}
    run_url = None
    if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID"):
        run_url = (
            f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}"
            f"/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        )
    status_text = "passed" if passed else "failed"
    header = f"{icon} Notary OpenCode canary {status_text}"
    if run_url:
        header += f" · <{run_url}|run>"
    fields = [
        {"type": "mrkdwn", "text": f"*Model*\n`{model.get('requested_openrouter_model', 'unknown')}`"},
        {
            "type": "mrkdwn",
            "text": (
                "*Attempts / calls / eligible*\n"
                f"{summary.get('attempt_count', 0)} / {summary.get('model_turns', 0)} / "
                f"{summary.get('eligible_traces', 0)}"
            ),
        },
        {
            "type": "mrkdwn",
            "text": (
                "*Tokens in / out*\n"
                f"{tokens.get('input', 0)} / {tokens.get('output', 0)}"
            ),
        },
        {
            "type": "mrkdwn",
            "text": (
                "*Agent / proof / share / total*\n"
                f"{duration(summary.get('opencode_wall_ms'))} / "
                f"{duration(summary.get('proof_wall_ms'))} / "
                f"{duration(summary.get('share_wall_ms'))} / "
                f"{duration(result.get('total_wall_ms'))}"
            ),
        },
        {
            "type": "mrkdwn",
            "text": (
                "*Runtime / hosted rollout*\n"
                f"`{source.get('runtime_build_id') or 'unknown'}` / "
                f"`{source.get('hosted_rollout_id') or 'unknown'}`"
            ),
        },
    ]
    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "section", "fields": fields},
    ]
    if not passed:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Failure: `{result.get('failure_stage') or 'unknown'}` / "
                            f"`{result.get('failure_code') or 'unknown'}`"
                        ),
                    }
                ],
            }
        )
    links = [
        f"<{item['share_url']}|{item['trace_id']}>"
        for item in result.get("shares", [])[:10]
        if isinstance(item, dict)
        and isinstance(item.get("share_url"), str)
        and isinstance(item.get("trace_id"), str)
    ]
    if links:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "Verified public traces: " + " · ".join(links)}
                ],
            }
        )
    return {"text": header, "blocks": blocks}


def post(webhook: str, payload: dict[str, Any]) -> None:
    request = urllib.request.Request(
        webhook,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status < 200 or response.status >= 300:
            raise OSError("Slack returned a non-success status")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    arguments = parser.parse_args()
    webhook = os.environ.get("CAPTURED_E2E_SLACK_WEBHOOK_URL")
    if not webhook:
        print("Slack notification skipped: CAPTURED_E2E_SLACK_WEBHOOK_URL is unset")
        return 0
    try:
        post(webhook, slack_payload(load_result(arguments.result)))
    except (OSError, urllib.error.URLError):
        print("Slack notification failed", file=sys.stderr)
        return 1
    print("Posted sanitized OpenCode E2E summary to Slack")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
