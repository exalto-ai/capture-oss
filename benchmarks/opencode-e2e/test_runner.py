import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import notify
import run


class ModelPreflightTests(unittest.TestCase):
    def test_accepts_exact_free_tool_model(self) -> None:
        value = run.validate_model_metadata(
            {
                "data": {
                    "id": "cohere/north-mini-code:free",
                    "canonical_slug": "cohere/north-mini-code",
                    "supported_parameters": ["tools", "temperature"],
                    "pricing": {"prompt": "0", "completion": "0", "request": None},
                }
            },
            "cohere/north-mini-code:free",
        )
        self.assertTrue(value["supports_tools"])

    def test_rejects_paid_or_toolless_model(self) -> None:
        cases = [
            {"supported_parameters": ["tools"], "pricing": {"prompt": "0.1", "completion": "0"}},
            {"supported_parameters": [], "pricing": {"prompt": "0", "completion": "0"}},
        ]
        for partial in cases:
            with self.subTest(partial=partial):
                with self.assertRaises(run.CanaryFailure):
                    run.validate_model_metadata(
                        {"data": {"id": "m:free", **partial}}, "m:free"
                    )


class EventParsingTests(unittest.TestCase):
    def test_extracts_only_counts_and_token_totals(self) -> None:
        raw = b"\n".join(
            [
                json.dumps(
                    {"type": "text", "part": {"type": "text", "text": "private output"}}
                ).encode(),
                json.dumps({"type": "tool_use", "part": {"type": "tool"}}).encode(),
                json.dumps(
                    {
                        "type": "step_finish",
                        "part": {
                            "type": "step-finish",
                            "reason": "stop",
                            "tokens": {"input": 10, "output": 4, "reasoning": 2},
                        },
                    }
                ).encode(),
            ]
        )
        summary = run.parse_opencode_events(raw)
        self.assertEqual(summary["agent_steps"], 1)
        self.assertEqual(summary["tool_calls"], 1)
        self.assertEqual(summary["tokens"]["input"], 10)
        self.assertEqual(summary["text_characters"], len("private output"))
        self.assertEqual(summary["part_types"], {"text": 1, "tool": 1, "step-finish": 1})
        self.assertEqual(summary["finish_reasons"], {"stop": 1})
        self.assertNotIn("private output", json.dumps(summary))

    def test_extracts_bounded_retry_after(self) -> None:
        self.assertEqual(run.extract_retry_after_seconds(b"Retry-After: 17"), 17)
        self.assertEqual(run.extract_retry_after_seconds(b"Retry-After: 9999"), 300)
        self.assertEqual(run.extract_retry_after_seconds(b"no hint"), 60)


class GateAndClassificationTests(unittest.TestCase):
    def test_workflow_maps_secrets_to_canonical_canary_environment(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[3]
            / ".github"
            / "workflows"
            / "opencode-e2e.yml"
        ).read_text()
        self.assertIn(
            "CAPTURED_E2E_API_KEY: ${{ secrets.NOTARY_E2E_API_KEY }}",
            workflow,
        )
        self.assertIn(
            "CAPTURED_E2E_SLACK_WEBHOOK_URL: "
            "${{ secrets.NOTARY_SLACK_WEBHOOK_URL }}",
            workflow,
        )

    def test_parser_exposes_the_canonical_captured_option(self) -> None:
        with patch.object(sys, "argv", ["run.py", "--captured", "/tmp/captured"]):
            arguments = run.parse_arguments()
        self.assertEqual(arguments.captured, "/tmp/captured")
        self.assertFalse(hasattr(arguments, "llm_notaryd"))

    def test_notarization_uses_the_trace_wait_command(self) -> None:
        canary = run.Canary.__new__(run.Canary)
        canary.cli = ["capture", "--json"]
        canary.environment = {}
        canary.arguments = SimpleNamespace(notarization_timeout=60)

        with (
            patch.object(
                run,
                "run_json",
                side_effect=[
                    {"operation": {"operation_id": "op-1", "state": "succeeded"}},
                    RuntimeError("stop after notarization"),
                ],
            ) as run_json,
            patch.object(run.time, "sleep"),
            self.assertRaisesRegex(RuntimeError, "stop after notarization"),
        ):
            canary.seal_verify_share(
                [{"trace_id": "trc-1"}],
                {"notarizations": [], "shares": []},
            )

        self.assertEqual(
            run_json.call_args_list[0].args[0],
            ["capture", "--json", "traces", "seal", "trc-1", "--wait"],
        )

    def test_notarization_uses_canonical_verification_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            canary = run.Canary.__new__(run.Canary)
            canary.cli = [
                "capture",
                "--json",
                "--config",
                "/private/config.toml",
            ]
            canary.environment = {}
            canary.arguments = SimpleNamespace(
                notarization_timeout=60,
                share_timeout=60,
            )
            canary.admin_origin = "http://127.0.0.1:8788"
            canary.root = Path(directory)
            result = {"notarizations": [], "shares": []}
            download = MagicMock()
            download.read.return_value = b"trace-package"
            download.__enter__.return_value = download

            with (
                patch.object(
                    run,
                    "run_json",
                    side_effect=[
                        {
                            "operation": {
                                "operation_id": "op-1",
                                "state": "succeeded",
                            }
                        },
                        {"outcome": "passed", "trace_id": "trc-1"},
                        {},
                        {
                            "trace_id": "trc-1",
                            "progress": "shared",
                            "package_url": "https://example.test/package.llmtrace",
                            "share_url": "https://example.test/s/trc-1",
                        },
                        {"outcome": "passed", "trace_id": "trc-1"},
                    ],
                ) as run_json,
                patch.object(run.urllib.request, "urlopen", return_value=download),
            ):
                canary.seal_verify_share([{"trace_id": "trc-1"}], result)

        self.assertEqual(len(result["notarizations"]), 1)
        self.assertEqual(len(result["shares"]), 1)
        self.assertEqual(
            run_json.call_args_list[-1].args[0][:-1],
            [
                "capture",
                "--json",
                "--config",
                "/private/config.toml",
                "traces",
                "verify",
            ],
        )

    def test_canary_publications_are_listed(self) -> None:
        self.assertEqual(run.SHARE_VISIBILITY, "listed")

    def test_disclosure_scanner_reports_names_and_counts_only(self) -> None:
        value = {
            "header": "Authorization: Bearer token-value",
            "path": "/home/runner/work/private",
            "contact": "person@example.com",
        }
        violations = run.scan_disclosure(value)
        self.assertEqual(
            set(violations),
            {"authorization_value", "home_or_runner_path", "email_address"},
        )
        self.assertNotIn("token-value", json.dumps(violations))

    def test_diff_allowlist_is_exact(self) -> None:
        allowed = {"retry_after.py"}
        self.assertTrue(run.validate_changed_files(["retry_after.py"], allowed))
        self.assertFalse(run.validate_changed_files([], allowed))
        self.assertFalse(run.validate_changed_files(["retry_after.py", "TASK.md"], allowed))
        self.assertFalse(run.validate_changed_files(["slugify.py"], allowed))

    def test_classifies_transient_and_auth_provider_failures(self) -> None:
        self.assertEqual(
            run.classify_provider_failure([{"http_status": 429}]),
            "provider_rate_limited",
        )
        self.assertEqual(
            run.classify_provider_failure([{"http_status": 503}]),
            "model_unavailable",
        )
        self.assertEqual(
            run.classify_provider_failure([{"http_status": 401}]),
            "provider_auth_failed",
        )

    def test_retries_one_successful_response_that_made_no_tool_call(self) -> None:
        self.assertEqual(
            run.classify_attempt_failure([{"http_status": 200}], 0, 0, False),
            ("agent_no_tool_call", True),
        )
        self.assertEqual(
            run.classify_attempt_failure([{"http_status": 200}], 1, 0, False),
            ("agent_task_failed", False),
        )

    def test_retries_post_task_exit_only_for_an_eligible_trace_set(self) -> None:
        self.assertEqual(
            run.classify_attempt_failure(
                [{"http_status": 200, "notarization_eligible": True}], 1, 4, True
            ),
            ("agent_post_task_error", True),
        )
        self.assertEqual(
            run.classify_attempt_failure(
                [{"http_status": 200, "notarization_eligible": False}], 1, 4, True
            ),
            ("agent_task_failed", False),
        )

    def test_agent_environment_drops_unrelated_credentials(self) -> None:
        value = run.scrub_agent_environment(
            {"PATH": "/bin", "OPENAI_API_KEY": "paid", "GITHUB_TOKEN": "secret"},
            "free",
        )
        self.assertEqual(value["OPENROUTER_API_KEY"], "free")
        self.assertNotIn("OPENAI_API_KEY", value)
        self.assertNotIn("GITHUB_TOKEN", value)

    def test_daemon_environment_drops_unrelated_credentials(self) -> None:
        value = run.scrub_sensitive_environment(
            {"PATH": "/bin", "OPENAI_API_KEY": "paid", "GITHUB_TOKEN": "secret"}
        )
        self.assertEqual(value, {"PATH": "/bin"})

    def test_cleanup_removes_private_tree(self) -> None:
        root = Path(tempfile.mkdtemp())
        (root / "secret").write_text("value", encoding="utf-8")
        run.cleanup_private_path(root)
        self.assertFalse(root.exists())


class FixtureLibraryTests(unittest.TestCase):
    def build(self, root: Path, name: str, manifest, files=("target.py",)) -> Path:
        fixture = root / name
        fixture.mkdir(parents=True)
        for filename in files:
            (fixture / filename).write_text("", encoding="utf-8")
        if manifest is not None:
            (fixture / "fixture.json").write_text(
                manifest if isinstance(manifest, str) else json.dumps(manifest),
                encoding="utf-8",
            )
        return fixture

    def valid(self) -> dict:
        return {
            "version": "target/v1",
            "summary": "Fix the target.",
            "allowed_files": ["target.py"],
            "test_command": ["python3", "-m", "unittest", "-v"],
        }

    def test_loads_a_valid_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.build(Path(directory), "target", self.valid())
            loaded = run.load_fixture(fixture)
            self.assertEqual(loaded["name"], "target")
            self.assertEqual(loaded["version"], "target/v1")
            self.assertEqual(loaded["allowed_files"], {"target.py"})
            self.assertEqual(loaded["test_command"], ["python3", "-m", "unittest", "-v"])

    def test_rejects_manifests_that_would_widen_the_diff_gate(self) -> None:
        rejected = [
            {**self.valid(), "allowed_files": []},
            {**self.valid(), "allowed_files": ["*.py"]},
            {**self.valid(), "allowed_files": ["../escape.py"]},
            {**self.valid(), "allowed_files": ["nested/target.py"]},
            {**self.valid(), "allowed_files": ["target.py", "target.py"]},
            {**self.valid(), "allowed_files": ["missing.py"]},
            {**self.valid(), "allowed_files": "target.py"},
            {**self.valid(), "test_command": []},
            {**self.valid(), "test_command": "python3 -m unittest"},
            {**self.valid(), "version": ""},
            {**self.valid(), "summary": " "},
            "{ not json",
            None,
        ]
        for index, manifest in enumerate(rejected):
            with self.subTest(index=index):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self.build(Path(directory), f"target{index}", manifest)
                    with self.assertRaises(run.CanaryFailure) as raised:
                        run.load_fixture(fixture)
                    self.assertEqual(raised.exception.stage, "fixture")

    def test_discovers_only_directories_holding_a_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.build(root, "one", self.valid())
            self.build(root, "two", self.valid())
            self.build(root, "no-manifest", None)
            (root / "loose.txt").write_text("", encoding="utf-8")
            self.assertEqual([item.name for item in run.discover_fixtures(root)], ["one", "two"])

    def test_selection_pins_a_requested_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.build(root, "one", self.valid())
            pinned = self.build(root, "two", self.valid())
            arguments = SimpleNamespace(fixtures=str(root), fixture=str(pinned))
            self.assertEqual(run.select_fixture(arguments)["name"], "two")

    def test_selection_covers_every_fixture_over_many_draws(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("one", "two", "three"):
                self.build(root, name, self.valid())
            arguments = SimpleNamespace(fixtures=str(root), fixture=None)
            drawn = {run.select_fixture(arguments)["name"] for _ in range(120)}
            self.assertEqual(drawn, {"one", "two", "three"})

    def test_selection_fails_on_an_empty_library(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = SimpleNamespace(fixtures=directory, fixture=None)
            with self.assertRaises(run.CanaryFailure) as raised:
                run.select_fixture(arguments)
            self.assertEqual(raised.exception.code, "fixture_library_missing")


class ShippedFixtureTests(unittest.TestCase):
    def fixtures(self) -> list[Path]:
        return run.discover_fixtures(Path(__file__).resolve().parent / "fixtures")

    def test_every_shipped_fixture_has_a_valid_manifest(self) -> None:
        found = self.fixtures()
        self.assertGreaterEqual(len(found), 2)
        for path in found:
            with self.subTest(fixture=path.name):
                loaded = run.load_fixture(path)
                self.assertTrue(loaded["version"].startswith(f"{path.name}/"))

    def test_every_shipped_fixture_permits_editing_exactly_its_allowlist(self) -> None:
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                loaded = run.load_fixture(path)
                config = json.loads((path / "opencode.json").read_text(encoding="utf-8"))
                permission = config["agent"]["canary"]["permission"]
                self.assertEqual(permission["edit"]["*"], "deny")
                allowed = {
                    name
                    for name, decision in permission["edit"].items()
                    if decision == "allow" and not name.startswith("**/")
                }
                self.assertEqual(allowed, loaded["allowed_files"])
                self.assertEqual(
                    set(permission["bash"]) - {"*"},
                    {" ".join(loaded["test_command"])},
                )

    def test_every_shipped_fixture_fails_before_the_task_is_done(self) -> None:
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                loaded = run.load_fixture(path)
                completed = run.safe_run(loaded["test_command"], cwd=path, timeout=60)
                self.assertNotEqual(completed.returncode, 0)


# The intended fixes live here, not beside the fixtures: `initialize_fixture` copies a fixture
# directory wholesale into the agent workspace, so a solution stored there would be handed to
# the model and published in the trace.
FIXTURE_SOLUTIONS = {
    "retry-after": (
        "retry_after.py",
        "    return max(0, int(delay_seconds))",
        "    return max(0, math.ceil(delay_seconds))",
    ),
    "slugify": (
        "slugify.py",
        '    slug = "".join(character if character.isalnum() else SEPARATOR'
        " for character in lowered)\n    slug = slug.strip(SEPARATOR)",
        "    slug = _ALLOWED.sub(SEPARATOR, lowered).strip(SEPARATOR)",
    ),
    "semver-compare": (
        "semver.py",
        '    return -1 if (left_pre or "") < (right_pre or "") else 1',
        "    if left_pre is None:\n        return 1\n    if right_pre is None:\n"
        "        return -1\n    return -1 if left_pre < right_pre else 1",
    ),
}


class RunnerFailureDetailTests(unittest.TestCase):
    def test_reports_the_runner_frame_without_the_message(self) -> None:
        try:
            run.trace_record(None, 1)
        except Exception as error:  # noqa: BLE001 - the point is the unexpected case
            detail = run.runner_failure_detail(error)
            message = str(error)
        self.assertEqual(detail["type"], "AttributeError")
        self.assertRegex(detail["location"], r"^run\.py:\d+$")
        self.assertNotIn("message", detail)
        self.assertNotIn(message, json.dumps(detail))

    def test_reports_no_location_for_a_failure_outside_the_runner(self) -> None:
        try:
            raise ValueError("prompt text that must not be recorded")
        except ValueError as error:
            detail = run.runner_failure_detail(error)
        self.assertEqual(detail, {"type": "ValueError", "location": None})


class ModuleCallSignatureTests(unittest.TestCase):
    """Guard the arity of module-level calls.

    `main` wraps the run in a bare `except Exception`, so a call left with the wrong number of
    arguments after a refactor surfaces only as `unexpected_runner_failure` at the end of a live
    canary run. This caught `validate_changed_files` being updated at one call site but not the
    other.
    """

    def test_module_calls_match_local_signatures(self) -> None:
        source = Path(run.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        signatures = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                positional = node.args.posonlyargs + node.args.args
                required = len(positional) - len(node.args.defaults)
                maximum = None if node.args.vararg else len(positional)
                signatures[node.name] = (required, maximum, {a.arg for a in positional})

        problems = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            signature = signatures.get(node.func.id)
            if signature is None:
                continue
            if any(isinstance(a, ast.Starred) for a in node.args):
                continue
            if any(k.arg is None for k in node.keywords):
                continue
            required, maximum, names = signature
            supplied = len(node.args) + len([k for k in node.keywords if k.arg in names])
            if supplied < required or (maximum is not None and supplied > maximum):
                problems.append(
                    f"{node.func.id} called with {supplied} at line {node.lineno}, "
                    f"expects {required}..{maximum}"
                )
        self.assertEqual(problems, [])


class FixtureEndToEndTests(unittest.TestCase):
    """Walk the path the runner takes, minus the provider call and notarization."""

    def fixtures(self) -> list[Path]:
        return run.discover_fixtures(Path(__file__).resolve().parent / "fixtures")

    def test_each_fixture_walks_the_full_gate_path(self) -> None:
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                self.assertIn(path.name, FIXTURE_SOLUTIONS)
                filename, before, after = FIXTURE_SOLUTIONS[path.name]
                with tempfile.TemporaryDirectory() as directory:
                    workspace = Path(directory) / "fixture-attempt-1"
                    loaded = run.load_fixture(path)
                    run.initialize_fixture(path, workspace)

                    initial = run.safe_run(loaded["test_command"], cwd=workspace, timeout=60)
                    self.assertNotEqual(initial.returncode, 0, "fixture must fail first")
                    self.assertEqual(run.changed_files(workspace)[0], [])

                    target = workspace / filename
                    source = target.read_text(encoding="utf-8")
                    self.assertIn(before, source)
                    target.write_text(source.replace(before, after), encoding="utf-8")

                    final = run.safe_run(loaded["test_command"], cwd=workspace, timeout=60)
                    self.assertEqual(final.returncode, 0, final.stdout + final.stderr)

                    files, stats = run.changed_files(workspace)
                    self.assertEqual(set(files), loaded["allowed_files"])
                    self.assertTrue(run.validate_changed_files(files, loaded["allowed_files"]))
                    self.assertGreater(stats["added_lines"], 0)

    def test_interpreter_caches_do_not_reach_the_diff_gate(self) -> None:
        """Each fixture must carry its own .gitignore.

        `initialize_fixture` copies only the fixture directory, so an ignore file kept beside
        the library rather than inside each fixture never reaches the agent workspace. The
        interpreter then writes `__pycache__` while running the tests, the cache lands in
        `changed_files`, and the exact-diff gate refuses to publish. Planting the cache keeps
        this honest on hosts that do not write bytecode themselves.
        """

        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                self.assertTrue((path / ".gitignore").is_file())
                with tempfile.TemporaryDirectory() as directory:
                    workspace = Path(directory) / "fixture-attempt-1"
                    loaded = run.load_fixture(path)
                    run.initialize_fixture(path, workspace)
                    self.assertTrue((workspace / ".gitignore").is_file())

                    cache = workspace / "__pycache__"
                    cache.mkdir()
                    (cache / "module.cpython-312.pyc").write_bytes(b"\x00")
                    run.safe_run(loaded["test_command"], cwd=workspace, timeout=60)

                    self.assertEqual(run.changed_files(workspace)[0], [])

    def test_the_gate_rejects_an_edit_outside_the_allowlist(self) -> None:
        for path in self.fixtures():
            with self.subTest(fixture=path.name):
                with tempfile.TemporaryDirectory() as directory:
                    workspace = Path(directory) / "fixture-attempt-1"
                    loaded = run.load_fixture(path)
                    run.initialize_fixture(path, workspace)
                    filename, before, after = FIXTURE_SOLUTIONS[path.name]

                    target = workspace / filename
                    target.write_text(
                        target.read_text(encoding="utf-8").replace(before, after),
                        encoding="utf-8",
                    )
                    (workspace / "TASK.md").write_text("tampered\n", encoding="utf-8")
                    (workspace / "sneaked.py").write_text("x = 1\n", encoding="utf-8")

                    files, _ = run.changed_files(workspace)
                    self.assertIn("TASK.md", files)
                    self.assertIn("sneaked.py", files)
                    self.assertFalse(run.validate_changed_files(files, loaded["allowed_files"]))


class NotificationTests(unittest.TestCase):
    def test_payload_is_compact_and_contains_only_public_links(self) -> None:
        payload = notify.slack_payload(
            {
                "status": "passed",
                "model": {"requested_openrouter_model": "model:free"},
                "summary": {
                    "attempt_count": 1,
                    "model_turns": 2,
                    "eligible_traces": 2,
                    "tokens": {"input": 10, "output": 4},
                    "opencode_wall_ms": 1200,
                    "proof_wall_ms": 2300,
                },
                "total_wall_ms": 5000,
                "shares": [
                    {
                        "trace_id": "trc-1",
                        "share_url": "https://example.test/s/share-1",
                    }
                ],
            }
        )
        encoded = json.dumps(payload)
        self.assertIn("trc-1", encoded)
        self.assertLess(len(encoded), 3000)


if __name__ == "__main__":
    unittest.main()
