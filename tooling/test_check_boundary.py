from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("check_boundary.py")
SPEC = importlib.util.spec_from_file_location("check_boundary", MODULE_PATH)
assert SPEC and SPEC.loader
check_boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_boundary)


class GitRepositoryPathspecTests(unittest.TestCase):
    def initialize_repository(self, root: pathlib.Path) -> None:
        subprocess.run(["git", "init", "--quiet", str(root)], check=True)

    def test_nested_runtime_uses_repository_relative_pathspec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary)
            runtime = repository / "runtime"
            runtime.mkdir()
            self.initialize_repository(repository)

            actual_repository, pathspec = check_boundary.git_repository_and_pathspec(runtime)

            self.assertEqual(actual_repository, repository.resolve())
            self.assertEqual(pathspec, "runtime")

    def test_exported_runtime_repository_uses_dot_pathspec(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary)
            self.initialize_repository(repository)

            actual_repository, pathspec = check_boundary.git_repository_and_pathspec(repository)

            self.assertEqual(actual_repository, repository.resolve())
            self.assertEqual(pathspec, ".")

    def test_missing_git_checkout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(subprocess.CalledProcessError):
                check_boundary.git_repository_and_pathspec(pathlib.Path(temporary))


if __name__ == "__main__":
    unittest.main()
