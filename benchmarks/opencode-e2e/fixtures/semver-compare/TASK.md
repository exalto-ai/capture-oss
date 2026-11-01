Fix the prerelease ordering bug in `compare_versions` in `semver.py`.

Start by calling the `read` tool for `semver.py` and `test_semver.py`. Then use
the `edit` tool to implement the function. Do not respond with a description
instead of editing the file.

Requirements:

- Compare major, minor, and patch numerically, not lexicographically.
- Return `-1`, `0`, or `1`, and `None` for any invalid version.
- Accept surrounding whitespace.
- Sort a prerelease before its own release, so `1.0.0-alpha` precedes `1.0.0`.
- Compare two prereleases as strings.
- Change only `semver.py`.
- Add no dependencies and make no network requests.
- Run the exact test command `python3 -m unittest -v` before finishing.

The parser is otherwise complete. Replace the comparison that substitutes the
empty string for a missing prerelease: a version with no prerelease must sort
after one that has it. If the tests fail, fix the implementation and rerun the
same test command before stopping.
