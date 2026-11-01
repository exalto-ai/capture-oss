Fix the repeated-separator bug in `slugify` in `slugify.py`.

Start by calling the `read` tool for `slugify.py` and `test_slugify.py`. Then
use the `edit` tool to implement the function. Do not respond with a
description instead of editing the file.

Requirements:

- Lowercase the value and transliterate accented characters to ASCII.
- Replace each run of disallowed characters with one `-` separator.
- Strip leading and trailing separators.
- Return an empty string when no alphanumeric characters remain.
- Truncate to `max_length` when it is a positive integer, leaving no trailing
  separator.
- Ignore a `max_length` that is `None` or not positive.
- Change only `slugify.py`.
- Add no dependencies and make no network requests.
- Run the exact test command `python3 -m unittest -v` before finishing.

The function is otherwise complete. Replace the per-character replacement with
the already compiled `_ALLOWED` pattern so each run of disallowed characters
collapses to a single separator. If the tests fail, fix the implementation and
rerun the same test command before stopping.
