Fix the rounding bug in `parse_retry_after` in `retry_after.py`.

Start by calling the `read` tool for `retry_after.py` and
`test_retry_after.py`. Then use the `edit` tool to implement the function. Do
not respond with a description instead of editing the file.

Requirements:

- Accept a non-negative decimal integer as delta-seconds.
- Accept an RFC 7231 HTTP date and return the number of seconds from `now`.
- Treat a naive `now` as UTC.
- Round a fractional future delay up to the next whole second.
- Clamp a past HTTP date to zero.
- Return `None` for empty, negative, fractional, or otherwise invalid input.
- Change only `retry_after.py`.
- Add no dependencies and make no network requests.
- Run the exact test command `python3 -m unittest -v` before finishing.

The parser is otherwise complete. Replace the incorrect positive fractional
delay rounding with the already imported standard-library `math.ceil`. If the
tests fail, fix the implementation and rerun the same test command before
stopping.
