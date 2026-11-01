import unittest
from datetime import datetime, timezone

from retry_after import parse_retry_after


class ParseRetryAfterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_accepts_delta_seconds(self) -> None:
        self.assertEqual(parse_retry_after("0", self.now), 0)
        self.assertEqual(parse_retry_after(" 120 ", self.now), 120)

    def test_rejects_invalid_delta_seconds(self) -> None:
        for value in ("", "-1", "+1", "1.5", "12 seconds"):
            with self.subTest(value=value):
                self.assertIsNone(parse_retry_after(value, self.now))

    def test_accepts_future_http_date(self) -> None:
        self.assertEqual(
            parse_retry_after("Wed, 01 Jan 2025 12:02:30 GMT", self.now),
            150,
        )

    def test_rounds_fractional_future_delay_up(self) -> None:
        now = datetime(2025, 1, 1, 12, 0, 0, 500_000, tzinfo=timezone.utc)
        self.assertEqual(
            parse_retry_after("Wed, 01 Jan 2025 12:00:02 GMT", now),
            2,
        )

    def test_clamps_past_http_date_to_zero(self) -> None:
        self.assertEqual(
            parse_retry_after("Wed, 01 Jan 2025 11:59:00 GMT", self.now),
            0,
        )

    def test_rejects_invalid_http_date(self) -> None:
        self.assertIsNone(parse_retry_after("not a date", self.now))

    def test_treats_naive_now_as_utc(self) -> None:
        naive_now = datetime(2025, 1, 1, 12, 0, 0)
        self.assertEqual(
            parse_retry_after("Wed, 01 Jan 2025 12:00:01 GMT", naive_now),
            1,
        )


if __name__ == "__main__":
    unittest.main()
