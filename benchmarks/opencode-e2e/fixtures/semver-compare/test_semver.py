import unittest

from semver import compare_versions


class CompareVersionsTests(unittest.TestCase):
    def test_orders_by_major_minor_patch(self) -> None:
        self.assertEqual(compare_versions("1.2.3", "1.2.4"), -1)
        self.assertEqual(compare_versions("1.3.0", "1.2.9"), 1)
        self.assertEqual(compare_versions("2.0.0", "10.0.0"), -1)

    def test_reports_equal_versions(self) -> None:
        self.assertEqual(compare_versions("1.2.3", "1.2.3"), 0)
        self.assertEqual(compare_versions(" 1.2.3 ", "1.2.3"), 0)

    def test_sorts_a_prerelease_before_its_release(self) -> None:
        self.assertEqual(compare_versions("1.0.0-alpha", "1.0.0"), -1)
        self.assertEqual(compare_versions("1.0.0", "1.0.0-alpha"), 1)

    def test_orders_two_prereleases(self) -> None:
        self.assertEqual(compare_versions("1.0.0-alpha", "1.0.0-beta"), -1)
        self.assertEqual(compare_versions("1.0.0-beta", "1.0.0-alpha"), 1)
        self.assertEqual(compare_versions("1.0.0-alpha", "1.0.0-alpha"), 0)

    def test_rejects_invalid_versions(self) -> None:
        for value in ("", "1.2", "1.2.3.4", "v1.2.3", "1.2.x", "-1.2.3"):
            with self.subTest(value=value):
                self.assertIsNone(compare_versions(value, "1.2.3"))
                self.assertIsNone(compare_versions("1.2.3", value))


if __name__ == "__main__":
    unittest.main()
