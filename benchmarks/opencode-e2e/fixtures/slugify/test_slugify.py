import unittest

from slugify import slugify


class SlugifyTests(unittest.TestCase):
    def test_lowercases_and_joins_words(self) -> None:
        self.assertEqual(slugify("Hello World"), "hello-world")

    def test_collapses_repeated_separators(self) -> None:
        self.assertEqual(slugify("Hello   World"), "hello-world")
        self.assertEqual(slugify("a -- b__c"), "a-b-c")

    def test_strips_leading_and_trailing_separators(self) -> None:
        self.assertEqual(slugify("  ...Hello World!  "), "hello-world")

    def test_transliterates_accented_characters(self) -> None:
        self.assertEqual(slugify("Café Déjà Vu"), "cafe-deja-vu")

    def test_returns_empty_string_for_no_usable_characters(self) -> None:
        self.assertEqual(slugify(""), "")
        self.assertEqual(slugify("   "), "")
        self.assertEqual(slugify("!!!"), "")

    def test_truncates_to_max_length_without_trailing_separator(self) -> None:
        self.assertEqual(slugify("hello world", max_length=8), "hello-wo")
        self.assertEqual(slugify("hello world", max_length=6), "hello")

    def test_ignores_non_positive_max_length(self) -> None:
        self.assertEqual(slugify("hello world", max_length=0), "hello-world")


if __name__ == "__main__":
    unittest.main()
