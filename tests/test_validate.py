"""Repository submission checks."""

import unittest

from jrlib.validate import validate_submission


class ValidateTests(unittest.TestCase):
    def test_github_repository_is_normalized(self):
        result = validate_submission("https://github.com/Jaseci-Labs/jaclang.git", True, "repository_only")
        self.assertTrue(result["ok"])
        self.assertEqual(result["repository_url"], "https://github.com/Jaseci-Labs/jaclang")
        self.assertEqual(result["kind"], "github")

    def test_fixture_repository_is_allowed(self):
        result = validate_submission("fixture://safe-buggy", True, "repository_only")
        self.assertTrue(result["ok"])
        self.assertEqual(result["kind"], "fixture")

    def test_authorization_is_required(self):
        result = validate_submission("https://github.com/octocat/Hello-World", False, "repository_only")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "authorization_required")
        again = validate_submission("https://github.com/octocat/Hello-World", "true", "repository_only")
        self.assertEqual(again["error"], "authorization_required")

    def test_unsupported_forms_are_rejected(self):
        cases = [
            ("http://github.com/octocat/Hello-World", "unsupported_scheme"),
            ("ssh://git@github.com/octocat/Hello-World.git", "unsupported_scheme"),
            ("git@github.com:octocat/Hello-World.git", "unsupported_scheme"),
            ("file:///tmp/repo", "unsupported_scheme"),
            ("https://gitlab.com/octocat/Hello-World", "unsupported_repository"),
            ("https://github.com/octocat/Hello-World/tree/main", "malformed_url"),
            ("https://user:token@github.com/octocat/Hello-World", "malformed_url"),
            ("not a url", "malformed_url"),
            ("fixture://not-a-real-fixture", "unsupported_repository"),
        ]
        for url, error in cases:
            with self.subTest(url=url):
                result = validate_submission(url, True, "repository_only")
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], error)

    def test_scope_must_stay_on_the_repository(self):
        result = validate_submission("fixture://safe-buggy", True, "internet")
        self.assertEqual(result["error"], "unsupported_scope")


if __name__ == "__main__":
    unittest.main()
