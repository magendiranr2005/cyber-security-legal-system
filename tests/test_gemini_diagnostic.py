import unittest

from scripts.diagnose_gemini import _provider_category


class GeminiDiagnosticTests(unittest.TestCase):
    def test_high_demand_503_is_distinguished_from_generic_unavailable(self):
        self.assertEqual(
            _provider_category(503, "This model is experiencing high demand."),
            ("provider_overloaded", "Google reports temporary model capacity pressure."),
        )
        self.assertEqual(
            _provider_category(503, "Service unavailable."),
            ("provider_unavailable", "Google returned HTTP 503; the model service is unavailable."),
        )

    def test_provider_failures_are_categorized_without_raw_messages(self):
        cases = (
            (504, "Deadline expired.", "provider_deadline"),
            (429, "Quota exceeded.", "quota_or_billing"),
            (429, "Rate limit exceeded.", "rate_limit"),
            (403, "Permission denied.", "authentication_or_access"),
            (404, "Model not found.", "invalid_request_or_model"),
        )
        for status, message, expected_category in cases:
            with self.subTest(status=status, category=expected_category):
                category, _ = _provider_category(status, message)
                self.assertEqual(category, expected_category)


if __name__ == "__main__":
    unittest.main()
