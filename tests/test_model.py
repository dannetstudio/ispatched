import unittest

from ispatched.model import (
    EXIT_CODES,
    Confidence,
    Finding,
    IspatchedError,
    Status,
    Verdict,
)


class ModelTests(unittest.TestCase):
    def test_finding_to_dict_uses_lowercase_confidence_name(self):
        f = Finding("http", Status.PATCHED, Confidence.LOW, "r")
        d = f.to_dict()
        self.assertEqual(d["confidence"], "low")
        self.assertEqual(d["status"], "patched")
        self.assertEqual(d["provider"], "http")
        self.assertIsNone(d["evidence"])

    def test_status_values(self):
        self.assertEqual(Status.UNKNOWN.value, "unknown")
        self.assertEqual(Status.POTENTIALLY_VULNERABLE.value, "potentially_vulnerable")

    def test_confidence_orders_by_strength(self):
        self.assertLess(Confidence.LOW, Confidence.MEDIUM)
        self.assertLess(Confidence.MEDIUM, Confidence.HIGH)

    def test_verdict_exit_codes(self):
        for status, code in ((Status.PATCHED, 0), (Status.POTENTIALLY_VULNERABLE, 1), (Status.UNKNOWN, 3)):
            v = Verdict("t", "PHP2Shell", status, Confidence.LOW, "r", [])
            self.assertEqual(v.exit_code, code)
            self.assertEqual(EXIT_CODES[status], code)

    def test_verdict_to_dict_includes_findings_and_exit_code(self):
        f = Finding("http", Status.UNKNOWN, Confidence.NONE, "r", evidence={"a": 1})
        v = Verdict("t", "PHP2Shell", Status.UNKNOWN, Confidence.NONE, "why", [f])
        d = v.to_dict()
        self.assertEqual(d["exit_code"], 3)
        self.assertEqual(d["findings"][0]["evidence"], {"a": 1})
        self.assertEqual(d["advisory"], "PHP2Shell")

    def test_error_is_exception(self):
        self.assertTrue(issubclass(IspatchedError, Exception))


if __name__ == "__main__":
    unittest.main()
