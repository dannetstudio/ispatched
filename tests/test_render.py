import json
import unittest

from ispatched.model import Confidence, Status, Verdict
from ispatched.render import render_json, render_sarif, render_text


def v(status, conf=Confidence.LOW):
    return Verdict("https://x", "PHP2Shell", status, conf, "why", [])


class RenderTests(unittest.TestCase):
    def test_text_line(self):
        self.assertEqual(render_text([v(Status.POTENTIALLY_VULNERABLE)]),
                         "POTENTIALLY VULNERABLE (low): https://x → why")

    def test_text_neutralises_control_characters(self):
        evil = Verdict("https://x/\x1b]0;pwned\x07", "PHP2Shell", Status.UNKNOWN,
                       Confidence.LOW, "PHP 8.4.27\x1b[2J\r\nFAKE: PATCHED", [])
        out = render_text([evil])
        for bad in ("\x1b", "\x07", "\r"):
            self.assertNotIn(bad, out)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("\\x1b", out)

    def test_json_shape(self):
        d = json.loads(render_json([v(Status.PATCHED)]))
        self.assertEqual(d["tool"], "ispatched")
        self.assertEqual(d["results"][0]["exit_code"], 0)

    def test_sarif_levels(self):
        d = json.loads(render_sarif([v(Status.UNKNOWN, Confidence.NONE), v(Status.PATCHED)]))
        self.assertEqual([r["level"] for r in d["runs"][0]["results"]], ["note"])


if __name__ == "__main__":
    unittest.main()
