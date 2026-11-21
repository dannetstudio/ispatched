import json
import unittest

from unittest import mock

from ispatched.model import Confidence, Finding, Status, Verdict
from ispatched.render import render_json, render_sarif, render_text


def v(status, conf=Confidence.LOW):
    return Verdict("https://x", "PHP2Shell", status, conf, "why", [])


class RenderTests(unittest.TestCase):
    def test_text_line(self):
        self.assertEqual(render_text([v(Status.POTENTIALLY_VULNERABLE)]),
                         "POTENTIALLY VULNERABLE (low): https://x → why")

    def test_text_shows_the_final_url_after_a_redirect(self):
        f = Finding("http", Status.UNKNOWN, Confidence.NONE, "why",
                    {"final_url": "https://x/final\x1b[2J"})
        out = render_text([Verdict("https://x", "PHP2Shell", Status.UNKNOWN,
                                   Confidence.NONE, "why", [f])])
        self.assertIn("final URL: https://x/final", out)
        self.assertNotIn("\x1b", out)

    def test_text_omits_final_url_when_there_was_no_redirect(self):
        f = Finding("http", Status.UNKNOWN, Confidence.NONE, "why", {"final_url": "https://x"})
        out = render_text([Verdict("https://x", "PHP2Shell", Status.UNKNOWN,
                                   Confidence.NONE, "why", [f])])
        self.assertNotIn("final URL", out)

    def test_sarif_uri_names_the_host_for_a_local_check(self):
        local = Verdict("this server", "PHP2Shell", Status.POTENTIALLY_VULNERABLE,
                        Confidence.HIGH, "why", [])
        with mock.patch("ispatched.render.socket.gethostname", return_value="web1"):
            doc = json.loads(render_sarif([local]))
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "urn:ispatched:host:web1")

    def test_sarif_uri_keeps_the_url_for_a_remote_check(self):
        doc = json.loads(render_sarif([v(Status.POTENTIALLY_VULNERABLE)]))
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "https://x")

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
