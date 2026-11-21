import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from ispatched.cli import main


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.server.hits.append(self.path)
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/" + self.server.versions.get(self.path, "8.4.27"))
        self.end_headers()


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.srv.hits, self.srv.versions = [], {}
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_port

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_list(self):
        code, out, _ = run(["list"])
        self.assertEqual(code, 0)
        self.assertIn("PHP2Shell", out)

    def test_patched_and_vulnerable_exit_codes(self):
        self.assertEqual(run(["CVE-2026-109618", self.base])[0], 0)
        self.srv.versions["/"] = "8.4.26"
        code, out, _ = run(["CVE-2026-109618", self.base, "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["results"][0]["status"], "potentially_vulnerable")

    def test_no_target(self):
        code, _, err = run(["CVE-2026-109618"])
        self.assertEqual(code, 2)
        self.assertIn("error: provide at least one URL, --targets FILE or --server", err)

    def test_unknown_advisory(self):
        self.assertEqual(run(["CVE-0000-0", self.base])[0], 2)

    def test_targets_file_dedup(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# c\n\n%s/a\n%s/a\n%s/b\n" % (self.base, self.base, self.base))
        self.addCleanup(os.unlink, fh.name)
        code, _, _ = run(["PHP2Shell", "--targets", fh.name])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(self.srv.hits), ["/a", "/b"])

    def test_worst_exit_code(self):
        self.srv.versions["/bad"] = "8.4.1"
        code, _, _ = run(["PHP2Shell", self.base + "/ok", self.base + "/bad"])
        self.assertEqual(code, 1)

    def test_unknown_beats_patched(self):
        code, _, _ = run(["PHP2Shell", self.base + "/ok", "http://127.0.0.1:1/", "--timeout", "0.5"])
        self.assertEqual(code, 3)

    def test_sarif(self):
        self.srv.versions["/bad"] = "8.4.1"
        _, out, _ = run(["PHP2Shell", self.base + "/ok", self.base + "/bad", "--format", "sarif"])
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["level"], "warning")

    def test_broken_advisory_dir(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "bad.json"), "w") as fh:
            fh.write("{nope")
        code, _, err = run(["list", "--advisories", d])
        self.assertEqual(code, 2)
        self.assertIn("bad.json", err)


if __name__ == "__main__":
    unittest.main()
