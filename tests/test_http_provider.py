import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from ispatched.advisory import find_advisory, load_advisories
from ispatched.model import Confidence, Status
from ispatched.providers.http import check_url


class _Handler(BaseHTTPRequestHandler):
    routes = {}
    log = []

    def log_message(self, *args):
        pass

    def _serve(self):
        self.server.log.append(self.command + " " + self.path)
        route = self.server.routes.get(self.path)
        if route is None:
            route = (200, {}, b"")
        if callable(route):
            route = route(self)
            if route is None:
                return
        status, headers, body = route
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = _serve


class HttpProviderTests(unittest.TestCase):
    def setUp(self):
        self.advisory = find_advisory(load_advisories(), "PHP2Shell")
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.server.routes = {}
        self.server.log = []
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.base = "http://127.0.0.1:%d" % self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def route(self, path, status=200, headers=None, body=b""):
        self.server.routes[path] = (status, headers or {}, body)

    def test_version_table(self):
        cases = [
            ({"X-Powered-By": "PHP/8.4.26"}, Status.POTENTIALLY_VULNERABLE),
            ({"X-Powered-By": "PHP/8.4.27"}, Status.PATCHED),
            ({"Server": "Apache/2.4 PHP/8.1.35"}, Status.POTENTIALLY_VULNERABLE),
        ]
        for headers, expected in cases:
            self.route("/", headers=headers)
            f = check_url(self.advisory, self.base)
            self.assertEqual(f.status, expected, headers)
            self.assertEqual(f.confidence, Confidence.LOW)
            self.assertEqual(f.provider, "http")

    def test_reason_strings(self):
        self.route("/", headers={"X-Powered-By": "PHP/8.4.27"})
        self.assertEqual(check_url(self.advisory, self.base).reason,
                         "PHP 8.4.27 advertised; installed build not verified.")
        self.route("/", headers={"X-Powered-By": "PHP/8.4.26"})
        self.assertEqual(check_url(self.advisory, self.base).reason,
                         "PHP 8.4.26 advertised: potentially vulnerable. "
                         "HTTP headers cannot show backported fixes.")

    def test_head_only_when_it_works(self):
        self.route("/", headers={"X-Powered-By": "PHP/8.4.27"})
        check_url(self.advisory, self.base)
        self.assertEqual(self.server.log, ["HEAD /"])

    def test_405_falls_back_to_get(self):
        def handler(h):
            if h.command == "HEAD":
                return (405, {}, b"")
            return (200, {"X-Powered-By": "PHP/8.4.27"}, b"")
        self.server.routes["/"] = handler
        f = check_url(self.advisory, self.base)
        self.assertEqual(f.status, Status.PATCHED)
        self.assertEqual(self.server.log, ["HEAD /", "GET /"])

    def test_redirect_followed_and_final_url_reported(self):
        self.route("/", 301, {"Location": "/final"})
        self.route("/final", headers={"X-Powered-By": "PHP/8.4.26"})
        f = check_url(self.advisory, self.base)
        self.assertEqual(f.status, Status.POTENTIALLY_VULNERABLE)
        self.assertEqual(f.evidence["final_url"], self.base + "/final")

    def test_redirect_loop(self):
        self.route("/", 302, {"Location": "/"})
        f = check_url(self.advisory, self.base)
        self.assertEqual(f.status, Status.UNKNOWN)
        self.assertIn("too many redirects", f.reason)

    def test_redirect_to_unsupported_scheme(self):
        self.route("/", 302, {"Location": "ftp://x/"})
        f = check_url(self.advisory, self.base)
        self.assertEqual(f.status, Status.UNKNOWN)
        self.assertIn("unsupported redirect", f.reason)

    def test_most_pessimistic_header_wins(self):
        self.route("/", headers={"Server": "Apache PHP/8.4.27", "X-Powered-By": "PHP/8.1.35"})
        f = check_url(self.advisory, self.base)
        self.assertEqual(f.status, Status.POTENTIALLY_VULNERABLE)
        self.assertEqual(f.evidence["php_version"], "8.1.35")

    def test_no_php_header(self):
        self.route("/", body=b"powered by PHP 8.4.27")
        f = check_url(self.advisory, self.base)
        self.assertEqual(f.status, Status.UNKNOWN)
        self.assertEqual(f.confidence, Confidence.NONE)
        self.assertEqual(f.reason, "PHP version not found")

    def test_connection_destroyed(self):
        def handler(h):
            h.connection.close()
            return None
        self.server.routes["/"] = handler
        self.assertEqual(check_url(self.advisory, self.base).status, Status.UNKNOWN)

    def test_timeout(self):
        import time

        def handler(h):
            time.sleep(0.5)
            return (200, {}, b"")
        self.server.routes["/"] = handler
        f = check_url(self.advisory, self.base, timeout=0.1)
        self.assertEqual(f.status, Status.UNKNOWN)

    def test_non_utf8_header_does_not_crash(self):
        def handler(h):
            h.send_response(200)
            h.send_header("X-Powered-By", "PHP/8.4.27")
            h.send_header("X-Junk", "caf\xe9")
            h.end_headers()
            return None
        self.server.routes["/"] = handler
        # raw latin-1 byte in a header
        self.assertEqual(check_url(self.advisory, self.base).status, Status.PATCHED)

    def test_version_token_stops_at_control_characters(self):
        from ispatched.providers.http import _PHP_IN_HEADER
        m = _PHP_IN_HEADER.search("PHP/8.4.27\x1b[2Jevil")
        self.assertEqual(m.group(1), "8.4.27")

    def test_bare_hostname_gets_https(self):
        f = check_url(self.advisory, "127.0.0.1:1", timeout=0.5)
        self.assertEqual(f.status, Status.UNKNOWN)
        self.assertTrue(f.evidence["final_url"].startswith("https://"))


if __name__ == "__main__":
    unittest.main()
