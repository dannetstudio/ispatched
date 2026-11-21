"""Regression tests for the whole-branch review findings."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from ispatched.advisory import find_advisory, load_advisories
from ispatched.cli import main
from ispatched.model import Confidence, IspatchedError, Status
from ispatched.providers.http import check_url
from ispatched.server import run_server
from tests.fakes import FakeSystem
from tests.test_vendor_providers import ADV, FPM, dpkg_cmds, host


def run(argv, stdout=None):
    out, err = stdout or io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out, err.getvalue()


def rpm_cmds(exe, package, vr, epoch="0", install="900"):
    return {
        ("rpm", "-qf", "--qf", "%{NAME}\n", exe): (0, package + "\n"),
        ("rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n%{INSTALLTIME}\n", package):
            (0, "%s:%s\n%s\n" % (epoch, vr, install)),
    }


class ForeignBuildTests(unittest.TestCase):
    """C1: a package from another source must never get a vendor-HIGH verdict."""

    def dpkg(self, os_id, rel, exe, pkg, version):
        return run_server(ADV, host(os_id, rel, [(10, exe, 100, "")], dpkg_cmds(exe, pkg, version)))

    def test_ppa_build_below_upstream_fix_is_not_patched(self):
        v = self.dpkg("ubuntu", "24.04", "/usr/sbin/php-fpm8.3", "php8.3-fpm",
                      "8.3.20-1+ubuntu24.04.1+deb.sury.org+1")
        self.assertEqual(v.status, Status.POTENTIALLY_VULNERABLE)
        self.assertNotEqual(v.confidence, Confidence.HIGH)

    def test_ppa_build_at_upstream_fix_gets_upstream_confidence_only(self):
        v = self.dpkg("ubuntu", "24.04", "/usr/sbin/php-fpm8.3", "php8.3-fpm",
                      "8.3.40-1+ubuntu24.04.1+deb.sury.org+1")
        self.assertEqual((v.status, v.confidence), (Status.PATCHED, Confidence.MEDIUM))

    def test_debian_sury_build_is_not_vendor_evidence(self):
        v = self.dpkg("debian", "12", "/usr/sbin/php-fpm8.2", "php8.2-fpm",
                      "8.2.20-1+0~20240601.52+debian12~1.gbp1234")
        self.assertNotEqual(v.confidence, Confidence.HIGH)

    def test_official_ubuntu_build_still_high(self):
        v = self.dpkg("ubuntu", "24.04", "/usr/sbin/php-fpm8.3", "php8.3-fpm",
                      "8.3.6-0ubuntu0.24.04.14")
        self.assertEqual((v.status, v.confidence), (Status.PATCHED, Confidence.HIGH))

    def rpm(self, vr, epoch="0"):
        exe = "/usr/sbin/php-fpm"
        return run_server(ADV, host("rhel", "9.4", [(10, exe, 100, "")],
                                    rpm_cmds(exe, "php-fpm", vr, epoch)))

    def test_rhel_module_stream_is_not_matched_to_the_default_branch(self):
        v = self.rpm("8.2.13-1.module+el9.3.0+1+abcd")
        self.assertEqual(v.status, Status.POTENTIALLY_VULNERABLE)
        self.assertNotEqual(v.confidence, Confidence.HIGH)

    def test_remi_build_is_not_vendor_evidence(self):
        v = self.rpm("8.3.10-1.el9.remi")
        self.assertNotEqual(v.confidence, Confidence.HIGH)


class ModPhpTests(unittest.TestCase):
    """C2: Apache mod_php is judged by the libphp package, not by httpd/apache2."""

    def test_debian_apache_module_uses_libphp_package(self):
        lib = "/usr/lib/apache2/modules/libphp8.2.so"
        apache = (20, "/usr/sbin/apache2", 100, "7f00-7f01 r-xp 0 08:01 9 %s\n" % lib)
        cmds = {("dpkg", "-S", "/usr/sbin/apache2"): (0, "apache2-bin: /usr/sbin/apache2\n"),
                ("dpkg-query", "-W", "-f", "${Version}\n", "apache2-bin"): (0, "2.4.62-1\n")}
        cmds.update(dpkg_cmds(lib, "libapache2-mod-php8.2", "8.2.35-1~deb12u1"))
        v = run_server(ADV, host("debian", "12", [apache], cmds))
        self.assertEqual((v.status, v.confidence), (Status.PATCHED, Confidence.HIGH))

    def test_rhel_httpd_is_never_compared_with_php(self):
        lib = "/usr/lib64/httpd/modules/libphp7.so"
        httpd = (20, "/usr/sbin/httpd", 100, "7f00-7f01 r-xp 0 08:01 9 %s\n" % lib)
        cmds = {("rpm", "-qf", "--qf", "%{NAME}\n", "/usr/sbin/httpd"): (0, "httpd\n"),
                ("rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n%{INSTALLTIME}\n", "httpd"):
                    (0, "0:2.4.62-1.el9\n900\n")}
        cmds.update(rpm_cmds(lib, "php", "8.0.30-8.el9_8.1"))
        v = run_server(ADV, host("rhel", "9.4", [httpd], cmds))
        self.assertEqual((v.status, v.confidence), (Status.PATCHED, Confidence.HIGH))

    def test_module_path_not_found_is_unknown(self):
        apache = (20, "/usr/sbin/apache2", 100, "libphp")
        v = run_server(ADV, host("debian", "12", [apache], {}))
        self.assertEqual(v.status, Status.UNKNOWN)


class UnsupportedOsTests(unittest.TestCase):
    EXE = "/usr/sbin/php-fpm83"

    def alpine(self, modes, root=True):
        h = host("alpine", "3.20", [(10, self.EXE, 100, "")],
                 {(self.EXE, "-v"): (0, "PHP 8.3.40 (fpm-fcgi)\n"),
                  ("php-fpm", "-v"): (0, "PHP 8.1.1 (fpm-fcgi)\n")})
        h.modes, h.root = modes, root
        return h

    CHAIN = {"/usr/sbin": (0, 0o755), "/usr": (0, 0o755), "/": (0, 0o755)}

    def test_serving_binary_is_asked_for_its_version(self):
        h = self.alpine(dict(self.CHAIN, **{self.EXE: (0, 0o755)}))
        v = run_server(ADV, h)
        self.assertEqual((v.status, v.confidence), (Status.PATCHED, Confidence.MEDIUM))
        self.assertNotIn(["php-fpm", "-v"], h.calls)

    def test_writable_binary_is_not_executed(self):
        h = self.alpine(dict(self.CHAIN, **{self.EXE: (1000, 0o755)}))
        v = run_server(ADV, h)
        self.assertEqual(v.status, Status.UNKNOWN)
        self.assertNotIn([self.EXE, "-v"], h.calls)

    def test_group_writable_binary_is_not_executed(self):
        h = self.alpine(dict(self.CHAIN, **{self.EXE: (0, 0o775)}))
        self.assertEqual(run_server(ADV, h).status, Status.UNKNOWN)

    def test_binary_in_user_writable_directory_is_not_executed(self):
        for parent in ("/usr/sbin", "/usr", "/"):
            chain = dict(self.CHAIN, **{self.EXE: (0, 0o755)})
            chain[parent] = (1000, 0o755)
            h = self.alpine(chain)
            self.assertEqual(run_server(ADV, h).status, Status.UNKNOWN, parent)
            self.assertNotIn([self.EXE, "-v"], h.calls, parent)

    def test_binary_below_world_writable_directory_is_not_executed(self):
        chain = dict(self.CHAIN, **{self.EXE: (0, 0o755), "/usr": (0, 0o777)})
        h = self.alpine(chain)
        self.assertEqual(run_server(ADV, h).status, Status.UNKNOWN)

    def test_unreadable_ancestor_is_not_trusted(self):
        chain = dict(self.CHAIN, **{self.EXE: (0, 0o755)})
        del chain["/usr"]
        self.assertEqual(run_server(ADV, self.alpine(chain)).status, Status.UNKNOWN)


class NonRootTests(unittest.TestCase):
    def test_no_process_found_as_regular_user_explains_why(self):
        v = run_server(ADV, FakeSystem(files={"/etc/os-release": "ID=debian\n"}, root=False))
        self.assertEqual(v.status, Status.UNKNOWN)
        self.assertIn("root", v.reason)

    def test_no_process_found_as_root_keeps_plain_reason(self):
        v = run_server(ADV, FakeSystem(files={"/etc/os-release": "ID=debian\n"}))
        self.assertEqual(v.reason, "No PHP serving process found")


class ServerMixTests(unittest.TestCase):
    def test_patched_plus_unknown_instance_is_unknown(self):
        other = (11, "/opt/custom/php-fpm", 100, "")
        cmds = dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.35-1~deb12u1")
        v = run_server(ADV, host("debian", "12", [FPM, other], cmds))
        self.assertEqual(v.status, Status.UNKNOWN)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_HEAD(self):
        path = self.path
        if path == "/slow":
            time.sleep(1.0)
        if path.startswith("/dup"):
            self.send_response(200)
            first, second = ("8.1.2", "8.4.27") if path == "/dup1" else ("8.4.27", "8.1.2")
            self.send_header("X-Powered-By", "PHP/" + first)
            self.send_header("X-Powered-By", "PHP/" + second)
            self.end_headers()
            return
        if path == "/badredirect":
            self.send_response(302)
            self.send_header("Location", "http://[::1/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/8.4.27")
        self.end_headers()


class HttpHardeningTests(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_port
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def test_malformed_urls_are_unknown_not_crashes(self):
        for url in ("https://[::1", "http://", "http:///x"):
            f = check_url(ADV, url)
            self.assertEqual(f.status, Status.UNKNOWN, url)

    def test_malformed_redirect_target_is_unknown(self):
        self.assertEqual(check_url(ADV, self.base + "/badredirect").status, Status.UNKNOWN)

    def test_duplicate_headers_worst_version_decides_in_any_order(self):
        for path in ("/dup1", "/dup2"):
            f = check_url(ADV, self.base + path)
            self.assertEqual(f.status, Status.POTENTIALLY_VULNERABLE, path)
            self.assertEqual(f.evidence["php_version"], "8.1.2", path)

    def test_cli_timeout_is_honoured(self):
        started = time.time()
        code, out, _ = run(["PHP2Shell", self.base + "/slow", "--timeout", "0.2"])
        self.assertEqual(code, 3)
        self.assertLess(time.time() - started, 0.9)


class CliHardeningTests(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_port
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def test_worst_wins_when_the_bad_target_is_first(self):
        code, _, _ = run(["PHP2Shell", self.base + "/dup1", self.base + "/ok"])
        self.assertEqual(code, 1)

    def test_vulnerable_beats_unknown_in_either_order(self):
        for argv in ([self.base + "/dup1", "http://127.0.0.1:1/"],
                     ["http://127.0.0.1:1/", self.base + "/dup1"]):
            code, _, _ = run(["PHP2Shell"] + argv + ["--timeout", "0.5"])
            self.assertEqual(code, 1)

    def test_bare_and_https_forms_deduplicate(self):
        code, out, _ = run(["PHP2Shell", "https://127.0.0.1:1/", "127.0.0.1:1/",
                            "--format", "json", "--timeout", "0.5"])
        self.assertEqual(len(json.loads(out.getvalue())["results"]), 1)

    def test_workers_are_clamped(self):
        for n in ("0", "-3", "500"):
            code, _, err = run(["PHP2Shell", self.base + "/ok", "--workers", n])
            self.assertEqual(code, 0, err)

    def test_unexpected_error_exits_2_with_message(self):
        with mock.patch("ispatched.cli.run_url", side_effect=RuntimeError("boom")):
            code, _, err = run(["PHP2Shell", self.base + "/ok"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_non_utf8_targets_file_exits_2(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
            fh.write(b"\xff\xfe\xfa http://x\n")
        self.addCleanup(os.unlink, fh.name)
        code, _, err = run(["PHP2Shell", "--targets", fh.name])
        self.assertEqual(code, 2)
        self.assertIn("targets", err)

    def test_text_output_survives_an_ascii_terminal(self):
        raw = io.BytesIO()
        ascii_out = io.TextIOWrapper(raw, encoding="ascii", write_through=True)
        code, _, _ = run(["PHP2Shell", self.base + "/ok"], stdout=ascii_out)
        self.assertEqual(code, 0)
        self.assertIn(b"PATCHED", raw.getvalue())


class AdvisoryTypeTests(unittest.TestCase):
    def load_with(self, **changes):
        src = os.path.join(os.path.dirname(__file__), "..", "src", "ispatched", "advisories",
                           "php2shell.json")
        with open(src, encoding="utf-8") as fh:
            data = json.load(fh)
        data.update(changes)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        with open(os.path.join(tmp, "x.json"), "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return load_advisories([tmp])

    def test_non_string_list_items_are_rejected(self):
        for key in ("aliases", "references", "eol_branches"):
            with self.assertRaises(IspatchedError, msg=key):
                self.load_with(**{key: [1]})


if __name__ == "__main__":
    unittest.main()
