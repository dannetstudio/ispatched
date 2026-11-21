import os
import unittest

from ispatched.advisory import Advisory, VendorFix, find_advisory, load_advisories
from ispatched.model import IspatchedError

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "advisories")


class AdvisoryTests(unittest.TestCase):
    def test_alias_lookup_is_case_insensitive(self):
        advisory = find_advisory(load_advisories(), "cve-2026-109619")
        self.assertEqual(advisory.id, "PHP2Shell")

    def test_builtin_php2shell_values(self):
        a = find_advisory(load_advisories(), "PHP2Shell")
        self.assertEqual(a.published, "2026-10-21")
        self.assertEqual(a.upstream_fixed, {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12})
        self.assertEqual(a.eol_branches, ["5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"])
        self.assertIn("CVE-2026-109618", a.aliases)
        self.assertIn("CVE-2026-109619", a.aliases)

    def test_unknown_name_message(self):
        with self.assertRaises(IspatchedError) as cm:
            find_advisory(load_advisories(), "CVE-0000-0")
        self.assertEqual(str(cm.exception), "Unknown advisory: CVE-0000-0. Run 'ispatched list'.")

    def test_invalid_json_names_the_file(self):
        with self.assertRaises(IspatchedError) as cm:
            load_advisories([os.path.join(FIX, "broken")])
        self.assertIn("broken.json", str(cm.exception))

    def test_unverified_vendor_rows_are_not_usable(self):
        a = load_advisories([os.path.join(FIX, "unverified")])["TEST-UNVERIFIED"]
        self.assertEqual(len(a.vendors), 3)
        usable = a.usable_vendor_fixes()
        self.assertEqual([v.release for v in usable], ["12"])
        self.assertIsInstance(usable[0], VendorFix)

    def test_extra_dir_overrides_builtin_by_id(self):
        a = load_advisories([os.path.join(FIX, "override")])["PHP2Shell"]
        self.assertEqual(a.title, "Override")

    def test_schema_problems_are_reported(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bad.json"), "w") as fh:
                json.dump({"id": "X", "published": "21-10-2026"}, fh)
            with self.assertRaises(IspatchedError) as cm:
                load_advisories([d])
            self.assertIn("bad.json", str(cm.exception))

    def test_unknown_vendor_is_rejected(self):
        import json, tempfile
        data = json.load(open(os.path.join(FIX, "override", "override.json")))
        data["id"] = "V"
        data["vendors"] = [{"vendor": "gentoo", "release": "1", "package": "p", "fixed": "1", "url": "u"}]
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "v.json"), "w") as fh:
                json.dump(data, fh)
            with self.assertRaises(IspatchedError) as cm:
                load_advisories([d])
            self.assertIn("gentoo", str(cm.exception))


class BuiltinVendorDataTests(unittest.TestCase):
    def setUp(self):
        self.advisory = find_advisory(load_advisories(), "PHP2Shell")

    def test_every_row_has_url_and_verification_date(self):
        self.assertTrue(self.advisory.vendors)
        for row in self.advisory.vendors:
            self.assertTrue(row.url.startswith("https://"), row.package)
            self.assertTrue(row.verified_on, (row.vendor, row.release, row.package))

    def test_no_duplicate_vendor_release_package(self):
        keys = [(v.vendor, v.release, v.package) for v in self.advisory.vendors]
        self.assertEqual(len(keys), len(set(keys)))

    def test_rows_confirmed_against_vendor_trackers(self):
        got = {(v.vendor, v.release, v.package): v.fixed for v in self.advisory.usable_vendor_fixes()}
        expected = {
            ("debian", "12", "php8.2"): "8.2.35-1~deb12u1",
            ("debian", "13", "php8.4"): "8.4.27-1~deb13u1",
            ("ubuntu", "22.04", "php8.1"): "8.1.2-1ubuntu2.28",
            ("ubuntu", "24.04", "php8.3"): "8.3.6-0ubuntu0.24.04.13",
            ("ubuntu", "26.04", "php8.5"): "8.5.4-0ubuntu1.5",
            ("ubuntu", "26.10", "php8.5"): "8.5.9-0ubuntu2.1",
            ("ubuntu", "20.04", "php7.4"): "7.4.3-4ubuntu2.29+esm5",
            ("ubuntu", "18.04", "php7.2"): "7.2.24-0ubuntu0.18.04.17+esm14",
            ("ubuntu", "16.04", "php7.0"): "7.0.33-0ubuntu0.16.04.16+esm22",
            ("ubuntu", "14.04", "php5"): "5.5.9+dfsg-1ubuntu4.29+esm18",
            ("rhel", "8", "php"): "0:7.4.33-8.module+el8.10.0+25117+30337cca",
            ("rhel", "9", "php"): "0:8.0.30-8.el9_8.1",
            ("rhel", "7", "php"): "0:5.4.16-48.el7_9.1",
        }
        for key, fixed in expected.items():
            self.assertEqual(got.get(key), fixed, key)


if __name__ == "__main__":
    unittest.main()
