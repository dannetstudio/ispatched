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


if __name__ == "__main__":
    unittest.main()
