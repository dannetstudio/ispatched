import shutil
import subprocess
import unittest

from ispatched.versions import dpkg_compare, parse_php_version, rpm_compare


class DpkgCompareTests(unittest.TestCase):
    def test_tilde_sorts_before_plain_revision(self):
        self.assertEqual(dpkg_compare("8.2.35-1~deb12u1", "8.2.35-1"), -1)

    def test_epoch_dominates(self):
        self.assertEqual(dpkg_compare("1:8.2.35", "8.2.35"), 1)

    def test_numeric_runs_compare_numerically(self):
        self.assertEqual(dpkg_compare("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.27"), 1)
        self.assertEqual(dpkg_compare("8.1.10", "8.1.9"), 1)

    def test_equal(self):
        self.assertEqual(dpkg_compare("8.4.27-1~deb13u1", "8.4.27-1~deb13u1"), 0)

    def test_letters_sort_before_non_letters(self):
        self.assertEqual(dpkg_compare("1.0a", "1.0+"), -1)

    def test_agrees_with_real_dpkg(self):
        if not shutil.which("dpkg"):
            self.skipTest("dpkg not installed")
        pairs = [
            ("8.2.35-1~deb12u1", "8.2.35-1"), ("1:8.2.35", "8.2.35"),
            ("8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.27"), ("1.0a", "1.0+"),
            ("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29"), ("1.0~rc1", "1.0"),
            ("1.0", "1.0-0"), ("2:1.0", "1:9.9"), ("8.5.9-0ubuntu2.1", "8.5.4-0ubuntu1.5"),
            ("5.5.9+dfsg-1ubuntu4.29+esm18", "5.5.9+dfsg-1ubuntu4.29"),
            ("1.0.1", "1.0.10"), ("1.0-1", "1.0-1ubuntu1"),
            ("1.0~~", "1.0~"), ("1.0+b1", "1.0"), ("0.9", "0.10"),
            ("7.0.33-0ubuntu0.16.04.16+esm22", "7.0.33-0ubuntu0.16.04.16"),
            ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.2"),
            ("1:0", "0:1"), ("1.0-1~bpo12+1", "1.0-1"),
        ]
        for a, b in pairs:
            expected = 0
            if subprocess.call(["dpkg", "--compare-versions", a, "lt", b]) == 0:
                expected = -1
            elif subprocess.call(["dpkg", "--compare-versions", a, "gt", b]) == 0:
                expected = 1
            self.assertEqual(dpkg_compare(a, b), expected, (a, b))


class RpmCompareTests(unittest.TestCase):
    def test_missing_epoch_is_zero(self):
        v = "7.4.33-8.module+el8.10.0+25117+30337cca"
        self.assertEqual(rpm_compare("0:" + v, v), 0)

    def test_epoch_dominates(self):
        self.assertEqual(rpm_compare("1:1.0-1", "2.0-1"), 1)

    def test_longer_release_is_newer(self):
        self.assertEqual(rpm_compare("8.0.30-8.el9_8.1", "8.0.30-8.el9_8"), 1)

    def test_tilde_sorts_first(self):
        self.assertEqual(rpm_compare("1.0~rc1-1", "1.0-1"), -1)

    def test_caret_sorts_after_end_but_before_next(self):
        self.assertEqual(rpm_compare("1.0^git1-1", "1.0-1"), 1)
        self.assertEqual(rpm_compare("1.0^git1-1", "1.0.1-1"), -1)

    def test_numeric_beats_alpha(self):
        self.assertEqual(rpm_compare("1.0.1-1", "1.0.a-1"), 1)

    def test_numbers_compare_as_numbers(self):
        self.assertEqual(rpm_compare("1.10-1", "1.9-1"), 1)


class PhpVersionTests(unittest.TestCase):
    def test_distro_suffix_is_split_off(self):
        v = parse_php_version("8.4.27-1ubuntu1")
        self.assertEqual((v.major, v.minor, v.patch), (8, 4, 27))
        self.assertEqual(v.branch, "8.4")
        self.assertEqual(v.suffix, "-1ubuntu1")
        self.assertFalse(v.prerelease)

    def test_plain_version(self):
        v = parse_php_version("8.2.35")
        self.assertEqual(v.suffix, "")
        self.assertFalse(v.prerelease)

    def test_prereleases_are_flagged(self):
        for text in ("8.4.27RC1", "8.4.27~beta1", "8.4.27-dev", "8.4.27alpha2"):
            v = parse_php_version(text)
            self.assertTrue(v is None or v.prerelease, text)

    def test_unparseable_is_none(self):
        for text in ("8.4", "not-a-version", "", None):
            self.assertIsNone(parse_php_version(text), text)


if __name__ == "__main__":
    unittest.main()
