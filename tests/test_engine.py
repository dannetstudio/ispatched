import unittest

from ispatched.advisory import find_advisory, load_advisories
from ispatched.engine import combine
from ispatched.model import Confidence, Finding, Status
from ispatched.providers.upstream import check_upstream_version

P, V, U = Status.PATCHED, Status.POTENTIALLY_VULNERABLE, Status.UNKNOWN
LOW, MED, HIGH, NONE = Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.NONE


def f(provider, status, conf, reason="r"):
    return Finding(provider, status, conf, reason)


class CombineTests(unittest.TestCase):
    def test_only_low_patched(self):
        v = combine("t", "A", [f("http", P, LOW)])
        self.assertEqual((v.status, v.confidence), (P, LOW))

    def test_vendor_patched_overrides_header_vulnerable(self):
        v = combine("t", "A", [f("http", V, LOW), f("dpkg", P, HIGH)])
        self.assertEqual((v.status, v.confidence), (P, HIGH))
        self.assertIn("dpkg", v.reason)

    def test_non_vendor_conflict_is_pessimistic(self):
        v = combine("t", "A", [f("upstream", P, MED), f("http", V, LOW)])
        self.assertEqual(v.status, V)

    def test_vendor_vulnerable_wins_over_everything(self):
        v = combine("t", "A", [f("http", P, LOW), f("rpm", V, HIGH)])
        self.assertEqual((v.status, v.confidence), (V, HIGH))

    def test_empty_is_unknown(self):
        v = combine("t", "A", [])
        self.assertEqual(v.status, U)
        self.assertEqual(v.exit_code, 3)

    def test_unknown_only(self):
        self.assertEqual(combine("t", "A", [f("http", U, NONE)]).status, U)

    def test_findings_and_ids_kept(self):
        fs = [f("http", P, LOW)]
        v = combine("host", "PHP2Shell", fs)
        self.assertEqual((v.target, v.advisory_id, v.findings), ("host", "PHP2Shell", fs))


class UpstreamTests(unittest.TestCase):
    def setUp(self):
        self.adv = find_advisory(load_advisories(), "PHP2Shell")

    def test_vendor_style_version_is_not_trusted(self):
        r = check_upstream_version(self.adv, "8.1.2-1ubuntu2.28")
        self.assertEqual((r.status, r.confidence, r.provider), (V, MED, "upstream"))
        self.assertIn("backport", r.reason)

    def test_fixed_upstream(self):
        self.assertEqual(check_upstream_version(self.adv, "8.4.27").status, P)

    def test_unparseable(self):
        self.assertEqual(check_upstream_version(self.adv, "banana").status, U)


if __name__ == "__main__":
    unittest.main()
