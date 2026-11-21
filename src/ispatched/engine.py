"""Turns provider findings into one verdict and runs the URL check."""

from .model import Confidence, Status, Verdict
from .providers.http import check_url

VENDOR_PROVIDERS = ("dpkg", "rpm")


def _top(findings):
    return max(findings, key=lambda f: int(f.confidence))


def combine(target, advisory_id, findings):
    """Merge findings: vendor package evidence first, otherwise the pessimist wins."""
    findings = list(findings)
    vendor = [f for f in findings if f.provider in VENDOR_PROVIDERS]

    vendor_bad = [f for f in vendor if f.status == Status.POTENTIALLY_VULNERABLE]
    if vendor_bad:
        d = _top(vendor_bad)
        return Verdict(target, advisory_id, d.status, d.confidence,
                       "%s: %s" % (d.provider, d.reason), findings)
    vendor_ok = [f for f in vendor if f.status == Status.PATCHED]
    if vendor_ok:
        d = _top(vendor_ok)
        return Verdict(target, advisory_id, Status.PATCHED, d.confidence,
                       "%s decided: %s" % (d.provider, d.reason), findings)

    bad = [f for f in findings if f.status == Status.POTENTIALLY_VULNERABLE]
    if bad:
        d = _top(bad)
        return Verdict(target, advisory_id, d.status, d.confidence,
                       "%s: %s" % (d.provider, d.reason), findings)
    ok = [f for f in findings if f.status == Status.PATCHED and f.confidence > Confidence.NONE]
    if ok:
        d = _top(ok)
        unsure = [f for f in findings if f.status == Status.UNKNOWN and f.confidence >= d.confidence]
        if not unsure:
            return Verdict(target, advisory_id, Status.PATCHED, d.confidence,
                           "%s: %s" % (d.provider, d.reason), findings)
    reason = findings[0].reason if findings else "no provider produced evidence"
    return Verdict(target, advisory_id, Status.UNKNOWN, Confidence.NONE, reason, findings)


def run_url(advisory, url, timeout=10.0):
    finding = check_url(advisory, url, timeout=timeout)
    return combine(url, advisory.id, [finding])
