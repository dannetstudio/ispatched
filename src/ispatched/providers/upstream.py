"""Upstream provider: compares a version against php.net's fixed releases.

It cannot know about distribution backports, so a version on an end-of-life
branch is reported as potentially vulnerable even if a vendor patched it.
"""

from ..model import Confidence, Finding, Status
from ..versions import parse_php_version
from .http import classify_branch_version


def check_upstream_version(advisory, version_text, evidence=None):
    version = parse_php_version(version_text)
    if version is None:
        return Finding("upstream", Status.UNKNOWN, Confidence.NONE,
                       "could not parse PHP version '%s'" % version_text, evidence)
    status = classify_branch_version(advisory, version)
    if status == Status.PATCHED:
        reason = "PHP %s is at or above the upstream fixed release." % version_text
    elif status == Status.POTENTIALLY_VULNERABLE:
        reason = ("PHP %s is below the upstream fix or on an end-of-life branch. "
                  "Upstream comparison cannot see vendor backports." % version_text)
    else:
        reason = "PHP %s cannot be classified against upstream releases." % version_text
    return Finding("upstream", status, Confidence.MEDIUM, reason, evidence)
