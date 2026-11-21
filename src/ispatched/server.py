"""Check the machine ispatched runs on."""

import re

from .discovery import discover_serving_php, read_os_release
from .engine import combine
from .model import Confidence, Status, Verdict
from .providers.dpkg import check_dpkg
from .providers.rpm import check_rpm
from .providers.upstream import check_upstream_version

DPKG_IDS = ("debian", "ubuntu")
RPM_IDS = ("rhel", "centos", "rocky", "almalinux")


def _upstream_fallback(advisory, system, osid):
    rc, out = system.run(["php-fpm", "-v"])
    match = re.search(r"PHP (\d+\.\d+\.\d+\S*)", out)
    note = " (unsupported OS '%s': upstream comparison only)" % osid
    if rc != 0 or not match:
        from .model import Finding
        return Finding("upstream", Status.UNKNOWN, Confidence.NONE,
                       "unsupported OS '%s' and PHP version unreadable" % osid)
    f = check_upstream_version(advisory, match.group(1))
    f.reason += note
    return f


def run_server(advisory, system):
    target = "this server"
    instances = discover_serving_php(system)
    if not instances:
        return Verdict(target, advisory.id, Status.UNKNOWN, Confidence.NONE,
                       "No PHP serving process found", [])
    osr = read_os_release(system)
    osid = osr["id"]
    findings = []
    for inst in instances:
        if osid in DPKG_IDS:
            findings.append(check_dpkg(advisory, system, inst, osr))
        elif osid in RPM_IDS:
            findings.append(check_rpm(advisory, system, inst, osr))
        else:
            findings.append(_upstream_fallback(advisory, system, osid))
    if (not any(f.status == Status.POTENTIALLY_VULNERABLE for f in findings)
            and any(f.status == Status.UNKNOWN for f in findings)):
        bad = [f for f in findings if f.status == Status.UNKNOWN][0]
        return Verdict(target, advisory.id, Status.UNKNOWN, Confidence.NONE, bad.reason, findings)
    return combine(target, advisory.id, findings)
