"""Check the machine ispatched runs on."""

import posixpath
import re

from .discovery import discover_serving_php, read_os_release
from .engine import combine
from .model import Confidence, Finding, Status, Verdict
from .providers.dpkg import check_dpkg
from .providers.rpm import check_rpm
from .providers.upstream import check_upstream_version

DPKG_IDS = ("debian", "ubuntu")
RPM_IDS = ("rhel", "centos", "rocky", "almalinux")


def _root_only(system, path):
    info = system.file_owner_mode(path)
    return info is not None and info[0] == 0 and not info[1] & 0o022


def _trusted_binary(system, path):
    """The file and every directory above it are root-owned and not group/other writable.

    A writable ancestor would let another user swap the file between this check and the
    execution, so an unreadable or writable ancestor means "do not execute".
    """
    if not path or not path.startswith("/") or not _root_only(system, path):
        return False
    parent = posixpath.dirname(path)
    while True:
        if not _root_only(system, parent):
            return False
        if parent == "/":
            return True
        parent = posixpath.dirname(parent)


def _upstream_fallback(advisory, system, osid, inst):
    unknown = lambda why: Finding("upstream", Status.UNKNOWN, Confidence.NONE,
                                  "unsupported OS '%s' and %s" % (osid, why))
    if inst.kind != "fpm":
        return unknown("the Apache module's version cannot be read safely")
    if not _trusted_binary(system, inst.exe):
        return unknown("%s is not a root-owned binary in root-owned, non-writable directories" % inst.exe)
    rc, out = system.run([inst.exe, "-v"])
    match = re.search(r"PHP (\d+\.\d+\.\d+\S*)", out)
    note = " (unsupported OS '%s': upstream comparison only)" % osid
    if rc != 0 or not match:
        return unknown("PHP version unreadable")
    f = check_upstream_version(advisory, match.group(1))
    f.reason += note
    return f


def run_server(advisory, system):
    target = "this server"
    instances = discover_serving_php(system)
    if not instances:
        reason = "No PHP serving process found"
        if not system.is_root():
            reason += " (cannot inspect other users' processes; run as root)"
        return Verdict(target, advisory.id, Status.UNKNOWN, Confidence.NONE, reason, [])
    osr = read_os_release(system)
    osid = osr["id"]
    findings = []
    for inst in instances:
        if inst.exe is None:
            findings.append(Finding("discovery", Status.UNKNOWN, Confidence.NONE,
                                    "Apache has a PHP module loaded but its file could not be located"))
        elif osid in DPKG_IDS:
            findings.append(check_dpkg(advisory, system, inst, osr))
        elif osid in RPM_IDS:
            findings.append(check_rpm(advisory, system, inst, osr))
        else:
            findings.append(_upstream_fallback(advisory, system, osid, inst))
    if (not any(f.status == Status.POTENTIALLY_VULNERABLE for f in findings)
            and any(f.status == Status.UNKNOWN for f in findings)):
        bad = [f for f in findings if f.status == Status.UNKNOWN][0]
        return Verdict(target, advisory.id, Status.UNKNOWN, Confidence.NONE, bad.reason, findings)
    return combine(target, advisory.id, findings)
