"""rpm provider: RHEL-family package evidence for the serving PHP."""

from ..model import Confidence, Finding, Status
from ..versions import rpm_compare
from .dpkg import restart_note


def _unknown(reason, evidence=None):
    return Finding("rpm", Status.UNKNOWN, Confidence.NONE, reason, evidence)


def check_rpm(advisory, system, instance, os_release):
    rc, out = system.run(["rpm", "-qf", "--qf", "%{NAME}\n", instance.exe])
    package = out.strip().splitlines()[0] if rc == 0 and out.strip() else ""
    if not package:
        return _unknown("rpm does not own %s" % instance.exe)
    rc, out = system.run(["rpm", "-q", "--qf",
                          "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n%{INSTALLTIME}\n", package])
    lines = out.strip().splitlines()
    if rc != 0 or not lines:
        return _unknown("could not read the installed version of %s" % package)
    installed = lines[0]
    try:
        install_time = float(lines[1])
    except (IndexError, ValueError):
        install_time = None
    rel = os_release.get("version_id", "").split(".")[0]
    rows = [v for v in advisory.usable_vendor_fixes()
            if v.vendor == "rhel" and v.release == rel and v.package == "php"]
    evidence = {"package": package, "installed": installed, "exe": instance.exe}
    if not rows:
        return _unknown("no verified advisory data for rhel %s php" % rel, evidence)
    row = rows[0]
    evidence["fixed"] = row.fixed
    if rpm_compare(installed, row.fixed) < 0:
        return Finding("rpm", Status.POTENTIALLY_VULNERABLE, Confidence.HIGH,
                       "%s %s is older than the vendor fix %s." % (package, installed, row.fixed),
                       evidence)
    note = restart_note(system, instance, install_time)
    if note:
        return Finding("rpm", Status.POTENTIALLY_VULNERABLE, Confidence.HIGH,
                       "%s %s includes the fix. %s" % (package, installed, note), evidence)
    return Finding("rpm", Status.PATCHED, Confidence.HIGH,
                   "%s %s includes the vendor fix (%s)." % (package, installed, row.fixed), evidence)
