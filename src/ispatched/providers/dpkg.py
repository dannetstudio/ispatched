"""dpkg provider: Debian/Ubuntu package evidence for the serving PHP."""

import re

from ..model import Confidence, Finding, Status
from ..versions import dpkg_compare, upstream_branch
from .upstream import check_upstream_version

_NAME = re.compile(r"php(\d+(?:\.\d+)?)")


def restart_note(system, instance, install_time):
    if install_time is None or instance.started_at is None:
        return None
    if instance.started_at < install_time:
        return ("Patched package installed but PHP workers started before the update; "
                "restart php-fpm/Apache.")
    return None


def _unknown(reason):
    return Finding("dpkg", Status.UNKNOWN, Confidence.NONE, reason)


def foreign_fallback(advisory, installed, package, evidence, why):
    """The package does not come from the vendor the advisory row describes.

    Vendor backport data would be wrong for it, so fall back to the upstream
    comparison (MEDIUM) and say why.
    """
    finding = check_upstream_version(advisory, installed.split(":", 1)[-1], evidence)
    finding.reason = "%s %s %s; upstream comparison only. %s" % (package, installed, why,
                                                                  finding.reason)
    return finding


def _is_vendor_build(vendor, release, installed, row_fixed):
    """True when ``installed`` looks like the distribution's own build of the row's branch."""
    low = installed.lower()
    if "sury" in low or "ondrej" in low:
        return False
    if upstream_branch(installed) != upstream_branch(row_fixed):
        return False
    if vendor == "debian":
        return re.search(r"deb%su\d" % re.escape(release), installed) is not None
    return re.search(r"-\d+ubuntu\d", installed) is not None


def check_dpkg(advisory, system, instance, os_release):
    rc, out = system.run(["dpkg", "-S", instance.exe])
    if rc != 0 or ":" not in out:
        return _unknown("dpkg does not own %s" % instance.exe)
    package = out.splitlines()[0].split(":")[0].split(",")[0].strip()
    rc, out = system.run(["dpkg-query", "-W", "-f", "${Version}\n", package])
    installed = out.strip()
    if rc != 0 or not installed:
        return _unknown("could not read the installed version of %s" % package)
    match = _NAME.search(package)
    key = "php" + match.group(1) if match else package
    osid, rel = os_release.get("id", ""), os_release.get("version_id", "")
    rows = [v for v in advisory.usable_vendor_fixes()
            if v.vendor == osid and v.release == rel and v.package == key]
    evidence = {"package": package, "installed": installed, "exe": instance.exe}
    if not rows:
        return Finding("dpkg", Status.UNKNOWN, Confidence.NONE,
                       "no verified advisory data for %s %s %s" % (osid, rel, key), evidence)
    row = rows[0]
    evidence["fixed"] = row.fixed
    if not _is_vendor_build(osid, rel, installed, row.fixed):
        return foreign_fallback(advisory, installed, package, evidence,
                                "is not the %s %s build the advisory row describes" % (osid, rel))
    if dpkg_compare(installed, row.fixed) < 0:
        return Finding("dpkg", Status.POTENTIALLY_VULNERABLE, Confidence.HIGH,
                       "%s %s is older than the vendor fix %s." % (package, installed, row.fixed),
                       evidence)
    note = restart_note(system, instance,
                        system.read_mtime("/var/lib/dpkg/info/%s.list" % package))
    if note:
        return Finding("dpkg", Status.POTENTIALLY_VULNERABLE, Confidence.HIGH,
                       "%s %s includes the fix. %s" % (package, installed, note), evidence)
    return Finding("dpkg", Status.PATCHED, Confidence.HIGH,
                   "%s %s includes the vendor fix (%s)." % (package, installed, row.fixed), evidence)
