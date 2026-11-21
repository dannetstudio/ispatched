"""Find the PHP that actually serves requests (never the CLI ``php``)."""

import os

CLOCK_TICKS = 100


class PhpInstance(object):
    __slots__ = ("pid", "exe", "kind", "started_at")

    def __init__(self, pid, exe, kind, started_at):
        self.pid = pid
        self.exe = exe
        self.kind = kind
        self.started_at = started_at

    def __repr__(self):
        return "PhpInstance(%s, %s, %s)" % (self.pid, self.exe, self.kind)


def _boot_time(system):
    for line in (system.read_text("/proc/stat") or "").splitlines():
        if line.startswith("btime"):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def _started_at(system, pid, btime):
    stat = system.read_text("/proc/%s/stat" % pid)
    if not stat or btime is None or ")" not in stat:
        return None
    rest = stat.rsplit(")", 1)[1].split()
    try:
        return btime + int(rest[19]) / float(CLOCK_TICKS)
    except (IndexError, ValueError):
        return None


def discover_serving_php(system):
    btime = _boot_time(system)
    found = []
    pids = sorted((n for n in system.listdir("/proc") if n.isdigit()), key=int)
    for name in pids:
        exe = system.readlink("/proc/%s/exe" % name)
        if not exe:
            continue
        exe = exe.replace(" (deleted)", "")
        base = os.path.basename(exe)
        kind = None
        if base.startswith("php-fpm"):
            kind = "fpm"
        elif base in ("apache2", "httpd"):
            if "libphp" in (system.read_text("/proc/%s/maps" % name) or ""):
                kind = "apache-module"
        if kind:
            found.append(PhpInstance(int(name), exe, kind, _started_at(system, name, btime)))
    return found


def read_os_release(system):
    result = {"id": "", "version_id": ""}
    for line in (system.read_text("/etc/os-release") or "").splitlines():
        key, _, value = line.partition("=")
        if key in ("ID", "VERSION_ID"):
            result[key.lower()] = value.strip().strip('"\'')
    return result
