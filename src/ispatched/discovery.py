"""Find the PHP that actually serves requests (never the CLI ``php``)."""

import os

CLOCK_TICKS = 100


class PhpInstance(object):
    __slots__ = ("pid", "exe", "kind", "started_at", "replaced")

    def __init__(self, pid, exe, kind, started_at, replaced=False):
        self.replaced = replaced  # the file this process runs was replaced on disk afterwards
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


def _libphp_path(maps):
    """(path, replaced) of the mapped ``libphp*.so``.

    The path is '' if mapped without a readable path and None if absent."""
    found = None
    for line in maps.splitlines():
        if "libphp" not in line:
            continue
        found = ""
        fields = line.split(None, 5)
        if len(fields) == 6 and "libphp" in os.path.basename(fields[5]):
            return fields[5].replace(" (deleted)", "").strip(), fields[5].rstrip().endswith("(deleted)")
    return found, False


def discover_serving_php(system):
    btime = _boot_time(system)
    found = []
    pids = sorted((n for n in system.listdir("/proc") if n.isdigit()), key=int)
    for name in pids:
        exe = system.readlink("/proc/%s/exe" % name)
        if not exe:
            continue
        replaced = exe.rstrip().endswith("(deleted)")
        exe = exe.replace(" (deleted)", "")
        base = os.path.basename(exe)
        kind = None
        if base.startswith("php-fpm"):
            kind = "fpm"
        elif base in ("apache2", "httpd"):
            lib, lib_replaced = _libphp_path(system.read_text("/proc/%s/maps" % name) or "")
            if lib is not None:
                kind = "apache-module"
                exe = lib or None  # '' = loaded but path unreadable
                replaced = lib_replaced  # the web server binary itself is not what runs PHP
        if kind:
            found.append(PhpInstance(int(name), exe, kind, _started_at(system, name, btime), replaced))
    return found


def read_os_release(system):
    result = {"id": "", "version_id": ""}
    for line in (system.read_text("/etc/os-release") or "").splitlines():
        key, _, value = line.partition("=")
        if key in ("ID", "VERSION_ID"):
            result[key.lower()] = value.strip().strip('"\'')
    return result
