"""Version comparison for the formats we meet on real servers.

Three small, dependency-free helpers:

* ``dpkg_compare``  - Debian policy ordering (Debian, Ubuntu).
* ``rpm_compare``   - ``rpmvercmp`` ordering (RHEL, Fedora, Alma, Rocky...).
* ``parse_php_version`` - split a PHP version banner into its numeric parts.
"""

import re


def _split_epoch(text):
    if ":" in text:
        epoch, rest = text.split(":", 1)
        try:
            return int(epoch), rest
        except ValueError:
            return 0, text
    return 0, text


def _sign(a, b):
    return (a > b) - (a < b)


# --------------------------------------------------------------------- dpkg

def _dpkg_order(ch):
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _dpkg_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        # non-digit prefix
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ca = a[i] if i < len(a) and not a[i].isdigit() else ""
            cb = b[j] if j < len(b) and not b[j].isdigit() else ""
            oa, ob = _dpkg_order(ca), _dpkg_order(cb)
            if oa != ob:
                return _sign(oa, ob)
            if ca:
                i += 1
            if cb:
                j += 1
        # digit run
        ni = i
        while ni < len(a) and a[ni].isdigit():
            ni += 1
        nj = j
        while nj < len(b) and b[nj].isdigit():
            nj += 1
        va = int(a[i:ni] or 0)
        vb = int(b[j:nj] or 0)
        if va != vb:
            return _sign(va, vb)
        i, j = ni, nj
    return 0


def _dpkg_split(text):
    epoch, rest = _split_epoch(text)
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def dpkg_compare(a, b):
    """Return -1, 0 or 1 following Debian policy version ordering."""
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return _sign(ea, eb)
    result = _dpkg_part(ua, ub)
    if result:
        return result
    return _dpkg_part(ra, rb)


# ---------------------------------------------------------------------- rpm

def _rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        ta = a[i] if i < len(a) else ""
        tb = b[j] if j < len(b) else ""
        # tilde sorts before everything, even the end of the string
        if ta == "~" or tb == "~":
            if ta != "~":
                return 1
            if tb != "~":
                return -1
            i += 1
            j += 1
            continue
        # caret sorts after the end of the string but before anything else
        if ta == "^" or tb == "^":
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if ta != "^":
                return 1
            if tb != "^":
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        if a[i].isdigit():
            ni = i
            while ni < len(a) and a[ni].isdigit():
                ni += 1
            nj = j
            while nj < len(b) and b[nj].isdigit():
                nj += 1
            sa, sb = a[i:ni], b[j:nj]
            if not sb:  # digits beat letters
                return 1
            va, vb = int(sa), int(sb)
            if va != vb:
                return _sign(va, vb)
        else:
            ni = i
            while ni < len(a) and a[ni].isalpha():
                ni += 1
            nj = j
            while nj < len(b) and b[nj].isalpha():
                nj += 1
            sa, sb = a[i:ni], b[j:nj]
            if not sb:
                return -1
            if sa != sb:
                return _sign(sa, sb)
        i, j = ni, nj
    ra = len(a) - i
    rb = len(b) - j
    if not ra and not rb:
        return 0
    return -1 if not ra else 1


def _rpm_split(text):
    epoch, rest = _split_epoch(text)
    if "-" in rest:
        version, release = rest.rsplit("-", 1)
    else:
        version, release = rest, ""
    return epoch, version, release


def rpm_compare(a, b):
    """Return -1, 0 or 1 following ``rpmvercmp`` on ``[epoch:]version-release``."""
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return _sign(ea, eb)
    result = _rpmvercmp(va, vb)
    if result:
        return result
    if ra and rb:
        return _rpmvercmp(ra, rb)
    return 0


# ---------------------------------------------------------------------- php

_PHP_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(.*)$", re.DOTALL)
_PRERELEASE_RE = re.compile(r"^[-+~.]?(dev|alpha|beta|rc)", re.IGNORECASE)


class PhpVersion(object):
    """A parsed ``major.minor.patch`` PHP version with whatever trails it."""

    __slots__ = ("major", "minor", "patch", "suffix", "prerelease")

    def __init__(self, major, minor, patch, suffix="", prerelease=False):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.suffix = suffix
        self.prerelease = prerelease

    @property
    def branch(self):
        return "%d.%d" % (self.major, self.minor)

    def __repr__(self):
        return "PhpVersion(%d.%d.%d%s)" % (self.major, self.minor, self.patch, self.suffix)


def parse_php_version(text):
    """Parse a PHP version string; return ``None`` when it has no ``X.Y.Z``."""
    if not text:
        return None
    match = _PHP_RE.match(text.strip())
    if not match:
        return None
    suffix = match.group(4)
    return PhpVersion(
        int(match.group(1)), int(match.group(2)), int(match.group(3)),
        suffix, bool(_PRERELEASE_RE.match(suffix)),
    )
