"""Advisories are data: one JSON file per advisory, validated on load."""

import json
import os
import re

from ispatched.model import IspatchedError

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "advisories")
VENDORS = ("debian", "ubuntu", "rhel")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class VendorFix(object):
    """The package version in which a vendor shipped the fix for one release."""

    __slots__ = ("vendor", "release", "package", "fixed", "url", "verified_on")

    def __init__(self, vendor, release, package, fixed, url, verified_on=""):
        self.vendor = vendor
        self.release = release
        self.package = package
        self.fixed = fixed
        self.url = url
        self.verified_on = verified_on or ""


class Advisory(object):
    __slots__ = (
        "id", "aliases", "title", "summary", "published", "references",
        "upstream_fixed", "eol_branches", "vendors", "notes",
    )

    def __init__(self, id, aliases, title, summary, published, references,
                 upstream_fixed, eol_branches, vendors, notes=""):
        self.id = id
        self.aliases = list(aliases)
        self.title = title
        self.summary = summary
        self.published = published
        self.references = list(references)
        self.upstream_fixed = dict(upstream_fixed)
        self.eol_branches = list(eol_branches)
        self.vendors = list(vendors)
        self.notes = notes

    def usable_vendor_fixes(self):
        """Vendor rows we are allowed to base a verdict on (those we verified)."""
        return [v for v in self.vendors if v.verified_on]

    def names(self):
        return [self.id] + self.aliases


def _fail(path, message):
    raise IspatchedError("%s: %s" % (os.path.basename(path), message))


def _need(path, data, key, kind):
    if key not in data:
        _fail(path, "missing required key '%s'" % key)
    if not isinstance(data[key], kind):
        _fail(path, "'%s' has the wrong type" % key)
    return data[key]


def _parse(path, data):
    if not isinstance(data, dict):
        _fail(path, "top level must be an object")
    published = _need(path, data, "published", str)
    if not _DATE_RE.match(published):
        _fail(path, "'published' must be YYYY-MM-DD")
    upstream = _need(path, data, "upstream_fixed", dict)
    for branch, patch in upstream.items():
        if not isinstance(branch, str) or not isinstance(patch, int) or isinstance(patch, bool):
            _fail(path, "'upstream_fixed' must map branch strings to integers")
    vendors = []
    for row in _need(path, data, "vendors", list):
        if not isinstance(row, dict):
            _fail(path, "each vendor row must be an object")
        for key in ("vendor", "release", "package", "fixed", "url"):
            if not isinstance(row.get(key), str) or not row.get(key):
                _fail(path, "vendor row needs a non-empty '%s'" % key)
        if row["vendor"] not in VENDORS:
            _fail(path, "unknown vendor '%s' (allowed: %s)" % (row["vendor"], ", ".join(VENDORS)))
        verified = row.get("verified_on", "")
        if verified and (not isinstance(verified, str) or not _DATE_RE.match(verified)):
            _fail(path, "'verified_on' must be YYYY-MM-DD")
        vendors.append(VendorFix(row["vendor"], row["release"], row["package"],
                                 row["fixed"], row["url"], verified))
    for key in ("aliases", "references", "eol_branches"):
        if not all(isinstance(item, str) for item in _need(path, data, key, list)):
            _fail(path, "'%s' must contain only strings" % key)
    return Advisory(
        id=_need(path, data, "id", str),
        aliases=_need(path, data, "aliases", list),
        title=_need(path, data, "title", str),
        summary=_need(path, data, "summary", str),
        published=published,
        references=_need(path, data, "references", list),
        upstream_fixed=upstream,
        eol_branches=_need(path, data, "eol_branches", list),
        vendors=vendors,
        notes=data.get("notes", ""),
    )


def _load_dir(directory):
    found = {}
    if not os.path.isdir(directory):
        raise IspatchedError("Advisory directory not found: %s" % directory)
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except ValueError as exc:
            _fail(path, "invalid JSON (%s)" % exc)
        except OSError as exc:
            _fail(path, "cannot be read (%s)" % exc)
        advisory = _parse(path, data)
        found[advisory.id] = advisory
    return found


def load_advisories(extra_dirs=None):
    """Load built-in advisories, then ``extra_dirs`` (later ones override by id)."""
    advisories = _load_dir(BUILTIN_DIR)
    for directory in extra_dirs or []:
        advisories.update(_load_dir(directory))
    return advisories


def find_advisory(advisories, name):
    wanted = name.lower()
    for advisory in advisories.values():
        if any(n.lower() == wanted for n in advisory.names()):
            return advisory
    raise IspatchedError("Unknown advisory: %s. Run 'ispatched list'." % name)
