"""HTTP header provider: reads the PHP version a site advertises.

Evidence is LOW by design: headers are announced, can be spoofed or hidden, and
say nothing about vendor backports. Only ``HEAD`` is sent (``GET`` only after a
405/501), redirects are followed by hand so scheme and count are enforced, and
no body is ever read beyond a small cap.
"""

import re
import socket
import ssl
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from urllib.parse import urljoin, urlsplit

from ..model import Confidence, Finding, Status
from ..versions import parse_php_version

USER_AGENT = "ispatched/0.1 (+https://github.com/dannetstudio/ispatched)"
_PHP_IN_HEADER = re.compile(r"PHP/(\d+\.\d+\.\d+[^\s;,()]*)", re.I)
_READ_CAP = 4096


def classify_branch_version(advisory, version):
    """Judge a plain upstream-style PHP version against an advisory."""
    if version.prerelease:
        return Status.UNKNOWN
    if version.branch in advisory.eol_branches:
        return Status.POTENTIALLY_VULNERABLE
    fixed = advisory.upstream_fixed.get(version.branch)
    if fixed is None:
        return Status.UNKNOWN
    if version.patch >= fixed:
        return Status.PATCHED
    return Status.POTENTIALLY_VULNERABLE


def _unknown(reason, final_url, headers=None):
    return Finding("http", Status.UNKNOWN, Confidence.NONE, reason,
                   {"final_url": final_url, "headers": headers or {}, "php_version": None})


def _request(url, timeout, method):
    parts = urlsplit(url)
    cls = HTTPSConnection if parts.scheme == "https" else HTTPConnection
    kwargs = {"timeout": timeout}
    if parts.scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    conn = cls(parts.hostname, parts.port, **kwargs)
    try:
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*",
                                            "Connection": "close"})
        resp = conn.getresponse()
        if method == "GET":
            resp.read(_READ_CAP)
        headers = dict((k.lower(), v) for k, v in resp.getheaders())
        return resp.status, headers
    finally:
        conn.close()


def _fetch(url, timeout):
    status, headers = _request(url, timeout, "HEAD")
    if status in (405, 501):
        status, headers = _request(url, timeout, "GET")
    return status, headers


def check_url(advisory, url, timeout=10.0, max_redirects=5):
    if "://" not in url:
        url = "https://" + url
    if urlsplit(url).scheme not in ("http", "https"):
        return _unknown("unsupported URL scheme", url)
    current = url
    redirects = 0
    while True:
        try:
            status, headers = _fetch(current, timeout)
        except (OSError, HTTPException, socket.timeout, ValueError) as exc:
            return _unknown("request failed: %s" % (exc or exc.__class__.__name__), current)
        location = headers.get("location")
        if status in (301, 302, 303, 307, 308) and location:
            redirects += 1
            if redirects > max_redirects:
                return _unknown("too many redirects", current)
            target = urljoin(current, location)
            if urlsplit(target).scheme not in ("http", "https"):
                return _unknown("unsupported redirect to %s" % target, current)
            current = target
            continue
        break

    seen = {}
    versions = []
    for name in ("server", "x-powered-by"):
        value = headers.get(name, "")
        seen[name] = value
        for match in _PHP_IN_HEADER.finditer(value):
            parsed = parse_php_version(match.group(1))
            if parsed is not None:
                versions.append((match.group(1), parsed))
    shown = dict((k, v) for k, v in seen.items() if v)
    if not versions:
        return _unknown("PHP version not found", current, shown)

    # Several advertised versions: the most pessimistic one decides.
    verdicts = [(classify_branch_version(advisory, v), text) for text, v in versions]
    order = {Status.POTENTIALLY_VULNERABLE: 0, Status.UNKNOWN: 1, Status.PATCHED: 2}
    verdict, text = sorted(verdicts, key=lambda p: order[p[0]])[0]
    evidence = {"final_url": current, "headers": shown, "php_version": text}
    if verdict == Status.PATCHED:
        reason = "PHP %s advertised; installed build not verified." % text
    elif verdict == Status.POTENTIALLY_VULNERABLE:
        reason = ("PHP %s advertised: potentially vulnerable. "
                  "HTTP headers cannot show backported fixes." % text)
    else:
        reason = "PHP %s advertised; cannot classify this version." % text
    return Finding("http", verdict, Confidence.LOW, reason, evidence)
