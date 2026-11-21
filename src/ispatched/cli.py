"""Command line interface."""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, urlunsplit

from .advisory import find_advisory, load_advisories
from .engine import run_url
from .model import IspatchedError, Status
from .render import RENDERERS
from .server import run_server
from .system import SystemRunner

_RANK = {Status.POTENTIALLY_VULNERABLE: 2, Status.UNKNOWN: 1, Status.PATCHED: 0}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise IspatchedError(message)


def _parser():
    p = _Parser(prog="ispatched",
                description="Is this host patched against that CVE? "
                            "Usage: ispatched list | ispatched ADVISORY [URL ...] [--server]")
    p.add_argument("advisory", help="'list', or an advisory id/alias such as CVE-2026-109618")
    p.add_argument("urls", nargs="*", help="URLs or bare hostnames to check")
    p.add_argument("--server", action="store_true", help="check this machine")
    p.add_argument("--targets", metavar="FILE", help="file with one URL per line")
    p.add_argument("--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("--advisories", metavar="DIR", action="append", default=[],
                   help="extra directory of advisory JSON files")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--same-host", action="store_true",
                   help="do not follow redirects to a different host (www. is ignored)")
    return p


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalise(url):
    """Add the default scheme and fold equivalent spellings (case, default port) together."""
    if "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        scheme, host, port = parts.scheme.lower(), parts.hostname, parts.port
    except ValueError:
        return url
    if not host:
        return url
    if ":" in host:
        host = "[%s]" % host
    netloc = host + ("" if port in (None, _DEFAULT_PORTS.get(scheme)) else ":%d" % port)
    if "@" in parts.netloc:
        netloc = parts.netloc.rsplit("@", 1)[0] + "@" + netloc
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def _read_targets(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
    except (OSError, ValueError) as exc:
        raise IspatchedError("cannot read targets file %s (%s)" % (path, exc))


def _emit(text):
    try:
        print(text)
    except UnicodeEncodeError:  # C/POSIX locale under cron: degrade instead of crashing
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(text.replace("\u2192", "->").encode(encoding, "replace").decode(encoding))


def _run(argv):
    args = _parser().parse_args(argv)
    advisories = load_advisories(args.advisories)
    if args.advisory == "list":
        for a in advisories.values():
            print("%s  %s  (%s)" % (a.id, a.title, ", ".join(a.aliases)))
        return 0
    advisory = find_advisory(advisories, args.advisory)
    urls = list(args.urls)
    if args.targets:
        urls += _read_targets(args.targets)
    unique = []
    for u in map(_normalise, urls):
        if u not in unique:
            unique.append(u)
    if not unique and not args.server:
        raise IspatchedError("provide at least one URL, --targets FILE or --server")
    workers = max(1, min(args.workers, 20))
    verdicts = []
    if args.server:
        verdicts.append(run_server(advisory, SystemRunner()))
    if unique:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            verdicts.extend(pool.map(lambda u: run_url(advisory, u, timeout=args.timeout,
                                                       same_host=args.same_host), unique))
    _emit(RENDERERS[args.format](verdicts))
    worst = max(verdicts, key=lambda v: _RANK[v.status])
    return worst.exit_code


def main(argv=None):
    try:
        return _run(sys.argv[1:] if argv is None else argv)
    except IspatchedError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except SystemExit as exc:  # argparse --help
        return exc.code if isinstance(exc.code, int) else 0
    except Exception as exc:  # never a traceback: exit 1 would read as "vulnerable"
        sys.stderr.write("error: unexpected failure (%s: %s)\n" % (exc.__class__.__name__, exc))
        return 2
