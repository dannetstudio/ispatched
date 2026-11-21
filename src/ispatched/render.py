"""Output formats: text for people, JSON for scripts, SARIF for CI."""

import json
import socket

from . import __version__
from .model import Status

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _printable(text):
    """Escape control characters so remote data cannot drive the terminal."""
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
                   for ch in str(text))


def _final_url(verdict):
    """The URL a redirect ended on, when it differs from the one that was asked for."""
    for f in verdict.findings:
        final = (f.evidence or {}).get("final_url") if isinstance(f.evidence, dict) else None
        if final and final != verdict.target:
            return final
    return None


def _sarif_uri(target):
    if "://" in target:
        return target
    return "urn:ispatched:host:%s" % socket.gethostname()


def render_text(verdicts):
    lines = []
    for v in verdicts:
        label = v.status.value.replace("_", " ").upper()
        line = "%s (%s): %s → %s" % (label, v.confidence.name.lower(),
                                    _printable(v.target), _printable(v.reason))
        final = _final_url(v)
        if final:
            line += " (final URL: %s)" % _printable(final)
        lines.append(line)
    return "\n".join(lines)


def render_json(verdicts):
    return json.dumps({"tool": "ispatched", "version": __version__,
                       "results": [v.to_dict() for v in verdicts]}, indent=2)


def render_sarif(verdicts):
    results, rules = [], {}
    for v in verdicts:
        if v.status == Status.PATCHED:
            continue
        rules[v.advisory_id] = {"id": v.advisory_id, "name": v.advisory_id}
        results.append({
            "ruleId": v.advisory_id,
            "level": "warning" if v.status == Status.POTENTIALLY_VULNERABLE else "note",
            "message": {"text": "%s (%s evidence): %s" % (
                v.status.value, v.confidence.name.lower(), v.reason)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _sarif_uri(v.target)}}}],
        })
    doc = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "ispatched", "version": __version__,
                            "informationUri": "https://github.com/dannetstudio/ispatched",
                            "rules": list(rules.values())}},
        "results": results,
    }]}
    return json.dumps(doc, indent=2)


RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif}
