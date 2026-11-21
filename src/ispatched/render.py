"""Output formats: text for people, JSON for scripts, SARIF for CI."""

import json

from . import __version__
from .model import Status

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def render_text(verdicts):
    lines = []
    for v in verdicts:
        label = v.status.value.replace("_", " ").upper()
        lines.append("%s (%s): %s → %s" % (label, v.confidence.name.lower(), v.target, v.reason))
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
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": v.target}}}],
        })
    doc = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "ispatched", "version": __version__,
                            "informationUri": "https://github.com/dannetstudio/ispatched",
                            "rules": list(rules.values())}},
        "results": results,
    }]}
    return json.dumps(doc, indent=2)


RENDERERS = {"text": render_text, "json": render_json, "sarif": render_sarif}
