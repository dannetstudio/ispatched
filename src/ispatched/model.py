"""Core data types shared by every provider and renderer."""

from enum import Enum, IntEnum


class Status(str, Enum):
    PATCHED = "patched"
    POTENTIALLY_VULNERABLE = "potentially_vulnerable"
    UNKNOWN = "unknown"


class Confidence(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


EXIT_CODES = {
    Status.PATCHED: 0,
    Status.POTENTIALLY_VULNERABLE: 1,
    Status.UNKNOWN: 3,
}


class IspatchedError(Exception):
    """A user-facing error: the CLI prints the message and exits with 2."""


class Finding(object):
    """What one provider concluded, and how much evidence stands behind it."""

    __slots__ = ("provider", "status", "confidence", "reason", "evidence")

    def __init__(self, provider, status, confidence, reason, evidence=None):
        self.provider = provider
        self.status = status
        self.confidence = confidence
        self.reason = reason
        self.evidence = evidence

    def to_dict(self):
        return {
            "provider": self.provider,
            "status": self.status.value,
            "confidence": self.confidence.name.lower(),
            "reason": self.reason,
            "evidence": self.evidence,
        }


class Verdict(object):
    """The combined answer for one target and one advisory."""

    __slots__ = ("target", "advisory_id", "status", "confidence", "reason", "findings")

    def __init__(self, target, advisory_id, status, confidence, reason, findings):
        self.target = target
        self.advisory_id = advisory_id
        self.status = status
        self.confidence = confidence
        self.reason = reason
        self.findings = list(findings)

    @property
    def exit_code(self):
        return EXIT_CODES[self.status]

    def to_dict(self):
        return {
            "target": self.target,
            "advisory": self.advisory_id,
            "status": self.status.value,
            "confidence": self.confidence.name.lower(),
            "reason": self.reason,
            "exit_code": self.exit_code,
            "findings": [f.to_dict() for f in self.findings],
        }
