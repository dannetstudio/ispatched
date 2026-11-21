# Writing a provider

A provider turns one kind of evidence into a `Finding`. Existing ones live in
`src/ispatched/providers/` (`http`, `upstream`, `dpkg`, `rpm`).

## The contract

```python
from ispatched.model import Confidence, Finding, Status

Finding(provider, status, confidence, reason, evidence=None)
```

- `provider`: your provider's short name (`"apk"`).
- `status`: `Status.PATCHED`, `Status.POTENTIALLY_VULNERABLE` or `Status.UNKNOWN`.
- `confidence`: `Confidence.NONE/LOW/MEDIUM/HIGH`. Use `NONE` with `UNKNOWN`. Be modest: high
  confidence means "read from the package database of the machine that serves requests".
- `reason`: one plain sentence a sysadmin can act on.
- `evidence`: a dict of what you read (package, version, path) for JSON and SARIF output.

## Talk to the host through `System`

Never call `subprocess` or open files directly. Use the `System` object so your provider
can be tested without a real machine:

| Method | Returns |
| --- | --- |
| `system.run(argv)` | `(returncode, stdout)`; never raises for a missing command. |
| `system.read_text(path)` | file contents or `None`. |
| `system.listdir(path)` | list of names. |
| `system.readlink(path)` | link target or `None`. |
| `system.read_mtime(path)` | modification time or `None`. |
| `system.now()` | current time. |

In tests, use `FakeSystem` from `tests/fakes.py`, e.g.
`FakeSystem(commands={("apk", "info", "-W", "/usr/sbin/php-fpm83"): (0, "...")})`.

## A server-side provider

The signature the existing package providers use:

```python
def check_apk(advisory, system, instance, os_release):
    """instance has .pid, .exe, .kind and .started_at; os_release has 'id' and 'version_id'."""
    rc, out = system.run(["apk", "info", "-W", instance.exe])
    if rc != 0:
        return Finding("apk", Status.UNKNOWN, Confidence.NONE,
                       "apk does not own %s" % instance.exe)
    ...  # find the matching vendor row, compare versions, return a Finding
```

Look up fixed versions with `advisory.usable_vendor_fixes()` (rows with `verified_on`) and
compare with the helpers in `ispatched.versions` (`dpkg_compare`, `rpm_compare`). If you
need a new ordering (Alpine's `-r` revisions), add it there with tests.

## Wiring it in

- `src/ispatched/server.py` chooses a provider from the `ID` in `/etc/os-release`
  (`DPKG_IDS`, `RPM_IDS`). Add your ids and branch there.
- If your provider reads package databases, add its name to `VENDOR_PROVIDERS` in
  `src/ispatched/engine.py` so that its findings outrank headers, the way `dpkg` and `rpm` do.
- URL-style providers return a `Finding` from a function like
  `check_url(advisory, url, timeout=10.0, max_redirects=5)` and are called from `run_url`.

## Checklist

- Tests first: a vulnerable case, a patched case, and "tool missing / package not found".
- No network in unit tests; use `System` fakes or a local server on `127.0.0.1`.
- Remote data (headers, package names) is untrusted: it is printed to terminals, so keep
  parsing strict. Text output escapes control characters, but don't rely on that alone.
- Python 3.6 compatible: no dataclasses, no walrus, no `match`.
