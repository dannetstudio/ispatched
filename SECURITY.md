# Security policy

## Reporting a problem in ispatched

If you find a vulnerability in `ispatched` itself (for example, a way for a remote server's
response to harm the machine running the tool), please report it privately through GitHub:
**Security tab → Report a vulnerability** on
<https://github.com/dannetstudio/ispatched>. Please do not open a public issue.

Include the version (`python3 -m ispatched --help` shows usage; the version is in
`src/ispatched/__init__.py`), what you did, and what happened. You will get an
acknowledgement, and a fix or an explanation as soon as reasonably possible.

## Scope

In scope: how `ispatched` handles untrusted input (HTTP headers and redirects, advisory
files, command output) and anything that makes it modify the system or send more than the
documented requests.

Out of scope: vulnerabilities in PHP itself (report those to the PHP project), and wrong or
missing vendor data (open an issue or pull request instead; see [CONTRIBUTING.md](CONTRIBUTING.md)).

## What the tool does on the network

One `HEAD` request per URL (a `GET` only if `HEAD` is refused with 405/501), at most 5
http(s) redirects, bounded reads, a total time limit per target, and a User-Agent that identifies the tool.
No payloads, no authentication, no credentials in URLs.
