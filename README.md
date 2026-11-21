# ispatched — is this host patched against that CVE?

[English](README.md) · [Español](README.es.md)

When a critical CVE lands, every sysadmin asks the same thing: **is *my* server already
patched?** The answer is rarely "look at the version number". Debian, Ubuntu and Red Hat
backport fixes without changing the upstream version, so `PHP 8.1.2` can be fixed on one
host and vulnerable on another. Banners can be hidden or forged, and the PHP that serves
your site is often not the `php` your shell finds first.

`ispatched` answers the question honestly. It collects whatever evidence it can reach,
says **how strong that evidence is**, and never claims more than it knows. It starts with
**PHP2Shell** (CVE-2026-109618 and CVE-2026-109619), and new advisories are plain JSON
files, so adding the next CVE does not require touching code.

- Python 3.6+, standard library only. Nothing to install on a typical server.
- Checks a **URL** (HTTP headers) or **the machine it runs on** (`--server`: dpkg/rpm package
  evidence for the PHP that is actually serving requests, and whether it was restarted
  after the update).
- Output for people (`text`), scripts (`json`) and CI (`sarif`), with exit codes for cron.
- It never sends an exploit payload and never changes anything on the system.

> **Use it only on systems you own or have permission to test.** See
> [Responsible use](#responsible-use).

## Contents

1. [Quick start](#quick-start)
2. [What happened: PHP2Shell](#what-happened-php2shell)
3. [How a verdict is decided](#how-a-verdict-is-decided)
4. [What ispatched does not prove](#what-ispatched-does-not-prove)
5. [If the result is `potentially_vulnerable`](#if-the-result-is-potentially_vulnerable)
6. [Extending it](#extending-it)
7. [Alternatives and credits](#alternatives-and-credits)
8. [Contributing, security, license](#contributing-security-license)

## Quick start

```sh
pip install git+https://github.com/dannetstudio/ispatched   # or just clone the repo
python3 -m ispatched list
```

```text
PHP2Shell  PHP2Shell: remote code execution in the PHP core  (CVE-2026-109618, CVE-2026-109619)
```

Check one or more sites (a bare hostname gets `https://`):

```sh
ispatched CVE-2026-109618 https://example.com
ispatched PHP2Shell https://a.example https://b.example --format json
ispatched PHP2Shell --targets sites.txt          # one URL per line
```

```text
POTENTIALLY VULNERABLE (low): http://127.0.0.1:8761 → http: PHP 8.4.26 advertised: potentially vulnerable. HTTP headers cannot show backported fixes.
PATCHED (low): http://127.0.0.1:8762 → http: PHP 8.4.27 advertised; installed build not verified.
UNKNOWN (none): http://127.0.0.1:1 → request failed: [Errno 111] Connection refused
```

Check the machine you are logged into (the strongest evidence, because it reads the
package database instead of a banner):

```sh
ispatched PHP2Shell --server
```

```text
UNKNOWN (none): this server → No PHP serving process found
```

(That sample comes from a machine without PHP. On a web server you get the installed
package, the fixed version it was compared with, and a note if the workers have not been
restarted since the update.)

### Options

| Option | Meaning |
| --- | --- |
| `ispatched list` | Show the advisories included in the package. |
| `ADVISORY` | An advisory id or any alias, e.g. `PHP2Shell`, `CVE-2026-109618`. |
| `URL ...` | URLs or bare hostnames to check. |
| `--server` | Check this machine instead of (or as well as) URLs. |
| `--targets FILE` | File with one URL per line (blank lines and `#` comments are skipped). |
| `--format text\|json\|sarif` | Output format. SARIF 2.1.0 goes straight into GitHub code scanning. |
| `--advisories DIR` | Load extra advisory JSON files from `DIR` (repeatable). |
| `--timeout SECONDS` | Timeout per network operation, default 10 (a slow redirect chain can take longer overall). |
| `--workers N` | Concurrent URL checks, default 5, maximum 20. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `patched` for every target. |
| `1` | At least one target is `potentially_vulnerable`. |
| `2` | Usage error (bad option, unknown advisory, unreadable file). |
| `3` | No target is vulnerable, but at least one is `unknown`. |

That makes it usable from cron or CI: `ispatched PHP2Shell --server || notify-someone`.

## What happened: PHP2Shell

*Everything in this section is linked to its source. Dates are 2026.*

- **Two flaws in the PHP core, not in a library.** The PHP project describes them as
  [CVE-2026-109618, "RCE via OOM corruption"](https://github.com/advisories/GHSA-w8hw-w9fx-j79w):
  out-of-memory handling can interrupt PHP while internal request data is only partly
  initialized, and request cleanup then treats the invalid data as valid; and
  [CVE-2026-109619, "RCE via stale global state"](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp):
  request-owned internal state survives after its memory was freed, and a later request
  handled by the same worker can use it. Both can allow unauthenticated remote code
  execution ([php.net advisory, 21 Oct](https://www.php.net/archive/2026.php#2026-10-21-5)).
- **Why the engine matters.** The bugs live in PHP itself, so every PHP application is
  exposed regardless of its own code or framework. PHP says all installations serving web
  requests are at risk (PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP, LiteSpeed) and
  rates mod_php highest, with a demonstrated exploit that triggers before any application
  code runs ([php.net](https://www.php.net/archive/2026.php#2026-10-21-5)).
- **Timeline.** The flaws leaked on 20 October and were patched on 21 October
  ([PHP2Shell on Wikipedia](https://en.wikipedia.org/wiki/PHP2Shell);
  [Wiz write-up](https://www.wiz.io/blog/php2shell-php-rce), which named it "PHP2Shell").
- **Fixed upstream in** 8.5.12, 8.4.27, 8.3.36 and 8.2.35. PHP 8.1 and older no longer
  receive upstream updates; the project published minimal source backports for 7.4, 8.0
  and 8.1 for people building from source ([php.net](https://www.php.net/archive/2026.php#2026-10-21-5)).
  Versions as old as 5.4 are affected ([Wikipedia](https://en.wikipedia.org/wiki/PHP2Shell)).
- **Is it being exploited? The sources disagree.** Amazon's threat intelligence team
  [reported exploitation](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
  and watchTowr
  [published an FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/) treating it as
  actively dangerous. Sansec
  [reports that the public proofs of concept fail on default installations](https://sansec.io/research/php2shell)
  and that mass exploitation is therefore less likely. `ispatched` does not pick a side:
  the safe reading is that a patch is needed either way, and a working exploit is a matter
  of time and configuration.
- **Why a version number misleads.** Distributions fix old branches by backporting, keeping
  the upstream version. `8.1.2-1ubuntu2.28` on Ubuntu 22.04 contains the fix; plain `8.1.2`
  from a hand-built source does not. Reading `X-Powered-By: PHP/8.1.2` cannot tell them
  apart, so HTTP evidence is rated *low* and is never reported as "vulnerable", only as
  "potentially vulnerable".

Related defensive references: the Dutch NCSC's
[NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) and the
[UK NCSC notice](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php).

## How a verdict is decided

Each target gets one of three statuses, backed by one or more *findings*, each from a
*provider* with a *confidence*:

| Provider | Looks at | Confidence |
| --- | --- | --- |
| `dpkg` | Debian/Ubuntu package that owns the serving PHP binary, compared with the vendor's fixed version | **high** |
| `rpm` | RHEL-family package that owns the serving PHP binary (epoch-aware) | **high** |
| `upstream` | The PHP version against upstream fixed versions (cannot see backports) | medium |
| `http` | `Server` / `X-Powered-By` headers, following up to 5 http(s) redirects | low |

Statuses: `patched`, `potentially_vulnerable`, `unknown`. There is deliberately no
"confirmed vulnerable": without exploiting the flaw, nobody can confirm it.

Rules, in order of strength: vendor package evidence beats upstream versions, which beat
headers. If evidence conflicts, the more pessimistic reading wins, except that a vendor
package (high confidence) overrides a header guess. An `unknown` finding of equal or higher
confidence stops a lower-confidence "patched" from standing. `--server` also notices when
the patched package was installed **after** the PHP workers started, because those
workers still run the old code: restart PHP-FPM or Apache.

Full detail and the reasoning: [docs/how-verdicts-work.md](docs/how-verdicts-work.md).

## What ispatched does not prove

- A header saying `PHP/8.4.27` shows what the server *advertises*. It can be forged or be a
  different layer (a proxy) than the one running PHP. That is why a `patched` result from
  URL checks says "installed build not verified".
- A host with no `X-Powered-By` header (the sensible default) comes back `unknown`.
  That is not a defect: hiding the version is good practice. Use `--server` on the host.
- Vendor tables cover what has been verified so far (Debian 12/13, Ubuntu 14.04–26.10,
  RHEL 7/8/9). Other distributions fall back to an upstream comparison or `unknown`.
  See [docs/unverified-vendor-data.md](docs/unverified-vendor-data.md).
- `--server` needs root to see other users' processes (PHP-FPM usually runs as `www-data`).
  Without it you get `unknown` with a note saying so.
- Vendor evidence applies only to the distribution's own build. A PHP from another source
  (Sury/Ondřej PPA, Remi, a RHEL module stream, a source build) is compared against upstream
  releases only, at medium confidence, and the reason says so.
- Several PHP versions on one box: every serving process is checked, and one `unknown`
  instance makes the whole verdict `unknown` rather than hiding behind a patched one.
- It does not scan for compromise. If you ran an exposed, unpatched PHP, look at your logs
  and files as well as patching.

## If the result is `potentially_vulnerable`

1. **Update PHP** to a fixed upstream release (8.2.35, 8.3.36, 8.4.27, 8.5.12) or your
   vendor's patched package. For PHP 8.1 and older, only a vendor backport or a move to a
   supported branch fixes it.
2. **Restart the workers**: `systemctl restart php8.x-fpm` or reload Apache. An updated
   package does not protect processes that were started earlier.
3. **If you cannot update right now**, the PHP project lists measures that *reduce
   exposure but do not make an installation safe*
   ([php.net](https://www.php.net/archive/2026.php#2026-10-21-5)):
   - `session.upload_progress.enabled=0` in `php.ini` or the pool config (not via
     `ini_set()` or `.user.ini`), then restart every worker. It blocks the confirmed paths
     for CVE-2026-109619, not other variants.
   - On PHP 8.5, `fatal_error_backtraces=0`.
   - `memory_limit=-1` set so applications cannot override it (`php_admin_value`), and a
     low `post_max_size` (8M, or 32M if you need uploads) for CVE-2026-109618. An
     underlying allocation failure can still reach the vulnerable path.
   - Enforce request-size, field-count and multipart-part limits at the web server or proxy.
   - Do not use `RLIMIT_AS` / `RLIMIT_DATA`: they can trigger the vulnerable allocation failure.
4. Re-run `ispatched` afterwards.

## Extending it

- **A new CVE** is a JSON file. Copy the example in
  [docs/adding-an-advisory.md](docs/adding-an-advisory.md), run it with
  `ispatched --advisories ./my-advisories NEW-ID --server`, and send it as a pull request.
- **A new source of evidence** (Alpine, cPanel/CloudLinux, Plesk, Sury/Remi, containers) is a
  provider: a function returning a `Finding`. See
  [docs/writing-a-provider.md](docs/writing-a-provider.md).
- Vendor rows without a `verified_on` date are ignored on purpose: unverified data must not
  produce a "patched".

## Alternatives and credits

`ispatched` was inspired by [openai/php2shell-checker](https://github.com/openai/php2shell-checker),
which showed what a checker could look like for this CVE. The code here is written from scratch
with a different design (advisories as data, pluggable providers, honest confidence levels).
Also worth knowing:

- [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell): the Dutch NCSC's reference material.
- [Sansec](https://sansec.io/research/php2shell): analysis, and tooling for Magento and PHP shops.
- Your distribution's own tracker: [Debian](https://security-tracker.debian.org/tracker/CVE-2026-109618),
  [Ubuntu](https://ubuntu.com/security/CVE-2026-109618),
  [Red Hat](https://access.redhat.com/security/cve/CVE-2026-109618).

## Contributing, security, license

- Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md). Advisory data and new
  providers are the most useful.
- Found a problem in `ispatched` itself? See [SECURITY.md](SECURITY.md).
- Release notes: [CHANGELOG.md](CHANGELOG.md).
- Licensed under Apache-2.0; see [LICENSE](LICENSE).

### Responsible use

`ispatched` sends one ordinary `HEAD` request per URL (a `GET` only if the server refuses
`HEAD`), with a User-Agent that identifies the tool, and it never sends exploit payloads.
Even so, run it only against systems you own or have explicit permission to test. You are
responsible for how you use it.
