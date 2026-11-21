# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.2] - 2026-11-21

### Changed
- `--timeout` is now a total time limit per target (shared by a whole redirect chain and
  enforced even against servers that send data slowly), not a limit per socket operation.
- Process start times use the system's real clock tick rate instead of a fixed 100.

## [0.2.1] - 2026-11-21

### Changed
- The text output shows the final URL when a redirect was followed.
- SARIF locations for `--server` use `urn:ispatched:host:<hostname>` instead of a literal
  "this server".
- A PHP process whose binary or `libphp` was replaced after it started is never reported as
  patched: restart PHP-FPM or Apache.

## [0.2.0] - 2026-11-21

### Added
- CI badge, project URLs in the package metadata, issue and pull request templates,
  Dependabot for GitHub Actions and a code of conduct.
- `--same-host`: do not follow HTTP redirects to a different host (a leading `www.` is
  ignored); the target is reported as `unknown`.

### Changed
- `user:password@` in a URL is never echoed in any output.
- Equivalent spellings of one target (scheme case, default port) are checked once.
- Removed a leftover fallback stub from `__main__.py`.

## [0.1.0] - 2026-11-21

First release.

### Added
- Advisories as JSON data, with the built-in `PHP2Shell` advisory (CVE-2026-109618 and
  CVE-2026-109619) and verified vendor rows for Debian, Ubuntu and RHEL.
- Providers: `http` (headers, bounded redirects), `upstream`, `dpkg`, `rpm`.
- Detection of the PHP that actually serves requests (PHP-FPM, Apache with `libphp`) and of
  workers that were not restarted after the update.
- Verdicts `patched`, `potentially_vulnerable`, `unknown` with explicit confidence, and
  exit codes `0`, `1`, `3` (usage error `2`).
- Output as text, JSON and SARIF 2.1.0; `--targets` batch mode with bounded concurrency;
  `--advisories` for custom advisory directories.
- Documentation in English and Spanish.
