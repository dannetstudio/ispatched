# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `--same-host`: do not follow HTTP redirects to a different host (a leading `www.` is
  ignored); the target is reported as `unknown`.

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
