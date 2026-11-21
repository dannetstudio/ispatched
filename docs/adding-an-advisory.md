# Adding an advisory

Advisories are JSON files. Adding one needs no code. Built-in advisories live in
`src/ispatched/advisories/`; your own can live anywhere and be loaded with
`--advisories DIR` (repeatable; later directories override earlier ones by `id`).

## Example

```json
{
  "id": "EXAMPLE-2026-1",
  "aliases": ["CVE-2026-0001"],
  "title": "Example: remote code execution in the PHP core",
  "summary": "A short, neutral description of the flaw, taken from the primary advisory.",
  "published": "2026-01-15",
  "references": ["https://www.php.net/archive/2026.php"],
  "upstream_fixed": {"8.3": 20, "8.4": 5},
  "eol_branches": ["8.0", "8.1"],
  "vendors": [
    {
      "vendor": "debian",
      "release": "12",
      "package": "php8.2",
      "fixed": "8.2.20-1~deb12u1",
      "url": "https://security-tracker.debian.org/tracker/CVE-2026-0001",
      "verified_on": "2026-01-20"
    }
  ],
  "notes": "Anything a reader needs to interpret the result."
}
```

Try it:

```sh
mkdir my-advisories && cp example.json my-advisories/
ispatched --advisories my-advisories list
ispatched --advisories my-advisories EXAMPLE-2026-1 --server
```

## Fields

| Field | Meaning |
| --- | --- |
| `id` | Unique name. Used on the command line. |
| `aliases` | Other names (CVE ids). Any alias works on the command line. |
| `title`, `summary`, `notes` | Human text shown in listings and reports. |
| `published` | `YYYY-MM-DD`. |
| `references` | Links to the primary advisories and trackers. |
| `upstream_fixed` | Map of PHP branch to the first fixed **patch** number (`{"8.4": 27}` means 8.4.27). |
| `eol_branches` | Branches with no upstream fix; only a vendor backport helps. |
| `vendors` | One row per distribution release, see below. |

### Vendor rows

| Field | Meaning |
| --- | --- |
| `vendor` | The `ID` from `/etc/os-release` (`debian`, `ubuntu`, `rhel`, ...). |
| `release` | The `VERSION_ID`: `12`, `22.04`; for RPM distributions the major (`9`). |
| `package` | Debian-family: `php<branch>` such as `php8.2` (or `php5`). RHEL: `php`. |
| `fixed` | First fixed package version. Debian: full version. RPM: `epoch:version-release`. |
| `url` | The vendor's own advisory or tracker page. |
| `verified_on` | `YYYY-MM-DD`: the day **you** checked the row against the vendor page. |

## Rules for good data

- **Verify every vendor row yourself** against the vendor's tracker or errata, and date it.
  Rows without `verified_on` are ignored for verdicts: unverified data must never produce
  a "patched".
- Copy the version string exactly, including `~`, `+esm`, epochs and the release suffix.
- Cite the primary source in `references`, and describe the flaw as the primary source does.
- Note oddities in `notes` (extended-support-only fixes, CVEs fixed in separate updates).
- Run `python3 -m unittest discover -t . -s tests` before opening a pull request.
