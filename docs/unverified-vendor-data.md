# Vendor data notes and known gaps

Every vendor row in `src/ispatched/advisories/php2shell.json` was checked against the
vendor's own tracker or errata on 2026-11-21 (`verified_on`). The following points are
worth knowing:

- **Ubuntu 14.04 to 20.04 rows** are fixed only in the ESM / Ubuntu Pro archives
  (`+esmN` versions). A host without Ubuntu Pro cannot receive them and will correctly
  stay `potentially_vulnerable`.
- **RHEL 7** is split between the two CVEs: RHSA-2026:88693 fixes only CVE-2026-109619;
  Red Hat lists CVE-2026-109618 as "Not affected" for 5.4.16. The row is therefore a valid
  "fully fixed" threshold for PHP2Shell as a whole, but it will not match a CVE-2026-109618-only reading.
- **RHEL 8/9 module streams**: only the `php` module stream shipped in the cited RHSAs
  (7.4 on RHEL 8, 8.0 on RHEL 9) has a verified NEVRA. Other streams (for example
  `php:8.2`) are not listed, so they yield `unknown` rather than a guess.
- Debian 11 and older, and other derivatives (Alma, Rocky, CentOS Stream, Sury, Remi,
  Alpine) are not covered yet. Contributions are welcome; see `docs/adding-an-advisory.md`.
