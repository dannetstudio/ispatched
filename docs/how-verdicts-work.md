# How verdicts work

`ispatched` turns raw evidence into one of three statuses. This page explains the rules,
so you can judge a result and know what it does **not** say.

## Vocabulary

- **Finding**: what one provider concluded: `provider`, `status`, `confidence`, `reason`,
  and the `evidence` it read (package name, headers, final URL, ...).
- **Verdict**: the combined result for one target, with the findings attached.
- **Status**: `patched`, `potentially_vulnerable` or `unknown`. There is no "confirmed
  vulnerable"; that would require exploiting the flaw, which this tool never does.
- **Confidence**: `none`, `low`, `medium`, `high`. How strong the evidence is, not how
  sure the author feels.

## Providers and their confidence

| Provider | Evidence | Confidence |
| --- | --- | --- |
| `dpkg` | The package owning the serving PHP binary (`dpkg -S`), version read with `dpkg-query`, compared with `dpkg` ordering against the vendor row for that release. | high |
| `rpm` | The package owning the binary (`rpm -qf`), `epoch:version-release` compared with RPM ordering against the vendor row for that major release. | high |
| `upstream` | The PHP version against the upstream fixed version of its branch. Knows nothing about backports, so a fixed backport can look vulnerable. | medium |
| `http` | `Server` and `X-Powered-By` headers after following up to 5 http(s) redirects. Anything on the path can alter them. | low |

"Serving PHP" means the PHP-FPM master or an Apache process with `libphp` loaded; the `php`
command line binary is ignored because it is not what answers web requests.

## Combining findings

1. Any **vendor** (`dpkg`/`rpm`) finding that is `potentially_vulnerable` decides the verdict.
2. Otherwise a vendor `patched` finding decides it: package evidence supersedes headers
   and upstream versions. The reason names the provider that decided.
3. Otherwise any `potentially_vulnerable` finding decides it (the most pessimistic wins).
4. Otherwise `patched` only if some finding with confidence above `none` says patched and no
   `unknown` finding has equal or higher confidence.
5. Otherwise `unknown`.

With `--server`, an `unknown` instance next to patched ones makes the verdict `unknown`:
one unchecked PHP is exactly where a vulnerable process would hide.

## Versions and ordering

- Debian/Ubuntu versions use dpkg ordering (`~` sorts before everything, epochs, revisions).
- RPM versions are `[epoch:]version-release`; a missing epoch is `0`.
- Upstream versions are parsed as `major.minor.patch` plus a suffix. Pre-releases (`-dev`,
  `alpha`, `beta`, `RC`) are `unknown`: they cannot be judged against a release number.
- A branch in the advisory's `eol_branches` list is `potentially_vulnerable` on upstream
  evidence: nothing upstream will ever fix it, only a vendor backport can.

## Restart detection

A patched package does not fix running workers. With `--server`, `ispatched` compares the
process start time with the package install time. If the workers started first, the
finding says so and the result is not "patched": restart PHP-FPM or Apache.

## Exit codes

`0` all patched, `1` something `potentially_vulnerable`, `3` nothing vulnerable but
something `unknown`, `2` usage error. When targets differ, the worst result wins
(`1` before `3` before `0`).

## What the evidence cannot show

Headers can be forged; a proxy may answer instead of PHP; a package version proves the
package, not that the service was restarted or that an application bundles its own PHP
(containers, some control panels). Treat `patched (low)` as "advertised as patched" and
`patched (high)` as "the installed package is at or above the vendor's fixed version".
