# Contributing

Thanks for helping. The most valuable contributions are **verified advisory data** and
**new providers**; bug reports and doc fixes are just as welcome.

## Ground rules

- Python 3.6+, standard library only. No third-party dependencies, no dataclasses, walrus or `match`.
- Never add anything that sends exploit payloads or probes for the flaw itself. `ispatched`
  reads evidence; it does not attack.
- Never state more certainty than the evidence gives. A new status such as "confirmed
  vulnerable" will not be accepted.
- Vendor rows must be verified by you against the vendor's own page and carry `verified_on`.

## Setup and tests

```sh
git clone https://github.com/dannetstudio/ispatched
cd ispatched
python3 -m unittest discover -t . -s tests
```

Write the failing test first, watch it fail, then make it pass. Network tests use a local
server on `127.0.0.1`; host tests use `FakeSystem` from `tests/fakes.py`.

## What to send

- **A new advisory:** [docs/adding-an-advisory.md](docs/adding-an-advisory.md).
- **A new provider:** [docs/writing-a-provider.md](docs/writing-a-provider.md).
- **A correction to vendor data:** link the vendor page showing the right version.
- **A bug:** include the command, the output, and the OS (`/etc/os-release`).

Open an issue first for larger changes. Keep pull requests focused; one concern each.
By contributing you agree that your work is licensed under Apache-2.0.
