#!/bin/sh
# Run the test suite on Python 3.6, the oldest version ispatched supports (RHEL 8 ships it).
set -eu
cd "$(dirname "$0")/.."
exec docker run --rm -v "$PWD":/w -w /w python:3.6-slim python -m unittest discover -t . -s tests
