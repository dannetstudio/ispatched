"""The only place that touches the host: commands, files and the clock."""

import os
import subprocess
import time


class System(object):
    def run(self, argv):
        raise NotImplementedError

    def read_text(self, path):
        raise NotImplementedError

    def listdir(self, path):
        raise NotImplementedError

    def readlink(self, path):
        raise NotImplementedError

    def now(self):
        raise NotImplementedError


class SystemRunner(System):
    """Real implementation; never raises for missing files or commands."""

    def run(self, argv):
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               universal_newlines=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return 127, ""
        return p.returncode, p.stdout

    def read_text(self, path):
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def listdir(self, path):
        try:
            return os.listdir(path)
        except OSError:
            return []

    def readlink(self, path):
        try:
            return os.readlink(path)
        except OSError:
            return None

    def now(self):
        return time.time()
