"""Test doubles for the System layer."""

from ispatched.system import System


class FakeSystem(System):
    def __init__(self, files=None, commands=None, links=None, mtimes=None, now=0.0,
                 modes=None, root=True):
        self.files = dict(files or {})
        self.commands = dict(commands or {})
        self.links = dict(links or {})
        self.mtimes = dict(mtimes or {})
        self.modes = dict(modes or {})
        self.root = root
        self._now = now
        self.calls = []

    def run(self, argv):
        self.calls.append(list(argv))
        return self.commands.get(tuple(argv), (127, ""))

    def read_text(self, path):
        return self.files.get(path)

    def readlink(self, path):
        return self.links.get(path)

    def listdir(self, path):
        prefix = path.rstrip("/") + "/"
        names = set()
        for key in list(self.files) + list(self.links):
            if key.startswith(prefix):
                names.add(key[len(prefix):].split("/")[0])
        return sorted(names)

    def read_mtime(self, path):
        return self.mtimes.get(path)

    def now(self):
        return self._now

    def file_owner_mode(self, path):
        return self.modes.get(path)

    def is_root(self):
        return self.root
