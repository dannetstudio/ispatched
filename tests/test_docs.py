import json
import os
import re
import subprocess
import tempfile
import unittest

from ispatched.advisory import load_advisories

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ["README.md", "README.es.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md",
        "docs/how-verdicts-work.md", "docs/adding-an-advisory.md",
        "docs/writing-a-provider.md", "docs/unverified-vendor-data.md"]
FLAGS = ["--server", "--targets", "--format", "--advisories", "--timeout", "--workers",
         "--same-host"]
# Built by concatenation so this file never contains the words it forbids.
FORBIDDEN = ["cla" + "ude", "anth" + "ropic", "chat" + "gpt", "co-auth" + "ored-by",
             "generated " + "with", "co" + "pilot"]


def git(*args):
    """Run git in the repo; skip the calling test when git or the checkout is unavailable."""
    try:
        return subprocess.check_output(["git"] + list(args), cwd=ROOT,
                                       stderr=subprocess.DEVNULL).decode()
    except (OSError, subprocess.CalledProcessError):
        raise unittest.SkipTest("git is not available for this checkout")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class DocsTests(unittest.TestCase):
    def test_documents_exist(self):
        for rel in DOCS:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, rel)), rel)

    def test_readmes_name_both_cves_and_every_flag(self):
        for rel in ("README.md", "README.es.md"):
            text = read(rel)
            for needle in ["CVE-2026-109618", "CVE-2026-109619", "ispatched list"] + FLAGS:
                self.assertIn(needle, text, "%s is missing %s" % (rel, needle))

    def test_readme_title(self):
        self.assertTrue(read("README.md").startswith(
            "# ispatched — is this host patched against that CVE?"))

    def test_readme_states_the_exploitation_disagreement_and_responsible_use(self):
        text = read("README.md")
        for needle in ("Sansec", "watchTowr", "Amazon", "openai/php2shell-checker",
                       "permission", "Apache-2.0"):
            self.assertIn(needle, text)

    def test_relative_links_resolve(self):
        link = re.compile(r"\]\(([^)\s]+)\)")
        for rel in DOCS:
            base = os.path.dirname(os.path.join(ROOT, rel))
            for target in link.findall(read(rel)):
                if re.match(r"^(https?:|mailto:|#)", target):
                    continue
                path = os.path.normpath(os.path.join(base, target.split("#")[0]))
                self.assertTrue(os.path.exists(path), "%s links to missing %s" % (rel, target))

    def test_advisory_example_loads(self):
        match = re.search(r"```json\n(.*?)```", read("docs/adding-an-advisory.md"), re.S)
        self.assertIsNotNone(match, "no json example found")
        data = json.loads(match.group(1))
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "example.json"), "w", encoding="utf-8") as fh:
                fh.write(match.group(1))
            loaded = load_advisories([tmp])
        self.assertIn(data["id"], loaded)

    def test_no_tool_attribution_in_tracked_files(self):
        files = git("ls-files").split("\n")
        for rel in [f for f in files if f]:
            try:
                text = read(rel).lower()
            except (UnicodeDecodeError, OSError):
                continue
            for word in FORBIDDEN:
                self.assertNotIn(word, text, "%s contains a forbidden word" % rel)

    def test_no_tool_attribution_in_commit_messages(self):
        log = git("log", "--format=%B").lower()
        # Dependabot's own sign-off and co-author trailers are legitimate; nothing else is.
        log = "\n".join(l for l in log.split("\n") if "dependabot[bot]" not in l)
        for word in FORBIDDEN:
            self.assertNotIn(word, log)


if __name__ == "__main__":
    unittest.main()
