import unittest

from ispatched.advisory import find_advisory, load_advisories
from ispatched.model import Confidence, Status
from ispatched.server import run_server
from tests.fakes import FakeSystem

ADV = find_advisory(load_advisories(), "PHP2Shell")
STAT = "%d (php) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 1 1 0"


def host(os_id, version_id, procs, commands, mtimes=None):
    """procs: list of (pid, exe, start_ticks, maps)."""
    files = {"/etc/os-release": 'ID=%s\nVERSION_ID="%s"\n' % (os_id, version_id),
             "/proc/stat": "btime 1000\n"}
    links = {}
    for pid, exe, start, maps in procs:
        links["/proc/%d/exe" % pid] = exe
        files["/proc/%d/stat" % pid] = STAT % (pid, start)
        files["/proc/%d/maps" % pid] = maps
    return FakeSystem(files=files, links=links, commands=commands, mtimes=mtimes)


def dpkg_cmds(exe, pkg, version):
    return {
        ("dpkg", "-S", exe): (0, "%s: %s\n" % (pkg, exe)),
        ("dpkg-query", "-W", "-f", "${Version}\n", pkg): (0, version + "\n"),
    }


FPM = (10, "/usr/sbin/php-fpm8.2", 100, "")


class DpkgTests(unittest.TestCase):
    def verdict(self, os_id, rel, procs, cmds, mtimes=None):
        return run_server(ADV, host(os_id, rel, procs, cmds, mtimes))

    def test_debian_patched(self):
        v = self.verdict("debian", "12", [FPM], dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.35-1~deb12u1"))
        self.assertEqual((v.status, v.confidence), (Status.PATCHED, Confidence.HIGH))

    def test_debian_vulnerable(self):
        v = self.verdict("debian", "12", [FPM], dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.34-1~deb12u1"))
        self.assertEqual(v.status, Status.POTENTIALLY_VULNERABLE)

    def test_ubuntu_backport_is_patched(self):
        fpm = (10, "/usr/sbin/php-fpm8.1", 100, "")
        v = self.verdict("ubuntu", "22.04", [fpm], dpkg_cmds(fpm[1], "php8.1-fpm", "8.1.2-1ubuntu2.28"))
        self.assertEqual(v.status, Status.PATCHED)

    def test_unknown_distro_row(self):
        v = self.verdict("debian", "99", [FPM], dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.35-1"))
        self.assertEqual(v.status, Status.UNKNOWN)
        self.assertIn("no verified advisory data for debian 99 php8.2", v.reason)

    def test_restart_needed(self):
        cmds = dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.35-1~deb12u1")
        v = self.verdict("debian", "12", [FPM], cmds, {"/var/lib/dpkg/info/php8.2-fpm.list": 5000.0})
        self.assertEqual(v.status, Status.POTENTIALLY_VULNERABLE)
        self.assertIn("restart php-fpm/Apache", v.reason)

    def test_started_after_install_is_patched(self):
        cmds = dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.35-1~deb12u1")
        v = self.verdict("debian", "12", [FPM], cmds, {"/var/lib/dpkg/info/php8.2-fpm.list": 1000.0})
        self.assertEqual(v.status, Status.PATCHED)

    def test_two_instances_worst_wins(self):
        lib = "/usr/lib/apache2/modules/libphp8.4.so"
        apache = (20, "/usr/sbin/apache2", 100, "7f00-7f01 r-xp 0 08:01 9 %s\n" % lib)
        cmds = dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.34-1~deb12u1")
        cmds.update(dpkg_cmds(lib, "libapache2-mod-php8.4", "8.4.27-1~deb13u1"))
        v = self.verdict("debian", "12", [FPM, apache], cmds)
        self.assertEqual(v.status, Status.POTENTIALLY_VULNERABLE)

    def test_no_processes(self):
        v = self.verdict("debian", "12", [], {})
        self.assertEqual((v.status, v.reason), (Status.UNKNOWN, "No PHP serving process found"))

    def test_cli_never_influences(self):
        cli = (30, "/usr/bin/php7.4", 100, "")
        cmds = dpkg_cmds(FPM[1], "php8.2-fpm", "8.2.35-1~deb12u1")
        cmds.update(dpkg_cmds(cli[1], "php7.4-cli", "7.4.1-1"))
        v = self.verdict("debian", "12", [FPM, cli], cmds)
        self.assertEqual(v.status, Status.PATCHED)


class RpmTests(unittest.TestCase):
    def rpm(self, vr, epoch="0", install="900", start=100):
        exe = "/usr/sbin/php-fpm"
        cmds = {
            ("rpm", "-qf", "--qf", "%{NAME}\n", exe): (0, "php-fpm\n"),
            ("rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n%{INSTALLTIME}\n", "php-fpm"):
                (0, "%s:%s\n%s\n" % (epoch, vr, install)),
        }
        return run_server(ADV, host("rhel", "9.4", [(10, exe, start, "")], cmds))

    def test_rhel_patched(self):
        v = self.rpm("8.0.30-8.el9_8.1")
        self.assertEqual((v.status, v.confidence), (Status.PATCHED, Confidence.HIGH))

    def test_rhel_vulnerable(self):
        self.assertEqual(self.rpm("8.0.30-8.el9_8").status, Status.POTENTIALLY_VULNERABLE)

    def test_epoch_dominates(self):
        self.assertEqual(self.rpm("8.0.30-1.el9", epoch="1").status, Status.PATCHED)

    def test_rpm_restart_note(self):
        v = self.rpm("8.0.30-8.el9_8.1", install="5000")
        self.assertEqual(v.status, Status.POTENTIALLY_VULNERABLE)
        self.assertIn("restart", v.reason)


if __name__ == "__main__":
    unittest.main()
