import unittest

from ispatched.discovery import discover_serving_php, read_os_release
from tests.fakes import FakeSystem

STAT = "%d (%s) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %d 1000 100 0"


def proc(pid, exe, comm="x", start=500, maps=""):
    return {
        "/proc/%d/exe" % pid: exe,
    }, {
        "/proc/%d/stat" % pid: STAT % (pid, comm, start),
        "/proc/%d/maps" % pid: maps,
    }


def system(*procs):
    files = {"/proc/stat": "cpu 1 2 3\nbtime 1000\n"}
    links = {}
    for l, f in procs:
        links.update(l)
        files.update(f)
    return FakeSystem(files=files, links=links)


class DiscoveryTests(unittest.TestCase):
    def test_fpm(self):
        r = discover_serving_php(system(proc(10, "/usr/sbin/php-fpm8.2", "php-fpm8.2")))
        self.assertEqual([(i.pid, i.kind) for i in r], [(10, "fpm")])

    def test_apache_with_libphp(self):
        maps = "7f00 r-xp /usr/lib/apache2/modules/libphp8.2.so\n"
        r = discover_serving_php(system(proc(20, "/usr/sbin/apache2", maps=maps)))
        self.assertEqual([(i.pid, i.kind) for i in r], [(20, "apache-module")])

    def test_apache_without_libphp_ignored(self):
        self.assertEqual(discover_serving_php(system(proc(20, "/usr/sbin/httpd", maps="libc.so"))), [])

    def test_cli_php_ignored(self):
        self.assertEqual(discover_serving_php(system(proc(30, "/usr/bin/php8.2"))), [])

    def test_empty_proc(self):
        self.assertEqual(discover_serving_php(FakeSystem()), [])

    def test_started_at(self):
        r = discover_serving_php(system(proc(10, "/usr/sbin/php-fpm", "php (fpm)", start=500)))
        self.assertEqual(r[0].started_at, 1005.0)

    def test_deleted_exe_suffix(self):
        r = discover_serving_php(system(proc(10, "/usr/sbin/php-fpm8.2 (deleted)")))
        self.assertEqual(r[0].kind, "fpm")

    def test_os_release(self):
        s = FakeSystem(files={"/etc/os-release": 'NAME="Debian"\nID=debian\nVERSION_ID="12"\n'})
        self.assertEqual(read_os_release(s), {"id": "debian", "version_id": "12"})

    def test_os_release_missing(self):
        self.assertEqual(read_os_release(FakeSystem()), {"id": "", "version_id": ""})


class ClockTicksTests(unittest.TestCase):
    def test_uses_the_system_value(self):
        from unittest import mock
        from ispatched import discovery
        with mock.patch.object(discovery.os, "sysconf", return_value=250):
            self.assertEqual(discovery._clock_ticks(), 250)

    def test_falls_back_to_100(self):
        from unittest import mock
        from ispatched import discovery
        with mock.patch.object(discovery.os, "sysconf", side_effect=OSError):
            self.assertEqual(discovery._clock_ticks(), 100)
        with mock.patch.object(discovery.os, "sysconf", return_value=-1):
            self.assertEqual(discovery._clock_ticks(), 100)


if __name__ == "__main__":
    unittest.main()
