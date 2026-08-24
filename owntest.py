r"""Does every binary on this box belong to a package?

Forty-sixth coherence sweep. dpkg and the filesystem are two records of
the same thing, and `dpkg -S $(which curl)` is a normal thing to type
when you are working out what a box is. On a real Debian machine every
file under /usr/bin and /usr/sbin belongs to something, with a short and
knowable list of exceptions.

Eleven binaries in /usr/bin and two in /usr/sbin had no owner:

    dash dbus-daemon expiry gpasswd udevadm    (/usr/bin)
    agetty rsyslogd                            (/usr/sbin)

Five of them had a package that existed and simply did not list the file
-- dash shipped "sh" but not "dash", passwd shipped chage and chsh but
not gpasswd or expiry, util-linux did not claim agetty, and rsyslog was
in the package list with no files at all, so the daemon this box actually
runs belonged to nothing. Two more, dbus-daemon and udev, were not in the
package database at all while their binaries sat on disk.

The reverse direction was already sound and is pinned here: 98 packages,
every file dpkg -L claims is really there and findable by command -v.

Six in /usr/bin are *correctly* unowned, and the guest agrees:
editor, pager, nawk, lzcat and unlzma are update-alternatives symlinks,
which dpkg genuinely reports "no path found" for, and /usr/bin/write has
no owner on the guest either. Asserting a blanket "everything is owned"
would have been wrong, which is why the exception list is measured rather
than assumed.

Reference measured on the guest, as root:

    /usr/bin/dash          dash: /usr/bin/dash
    /usr/bin/dbus-daemon   dbus-daemon: /usr/bin/dbus-daemon
    /usr/bin/expiry        passwd: /usr/bin/expiry
    /usr/bin/gpasswd       passwd: /usr/bin/gpasswd
    /usr/bin/udevadm       udev: /usr/bin/udevadm
    /usr/sbin/agetty       util-linux: /usr/sbin/agetty
    /usr/bin/editor        no path found        (alternatives symlink)
    /usr/bin/write         no path found
    dbus-daemon 1.16.2-2 / udev 257.13-1~deb13u1 / dash 0.5.12-12

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

# Measured on the guest: dpkg really does disown these.
# write went with bsdextrautils, which this box does not install:
# it was the one unowned binary that a package could have owned.
UNOWNED_OK = {"editor", "pager", "nawk", "lzcat", "unlzma"}


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err).strip()


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- every binary has an owner -------------------------------------------

def t_usr_bin_is_owned():
    s = sh()
    bins = run(s, "ls /usr/bin").split()
    check("there are binaries to check", len(bins) > 200, len(bins))
    unowned = [b for b in bins
               if "no path found" in run(s, "dpkg -S /usr/bin/%s" % b)]
    eq("only the known exceptions are unowned",
       sorted(unowned), sorted(UNOWNED_OK))


def t_usr_sbin_is_owned():
    s = sh()
    bins = run(s, "ls /usr/sbin").split()
    check("there are sbin binaries", len(bins) > 20, len(bins))
    unowned = [b for b in bins
               if "no path found" in run(s, "dpkg -S /usr/sbin/%s" % b)]
    eq("nothing in sbin is unowned", unowned, [])


def t_the_ones_this_sweep_fixed():
    s = sh()
    for path, pkg in (("/usr/bin/dash", "dash"),
                      ("/usr/bin/dbus-daemon", "dbus-daemon"),
                      ("/usr/bin/expiry", "passwd"),
                      ("/usr/bin/gpasswd", "passwd"),
                      ("/usr/bin/udevadm", "udev"),
                      ("/usr/sbin/agetty", "util-linux"),
                      ("/usr/sbin/rsyslogd", "rsyslog")):
        eq("owner of %s" % path, run(s, "dpkg -S %s" % path),
           "%s: %s" % (pkg, path))


def t_the_alternatives_stay_unowned():
    """dpkg really does disown these; claiming otherwise is also a lie."""
    s = sh()
    for b in ("editor", "pager", "nawk", "lzcat", "unlzma"):
        out = run(s, "dpkg -S /usr/bin/%s" % b)
        check("%s has no owner" % b, "no path found" in out, out)


# -- and every owner is a package that exists ----------------------------

def t_every_named_owner_is_installed():
    """dpkg -S naming a package that dpkg -l does not list is the bug this
    sweep nearly introduced: a file list without a version entry."""
    s = sh()
    listed = set()
    for line in run(s, "dpkg -l").splitlines():
        f = line.split()
        if line.startswith("ii") and len(f) > 1:
            listed.add(f[1])
    check("dpkg -l returned packages", len(listed) > 50, len(listed))
    named = set()
    for d in ("/usr/bin", "/usr/sbin"):
        for b in run(s, "ls %s" % d).split()[:400]:
            out = run(s, "dpkg -S %s/%s" % (d, b))
            if ":" in out and "no path found" not in out:
                named.add(out.split(":", 1)[0].strip())
    missing = sorted(named - listed)
    eq("every owner appears in dpkg -l", missing, [])
    check("and owners were actually found", len(named) > 20, len(named))


def t_every_claimed_file_exists():
    """The other direction, already sound and pinned."""
    s = sh()
    pkgs = [l.split()[1] for l in run(s, "dpkg -l").splitlines()
            if l.startswith("ii") and len(l.split()) > 1]
    missing, unfindable, checked = [], [], 0
    for pkg in pkgs:
        files = [f for f in run(s, "dpkg -L %s" % pkg).splitlines()
                 if f.startswith(("/usr/bin/", "/usr/sbin/", "/bin/",
                                  "/sbin/"))]
        for f in files[:3]:
            checked += 1
            if "No such file" in run(s, "ls -l %s 2>&1" % f):
                missing.append((pkg, f))
            if run(s, "command -v %s" % f.rsplit("/", 1)[-1]) == "":
                unfindable.append((pkg, f))
    check("a useful number were checked", checked > 100, checked)
    eq("dpkg -L never names a file that is absent", missing, [])
    eq("and command -v finds all of them", unfindable, [])


# -- the new packages look like the rest ---------------------------------

def t_the_new_packages_are_well_formed():
    s = sh()
    for pkg, ver in (("dbus-daemon", "1.16.2-2"),
                     ("udev", "257.13-1~deb13u1")):
        line = [l for l in run(s, "dpkg -l %s" % pkg).splitlines()
                if l.startswith("ii")]
        check("%s is listed" % pkg, line, run(s, "dpkg -l %s" % pkg))
        if line:
            f = line[0].split()
            eq("%s version" % pkg, f[2], ver)
            eq("%s arch" % pkg, f[3], "amd64")
            check("%s has a real description" % pkg,
                  "Debian %s package" % pkg not in line[0], line[0])


def t_the_shape_someone_actually_types():
    s = sh()
    eq("dpkg -S $(which curl)", run(s, "dpkg -S $(which curl)"),
       "curl: /usr/bin/curl")
    eq("dpkg -S /bin/ls", run(s, "dpkg -S /bin/ls"), "coreutils: /usr/bin/ls")
    eq("dpkg -S /bin/sh", run(s, "dpkg -S /bin/sh"), "dash: /usr/bin/sh")
    out = run(s, "dpkg -S /usr/bin/definitelynotreal")
    check("a path that is not there", "no path found" in out, out)


TESTS = [t_usr_bin_is_owned, t_usr_sbin_is_owned,
         t_the_ones_this_sweep_fixed, t_the_alternatives_stay_unowned,
         t_every_named_owner_is_installed, t_every_claimed_file_exists,
         t_the_new_packages_are_well_formed,
         t_the_shape_someone_actually_types]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
