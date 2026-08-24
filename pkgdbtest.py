#!/usr/bin/env python3
"""What is installed here, and does the database agree with the tools?

`dpkg -l`, `dpkg-query -W`, `apt list --installed` and `dpkg
--get-selections` all read one file: /var/lib/dpkg/status. That file held
two stanzas.

    grep -c '^Package:' /var/lib/dpkg/status      2
    dpkg -l | grep -c '^ii'                     103

Two commands about one database, and the file is what anything that does
not shell out to dpkg reads -- which is most of what a recon script does
when it wants an inventory without leaving dpkg in the process list. It is
rendered from the same table dpkg -l walks now, so the count cannot drift
again.

Around it, dpkg's admin directory had one entry where the guest has
fifteen: no info/, no lock, no diversions, no available. /var/cache/apt did
not exist at all, so `ls /var/cache/apt/archives` -- the first place anyone
looks for a downloaded .deb -- said No such file or directory on a box
whose apt works.

Two commands were answering the wrong question outright:

    apt list --installed nginx
        zlib1g/stable,now 1:1.3.dfsg+really1.3.1-1 amd64 [installed]

The pattern was thrown away with the rest of the operands, so asking about
one package answered about a different one. And `apt-cache stats` printed
apt-get's "Reading package lists... Done" preamble, which is not what stats
prints at all.

Counts and shapes measured on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


S = sh()


def R(cmd, s=None):
    t = s or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


# ---------------------------------------------------------------------------
# one database, four readers
# ---------------------------------------------------------------------------
def t_the_status_file_lists_what_dpkg_lists():
    stanzas = int(R("grep -c '^Package:' /var/lib/dpkg/status")[0].strip())
    ii = int(R("dpkg -l | grep -c '^ii'")[0].strip())
    check("status has a stanza per installed package", stanzas == ii,
          "%d stanzas, %d installed" % (stanzas, ii))
    check("and there are plausibly many of them", ii > 90, str(ii))
    for cmd, count in (("dpkg-query -W | wc -l", None),
                       ("dpkg --get-selections | wc -l", None),
                       ("apt list --installed | grep -c installed", None)):
        got = int(R(cmd)[0].strip())
        check("%s agrees" % cmd.split("|")[0].strip(), got == ii,
              "%d vs %d" % (got, ii))


def t_a_package_reads_the_same_from_all_of_them():
    for pkg in ("nginx", "bash", "openssl", "python3"):
        ver = [l.split()[2] for l in R("dpkg -l %s" % pkg)[0].splitlines()
               if l.startswith("ii")]
        check("dpkg -l knows %s" % pkg, bool(ver), "missing")
        if not ver:
            continue
        q = R("dpkg-query -W %s" % pkg)[0].split()
        check("dpkg-query gives the same version for %s" % pkg,
              q[1:2] == ver, "%s vs %s" % (q[1:2], ver))
        a = R("apt list --installed %s" % pkg)[0].splitlines()
        row = [l for l in a if l.startswith(pkg + "/")]
        check("apt list gives the same version for %s" % pkg,
              row and row[0].split()[1] == ver[0],
              "%s vs %s" % (row[:1], ver))
        # ...and the stanza in the file itself.
        body = R("sed -n '/^Package: %s$/,/^$/p' /var/lib/dpkg/status"
                 % pkg)[0]
        check("the status stanza exists for %s" % pkg,
              body.strip().startswith("Package: %s" % pkg), body[:40])
        m = re.search(r"^Version: (\S+)$", body, re.M)
        check("and carries the same version", m and m.group(1) == ver[0],
              "%s vs %s" % (m and m.group(1), ver))
        check("and says it is installed",
              "Status: install ok installed" in body, body[:60])


def t_a_stanza_has_the_fields_the_guest_writes():
    body = R("sed -n '/^Package: nginx$/,/^$/p' /var/lib/dpkg/status")[0]
    keys = [l.split(":")[0] for l in body.splitlines() if ":" in l]
    for k in ("Package", "Status", "Priority", "Section", "Installed-Size",
              "Maintainer", "Architecture", "Version", "Description"):
        check("the stanza has %s" % k, k in keys, str(keys))
    m = re.search(r"^Installed-Size: (\d+)$", body, re.M)
    check("Installed-Size is a number", m is not None, body[:60])
    m = re.search(r"^Architecture: (\S+)$", body, re.M)
    check("Architecture matches dpkg -l's column",
          m and m.group(1) == R("dpkg -l nginx")[0].splitlines()[-1].split()[3],
          "%s" % (m and m.group(1)))
    check("the description is the one dpkg -l prints",
          re.search(r"^Description: small, powerful", body, re.M) is not None,
          [l for l in body.splitlines() if l.startswith("Description")])
    # Stanzas are separated by a blank line, as deb822 requires.
    whole = R("cat /var/lib/dpkg/status")[0]
    check("stanzas are blank-line separated",
          "\n\nPackage: " in whole, whole[:60])


def t_installing_and_removing_move_the_file_too():
    s = sh()
    before = int(R("grep -c '^Package:' /var/lib/dpkg/status", s)[0].strip())
    R("apt-get install -y nmap", s)
    after = int(R("grep -c '^Package:' /var/lib/dpkg/status", s)[0].strip())
    ii = int(R("dpkg -l | grep -c '^ii'", s)[0].strip())
    # apt pulls dependencies in, so the count moves by more than one --
    # what matters is that the file and dpkg -l move by the *same* amount.
    check("installing adds stanzas", after > before,
          "%d then %d" % (before, after))
    check("and dpkg -l agrees", after == ii, "%d vs %d" % (after, ii))
    check("the new package is in the file",
          "Package: nmap\n" in R("cat /var/lib/dpkg/status", s)[0],
          "missing")
    R("apt-get remove -y nmap", s)
    gone = int(R("grep -c '^Package:' /var/lib/dpkg/status", s)[0].strip())
    check("removing takes it away again", gone == after - 1,
          "%d vs %d" % (gone, after - 1))
    check("and the two still agree",
          gone == int(R("dpkg -l | grep -c '^ii'", s)[0].strip()),
          "%d" % gone)
    check("nmap is out of the file",
          "Package: nmap\n" not in R("cat /var/lib/dpkg/status", s)[0],
          "still there")


# ---------------------------------------------------------------------------
# the admin directory around it
# ---------------------------------------------------------------------------
GUEST_DPKG_DIR = {"alternatives", "arch-native", "available", "cmethopt",
                  "diversions", "diversions-old", "info", "lock",
                  "lock-frontend", "parts", "statoverride", "status",
                  "status-old", "triggers", "updates"}


def t_the_admin_directory_is_the_guests():
    have = set(R("ls /var/lib/dpkg/")[0].split())
    check("/var/lib/dpkg has the guest's fifteen entries",
          have == GUEST_DPKG_DIR, str(sorted(GUEST_DPKG_DIR ^ have)))
    for d in ("info", "alternatives", "triggers", "updates", "parts"):
        check("%s is a directory" % d,
              R("test -d /var/lib/dpkg/%s" % d)[2] == 0, "not a directory")
    check("arch-native says what dpkg -l's column says",
          R("cat /var/lib/dpkg/arch-native")[0].strip() == "amd64",
          R("cat /var/lib/dpkg/arch-native")[0].strip())
    # info/ holds a .list per package, which is where dpkg -L reads.
    lists = R("ls /var/lib/dpkg/info/")[0].split()
    check("info/ holds .list files", lists and all(l.endswith(".list")
                                                   for l in lists),
          str(lists[:3]))
    for pkg in ("coreutils", "nginx"):
        p = "/var/lib/dpkg/info/%s.list" % pkg
        if R("test -f %s" % p)[2] != 0:
            continue
        want = set(R("dpkg -L %s" % pkg)[0].split())
        got = set(R("cat %s" % p)[0].split())
        missing = [x for x in got if x not in want and x.startswith("/usr/")]
        check("%s.list agrees with dpkg -L" % pkg, not missing,
              str(missing[:3]))


def t_apt_has_a_cache_directory():
    check("/var/cache/apt exists", R("test -d /var/cache/apt")[2] == 0,
          "missing")
    have = set(R("ls /var/cache/apt/")[0].split())
    check("with the guest's three entries",
          have == {"archives", "pkgcache.bin", "srcpkgcache.bin"},
          str(sorted(have)))
    check("archives has a lock and a partial dir",
          R("test -f /var/cache/apt/archives/lock")[2] == 0
          and R("test -d /var/cache/apt/archives/partial")[2] == 0,
          R("ls -a /var/cache/apt/archives/")[0].split())
    size = R("stat -c %s /var/cache/apt/pkgcache.bin")[0].strip()
    check("the package cache is a plausible size",
          size.isdigit() and int(size) > 1000000, size)


# ---------------------------------------------------------------------------
# the two commands that answered the wrong question
# ---------------------------------------------------------------------------
def t_apt_list_filters():
    out = R("apt list --installed nginx")[0].splitlines()
    rows = [l for l in out if "/" in l]
    check("apt list --installed nginx returns one row", len(rows) == 1,
          str(rows))
    check("...and it is nginx", rows and rows[0].startswith("nginx/"),
          str(rows[:1]))
    check("the header is still there", out[:1] == ["Listing..."], str(out[:1]))
    out = R("apt list --installed 'ngin*'")[0].splitlines()
    rows = [l.split("/")[0] for l in out if "/" in l]
    check("a glob matches the family",
          set(rows) == {"nginx", "nginx-common"}, str(sorted(rows)))
    out = R("apt list --installed nosuchpkg")[0].splitlines()
    check("a name nothing matches returns just the header",
          out == ["Listing..."], str(out))
    # Without --installed it still says which are installed.
    row = [l for l in R("apt list bash")[0].splitlines()
           if l.startswith("bash/")]
    check("apt list bash marks it installed",
          row and "[installed]" in row[0], str(row[:1]))
    check("and the unfiltered list is still everything",
          len([l for l in R("apt list --installed")[0].splitlines()
               if "/" in l])
          == int(R("dpkg -l | grep -c '^ii'")[0].strip()), "count differs")


def t_apt_cache_stats_is_statistics():
    out, err, rc = R("apt-cache stats")
    check("apt-cache stats exits 0", rc == 0, "rc=%s" % rc)
    check("it does not print apt-get's preamble",
          "Reading package lists" not in out, out[:60])
    check("it opens with the package-name total",
          out.startswith("Total package names:"), out[:50])
    for line in ("Total package structures:", "  Normal packages:",
                 "  Pure virtual packages:", "Total dependencies:",
                 "Total slack space:"):
        check("stats has %r" % line.strip(), line in out, out[:60])
    nums = re.findall(r": (\d+)", out)
    check("every figure is a number", len(nums) > 8, str(len(nums)))


TESTS = [t_the_status_file_lists_what_dpkg_lists,
         t_a_package_reads_the_same_from_all_of_them,
         t_a_stanza_has_the_fields_the_guest_writes,
         t_installing_and_removing_move_the_file_too,
         t_the_admin_directory_is_the_guests,
         t_apt_has_a_cache_directory,
         t_apt_list_filters,
         t_apt_cache_stats_is_statistics]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
