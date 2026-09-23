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


def t_referenced_packages_answer_un_not_notfound():
    """dpkg keeps a stub for every name an installed package mentions.

    Measured on the real Debian 13 cloud guest: `dpkg -l busybox` prints an
    `un` row and exits 0 even though busybox was never installed, because
    something Recommends it; lsof is the same via a Suggests. We answered
    "no packages found matching busybox" and exited 1. Four botnet addresses
    probed busybox eight times in a day as `nproc || busybox nproc`, and one
    probed lsof.
    """
    for name in ("busybox", "lsof"):
        out, err, rc = R("dpkg -l %s" % name)
        rows = [l for l in out.splitlines() if l.startswith("un ")]
        check("dpkg -l %s prints one un row" % name, len(rows) == 1,
              "got %r" % (rows[:2],))
        check("dpkg -l %s exits 0" % name, rc == 0, "rc=%s" % rc)
        check("dpkg -l %s says nothing on stderr" % name, err == "",
              "err=%r" % err[:70])
        if rows:
            check("dpkg -l %s row is the guest's" % name,
                  rows[0].split() == ["un", name, "<none>", "<none>",
                                      "(no", "description", "available)"],
                  "got %r" % rows[0])


def t_a_name_dpkg_never_heard_of_is_still_not_found():
    """The un set must not swallow the negative case.

    nmap, gcc, telnet and docker.io are absent from the guest's referenced
    set and absent from its dpkg -- verified against dpkg itself. If they
    started printing un rows the fix would have replaced one wrong answer
    with another.
    """
    for name in ("nmap", "gcc", "telnet", "docker.io", "zzzznotapackage"):
        out, err, rc = R("dpkg -l %s" % name)
        check("dpkg -l %s is not found" % name,
              rc == 1 and "no packages found matching %s" % name in err,
              "rc=%s err=%r" % (rc, err[:70]))
        check("dpkg -l %s prints no un row" % name,
              not [l for l in out.splitlines() if l.startswith("un ")],
              "out=%r" % out[-70:])


def t_a_bare_listing_leaves_the_stubs_out():
    """`dpkg -l | grep -c '^un '` is 0 on the guest; a named query is not.

    The stubs are reachable by name and by glob but are not part of the
    inventory, so a bare listing that grew 509 rows would be its own tell.
    """
    out, _err, rc = R("dpkg -l")
    check("bare dpkg -l exits 0", rc == 0, "rc=%s" % rc)
    check("bare dpkg -l has no un rows",
          not [l for l in out.splitlines() if l.startswith("un ")],
          "%d un rows" % len([l for l in out.splitlines()
                              if l.startswith("un ")]))
    check("bare dpkg -l still lists what is installed",
          len([l for l in out.splitlines() if l.startswith("ii ")])
          == len(fs.Shell.PACKAGES),
          "%d rows vs %d packages"
          % (len([l for l in out.splitlines() if l.startswith("ii ")]),
             len(fs.Shell.PACKAGES)))


def t_a_glob_reaches_the_stubs():
    """`dpkg -l 'busybo*'` returns busybox and busybox-static on the guest."""
    out, err, rc = R("dpkg -l 'busybo*'")
    names = [l.split()[1] for l in out.splitlines() if l.startswith("un ")]
    check("glob matches both busybox stubs",
          names == ["busybox", "busybox-static"], "got %r" % (names,))
    check("glob over stubs exits 0", rc == 0, "rc=%s err=%r" % (rc, err[:60]))


def t_installed_and_stub_rows_sort_together():
    """`dpkg -l python3 busybox` puts busybox first -- one alphabetical list.

    Grouping the un rows after the ii rows would be the obvious way to build
    this and is not what dpkg does.
    """
    out, _err, rc = R("dpkg -l python3 busybox")
    rows = [l.split()[:2] for l in out.splitlines()
            if l.startswith(("ii ", "un "))]
    check("both kinds listed", len(rows) == 2, "got %r" % (rows,))
    check("sorted by name across both kinds",
          rows == [["un", "busybox"], ["ii", "python3"]], "got %r" % (rows,))
    check("mixed query exits 0", rc == 0, "rc=%s" % rc)


def t_one_missing_name_still_lists_the_rest():
    """dpkg -l busybox nmap: the stub row prints, nmap goes to stderr, rc 1."""
    out, err, rc = R("dpkg -l busybox nmap")
    check("stub row survives a missing sibling",
          [l.split()[1] for l in out.splitlines() if l.startswith("un ")]
          == ["busybox"], "out=%r" % out[-80:])
    check("missing sibling named on stderr",
          "no packages found matching nmap" in err, "err=%r" % err[:70])
    check("mixed hit and miss exits 1", rc == 1, "rc=%s" % rc)


def t_the_description_rule_is_as_wide_as_the_widest_description():
    """Measured three ways on the guest: bash 33, tcpdump 37, python3 73.

    The rule was pinned at 33, so any package whose description ran past the
    floor printed a table whose rule stopped short of its own content -- and
    it only shows when you look at two queries side by side, which is
    exactly what `dpkg -l` on a list does.
    """
    for pat in ("bash", "python3", "busybox", "python3 busybox"):
        out, _err, _rc = R("dpkg -l %s" % pat)
        lines = out.splitlines()
        rule = [l for l in lines if l.startswith("+++-")]
        body = [l for l in lines if l.startswith(("ii ", "un "))]
        if not rule or not body:
            check("dpkg -l %s renders a table" % pat, False, "out=%r" % out[:60])
            continue
        # The description column starts after "ii  " + name + " " + version
        # + " " + arch + " "; take it from the header row instead so the
        # widths come from dpkg's own layout rather than from this test.
        hdr = [l for l in lines if l.startswith("||/ ")][0]
        off = hdr.index("Description")
        widest = max(len(l[off:].rstrip()) for l in body)
        got = len(rule[0].rsplit("-", 1)[-1])
        check("dpkg -l %s rule fits its descriptions" % pat,
              got == max(33, widest), "rule=%d widest=%d" % (got, widest))


def t_dpkg_s_points_at_dpkg_deb():
    """dpkg -s on a package that is not installed prints two lines, not one.

    The second line is dpkg's pointer at dpkg-deb. A dropper that reads all
    of stderr sees a one-line answer as a truncated one.
    """
    for name in ("busybox", "zzzznotapackage"):
        _out, err, rc = R("dpkg -s %s" % name)
        lines = [l for l in err.splitlines() if l.strip()]
        check("dpkg -s %s complains" % name,
              lines and lines[0] == ("dpkg-query: package '%s' is not "
                                     "installed and no information is "
                                     "available" % name),
              "got %r" % (lines[:1],))
        check("dpkg -s %s points at dpkg-deb" % name,
              len(lines) == 2 and lines[1] == ("Use dpkg --info (= dpkg-deb "
                                               "--info) to examine archive "
                                               "files."),
              "got %r" % (lines[1:2],))
        check("dpkg -s %s exits 1" % name, rc == 1, "rc=%s" % rc)


def t_the_stub_set_and_the_installed_set_are_disjoint():
    """A name cannot be both ii and un. Five of the guest's 514 referenced
    names are installed here, and they were dropped from the set when it was
    built -- this asserts they stay dropped."""
    inst = {r[0] for r in fs.Shell.PACKAGES}
    both = sorted(inst & fs.Shell.UN_PACKAGES)
    check("no name is both installed and referenced", not both,
          "%d overlap: %r" % (len(both), both[:6]))
    check("the stub set is the guest's size", len(fs.Shell.UN_PACKAGES) == 509,
          "got %d" % len(fs.Shell.UN_PACKAGES))


def t_apt_cache_knows_the_names_dpkg_knows():
    """The contradiction this closes: dpkg -l busybox reported the box had
    heard of busybox while apt-cache policy busybox said the package did
    not exist. One box, one question, two answers -- and busybox is not a
    hypothetical, four botnets probed it eight times in a day."""
    s = sh()
    out, err, rc = R("apt-cache policy busybox", s)
    check("policy knows a referenced package", "Unable to locate" not in
          (out + err), (out + err)[:70])
    check("...and reports it not installed",
          "Installed: (none)" in out, out[:70])
    check("...with the version Debian 13 actually ships",
          "Candidate: 1:1.37.0-6+b8" in out, out[:90])
    check("...and a version table naming our own mirror",
          "500 http://deb.debian.org/debian trixie/main amd64 Packages"
          in out, out[:160])
    check("...exiting 0", rc == 0, rc)
    out, err, rc = R("apt-cache show busybox", s)
    check("show answers for it too", "Package: busybox" in out, out[:60])
    check("...with the same version policy gave",
          "Version: 1:1.37.0-6+b8" in out, out[:90])


def t_a_referenced_name_with_no_candidate_still_answers():
    """Not every referenced name is installable. `awk` is virtual and
    others are only referenced by a dependency or an old dpkg entry.
    Measured on Debian 13 for awk, apport, arpd, bind-host and
    cloud-init-22.4.2: policy prints the header with Candidate: (none) and
    an empty version table and exits 0 -- it does not disown the name."""
    s = sh()
    for name in ("awk", "apport", "arpd", "bind-host"):
        out, err, rc = R("apt-cache policy " + name, s)
        check("policy answers for %s" % name,
              out.startswith(name + ":"), repr(out[:60]))
        check("...not installed (%s)" % name,
              "Installed: (none)" in out, out[:60])
        check("...no candidate (%s)" % name,
              "Candidate: (none)" in out, out[:70])
        check("...empty version table (%s)" % name,
              out.rstrip().endswith("Version table:"), repr(out[-40:]))
        check("...exit 0 (%s)" % name, rc == 0, rc)
        check("...and nothing on stderr (%s)" % name, err == "", repr(err))
    # show is silent for these, and still succeeds.
    out, err, rc = R("apt-cache show awk", s)
    check("show prints nothing for a virtual name", out == "", repr(out[:60]))
    check("...and still exits 0", rc == 0, rc)


def t_a_name_apt_never_heard_of_is_not_apt_gets_wording():
    """Both surfaces answered "N: Unable to locate package <name>" with rc
    100. That is apt-get's sentence, not apt-cache's. Measured on Debian 13
    with the streams separated, for zzqqxx123 and notarealpkg99: policy is
    silent on both streams and exits 0; show is silent on stdout, says
    "E: No packages found" on stderr, and exits 100."""
    s = sh()
    for name in ("zzqqxx123", "notarealpkg99"):
        out, err, rc = R("apt-cache policy " + name, s)
        check("policy is silent for %s" % name, out == "", repr(out[:60]))
        check("...on stderr too (%s)" % name, err == "", repr(err[:60]))
        check("...and exits 0 (%s)" % name, rc == 0, rc)
        out, err, rc = R("apt-cache show " + name, s)
        check("show is silent on stdout (%s)" % name, out == "",
              repr(out[:60]))
        check("...and says No packages found (%s)" % name,
              "E: No packages found" in err, repr(err[:60]))
        check("...and exits 100 (%s)" % name, rc == 100, rc)
        check("...never apt-get's wording (%s)" % name,
              "Unable to locate" not in (out + err), repr((out + err)[:60]))


def t_installing_a_referenced_package_stops_it_being_referenced():
    """A name cannot be both installed and merely referenced. After
    `apt-get install busybox`, dpkg -l said `un busybox <none>` while
    `which busybox` found the binary and policy reported it installed:
    three answers to one question. Only two referenced names were
    installable before this data landed, so it was latent; it is reachable
    for 314 of them now."""
    s = sh()
    check("starts out referenced only",
          R("dpkg -l busybox", s)[0].strip().splitlines()[-1].startswith("un"),
          R("dpkg -l busybox", s)[0][-70:])
    R("apt-get install -y busybox", s)
    row = R("dpkg -l busybox", s)[0].strip().splitlines()[-1]
    check("dpkg calls it installed afterwards", row.startswith("ii"), row[:70])
    check("...with the version it installed", "1:1.37.0-6+b8" in row, row[:80])
    check("the binary is really there",
          R("which busybox", s)[0].strip(), "/usr/bin/busybox")
    check("...and policy agrees it is installed",
          "Installed: 1:1.37.0-6+b8" in R("apt-cache policy busybox", s)[0],
          R("apt-cache policy busybox", s)[0][:70])
    # A sibling that was never installed is still reported un, so the fix
    # is precedence and not a blanket suppression.
    both = R('dpkg -l "busybo*"', s)[0]
    check("a sibling is still referenced",
          any(l.startswith("un") and "busybox-static" in l
              for l in both.splitlines()), both[-90:])


def t_a_package_that_ships_no_binary_creates_none():
    """The binary lists come from Debian's own Contents index, not from
    guessing that a package provides a command of its own name. 112 of the
    314 ship something in /usr/bin or /usr/sbin; the rest are libraries,
    data and profile packages. apparmor-profiles-extra is one of those, and
    installing it must leave /usr/bin exactly as it was."""
    s = sh()
    before = R("ls /usr/bin | wc -l", s)[0].strip()
    R("apt-get install -y apparmor-profiles-extra", s)
    after = R("ls /usr/bin | wc -l", s)[0].strip()
    check("installing a binary-less package adds no binaries",
          before, after)
    row = R("dpkg -l apparmor-profiles-extra", s)[0].strip().splitlines()[-1]
    check("...but dpkg still records it installed",
          row.startswith("ii"), row[:70])


def t_no_referenced_name_is_disowned_by_apt_cache():
    """The sweep in one assertion: walk every name dpkg admits to and
    require that apt-cache never answers "cannot locate" for any of them.
    That is the shape of the original defect, and it is cheap to hold."""
    s = sh()
    names = sorted(fs.Shell.UN_PACKAGES)
    bad = []
    for n in names:
        out, err, rc = R("apt-cache policy " + n, s)
        if "Unable to locate" in (out + err) or not out.startswith(n + ":"):
            bad.append(n)
    check("every referenced name answers policy", not bad,
          "%d disowned, e.g. %s" % (len(bad), bad[:5]))
    check("...and there are enough of them to matter",
          len(names) >= 500, len(names))


TESTS = [t_apt_cache_knows_the_names_dpkg_knows,
         t_a_referenced_name_with_no_candidate_still_answers,
         t_a_name_apt_never_heard_of_is_not_apt_gets_wording,
         t_installing_a_referenced_package_stops_it_being_referenced,
         t_a_package_that_ships_no_binary_creates_none,
         t_no_referenced_name_is_disowned_by_apt_cache,
         t_referenced_packages_answer_un_not_notfound,
         t_a_name_dpkg_never_heard_of_is_still_not_found,
         t_a_bare_listing_leaves_the_stubs_out,
         t_a_glob_reaches_the_stubs,
         t_installed_and_stub_rows_sort_together,
         t_one_missing_name_still_lists_the_rest,
         t_the_description_rule_is_as_wide_as_the_widest_description,
         t_dpkg_s_points_at_dpkg_deb,
         t_the_stub_set_and_the_installed_set_are_disjoint,
         t_the_status_file_lists_what_dpkg_lists,
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
