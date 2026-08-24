#!/usr/bin/env python3
"""Do the commands that resolve paths agree with each other?

Seventh coherence sweep. A box has several ways to answer "where does this
path actually lead" -- realpath, readlink -f, pwd -P, cd -P, stat -L, and
test's file predicates -- and on a real machine they all consult the same
resolver, so they cannot disagree. Attackers walk paths constantly: `cd ..`,
absolute paths, and `[ -d "$dir" ]` are in every script.

The axis was picked because hardlinks and the update-alternatives symlinks
had just been added, and new links are exactly where resolvers drift apart.

Found in one pass:

  * realpath resolved nothing. `realpath /bin` returned /bin while
    `readlink -f /bin` returned /usr/bin, and `realpath /usr/bin/php`
    returned the alternatives symlink instead of php8.4.
  * pwd -P returned the logical path, so `cd /bin && pwd -P` said /bin where
    a real shell says /usr/bin.
  * cd -P was parsed as a directory called "-P" and failed.
  * test followed no symlinks at all: `[ -d link ]` was false for a link to
    a directory and `[ -f dangling ]` was true for a link to nothing. There
    was no -L or -h either.
  * `stat -Lc %F` was read as one unknown option, losing the -c format, so
    it printed the whole stat block instead of one field.
  * realpath's existence rules were all-or-nothing: -m, -e and -s were
    ignored and a missing final component was always an error.

The reference is the real coreutils and bash on this host, through a fixture
built identically on both sides.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

# Built the same way in the real temp dir and inside the emulator.
FIXTURE = ("mkdir -p %(d)s/real/sub; echo x > %(d)s/real/f; "
           "ln -s real %(d)s/link; ln -s /etc/passwd %(d)s/fl; "
           "ln -s /nope %(d)s/dang; ln -s link %(d)s/link2")

# %(d)s is substituted with the fixture root on each side.
CASES = [
    ("realpath a symlink",      "realpath %(d)s/link"),
    ("realpath a link chain",   "realpath %(d)s/link2"),
    ("realpath a file link",    "realpath %(d)s/fl"),
    ("realpath -s",             "realpath -s %(d)s/link"),
    ("realpath missing last",   "realpath %(d)s/real/nope; echo rc=$?"),
    ("realpath missing mid",    "realpath %(d)s/nodir/x; echo rc=$?"),
    ("realpath -m missing",     "realpath -m %(d)s/nodir/x; echo rc=$?"),
    ("realpath -e missing",     "realpath -e %(d)s/real/nope; echo rc=$?"),
    ("readlink plain",          "readlink %(d)s/link"),
    ("readlink -f symlink",     "readlink -f %(d)s/link"),
    ("readlink -f chain",       "readlink -f %(d)s/link2"),
    ("readlink -f missing last", "readlink -f %(d)s/real/nope; echo rc=$?"),
    ("readlink -f missing mid", "readlink -f %(d)s/nodir/x; echo rc=$?"),
    ("readlink on a real file", "readlink %(d)s/real/f; echo rc=$?"),
    ("realpath and readlink -f agree",
     "a=$(realpath %(d)s/link); b=$(readlink -f %(d)s/link); "
     "[ \"$a\" = \"$b\" ] && echo agree || echo \"$a vs $b\""),

    ("pwd is logical",          "cd %(d)s/link && pwd"),
    ("pwd -L is logical",       "cd %(d)s/link && pwd -L"),
    ("pwd -P is physical",      "cd %(d)s/link && pwd -P"),
    ("cd -P lands physical",    "cd -P %(d)s/link && pwd"),
    ("cd -L lands logical",     "cd -L %(d)s/link && pwd"),
    ("cd .. from a link",       "cd %(d)s/link && cd .. && pwd"),
    ("cd through .. mid path",  "cd %(d)s/real/sub/.. && pwd"),
    ("pwd -P matches realpath",
     "cd %(d)s/link && a=$(pwd -P); b=$(realpath %(d)s/link); "
     "[ \"$a\" = \"$b\" ] && echo agree || echo \"$a vs $b\""),

    ("test -d on a dir link",   "[ -d %(d)s/link ] && echo yes || echo no"),
    ("test -L on a link",       "[ -L %(d)s/link ] && echo yes || echo no"),
    ("test -h on a link",       "[ -h %(d)s/link ] && echo yes || echo no"),
    ("test -L on a real dir",   "[ -L %(d)s/real ] && echo yes || echo no"),
    ("test -f through a link",  "[ -f %(d)s/fl ] && echo yes || echo no"),
    ("test -f on a dangling link",
     "[ -f %(d)s/dang ] && echo yes || echo no"),
    ("test -e on a dangling link",
     "[ -e %(d)s/dang ] && echo yes || echo no"),
    ("test -L on a dangling link",
     "[ -L %(d)s/dang ] && echo yes || echo no"),
    ("test -d on a file",       "[ -d %(d)s/real/f ] && echo yes || echo no"),
    ("test -s through a link",  "[ -s %(d)s/fl ] && echo yes || echo no"),

    ("stat names a link",       "stat -c %%F %(d)s/link"),
    ("stat -L follows it",      "stat -Lc %%F %(d)s/link"),
    ("stat -L split form",      "stat -L -c %%F %(d)s/link"),
    ("stat and test agree on the type",
     "t=$(stat -Lc %%F %(d)s/link); [ -d %(d)s/link ] && d=directory || d=other; "
     "[ \"$t\" = \"$d\" ] && echo agree || echo \"$t vs $d\""),

    ("ls through a link",       "ls %(d)s/link | sort"),
    ("ls -l names the target",  "ls -l %(d)s/link | sed 's/.*-> //'"),
    ("cat through a link",      "cat %(d)s/fl | head -1"),
    ("basename",                "basename %(d)s/real/f"),
    ("dirname",                 "dirname %(d)s/real/f"),
    ("dirname of a bare name",  "dirname justaname"),
    ("basename with suffix",    "basename %(d)s/real/f.tar.gz .tar.gz"),
]


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0
    real_root = tempfile.mkdtemp(prefix="pathtest-")
    subprocess.run(["bash", "-c", "umask 022\n" + FIXTURE % {"d": real_root}],
                   capture_output=True)

    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    ours_root = "/tmp/pathtest"
    sh.run("rm -rf %s; mkdir -p %s" % (ours_root, ours_root))
    sh.run(FIXTURE % {"d": ours_root})

    for name, tpl in CASES:
        real_cmd = tpl % {"d": real_root}
        ours_cmd = tpl % {"d": ours_root}
        try:
            r = subprocess.run(["bash", "-c", "umask 022\n" + real_cmd],
                               capture_output=True, text=True,
                               cwd=real_root, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        want = r.stdout.replace(real_root, "<R>")
        got = sh.run(ours_cmd).replace(ours_root, "<R>")
        sh._err.clear()
        if want == got:
            ok += 1
            if verbose:
                print("  ok   %-34s %r" % (name, want[:40]))
        else:
            bad += 1
            print("  DIFF %-34s %s" % (name, tpl[:44]))
            print("       real %r" % want[:80])
            print("       ours %r" % got[:80])
    # ---- structural invariant, not a diff against the host ----------
    # Every node's parent directories must exist as directories. Five did
    # not, and /var/lib was the worst: 31 descendants and the directory
    # itself unreachable, so `cd /var/lib/mysql` worked while `cd /var/lib`
    # returned No such file or directory -- along with ls, stat, test -d and
    # find. Checked as a sweep over the whole tree rather than as a handful
    # of named paths, because the hole appears wherever something writes a
    # deep path without creating the tree above it and the next one would be
    # as invisible as these were.
    import os as _os
    v = fs.VFS()
    orphans = {}
    for path in v.nodes:
        parent = _os.path.dirname(path)
        if parent and parent != "/" and parent not in v.nodes:
            orphans.setdefault(parent, 0)
            orphans[parent] += 1
    if orphans:
        bad += 1
        print("  DIFF %-34s %d directories have children but no node"
              % ("orphaned parent directories", len(orphans)))
        for d, n in sorted(orphans.items())[:6]:
            print("       %s (%d descendants)" % (d, n))
    else:
        ok += 1
        if verbose:
            print("  ok   %-34s no orphaned parents" % "tree is connected")

    # ...and every directory must be reachable by the commands that walk it.
    sh2 = fs.Shell(v)
    sh2.exec_mode = True
    for probe in ("/var/lib", "/usr/lib/systemd", "/usr/lib/modules",
                  "/var/www", "/etc/nginx"):
        sh2.run("cd / ")
        out = sh2.run("test -d %s && echo yes || echo no" % probe)
        sh2._err.clear()
        if out.strip() == "yes":
            ok += 1
        else:
            bad += 1
            print("  DIFF %-34s test -d says %r" % (probe, out.strip()))

    print()
    print("=" * 60)
    print("%d/%d match  (%d differ)" % (ok, ok + bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
