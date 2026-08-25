#!/usr/bin/env python3
"""A binary an attacker deleted has to still be gone when they come back.

Found while working out why the live box answered "command not found" to
everything (selfstatetest.py). The journal that wrecked it was real, and
replaying it exposed three ways the emulator disagreed with itself about
what "deleted" means:

  * `rm -f /bin/ps` unlinked both spellings for the session and journalled
    only the one that was typed, so seed_binaries put /usr/bin/ps back on
    the next login. _drop_merged_usr_twins' docstring says every
    anti-forensics script deletes /bin/ps first and that they all reported
    success and changed nothing -- that was fixed for the session and not
    across the reconnect, which is the login the script's author sees.

  * `rm -rf /usr/bin` tombstoned the directory and not its 316 children,
    which did not exist yet at replay time to be tombstoned individually.
    seed_binaries then rebuilt every one of them. Deleting a binary by name
    survived a reconnect and deleting it with its directory did not.

  * `rm -rf /bin` removed the symlink and left every /bin/<name> key in the
    node table, so /bin was gone and `ls -l /bin/ls` still answered.

The shape of all three is one question with two answers, and the second
answer is the one the attacker gets on their next login -- the session where
they check whether last session's work held.

Reference behaviour measured on debian:trixie, where /bin -> usr/bin:

    rm -rf /bin        rc 0, `ls -ld /bin` No such file or directory,
                       `ls /usr/bin | wc -l` still 259
    rm -f /bin/ps      /usr/bin/ps gone too -- one inode, two names

Usage:  python3 rmpersisttest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def session(cmds):
    """Run cmds on a fresh box; return (vfs, shell)."""
    fs = fakeshell.VFS()
    sh = fakeshell.Shell(vfs=fs)
    for c in cmds:
        sh.run(c)
    return fs, sh


def reconnect(fs):
    """What the same source sees on their next login."""
    fresh = fakeshell.VFS()
    fresh.load_journal(fs.dump_journal())
    return fresh, fakeshell.Shell(vfs=fresh)


PROBES = (
    ("ps runs", lambda fs, sh: bool(sh.run("ps"))),
    ("id runs", lambda fs, sh: "uid=0(root)" in sh.run("id")),
    ("ls runs", lambda fs, sh: "hostname" in sh.run("ls /etc")),
    ("/bin/ps in tree", lambda fs, sh: fs.exists("/bin/ps")),
    ("/usr/bin/ps in tree", lambda fs, sh: fs.exists("/usr/bin/ps")),
    ("/bin/ls in tree", lambda fs, sh: fs.exists("/bin/ls")),
    ("/usr/bin/ls in tree", lambda fs, sh: fs.exists("/usr/bin/ls")),
    ("/bin resolvable", lambda fs, sh: fs.exists("/bin")),
    # Counted here rather than with `| wc -l`: wc lives in /usr/bin, so in
    # the case that empties it the pipeline has no wc and prints nothing.
    # That is correct -- and it makes the probe answer "" for two different
    # reasons, which is exactly the kind of reader that cannot be trusted.
    ("usr/bin count", lambda fs, sh: len(sh.run("ls /usr/bin").split())),
    ("ls -l /bin/ps answers", lambda fs, sh: bool(sh.run("ls -l /bin/ps"))),
    ("command -v ps", lambda fs, sh: sh.run("command -v ps").strip()),
)


def survives(label, cmds):
    """Every probe must give the same answer this session and the next.

    Returns the session's answers so a caller can assert what they are --
    two wrong readers that agree still pass a consistency check, so the
    absolute values are pinned separately below.
    """
    fs, sh = session(cmds)
    live = {n: f(fs, sh) for n, f in PROBES}
    fs2, sh2 = reconnect(fs)
    back = {n: f(fs2, sh2) for n, f in PROBES}
    for n in live:
        check("%s: %s survives the reconnect" % (label, n), back[n], live[n])
    return live


def main():
    # -- the box before anything is deleted ---------------------------------
    base = survives("untouched", [])
    check("untouched: ps runs", base["ps runs"], True)
    check("untouched: both spellings of ps exist",
          base["/bin/ps in tree"] and base["/usr/bin/ps in tree"], True)
    n_base = base["usr/bin count"]
    check("untouched: /usr/bin is populated", n_base > 200, True)

    # -- rm -f /bin/ps: one inode, two names, and it stays gone -------------
    for spelling in ("/bin/ps", "/usr/bin/ps"):
        got = survives("rm -f %s" % spelling, ["rm -f %s" % spelling])
        check("rm -f %s: ps stops running" % spelling, got["ps runs"], False)
        check("rm -f %s: /bin/ps gone" % spelling,
              got["/bin/ps in tree"], False)
        check("rm -f %s: /usr/bin/ps gone too" % spelling,
              got["/usr/bin/ps in tree"], False)
        check("rm -f %s: command -v agrees" % spelling,
              got["command -v ps"], "")
        check("rm -f %s: one file fewer" % spelling,
              got["usr/bin count"], n_base - 1)
        check("rm -f %s: ls is untouched" % spelling, got["ls runs"], True)

    # -- rm -rf /usr/bin: the directory and everything under it -------------
    got = survives("rm -rf /usr/bin", ["rm -rf /usr/bin"])
    check("rm -rf /usr/bin: nothing runs", got["ps runs"] or got["id runs"]
          or got["ls runs"], False)
    check("rm -rf /usr/bin: the directory reads empty",
          got["usr/bin count"], 0)
    check("rm -rf /usr/bin: the /bin spelling goes with it",
          got["/bin/ls in tree"], False)
    check("rm -rf /usr/bin: and does not answer ls -l",
          got["ls -l /bin/ps answers"], False)

    # -- rm -rf /bin: the symlink, not what it points at --------------------
    # Measured: on the guest this leaves /usr/bin whole and only removes the
    # way in. Getting this wrong in the other direction would be worse than
    # the bug -- it would delete 259 files the attacker did not delete.
    got = survives("rm -rf /bin", ["rm -rf /bin"])
    check("rm -rf /bin: /bin is gone", got["/bin resolvable"], False)
    check("rm -rf /bin: /bin/ps is gone with it",
          got["/bin/ps in tree"], False)
    check("rm -rf /bin: /usr/bin/ps is not",
          got["/usr/bin/ps in tree"], True)
    check("rm -rf /bin: /usr/bin still has everything",
          got["usr/bin count"], n_base)
    check("rm -rf /bin: ps still runs, PATH has /usr/bin",
          got["ps runs"], True)
    check("rm -rf /bin: ls -l /bin/ps says nothing",
          got["ls -l /bin/ps answers"], False)

    # -- the tombstone must not over-reach ----------------------------------
    got = survives("rm -f /usr/bin/curl", ["rm -f /usr/bin/curl"])
    check("removing curl leaves id alone", got["id runs"], True)
    check("removing curl leaves ps alone", got["ps runs"], True)
    check("removing curl leaves ls alone", got["ls runs"], True)

    # A directory the attacker removed and then rebuilt is theirs again:
    # the tombstone is about the seeder putting stock files back, not about
    # forbidding the path forever.
    fs, sh = session(["rm -rf /root/.cache", "mkdir -p /root/.cache",
                      "echo payload > /root/.cache/x"])
    fs2, sh2 = reconnect(fs)
    check("a rebuilt directory comes back", fs2.exists("/root/.cache"), True)
    check("...with what was written into it",
          "payload" in sh2.run("cat /root/.cache/x"), True)

    # ...and the same for a stock directory, which is the case that would
    # break if unlinked_dirs were consulted for writes rather than seeding.
    # /usr/sbin rather than /usr/bin: wiping /usr/bin takes mkdir with it,
    # so there is no way back in -- true here and true on a real box.
    fs, sh = session(["rm -rf /usr/sbin", "mkdir -p /usr/sbin",
                      "echo x > /usr/sbin/mine", "chmod 755 /usr/sbin/mine"])
    check("the wipe-and-rebuild actually ran", fs.exists("/usr/sbin/mine"),
          True)
    fs2, sh2 = reconnect(fs)
    check("a file dropped into a wiped /usr/sbin survives",
          fs2.exists("/usr/sbin/mine"), True)
    check("...and the stock binaries stay deleted",
          fs2.exists("/usr/sbin/blkid"), False)
    check("...so the directory holds exactly what they put there",
          sh2.run("ls /usr/sbin").split(), ["mine"])
    # blkid rather than ip: four names -- ip, lsmod, php-fpm8.4 and
    # rsyslogd -- are seeded into /usr/bin as well as /usr/sbin, because
    # dpkg -S on the guest names both locations for them. Wiping one
    # directory is not supposed to take those away.
    check("...and the deleted one is not runnable either",
          sh2.run("command -v blkid").strip(), "")
    check("...while a name that lives in both is still reachable",
          sh2.run("command -v ip").strip(), "/usr/bin/ip")

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("rmpersisttest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
