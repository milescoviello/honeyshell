#!/usr/bin/env python3
"""tar: does unpacking put the files where the script expects them?

Thirty-fifth coherence sweep, and the fifth taken from a captured payload
rather than a chosen axis. srb.sh, the SRBMiner installer 203.0.113.33
ran as root on 2026-08-22, unpacks with

    tar -xzf /tmp/srb.tar.gz -C /opt/srbminer --strip-components=1
    mv /opt/srbminer/SRBMiner-MULTI /opt/srbminer/kaudit
    chmod +x /opt/srbminer/kaudit

Every one of those commands reported success in our log. The install
still could not have worked, because _tar_flags dropped every long option
on the floor:

  * `--strip-components=1` was ignored, so the binary landed at
    /opt/srbminer/SRBMiner-Multi-3-4-1-Linux/SRBMiner-MULTI, one level
    deeper than the mv that follows looks. The mv finds nothing, the
    chmod finds nothing, and the unit points at a file that is not there
    -- while every step exits 0. A silent wrong answer three commands
    before the one that would have shown it.
  * `--exclude` likewise ignored.
  * Naming members on extract did nothing: `tar -xzf a.tgz src/a.txt`
    unpacked the whole archive rather than that one file.
  * `-O` wrote to the filesystem instead of stdout, so
    `tar -xzOf a.tgz path | sh` -- a way of running a staged script
    without ever landing it -- produced nothing at all.

The round trip was already sound: tar -czf then -tzf then -xzf returns
the same tree with content, modes, owners and mtimes intact, and a
missing archive fails with tar's own wording and rc 2.

Reference measured on the guest, as root, from src/{a.txt,sub/b.txt}:

    -C o0                          o0/src/a.txt  o0/src/sub/b.txt
    -C o1 --strip-components=1     o1/a.txt      o1/sub/b.txt
    -C o2 --strip-components=2     o2/b.txt
    -C o5 --strip-components=5     (nothing)
    -C o6 --strip=1                same as strip-components=1
    -C o7 --exclude="*/sub/*"      o7/src/a.txt, o7/src/sub, no b.txt
    -C om src/a.txt                om/src/a.txt only
    -xzOf t.tgz src/a.txt          "one" on stdout
    -C os --strip-components=1 src/sub   os/sub/b.txt

and the installer's own shape:

    tar -xzf srb.tar.gz -C opt --strip-components=1  ->  opt/SRBMiner-MULTI

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

BUILD = ("mkdir -p /w/src/sub; echo one > /w/src/a.txt; "
         "echo two > /w/src/sub/b.txt; chmod 755 /w/src/a.txt; "
         "cd /w && tar -czf /w/t.tgz src")


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    s.run(BUILD)
    s._err.clear()
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def extract(s, args, out="/o"):
    run(s, "rm -rf %s; mkdir -p %s" % (out, out))
    _o, rc = run(s, "tar -xzf /w/t.tgz -C %s %s" % (out, args))
    listing = run(s, "find %s | sort" % out)[0].split()
    return [p[len(out):] or "/" for p in listing], rc


# -- the round trip, already sound and pinned here -----------------------

def t_round_trip():
    s = sh()
    eq("tar -tzf lists what -czf wrote",
       run(s, "tar -tzf /w/t.tgz")[0].split(),
       ["src/", "src/a.txt", "src/sub/", "src/sub/b.txt"])
    got, rc = extract(s, "")
    eq("full extract", got, ["/", "/src", "/src/a.txt", "/src/sub",
                             "/src/sub/b.txt"])
    eq("rc 0", rc, 0)
    eq("content survives", run(s, "cat /o/src/a.txt /o/src/sub/b.txt"
                               )[0].split(), ["one", "two"])
    eq("mode survives", run(s, "stat -c %a /o/src/a.txt")[0].strip(), "755")


def t_a_missing_archive_fails():
    s = sh()
    out, rc = run(s, "tar -xzf /w/nope.tgz")
    check("tar's own wording", "Cannot open" in out, out)
    eq("rc 2", rc, 2)


# -- --strip-components --------------------------------------------------

def t_strip_components():
    s = sh()
    eq("strip 1", extract(s, "--strip-components=1")[0],
       ["/", "/a.txt", "/sub", "/sub/b.txt"])
    eq("strip 2", extract(s, "--strip-components=2")[0], ["/", "/b.txt"])
    eq("strip too deep extracts nothing",
       extract(s, "--strip-components=5")[0], ["/"])
    eq("strip 0 is the plain case", extract(s, "--strip-components=0")[0],
       ["/", "/src", "/src/a.txt", "/src/sub", "/src/sub/b.txt"])


def t_strip_spellings():
    s = sh()
    want = ["/", "/a.txt", "/sub", "/sub/b.txt"]
    eq("--strip=1", extract(s, "--strip=1")[0], want)
    eq("--strip-components 1 separated",
       extract(s, "--strip-components 1")[0], want)


def t_strip_keeps_the_content():
    s = sh()
    extract(s, "--strip-components=1")
    eq("the stripped files still hold their bytes",
       run(s, "cat /o/a.txt /o/sub/b.txt")[0].split(), ["one", "two"])


# -- member selection ----------------------------------------------------

def t_naming_a_member_selects_it():
    s = sh()
    eq("one file only", extract(s, "src/a.txt")[0],
       ["/", "/src", "/src/a.txt"])
    eq("a directory takes its subtree", extract(s, "src/sub")[0],
       ["/", "/src", "/src/sub", "/src/sub/b.txt"])


def t_member_and_strip_together():
    s = sh()
    eq("strip applies to the selected member",
       extract(s, "--strip-components=1 src/sub")[0],
       ["/", "/sub", "/sub/b.txt"])


# -- --exclude -----------------------------------------------------------

def t_exclude():
    s = sh()
    got = extract(s, '--exclude="*/sub/*"')[0]
    check("b.txt is gone", "/src/sub/b.txt" not in got, got)
    check("a.txt is kept", "/src/a.txt" in got, got)


# -- -O ------------------------------------------------------------------

def t_dash_O_writes_to_stdout():
    s = sh()
    run(s, "rm -rf /o; mkdir -p /o")
    out, rc = run(s, "tar -xzOf /w/t.tgz src/a.txt")
    eq("the member's bytes come back", out.strip(), "one")
    eq("rc 0", rc, 0)
    check("and nothing was written", run(s, "find /o")[0].split() == ["/o"],
          run(s, "find /o")[0])
    eq("no member means all of them",
       run(s, "tar -xzOf /w/t.tgz")[0].split(), ["one", "two"])


def t_dash_O_piped_is_a_stager():
    """`tar -xzOf x.tgz run.sh | sh` never lands the script."""
    s = sh()
    run(s, "mkdir -p /p; echo 'echo staged' > /p/run.sh; "
           "cd / && tar -czf /w/p.tgz p")
    eq("the piped stager runs",
       run(s, "tar -xzOf /w/p.tgz p/run.sh | sh")[0].strip(), "staged")


# -- the installer's own shape -------------------------------------------

def t_the_srbminer_unpack():
    """tar -xzf srb.tar.gz -C /opt/srbminer --strip-components=1,
    then mv the binary into place. Every step must land."""
    s = sh()
    run(s, "mkdir -p /rel/SRBMiner-Multi-3-4-1-Linux; "
           "echo binary > /rel/SRBMiner-Multi-3-4-1-Linux/SRBMiner-MULTI; "
           "cd /rel && tar -czf /tmp/srb.tar.gz SRBMiner-Multi-3-4-1-Linux")
    run(s, "mkdir -p /opt/srbminer")
    _o, rc = run(s, "tar -xzf /tmp/srb.tar.gz -C /opt/srbminer "
                    "--strip-components=1")
    eq("the unpack succeeds", rc, 0)
    eq("the binary is where the script looks",
       run(s, "find /opt/srbminer | sort")[0].split(),
       ["/opt/srbminer", "/opt/srbminer/SRBMiner-MULTI"])
    _o, rc = run(s, "mv /opt/srbminer/SRBMiner-MULTI /opt/srbminer/kaudit")
    eq("the mv finds it", rc, 0)
    _o, rc = run(s, "chmod +x /opt/srbminer/kaudit")
    eq("the chmod finds it", rc, 0)
    eq("and it is executable",
       run(s, "stat -c %a /opt/srbminer/kaudit")[0].strip(), "755")


TESTS = [t_round_trip, t_a_missing_archive_fails, t_strip_components,
         t_strip_spellings, t_strip_keeps_the_content,
         t_naming_a_member_selects_it, t_member_and_strip_together,
         t_exclude, t_dash_O_writes_to_stdout, t_dash_O_piped_is_a_stager,
         t_the_srbminer_unpack]


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
