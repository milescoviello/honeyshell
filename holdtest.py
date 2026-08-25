#!/usr/bin/env python3
"""Holding a package is persistence. Do the two commands that show it agree?

The SRBMiner installer that ran on 2026-08-25 replaced twenty-odd tools --
ps, top, htop, pgrep, kill, pkill, killall, lsof, strace, gdb, netstat, ss,
w, who, id -- with fakes, sealed them `chattr +i`, and then, for each one,
tried to pin the package so an upgrade could not repair it:

    dpkg --set-selections        (x20, one per tool)
    yum versionlock add strace
    dnf versionlock add strace

The yum and dnf lines are a multi-distro script guessing; on Debian they are
correctly "command not found". The dpkg line is the one that matters, and
every one of the twenty **exited 2**. It fell through to dpkg's "need an
action option" branch, so nothing was recorded, and:

  * `apt-mark showhold` returned "" unconditionally -- it did not read any
    state at all, so a hold set one command earlier was invisible.
  * `apt-mark hold`, `unhold`, `manual` and `auto` were silent no-ops with
    rc 0, so a script could not tell a successful hold from a typo.
  * `dpkg --get-selections procps` ignored its argument and printed all 104
    packages, so anything reading the second field got whichever package
    sorted first.

And the format was wrong in a way one `cat -A` shows: dpkg pads the name
with **tabs** to column 48, and this printed "%-40s install" -- a different
number of a different character.

Measured on a trixie container, since the guest has no dpkg selections
worth holding:

    dpkg --get-selections coreutils   ->  coreutils\\t\\t\\t\\t\\tinstall   rc 0
    echo "coreutils hold" | dpkg --set-selections  ->  rc 0
    apt-mark hold coreutils           ->  "coreutils set on hold."   rc 0
    apt-mark unhold coreutils         ->  "Canceled hold on coreutils."
    apt-mark hold nosuchpkg123        ->  two E: lines on stderr,   rc 100
    dpkg --get-selections nosuchpkg   ->  stderr message, no stdout, rc 0

Usage:  python3 holdtest.py
"""

import sys

import fakeshell as F

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh(vfs=None):
    return F.Shell(vfs=vfs) if vfs is not None else F.Shell()


def t_get_selections_filters():
    s = sh()
    all_lines = s.run("dpkg --get-selections").splitlines()
    one = s.run("dpkg --get-selections coreutils").splitlines()
    check("the whole list is long", len(all_lines) > 50, True)
    check("an argument filters it to one", len(one), 1)
    check("and it is the right one",
          one[0].split()[0] if one else None, "coreutils")
    # A glob, which dpkg accepts.
    many = s.run("dpkg --get-selections 'openssh*'").splitlines()
    check("a glob matches several", len(many) >= 2, True)
    check("and only matching ones",
          all(l.split()[0].startswith("openssh") for l in many), True)


def t_the_format_is_dpkgs():
    """Tabs to column 48, not spaces. `cat -A` is one command."""
    s = sh()
    line = s.run("dpkg --get-selections coreutils").rstrip("\n")
    check("no spaces between the columns", " " in line, False)
    check("padded with tabs", "\t" in line, True)
    # Expand the tabs and see where the state actually lands. The first
    # version of this check did arithmetic on lengths and counts that did
    # not mean anything, and reported 19.
    col = 0
    for ch in line:
        col = (col // 8 + 1) * 8 if ch == "\t" else col + 1
        if ch == "\t" and col >= 48:
            break
    check("the state starts at column 48", col, 48)
    check("the state is the second field", line.split()[1], "install")


def t_set_selections_is_accepted_and_recorded():
    s = sh()
    check("dpkg --set-selections succeeds",
          s.run("echo 'procps hold' | dpkg --set-selections; echo $?").strip(),
          "0")
    check("the selection changed",
          s.run("dpkg --get-selections procps").split()[1], "hold")
    check("and grep hold finds it",
          "procps" in s.run("dpkg --get-selections | grep hold"), True)
    # Everything else is untouched.
    check("other packages stay installed",
          s.run("dpkg --get-selections coreutils").split()[1], "install")


def t_apt_mark_says_what_it_did():
    s = sh()
    check("hold prints the message",
          s.run("apt-mark hold procps").strip(), "procps set on hold.")
    check("hold succeeds",
          s.run("apt-mark hold nano >/dev/null; echo $?").strip(), "0")
    check("unhold prints the message",
          s.run("apt-mark unhold procps").strip(), "Canceled hold on procps.")
    check("an unknown package is an error",
          s.run("apt-mark hold nosuchpkg123 >/dev/null 2>&1; echo $?").strip(),
          "100")
    err = s.run("apt-mark hold nosuchpkg123 2>&1")
    check("...and says why",
          "E: Unable to locate package nosuchpkg123" in err, True)
    check("...and summarises", "E: No packages found" in err, True)


def t_the_two_commands_agree():
    """The point of the suite: one hold, two readers."""
    s = sh()
    check("nothing is held to begin with",
          s.run("apt-mark showhold").strip(), "")
    s.run("apt-mark hold procps")
    s.run("echo 'nano hold' | dpkg --set-selections")
    held_apt = sorted(s.run("apt-mark showhold").split())
    held_dpkg = sorted(l.split()[0] for l in
                       s.run("dpkg --get-selections").splitlines()
                       if l.split()[1] == "hold")
    check("apt-mark showhold matches dpkg's selections", held_apt, held_dpkg)
    check("and both list what was held", held_apt, ["nano", "procps"])
    # Whichever command set it, the other one sees it.
    check("a hold set by dpkg shows in apt-mark", "nano" in held_apt, True)
    check("a hold set by apt-mark shows in dpkg", "procps" in held_dpkg, True)
    s.run("apt-mark unhold procps")
    check("unhold is visible to dpkg too",
          s.run("dpkg --get-selections procps").split()[1], "install")


def t_a_hold_outlives_the_session():
    """It is persistence, so it has to survive the way their files do."""
    v = F.VFS()
    s1 = sh(v)
    s1.run("apt-mark hold procps")
    s2 = sh(v)
    check("a later shell on the same box still sees the hold",
          s2.run("apt-mark showhold").strip(), "procps")
    check("...and so does dpkg",
          s2.run("dpkg --get-selections procps").split()[1], "hold")
    # A different box does not.
    s3 = sh(F.VFS())
    check("a different filesystem is unaffected",
          s3.run("apt-mark showhold").strip(), "")


def t_unknown_package_in_get_selections():
    s = sh()
    check("nothing on stdout",
          s.run("dpkg --get-selections nosuchpkg123 2>/dev/null").strip(), "")
    check("the message is on stderr, not stdout",
          "no packages found matching nosuchpkg123"
          in s.run("dpkg --get-selections nosuchpkg123 2>&1"), True)
    check("and it is not an error",
          s.run("dpkg --get-selections nosuchpkg123 >/dev/null 2>&1; echo $?")
          .strip(), "0")


def main():
    for fn in (t_get_selections_filters,
               t_the_format_is_dpkgs,
               t_set_selections_is_accepted_and_recorded,
               t_apt_mark_says_what_it_did,
               t_the_two_commands_agree,
               t_a_hold_outlives_the_session,
               t_unknown_package_in_get_selections):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-54s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("holdtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
