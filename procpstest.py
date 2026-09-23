#!/usr/bin/env python3
"""What procps ships, and what its tools say when asked for help.

Started from one missing pair and turned into something wider.

`dpkg -l procps` claimed 4.0.4 while `dpkg -L procps` described a package
that shipped neither pidwait nor snice, and neither was on disk. procps has
shipped snice for decades and pidwait since 4.0.0, so the version and the
file list contradicted each other.

Fixing that exposed the bigger one. Of the eighteen names procps ships,
twelve ignored `--help` and ran themselves instead:

    free --help     printed a memory table
    ps --help       printed 22579 bytes of process list
    w --help        printed who was logged in
    uptime --help   printed the uptime
    vmstat --help   printed the vmstat table
    tload --help    printed a load average

and skill and slabtop, having no implementation at all, fell through to a
stock template -- `skill 4.0.4` followed by `Usage: skill [OPTION]...
[FILE]...` -- which is GNU coreutils' shape and one no procps tool prints.

`--help` is what someone types when a command did not do what they
expected, so a box where it runs the command instead is a box that behaves
differently from every other box at exactly the moment it is being
examined.

## The part that could not be guessed

`-h` is help for ten of them and something else entirely for three:

    free -h    human-readable sizes
    ps -h      no header
    w -h       no header

Those were measured one command at a time. Assuming would have made three
tools print usage where a real box prints output -- the same mistake in the
opposite direction.

skill and snice are one binary reading argv[0], so implementing snice alone
would have left one file telling the truth under one of its two names.

Lengths below are the guest's own procps-ng 4.0.4, byte for byte.

Usage:  python3 procpstest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.11", peer_port=45100)
sh.exec_mode = True


def r(cmd):
    try:
        return sh.run(cmd + " 2>&1")
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def rc_of(cmd):
    return (sh.run(cmd + " >/dev/null 2>&1; echo $?") or "").strip()


#: Every name the procps deb puts in a bin directory, from `dpkg -L procps`
#: on the guest.
SHIPS = ("free", "kill", "pgrep", "pidwait", "pkill", "pmap", "ps", "pwdx",
         "skill", "slabtop", "snice", "sysctl", "tload", "top", "uptime",
         "vmstat", "w", "watch")

#: --help length per tool, measured on the guest.
#:
#: slabtop was left out of this table on the reasoning that its bare and
#: -o paths were unfinished. That deferred the wrong half. Once --help was
#: answered for it from the other help table, `slabtop -h` still gave the
#: stock template -- and for procps -h IS --help, so one command had two
#: answers depending on which spelling was used. Its help is measured here
#: now and _PROCPS_HELP owns it alone. The -o path still needs slabinfo we
#: do not have, and is still queued.
HELP_LEN = {"free": 1125, "pgrep": 1853, "pkill": 1853, "pmap": 891,
            "slabtop": 682,
            "ps": 165, "pwdx": 167, "skill": 1433, "snice": 1401,
            "sysctl": 1109, "tload": 250, "uptime": 241, "vmstat": 723,
            "w": 544, "watch": 1024, "pidwait": 1659}

#: Where -h is help, and where it is a different option entirely.
DASH_H_IS_HELP = ("pgrep", "pkill", "pmap", "pwdx", "skill", "slabtop",
                  "sysctl", "tload", "uptime", "vmstat", "watch", "pidwait")

#: One command, one table. slabtop was briefly in both _PROCPS_HELP and
#: the general help table, which is how the two spellings came to
#: disagree; this asserts the ownership rather than the symptom.
import fakeshell as _fs_mod  # noqa: E402
try:
    import helpdb as _helpdb_mod  # noqa: E402
except ImportError:                                            # pragma: no cover
    _helpdb_mod = None
DASH_H_IS_NOT = ("free", "ps", "w")

# --- no procps tool is described by two tables at once
if _helpdb_mod is not None:
    both = sorted(n for n in SHIPS
                  if n in getattr(_fs_mod.Shell, "_PROCPS_HELP", {})
                  and n in getattr(_helpdb_mod, "HELP", {}))
    check("no procps tool has its help in two tables", both, [],
          "slabtop was in both, and `slabtop -h` and `slabtop --help` "
          "gave different answers because only one table is consulted for "
          "the -h spelling")

# --- the package and the filesystem describe the same package
# sysctl lives in /usr/sbin, so a "/bin/" test alone drops it -- which is
# this file getting the question wrong, not the box.
listed = [x.strip().rsplit("/", 1)[-1]
          for x in r("dpkg -L procps").splitlines()
          if "/bin/" in x or "/sbin/" in x]
for n in SHIPS:
    check("dpkg -L procps lists %s" % n, n in listed, True,
          "procps 4.0.4 ships it; a file list that omits it describes a "
          "different package than the version beside it")
    # kill is a shell builtin, so `command -v kill` answers "kill" -- that
    # is bash being right, not the box being wrong.
    if n != "kill":
        check("...and %s is on disk" % n,
              r("command -v %s" % n).strip().endswith("/" + n), True)
        check("...and dpkg -S agrees procps owns it",
              r("dpkg -S $(command -v %s)" % n).strip().startswith("procps:"),
              True)

# --- every one of them runs and names its own version
for n in SHIPS:
    if n in ("kill", "watch"):
        continue          # kill is a builtin; watch has no -V, only -v
    check("%s -V is procps-ng's own banner" % n,
          r("%s -V" % n).strip(), "%s from procps-ng 4.0.4" % n,
          "a name in the file list that does not run is a file list that "
          "is not describing this box")

# --- --help is the tool's own help, byte for byte
for n, ln in sorted(HELP_LEN.items()):
    got = r("%s --help" % n)
    check("%s --help is the right length" % n, len(got), ln,
          "measured on the guest's procps-ng 4.0.4")
    check("...and starts with its own usage line" % (),
          got.startswith("\nUsage:\n %s " % n), True,
          "got %r" % got[:48])
    check("...and is not the stock template" % (),
          "[OPTION]... [FILE]..." in got, False,
          "that shape is GNU coreutils'; no procps tool prints it")

# --- -h, which is not the same question
for n in DASH_H_IS_HELP:
    check("%s -h is help" % n, r("%s -h" % n), r("%s --help" % n))
for n in DASH_H_IS_NOT:
    dash_h, dash_help = r("%s -h" % n), r("%s --help" % n)
    check("%s -h is NOT help" % n, dash_h == dash_help, False,
          "free -h is human-readable, ps -h and w -h suppress the header; "
          "sending them to the help text would be this fix overreaching")
    check("...and %s -h still produces output" % n, bool(dash_h.strip()), True)

# --- skill and snice: one binary, two names
sk, sn = r("skill --help"), r("snice --help")
check("skill's usage names a signal",
      "skill [signal] [options] <expression>" in sk, True)
check("snice's names a priority",
      "snice [new priority] [options] <expression>" in sn, True)
check("neither is the other's text", sk == sn, False)
for n in ("skill", "snice"):
    check("bare %s prints its usage and fails" % n, rc_of(n), "1")
    check("...and it is the real usage, not the template",
          "[OPTION]... [FILE]..." in r(n), False)
check("skill takes a signal name as a signal, not an option",
      rc_of("skill -TERM nosuchproc"), "0",
      "-TERM is how skill is normally called; reading it as options would "
      "reject the documented form")
check("...including -SIGKILL and -9",
      (rc_of("skill -SIGKILL nosuchproc"), rc_of("skill -9 nosuchproc")),
      ("0", "0"))
check("an option it really lacks is still an error",
      rc_of("skill -q"), "1")

# --- pidwait: pgrep's twin, measured
check("pidwait with no criteria says so",
      r("pidwait").splitlines()[0],
      "pidwait: no matching criteria specified")
check("...and exits 2, where snice exits 1",
      (rc_of("pidwait"), rc_of("snice --zzz")), ("2", "1"),
      "the two halves of procps disagree about this on the real box too")
check("an unknown long option is unrecognized",
      r("pidwait --zzz").splitlines()[0],
      "pidwait: unrecognized option '--zzz'")
check("an unknown short option is invalid",
      r("pidwait -q").splitlines()[0], "pidwait: invalid option -- 'q'")
check("both exit 2", (rc_of("pidwait --zzz"), rc_of("pidwait -q")),
      ("2", "2"))
# comm is 15 bytes, so procps warns rather than quietly finding nothing
long_pat = "nosuchprocessxyz"
check("a pattern longer than comm is warned about",
      r("pidwait %s" % long_pat).splitlines()[0],
      "pidwait: pattern that searches for process name longer than 15 "
      "characters will result in zero matches",
      "%d characters, and comm holds 15" % len(long_pat))
check("...and it says which flag to use instead",
      "Try `pidwait -f' option to match against the complete command line."
      in r("pidwait %s" % long_pat), True)
check("no match exits 1", rc_of("pidwait zzzq"), "1")
check("-c still prints the count on no match", r("pidwait -c zzzq"), "0\n",
      "same as pgrep -c: only the status says nothing matched, so a script "
      "doing n=$(pidwait -c x) gets a number")

# --- pgrep and pidwait are the same matcher, so they cannot disagree
for pat in ("nginx", "sshd", "zzzq"):
    check("pgrep and pidwait agree about %r" % pat,
          rc_of("pgrep -c %s" % pat), rc_of("pidwait -c %s" % pat),
          "pidwait is pgrep's source with another argv[0]; a different "
          "answer here would mean two matchers")

# --- slabtop, which had no implementation at all
#
# Every invocation fell through to the stock `slabtop 4.0.4` plus the
# coreutils usage template -- a shape no procps tool prints. Measured on
# the guest as root with stdout on a pipe: a bare slabtop answers
# "Error opening terminal: unknown." and exits 1, byte for byte what htop
# answers, because both are ncurses programs and ncurses reads TERM from
# the environment rather than asking isatty.
#
# The first version of this refused unconditionally, which would have had
# two ncurses programs on one box disagreeing about the same channel --
# htop painting while slabtop refused. It keys on the same condition htop
# does now.
check("slabtop refuses when there is no TERM, exactly as htop does",
      r("env -u TERM slabtop"), r("env -u TERM htop"),
      "both are ncurses; one refusing while the other paints is two "
      "answers to one question about the same channel")
check("...with the terminal error", r("env -u TERM slabtop"),
      "Error opening terminal: unknown.\n")
check("...and exit 1", rc_of("env -u TERM slabtop"), "1")
check("slabtop -V still answers", r("slabtop -V").strip(),
      "slabtop from procps-ng 4.0.4")
check("slabtop --help is still its own help", len(r("slabtop --help")), 682)

# Not fixed, and not claimed to be: with a terminal, and for -o, slabtop
# reads /proc/slabinfo, and this box has none. The guest's cannot be
# copied -- its slab counts describe a 2GB two-core VM against this
# persona's 1TB and sixty-four cores, which makes it synthesis rather than
# measurement. Asserted here only so the gap stays visible.
check("slabtop -o is still the unimplemented answer",
      r("slabtop -o").startswith("slabtop 4.0.4"), True,
      "it needs /proc/slabinfo, which this box does not have at all")
check("...and /proc/slabinfo is indeed absent",
      "No such file" in r("cat /proc/slabinfo"), True,
      "a real Linux always has it, root-only -- that is the deeper gap")

for f in FAILS:
    print(" ", f)
print("   procps: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
