#!/usr/bin/env python3
"""`--help` outside coreutils -- the interpreters and the downloaders.

cuhelptest covers the 96 coreutils programs. These are the 29 an
attacker's script actually reaches for, and every one of them answered
with nothing:

    python3 --help    (empty)     guest: 2548 bytes
    perl --help       (empty)     guest: 2126
    awk --help        (empty)     guest: 1187, and it identifies as mawk
    xargs --help      (empty)     guest: 3121
    wget --help       (empty)     guest: 13331
    curl --help       45 bytes    guest: 1139

curl and wget are the two commands every loader runs before it decides how
to fetch its payload, so those two matter more than the rest put together.

## Why the table stores three things per program

For five of these, --help is not a help request and the honest answer is
an error:

    which        rc 2, and it splits: a usage line on stdout, "Illegal
                 option --" on stderr
    reset, tset  rc 1, entirely on stderr
    ssh-keyscan  rc 1, "unknown option -- -" on stderr
    pidof        rc 1, and nothing on either stream -- so the empty output
                 we already had was right, and is pinned here so it stays
                 right for the right reason

Streams are checked separately, not through 2>&1. A help text on the wrong
stream is invisible until someone runs `cmd --help 2>/dev/null`, and then
it is very visible.

## The path in zcat's usage is not a bug

`zcat --help` says "Usage: /usr/bin/zcat [OPTION]..." and gunzip likewise.
cuhelp.py warns about exactly this shape, because collecting coreutils
help by running a resolved path made every usage line name /usr/bin. These
two are different: both are /bin/sh scripts that interpolate $0, and $0 is
the resolved path when bash finds them on PATH. Someone typing
`zcat --help` sees this. It is pinned below so it does not get "fixed".

Usage:  python3 helpdbtest.py
"""

import sys

import fakeshell
import helpdb

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13", peer_port=45300)
sh.exec_mode = True


def out_of(cmd):
    return sh.run(cmd + " 2>/dev/null")


def err_of(cmd):
    return sh.run(cmd + " 2>&1 >/dev/null")


def rc_of(cmd):
    return (sh.run(cmd + " >/dev/null 2>&1; echo $?") or "").strip()


def first(text):
    """First line, or "" -- never an IndexError.

    An earlier draft indexed the first line directly and raised against
    a tree where these commands print nothing -- which is precisely the
    tree this file exists to fail against. One raising check takes every check
    below it with it, so the suite reported nothing instead of reporting
    the gap.
    """
    return (text.splitlines() or [""])[0]


check("the table is not empty", len(helpdb.HELP) >= 29, True)

# --- every entry, on the stream it belongs on, with its own status
for name in sorted(helpdb.HELP):
    want_out, want_err, want_rc = helpdb.HELP[name]
    check("%s --help stdout" % name, out_of("%s --help" % name), want_out)
    check("%s --help stderr" % name, err_of("%s --help" % name), want_err)
    check("%s --help exits %d" % (name, want_rc),
          rc_of("%s --help" % name), str(want_rc))

# --- the two a loader runs first
check("curl --help is curl's own usage",
      first(out_of("curl --help")), "Usage: curl [options...] <url>")
check("wget --help is wget's own banner",
      out_of("wget --help").startswith("GNU Wget 1.25.0,"), True)
check("...and neither is on stderr",
      (err_of("curl --help"), err_of("wget --help")), ("", ""),
      "a help text on stderr disappears under 2>/dev/null")

# --- awk is mawk and says so
check("awk --help identifies as mawk",
      first(out_of("awk --help")),
      "Usage: mawk [Options] [Program] [file ...]",
      "the alternative points at mawk, so the help has to as well")
for alias in ("mawk", "nawk"):
    check("%s --help is the same text" % alias,
          out_of("%s --help" % alias), out_of("awk --help"))

# --- the five where --help is not help
check("which splits across both streams",
      (out_of("which --help"), err_of("which --help"), rc_of("which --help")),
      ("Usage: /usr/bin/which [-as] args\n", "Illegal option --\n", "2"))
for name in ("reset", "tset", "ssh-keyscan"):
    check("%s --help answers only on stderr" % name,
          (out_of("%s --help" % name) == "", err_of("%s --help" % name) != ""),
          (True, True))
    check("...and %s exits 1" % name, rc_of("%s --help" % name), "1")
check("pidof --help says nothing at all, and fails",
      (out_of("pidof --help"), err_of("pidof --help"), rc_of("pidof --help")),
      ("", "", "1"),
      "the empty output was already right; this pins it as measured "
      "rather than as an accident")

# --- the path in these two is real
for name in ("zcat", "gunzip"):
    check("%s names its own path, as the script does" % name,
          first(out_of("%s --help" % name)),
          "Usage: /usr/bin/%s [OPTION]... [FILE]..." % name,
          "both are /bin/sh scripts interpolating $0; this is not the "
          "argv[0] mistake cuhelp.py warns about")

# --- exact spelling only outside coreutils
check("curl does not take an abbreviation",
      out_of("curl --hel") == out_of("curl --help"), False,
      "coreutils uses getopt_long and accepts unambiguous prefixes; curl, "
      "perl and python3 do not, and answering --hel would be inventing a "
      "behaviour the real one refuses")
check("-- ends option parsing",
      out_of("curl -- --help") == out_of("curl --help"), False)

# --- and the programs still do their jobs
for cmd, want in (("awk '{print $1}' /etc/hostname", "web01\n"),
                  ("python3 -c 'print(7*6)'", "42\n"),
                  ("which ls", "/usr/bin/ls\n"),
                  ("file /etc/hostname", "/etc/hostname: ASCII text\n")):
    check("%s still works" % cmd, sh.run(cmd + " 2>&1"), want,
          "a --help hook that ate ordinary arguments shows up here")
check("xargs --version is still findutils'",
      first(sh.run("xargs --version")), "xargs (GNU findutils) 4.10.0")
check("curl --version is still curl's",
      sh.run("curl --version").startswith("curl 8.14.1 "), True)

# ---------------------------------------------------------------------------
# The stock template, and what is left of it.
#
# `<name> <version>` followed by `Usage: <name> [OPTION]... [FILE]...` is
# GNU coreutils' shape. It was the answer 92 executables on this box gave
# to --help, coreutils members and non-members alike. Twenty-two are left,
# and every one has a reason that is not "nobody got to it":
#
#   nineteen are not on the guest, so there is nothing to measure --
#   apt-key, bzgrep, bzip2recover, cron, ipmaddr, iptunnel, logrotate,
#   lsfd, mariadb-admin, mariadbd, mysqld, nameif, php-fpm8.4, php8.4,
#   plipconfig, rarp, rsyslogd, slattach, sshd-session. Same position
#   netstat's option validation has been in since it was first looked at.
#
#   three were not run there on purpose: killall5 signals every process
#   on the machine, init can change its runlevel, and bashbug wants a
#   mailer and an editor. Measuring is not worth disturbing the one box
#   that is the reference.
#
# The list is named so the count can only fall. A name leaving it means
# someone measured it; a name arriving means a regression.
TEMPLATE_OK = frozenset((
    "apt-key", "bashbug", "bzgrep", "bzip2recover", "cron", "init",
    "ipmaddr", "iptunnel", "killall5", "logrotate", "lsfd",
    "mariadb-admin", "mariadbd", "mysqld", "nameif", "php-fpm8.4",
    "php8.4", "plipconfig", "rarp", "rsyslogd", "slattach",
    "sshd-session"))

_names = set()
for _d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
    _names.update(sh.run("ls %s 2>/dev/null" % _d).split())
_generic = sorted(n for n in _names
                  if "[OPTION]... [FILE]..." in sh.run("%s --help 2>&1" % n)[:220]
                  and len(sh.run("%s --help 2>&1" % n)) < 200)
check("nothing new answers --help with the stock template",
      [n for n in _generic if n not in TEMPLATE_OK], [],
      "a name here has never been measured against the guest")
check("...and the ones that do are only the ones with a reason",
      len(_generic) <= len(TEMPLATE_OK), True,
      "%d generic, ceiling %d: %s" % (len(_generic), len(TEMPLATE_OK), _generic))

# ---------------------------------------------------------------------------
# The tools an attacker actually types. These never showed up on the
# stock-template survey, because they answered --help with something -- it
# just was not their help.
check("journalctl --help is help, not the journal",
      (len(out_of("journalctl --help")), rc_of("journalctl --help")),
      (5213, "0"),
      "it printed 310899 bytes of the journal: a command that dumps the "
      "log when asked how to use it is not one anybody has used")
check("...and the journal is still reachable",
      "web01" in sh.run("journalctl -n1 --no-pager 2>&1"), True)

# A short line on stderr with a non-zero status, for a request that
# succeeds. Nine commands shared this shape.
for _n, _bytes in (("grep", 4042), ("egrep", 4042), ("fgrep", 4042),
                   ("sed", 1838), ("find", 2110), ("tar", 16663),
                   ("dpkg", 4838), ("dmesg", 3375), ("getent", 820),
                   ("umount", 1307), ("unxz", 1500)):
    check("%s --help is on stdout, whole, rc 0" % _n,
          (len(out_of("%s --help" % _n)), err_of("%s --help" % _n),
           rc_of("%s --help" % _n)),
          (_bytes, "", "0"))
check("egrep and fgrep print grep's help exactly",
      (out_of("egrep --help") == out_of("grep --help"),
       out_of("fgrep --help") == out_of("grep --help")), (True, True),
      "they are grep, so their help is grep's")

# And the ones that really do answer on stderr, with their own status.
for _n, _rc in (("ip", "255"), ("lsattr", "1"), ("chattr", "1"),
                ("killall", "1"), ("ssh", "255"), ("ssh-keygen", "1")):
    check("%s --help answers on stderr, rc %s" % (_n, _rc),
          (out_of("%s --help" % _n), bool(err_of("%s --help" % _n)),
           rc_of("%s --help" % _n)),
          ("", True, _rc),
          "ours put this on stdout with rc 0, which is the opposite of "
          "what the real one does")

check("systemctl --help is the whole help",
      len(out_of("systemctl --help")), 12585,
      "it was 3836 bytes -- a partial help is harder to notice than none")

# the commands still do their jobs
for _cmd, _want in (("grep root /etc/passwd", "root:x:0:0:root:/root:/bin/bash"),
                    ("sed -n 1p /etc/hostname", "web01"),
                    ("find /etc/hostname", "/etc/hostname"),
                    ("systemctl is-active ssh", "active")):
    check("%s still works" % _cmd, first(sh.run(_cmd + " 2>&1")), _want)
check("tar --version is still GNU tar",
      first(sh.run("tar --version")), "tar (GNU tar) 1.35")

# ---------------------------------------------------------------------------
# bash builtins. A builtin prints its own help for --help and exits 2, not
# 0 -- which is what made ours look plausible while being wrong:
#
#   printf --help   printed "--help" and exited 0
#   pwd --help      printed the working directory
#   cd --help       "cd: --help: No such file or directory"
#   read --help     nothing, exit 1
#
# Fifty-four are in the table. All fifty-four exit 2.
check("the builtin table is not empty", len(helpdb.BUILTIN) >= 54, True)
check("every builtin help exits 2",
      sorted(set(v[2] for v in helpdb.BUILTIN.values())), [2],
      "the status is the part that is easy to get wrong, because 0 looks "
      "right for a successful help request")
for name in sorted(helpdb.BUILTIN):
    want_out, want_err, want_rc = helpdb.BUILTIN[name]
    check("%s --help stdout" % name, out_of("%s --help" % name), want_out)
    check("%s --help stderr" % name, err_of("%s --help" % name), want_err)
    check("%s --help exits %d" % (name, want_rc),
          rc_of("%s --help" % name), str(want_rc))

# Position is the whole subtlety: --help is a help request only while bash
# is still reading options.
check("cd --help is help", first(out_of("cd --help")),
      "cd: cd [-L|[-P [-e]] [-@]] [dir]")
check("cd --help / is still help", out_of("cd --help /"), out_of("cd --help"),
      "--help comes first, so options are still being read")
check("pwd -L --help is still help", first(out_of("pwd -L --help")),
      "pwd: pwd [-LP]", "an option does not end option parsing")
check("cd / --help is NOT help",
      "cd: cd [-L" in sh.run("cd / --help 2>&1"), False,
      "an operand has been seen, so --help is just another argument; the "
      "real one answers 'cd: too many arguments'")
check("export FOO=1 --help is NOT help",
      "export: export" in sh.run("export FOO=1 --help 2>&1"), False,
      "the real one answers \"`--help': not a valid identifier\"")

# The five that ignore their arguments keep doing so.
for name, want_rc in ((":", "0"), ("test", "0"), ("true", "0"),
                      ("false", "1")):
    check("%s --help says nothing, rc %s" % (name, want_rc),
          (sh.run("%s --help 2>&1" % name), rc_of("%s --help" % name)),
          ("", want_rc))
    check("...and %s is absent from the table" % name,
          name in helpdb.BUILTIN, False)
check("echo --help prints its argument", sh.run("echo --help 2>&1"), "--help\n")
check("echo is absent from the table", "echo" in helpdb.BUILTIN, False)

# Two are left out for stated reasons, not oversight.
for name in ("[", "bind"):
    check("%s is absent from the table" % name, name in helpdb.BUILTIN, False)
check("[ --help ] is still a string test, not an error",
      (sh.run("[ --help ] 2>&1"), rc_of("[ --help ]")), ("", "0"),
      "the table entry for [ is the missing-]' error, so routing this "
      "through it would break a case that is already right")

# and the builtins still do their jobs. Each of these puts the directory
# back: they share one shell, and an earlier draft left it wherever the
# last check had wandered, so a check inserted between them could fail for
# a reason that had nothing to do with what it tested.
check("cd still changes directory",
      sh.run("cd /tmp && pwd; cd /root 2>&1"), "/tmp\n")
check("export still exports",
      sh.run("export ZZQ=7; echo $ZZQ 2>&1"), "7\n")
check("pwd still prints the directory",
      sh.run("cd / && pwd; cd /root 2>&1"), "/\n")
check("...and the directory is back where it started",
      sh.run("pwd 2>&1"), "/root\n")

# The other half, now done: once the help hook declines these, the builtin
# has to answer the way bash does. It used to answer with silence and 0.
check("cd / --help is 'too many arguments'",
      (first(sh.run("cd / --help 2>&1")), rc_of("cd / --help")),
      ("bash: line 1: cd: too many arguments", "1"))
check("...and so is cd with two real operands",
      (first(sh.run("cd / /tmp 2>&1")), rc_of("cd / /tmp")),
      ("bash: line 1: cd: too many arguments", "1"))
check("export FOO=1 --help is an invalid identifier",
      (first(sh.run("export FOO=1 --help 2>&1")), rc_of("export FOO=1 --help")),
      ("bash: line 1: export: `--help': not a valid identifier", "1"),
      "bash does not call it an invalid option: after the option letters "
      "every word is a name")
check("...and so is a name that cannot be one",
      (first(sh.run("export 1bad=2 2>&1")), rc_of("export 1bad=2")),
      ("bash: line 1: export: `1bad=2': not a valid identifier", "1"))
check("a real cd still works and still says nothing",
      (sh.run("cd /etc 2>&1"), rc_of("cd /etc")), ("", "0"))

for f in FAILS:
    print(" ", f)
print("   helpdb: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
