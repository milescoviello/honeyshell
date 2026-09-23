#!/usr/bin/env python3
"""`--help` on this box, for the 96 coreutils programs that have one.

Of the 102 names our coreutils claims, exactly one answered --help the way
the guest does. Forty-five printed nothing whatsoever:

    cat --help        (empty)          guest: 1178 bytes
    stat --help       (empty)          guest: 3925
    readlink --help   (empty)          guest: 1423
    sort --help       (empty)
    head --help       (empty)

and the other fifty-six ran, with --help taken as an operand:

    arch --help       "x86_64"
    basename --help   "--help"
    chmod --help      an error about a missing operand

--help is what a person types when a command did not do what they
expected, so a box that runs the command instead is behaving differently
from every other box at the exact moment someone is looking at it.

## Two things this file exists to stop coming back

The first is the argv[0] mistake. The texts were collected by running
`$(command -v cat) --help`, and coreutils prints the name it was invoked
under: every usage line came back as `Usage: /usr/bin/cat [OPTION]...`.
That would have replaced empty output with a worse tell, and it was caught
only by chasing a 27-byte disagreement between two measurements of the
same command rather than assuming the smaller one was a stripped newline.
So the shape of the usage line is checked here, not just its bytes.

The second is the builtins. `echo --help` in a shell prints "--help",
because the builtin shadows /usr/bin/echo; `true --help` prints nothing
and exits 0; `false --help` nothing and exits 1. Six coreutils names are
builtins here and are deliberately absent from the table -- routing them
through it would be a new mistake in place of the old one.

Usage:  python3 cuhelptest.py
"""

import re
import sys

import cuhelp
import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.12", peer_port=45200)
sh.exec_mode = True


def r(cmd):
    try:
        return sh.run(cmd + " 2>&1")
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def rc_of(cmd):
    return (sh.run(cmd + " >/dev/null 2>&1; echo $?") or "").strip()


def line0(text):
    """First line, or "" -- never an IndexError.

    Named line0 rather than first because a loop variable called `first`
    already exists below and shadowed it, which is its own small lesson
    about helpers in a linear script.
    """
    return (text.splitlines() or [""])[0]


check("the table is not empty", len(cuhelp.HELP) >= 96, True,
      "96 names were measured; a table that shrank means data was lost")

# --- the wiring: what the shell prints is what was measured
for name in sorted(cuhelp.HELP):
    check("%s --help is its measured text" % name,
          r("%s --help" % name), cuhelp.HELP[name])

# --- the shape of it, which is what the argv[0] bug broke
for name, text in sorted(cuhelp.HELP.items()):
    first = text.split("\n", 1)[0]
    # coreutils writes either "Usage: <name> ..." or, for a few, several
    # usage lines; every one of them names the program by its bare name.
    check("%s names itself in its usage line" % name,
          first.startswith("Usage: %s" % name)
          or first.startswith("Usage: %s," % name), True,
          "got %r -- a path here means the text was collected by running "
          "the resolved binary rather than the bare name" % first[:60])
    check("...and %s's usage line carries no path" % name,
          "Usage: /" in text, False)

# --- a lone -- ends option parsing, so --help after it is a filename
check("cat -- --help does not print help",
      "Usage: cat" in r("cat -- --help"), False,
      "GNU parses options anywhere in argv, but -- terminates that")
check("...while cat <file> --help still does",
      r("cat /etc/hostname --help"), cuhelp.HELP["cat"],
      "options are parsed anywhere, so this is help and not a file read")

# --- the builtins keep their own behaviour
for name in ("echo", "false", "printf", "pwd", "test", "true"):
    check("%s is absent from the table" % name, name in cuhelp.HELP, False,
          "it is a bash builtin here, and the builtin shadows the binary")
check("echo --help prints its argument", r("echo --help"), "--help\n")
check("true --help says nothing, successfully",
      (r("true --help"), rc_of("true --help")), ("", "0"))
check("false --help says nothing, unsuccessfully",
      (r("false --help"), rc_of("false --help")), ("", "1"))

# --- --version was already right and has to stay right
check("cat --version still answers",
      r("cat --version").splitlines()[0], "cat (GNU coreutils) 9.7")
check("...and --help did not swallow it",
      "Usage:" in r("cat --version"), False)

# --- and the programs still do their jobs
for cmd, want in (("cat /etc/hostname", "web01\n"),
                  ("head -1 /etc/hostname", "web01\n"),
                  ("sort /etc/hostname", "web01\n"),
                  ("wc -c /etc/hostname", "6 /etc/hostname\n"),
                  ("base64 /etc/hostname", "d2ViMDEK\n"),
                  ("stat -c %s /etc/hostname", "6\n"),
                  ("readlink /bin", "usr/bin\n")):
    check("%s still works" % cmd, r(cmd), want,
          "a --help hook that ate ordinary arguments would show up here")

# --- help must reach every name the package claims, or be absent for a
#     reason. This is the check that notices a name added to the package
#     file list and never measured.
claimed = set(fakeshell.Shell._PKG_FILES.get("coreutils", ()))
builtins = set(fakeshell.Shell._BUILTINS)
missing = sorted(claimed - set(cuhelp.HELP) - builtins - {"chroot"})
check("every coreutils name has measured help, or a stated reason",
      missing, [],
      "chroot is not on the guest's PATH to measure and the six builtins "
      "are shadowed; anything else here is a name nobody measured")

# ---------------------------------------------------------------------------
# The other half: an option the program does not have is an error.
#
# 77 of 103 accepted anything at all -- `cat --zzzq` exited 0 and printed
# nothing, where the real one exits 1 and says so. Measured across all 102
# on the guest: 85 exit 1, six exit 2 (ls, dir, vdir, sort, printenv, tty)
# and six exit 125 (env, nice, nohup, runcon, stdbuf, timeout -- the exec
# wrappers, which keep their own codes for "could not run the command").
for _cmd, _rc in (("cat", "1"), ("stat", "1"), ("head", "1"), ("wc", "1"),
                  ("du", "1"), ("ls", "2"), ("sort", "2"), ("dir", "2"),
                  ("vdir", "2"), ("printenv", "2"), ("tty", "2"),
                  ("env", "125"), ("nice", "125"), ("nohup", "125"),
                  ("timeout", "125"), ("stdbuf", "125"), ("runcon", "125")):
    _out = r("%s --zzzq" % _cmd)
    check("%s rejects an option it does not have" % _cmd,
          _out.splitlines()[:2] if _out else [],
          ["%s: unrecognized option '--zzzq'" % _cmd,
           "Try '%s --help' for more information." % _cmd])
    check("...and %s exits %s" % (_cmd, _rc), rc_of("%s --zzzq" % _cmd), _rc,
          "measured per command; they are not all 1")

# --- short clusters, which is the half that could break working commands
#
# `cat --zzz` was the easy half. A short cluster carries three traps, and
# each of these is a form the real thing accepts:
#   head -2, tail -2, uniq -1, split -2   the legacy count
#   tail -n+3                             a value that starts with +
#   head -c3, cut -d,, sort -k1,1, fold -w2   the value inside the cluster
# Rejecting any of those to catch `cat -zq` would be a worse trade than
# leaving `cat -zq` alone, so the validator stops at the first letter that
# takes a value and never refuses a cluster of digits.
r("printf 'a\nb\nc\nd\ne\n' > /tmp/five.txt")
for _cmd, _want in (("head -2 /tmp/five.txt", "a\nb\n"),
                    ("tail -2 /tmp/five.txt", "d\ne\n"),
                    ("head -n2 /tmp/five.txt", "a\nb\n"),
                    ("tail -n+3 /tmp/five.txt", "c\nd\ne\n"),
                    ("uniq -1 /tmp/five.txt", "a\n"),
                    ("head -c3 /tmp/five.txt", "a\nb"),
                    ("fold -w2 /tmp/five.txt", "a\nb\nc\nd\ne\n"),
                    ("sort -ru /tmp/five.txt", "e\nd\nc\nb\na\n")):
    check("%s still works" % _cmd, r(_cmd), _want,
          "a short-cluster validator that refuses this is worse than none")
check("wc -lwc reads as three flags",
      r("wc -lwc /tmp/five.txt").split()[:3], ["5", "5", "10"])
check("cut -d, -f1 keeps its delimiter",
      r("cut -d, -f1 /tmp/five.txt"), "a\nb\nc\nd\ne\n")

# and an unknown letter is an error, naming the first one
for _cmd, _ch, _rc in (("cat -zq /tmp/five.txt", "z", "1"),
                       ("wc -Z /tmp/five.txt", "Z", "1"),
                       ("head -Q /tmp/five.txt", "Q", "1")):
    check("%s names the letter" % _cmd,
          line0(r(_cmd)), "%s: invalid option -- '%s'"
          % (_cmd.split()[0], _ch))
    check("...and exits %s" % _rc, rc_of(_cmd), _rc)
check("a digit cluster is never refused",
      "invalid option" in r("cat -2 /tmp/five.txt"), False,
      "cat -2 is an error on a real box and is let through here: the "
      "direction that cannot break head -2 or tail -2")

# ls -T, found by sweeping every documented short option against the box
check("ls -T1 is as valid as ls -T 1",
      ("invalid option" in r("ls -T1 /tmp/five.txt"),
       "invalid option" in r("ls -T 1 /tmp/five.txt")), (False, False),
      "T is not in the accepted flag string because -T takes a value, and "
      "only the separate-argument form was ever handled")
check("ls -T with a non-number stops",
      (line0(r("ls -T /tmp/five.txt")), rc_of("ls -T /tmp/five.txt")),
      ("ls: invalid tab size: \u2018/tmp/five.txt\u2019", "2"),
      "it used to eat the operand as the tab size and list the current "
      "directory instead")
check("...and says which value, inline too",
      line0(r("ls -Tx /tmp/five.txt")),
      "ls: invalid tab size: \u2018x\u2019")
check("ls -Isw2 keeps working", "invalid option" in r("ls -Isw2 /tmp/five.txt"),
      False)

# `stat -t` raised. Found by sweeping every documented short option, which
# is worth more than the option check it was written for: the terse form
# threw TypeError rather than answering, because info["f"] is already the
# hex string %f prints and the line formatted it with %x. A command that
# raises does not fail politely -- it takes the rest of the pipeline with
# it.
#
# The field list was one short as well. coreutils prints sixteen: name,
# size, blocks, rawmode, uid, gid, device, inode, links, major, minor,
# then FOUR timestamps -- atime mtime ctime btime -- then the block size.
# Ours had three, with ctime missing. Measured on the guest:
#   sw.txt 4 8 81b4 1001 1001 20 898979 1 0 0 <a> <m> <c> <b> 4096
r("printf 'a\nb\n' > /tmp/st.txt")
_t = r("stat -t /tmp/st.txt")
check("stat -t answers instead of raising",
      "<raised" in _t or "Traceback" in _t, False, _t[:80])
_f = _t.split()
check("...with sixteen fields", len(_f), 16,
      "eleven, four timestamps and the block size: %r" % (_f,))
check("...the fourth being the raw mode in hex, not a crash",
      _f[3] if len(_f) > 3 else "", r("stat -c %f /tmp/st.txt").strip())
check("...the seventh the device in hex",
      _f[6] if len(_f) > 6 else "",
      "%x" % int(r("stat -c %d /tmp/st.txt").strip() or 0))
check("...and the last the block size", _f[-1] if _f else "", "4096")
check("...with four distinct timestamp slots",
      len([x for x in _f[11:15] if x.isdigit()]) if len(_f) >= 15 else 0, 4)

# The guard that matters: nothing coreutils documents may be refused.
def _documented_shorts(text):
    out = []
    for m in re.finditer(r"^\s+-([A-Za-z0-9])(?:,\s*--([a-z0-9-]+)(=?))?",
                         text, re.M):
        out.append((m.group(1), m.group(3) == "="))
    return out


r("printf 'a\nb\n' > /tmp/sw.txt")
_short_bad = []
for _n in sorted(cuhelp.HELP):
    for _ch, _takes in _documented_shorts(cuhelp.HELP[_n]):
        if "invalid option" in r("%s -%s%s /tmp/sw.txt"
                                 % (_n, _ch, "1" if _takes else "")):
            _short_bad.append("%s -%s" % (_n, _ch))
check("no documented short option is refused", _short_bad, [],
      "swept across every coreutils program: %s" % _short_bad[:6])
# A value is appended only where the help says the option takes one.
# Appending one to a plain flag builds an invalid cluster -- `b2sum -b1`
# is -b followed by -1, and a real b2sum refuses it too -- so a sweep that
# did that would be asserting the opposite of the truth for 260 options.

# GNU takes any unambiguous abbreviation, so a strict membership test would
# have broken working commands. These three are real forms.
check("head --li=1 is --lines", r("head --li=1 /etc/hostname"), "web01\n",
      "an abbreviation carrying its value")
check("sort --uniq is --unique", r("sort --uniq /etc/hostname"), "web01\n")

# and an ambiguous one names the possibilities, in the order the help lists
# them -- not alphabetically
check("an ambiguous abbreviation lists its possibilities",
      r("cat --numb /etc/hostname").splitlines()[:2],
      ["cat: option '--numb' is ambiguous; possibilities: "
       "'--number-nonblank' '--number'",
       "Try 'cat --help' for more information."],
      "help-text order: -b --number-nonblank is listed above -n --number")
check("...and ls names all three",
      r("ls --a").splitlines()[0],
      "ls: option '--a' is ambiguous; possibilities: '--all' '--almost-all' "
      "'--author'")

# getopt reads argv in order, so which of the two comes first decides
check("cat --help --zzzq prints help", r("cat --help --zzzq"), cuhelp.HELP["cat"])
check("cat --zzzq --help complains",
      r("cat --zzzq --help").splitlines()[0],
      "cat: unrecognized option '--zzzq'",
      "a scan that just asked whether --help was anywhere in argv got this "
      "one backwards")
check("-- ends option parsing",
      "unrecognized" in r("cat -- --zzzq"), False)

# expr is left alone: it takes its arguments as data
# The hook resolves an abbreviation and passes it through; whether the
# command then understands it is the command's own parser. `ls --color` and
# `ls --color=never` both work, `ls --colo=never` does not -- cmd_ls does no
# abbreviating. Same family as the 54 below.
check("ls --color and --color=never both work",
      ("unrecognized" in r("ls --color /etc/hostname"),
       "unrecognized" in r("ls --color=never /etc/hostname")), (False, False))

check("expr --help is still help, not an expression",
      r("expr --help"), cuhelp.HELP["expr"],
      "expr was briefly exempted from the hook wholesale, which made this "
      "evaluate --help and print -1")
check("expr does not reject its own argument",
      "unrecognized" in r("expr --zzzq"), False,
      "the other four that take arguments as data -- echo, printf, test, "
      "true -- are builtins and never reach the hook")
# expr's one-operand case, which used to go through arith_eval: `expr foo`
# printed 0 and exited 1, and `expr --zzzq` printed -1 -- a leading minus
# that reads exactly like an option being parsed, which is the one thing
# expr does not do.
check("expr with one operand prints it", r("expr --zzzq"), "--zzzq\n")
check("...and exits 0, because it is neither null nor zero",
      rc_of("expr --zzzq"), "0")
check("...the same for an ordinary word", (r("expr foo"), rc_of("expr foo")),
      ("foo\n", "0"))
check("...and a zero is still false", (r("expr 0"), rc_of("expr 0")),
      ("0\n", "1"))
check("an expression ending on an operator is a syntax error",
      (r("expr 1 +").strip(), rc_of("expr 1 +")),
      ("expr: syntax error: missing argument after \u2018+\u2019", "2"),
      "coreutils quotes the operator with curly quotes")
check("expr still computes", r("expr 1 + 2"), "3\n")
check("...and still compares", r("expr 1 = 1"), "1\n")

# Known gap, pinned so it can only shrink. It was 54: every long option
# ls, dir and vdir document but did not take, plus chmod's three. Those
# were the long spellings of flags ls already implemented -- `ls -k`
# worked and `ls --kibibytes` did not -- so mapping them fixed 45 at once,
# and it exposed that `-B` was refused too, from the other direction.
#
# It is zero now. The last nine were the three that change the shape of
# the output rather than the spelling of a flag, across ls/dir/vdir, and
# each is measured on the guest:
#   --author     an extra column after the group -- and after the owner
#                when -G dropped the group. Measured on /etc/shadow, where
#                owner and group differ: "root shadow root".
#   --zero       NUL after every record, including a -l block's "total"
#                line. A terminator, not a separator: the last name gets
#                one and there is no trailing newline.
#   --hyperlink  OSC 8 around every name, with the RESOLVED path -- a
#                symlink links to its target. Bare means "always"; "auto"
#                prints the plain name off a terminal, which an exec
#                channel is not.
def _documented_longs(text):
    """The long options a help text lists, in the order it lists them.

    Parsed here rather than borrowed from the Shell, so this file measures
    the behaviour and not the implementation -- and so it still runs
    against a tree that has no such helper.
    """
    seen = []
    for m in re.finditer(r"--([a-z0-9][a-z0-9-]*)", text):
        if m.group(1) not in seen:
            seen.append(m.group(1))
    return seen


_rejected = []
for _n in sorted(cuhelp.HELP):
    for _o in _documented_longs(cuhelp.HELP[_n]):
        _out = r("%s --%s" % (_n, _o))
        if "unrecognized option" in _out or "is ambiguous" in _out:
            _rejected.append("%s --%s" % (_n, _o))
check("no documented option is refused at all", _rejected, [],
      "the ceiling was 54, then 9, and is 0: every long option coreutils "
      "documents is taken. Anything here is a regression")

# --- the three that changed the output, each against the guest
r("rm -rf /tmp/at; mkdir -p /tmp/at; touch /tmp/at/f1; mkdir /tmp/at/d1; "
  "ln -sf f1 /tmp/at/l1")
check("--author adds a column after the group",
      line0(r("ls -l --author /tmp/at/f1")).split()[:5],
      ["-rw-r--r--", "1", "root", "root", "root"],
      "three names where -l alone prints two")
check("...and the flag adds exactly one column",
      len(line0(r("ls -l --author /tmp/at/f1")).split())
      - len(line0(r("ls -l /tmp/at/f1")).split()), 1,
      "counting the columns rather than naming a total: the date is "
      "three whitespace-separated fields, which an earlier draft of this "
      "check got wrong")
check("...and follows the owner when -G drops the group",
      line0(r("ls -l --author -G /tmp/at/f1")).split()[:4],
      ["-rw-r--r--", "1", "root", "root"])
check("--author alone changes nothing visible",
      r("cd /tmp/at && ls --author"), r("cd /tmp/at && ls"))

check("--zero terminates every name with NUL",
      r("cd /tmp/at && ls --zero"), "d1\0f1\0l1\0",
      "a terminator, so the last name has one and there is no newline")
check("...including a -l block's total line",
      r("cd /tmp/at && ls -l --zero").startswith("total 4\0"), True)
check("...and no newline survives",
      "\n" in r("cd /tmp/at && ls --zero"), False)

_h = r("ls --hyperlink /tmp/at/f1").rstrip("\n")
check("--hyperlink wraps the name in OSC 8",
      _h, "\x1b]8;;file://web01/tmp/at/f1\x07/tmp/at/f1\x1b]8;;\x07")
check("...bare means always",
      _h, r("ls --hyperlink=always /tmp/at/f1").rstrip("\n"))
check("...=auto is plain off a terminal",
      r("ls --hyperlink=auto /tmp/at/f1"), r("ls /tmp/at/f1"),
      "an exec channel has no tty, so auto is off")
check("...=never is plain", r("ls --hyperlink=never /tmp/at/f1"),
      r("ls /tmp/at/f1"))
check("...and a symlink links to what it points at",
      "file://web01/tmp/at/f1\x07/tmp/at/l1" in r("ls --hyperlink /tmp/at/l1"),
      True, "the URL is the resolved path, not the link's own")
check("...and -l wraps the name column",
      line0(r("ls -l --hyperlink /tmp/at/f1")).endswith(
          "\x1b]8;;file://web01/tmp/at/f1\x07/tmp/at/f1\x1b]8;;\x07"), True)

# the long spellings, against the short ones they are
for _short, _long in (("-b", "--escape"), ("-B", "--ignore-backups"),
                      ("-D", "--dired"), ("-H", "--dereference-command-line"),
                      ("-k", "--kibibytes"), ("-L", "--dereference"),
                      ("-q", "--hide-control-chars"), ("-Q", "--quote-name"),
                      ("-Z", "--context")):
    # -p and --file-type are deliberately NOT in this list. An earlier
    # draft paired them, because both were refused and both map onto the
    # same machinery -- and the pairing only failed once the machinery
    # started working and marked symlinks for one and not the other. They
    # are compared separately below, as the different options they are.
    check("ls %s and ls %s are one option" % (_short, _long),
          r("ls %s /etc" % _short), r("ls %s /etc" % _long),
          "one option with two spellings cannot have two answers")
check("ls -B is accepted at all", "invalid option" in r("ls -B /etc"), False,
      "B was missing from the accepted flag string, which only showed up "
      "once --ignore-backups started working")
r("touch /tmp/keepme.txt /tmp/dropme.txt~")
check("-B drops what it says it drops",
      "dropme.txt~" in r("ls -B /tmp"), False,
      "accepting the flag and then listing the backups anyway would be a "
      "wrong answer rather than a refused one")
check("...and a plain ls still shows them",
      "dropme.txt~" in r("ls /tmp"), True)
# -p was accepted and did nothing, so `ls -p` and a plain ls were the same
# listing and --indicator-style=slash -- which is -p by another name --
# marked nothing either. The three indicator flags differ only in how far
# they go, measured on the guest against a file, an executable and a
# symlink:
#     -p            exe  lnk   plain      directories only
#     --file-type   exe  lnk@  plain      everything but the star
#     -F            exe* lnk@  plain      the star too
r("rm -rf /tmp/itest; mkdir -p /tmp/itest; touch /tmp/itest/plain; "
  "cp /bin/true /tmp/itest/exe; chmod 755 /tmp/itest/exe; "
  "ln -sf plain /tmp/itest/lnk")
check("-p marks a directory",
      line0(r("ls -p /etc")), "alternatives/")
check("...and --indicator-style=slash is the same option",
      r("ls --indicator-style=slash /etc"), r("ls -p /etc"))
check("...and --indicator-style=none marks nothing",
      line0(r("ls --indicator-style=none /etc")), "alternatives")
check("-p leaves an executable and a symlink alone",
      (r("ls -p /tmp/itest/exe").strip(), r("ls -p /tmp/itest/lnk").strip()),
      ("/tmp/itest/exe", "/tmp/itest/lnk"))
check("-F stars the executable and marks the symlink",
      (r("ls -F /tmp/itest/exe").strip(), r("ls -F /tmp/itest/lnk").strip()),
      ("/tmp/itest/exe*", "/tmp/itest/lnk@"))
check("--file-type marks the symlink but not the executable",
      (r("ls --file-type /tmp/itest/exe").strip(),
       r("ls --file-type /tmp/itest/lnk").strip()),
      ("/tmp/itest/exe", "/tmp/itest/lnk@"),
      "the one indicator that needs to read the mode is the one "
      "--file-type omits")
check("--indicator-style=file-type is --file-type",
      r("ls --indicator-style=file-type /tmp/itest/lnk"),
      r("ls --file-type /tmp/itest/lnk"))
check("--tabsize takes its value either way",
      ("unrecognized" in r("ls --tabsize=4 /etc/hostname"),
       "unrecognized" in r("ls --tabsize 4 /etc/hostname")), (False, False))

# chmod --reference is the one a script actually reaches for
r("touch /tmp/cref /tmp/ctgt; chmod 640 /tmp/cref; chmod 600 /tmp/ctgt")
check("chmod --reference copies the mode",
      (r("chmod --reference=/tmp/cref /tmp/ctgt"),
       r("stat -c %a /tmp/ctgt")), ("", "640\n"))
check("...and says so when the reference is missing",
      (line0(r("chmod --reference=/tmp/nosuchref /tmp/ctgt")),
       rc_of("chmod --reference=/tmp/nosuchref /tmp/ctgt")),
      ("chmod: cannot stat '/tmp/nosuchref': No such file or directory", "1"))
for _o in ("--dereference", "--no-dereference"):
    check("chmod %s is accepted" % _o,
          "unrecognized" in r("chmod %s 644 /tmp/ctgt" % _o), False)
# -v and -c were accepted and silent. Measured on the guest, including
# the no-change wording, which is a different sentence rather than a
# suppressed one -- and -c prints nothing at all when nothing changed,
# which is the only thing separating it from -v.
r("rm -f /tmp/cv.txt; touch /tmp/cv.txt; chmod 644 /tmp/cv.txt")
check("chmod -v names the file and both modes",
      r("chmod -v 755 /tmp/cv.txt").strip(),
      "mode of '/tmp/cv.txt' changed from 0644 (rw-r--r--) to 0755 "
      "(rwxr-xr-x)")
check("...and says so when nothing changed",
      r("chmod -v 755 /tmp/cv.txt").strip(),
      "mode of '/tmp/cv.txt' retained as 0755 (rwxr-xr-x)")
check("chmod -c is silent when nothing changed",
      r("chmod -c 755 /tmp/cv.txt"), "",
      "that is the whole difference between -c and -v")
check("...and reports when something does",
      r("chmod -c 700 /tmp/cv.txt").strip(),
      "mode of '/tmp/cv.txt' changed from 0755 (rwxr-xr-x) to 0700 "
      "(rwx------)")
check("a symbolic mode reports too",
      r("chmod -v u+x /tmp/cv.txt").strip(),
      "mode of '/tmp/cv.txt' retained as 0700 (rwx------)")
check("and a plain chmod still says nothing",
      r("chmod 644 /tmp/cv.txt"), "")

check("chmod with no operand goes to stderr, with both lines",
      (sh.run("chmod 2>/dev/null"), r("chmod").splitlines()[:2],
       rc_of("chmod")),
      ("", ["chmod: missing operand",
            "Try 'chmod --help' for more information."], "1"),
      "it used to return the first line on stdout, so `chmod 2>/dev/null` "
      "still printed it and the second line was missing")

for f in FAILS:
    print(" ", f)
print("   cuhelp: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
