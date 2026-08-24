#!/usr/bin/env python3
"""Do commands *fail* the same way the real ones do?

Every other differential suite compares stdout. None of them compared exit
status, which is the half of a command's output that scripts actually branch
on: `command -v curl || command -v wget` picks a downloader, `grep -q x f &&
...` gates an action, `set -e` aborts. A command that prints the right thing
and returns the wrong code is a silent wrong answer of exactly the kind that
changes what an attacker does next -- and stdout-only tests can never see it.

Real bash and real coreutils on this host are the reference. Only the exit
status is compared; stdout is deliberately ignored, because the other suites
cover it and the interesting failures here are ones where the text is fine.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

# (name, snippet). Snippets run in a fresh temp dir with umask 022 and must
# not touch anything outside it.
CASES = [
    ("true",                    "true"),
    ("false",                   "false"),
    ("exit code passthrough",   "(exit 42)"),
    ("bash -c exit",            "bash -c 'exit 7'"),

    # the classic downloader probe
    ("command -v present",      "command -v ls"),
    ("command -v absent",       "command -v definitelynotacommand"),
    ("command -v chain",        "command -v definitelynot || command -v ls"),
    ("which present",           "which ls"),
    ("which absent",            "which definitelynotacommand"),
    ("type present",            "type ls"),
    ("type absent",             "type definitelynotacommand"),
    ("hash absent",             "hash definitelynotacommand"),

    ("unknown command",         "definitelynotacommand"),
    ("absolute missing path",   "/nonexistent/binary"),
    ("not executable",          "echo hi > f; ./f"),
    ("is a directory",          "mkdir d; ./d"),

    # file tests
    ("test -f present",         "[ -f /etc/passwd ]"),
    ("test -f absent",          "[ -f /nonexistent ]"),
    ("test -d present",         "[ -d /etc ]"),
    ("test -x on a file",       "echo x > f; [ -x f ]"),
    ("test -s empty",           ": > f; [ -s f ]"),
    ("test -s nonempty",        "echo x > f; [ -s f ]"),
    ("test string equal",       "[ a = a ]"),
    ("test string unequal",     "[ a = b ]"),
    ("test numeric",            "[ 1 -eq 2 ]"),
    ("test -z empty",           '[ -z "" ]'),
    ("test -n empty",           '[ -n "" ]'),

    # reading things that are not there
    ("cat missing",             "cat /nonexistent"),
    ("head missing",            "head -1 /nonexistent"),
    ("tail missing",            "tail -1 /nonexistent"),
    ("wc missing",              "wc -l /nonexistent"),
    ("stat missing",            "stat /nonexistent"),
    ("ls missing",              "ls /nonexistent"),
    ("ls present",              "ls /etc/passwd"),
    ("du missing",              "du /nonexistent"),
    ("df missing",              "df /nonexistent"),
    ("file missing",            "file /nonexistent"),
    ("readlink not a link",     "readlink /etc/passwd"),
    ("readlink a link",         "ln -s /etc/passwd l; readlink l"),
    ("cut missing",             "cut -d: -f1 /nonexistent"),
    ("sort missing",            "sort /nonexistent"),
    ("md5sum missing",          "md5sum /nonexistent"),
    ("sha256sum missing",       "sha256sum /nonexistent"),
    ("basename no args",        "basename"),
    ("dirname no args",         "dirname"),

    # grep's three-way exit status, which scripts rely on
    ("grep match",              "echo hello > f; grep hello f"),
    ("grep no match",           "echo hello > f; grep zzz f"),
    ("grep missing file",       "grep hello /nonexistent"),
    ("grep -q match",           "echo hello | grep -q hello"),
    ("grep -q no match",        "echo hello | grep -q zzz"),
    ("grep -c no match",        "echo hello > f; grep -c zzz f"),
    ("grep recursive nothing",  "mkdir d; grep -r zzz d"),

    # writing where you should not be able to
    ("mkdir missing parent",    "mkdir a/b/c"),
    ("mkdir -p",                "mkdir -p a/b/c"),
    ("mkdir existing",          "mkdir d; mkdir d"),
    ("rm missing",              "rm /nonexistent"),
    ("rm -f missing",           "rm -f /nonexistent"),
    ("rmdir non-empty",         "mkdir d; touch d/f; rmdir d"),
    ("cp missing source",       "cp /nonexistent /tmp/x"),
    ("mv missing source",       "mv /nonexistent /tmp/x"),
    ("chmod missing",           "chmod 644 /nonexistent"),
    ("touch in /proc",          "touch /proc/definitelynot"),
    ("cd missing",              "cd /nonexistent"),
    ("redirect into missing dir", "echo x > /nonexistent/dir/f"),

    # pipelines and lists: the status is the last command's
    ("true && echo",            "true && echo yes"),
    ("false && echo",           "false && echo yes"),
    ("false || true",           "false || true"),
    ("false || false",          "false || false"),
    ("true | false",            "true | false"),
    ("false | true",            "false | true"),
    ("pipeline last fails",     "echo x | grep zzz"),
    ("semicolon list",          "false; true"),
    ("subshell failure",        "(false)"),
    ("brace group failure",     "{ false; }"),
    ("negation of false",       "! false"),
    ("negation of true",        "! true"),

    # processes and users
    ("kill nonexistent pid",    "kill -0 999999"),
    ("pgrep absent",            "pgrep definitelynotaprocess"),
    ("pkill absent",            "pkill definitelynotaprocess"),
    ("id absent user",          "id definitelynotauser"),
    ("id present user",         "id root"),
    ("getent absent",           "getent passwd definitelynotauser"),
    ("getent present",          "getent passwd root"),
    ("groups present",          "groups root"),

    # text tools on missing input
    ("awk missing file",        "awk '{print}' /nonexistent"),
    ("sed missing file",        "sed '' /nonexistent"),
    ("tr needs no file",        "echo abc | tr a-z A-Z"),
    ("diff identical",          "echo a > x; echo a > y; diff x y"),
    ("diff differing",          "echo a > x; echo b > y; diff x y"),
    ("cmp identical",           "echo a > x; echo a > y; cmp x y"),
    ("cmp differing",           "echo a > x; echo b > y; cmp x y"),
    ("tar missing archive",     "tar tf /nonexistent.tar"),
    ("gzip missing",            "gzip /nonexistent"),
    ("find missing path",       "find /nonexistent"),
    ("find present path",       "find /etc/passwd"),
    ("xargs false",             "echo x | xargs false"),

    # arithmetic and expr, whose conventions are inverted
    ("expr true",               "expr 1 = 1"),
    ("expr false",              "expr 1 = 2"),
    ("arith nonzero",           "(( 1 ))"),
    ("arith zero",              "(( 0 ))"),
    ("let nonzero",             "let x=1"),
    ("let zero",                "let x=0"),
]


def real_rc(snippet, cwd):
    p = subprocess.run(["bash", "-c", "umask 022\n" + snippet],
                       capture_output=True, cwd=cwd, timeout=20)
    return p.returncode


def ours_rc(snippet):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.cwd = "/tmp"
    sh.run("rm -rf /tmp/w; mkdir -p /tmp/w; cd /tmp/w")
    out = sh.run(snippet + "\nprintf '__RC__%s' \"$?\"")
    marker = out.rsplit("__RC__", 1)
    if len(marker) != 2:
        return None
    try:
        return int(marker[1].strip())
    except ValueError:
        return None


def main():
    verbose = "-v" in sys.argv
    only = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else None
    ok = bad = 0
    for name, snip in CASES:
        if only and only not in name:
            continue
        with tempfile.TemporaryDirectory() as d:
            try:
                want = real_rc(snip, d)
            except (OSError, subprocess.TimeoutExpired):
                continue
        got = ours_rc(snip)
        if got == want:
            ok += 1
            if verbose:
                print("  ok   %-26s rc=%s" % (name, want))
        else:
            bad += 1
            print("  DIFF %-26s %s" % (name, snip[:52]))
            print("       real rc=%s   ours rc=%s" % (want, got))
    print()
    print("=" * 60)
    print("%d/%d match  (%d differ)" % (ok, ok + bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
