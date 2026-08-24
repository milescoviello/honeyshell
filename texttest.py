#!/usr/bin/env python3
"""Diff the text-processing tools against real bash, deeply.

difftest4 already covers ~90 coreutils commands, but at the level of "does
`wc -l` work". This suite goes after *flags and syntax*, which is where the
silent-wrong-answer bugs live: on 2026-08-20 an actor got 562 bytes of lscpu
from an awk one-liner because the old awk printed $0 for any program it could
not parse. Running this sweep the same day found 33 more of the same shape --
`head -n2` returning every line, `sed -i` appending instead of replacing,
`xargs -n1` returning nothing, and here-doc bodies losing their variables.

Every case is a complete shell snippet, run through real bash in a scratch
directory and through the emulator, and compared on stdout. Run it from
`honeypot/`, or on the guest -- the guest's coreutils are the ones the persona
claims, so that is the reference that counts.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402


CASES = [
 # sed -- the big one
 ("sed s basic",        "echo aaa | sed 's/a/b/'"),
 ("sed s global",       "echo aaa | sed 's/a/b/g'"),
 ("sed s nth",          "echo aaa | sed 's/a/b/2'"),
 ("sed s ampersand",    "echo abc | sed 's/b/[&]/'"),
 ("sed s backref",      "echo abc | sed -E 's/(a)(b)/\\2\\1/'"),
 ("sed s case insens",  "echo ABC | sed 's/abc/x/I'"),
 ("sed alt delim",      "echo /usr/bin | sed 's|/usr|/opt|'"),
 ("sed delete line",    "printf 'a\\nb\\nc\\n' | sed '2d'"),
 ("sed delete pattern", "printf 'a\\nb\\nc\\n' | sed '/b/d'"),
 ("sed print -n",       "printf 'a\\nb\\nc\\n' | sed -n '2p'"),
 ("sed print range",    "printf 'a\\nb\\nc\\nd\\n' | sed -n '2,3p'"),
 ("sed last line",      "printf 'a\\nb\\nc\\n' | sed -n '$p'"),
 ("sed append",         "printf 'a\\nb\\n' | sed '1a inserted'"),
 ("sed insert",         "printf 'a\\nb\\n' | sed '1i inserted'"),
 ("sed change",         "printf 'a\\nb\\n' | sed '1c changed'"),
 ("sed quit",           "printf 'a\\nb\\nc\\n' | sed '2q'"),
 ("sed multiple -e",    "echo abc | sed -e 's/a/1/' -e 's/c/3/'"),
 ("sed semicolon",      "echo abc | sed 's/a/1/;s/c/3/'"),
 ("sed in place",       "printf 'a\\nb\\n' > f1; sed -i 's/a/X/' f1; cat f1"),
 ("sed y transliterate","echo abc | sed 'y/abc/xyz/'"),
 ("sed neg pattern",    "printf 'a\\nb\\nc\\n' | sed -n '/b/!p'"),
 ("sed anchors",        "printf 'ab\\nba\\n' | sed 's/^a/X/'"),
 ("sed char class",     "echo a1b2 | sed 's/[0-9]//g'"),
 ("sed posix class",    "echo 'a 1' | sed 's/[[:digit:]]/D/'"),
 ("sed star",           "echo aaab | sed 's/a*/X/'"),
 ("sed plus ere",       "echo aaab | sed -E 's/a+/X/'"),
 ("sed group basic",    "echo ab | sed 's/\\(a\\)b/\\1/'"),
 ("sed empty match g",  "echo abc | sed 's/x*/-/g'"),
 # sed, harder
 ("sed hold space",     "printf 'a\\nb\\n' | sed -n '1h;2{G;p}'"),
 ("sed exchange",       "printf 'a\\nb\\n' | sed -n 'x;$!d;p'"),
 ("sed N join",         "printf 'a\\nb\\n' | sed 'N;s/\\n/-/'"),
 ("sed branch loop",    "echo aaa | sed ':x;s/a/b/;tx'"),
 ("sed range regex",    "printf 'a\\nSTART\\nx\\nEND\\nb\\n' | sed -n '/START/,/END/p'"),
 ("sed range delete",   "printf '1\\n2\\n3\\n4\\n' | sed '2,3d'"),
 ("sed step addr",      "printf '1\\n2\\n3\\n4\\n5\\n' | sed -n '1~2p'"),
 ("sed addr plus",      "printf '1\\n2\\n3\\n4\\n' | sed -n '2,+1p'"),
 ("sed block negate",   "printf 'a\\nb\\n' | sed -n '/a/!{p}'"),
 ("sed multiple cmds",  "echo abc | sed 's/a/1/;s/b/2/;s/c/3/'"),
 ("sed uppercase repl", "echo abc | sed 's/.*/\\U&/'"),
 ("sed s w flag p",     "echo abc | sed -n 's/b/X/p'"),
 ("sed delete blank",   "printf 'a\\n\\nb\\n' | sed '/^$/d'"),
 ("sed trim spaces",    "echo '  x  ' | sed 's/^[ \\t]*//;s/[ \\t]*$//'"),
 ("sed equals",         "printf 'a\\nb\\n' | sed -n '$='"),
 ("sed alt delim comma","echo /a/b | sed 's,/a,/z,'"),
 ("sed ere plus",       "echo aab | sed -E 's/a+/X/'"),
 ("sed bre plus esc",   "echo aab | sed 's/a\\+/X/'"),
 ("sed backref two",    "echo 'ab' | sed -E 's/(a)(b)/\\2\\1/'"),
 ("sed i suffix",       "printf 'a\\n' > g1; sed -i.bak 's/a/Z/' g1; cat g1; cat g1.bak"),
 ("sed i two files",    "printf 'a\\n' > h1; printf 'a\\n' > h2; sed -i 's/a/Q/' h1 h2; cat h1 h2"),
 ("sed no match rc",    "echo x | sed 's/zz/y/'; echo rc=$?"),
 ("sed bad script rc",  "echo x | sed 's/a' 2>/dev/null; echo rc=$?"),
 ("sed file operand",   "printf 'a\\nb\\n' > i1; sed -n '2p' i1"),
 ("sed sshd_config",    "printf 'PermitRootLogin no\\nPort 22\\n' > sc; "
                        "sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' sc; cat sc"),
 ("sed append to file", "printf 'a\\n' > j1; sed -i '$a added' j1; cat j1"),
 # grep
 ("grep -o",            "echo 'a1b22c' | grep -o '[0-9]*'"),
 ("grep -c",            "printf 'a\\nb\\na\\n' | grep -c a"),
 ("grep -v",            "printf 'a\\nb\\n' | grep -v a"),
 ("grep -E alt",        "printf 'cat\\ndog\\n' | grep -E 'cat|dog'"),
 ("grep -i",            "echo ABC | grep -i abc"),
 ("grep -n",            "printf 'a\\nb\\n' | grep -n b"),
 ("grep -w",            "echo 'foobar foo' | grep -ow foo"),
 # Stream order under 2>&1. The two streams become one, and the order is
 # the order things were written -- but stderr was collected separately
 # and tacked on at the end, so a group came back as all-stdout-then-all-
 # stderr. The recon payload wraps its entire probe in `( ... ) 2>&1` and
 # splits the result on markers it echoes, so every error it harvested was
 # in the wrong place relative to the marker it belonged to.
 ("2>&1 group order",   "{ echo a; echo b >&2; echo c; } 2>&1"),
 ("2>&1 subshell order", "( echo one; ls /nope; echo two ) 2>&1"),
 ("2>&1 alternating",   "( echo 1; echo 2 >&2; echo 3; echo 4 >&2 ) 2>&1"),
 ("2>&1 then pipe",     "( ls /nope; echo after ) 2>&1 | head -2"),
 ("2>&1 with &&",       "( echo a && echo b >&2 && echo c ) 2>&1"),
 ("2>&1 err first",     "( ls /nope; echo tail ) 2>&1"),
 ("2>&1 nested group",  "( echo o; { ls /nope; } ; echo p ) 2>&1"),
 # The streams must stay separate when nothing merges them.
 ("no merge stays split", "echo a; echo b >&2; echo c"),
 ("2>/dev/null drops",  "( echo p; ls /nope; echo q ) 2>/dev/null"),
 ("single cmd 2>&1",    "ls /nope 2>&1; echo done"),
 # -r is the shape actors actually use to hunt for credentials, and it
 # matched nothing: a directory operand was read as a file, so the answer
 # was rc 1 and silence -- the same thing a box with nothing to find says.
 # Ordering is normalised with sort because readdir order is not a promise.
 ("grep -r dir",        "mkdir -p d/sub; echo hit > d/a; echo hit > d/sub/b;"
                        " grep -r hit d | sort"),
 ("grep -r slash",      "mkdir -p d; echo hit > d/a; grep -r hit d/ | sort"),
 ("grep -R dir",        "mkdir -p d; echo hit > d/a; grep -R hit d | sort"),
 ("grep -r dot",        "echo hit > a; grep -r hit . | sort"),
 ("grep -rn",           "mkdir -p d; printf 'x\nhit\n' > d/a;"
                        " grep -rn hit d | sort"),
 ("grep -rl",           "mkdir -p d; echo hit > d/a; echo hit > d/b;"
                        " grep -rl hit d | sort"),
 ("grep -ri",           "mkdir -p d; echo HIT > d/a; grep -ri hit d | sort"),
 # More than one file means every line is prefixed with the file it is in.
 # Concatenating the files first threw that away.
 ("grep two files",     "echo hit > a; echo hit > b; grep hit a b | sort"),
 ("grep -h two files",  "echo hit > a; echo hit > b; grep -h hit a b | sort"),
 ("grep -H one file",   "echo hit > a; grep -H hit a"),
 ("grep -c two files",  "echo hit > a; echo no > b; grep -c hit a b | sort"),
 ("grep -l two files",  "echo hit > a; echo no > b; grep -l hit a b | sort"),
 ("grep dir no -r",     "mkdir -p d; echo hit > d/a; grep hit d 2>/dev/null;"
                        " echo rc=$?"),
 ("grep -q rc",         "echo a | grep -q a; echo rc=$?"),
 ("grep -m1",           "printf 'a\\na\\na\\n' | grep -m1 a"),
 ("grep -A1",           "printf 'a\\nb\\nc\\n' | grep -A1 b"),
 ("grep -B1",           "printf 'a\\nb\\nc\\n' | grep -B1 b"),
 ("grep -r missing",    "grep -r zzz /nonexistent-dir 2>&1; echo rc=$?"),
 ("grep fixed -F",      "echo 'a.c' | grep -F 'a.c'"),
 ("grep anchors",       "printf 'ab\\nba\\n' | grep '^a'"),
 # cut
 ("cut -d -f",          "echo a:b:c | cut -d: -f2"),
 ("cut -f range",       "echo a:b:c:d | cut -d: -f2-3"),
 ("cut -f open",        "echo a:b:c:d | cut -d: -f3-"),
 ("cut -c",             "echo abcdef | cut -c2-4"),
 ("cut multiple -f",    "echo a:b:c | cut -d: -f1,3"),
 ("cut --complement",   "echo a:b:c | cut -d: --complement -f2"),
 ("cut no delim line",  "printf 'a:b\\nnodelim\\n' | cut -d: -f1"),
 ("cut -s",             "printf 'a:b\\nnodelim\\n' | cut -s -d: -f1"),
 # sort / uniq
 ("sort basic",         "printf 'b\\na\\nc\\n' | sort"),
 ("sort -n",            "printf '10\\n9\\n100\\n' | sort -n"),
 ("sort -r",            "printf 'a\\nb\\n' | sort -r"),
 ("sort -u",            "printf 'a\\na\\nb\\n' | sort -u"),
 ("sort -k2",           "printf 'x 2\\ny 1\\n' | sort -k2"),
 ("sort -t -k",         "printf 'x:2\\ny:1\\n' | sort -t: -k2"),
 ("sort -nr",           "printf '1\\n10\\n2\\n' | sort -nr"),
 ("uniq",               "printf 'a\\na\\nb\\n' | uniq"),
 ("uniq -c",            "printf 'a\\na\\nb\\n' | uniq -c"),
 ("uniq -d",            "printf 'a\\na\\nb\\n' | uniq -d"),
 ("sort|uniq -c|sort -rn","printf 'a\\nb\\na\\n' | sort | uniq -c | sort -rn"),
 # tr
 ("tr ranges",          "echo abc | tr a-z A-Z"),
 ("tr -d",              "echo a1b2 | tr -d 0-9"),
 ("tr -s",              "echo 'a   b' | tr -s ' '"),
 ("tr -c -d",           "echo 'ab12' | tr -cd '0-9'"),
 ("tr newline",         "printf 'a\\nb\\n' | tr '\\n' ' '"),
 ("tr classes",         "echo 'a b' | tr '[:space:]' '_'"),
 # head / tail / wc
 ("head -n",            "printf 'a\\nb\\nc\\n' | head -n2"),
 ("head -c",            "echo abcdef | head -c3"),
 ("head negative",      "printf 'a\\nb\\nc\\n' | head -n -1"),
 ("tail -n",            "printf 'a\\nb\\nc\\n' | tail -n2"),
 ("tail +2",            "printf 'a\\nb\\nc\\n' | tail -n +2"),
 ("wc -l -w -c",        "printf 'a b\\nc\\n' | wc -l; printf 'a b\\nc\\n' | wc -w"),
 # xargs
 ("xargs echo",         "printf 'a\\nb\\n' | xargs echo"),
 ("xargs -n1",          "printf 'a\\nb\\n' | xargs -n1 echo"),
 ("xargs -I",           "printf 'a\\nb\\n' | xargs -I{} echo [{}]"),
 # misc pipelines attackers write
 ("ps|grep|awk",        "ps aux | grep -v grep | awk '{print $2}' | head -3"),
 ("cat|tr|sort|uniq",   "printf 'b\\na\\nb\\n' | tr -d ' ' | sort | uniq -c"),
 ("rev",                "echo abc | rev"),
 ("basename dirname",   "basename /a/b/c; dirname /a/b/c"),
 ("printf loop",        "for i in 1 2 3; do printf '%d,' $i; done; echo"),
 ("test -z",            "[ -z '' ] && echo empty"),
 ("case stmt",          "case abc in a*) echo starts-a;; *) echo other;; esac"),
 ("param default",      "unset X; echo ${X:-default}"),
 ("param subst",        "V=abcdef; echo ${V#abc}; echo ${V%def}; echo ${V/b/B}"),
 ("array-ish",          "set -- a b c; echo $#; echo $2"),
 ("here doc var",       "V=hi; cat <<EOF\n$V\nEOF"),
 ("here doc quoted",    'cat <<"EOF"\n$HOME\nEOF'),
 ("here doc owner mid", "V=x; cat <<EOF > f2; cat f2\nval=$V\nEOF"),
 ("here doc piped",     "cat <<EOF | tr a-z A-Z\nhello\nEOF"),
 ("here doc dash",      "cat <<-EOF\n\tindented\nEOF"),
 ("here string",        "tr a-z A-Z <<< hello"),
 ("nested subst",       "echo $(echo $(echo deep))"),
 ("arith in string",    "n=3; echo \"n is $((n*2))\""),
]

def real(snippet, cwd):
    p = subprocess.run(["bash", "-c", snippet], capture_output=True, text=True,
                       cwd=cwd, timeout=15)
    return p.stdout


def ours(snippet):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.cwd = "/tmp"
    return sh.run(snippet)


def main():
    verbose = "-v" in sys.argv
    only = None
    if "-k" in sys.argv:
        only = sys.argv[sys.argv.index("-k") + 1]
    ok = bad = 0
    for name, snip in CASES:
        if only and only not in name:
            continue
        with tempfile.TemporaryDirectory() as d:
            try:
                want = real(snip, d)
            except (OSError, subprocess.TimeoutExpired):
                continue
        try:
            got = ours(snip)
        except Exception as exc:                      # noqa: BLE001
            got = "<crash: %r>" % (exc,)
        if want == got:
            ok += 1
            if verbose:
                print("  ok   %-24s %r" % (name, got[:46]))
        else:
            bad += 1
            print("  DIFF %-24s %s" % (name, snip.replace("\n", "\\n")[:56]))
            print("       real %r" % want[:90])
            print("       ours %r" % got[:90])
    print()
    print("=" * 60)
    print("%d/%d match  (%d differ)" % (ok, ok + bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
