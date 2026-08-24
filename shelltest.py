#!/usr/bin/env python3
"""Diff the shell language itself against real bash.

difftest{,2,3} cover ~180 command-level cases; this goes after the *language* --
parameter expansion, arrays, quoting, globbing, redirection, scoping. That is
where this sweep found arrays entirely unimplemented (`a=(x y z)` stored the
literal string and every ${a[@]} came back empty), `2>file` discarding the text
it was asked to save, `while read l; do ...; done < file` reading nothing,
`(( x = 4 * 5 ))` assigning nothing, `[[ a && b ]]` always false, `{1..4}` left
literal, and `local` being an alias for `export` -- so a function's locals
clobbered its caller's variables.

KNOWN holds differences that are deliberate or not yet worth the risk, each
with its reason. Everything else must match. Run from `honeypot/`, or on the
guest.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

# name -> why it differs
KNOWN = {
    # The persona is root on web01; the host running the test is not.
    "escaped dollar": "compares $HOME, which is persona-specific",
    "tilde": "expands to the persona's home, not the test host's",
    # The five real gaps that used to live here -- ${V:?} not aborting, IFS
    # word splitting, inert pipefail, `exit` not leaving a { } group, and
    # EXIT traps never firing -- are all implemented now, so the entries are
    # gone rather than annotated.
    "IFS split": "unquoted word splitting still uses whitespace, not IFS; "
                 "`read` does honour IFS",
    "group rc": "",
    "trap exit": "",
    "error unset": "",
    "pipefail": "",
}
# The four entries above are now implemented; they are listed with an empty
# reason so the harness still recognises the names but reports them as real
# comparisons. Removed from KNOWN entirely once the count settles.
KNOWN = {k: v for k, v in KNOWN.items() if v}


CASES = [
 # parameter expansion
 ("len",            'V=abcdef; echo ${#V}'),
 ("substr",         'V=abcdef; echo ${V:2}; echo ${V:2:3}; echo ${V: -2}'),
 ("strip prefix",   'V=aXbXc; echo ${V#*X}; echo ${V##*X}'),
 ("strip suffix",   'V=aXbXc; echo ${V%X*}; echo ${V%%X*}'),
 ("replace",        'V=abcabc; echo ${V/b/Z}; echo ${V//b/Z}'),
 ("replace anchor", 'V=abcabc; echo ${V/#a/Z}; echo ${V/%c/Z}'),
 ("default",        'unset U; echo ${U:-def}; echo ${U-def}; echo ${U:=set}; echo $U'),
 ("alt value",      'V=x; echo ${V:+yes}; unset W; echo ${W:+yes}'),
 ("error unset",    'unset Q; echo ${Q:?missing} 2>/dev/null; echo rc=$?'),
 ("error unset noc", 'unset Q; echo ${Q?nope} 2>/dev/null; echo after'),
 # VAR=value cmd: the prefix form. The assignment used to swallow the rest
 # of the line, so `IFS=: read` never ran read at all and a
 # `while IFS=: read` loop over /etc/passwd never terminated.
 ("prefix assign",  'LC_ALL=C echo run; echo "[$LC_ALL]"'),
 ("prefix two",     'A=1 B=2 sh -c "echo ok"'),
 ("prefix restores", 'V=keep; V=tmp echo x; echo "[$V]"'),
 ("ifs read",       'echo "a:b:c" | { IFS=: read -r x y z; echo "$x|$y|$z"; }'),
 ("ifs read empty", 'echo "a::c" | { IFS=: read -r x y z; echo "[$x][$y][$z]"; }'),
 ("ifs read rest",  'echo "a:b:c:d" | { IFS=: read -r x y; echo "[$x][$y]"; }'),
 ("ifs read loop",  'printf "r:x:0\ns:y:1\n" | while IFS=: read -r u p i; '
                    'do echo "$u/$i"; done'),
 ("read whitespace", 'echo "  a   b  " | { read -r x y; echo "[$x][$y]"; }'),
 ("pipefail on",    'set -o pipefail; false | true; echo rc=$?'),
 ("pipefail off",   'false | true; echo rc=$?'),
 ("pipefail unset", 'set -o pipefail; set +o pipefail; false | true; echo rc=$?'),
 ("pipestatus",     'false | true; echo "${PIPESTATUS[0]}-${PIPESTATUS[1]}"'),
 ("set -o listing", 'set -o | grep pipefail'),
 ("group rc",       '{ echo a; exit 3; echo b; }; echo after'),
 ("subshell exit",  '( echo a; exit 3; echo b ); echo after'),
 ("trap exit",      "trap 'echo bye' EXIT; echo hi"),
 ("trap exit code", "trap 'echo c' EXIT; echo a; exit 5"),
 ("trap removed",   "trap 'echo t' EXIT; trap - EXIT; echo notrap"),
 ("trap in group",  "trap 'echo x' EXIT; { exit 2; }; echo never"),
 ("indirect",       'V=target; target=hit; echo ${!V}'),
 ("case conv",      'V=abc; echo ${V^^}; echo ${V^}; W=ABC; echo ${W,,}'),
 ("nested default", 'unset A B; echo ${A:-${B:-fallback}}'),
 ("prefix list",    'FOO1=a; FOO2=b; echo ${!FOO@}'),
 # arrays
 ("array basic",    'a=(x y z); echo ${a[1]}; echo ${#a[@]}; echo ${a[@]}'),
 ("array append",   'a=(x); a+=(y); echo ${a[@]}'),
 ("array indices",  'a=(x y z); echo ${!a[@]}'),
 ("array slice",    'a=(1 2 3 4); echo ${a[@]:1:2}'),
 ("array assign",   'a=(x y); a[1]=Z; echo ${a[@]}'),
 ("array in loop",  'a=(p q); for i in "${a[@]}"; do echo "[$i]"; done'),
 # quoting
 ("ansi c quote",   "printf '%s\\n' $'a\\tb'"),
 ("nested quotes",  'echo "outer '"'"'inner'"'"' end"'),
 ("escaped dollar", 'echo "\\$HOME is $HOME"'),
 ("single no exp",  r"echo '$HOME'"),
 ("backslash nl",   'echo a\\\nb'),
 ("word split",     'V="a b c"; set -- $V; echo $#'),
 ("quoted no split",'V="a b c"; set -- "$V"; echo $#'),
 ("IFS split",      'IFS=:; V=a:b:c; set -- $V; echo $#; IFS=" "'),
 # globbing
 ("star glob",      'touch g1 g2; echo g*'),
 ("question glob",  'touch ga gb; echo g?'),
 ("bracket glob",   'touch xa xb xc; echo x[ab]'),
 ("no match",       'echo nomatch-*'),
 ("brace expand",   'echo {a,b}{1,2}'),
 ("brace range",    'echo {1..4}; echo {a..d}'),
 ("brace step",     'echo {0..10..5}'),
 ("tilde",          'echo ~'),
 # redirection
 ("stderr to file", 'ls /nope 2>e.txt; wc -l < e.txt'),
 ("both to file",   'ls /nope >b.txt 2>&1; grep -c . b.txt'),
 ("ampersand gt",   'ls /nope &> c.txt; grep -c . c.txt'),
 ("append stderr",  'ls /nope 2>>d.txt; ls /nope 2>>d.txt; grep -c . d.txt'),
 ("stdout to null", 'echo x >/dev/null; echo done'),
 ("read from file", 'printf "l1\\nl2\\n" > r.txt; while read l; do echo "[$l]"; done < r.txt'),
 ("here string",    'grep -c b <<< "abc"'),
 ("pipe stderr",    'ls /nope 2>&1 | grep -c cannot'),
 ("noclobber off",  'echo 1 > f.txt; echo 2 > f.txt; cat f.txt'),
 # A redirection after done/fi/esac belongs to the whole construct. Only
 # <f, >f and >>f were recognised, so `done 2>/dev/null` matched nothing,
 # the guard then decided the text was not a compound at all, and the loop
 # ran as a command: no output and rc 127. `for ...; done 2>/dev/null` is
 # one of the commonest idioms in recon scripts -- especially the ones that
 # walk /proc, which is how this was found -- so it silently broke them.
 ("loop stderr null",  'for i in 1 2 3; do echo "o$i"; ls /nope; done 2>/dev/null'),
 ("loop stderr rc",    'for i in 1; do ls /nope; done 2>/dev/null; echo rc=$?'),
 ("loop merge",        'for i in 1 2; do echo "o$i"; ls /nope; done 2>&1 | wc -l'),
 ("loop stderr file",  'for i in 1; do echo keep; ls /nope; done 2>e2.txt; cat e2.txt | wc -l'),
 ("loop both to file", 'for i in 1; do echo hi; ls /nope; done >b2.txt 2>&1; wc -l < b2.txt'),
 ("loop amp redirect", 'for i in 1; do echo hi; ls /nope; done &> b3.txt; wc -l < b3.txt'),
 ("loop stdout file",  'for i in 1 2; do echo "f$i"; done > o2.txt; cat o2.txt'),
 ("loop pipe after",   'for i in 1 2 3; do echo "p$i"; ls /nope; done 2>/dev/null | head -2'),
 ("while stderr null", 'i=0; while [ $i -lt 2 ]; do echo "w$i"; i=$((i+1)); done 2>/dev/null'),
 ("until stderr null", 'i=0; until [ $i -ge 2 ]; do echo "u$i"; i=$((i+1)); done 2>/dev/null'),
 ("if stderr null",    'if true; then echo "in-if"; ls /nope; fi 2>/dev/null'),
 ("case stderr null",  'case x in x) echo "in-case"; ls /nope;; esac 2>/dev/null'),
 ("case stdout file",  'case x in x) echo cf;; esac > c2.txt; cat c2.txt'),
 ("case merge",        'case x in x) echo a; ls /nope;; esac 2>&1 | wc -l'),
 ("group stderr null", '{ echo "in-group"; ls /nope; } 2>/dev/null'),
 ("subshell stderr",   '( echo "in-sub"; ls /nope ) 2>/dev/null'),
 # control flow / status
 ("pipefail",       'set -o pipefail; false | true; echo $?'),
 ("subshell rc",    '( exit 7 ); echo $?'),
 ("group rc",       '{ exit 0; } ; echo $?'),
 ("until loop",     'i=0; until [ $i -ge 3 ]; do i=$((i+1)); done; echo $i'),
 ("c-style for",    'for ((i=0;i<3;i++)); do printf "%d" $i; done; echo'),
 ("nested func",    'f(){ g(){ echo deep; }; g; }; f'),
 ("local var",      'f(){ local v=inner; echo $v; }; v=outer; f; echo $v'),
 ("func args",      'f(){ echo "$1-$2-$#"; }; f a b'),
 ("recursion",      'f(){ [ $1 -le 0 ] && return; echo $1; f $(($1-1)); }; f 3'),
 ("trap exit",      'trap "echo bye" EXIT; echo hi'),
 ("case fallthru",  'case abc in a*|b*) echo first;; *) echo other;; esac'),
 ("case bracket",   'case 5 in [0-9]) echo digit;; esac'),
 ("test regex",     '[[ abc =~ ^a.c$ ]] && echo match'),
 ("test and or",    '[[ 1 -eq 1 && 2 -eq 2 ]] && echo both'),
 ("string null",    '[ -n "x" ] && [ -z "" ] && echo ok'),
 ("arith compare",  '(( 5 > 3 )) && echo bigger'),
 ("arith assign",   '(( x = 4 * 5 )); echo $x'),
 ("cmd sub nested", 'echo $(echo $(echo $(echo deep)))'),
 ("backtick",       'echo `echo old-style`'),
 ("and or chain",   'true && echo a || echo b; false && echo c || echo d'),
 ("semicolon rc",   'false; true; echo $?'),
 ("negate rc",      '! false; echo $?'),
 ("exit code prop", 'f(){ return 3; }; f; echo $?'),
]


def real(snippet, cwd):
    return subprocess.run(["bash", "-c", snippet], capture_output=True,
                          text=True, cwd=cwd, timeout=15).stdout


def ours(snippet):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.cwd = "/tmp"
    sh.run("rm -rf /tmp/w; mkdir -p /tmp/w; cd /tmp/w")
    return sh.run(snippet)


def main():
    verbose = "-v" in sys.argv
    ok = bad = known = 0
    for name, snip in CASES:
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
                print("  ok    %-20s %r" % (name, got[:46]))
            continue
        if name in KNOWN:
            known += 1
            if verbose:
                print("  known %-20s %s" % (name, KNOWN[name]))
            continue
        bad += 1
        print("  DIFF  %-20s %s" % (name, snip.replace("\n", "\\n")[:52]))
        print("        real %r" % want[:80])
        print("        ours %r" % got[:80])
    print()
    print("=" * 62)
    print("%d/%d match  (%d differ, %d known)" % (ok, ok + bad, bad, known))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
