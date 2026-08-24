#!/usr/bin/env python3
"""Round 2: wider corpus, still machine-independent constructs only."""
import importlib.util
import os, subprocess
# Resolve next to this file, not relative to the caller's cwd: the guest
# has no repo checkout, so a hardcoded "honeypot/fakeshell.py" meant these
# could only ever run from the repo root -- and the guest's bash is the
# reference these suites most want to be diffed against.
_HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "fakeshell", os.path.join(_HERE, "fakeshell.py"))
fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)

CASES = [
 # positional / special params
 ("dollar-hash",        "set -- a b c; echo $#"),
 ("dollar-1",           "set -- a b c; echo $1"),
 ("dollar-star",        "set -- a b; echo $*"),
 # functions
 ("function",           "f() { echo infunc; }; f"),
 ("function args",      "f() { echo got $1; }; f hello"),
 ("function kw",        "function g { echo kw; }; g"),
 # more expansion
 ("nested default",     "echo ${a:-${b:-deep}}"),
 ("plus alt set",       "x=1; echo ${x:+set}"),
 ("plus alt unset",     "echo ${y:+set}"),
 ("subst all",          "p=a-b-a; echo ${p//a/X}"),
 ("subst one",          "p=a-b-a; echo ${p/a/X}"),
 ("longest suffix",     "f=a.b.c; echo ${f%%.*}"),
 ("longest prefix",     "f=a.b.c; echo ${f##*.}"),
 ("arith compare",      "echo $((3>2))"),
 ("arith mod",          "echo $((17%5))"),
 ("arith paren",        "echo $(((1+2)*3))"),
 ("arith neg",          "echo $((-4+1))"),
 # quoting
 ("single in double",   """echo "it's" """),
 ("escaped dollar",     r'echo "\$notvar"'),
 ("adjacent quotes",    """echo a"b"c'd'"""),
 ("empty string arg",   'echo "" end'),
 # loops / control
 ("for with break-ish", "for i in 1 2 3; do echo $i; done | head -2"),
 ("nested if in for",   "for i in 1 2; do if [ $i = 2 ]; then echo two; fi; done"),
 ("until loop",         "i=0; until [ $i -ge 2 ]; do echo u$i; i=$((i+1)); done"),
 ("while read-ish",     "printf 'a\\nb\\n' | while read l; do echo got-$l; done"),
 ("elif",               "x=2; if [ $x = 1 ]; then echo one; elif [ $x = 2 ]; then echo two; else echo other; fi"),
 ("case multi pattern", "case b in a|b) echo ab;; *) echo no;; esac"),
 # text tools round 2
 ("uniq",               "printf 'a\\na\\nb\\n' | uniq"),
 ("uniq -c",            "printf 'a\\na\\nb\\n' | uniq -c"),
 ("wc -w",              "echo a b c | wc -w"),
 ("tr -s",              "echo 'aaab' | tr -s a"),
 ("sed -n p",           "printf '1\\n2\\n3\\n' | sed -n '2p'"),
 ("sed multiple",       "echo abc | sed -e 's/a/1/' -e 's/c/3/'"),
 ("awk NF",             "echo 'a b c' | awk '{print NF}'"),
 ("awk NR",             "printf 'x\\ny\\n' | awk '{print NR}'"),
 ("awk print all",      "echo 'a b' | awk '{print $0}'"),
 ("awk OFS",            "echo 'a b' | awk '{print $2, $1}'"),
 ("cat -n",             "printf 'x\\ny\\n' | cat -n"),
 ("sort -n",            "printf '10\\n9\\n' | sort -n"),
 ("sort -u",            "printf 'b\\na\\nb\\n' | sort -u"),
 ("cut -c",             "echo abcdef | cut -c2-4"),
 ("head default",       "printf '1\\n2\\n' | head"),
 ("grep -i",            "echo ABC | grep -i abc"),
 ("grep -E",            "echo a1 | grep -E '[a-z][0-9]'"),
 ("grep -q",            "echo a | grep -q a; echo $?"),
 ("xargs echo",         "printf 'a\\nb\\n' | xargs echo"),
 ("seq",                "seq 1 3"),
 ("expr add",           "expr 2 + 3"),
 ("md5sum stdin",       "printf abc | md5sum"),
 ("sha256sum stdin",    "printf abc | sha256sum"),
 ("base64",             "printf abc | base64"),
 ("base64 -d",          "printf YWJj | base64 -d"),
 ("rev",                "echo abc | rev"),
 ("tee-ish",            "echo hi | cat"),
 # command lookup
 ("command -v yes",     "command -v echo"),
 ("which sh",           "which sh"),
 ("type builtin",       "type echo"),
 # misc builtins
 ("shift",              "set -- a b c; shift; echo $1"),
 ("read var",            "echo val | { read v; echo got-$v; }"),
 ("sleep 0",            "sleep 0; echo done"),
 ("pwd",                "cd /tmp; pwd"),
 ("exit code explicit", "( exit 3 ); echo $?"),
 # error strings round 2
 ("err mkdir exists",   "mkdir /tmp"),
 ("err rmdir",          "rmdir /nonexistent-xyz"),
 ("err chmod",          "chmod 755 /nonexistent-xyz"),
 ("err touch dir",      "touch /nonexistent-dir-xyz/f"),
 ("err head",           "head /nonexistent-xyz"),
 ("err wc",             "wc /nonexistent-xyz"),
 ("err grep file",      "grep x /nonexistent-xyz"),
 ("err cp",             "cp /nonexistent-xyz /tmp/y"),
 ("err mv",             "mv /nonexistent-xyz /tmp/y"),
]

def run_real(script):
    r = subprocess.run(["bash","--noprofile","--norc","-c",script],
        capture_output=True, text=True, cwd="/tmp",
        env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":"/tmp"})
    return r.stdout, r.stderr
def run_fake(script):
    sh = fs.Shell(); sh.cwd = "/tmp"
    return sh.run(script), "".join(sh._err)
def norm(e): return e.replace("bash: line 1: ","bash: ").strip()

bad=[]
for name, sc in CASES:
    ro,re_ = run_real(sc); fo,fe = run_fake(sc)
    if ro!=fo or norm(re_)!=norm(fe): bad.append((name,sc,ro,re_,fo,fe))
print(f"{len(CASES)-len(bad)}/{len(CASES)} match  ({len(bad)} differ)\n")
for name,sc,ro,re_,fo,fe in bad:
    print(f"--- {name}\n    $ {sc}")
    print(f"    real out={ro!r} err={norm(re_)!r}")
    print(f"    ours out={fo!r} err={norm(fe)!r}")
