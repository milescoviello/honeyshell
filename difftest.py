#!/usr/bin/env python3
"""Differential test: our fake shell vs real bash.

Only machine-independent constructs are compared -- we deliberately lie about
hostname, kernel, /etc/passwd and so on, so those are not fidelity bugs.
What must match is *behaviour*: expansion, quoting, control flow, exit codes,
error strings and text-tool semantics.
"""
import importlib.util
import os, subprocess, sys, os

# Resolve next to this file, not relative to the caller's cwd: the guest
# has no repo checkout, so a hardcoded "honeypot/fakeshell.py" meant these
# could only ever run from the repo root -- and the guest's bash is the
# reference these suites most want to be diffed against.
_HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "fakeshell", os.path.join(_HERE, "fakeshell.py"))
fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)

CASES = [
 # --- echo / printf ---
 ("echo plain",            "echo hello world"),
 ("echo -n",               "echo -n abc"),
 ("echo -e tab",           r"echo -e 'a\tb'"),
 ("echo multiple args",    "echo a   b    c"),
 ("echo quoted spaces",    'echo "a   b"'),
 ("printf %s",             "printf '%s-%s' one two"),
 ("printf newline",        r"printf 'a\nb\n'"),
 ("printf %d",             "printf '%d\n' 42"),
 ("printf no newline",     "printf abc"),
 # --- variables / expansion ---
 ("assign+use",            "x=5; echo $x"),
 ("braced",                "x=5; echo ${x}"),
 ("default unset",         "echo ${nope:-fallback}"),
 ("default set",           "x=v; echo ${x:-fallback}"),
 ("length",                "x=hello; echo ${#x}"),
 ("strip suffix",          "f=a.tar.gz; echo ${f%.gz}"),
 ("strip prefix",          "f=/a/b/c; echo ${f#/a/}"),
 ("arith",                 "echo $((2+3*4))"),
 ("arith var",             "x=7; echo $((x*2))"),
 ("unset var empty",       "echo [$undefined]"),
 ("quoted expansion",      'x="a b"; echo "$x"'),
 ("cmd subst",             "echo $(echo nested)"),
 ("backtick",              "echo `echo old`"),
 ("nested subst",          "echo $(echo $(echo deep))"),
 # --- exit codes ---
 ("rc success",            "true; echo $?"),
 ("rc failure",            "false; echo $?"),
 ("rc notfound",           "nosuchcmd 2>/dev/null; echo $?"),
 ("and-list short",        "false && echo no; echo done"),
 ("or-list",               "false || echo yes"),
 ("chain",                 "true && echo a || echo b"),
 ("negate",                "! false; echo $?"),
 # --- test / [ ---
 ("test str eq",           '[ a = a ] && echo eq'),
 ("test num",              "[ 3 -gt 2 ] && echo gt"),
 ("test -z",               '[ -z "" ] && echo empty'),
 ("test -n",               '[ -n "x" ] && echo nonempty'),
 # --- control flow ---
 ("if",                    "if true; then echo yes; fi"),
 ("if else",               "if false; then echo a; else echo b; fi"),
 ("for loop",              "for i in 1 2 3; do echo n$i; done"),
 ("for over subst",        "for i in $(echo a b); do echo -n $i; done"),
 ("while",                 "i=0; while [ $i -lt 3 ]; do echo $i; i=$((i+1)); done"),
 ("case match",            "case abc in a*) echo hit;; *) echo miss;; esac"),
 ("case fallthrough",      "case zzz in a*) echo hit;; *) echo miss;; esac"),
 # --- pipes / redirection ---
 ("pipe",                  "echo hello | wc -c"),
 ("pipe chain",            "printf 'b\\na\\nc\\n' | sort | head -1"),
 ("stderr suppress",       "nosuchcmd 2>/dev/null; echo after"),
 ("stderr to stdout",      "nosuchcmd 2>&1 | wc -l"),
 ("here string",           "cat <<< hello"),
 # --- text tools ---
 ("grep",                  "printf 'aa\\nbb\\n' | grep bb"),
 ("grep -v",               "printf 'aa\\nbb\\n' | grep -v bb"),
 ("grep -c",               "printf 'aa\\nab\\n' | grep -c a"),
 ("grep -o",               "echo foobarbaz | grep -o bar"),
 ("head -n",               "printf '1\\n2\\n3\\n' | head -n 2"),
 ("head -c",               "printf 'abcdef' | head -c 3"),
 ("tail -n",               "printf '1\\n2\\n3\\n' | tail -n 1"),
 ("wc -l",                 "printf 'a\\nb\\n' | wc -l"),
 ("wc -c",                 "printf 'abc' | wc -c"),
 ("cut -d",                "echo a:b:c | cut -d: -f2"),
 ("cut -f range",          "echo a:b:c | cut -d: -f2-"),
 ("tr delete",             r"printf 'a\nb' | tr -d '\n'"),
 ("tr translate",          "echo abc | tr a-z A-Z"),
 ("sort",                  "printf 'c\\na\\nb\\n' | sort"),
 ("sort -r",               "printf 'a\\nb\\n' | sort -r"),
 ("sed subst",             "echo aaa | sed 's/a/b/'"),
 ("sed global",            "echo aaa | sed 's/a/b/g'"),
 ("sed delete blank",      "printf 'a\\n\\nb\\n' | sed '/^$/d'"),
 ("awk field",             "echo 'a b c' | awk '{print $2}'"),
 ("awk -F",                "echo a:b | awk -F: '{print $2}'"),
 ("awk pattern",           "printf 'x 1\\ny 2\\n' | awk '/y/ {print $2}'"),
 ("rev-ish basename",      "basename /a/b/c.txt"),
 ("dirname",               "dirname /a/b/c.txt"),
 # --- error strings (the fingerprint-critical ones) ---
 ("err notfound",          "nosuchcmd"),
 ("err path notfound",     "./nosuchfile"),
 ("err abs path",          "/nosuch/binary"),
 ("err cd",                "cd /nonexistent-dir"),
 ("err cat",               "cat /nonexistent-file"),
 ("err perm-ish rm",       "rm /nonexistent-file"),
 ("err ls",                "ls /nonexistent-path"),
]

def run_real(script):
    r = subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                       capture_output=True, text=True, cwd="/tmp",
                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/tmp"})
    return r.stdout, r.stderr, r.returncode

def run_fake(script):
    sh = fs.Shell()
    sh.cwd = "/tmp"
    out = sh.run(script)
    err = "".join(sh._err)
    return out, err, sh.last_rc

def norm_err(e):
    # real bash says "bash: line 1: x"; we say "bash: x". Compare modulo that.
    return e.replace("bash: line 1: ", "bash: ").strip()

if __name__ == "__main__":
    bad = []
    for name, script in CASES:
        ro, re_, rrc = run_real(script)
        fo, fe, frc = run_fake(script)
        out_ok = ro == fo
        err_ok = norm_err(re_) == norm_err(fe)
        if not (out_ok and err_ok):
            bad.append((name, script, (ro, re_), (fo, fe)))
    print(f"{len(CASES) - len(bad)}/{len(CASES)} match  ({len(bad)} differ)\n")
    for name, script, (ro, re_), (fo, fe) in bad:
        print(f"--- {name}")
        print(f"    $ {script}")
        print(f"    real out={ro!r} err={norm_err(re_)!r}")
        print(f"    ours out={fo!r} err={norm_err(fe)!r}")
