#!/usr/bin/env python3
"""Round 3: harder constructs + idioms lifted from real bot payloads."""
import importlib.util
import sys
import os, shutil, subprocess
# Resolve next to this file, not relative to the caller's cwd: the guest
# has no repo checkout, so a hardcoded "honeypot/fakeshell.py" meant these
# could only ever run from the repo root -- and the guest's bash is the
# reference these suites most want to be diffed against.
_HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "fakeshell", os.path.join(_HERE, "fakeshell.py"))
fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)

CASES = [
 ("heredoc",            "cat <<EOF\nline1\nline2\nEOF"),
 ("heredoc quoted",     "cat <<'EOF'\n$notexpanded\nEOF"),
 ("eval",               "x='echo hi'; eval $x"),
 ("indirect",           "v=name; name=val; echo ${!v}"),
 ("bracket test",       "[[ a == a ]] && echo yes"),
 ("bracket num",        "[[ 3 -gt 2 ]] && echo gt"),
 ("arith for",          "for ((i=0;i<3;i++)); do echo $i; done"),
 ("local in func",      "f() { local x=1; echo $x; }; f"),
 ("return code",        "f() { return 5; }; f; echo $?"),
 ("background",         "true & wait; echo after"),
 ("subshell var scope", "x=1; ( x=2 ); echo $x"),
 ("brace expand",       "echo {a,b}c"),
 ("glob star",          "cd /tmp && ls nonexistentglob* 2>/dev/null; echo rc=$?"),
 ("IFS split",          "IFS=:; set -- a:b; echo $1"),
 ("set -e ignored",     "set +e; false; echo survived"),
 ("nested func call",   "a() { echo A; }; b() { a; echo B; }; b"),
 ("printf reuse fmt",   "printf '%s\\n' a b c"),
 ("printf pad",         "printf '[%5s]' ab"),
 ("printf left pad",    "printf '[%-5s]' ab"),
 ("echo -e escapes",    r"echo -e 'a\nb'"),
 ("dollar at quoted",   'set -- "a b" c; for x in "$@"; do echo "[$x]"; done'),
 ("command sub multi",  "echo $(echo a; echo b)"),
 ("arith in string",    'n=3; echo "n is $((n+1))"'),
 ("case with esac var", 'x=abc; case "$x" in a*) echo A;; esac'),
 ("chained subst",      "x=/a/b/c.txt; y=${x##*/}; echo ${y%.txt}"),
 # idioms straight out of bot payloads
 ("bot: arch detect",   'a=$(uname -m 2>/dev/null || echo unknown); echo $a'),
 ("bot: cpu count",     'c=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo); echo $c'),
 ("bot: write+exec",    'printf "#!/bin/sh\\necho ok\\n" > /tmp/z && chmod +x /tmp/z && /tmp/z; rm -f /tmp/z'),
 ("bot: which chain",   "command -v wget || command -v curl || echo none"),
 ("bot: tmp writable",  "touch /tmp/.w && echo writable && rm -f /tmp/.w"),
 ("bot: id check",      "id -u"),
 ("bot: proc count",    "ls /proc | head -1 >/dev/null; echo $?"),
 ("bot: kill fake",     "kill -0 1 2>/dev/null; echo $?"),
 ("bot: base64 pipe",   "printf 'aGk=' | base64 -d"),
 ("bot: multi-stage",   'for b in wget curl; do command -v $b >/dev/null && { echo "have $b"; break; }; done'),
]

def run_real(sc):
    r = subprocess.run(["bash","--noprofile","--norc","-c",sc],capture_output=True,text=True,
        cwd="/tmp", env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":"/tmp"})
    return r.stdout, r.stderr
def run_fake(sc):
    sh=fs.Shell(); sh.cwd="/tmp"
    return sh.run(sc), "".join(sh._err)
def norm(e): return e.replace("bash: line 1: ","bash: ").strip()

# Cases where the persona and the *test host* are legitimately different
# machines. These were silently tolerated in the "N differ" count, which
# meant the baseline was 3 and a real regression could hide inside it -- the
# same weakness the SKIP bucket fixed in sftptest. Each needs a reason.
KNOWN = {
    "bot: cpu count":
        "the persona has 4 CPUs; the test host has however many it has",
    "bot: id check":
        "the persona is root (uid 0); the user running this suite is not",
    "bot: kill fake":
        "kill -0 1 succeeds for root and gives EPERM for anyone else, so "
        "this compares the persona's privilege against the test user's. "
        "Verified against `sudo kill -0 1` on the guest, which returns 0.",
    "IFS split":
        "unquoted word splitting still uses whitespace rather than IFS; "
        "`read` does honour IFS (see shelltest)",
}

# A case whose binary the test host does not have asks the host a question
# it cannot answer -- nothing about the emulator gets tested, so the result
# is neither a match nor a difference. It must not go in KNOWN either: KNOWN
# tolerates a case forever, including on hosts that *do* have the binary,
# where it would hide a real regression. Runtime-decided third bucket.
#
# Both of these resolve wget first in the persona, so a host without wget is
# answering a different question, not the same one differently. Found when
# CI moved to a debian:trixie container, which ships neither wget nor curl.
NEEDS = {
    "bot: which chain": ("wget",),
    "bot: multi-stage": ("wget",),
}

bad=[]; known=[]; skipped=[]
for name,sc in CASES:
    missing=[b for b in NEEDS.get(name,()) if not shutil.which(b)]
    if missing:
        skipped.append((name,missing)); continue
    ro,re_=run_real(sc); fo,fe=run_fake(sc)
    if ro!=fo or norm(re_)!=norm(fe):
        (known if name in KNOWN else bad).append((name,sc,ro,re_,fo,fe))
print(f"{len(CASES)-len(bad)-len(skipped)}/{len(CASES)} match  "
      f"({len(bad)} differ, {len(known)} known, {len(skipped)} skipped)\n")
for name,missing in skipped:
    print(f"    skip   {name:<22} host has no {', '.join(missing)}")
for name,sc,ro,re_,fo,fe in bad:
    print(f"--- {name}\n    $ {sc[:70]}")
    print(f"    real out={ro!r} err={norm(re_)[:70]!r}")
    print(f"    ours out={fo!r} err={norm(fe)[:70]!r}")
for name,_sc,_ro,_re,_fo,_fe in known:
    print(f"    known  {name:<22} {KNOWN[name]}")
sys.exit(1 if bad else 0)
