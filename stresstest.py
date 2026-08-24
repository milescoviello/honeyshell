#!/usr/bin/env python3
"""Adversarial input: try to hang, crash or exhaust the shell emulator.

Everything an attacker types reaches a Python parser, so a pathological line is
a denial of service against the honeypot itself -- and unlike a wrong output,
it costs us the session and every capture in it. These are the cases that did
break it:

  echo $((9**9**9))     Python computed 9 raised to 387,420,489. One command
                        from any authenticated attacker, unbounded CPU and RAM.
  echo AAAA... (200k)   _brace_expand led its regex with a greedy (\\S*), which
                        backtracked from every position on a long argument.
                        20k characters took a second; 200k hung. Nothing capped
                        the length on the exec path.
  f() { f; }; f         RecursionError escaped the session and dropped the
                        connection. bash prints an error and carries on.
  sleep 1 & x300        Self-inflicted: when backgrounded commands started
                        really executing, a backgrounded sleep began blocking
                        the caller. bash forks and returns immediately.

Each case runs in its own process with its own timeout, so one hang cannot hide
the rest -- the first version of this was a single process and died at the
second case, reporting nothing about the other twenty-four.

Usage:  python3 stresstest.py
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BUDGET = 20          # seconds per case

CASES = [
    ("fork bomb",             ":(){ :|:& };:"),
    ("infinite while",        "while true; do :; done"),
    ("infinite for",          "for ((;;)); do :; done"),
    ("recursive function",    "f() { f; }\nf\necho after"),
    ("mutual recursion",      "a() { b; }\nb() { a; }\na\necho after"),
    ("deep substitution",     "echo " + "$(" * 200 + "x" + ")" * 200),
    ("deep parens",           "(" * 500 + "echo hi" + ")" * 500),
    ("unbalanced quote",      'echo "unterminated'),
    ("unbalanced paren",      "echo $(echo hi"),
    ("unbalanced everything", 'echo "$( { ( [ '),
    ("pow bomb",              "echo $((9**9**9))"),
    ("shift bomb",            "echo $((1<<999999))"),
    ("pow at the cap",        "echo $((2**4096))"),
    ("long argument",         "echo " + "A" * 200000),
    ("very long argument",    "echo " + "A" * 1000000),
    ("long var name",         ("V" * 100000) + "=1; echo done"),
    ("nul byte",              "echo hi\x00there"),
    ("deep path",             "cat " + "../" * 5000 + "etc/passwd"),
    ("glob bomb",             "echo /*/*/*/*/*/*"),
    ("brace bomb",            "echo {1..10000000}"),
    ("brace nest",            "echo " + "{a,b}" * 12),
    ("here-doc unterminated", "cat <<EOF\nhello"),
    ("nested backticks",      "echo " + "`" * 100),
    ("case without esac",     "case $x in a) echo a;;"),
    ("huge printf",           "printf '%0999999999d' 1"),
    ("many background jobs",  "; ".join(["sleep 1 &"] * 300)),
    ("many semicolons",       "; ".join(["echo x"] * 5000)),
    ("deep pipeline",         "echo hi" + " | cat" * 500),
    ("seq bomb",              "seq 1 100000000 | wc -l"),
    ("urandom bomb",          "head -c 100000000 /dev/urandom | wc -c"),
    ("dd bomb",               "dd if=/dev/zero of=/tmp/z bs=1M count=100000; echo ok"),
    ("tar the whole root",    "tar cf /tmp/a.tar / ; echo ok"),
    ("self-referential var",  "A=$A$A$A; echo ${#A}"),
    ("redirect onto self",    "cat f > f; echo ok"),
    ("eval nesting",          "eval 'eval \"eval \\\"echo deep\\\"\"'"),
]

RUNNER = r'''
import sys, time, json
sys.path.insert(0, %r)
import fakeshell as fs
script = json.load(open(sys.argv[1]))
sh = fs.Shell(fs.VFS()); sh.exec_mode = True
t0 = time.time()
try:
    out = sh.run(script)
    print(json.dumps({"v": "ok", "dt": round(time.time() - t0, 2), "n": len(out)}))
except Exception as e:
    print(json.dumps({"v": type(e).__name__, "dt": round(time.time() - t0, 2),
                      "n": 0, "e": str(e)[:80]}))
''' % HERE


def main():
    runner = os.path.join(tempfile.mkdtemp(), "runner.py")
    with open(runner, "w") as fh:
        fh.write(RUNNER)
    payload = os.path.join(os.path.dirname(runner), "case.json")
    failed = []
    for name, script in CASES:
        with open(payload, "w") as fh:
            json.dump(script, fh)
        try:
            r = subprocess.run([sys.executable, runner, payload],
                               capture_output=True, text=True, timeout=BUDGET)
            line = (r.stdout.strip().splitlines() or ["{}"])[-1]
            d = json.loads(line) if line.startswith("{") else {
                "v": "NO OUTPUT", "e": r.stderr[-70:]}
            verdict = d.get("v", "?")
            if verdict != "ok":
                failed.append((name, verdict, d.get("e", "")))
            print("  %-4s %-24s %6.2fs  out=%-9s %s"
                  % ("ok" if verdict == "ok" else "FAIL", name,
                     d.get("dt", 0), d.get("n", "-"), d.get("e", "")[:44]))
        except subprocess.TimeoutExpired:
            failed.append((name, "HANG", ">%ds" % BUDGET))
            print("  FAIL %-24s   >%ds  (killed)" % (name, BUDGET))
    print("\n" + "=" * 58)
    print("passed %d, failed %d" % (len(CASES) - len(failed), len(failed)))
    for f in failed:
        print("   %s: %s %s" % f)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
