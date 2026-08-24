#!/usr/bin/env python3
"""Diff our awk against the real one, on the box that has the real one.

The reference is whatever `awk` is on PATH. On the guest that is mawk 1.3.4,
which is exactly what our persona's package list claims, so the guest is the
authoritative place to run this.

This exists because the previous awk understood two shapes and silently printed
$0 for everything else -- so an unsupported program behaved like `cat` and
returned a confidently wrong answer. The first case below is verbatim from a
live actor on 2026-08-20 who wanted a CPU count and got 562 bytes of lscpu.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import awkemu                                                  # noqa: E402

LSCPU = ("Architecture:            x86_64\n"
         "  CPU op-mode(s):        32-bit, 64-bit\n"
         "  Byte Order:            Little Endian\n"
         "CPU(s):                  4\n"
         "  On-line CPU(s) list:   0-3\n"
         "Vendor ID:               GenuineIntel\n"
         "  Model name:            Intel(R) Xeon(R) CPU E5-2670 v2 @ 2.50GHz\n")

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          "deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash\n")

NUMS = "3 1\n10 2\n7 5\n2 9\n"
MIXED = "alpha 10 x\nbeta 2 y\ngamma 33 z\n"

# (name, awk args as a list, stdin)
CASES = [
    # --- the live one, and its neighbours
    ("live lscpu cpus", ["-F:", r'/^CPU\(s\):/ {gsub(/ /,"",$2); print $2}'],
     LSCPU),
    ("gsub on $0", ["-F:", r'/^CPU\(s\)/ {gsub(/ /,""); print}'], LSCPU),
    ("gsub count", ['{n = gsub(/ /, "_"); print n, $0}'], "a b c\n"),
    ("sub once", ['{sub(/a/, "X"); print}'], "banana\n"),
    ("sub with &", ['{sub(/an/, "[&]"); print}'], "banana\n"),
    ("gsub with escaped amp", [r'{gsub(/a/, "\&"); print}'], "banana\n"),

    # --- fields
    ("print field", ['{print $2}'], MIXED),
    ("print NF", ['{print NF}'], MIXED),
    ("print NR and $0", ['{print NR": "$0}'], MIXED),
    ("last field", ['{print $NF}'], MIXED),
    ("field assign rebuilds", ['{$2 = "Z"; print}'], MIXED),
    ("field beyond NF extends", ['{$5 = "e"; print; print NF}'], "a b\n"),
    ("NF assign truncates", ['{NF = 2; print; print NF}'], MIXED),
    ("OFS on rebuild", ['BEGIN {OFS="-"} {$1=$1; print}'], MIXED),
    ("dollar zero assign", ['{$0 = "x y z"; print NF, $2}'], "ignored\n"),
    ("FS single char", ["-F:", '{print $1, $3}'], PASSWD),
    ("FS regex", ["-F", "[:/]", '{print $1, $NF}'], PASSWD),
    ("FS tab literal", ["-F", "\t", '{print NF}'], "a\tb\tc\n"),

    # --- patterns
    ("regex pattern", ['/deploy/ {print $1}'], PASSWD),
    ("negated match", ['$0 !~ /nologin/ {print $1}'], PASSWD),
    ("expression pattern", ["-F:", '$3 > 100 {print $1}'], PASSWD),
    ("compound pattern", ["-F:", '$3 > 0 && /bash/ {print $1}'], PASSWD),
    ("bare regex value", ['{print /alpha/ ? "hit" : "miss"}'], MIXED),
    ("NR range", ['NR==2, NR==3 {print NR}'], MIXED),
    ("pattern no action", ['/beta/'], MIXED),

    # --- BEGIN/END and accumulation
    ("sum END", ['{s += $2} END {print s}'], MIXED),
    ("max END", ['$2 > m {m = $2} END {print m}'], MIXED),
    ("count lines", ['END {print NR}'], MIXED),
    ("begin only", ['BEGIN {print "hello"}'], ""),
    ("begin ofs ors", ['BEGIN {OFS=","; ORS=";"} {print $1, $2}'], MIXED),
    ("average", ['{n++; t += $2} END {if (n) printf "%.2f\\n", t/n}'], MIXED),

    # --- control flow
    ("if else", ['{if ($2 > 5) print "big"; else print "small"}'], MIXED),
    ("while loop", ['{i = 1; while (i <= NF) {print $i; i++}}'], "a b c\n"),
    ("for loop", ['{for (i = NF; i >= 1; i--) printf "%s ", $i; print ""}'],
     "a b c\n"),
    ("next skips", ['/beta/ {next} {print $1}'], MIXED),
    ("exit in body", ['NR == 2 {exit} {print $1}'], MIXED),
    ("exit code", ['BEGIN {exit 3}'], ""),
    ("break", ['{for (i=1;i<=NF;i++) {if ($i=="b") break; print $i}}'],
     "a b c\n"),
    ("continue", ['{for (i=1;i<=NF;i++) {if ($i=="b") continue; print $i}}'],
     "a b c\n"),

    # --- arrays
    ("array count", ['{c[$1]++} END {for (k in c) print k, c[k]}'],
     "x\ny\nx\n"),
    ("array in test", ['{a[$1]=1} END {print ("x" in a), ("q" in a)}'],
     "x\ny\n"),
    ("delete element", ['{a[$1]=1} END {delete a["x"]; print ("x" in a)}'],
     "x\ny\n"),
    ("split into array", ['{n = split($0, p, ":"); print n, p[1], p[n]}'],
     "a:b:c\n"),
    ("split default fs", ['{n = split($0, p); print n, p[2]}'], "a b c\n"),
    ("subsep", ['BEGIN {a[1,2]=5; for (k in a) {split(k,q,SUBSEP);'
                ' print q[1], q[2], a[1,2]}}'], ""),

    # --- string functions
    ("length no arg", ['{print length}'], "hello\n"),
    ("length of expr", ['{print length($1)}'], "hello world\n"),
    ("substr two arg", ['{print substr($0, 3)}'], "abcdef\n"),
    ("substr three arg", ['{print substr($0, 2, 3)}'], "abcdef\n"),
    ("substr clamp", ['{print substr($0, 0, 3)}'], "abcdef\n"),
    ("index", ['{print index($0, "cd")}'], "abcdef\n"),
    ("toupper tolower", ['{print toupper($1), tolower($1)}'], "MiXeD\n"),
    ("match sets RSTART", ['{print match($0, /cd/), RSTART, RLENGTH}'],
     "abcdef\n"),
    ("match no hit", ['{print match($0, /zz/), RSTART, RLENGTH}'], "abcdef\n"),
    ("sprintf", ['{print sprintf("[%5s|%-5s]", $1, $1)}'], "ab\n"),
    ("int truncates", ['BEGIN {print int(3.9), int(-3.9)}'], ""),

    # --- printf
    ("printf d s", ['{printf "%d/%s\\n", $2, $1}'], MIXED),
    ("printf width", ['{printf "[%5d][%-5s]\\n", $2, $1}'], MIXED),
    ("printf float", ['BEGIN {printf "%.3f|%e|%g\\n", 3.14159, 1234.5, 0.0001}'],
     ""),
    ("printf percent", ['BEGIN {printf "100%%\\n"}'], ""),
    ("printf reuse", ['BEGIN {printf "%s-", "a", "b"; print ""}'], ""),
    ("printf char", ['BEGIN {printf "%c%c\\n", 65, "BC"}'], ""),
    ("printf zero pad", ['BEGIN {printf "%05.1f\\n", 3.14159}'], ""),

    # --- numbers and comparison
    ("string vs num compare", ['{if ($1 == 10) print "numeric"; else print "string"}'],
     "10\n"),
    ("leading zero num", ['{print ($1 == 0) ? "zero" : "nonzero"}'], "0.0\n"),
    ("concat vs add", ['BEGIN {print 1 " " 2, 1 + 2}'], ""),
    ("uninitialised", ['BEGIN {print x + 0, "[" x "]"}'], ""),
    ("modulo", ['BEGIN {print 7 % 3, -7 % 3}'], ""),
    ("exponent", ['BEGIN {print 2 ^ 10}'], ""),
    ("division float", ['BEGIN {print 10 / 4}'], ""),
    ("big int format", ['BEGIN {print 1000000, 1e6, 0.1 + 0.2}'], ""),
    ("increment", ['BEGIN {i = 5; print i++, i, ++i, i}'], ""),
    ("compound assign", ['BEGIN {x = 10; x += 5; x *= 2; print x}'], ""),
    ("unary not", ['BEGIN {print !0, !1, !"", !"a"}'], ""),
    ("ternary", ['BEGIN {print (1 ? "y" : "n"), (0 ? "y" : "n")}'], ""),

    # --- -v and variables
    ("dash v", ["-v", "n=7", 'BEGIN {print n + 1}'], ""),
    ("dash v string", ["-v", "s=hi", 'BEGIN {print s "!"}'], ""),
    ("FS via -v", ["-v", "FS=:", '{print $1}'], PASSWD),

    # --- user functions
    ("user function", ['function dbl(x) {return x * 2} BEGIN {print dbl(21)}'],
     ""),
    ("recursive function",
     ['function f(n) {return n <= 1 ? 1 : n * f(n-1)} BEGIN {print f(5)}'], ""),

    # --- pipelines attackers actually write
    ("cut-like", ["-F:", '{print $1}'], PASSWD),
    ("grep -c like", ['/bash/ {n++} END {print n+0}'], PASSWD),
    ("column sum", ['{s+=$1} END {printf "%d\\n", s}'], NUMS),
    ("sort keys stable", ['{print $2, $1}'], NUMS),
    ("uniq-ish", ['!seen[$0]++'], "a\nb\na\nc\nb\n"),
    ("field swap", ['{t=$1; $1=$2; $2=t; print}'], NUMS),
    ("strip whitespace", ['{gsub(/^[ \\t]+|[ \\t]+$/, ""); print "["$0"]"}'],
     "   padded   \n"),
    ("count words", ['{w += NF} END {print w}'], MIXED),
    ("meminfo style", ['/^MemTotal/ {print $2}'], "MemTotal:  2035124 kB\n"),
    ("df style", ['NR>1 {print $5}'], "H U A C M\n/dev/sda1 1 2 7% /\n"),
]


def real_awk(args, stdin):
    try:
        p = subprocess.run(["awk"] + args, input=stdin, capture_output=True,
                           text=True, timeout=10)
        return p.stdout, p.stderr.strip() != "", p.returncode
    except (OSError, subprocess.TimeoutExpired):
        return None, False, None


def ours(args, stdin):
    fs = None
    prog = None
    assigns = {}
    i = 0
    while i < len(args):
        x = args[i]
        if x.startswith("-F"):
            fs = x[2:] if x[2:] else args[i + 1]
            if not x[2:]:
                i += 1
            i += 1
            continue
        if x.startswith("-v"):
            spec = x[2:] if x[2:] else args[i + 1]
            if not x[2:]:
                i += 1
            k, _, v = spec.partition("=")
            assigns[k] = v
            i += 1
            continue
        if prog is None:
            prog = x
        i += 1
    records = stdin.split("\n")
    if records and records[-1] == "":
        records.pop()
    out, err, rc = awkemu.run_awk(prog, records, fs=fs, assigns=assigns)
    return out, err.strip() != "", rc


def main():
    verbose = "-v" in sys.argv
    ver = subprocess.run(["awk", "-W", "version"], capture_output=True,
                         text=True)
    which = (ver.stdout or ver.stderr).splitlines()[0] if (
        ver.stdout or ver.stderr) else "unknown awk"
    print("reference: %s\n" % which)
    ok = bad = skipped = 0
    for name, args, stdin in CASES:
        r_out, r_err, r_rc = real_awk(args, stdin)
        if r_out is None:
            skipped += 1
            continue
        o_out, o_err, o_rc = ours(args, stdin)
        same = (r_out == o_out) and (r_rc == o_rc) and (r_err == o_err)
        if same:
            ok += 1
            if verbose:
                print("  ok   %-26s %r" % (name, o_out[:50]))
        else:
            bad += 1
            print("  DIFF %-26s" % name)
            print("       argv %r  stdin %r" % (args, stdin[:40]))
            print("       real out=%r rc=%s err=%s" % (r_out[:90], r_rc, r_err))
            print("       ours out=%r rc=%s err=%s" % (o_out[:90], o_rc, o_err))
    print()
    print("=" * 58)
    print("%d/%d match  (%d differ, %d skipped)"
          % (ok, ok + bad, bad, skipped))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
