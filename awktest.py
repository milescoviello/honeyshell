#!/usr/bin/env python3
"""Diff our awk against the real one, on the box that has the real one.

The reference is whatever `awk` is on PATH. On the guest that is mawk 1.3.4,
which is exactly what our persona's package list claims, so the guest is the
authoritative place to run this.

Read that paragraph as a warning, because the differential half of this file
is only as good as the binary it runs against, and on the dev host that
binary is **gawk 5.2.1**. Every case below then passes while proving the
wrong thing: our awk was matched to gawk in the places the two implementations
disagree, on a box where `awk --version`, `readlink -f /usr/bin/awk`,
`dpkg -S` and update-alternatives all say mawk (verbannertest.py and
alttest.py pin that identity). The tell was `awk 'BEGIN{print "\x41"}'`,
which prints A on mawk and here printed "x41" plus a warning worded in
gawk's own style -- a gawk diagnostic emitted by a box with no gawk on it.
Six behaviours were wrong the same way; see MAWK below.

So the MAWK table does not diff against anything. It pins output measured on
the guest's mawk 1.3.4 by hand, and it is the only half of this file that
means anything when the local awk is not mawk. Put mawk-specific behaviour
there, never in CASES.

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
UPTIME = (" 06:39:19 up 5 days, 11:18,  7 users,  "
          "load average: 6.35, 6.73, 7.12\n")

CASES = [
    # --- the live one, and its neighbours
    ("live lscpu cpus", ["-F:", r'/^CPU\(s\):/ {gsub(/ /,"",$2); print $2}'],
     LSCPU),
    ("gsub on $0", ["-F:", r'/^CPU\(s\)/ {gsub(/ /,""); print}'], LSCPU),
    ("gsub count", ['{n = gsub(/ /, "_"); print n, $0}'], "a b c\n"),
    ("sub once", ['{sub(/a/, "X"); print}'], "banana\n"),
    ("sub with &", ['{sub(/an/, "[&]"); print}'], "banana\n"),
    # `gsub(/a/, "\&")` is deliberately NOT here. It is one of the cases
    # where gawk and mawk disagree -- gawk drops the backslash and prints
    # banana, mawk keeps it and prints b&n&n& -- so diffing it turns green
    # or red purely on which awk the host has. It is pinned against the
    # measured mawk output in MAWK instead.

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

    # --- a field separator with a group in it.
    # re.split() hands capture groups back as fields, so an FS containing
    # a group put the separators themselves into the record. 203.0.113.83
    # ran the first of these against this box on 2026-09-02 while
    # fingerprinting it for a miner: real awk answers "5 days", this one
    # answered " up ", and NF was 11 against a real 6. Bare alternation,
    # single characters, multi-character strings and bracket classes were
    # all already right, which is how it went unnoticed.
    ("FS group, the live one",
     ["-F", "( up |,|load)", '{print $2}'], UPTIME),
    ("FS group, NF", ["-F", "( up |,|load)", '{print NF}'], UPTIME),
    ("FS group alternation", ["-F", "(a|b)", '{print $2}'], "xaybz\n"),
    ("FS bare alternation", ["-F", "a|b", '{print $2}'], "xaybz\n"),
    ("FS nested groups", ["-F", "((1)|(2))", '{print NF, $2}'], "a1b2c\n"),
    ("FS group, every field",
     ["-F", "( up |,|load)", '{for (i = 1; i <= NF; i++) print i "[" $i "]"}'],
     UPTIME),
    ("split() with a group",
     ['{n = split($0, A, /( up |,)/); print n, A[2]}'], UPTIME),
    ("FS group that can match empty",
     ["-F", "(x*)", '{print NF}'], "abc\n"),
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


# ---------------------------------------------------------------- MAWK
# Absolute expectations, each one measured by hand on the guest's mawk
# 1.3.4 20250131. These do not diff against the local awk: on a host where
# that is gawk they would assert gawk's answer, which is the bug this table
# exists to stop from coming back.
MAWK_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/root", "USER": "root",
            "N": "7", "LEADZERO": "007", "_": "/usr/bin/awk"}

# (name, program, stdin, want_out, want_err, want_rc)
MAWK = [
    # -- escapes. mawk has \x and takes at most two hex digits; an escape it
    #    does not know keeps BOTH characters and is silent, where gawk drops
    #    the backslash and warns.
    ("hex escape", r'BEGIN{print "\x41\x42"}', "", "AB\n", "", 0),
    ("hex stops at 2 digits", r'BEGIN{print "\x414"}', "", "A4\n", "", 0),
    ("hex one digit", r'BEGIN{print "\x9z"}', "", "\tz\n", "", 0),
    ("hex either case", r'BEGIN{print "\x4a\x4A"}', "", "JJ\n", "", 0),
    ("hex with no digits", r'BEGIN{print "a\xzb"}', "", "a\\xzb\n", "", 0),
    ("unknown escape kept", r'BEGIN{print "a\qb"}', "", "a\\qb\n", "", 0),
    ("octal escape", r'BEGIN{print "\101"}', "", "A\n", "", 0),
    ("hex inside a regex", r'/\x41/{print "matched"}', "A\n",
     "matched\n", "", 0),
    # A bare & in a gsub replacement is the matched text and \& is a literal
    # one. Keeping the backslash is what makes this come out right, and it
    # is the case a gawk-shaped "fix" to the escape lexer broke.
    ("gsub escaped ampersand", r'{gsub(/a/, "\&"); print}', "banana\n",
     "b&n&n&\n", "", 0),
    ("gsub bare ampersand", r'{gsub(/a/, "&"); print}', "banana\n",
     "banana\n", "", 0),

    # -- CONVFMT governs every number->string conversion except print, and
    #    integers bypass it.
    ("CONVFMT on concat", r'BEGIN{CONVFMT="%.2g"; x=3.14159; print x ""}',
     "", "3.1\n", "", 0),
    ("CONVFMT building a string",
     r'BEGIN{CONVFMT="%.3g"; x=1/3; y="v" x; print y}', "", "v0.333\n", "", 0),
    ("CONVFMT skips integers", r'BEGIN{CONVFMT="%.2g"; x=100; print x ""}',
     "", "100\n", "", 0),
    # 0.1+0.2 is a useless value to test this with: %.6g and %.2g both
    # render it "0.3", so the case passed before CONVFMT was honoured at all.
    ("CONVFMT on a subscript",
     r'BEGIN{CONVFMT="%.2g"; a[3.14159]=1; for (k in a) print k}',
     "", "3.1\n", "", 0),
    ("subscript default CONVFMT",
     r'BEGIN{a[3.14159]=1; for (k in a) print k}', "", "3.14159\n", "", 0),
    ("subscript integer bare",
     r'BEGIN{CONVFMT="%.2g"; a[100]=1; for (k in a) print k}',
     "", "100\n", "", 0),
    ("CONVFMT through SUBSEP",
     r'BEGIN{CONVFMT="%.2g"; a[3.14159,2.71828]=1; '
     r'for (k in a) {split(k,pp,SUBSEP); print pp[1]"/"pp[2]}}',
     "", "3.1/2.7\n", "", 0),
    # A CONVFMT that is not a format string is ignored rather than fatal.
    ("CONVFMT set numeric", r'BEGIN{CONVFMT=1; print 3.14159 ""}',
     "", "3.14159\n", "", 0),

    # -- OFMT governs print, and only for a non-integral number.
    ("OFMT on print", r'BEGIN{OFMT="%.2f"; print 3.14159}', "",
     "3.14\n", "", 0),
    ("OFMT skips integers", r'BEGIN{OFMT="%.2f"; print 42}', "", "42\n", "", 0),
    ("OFMT not for concat", r'BEGIN{OFMT="%.2f"; print 3.14159 ""}', "",
     "3.14159\n", "", 0),
    ("OFMT set numeric", r'BEGIN{OFMT=1; print 3.14159}', "",
     "3.14159\n", "", 0),

    # -- RS. More than one character is a regex in mawk; before this it was
    #    not honoured at all, so RS=";;" left the file as one record and
    #    `{print $0}` echoed the whole thing back with NR=1.
    ("RS multi-char", r'BEGIN{RS=";;"}{print NR"["$0"]"}END{print "NR="NR}',
     "a;;b;;c", "1[a]\n2[b]\n3[c]\nNR=3\n", "", 0),
    ("RS trailing separator", r'BEGIN{RS=";;"}END{print "NR="NR}', "a;;b;;",
     "NR=2\n", "", 0),
    ("RS as a regex", r'BEGIN{RS="[0-9]+"}END{print "NR="NR}', "a1b22c",
     "NR=3\n", "", 0),
    # RS=":" leaves the newline inside the record, because the newline is
    # not the separator any more: the last record here is "c\n".
    ("RS single char keeps newline", r'BEGIN{RS=":"}{print NR"["$0"]"}',
     "a:b:c\n", "1[a]\n2[b]\n3[c\n]\n", "", 0),
    ("RS paragraph mode",
     r'BEGIN{RS=""}{print NR"["$0"]"}END{print "NR="NR}', "a\nb\n\nc\nd\n",
     "1[a\nb]\n2[c\nd]\nNR=2\n", "", 0),
    # In paragraph mode a newline separates fields as well as records.
    ("RS paragraph splits fields", r'BEGIN{RS=""}{print NR" NF="NF}',
     "a\nb\n\nc\n", "1 NF=2\n2 NF=1\n", "", 0),
    ("RS paragraph runs of blanks", r'BEGIN{RS=""}END{print "NR="NR}',
     "a\n\n\n\nb\n", "NR=2\n", "", 0),
    ("RS paragraph leading blanks", r'BEGIN{RS=""}{print NR"["$0"]"}',
     "\n\na\n\nb\n", "1[a]\n2[b]\n", "", 0),
    ("RS default drops trailing", r'END{print "NR="NR}', "a\nb\n",
     "NR=2\n", "", 0),
    ("RS default no trailing", r'END{print "NR="NR}', "a\nb",
     "NR=2\n", "", 0),
    # DEVIATION, measured and pinned so it reads as known rather than
    # untested: mawk reads one record at a time, so an RS assigned in a rule
    # body applies from the next record and mawk gives three records here
    # ("a:b", "c", "d\n"). This emulator reads RS once, after BEGIN, and
    # gives two. Matching mawk needs a streaming reader; no program seen on
    # this box has ever set RS outside BEGIN. See _rs_split in awkemu.py.
    ("RS set in a rule body (deviation)",
     r'NR==1{RS=":"}{print NR"["$0"]"}', "a:b\nc:d\n",
     "1[a:b]\n2[c:d]\n", "", 0),

    # -- ENVIRON. mawk populates it; this emulator did not, so a one-liner
    #    like `awk 'BEGIN{print ENVIRON["HOME"]}'` -- which appears in recon
    #    precisely because it needs no shell -- printed an empty line while
    #    printenv, env and $HOME all answered.
    ("ENVIRON lookup", r'BEGIN{print ENVIRON["HOME"]}', "", "/root\n", "", 0),
    ("ENVIRON underscore is awk", r'BEGIN{print ENVIRON["_"]}', "",
     "/usr/bin/awk\n", "", 0),
    ("ENVIRON is populated", r'BEGIN{print (length(ENVIRON)>3)}', "",
     "1\n", "", 0),
    # Values are strnum: they compare numerically when they look like a
    # number, leading zeros and all.
    ("ENVIRON value is strnum", r'BEGIN{print (ENVIRON["N"]==7)}', "",
     "1\n", "", 0),
    ("ENVIRON strnum leading zeros",
     r'BEGIN{print (ENVIRON["LEADZERO"]==7)}', "", "1\n", "", 0),
    ("ENVIRON missing key", r'BEGIN{print ENVIRON["NOPEXYZ"] "x"}', "",
     "x\n", "", 0),
    # Reading a missing key must not create it.
    ("ENVIRON in does not create", r'BEGIN{print ("NOPEXYZ" in ENVIRON)}',
     "", "0\n", "", 0),
    ("ENVIRON is writable", r'BEGIN{ENVIRON["Z"]="q"; print ENVIRON["Z"]}',
     "", "q\n", "", 0),

    # -- An undefined function is fatal at parse time, so nothing runs and
    #    nothing is printed. mawk notices at EOF and names the line its
    #    counter has reached: newlines in the program, plus two.
    ("undefined function is fatal", r'BEGIN{print "hi"} {print foo()}', "",
     "", "awk: line 2: function foo never defined\n", 2),
    ("undefined function 2 lines", 'BEGIN{x=1}\nBEGIN{foo()}', "",
     "", "awk: line 3: function foo never defined\n", 2),
    ("undefined function 3 lines",
     'BEGIN{x=1}\nBEGIN{y=2}\nBEGIN{foo()}', "",
     "", "awk: line 4: function foo never defined\n", 2),
    # A trailing newline counts, which is why this cannot rstrip the program.
    ("undefined function trailing nl", 'BEGIN{foo()}\n', "",
     "", "awk: line 3: function foo never defined\n", 2),
    ("undefined functions both named", r'BEGIN{foo(); bar()}', "",
     "", "awk: line 2: function bar never defined\n"
         "awk: line 2: function foo never defined\n", 2),
    ("defined function still runs",
     r'function f(x){return x*2} BEGIN{print f(21)}', "", "42\n", "", 0),
]


def mawk_run(prog, stdin):
    """Same shape as the shell's call: records split on newline, plus the
    raw text, because RS re-splitting needs the trailing newline back."""
    records = stdin.split("\n")
    if records and records[-1] == "":
        records.pop()
    return awkemu.run_awk(prog, records, env=MAWK_ENV, raw=stdin)


def main():
    verbose = "-v" in sys.argv
    ver = subprocess.run(["awk", "-W", "version"], capture_output=True,
                         text=True)
    which = (ver.stdout or ver.stderr).splitlines()[0] if (
        ver.stdout or ver.stderr) else "unknown awk"
    print("reference: %s" % which)
    if "mawk" not in which.lower():
        # Not fatal: the MAWK table below is measured, not diffed, so it is
        # still meaningful here. Loud, because a green run of CASES against
        # gawk says nothing about a box that claims mawk.
        print("NOTE: reference is not mawk -- the %d CASES below diff against\n"
              "      the wrong implementation. Only the %d MAWK cases are\n"
              "      authoritative on this host. Run on the guest to use both."
              % (len(CASES), len(MAWK)))
    print()
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
    m_ok = m_bad = 0
    for name, prog, stdin, w_out, w_err, w_rc in MAWK:
        got = mawk_run(prog, stdin)
        if got == (w_out, w_err, w_rc):
            m_ok += 1
            if verbose:
                print("  ok   %-34s %r" % (name, got[0][:40]))
        else:
            m_bad += 1
            print("  FAIL %-34s" % name)
            print("       prog  %r  stdin %r" % (prog, stdin[:40]))
            print("       want  %r" % ((w_out, w_err, w_rc),))
            print("       got   %r" % (got,))
    print()
    print("=" * 58)
    print("%d/%d match vs the reference awk  (%d differ, %d skipped)"
          % (ok, ok + bad, bad, skipped))
    print("%d/%d match mawk 1.3.4 measured by hand  (%d differ)"
          % (m_ok, m_ok + m_bad, m_bad))
    return 1 if (bad or m_bad) else 0


if __name__ == "__main__":
    sys.exit(main())
