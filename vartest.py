#!/usr/bin/env python3
"""What kind of variable is this, and who agrees?

bash keeps attributes on variables -- exported, readonly, integer -- and
five things report them: `env`, `export -p`, `declare -x`, `declare -p`,
and `readonly -p`. `export -p` and `declare -x` are the same builtin in
bash. Here they were two:

    export -p | wc -l      18
    declare -x | wc -l     33

-x was not a filter. `declare -x` printed every shell variable there is,
and printed each one as "declare --", so `declare -p PATH` described an
exported variable as unexported while `export -p` listed it three lines
further down its own output.

Underneath that, no attribute was tracked at all:

    readonly RO=1
    env | grep -c ^RO=     1        (the guest says 0)
    readonly -p            declare -x RO="1"
    RO=2; echo $?          0        (and the value became 2)

`readonly` was a straight alias for `export`. So it put the variable in
the environment, printed it with the wrong letter, and did not do the one
thing the attribute exists for: the guest answers "bash: RO: readonly
variable", leaves the value alone and exits 1, and refuses to unset it.
A script that marks something readonly and then checks is telling a shell
from a shell.

Reference output measured on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


def R(cmd, s):
    s._err = []
    out = s.run(cmd)
    return out or "", "".join(s._err), s.last_rc


# ---------------------------------------------------------------------------
# export -p and declare -x are one builtin
# ---------------------------------------------------------------------------
def t_declare_x_is_export_p():
    s = sh()
    a, b = R("export -p", s)[0], R("declare -x", s)[0]
    check("declare -x is export -p, line for line", a == b,
          "%d vs %d lines" % (len(a.splitlines()), len(b.splitlines())))
    check("and every line is a declare -x line",
          a and all(l.startswith("declare -x ") for l in a.splitlines()),
          next((l for l in a.splitlines()
                if not l.startswith("declare -x ")), "")[:50])
    # ...and the names in it are exactly what env shows, bar bash's own _.
    exported = {l.split()[2].split("=")[0] for l in a.splitlines()}
    envnames = {l.split("=")[0] for l in R("env", s)[0].splitlines()
                if "=" in l}
    check("export -p and env name the same variables",
          exported == envnames - {"_"},
          str(sorted(exported ^ (envnames - {"_"}))[:4]))


def t_declare_p_reports_the_attribute():
    s = sh()
    R("FOO=bar; export BAZ=qux; readonly RO=1; declare -i NUM=5", s)
    want = {"FOO": 'declare -- FOO="bar"',
            "BAZ": 'declare -x BAZ="qux"',
            "RO": 'declare -r RO="1"',
            "NUM": 'declare -i NUM="5"'}
    for name, line in want.items():
        got = R("declare -p %s" % name, s)[0].strip()
        check("declare -p %s says %s" % (name, line.split()[1]), got == line,
              "%r" % got)
    out, err, rc = R("declare -p NOSUCHVAR", s)
    check("an unknown name exits 1", rc == 1, "rc=%s" % rc)
    check("and says not found", "NOSUCHVAR: not found" in err, err[:50])
    # A variable that is exported has to show -x wherever it is printed.
    check("PATH is exported, so declare -p says -x",
          R("declare -p PATH", s)[0].startswith("declare -x PATH="),
          R("declare -p PATH", s)[0][:40])
    check("and export -p lists it too",
          any(l.startswith("declare -x PATH=")
              for l in R("export -p", s)[0].splitlines()), "missing")


def t_the_attribute_flags_filter():
    s = sh()
    R("FOO=bar; export BAZ=qux; readonly RO=1; declare -i NUM=5", s)
    x = R("declare -x", s)[0]
    check("declare -x has the exported one", "BAZ=" in x, "missing")
    check("and not the plain one", "FOO=" not in x, "FOO leaked in")
    r = R("declare -r", s)[0]
    check("declare -r has the readonly one", 'declare -r RO="1"' in r, r[:60])
    check("and only it", len(r.splitlines()) == 1, str(r.splitlines()[:3]))
    i = R("declare -i", s)[0]
    check("declare -i has the integer one", 'declare -i NUM="5"' in i, i[:60])
    check("readonly -p is the same as declare -r",
          R("readonly -p", s)[0] == r, "differs")
    # Bare declare lists everything, with each one's own letter.
    allv = R("declare", s)[0]
    check("bare declare lists them all",
          all(k + "=" in allv for k in ("FOO", "BAZ", "RO", "NUM")),
          "one missing")
    check("with the right letter on each",
          'declare -x BAZ="qux"' in allv and 'declare -- FOO="bar"' in allv,
          "wrong letters")


# ---------------------------------------------------------------------------
# readonly is an attribute, and it bites
# ---------------------------------------------------------------------------
def t_readonly_does_not_export():
    s = sh()
    R("readonly RO=1", s)
    check("readonly does not put it in the environment",
          R("env | grep -c '^RO='", s)[0].strip() == "0",
          R("env | grep '^RO='", s)[0][:40])
    check("nor in export -p", "RO=" not in R("export -p", s)[0], "leaked")
    check("readonly -p prints it with -r",
          R("readonly -p", s)[0].strip() == 'declare -r RO="1"',
          R("readonly -p", s)[0].strip()[:50])
    # It is a separate attribute from exported: a variable can be both.
    R("export -p >/dev/null; readonly PATH", s)
    # bash orders the letters i, r, x -- `declare -rx`, not `-xr`.
    check("a variable can be exported and readonly at once",
          R("declare -p PATH", s)[0].startswith("declare -rx PATH="),
          R("declare -p PATH", s)[0][:40])
    R("declare -i J=2; readonly J", s)
    check("and a readonly integer prints -ir",
          R("declare -p J", s)[0].strip() == 'declare -ir J="2"',
          R("declare -p J", s)[0].strip())


def t_a_readonly_refuses_to_change():
    s = sh()
    R("readonly RO=1", s)
    out, err, rc = R("RO=2", s)
    check("assigning to it exits 1", rc == 1, "rc=%s" % rc)
    check("with bash's message", "RO: readonly variable" in err, err[:60])
    check("and the value is untouched", R("echo $RO", s)[0].strip() == "1",
          R("echo $RO", s)[0].strip())
    out, err, rc = R("unset RO", s)
    check("unset exits 1 too", rc == 1, "rc=%s" % rc)
    check("saying it cannot unset it",
          "cannot unset: readonly variable" in err, err[:60])
    check("and it is still there", R("echo $RO", s)[0].strip() == "1",
          R("echo $RO", s)[0].strip())
    # declare -r on an existing one, then assign through declare.
    out, err, rc = R("declare -r RO2=9; declare RO2=3", s)
    check("declare cannot reassign a readonly either", rc == 1,
          "rc=%s" % rc)
    check("with the same message", "RO2: readonly variable" in err, err[:60])
    # A plain variable still assigns and still reports 0.
    out, _e, rc = R("X=5", s)
    check("an ordinary assignment still exits 0", rc == 0, "rc=%s" % rc)
    check("and takes", R("echo $X", s)[0].strip() == "5",
          R("echo $X", s)[0].strip())


def t_the_integer_attribute_still_computes():
    s = sh()
    R("declare -i n=5", s)
    check("declare -i evaluates its right-hand side",
          R("echo $n", s)[0].strip() == "5", R("echo $n", s)[0].strip())
    R("n=n+3", s)
    check("and keeps evaluating after that",
          R("echo $n", s)[0].strip() == "8", R("echo $n", s)[0].strip())
    check("declare -p still calls it an integer",
          R("declare -p n", s)[0].strip() == 'declare -i n="8"',
          R("declare -p n", s)[0].strip())
    R("m=5; m=m+3", s)
    check("a plain variable does not evaluate",
          R("echo $m", s)[0].strip() == "m+3", R("echo $m", s)[0].strip())


def t_export_n_takes_the_attribute_off():
    s = sh()
    R("export BAZ=qux", s)
    check("it is exported", R("env | grep -c '^BAZ='", s)[0].strip() == "1",
          R("env | grep '^BAZ='", s)[0][:30])
    check("and declare -p says so",
          R("declare -p BAZ", s)[0].startswith("declare -x BAZ="),
          R("declare -p BAZ", s)[0][:40])
    R("export -n BAZ", s)
    check("export -n takes it out of the environment",
          R("env | grep -c '^BAZ='", s)[0].strip() == "0",
          R("env | grep '^BAZ='", s)[0][:30])
    check("and declare -p drops the x",
          R("declare -p BAZ", s)[0].strip() == 'declare -- BAZ="qux"',
          R("declare -p BAZ", s)[0].strip())
    check("but the variable is still set",
          R("echo $BAZ", s)[0].strip() == "qux", R("echo $BAZ", s)[0].strip())
    check("and declare -x no longer lists it",
          "BAZ=" not in R("declare -x", s)[0], "still listed")


TESTS = [t_declare_x_is_export_p,
         t_declare_p_reports_the_attribute,
         t_the_attribute_flags_filter,
         t_readonly_does_not_export,
         t_a_readonly_refuses_to_change,
         t_the_integer_attribute_still_computes,
         t_export_n_takes_the_attribute_off]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
