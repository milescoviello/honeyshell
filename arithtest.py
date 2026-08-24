r"""Arithmetic, expr, and the escaped asterisk between them.

Forty-first coherence sweep. The axis is $(( )) -- srb.sh computes
HUGE_PAGES=$((1280 + $(nproc))) before it starts mining -- and it checks
against itself: $(( )), expr, let and (( )) all answer one question and
have to answer it the same way.

arith_eval handed the expression to Python's ast and evaluated that, so
every form bash has and Python does not silently became 0:

    $((0x1f))       0    should be 31
    $((017))        0    should be 15
    $((2#1010))     0    should be 10
    $((1 || 0))     0    should be 1
    $((1 ? 42 : 7)) 0    should be 42
    $((x = 3 + 4))  0    and x stayed unset
    n=5; $((n++))   0    and n stayed 5

That last one is the one that costs something: a counter that never
counts is an infinite loop in whatever script owns it, and `: $((i++))`
is how a shell loop counts. Replaced with a precedence-climbing
evaluator that handles the operator set and can write back.

Then expr, which was answering 6 for `expr 6 \* 7` -- and that turned out
not to be expr's fault. A backslashed metacharacter was being stripped to
a bare one and then globbed, so expr received the directory listing where
it should have received an asterisk:

    expr received: ['6', 'backup.sql', 'deploy.log', 'scripts', '7']

`echo \*` printed the directory too. `\?` and `a\*b` looked correct only
because nothing happened to match them. Escaped metacharacters are marked
during expansion now and the globber leaves them alone.

Reference measured on the guest, as root:

    $((0x1f)) 31   $((017)) 15   $((2#1010)) 10   $((1||0)) 1
    $((1 ? 42 : 7)) 42          $((x = 3 + 4)) -> 7 and x=7
    n=5; $((n++)) -> 5 then 6   n=5; $((++n)) -> 6 then 6
    n=5; $((n += 3)) -> 8 and n=8
    $((-7/2)) -3   $((7/-2)) -3   $((-7%2)) -1      (truncate toward zero)
    expr 6 \* 7 42   expr 10 / 3 3   expr length abcde 5   expr 3 = 3 1
    echo \* -> *   echo \? -> ?   echo a\*b -> a*b   echo * -> the files

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def case(script, want, rc=0):
    out, got_rc = run(script)
    eq("out: %s" % script[:44], out.strip(), want)
    eq("rc:  %s" % script[:44], got_rc, rc)


# -- the payload's own sum ----------------------------------------------

def t_hugepages():
    case("echo $((1280 + $(nproc)))", "1284")


# -- literals ------------------------------------------------------------

def t_bases():
    case("echo $((0x1f))", "31")
    case("echo $((0X1F))", "31")
    case("echo $((017))", "15")
    case("echo $((2#1010))", "10")
    case("echo $((16#ff))", "255")
    case("echo $((10))", "10")


# -- operators -----------------------------------------------------------

def t_arithmetic():
    case("echo $((7+3)) $((7-3)) $((7*3)) $((7/3)) $((7%3))", "10 4 21 2 1")
    case("echo $((2+3*4)) $(((2+3)*4))", "14 20")
    case("echo $((2**10))", "1024")
    case("echo $((-5 + 2))", "-3")


def t_division_truncates_toward_zero():
    case("echo $((-7/2)) $((7/-2)) $((-7%2)) $((7%-2))", "-3 -3 -1 1")


def t_comparison_and_logic():
    case("echo $((3 > 2)) $((3 < 2)) $((3 >= 3)) $((3 != 3))", "1 0 1 0")
    case("echo $((1 && 0)) $((1 || 0)) $((0 || 0)) $((1 && 1))", "0 1 0 1")
    case("echo $((!0)) $((!5))", "1 0")


def t_ternary():
    case("echo $((1 ? 42 : 7)) $((0 ? 42 : 7))", "42 7")
    case("n=3; echo $((n > 2 ? 100 : 200))", "100")


def t_bitwise():
    case("echo $((6 & 3)) $((6 | 3)) $((6 ^ 3)) $((1 << 4)) $((16 >> 2))",
         "2 7 5 16 4")


def t_divide_by_zero():
    out, _ = run("echo $((1/0))")
    check("bash's wording", "division by 0" in out, out)
    out, _ = run("echo $((1%0))")
    check("modulo too", "division by 0" in out, out)


# -- assignment writes back ----------------------------------------------

def t_increment():
    case("n=5; echo $((n++)) $n", "5 6")
    case("n=5; echo $((++n)) $n", "6 6")
    case("n=5; echo $((n--)) $n", "5 4")
    case("n=5; echo $((--n)) $n", "4 4")


def t_assignment():
    case("echo $((x = 3 + 4)) $x", "7 7")
    case("n=5; echo $((n += 3)) $n", "8 8")
    case("n=8; echo $((n -= 3)) $n", "5 5")
    case("n=5; echo $((n *= 3)) $n", "15 15")


def t_no_assignment_no_side_effect():
    case("n=5; echo $((n + 1)) $n", "6 5")


def t_a_counter_actually_counts():
    """`: $((i++))` is how a shell loop counts."""
    case('i=0; while [ $i -lt 3 ]; do printf "%s" "$i"; : $((i++)); done; '
         'echo', "012")


def t_double_paren_command():
    case("n=5; ((n++)); echo $n", "6")
    case('((1)); printf "%s " $?; ((0)); echo $?', "0 1")


def t_let():
    case('let "n = 6 * 7"; echo $n', "42")


# -- expr agrees with $(( )) ---------------------------------------------

def t_expr():
    case(r"expr 6 \* 7", "42")
    case("expr 10 + 5", "15")
    case("expr 10 / 3", "3")
    case("expr 10 % 3", "1")
    case("expr length abcde", "5")
    case("expr 3 = 3", "1")
    case("expr 3 = 4", "0", rc=1)


def t_expr_and_arith_agree():
    for a, op, b in (("6", "*", "7"), ("10", "+", "5"), ("10", "/", "3"),
                     ("10", "-", "4"), ("9", "%", "4")):
        e, _ = run("expr %s \\%s %s" % (a, op, b))
        s, _ = run("echo $((%s %s %s))" % (a, op, b))
        eq("expr and $(( )) agree on %s %s %s" % (a, op, b),
           e.strip(), s.strip())


# -- the escaped metacharacter that caused it ----------------------------

GT = "mkdir -p /tmp/gt; cd /tmp/gt; touch a.txt b.txt; "


def t_escaped_glob_is_literal():
    case(GT + r"echo \*", "*")
    case(GT + r"echo \?", "?")
    case(GT + r"echo a\*b", "a*b")
    case(GT + r"echo \[x\]", "[x]")


def t_unescaped_glob_still_globs():
    case(GT + "echo *", "a.txt b.txt")
    case(GT + "echo *.txt", "a.txt b.txt")
    case(GT + "echo ?.txt", "a.txt b.txt")


def t_no_marker_leaks_into_output():
    out, _ = run(GT + r"echo \* \? a\*b")
    check("no control character in the output",
          "\x01" not in out, repr(out))
    eq("and the words are right", out.strip(), "* ? a*b")


TESTS = [t_hugepages, t_bases, t_arithmetic,
         t_division_truncates_toward_zero, t_comparison_and_logic,
         t_ternary, t_bitwise, t_divide_by_zero, t_increment,
         t_assignment, t_no_assignment_no_side_effect,
         t_a_counter_actually_counts, t_double_paren_command, t_let,
         t_expr, t_expr_and_arith_agree, t_escaped_glob_is_literal,
         t_unescaped_glob_still_globs, t_no_marker_leaks_into_output]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
