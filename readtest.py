r"""Reading a list, and what a loop exits with.

Fortieth coherence sweep. `while read -r line; do ...; done < targets`
is how a script walks a list, and `read -p` / `read -t` are how it asks
a question. The axis is the read builtin and the loop around it.

One cause behind most of it: read's value-taking flags were not consumed,
so their argument stayed in the operand list and was read as a *variable
name*.

    read -d : v          assigned the line to a variable called ":"
                         and left $v empty
    read -p "Enter: " v  assigned it to "Enter:"
    read -t 1 v          assigned it to "1"

Each reported success. A script that prompts, or uses a delimiter, or
sets a timeout, got an empty variable out of a read that said it worked
-- and the variable it did fill has a name nothing will ever look at.

Four more in the same builtin:

  * -a filled a scalar with the first field instead of an array with all
    of them, so ${A[1]} was empty and ${#A[@]} was 0.
  * -n/-N were ignored, so `read -n2` consumed the whole line.
  * without -r, a backslash is supposed to quote the next character and a
    backslash-newline to continue the line. Both were passed through
    verbatim, so `read v` and `read -r v` returned the same string -- the
    one thing -r changes.

And one in the loop around it: a while/until loop exited with the status
of the *test* that ended it rather than the last command in its body. A
read loop is always ended by the read that hits EOF, so
`cmd | while read l; do ...; done && echo ok` never reached the ok.

Reference measured on the guest, as root:

    echo "a b c" | { read -a A; echo "${A[1]}"; }        b     (${#A[@]} 3)
    printf abcdef | { read -n2 v; echo "[$v]"; }         [ab]
    printf abcdef | { read -N3 v; echo "[$v]"; }         [abc]
    printf "ab:cd" | { read -d : v; echo "[$v]"; }       [ab]
    echo x | { read -p "Enter: " v; echo "[$v]"; }       [x]
    echo y | { read -t 1 v; echo "[$v]"; }               [y]
    printf 'a\tb\n' | { read v; echo "[$v]"; }           [atb]
    printf 'a\tb\n' | { read -r v; echo "[$v]"; }        [a\tb]
    printf "1\n2\n" | while read l; do echo L$l; done    L1 L2, rc 0
    while false; do :; done                              rc 0
    for i in 1; do false; done                           rc 1

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
    eq("out: %s" % script[:46], out.strip(), want)
    eq("rc:  %s" % script[:46], got_rc, rc)


# -- the plain forms, already right and pinned ---------------------------

def t_basic_read():
    case('echo hello | { read v; echo "[$v]"; }', "[hello]")
    case('echo hello | { read; echo "[$REPLY]"; }', "[hello]")
    case('echo "a b c" | { read x y; echo "[$x][$y]"; }', "[a][b c]")
    case('echo "a b c" | { read x y z; echo "[$x][$y][$z]"; }', "[a][b][c]")
    case('echo "a" | { read x y; echo "[$x][$y]"; }', "[a][]")
    case('printf "   x   \\n" | { read v; echo "[$v]"; }', "[x]")
    case('echo "a:b:c" | { IFS=: read x y z; echo "[$x][$y][$z]"; }',
         "[a][b][c]")


def t_eof_fails():
    case('printf "" | { read v; echo "rc=$?"; }', "rc=1")


# -- flags that take a value must consume it -----------------------------

def t_delimiter():
    case('printf "ab:cd" | { read -d : v; echo "[$v]"; }', "[ab]")


def t_prompt():
    case('echo x | { read -p "Enter: " v; echo "[$v]"; }', "[x]")


def t_timeout():
    case('echo y | { read -t 1 v; echo "[$v]"; }', "[y]")


def t_the_value_does_not_become_a_variable():
    """The flag's argument was being assigned to, under its own name."""
    out, _ = run('printf "ab:cd" | { read -d : v; echo "colon=[${:-}]"; }')
    check("nothing landed in a bogus name", "colon=[]" in out, out)
    out, _ = run('echo x | { read -p "Enter: " v; echo "[$Enter]"; }')
    eq("the prompt is not a variable", out.strip(), "[]")


def t_char_counts():
    case('printf abcdef | { read -n2 v; echo "[$v]"; }', "[ab]")
    case('printf abcdef | { read -N3 v; echo "[$v]"; }', "[abc]")
    case('printf abcdef | { read -n 2 v; echo "[$v]"; }', "[ab]")


def t_silent_still_reads():
    case('echo secret | { read -s v; echo "[$v]"; }', "[secret]")


# -- -a fills an array ---------------------------------------------------

def t_read_a():
    case('echo "a b c" | { read -a A; echo "${A[1]}"; }', "b")
    case('echo "a b c" | { read -a A; echo "${#A[@]}"; }', "3")
    case('echo "a b c" | { read -a A; echo "${A[@]}"; }', "a b c")


# -- -r is the difference between two answers ----------------------------

# printf "%s\n" hands the string through without interpreting it, which
# is the only way to get a literal backslash as far as read. Writing the
# input as printf "a\tb\n" instead makes printf eat the escape and tests
# nothing -- which is what the first version of these three did.
BSLASH = r'printf "%s\n" "a\tb"'
CONT = r'printf "%s\n%s\n" "a\\" "b"'


def t_backslash_handling():
    case(BSLASH + ' | { read v; echo "[$v]"; }', "[atb]")
    case(BSLASH + ' | { read -r v; echo "[$v]"; }', "[a\\tb]")


def t_line_continuation_without_r():
    out, _ = run(CONT + ' | { read v; echo "[$v]"; }')
    eq("the two lines join", out.strip(), "[ab]")


def t_r_and_no_r_differ():
    plain, _ = run(BSLASH + ' | { read v; echo "$v"; }')
    raw, _ = run(BSLASH + ' | { read -r v; echo "$v"; }')
    check("they are not the same answer", plain != raw,
          "%r == %r" % (plain, raw))


# -- echo, found while chasing the backslash tests -----------------------

def t_echo_does_not_interpret_without_e():
    """Found because a read -r test failed for the wrong reason: read had
    stored the backslash correctly and echo destroyed it on the way out."""
    out, _ = run('v="a\\tb"; echo "$v"')
    check("no tab appeared", "\t" not in out, repr(out))
    eq("the backslash survives", out.strip(), "a\\tb")


def t_echo_e_does_interpret():
    out, _ = run('v="a\\tb"; echo -e "$v"')
    check("a real tab", "\t" in out, repr(out))
    out, _ = run('echo -e "a\\nb"')
    eq("and a real newline", out.strip().split("\n"), ["a", "b"])


def t_echo_E_is_a_flag():
    out, _ = run('v="a\\tb"; echo -E "$v"')
    check("-E is not printed as a word", "-E" not in out, repr(out))
    eq("and the backslash survives", out.strip(), "a\\tb")


def t_echo_flags_bundle():
    out, _ = run('echo -ne "a\\tb"')
    check("-ne interprets", "\t" in out, repr(out))
    check("and suppresses the newline", not out.endswith("\n"), repr(out))
    out, _ = run('echo -n x')
    eq("-n alone", out, "x")


def t_echo_e_extras():
    out, _ = run('echo -e "abc\\cdef"')
    eq("\\c truncates", out, "abc")
    out, _ = run('echo -e "a\\x41b"')
    eq("hex escape", out.strip(), "aAb")


def t_a_backslash_survives_a_round_trip():
    """read it, echo it, and get the same bytes back."""
    out, _ = run(BSLASH + ' | { read -r v; echo "$v"; }')
    eq("unchanged", out.strip(), "a\\tb")


# -- the loop around it --------------------------------------------------

def t_while_read_walks_the_list():
    case('printf "1\\n2\\n3\\n" | while read l; do echo "L$l"; done',
         "L1\nL2\nL3")
    case('printf "a\\nb\\n" > /tmp/t; while read l; do echo "[$l]"; done '
         '< /tmp/t', "[a]\n[b]")


def t_loop_exits_with_its_body():
    case('printf "1\\n2\\n" | while read l; do echo "L$l"; done; echo "rc=$?"',
         "L1\nL2\nrc=0")
    case('printf "a\\n" | while read l; do echo "[$l]"; done && echo ok',
         "[a]\nok")
    case('while false; do :; done; echo rc=$?', "rc=0")
    case('for i in 1; do false; done; echo rc=$?', "rc=1")
    case('n=0; while [ $n -lt 1 ]; do n=1; false; done; echo rc=$?', "rc=1")
    case('n=0; until [ $n -ge 1 ]; do n=1; done; echo rc=$?', "rc=0")


def t_the_shape_a_script_walks_targets_with():
    case('printf "10.0.0.1\\n10.0.0.2\\n" > /tmp/tg; '
         'while read -r host; do echo "trying $host"; done < /tmp/tg '
         '&& echo done',
         "trying 10.0.0.1\ntrying 10.0.0.2\ndone")


TESTS = [t_echo_does_not_interpret_without_e, t_echo_e_does_interpret,
         t_echo_E_is_a_flag, t_echo_flags_bundle, t_echo_e_extras,
         t_a_backslash_survives_a_round_trip,
         t_basic_read, t_eof_fails, t_delimiter, t_prompt, t_timeout,
         t_the_value_does_not_become_a_variable, t_char_counts,
         t_silent_still_reads, t_read_a, t_backslash_handling,
         t_line_continuation_without_r, t_r_and_no_r_differ,
         t_while_read_walks_the_list, t_loop_exits_with_its_body,
         t_the_shape_a_script_walks_targets_with]


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
