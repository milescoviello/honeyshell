#!/usr/bin/env python3
"""Does `exit` end the shell from inside a loop, a branch, a case, a function?

Found by a live attacker, not by a sweep.

On 2026-09-06 at 03:12, 203.0.113.74 -- SSH-2.0-Go, one connection per
guess, spaced about 105 seconds apart -- landed on root/123456 and ran an
11,956-character host-fingerprinting script. Every fact it wanted was
gathered through a fallback chain shaped like this:

    uname=$(for c in uname /bin/uname /usr/bin/uname 'busybox uname' \
                     'toybox uname'; do
              v=$($c -s -v -n -m 2>/dev/null) && [ -n "$v" ] &&
                { printf '%s\n' "$v"; exit; }
            done
            IFS= read -r v < /proc/version && printf '%s\n' "$v")

Try each candidate; the first one that answers prints and exits. A real
box gives one line. This box gave four -- one per candidate that worked
-- and then appended /proc/version on top, because the `exit` never ended
the loop. `arch` came back as four copies of x86_64 followed by the
literal string `unknown`.

The cause is one line in run(). `exit` sets a flag, and run() restored
that flag whenever it was re-entered, on the grounds that `$( )` and
`( )` are subshells whose exit must not end the calling script. True --
but a loop body, an if branch, a case arm and a function body all
re-enter run() too, and none of them is a subshell. The flag was thrown
away the moment the body returned, so the loop tested a flag that had
just been cleared and carried on.

Measured against bash on the guest. Everything on the left ends the
shell; the middle column is what this box did:

    if true; then exit; fi          ran on
    for i in 1; do exit; done       ran every iteration
    while :; do exit; done          ran to MAX_LOOP -- 2000 iterations
    until [ .. ]; do exit; done     ran to MAX_LOOP
    for ((;;)) { exit; }            ran to MAX_LOOP
    case x in x) exit;; esac        ran on
    f() { exit; }; f                ran on
    { exit; }                       correct already
    ( exit )                        correct already -- a subshell
    $( exit )                       correct already -- a subshell

The three that were already right are the ones the original rule was
written for, which is why this survived: the rule is correct for
subshells and was being applied to everything.

`case` needed a second fix beside that one. _run_list checks brk, cont,
ret and exiting after a compound statement and did not check them after a
case, so `case x in x) exit;; esac; echo after` ran the echo -- and so
did the break, continue and return forms.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user="root")
    s.exec_mode = True
    return s


def run(script):
    s = sh()
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return out, err, s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def lines(script):
    return [x for x in run(script)[0].splitlines() if x != ""]


# -- every in-shell body, measured against bash ---------------------------

BODIES = [
    ("if", "if true; then echo in; exit; fi; echo AFTER"),
    ("for", "for i in 1; do echo in; exit; done; echo AFTER"),
    ("while", "while :; do echo in; exit; done; echo AFTER"),
    ("until", "i=0; until [ $i -gt 2 ]; do echo in; exit; done; echo AFTER"),
    ("case", "case x in x) echo in; exit;; esac; echo AFTER"),
    ("group", "{ echo in; exit; }; echo AFTER"),
    ("function", "f() { echo in; exit; }; f; echo AFTER"),
    ("nested for", "for i in 1 2; do for j in a b; do echo in; exit; done; "
                   "echo INNER; done; echo AFTER"),
    ("elif", "if false; then echo no; elif true; then echo in; exit; fi; "
             "echo AFTER"),
    ("else", "if false; then echo no; else echo in; exit; fi; echo AFTER"),
]


def t_exit_ends_the_shell_from_every_in_shell_body():
    for label, script in BODIES:
        eq("%s: only the body ran" % label, lines(script), ["in"])


def t_a_subshell_exit_does_not_end_the_caller():
    """The rule the original code was written for, still true."""
    eq("( exit ) carries on", lines("( echo in; exit ); echo AFTER"),
       ["in", "AFTER"])
    eq("$( exit ) carries on",
       lines("v=$(echo in; exit); echo \"$v\"; echo AFTER"),
       ["in", "AFTER"])
    eq("a subshell's rc still arrives",
       run("(exit 3); echo rc=$?")[0].strip(), "rc=3")
    eq("$(exit 5) rc", run("v=$(exit 5); echo rc=$?")[0].strip(), "rc=5")


def t_the_loop_stops_at_the_first_iteration():
    """A while loop with an exit in it used to run to MAX_LOOP."""
    for label, script in (
            ("while", "while :; do echo x; exit; done"),
            ("until", "until false; do echo x; exit; done"),
            ("for", "for i in 1 2 3 4 5; do echo x; exit; done"),
            ("c-style", "for ((i=0;i<5;i++)); do echo x; exit; done")):
        eq("%s: one iteration" % label, lines(script), ["x"])


def t_break_and_continue_still_work():
    """Adjacent control flow that must not have moved."""
    eq("break", lines("for i in 1 2 3; do echo $i; break; done; echo AFTER"),
       ["1", "AFTER"])
    eq("continue",
       lines("for i in 1 2 3; do [ $i = 2 ] && continue; echo $i; done"),
       ["1", "3"])
    eq("break out of a case arm",
       lines("for i in 1 2 3; do case $i in 2) break;; esac; echo $i; done; "
             "echo AFTER"), ["1", "AFTER"])
    eq("continue from a case arm",
       lines("for i in 1 2 3; do case $i in 2) continue;; esac; echo $i; "
             "done"), ["1", "3"])


def t_return_leaves_the_function_and_not_the_shell():
    eq("return ends the function",
       lines("f() { echo in; return; echo no; }; f; echo AFTER"),
       ["in", "AFTER"])
    eq("return carries its status",
       run("f() { return 4; }; f; echo rc=$?")[0].strip(), "rc=4")
    eq("return from a case arm inside a function",
       lines("f() { case x in x) return;; esac; echo no; }; f; echo AFTER"),
       ["AFTER"])


def t_exit_carries_its_status_out_of_a_body():
    for label, script in (
            ("for", "for i in 1; do exit 7; done"),
            ("while", "while :; do exit 7; done"),
            ("if", "if true; then exit 7; fi"),
            ("case", "case x in x) exit 7;; esac"),
            ("function", "f() { exit 7; }; f")):
        eq("%s: rc" % label, run(script)[2], 7)


# -- the shape that found it ----------------------------------------------

FALLBACK = (
    "v=$(for c in uname /bin/uname /usr/bin/uname 'busybox uname' "
    "'toybox uname'; do "
    "r=$($c -s 2>/dev/null) && [ -n \"$r\" ] && "
    "{ printf '%s\\n' \"$r\"; exit; }; done; "
    "printf '%s\\n' fallback); printf '%s\\n' \"$v\""
)


def t_the_fallback_chain_answers_once():
    """203.0.113.74's shape: first candidate that works wins, alone."""
    eq("one line, and it is uname's", lines(FALLBACK), ["Linux"])


def t_the_fallback_falls_back_when_nothing_answers():
    script = ("v=$(for c in nosuchcmd alsomissing; do "
              "r=$($c 2>/dev/null) && [ -n \"$r\" ] && "
              "{ printf '%s\\n' \"$r\"; exit; }; done; "
              "printf '%s\\n' fallback); printf '%s\\n' \"$v\"")
    eq("the tail runs when the loop finds nothing", lines(script),
       ["fallback"])


def t_arch_chain_does_not_append_unknown():
    """Two loops in one substitution: the first must stop the second."""
    script = ("a=$(for c in uname /bin/uname; do "
              "v=$($c -m 2>/dev/null) && [ -n \"$v\" ] && "
              "{ printf '%s\\n' \"$v\"; exit; }; done; "
              "for c in arch; do v=$($c 2>/dev/null) && [ -n \"$v\" ] && "
              "{ printf '%s\\n' \"$v\"; exit; }; done; "
              "printf '%s\\n' unknown); printf '%s\\n' \"$a\"")
    eq("one architecture and no 'unknown'", lines(script), ["x86_64"])


# -- exit still ends a session the way it always did ----------------------

def t_a_bare_exit_still_ends_the_script():
    eq("nothing after it runs", lines("echo one; exit; echo two"), ["one"])
    eq("and the status is kept", run("echo one; exit 9; echo two")[2], 9)


def t_a_new_command_is_a_new_shell():
    """The flag must not outlive the command that raised it."""
    s = sh()
    s.run("exit")
    s._err.clear()
    out = s.run("echo still-here")
    eq("the next command still runs", out.strip(), "still-here")
    s.run("for i in 1; do exit; done")
    s._err.clear()
    eq("and after an exit inside a loop too",
       s.run("echo still-here").strip(), "still-here")


TESTS = [t_exit_ends_the_shell_from_every_in_shell_body,
         t_a_subshell_exit_does_not_end_the_caller,
         t_the_loop_stops_at_the_first_iteration,
         t_break_and_continue_still_work,
         t_return_leaves_the_function_and_not_the_shell,
         t_exit_carries_its_status_out_of_a_body,
         t_the_fallback_chain_answers_once,
         t_the_fallback_falls_back_when_nothing_answers,
         t_arch_chain_does_not_append_unknown,
         t_a_bare_exit_still_ends_the_script,
         t_a_new_command_is_a_new_shell]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
