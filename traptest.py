#!/usr/bin/env python3
"""Who cleans up, and when? The trap table and the moments it fires.

Seventy-first coherence sweep. The axis is `trap`, picked because the
comment on the EXIT-trap machinery in run() says why: a dropper's
`trap cleanup EXIT` is often the most revealing line in its script, and
a box that runs it at the wrong moment -- or not at all -- loses exactly
the part worth recording.

Seven things were wrong, all measured against bash on the guest.

  * **A subshell shared the caller's trap table.** `( trap cleanup EXIT;
    ... )` replaced the caller's EXIT trap, fired at the end of the
    *script* instead of the end of the subshell, and left the caller's own
    trap never run at all. A subshell inherits no EXIT trap and cannot
    change the caller's. Same for `$( )` and backticks -- and inside a
    substitution the trap's output is *captured*, so
    `v=$(trap "echo INNER" EXIT; echo sub)` really does leave v as two
    lines on a real box.
  * **Signal names had no SIG prefix.** bash prints `trap -- 'x' SIGINT`;
    this printed `INT`. EXIT, ERR, DEBUG and RETURN are the four it prints
    bare.
  * **A numeric signal stayed numeric.** `trap x 15` was stored as "15",
    so it printed itself back as 15 and `trap -p TERM` could not find it.
    Signal 0 is EXIT.
  * **`trap -p SIG` ignored the signal.** It printed the whole table.
  * **The order was alphabetical.** bash prints EXIT first and then by
    signal *number*: SIGUSR1 (10) before SIGTERM (15).
  * **`trap "" INT` deleted the entry** instead of recording an empty
    action. bash prints `trap -- '' SIGINT` for an ignored signal, and the
    difference between a script that armoured itself against a signal and
    one that never mentioned it is worth keeping.
  * **The ERR trap was wired to errexit.** `trap "echo ERR" ERR; false`
    said nothing unless `set -e` was also on. It fires either way; errexit
    only decides whether the script *also* ends. It is not inherited by a
    function body or a subshell unless `set -o errtrace`, which is why
    `f() { false; }; f` fires it once -- for f returning 1 -- and
    `f() { false; echo tail; }` fires it not at all.

And one more: `trap "exit 9" EXIT; exit 0` leaves 9. The status the
script was exiting with was always restored over the trap's.

Checked and found already right: `trap -l`, `trap` with no arguments,
`trap - SIG`, the EXIT trap firing on a normal end, on `exit`, and now
through an `exit` inside a loop or a function; errexit itself in every
body; `set -u`; `set -o pipefail`.

Left alone deliberately: the DEBUG trap is recorded and listed correctly
and never fires. Firing it means a hook before every command in the
interpreter, which is a different change from this one.

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


def lines(script):
    out, err, _rc = run(script)
    return [x for x in (out + err).splitlines() if x != ""]


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- a subshell is not the caller -----------------------------------------

def t_a_subshell_does_not_inherit_the_exit_trap():
    eq("the caller's trap does not fire at the closing paren",
       lines('trap "echo OUTER" EXIT; ( echo sub ); echo AFTER'),
       ["sub", "AFTER", "OUTER"])


def t_a_subshell_trap_fires_at_the_closing_paren():
    eq("its own trap fires there, and the caller's still fires later",
       lines('trap "echo OUTER" EXIT; ( trap "echo INNER" EXIT; echo sub ); '
             'echo AFTER'),
       ["sub", "INNER", "AFTER", "OUTER"])
    eq("with no caller trap at all",
       lines('( trap "echo INNER" EXIT; echo sub ); echo AFTER'),
       ["sub", "INNER", "AFTER"])


def t_a_substitution_captures_its_own_trap_output():
    eq("$( ) keeps the trap's output inside the substitution",
       lines('trap "echo OUTER" EXIT\n'
             'v=$(trap "echo INNER" EXIT; echo sub)\n'
             'echo "v=[$v]"\necho AFTER\n'),
       ["v=[sub", "INNER]", "AFTER", "OUTER"])
    eq("backticks do the same",
       lines('v=`trap "echo INNER" EXIT; echo sub`; echo "v=[$v]"'),
       ["v=[sub", "INNER]"])


def t_a_subshell_cannot_change_the_callers_table():
    # The subshell's own trap fires at its closing paren even with an empty
    # body -- setting one and exiting is enough. Measured on the guest,
    # because the first version of this check expected the caller's table
    # and nothing else, and INNER belongs there.
    eq("the caller's trap is intact afterwards",
       lines('trap "echo OUTER" EXIT; ( trap "echo INNER" EXIT ); trap -p'),
       ["INNER", "trap -- 'echo OUTER' EXIT", "OUTER"])


# -- what the table prints ------------------------------------------------

def t_signal_names_carry_the_sig_prefix():
    eq("SIGINT, not INT",
       lines('trap "echo x" INT; trap -p'), ["trap -- 'echo x' SIGINT"])
    eq("EXIT has no prefix",
       lines('trap "echo x" EXIT; trap -p; trap - EXIT'),
       ["trap -- 'echo x' EXIT"])
    eq("SIG is accepted on the way in too",
       lines('trap "echo x" SIGTERM; trap -p'),
       ["trap -- 'echo x' SIGTERM"])


def t_a_numeric_signal_is_the_same_trap_as_its_name():
    eq("15 is SIGTERM", lines('trap "echo T" 15; trap -p'),
       ["trap -- 'echo T' SIGTERM"])
    eq("and -p finds it by name", lines('trap "echo T" 15; trap -p TERM'),
       ["trap -- 'echo T' SIGTERM"])
    eq("0 is EXIT", lines('trap "echo T" 0; trap -p; trap - EXIT'),
       ["trap -- 'echo T' EXIT"])


def t_dash_p_prints_only_what_it_was_asked_for():
    setup = 'trap "echo A" EXIT; trap "echo B" INT; trap "echo C" TERM; '
    eq("one signal", lines(setup + "trap -p INT; trap - EXIT"),
       ["trap -- 'echo B' SIGINT"])
    eq("two signals", lines(setup + "trap -p INT TERM; trap - EXIT"),
       ["trap -- 'echo B' SIGINT", "trap -- 'echo C' SIGTERM"])
    eq("nothing set", lines("trap -p INT; echo done"), ["done"])


def t_the_order_is_exit_then_signal_number():
    eq("SIGUSR1 before SIGTERM",
       lines('trap "echo x" TERM USR1 HUP INT QUIT EXIT; trap -p; '
             'trap - EXIT'),
       ["trap -- 'echo x' EXIT",
        "trap -- 'echo x' SIGHUP",
        "trap -- 'echo x' SIGINT",
        "trap -- 'echo x' SIGQUIT",
        "trap -- 'echo x' SIGUSR1",
        "trap -- 'echo x' SIGTERM"])


def t_an_ignored_signal_is_recorded():
    eq("trap '' is an empty action, not a deletion",
       lines('trap "" INT; trap -p'), ["trap -- '' SIGINT"])
    eq("trap - really does delete",
       lines('trap "" INT; trap - INT; trap -p; echo done'), ["done"])
    eq("an ignored EXIT trap does nothing at the end",
       lines('trap "echo A" EXIT; trap "" EXIT; echo one'), ["one"])


def t_an_unknown_signal_is_an_error():
    out, err, rc = run('trap "echo x" NOSUCHSIG')
    eq("message", err.strip(),
       "bash: line 1: trap: NOSUCHSIG: invalid signal specification")
    eq("rc", rc, 1)
    eq("stdout", out, "")


# -- when the EXIT trap fires ---------------------------------------------

def t_the_exit_trap_fires_once_at_the_end():
    eq("a normal end", lines('trap "echo TRAP" EXIT; echo one'),
       ["one", "TRAP"])
    eq("an explicit exit", lines('trap "echo TRAP" EXIT; echo one; exit; '
                                 'echo two'), ["one", "TRAP"])
    eq("an exit from inside a loop",
       lines('trap "echo TRAP" EXIT; for i in 1; do echo in; exit; done; '
             'echo AFTER'), ["in", "TRAP"])
    eq("an exit from inside a function",
       lines('trap "echo TRAP" EXIT; f() { echo in; exit; }; f; echo AFTER'),
       ["in", "TRAP"])


def t_an_exit_inside_the_trap_sets_the_status():
    eq("exit 9 beats exit 0", run('trap "exit 9" EXIT; exit 0')[2], 9)
    eq("and beats a nonzero one", run('trap "exit 9" EXIT; exit 2')[2], 9)
    eq("a trap that does not exit leaves the status alone",
       run('trap "echo T" EXIT; exit 3')[2], 3)
    eq("$? inside the trap is the exiting status",
       lines('trap "echo rc=$?" EXIT; exit 5'), ["rc=0"])


# -- the ERR trap ---------------------------------------------------------

def t_the_err_trap_does_not_need_errexit():
    eq("it fires on a plain failure",
       lines('trap "echo ERR" ERR; false; echo AFTER'), ["ERR", "AFTER"])
    eq("once per failing command",
       lines('trap "echo ERR" ERR; false; false; echo AFTER'),
       ["ERR", "ERR", "AFTER"])
    eq("with errexit it also ends the script",
       lines('set -e; trap "echo ERR" ERR; false; echo AFTER'), ["ERR"])


def t_the_err_trap_skips_conditions_and_guards():
    eq("a condition does not fire it",
       lines('trap "echo ERR" ERR; if false; then :; fi; echo AFTER'),
       ["AFTER"])
    eq("nor does a guarded failure",
       lines('trap "echo ERR" ERR; false || true; echo AFTER'), ["AFTER"])


def t_the_err_trap_is_not_inherited_by_a_function():
    eq("the call fires it, the body does not",
       lines('trap "echo ERR" ERR; f() { false; }; f; echo AFTER'),
       ["ERR", "AFTER"])
    eq("a function that ends well fires nothing",
       lines('trap "echo ERR" ERR; f() { false; echo tail; }; f; echo AFTER'),
       ["tail", "AFTER"])
    eq("errtrace turns the body back on",
       lines('set -o errtrace; trap "echo ERR" ERR; f() { false; }; f; '
             'echo AFTER'), ["ERR", "ERR", "AFTER"])
    eq("a subshell is the same",
       lines('trap "echo ERR" ERR; ( false ); echo AFTER'),
       ["ERR", "AFTER"])


# -- what was already right and has to stay -------------------------------

def t_errexit_still_ends_every_body():
    for label, script in (
            ("top", "set -e; false; echo AFTER"),
            ("for", "set -e; for i in 1 2 3; do false; echo no; done; "
                    "echo AFTER"),
            ("while", "set -e; while :; do false; echo no; done; echo AFTER"),
            ("if", "set -e; if true; then false; echo no; fi; echo AFTER"),
            ("func", "set -e; f() { false; echo no; }; f; echo AFTER"),
            ("case", "set -e; case x in x) false; echo no;; esac; "
                     "echo AFTER"),
            ("subshell", "set -e; ( false; echo no ); echo AFTER")):
        out, _err, rc = run(script)
        check("%s: nothing after the failure" % label, "AFTER" not in out,
              repr(out))
        eq("%s: rc" % label, rc, 1)
    eq("a false condition is not a failure",
       lines("set -e; if false; then echo no; fi; echo AFTER"), ["AFTER"])
    eq("a guarded failure is not one either",
       lines("set -e; false || echo guarded; echo AFTER"),
       ["guarded", "AFTER"])
    eq("errexit ignores a pipeline's early stage",
       lines("set -e; false | true; echo AFTER"), ["AFTER"])


def t_nounset_and_pipefail_are_unchanged():
    out, err, rc = run('set -u; echo "${NOPE}"; echo AFTER')
    check("nounset message", "NOPE: unbound variable" in err, repr(err))
    eq("nounset rc", rc, 127)
    check("nounset stops the script", "AFTER" not in out, repr(out))
    out, err, rc = run('set -u; for i in 1; do echo "${NOPE}"; done; '
                       'echo AFTER')
    check("nounset inside a loop too", "AFTER" not in out, repr(out))
    eq("pipefail", run("set -o pipefail; false | true; echo rc2=$?")[0]
       .strip(), "rc2=1")


def t_the_status_after_each_body_is_the_bodys():
    eq("after a for", run("for i in 1 2; do false; done; echo rc2=$?")[0]
       .strip(), "rc2=1")
    eq("after an if with no branch",
       run("if false; then :; fi; echo rc2=$?")[0].strip(), "rc2=0")
    eq("after a case", run("case x in x) false;; esac; echo rc2=$?")[0]
       .strip(), "rc2=1")
    eq("after a while",
       run("i=0; while [ $i -lt 2 ]; do i=$((i+1)); false; done; "
           "echo rc2=$?")[0].strip(), "rc2=1")


def t_trap_clearing_and_replacing():
    eq("trap - EXIT clears", lines('trap "echo TRAP" EXIT; trap - EXIT; '
                                   'echo one'), ["one"])
    eq("the last one set wins",
       lines('trap "echo A" EXIT; trap "echo B" EXIT; echo one'),
       ["one", "B"])
    eq("a function may replace it",
       lines('trap "echo TRAP" EXIT; f() { trap "echo INNER" EXIT; }; f; '
             'echo one'), ["one", "INNER"])
    eq("clearing several at once",
       lines('trap "echo A" EXIT INT; trap - EXIT INT; trap -p; echo done'),
       ["done"])


def t_trap_l_is_the_signal_table():
    out, _err, rc = run("trap -l")
    eq("rc", rc, 0)
    check("starts at SIGHUP", out.startswith(" 1) SIGHUP"), repr(out[:40]))
    check("has 64 entries", out.count(")") == 62, str(out.count(")")))


TESTS = [t_a_subshell_does_not_inherit_the_exit_trap,
         t_a_subshell_trap_fires_at_the_closing_paren,
         t_a_substitution_captures_its_own_trap_output,
         t_a_subshell_cannot_change_the_callers_table,
         t_signal_names_carry_the_sig_prefix,
         t_a_numeric_signal_is_the_same_trap_as_its_name,
         t_dash_p_prints_only_what_it_was_asked_for,
         t_the_order_is_exit_then_signal_number,
         t_an_ignored_signal_is_recorded,
         t_an_unknown_signal_is_an_error,
         t_the_exit_trap_fires_once_at_the_end,
         t_an_exit_inside_the_trap_sets_the_status,
         t_the_err_trap_does_not_need_errexit,
         t_the_err_trap_skips_conditions_and_guards,
         t_the_err_trap_is_not_inherited_by_a_function,
         t_errexit_still_ends_every_body,
         t_nounset_and_pipefail_are_unchanged,
         t_the_status_after_each_body_is_the_bodys,
         t_trap_clearing_and_replacing,
         t_trap_l_is_the_signal_table]


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
