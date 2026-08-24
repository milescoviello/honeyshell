#!/usr/bin/env python3
"""set -e, set -u, pipefail and trap -- does the shell stop when told to?

Thirty-third coherence sweep. The axis is error handling, chosen because
`set -e` or `set -euo pipefail` is the first line of most installer
scripts, including srb.sh, and because a shell that ignores it runs the
script further than the script itself allows. What we then record is a
run that could not have happened on the target.

set_opts already tracked every option and nothing ever read three of
them:

  * `set -e` did not abort. `set -e; echo a; false; echo b` printed both
    lines and exited 0 where bash prints "a" and exits 1.
  * `set -u` did not error. `set -u; echo ${NOPE}` expanded to empty and
    carried on where bash writes "NOPE: unbound variable" and exits 127.
    The bare and braced spellings took different code paths, so the fix
    had to go in twice -- plus a third time for ${#NOPE}, which is an
    unbound reference too and not a length of zero.
  * `trap ... ERR` never fired.

The exemptions are bash's and each has a case here: a failing command is
not fatal inside an if/elif condition, inside a while/until condition, or
anywhere in a && / || chain except after the final operator. `set +e`
turns it back off.

Two things this sweep did *not* change, because measuring showed them
already correct, and both had fooled a first careless probe:

  * pipefail. `false | true` is 0 and `set -o pipefail; false | true` is
    1, including `set +o pipefail` turning it back off. The first probe
    ran the two cases in one shell and saw the option persist from the
    line before -- correct behaviour reported as a bug.
  * here-documents. <<EOF, <<'EOF' (no expansion), <<-EOF, here-strings,
    heredoc into a file and into tee, and $( ) inside a heredoc body all
    matched the guest already. srb.sh writes its systemd unit that way.

Reference measured on the guest, as root:

    set -e; echo a; false; echo b   -> "a"                    rc=1
    set -e; false || true; echo ok  -> "ok"                   rc=0
    set -e; if false; then :; fi; echo after -> "after"       rc=0
    set -u; echo ${UNSETV}          -> unbound variable       rc=127
    set -u; echo ${#UNSETV}         -> unbound variable       rc=127
    set -u; echo ${UNSETV:-def}     -> "def"                  rc=0
    set -u; echo ${UNSETV+x}        -> ""                     rc=0
    false | true                    -> rc=0
    set -o pipefail; false | true   -> rc=1
    set -e; trap "echo trapped" ERR; false; echo after -> "trapped" rc=1

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script):
    """Each case gets its own shell: `set -e` and pipefail persist, and
    running them in one shell is how a first pass at this mistook correct
    behaviour for a bug."""
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-50s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def case(script, want_out, want_rc):
    out, rc = run(script)
    eq("out: %s" % script[:44], out.strip(), want_out)
    eq("rc:  %s" % script[:44], rc, want_rc)


# -- set -e --------------------------------------------------------------

def t_errexit_aborts():
    case("set -e; echo a; false; echo b", "a", 1)
    case("set -e; false", "", 1)
    case("set -e; echo a\nfalse\necho b", "a", 1)


def t_errexit_leaves_success_alone():
    case("set -e; true; echo ok", "ok", 0)
    case("set -e; echo a; echo b", "a\nb", 0)


def t_errexit_exemptions():
    """bash does not exit for a failure it can see you handling."""
    case("set -e; false || true; echo ok", "ok", 0)
    case("set -e; false && echo x; echo after", "after", 0)
    case("set -e; if false; then echo x; fi; echo after", "after", 0)
    case("set -e; if false; then echo x; else echo y; fi", "y", 0)
    case("set -e; while false; do echo x; done; echo after", "after", 0)
    case("set -e; until true; do echo x; done; echo after", "after", 0)


def t_errexit_can_be_turned_off():
    case("set -e; echo a; set +e; false; echo b", "a\nb", 0)
    case("echo a; false; echo b", "a\nb", 0)


# -- set -u --------------------------------------------------------------

def t_nounset_is_fatal():
    for script in ("set -u; echo ${UNSETV}; echo after",
                   "set -u; echo $UNSETV; echo after",
                   "set -u; echo ${#UNSETV}; echo after"):
        out, rc = run(script)
        check("unbound reported: %s" % script[:40],
              "UNSETV: unbound variable" in out, out)
        check("nothing ran after: %s" % script[:40],
              "after" not in out, out)
        eq("rc 127: %s" % script[:40], rc, 127)


def t_nounset_allows_the_guarded_forms():
    case("set -u; echo ${UNSETV:-def}", "def", 0)
    case("set -u; echo ${UNSETV+x}", "", 0)
    case("set -u; V=1; echo $V; echo ${V}; echo ${#V}", "1\n1\n1", 0)
    case("set -u; echo $HOME", "/root", 0)


def t_nounset_off_is_the_old_behaviour():
    case("echo ${UNSETV}; echo after", "after", 0)
    case("set -u; set +u; echo ${UNSETV}; echo after", "after", 0)


def t_set_eu_together():
    out, rc = run("set -eu; echo a; echo ${NOPE}; echo b")
    check("the first line ran", out.startswith("a"), out)
    check("the unbound one reported", "unbound variable" in out, out)
    # Check for the line, not the letter: "unbound variable" contains a b,
    # which is what the first version of this assertion tripped over.
    check("and b did not run", "b" not in out.split("\n"), out)
    eq("rc 127", rc, 127)


# -- pipefail: measured correct, kept honest -----------------------------

def t_pipefail():
    case("false | true; echo rc=$?", "rc=0", 0)
    case("set -o pipefail; false | true; echo rc=$?", "rc=1", 0)
    case("set -o pipefail; true | false; echo rc=$?", "rc=1", 0)
    case("set -o pipefail; true | true; echo rc=$?", "rc=0", 0)
    case("set -o pipefail; set +o pipefail; false | true; echo rc=$?",
         "rc=0", 0)


# -- traps ---------------------------------------------------------------

def t_err_trap_fires_with_errexit():
    case('set -e; trap "echo trapped" ERR; false; echo after', "trapped", 1)


def t_exit_trap_still_fires():
    case('trap "echo bye" EXIT; echo main', "main\nbye", 0)
    case('set -e; trap "echo t" ERR; trap "echo x" EXIT; false', "t\nx", 1)


def t_no_trap_no_output():
    case("set -e; false; echo after", "", 1)


# -- heredocs: measured correct, pinned so they stay that way ------------

def t_heredocs():
    case("cat <<EOF\nhello\nEOF", "hello", 0)
    case("V=world; cat <<EOF\nhello $V\nEOF", "hello world", 0)
    case("V=world; cat <<'EOF'\nhello $V\nEOF", "hello $V", 0)
    case("cat <<-EOF\n\tindented\n\tEOF", "indented", 0)
    case("cat > /tmp/h <<EOF\nl1\nl2\nEOF\ncat /tmp/h", "l1\nl2", 0)
    case("cat <<< 'one shot'", "one shot", 0)
    case("cat <<EOF\n$(echo inner)\nEOF", "inner", 0)


def t_heredoc_writes_a_unit_file():
    """The shape srb.sh uses for /etc/systemd/system/srbminer.service."""
    out, rc = run("tee /tmp/u.service <<EOF >/dev/null\n"
                  "[Unit]\nDescription=X\n\n[Service]\n"
                  "ExecStart=/opt/x\nEOF\ncat /tmp/u.service")
    eq("the unit came out whole", out.strip(),
       "[Unit]\nDescription=X\n\n[Service]\nExecStart=/opt/x")
    eq("and tee exits 0", rc, 0)


TESTS = [t_errexit_aborts, t_errexit_leaves_success_alone,
         t_errexit_exemptions, t_errexit_can_be_turned_off,
         t_nounset_is_fatal, t_nounset_allows_the_guarded_forms,
         t_nounset_off_is_the_old_behaviour, t_set_eu_together,
         t_pipefail, t_err_trap_fires_with_errexit,
         t_exit_trap_still_fires, t_no_trap_no_output,
         t_heredocs, t_heredoc_writes_a_unit_file]


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
