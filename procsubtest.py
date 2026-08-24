r"""Process substitution, and the loop that could not see it.

Forty-fifth coherence sweep. `while read x; do ...; done < <(cmd)` is how
a script iterates without the subshell a pipe would create, and
`tee >(cmd)` is how it forks a copy of its output somewhere else. Both
appear in _procsub's own docstring as the reason it exists, and neither
worked.

  * `done < <(cmd)` failed to parse at all: "bash: while read l; do ...;
    done: command not found", rc 127. procsub runs in the simple-command
    path, which a compound never reaches, and the parentheses in the
    trailing redirect made the keyword scan lose the `done`. It is
    resolved before the construct is recognised now.
  * The loop's own `done < file` handler then read the filename with
    \S+, so even once parsed it would have taken "<(printf" and left the
    rest to run as a command.
  * `>(cmd)` was created as an empty file and never drained -- the
    comment said "nothing reads it back here" -- so `echo hi > >(cat)`
    and `tee >(cat)` printed nothing. bash runs the command with whatever
    was written to the path as its stdin; the sinks are remembered and
    drained once the writing command finishes.
  * `xargs -t` was accepted and ignored. It echoes each command to stderr
    before running it, which is what a script turns on to show what it is
    about to delete -- and without it the operator reading that output
    cannot tell a no-op from a run.

Measured and already correct, pinned here: `cat <(cmd)`, `diff <(a) <(b)`,
`wc -l < <(cmd)`, `read a b < <(cmd)`, and xargs' own splitting -- a
filename with a space in it really does become two arguments, and
`find . | xargs rm` really does fail on it, on the guest as here.

Reference measured on the guest, as root:

    while read l; do echo "[$l]"; done < <(printf "1\n2\n")   [1] [2]
    echo hi > >(cat)                                          hi
    printf "x\n" | xargs -t echo          stderr: echo x   stdout: x
    printf "a\nb\n" | xargs -t -n1 echo   echo a / a / echo b / b
    wc -l < <(printf "1\n2\n3\n")                             3
    read a b < <(echo "x y")                                  [x][y]

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(script, shell=None):
    """stdout and stderr kept apart: xargs -t writes its trace to stderr,
    and merging the two cannot tell that from writing it twice."""
    s = shell or sh()
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return out, err, s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- the read side, in a loop --------------------------------------------

def t_while_read_from_a_substitution():
    out, err, rc = run('while read l; do echo "[$l]"; done '
                       '< <(printf "1\\n2\\n")')
    eq("both lines", out.split(), ["[1]", "[2]"])
    eq("no error", err.strip(), "")
    eq("rc 0", rc, 0)


def t_it_parses_at_all():
    """The failure was a parse failure, not a wrong answer."""
    out, err, rc = run('while read l; do echo "[$l]"; done < <(echo solo)')
    check("no command-not-found", "command not found" not in (out + err),
          repr(out + err))
    check("rc is not 127", rc != 127, rc)
    eq("and it read the line", out.strip(), "[solo]")


def t_a_plain_file_redirect_still_works():
    z = sh()
    run('printf "a\\nb\\n" > /tmp/f', z)
    out, _e, _rc = run('while read l; do echo "[$l]"; done < /tmp/f', z)
    eq("unchanged", out.split(), ["[a]", "[b]"])


def t_loop_status_after_a_substitution():
    out, _e, rc = run('while read l; do echo "[$l]"; done '
                      '< <(printf "x\\ny\\n"); echo rc=$?')
    eq("lines and status", out.split(), ["[x]", "[y]", "rc=0"])


# -- the read side, elsewhere: already worked, pinned --------------------

def t_read_side_basics():
    out, _e, _rc = run("cat <(echo hello)")
    eq("cat", out.strip(), "hello")
    out, _e, _rc = run('wc -l < <(printf "1\\n2\\n3\\n")')
    eq("wc", out.strip(), "3")
    out, _e, _rc = run('read a b < <(echo "x y"); echo "[$a][$b]"')
    eq("read into two names", out.strip(), "[x][y]")
    out, _e, rc = run("diff <(echo a) <(echo a); echo rc=$?")
    eq("diff of equals", out.strip(), "rc=0")


# -- the write side ------------------------------------------------------

def t_write_to_a_substitution():
    out, _e, _rc = run("echo hi > >(cat)")
    eq("the sink ran", out.strip(), "hi")


def t_tee_forks_a_copy():
    out, _e, _rc = run("echo hi | tee >(cat) >/dev/null")
    eq("the fork ran", out.strip(), "hi")


def t_two_sinks_both_run():
    out, _e, _rc = run("echo hi | tee >(cat) >(cat) >/dev/null")
    eq("both", out.split(), ["hi", "hi"])


def t_an_empty_sink_runs_nothing():
    out, _e, _rc = run("printf '' > >(cat); echo done")
    eq("nothing extra", out.strip(), "done")


# -- xargs ---------------------------------------------------------------

def t_xargs_t_traces_to_stderr():
    out, err, _rc = run('printf "x\\n" | xargs -t echo')
    eq("output on stdout", out.strip(), "x")
    eq("trace on stderr", err.strip(), "echo x")


def t_xargs_t_with_n1():
    out, err, _rc = run('printf "a\\nb\\n" | xargs -t -n1 echo')
    eq("both outputs", out.split(), ["a", "b"])
    eq("both traces", err.split(), ["echo", "a", "echo", "b"])


def t_xargs_t_with_replace():
    out, err, _rc = run('printf "q\\n" | xargs -t -I{} echo "[{}]"')
    eq("output", out.strip(), "[q]")
    check("trace mentions the substituted form", "[q]" in err, repr(err))


def t_xargs_without_t_is_quiet():
    out, err, _rc = run('printf "a\\nb\\n" | xargs echo')
    eq("output", out.strip(), "a b")
    eq("nothing on stderr", err.strip(), "")


def t_xargs_basics_unchanged():
    out, _e, _rc = run('printf "1\\n2\\n3\\n" | xargs -n1 echo')
    eq("-n1", out.split(), ["1", "2", "3"])
    out, _e, _rc = run('printf "a\\nb\\n" | xargs -I{} echo "[{}]"')
    eq("-I", out.split(), ["[a]", "[b]"])
    out, _e, _rc = run('printf "a\\0b\\0" | xargs -0 echo')
    eq("-0", out.strip(), "a b")
    out, _e, _rc = run('printf "" | xargs -r echo hit')
    eq("-r on empty", out.strip(), "")
    out, _e, _rc = run('printf "" | xargs echo hit')
    eq("no -r on empty", out.strip(), "hit")


def t_xargs_splits_on_whitespace_like_the_real_one():
    """A filename with a space really does become two arguments."""
    z = sh()
    run('mkdir -p /w2; cd /w2; touch "c d.txt"', z)
    out, _e, _rc = run('cd /w2 && ls | xargs echo', z)
    eq("two words out of one name", out.split(), ["c", "d.txt"])


TESTS = [t_while_read_from_a_substitution, t_it_parses_at_all,
         t_a_plain_file_redirect_still_works,
         t_loop_status_after_a_substitution, t_read_side_basics,
         t_write_to_a_substitution, t_tee_forks_a_copy,
         t_two_sinks_both_run, t_an_empty_sink_runs_nothing,
         t_xargs_t_traces_to_stderr, t_xargs_t_with_n1,
         t_xargs_t_with_replace, t_xargs_without_t_is_quiet,
         t_xargs_basics_unchanged,
         t_xargs_splits_on_whitespace_like_the_real_one]


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
