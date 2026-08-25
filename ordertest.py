r"""Redirections apply left to right, and the order changes the answer.

Forty-fourth coherence sweep, and the one the last sweep deferred by
name: `2>&1 >file` and `>file 2>&1` mean different things, and both were
being treated the same.

strip_redirections set a handful of independent booleans -- err_to_out,
out_devnull, redir -- so whichever redirection was scanned last won,
regardless of what it should have been layered on top of. The classic
teaching pair came out identical:

    { echo o; ls /nope; } >file 2>&1     both streams into the file
    { echo o; ls /nope; } 2>&1 >file     stderr to the terminal, stdout
                                         into the file

It now models where fd1 and fd2 each point as the scan proceeds, and a
dup copies the destination *by value* -- which is what the kernel does
and exactly what makes the two orders differ. The old booleans are
derived from the final state at the end, so nothing downstream changed.

Two things fell out of doing that:

  * `1>file` left a stray "1" in the command text: `echo a 1>/tmp/f` wrote
    "a 1" where bash writes "a". The digit belongs to the redirection.
    Only fd 1 and 2 are modelled; a higher one is left alone, because
    `exec 3>/dev/tcp/...` still has to reach the socket handler.
  * The terminal has to be tagged with which stream it came from. After
    `1>&2`, fd1 points at the terminal *as stderr*, and that stays true
    even when fd2 is sent to /dev/null afterwards -- so `echo z 1>&2
    2>/dev/null` puts z on stderr, not nowhere and not on stdout.

That last one I got wrong twice. I first measured it on the guest with an
outer `2>&1`, which captured the inner stderr and made z look like stdout;
jobtest, which separates the streams, was the thing that caught it.

`ls /nope 2>&1 1>/dev/null` puts the error on *stdout* -- fd2 copied stdout
while it still meant the terminal, then fd1 went to the bin. This used to
put it on stderr, and said so here, because the flag set the executor
consumes could say "merge the two streams" or "discard stdout" but had no
way to say "discard stdout, and send stderr where stdout used to go". The
model was right and the interface was too narrow to express it, which is a
better disguise than a wrong model: the scanner already ended with fd1 on
the file and fd2 on the terminal, and there was a comment saying so.

Fixed in sweep 157 with an explicit `err_to_term`, held aside and returned
after the redirect has taken stdout -- appending it to the output first
would write the errors into the file, which is the thing the ordering
exists to avoid. The note that used to live here asked for exactly that and
left a check that would fail once it arrived; it did, and this is it.

Reference measured on the guest, as root:

    echo x 1>&2 2>/dev/null            x on stderr, nothing on stdout
    echo x 2>/dev/null 1>&2            nothing at all
    ls /nope 2>&1 1>/dev/null          the error, on stdout
    ls /nope 1>/dev/null 2>&1          nothing
    { echo o; ls /nope; } >f 2>&1      2 lines in f
    { echo o; ls /nope; } 2>&1 >f      1 line in f, error to the terminal
    echo a 1>/tmp/f                    f holds "a"

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
    """Returns stdout and stderr separately: merging them is how the first
    pass at this sweep mistook a stderr write for a stdout one.

    Pass a shell in when a test writes a file and then reads it back. A
    fresh VFS per call cannot see what the previous call wrote, which is
    how the first version of this suite failed ten of its own assertions
    before the code under test was ever wrong.
    """
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


# -- the pair that started it --------------------------------------------

BOTH = "{ echo o; ls /nope; }"


def t_file_then_dup_merges_into_the_file():
    z = sh()
    run("%s >/tmp/o1 2>&1" % BOTH, z)
    out, _e, _rc = run("wc -l < /tmp/o1", z)
    eq("both lines in the file", out.strip(), "2")


def t_dup_then_file_does_not():
    z = sh()
    out, err, _rc = run("%s 2>&1 >/tmp/o2" % BOTH, z)
    n, _e, _rc = run("wc -l < /tmp/o2", z)
    eq("only stdout in the file", n.strip(), "1")
    check("and the error went to the terminal",
          "cannot access" in (out + err), repr(out + err))


def t_the_two_orders_differ():
    z = sh()
    run("%s >/tmp/a1 2>&1" % BOTH, z)
    run("%s 2>&1 >/tmp/a2" % BOTH, z)
    one, _e, _ = run("wc -l < /tmp/a1", z)
    two, _e, _ = run("wc -l < /tmp/a2", z)
    check("they must not agree", one.strip() != two.strip(),
          "both %r" % one.strip())


# -- stdout to stderr, and what happens to it afterwards -----------------

def t_one_to_two_puts_stdout_on_stderr():
    out, err, _rc = run("echo z 1>&2")
    eq("nothing on stdout", out.strip(), "")
    eq("z on stderr", err.strip(), "z")


def t_nulling_stderr_afterwards_does_not_reach_it():
    out, err, _rc = run("echo z 1>&2 2>/dev/null; echo rc=$?")
    eq("stdout has only the rc line", out.strip(), "rc=0")
    eq("z still went to stderr", err.strip(), "z")


def t_nulling_stderr_first_does_swallow_it():
    out, err, _rc = run("echo z 2>/dev/null 1>&2; echo done")
    eq("z is gone", out.strip(), "done")
    eq("and not on stderr either", err.strip(), "")


def t_bare_dup_to_stderr():
    out, err, _rc = run("echo msg >&2")
    eq("nothing on stdout", out.strip(), "")
    eq("msg on stderr", err.strip(), "msg")


# -- stderr to stdout ----------------------------------------------------

def t_two_to_one_merges():
    out, err, _rc = run("ls /nope 2>&1")
    check("the error is on stdout", "cannot access" in out, repr(out))
    eq("nothing left on stderr", err.strip(), "")


def t_two_to_one_survives_a_pipe():
    out, _e, _rc = run("ls /nope 2>&1 | wc -l")
    eq("the pipe sees it", out.strip(), "1")


def t_dup_then_null_stdout_keeps_the_error_visible():
    """And on the right stream: stdout, where fd2 was pointed."""
    out, err, _rc = run("ls /nope 2>&1 1>/dev/null")
    check("the error still shows", "cannot access" in (out + err),
          repr(out + err))
    check("it is on stdout, where fd2 was duplicated to",
          "cannot access" in out, repr(out))
    eq("and nothing is left on stderr", err.strip(), "")


def t_null_stdout_then_dup_swallows_everything():
    out, err, _rc = run("ls /nope 1>/dev/null 2>&1")
    eq("nothing on stdout", out.strip(), "")
    eq("nothing on stderr", err.strip(), "")


# -- the leading descriptor number ---------------------------------------

def t_one_gt_is_a_redirect_not_a_word():
    z = sh()
    run("echo a 1>/tmp/f1", z)
    out, _e, _rc = run("cat /tmp/f1", z)
    eq("the file holds only a", out.strip(), "a")


def t_two_gt_to_a_file():
    z = sh()
    run("ls /nope 2>/tmp/f2", z)
    out, _e, _rc = run("wc -l < /tmp/f2", z)
    eq("one error line", out.strip(), "1")


def t_higher_descriptors_are_left_alone():
    """exec 3>... still has to reach the socket handler."""
    events = []
    s = fs.Shell(fs.VFS(), log=lambda **k: events.append(k),
                 peer="203.0.113.77")
    s.exec_mode = True
    s.run("exec 3>/dev/tcp/198.51.100.5/9999")
    s._err.clear()
    nets = [e for e in events if e.get("event") == "net_redirect"]
    check("the socket open was seen", nets, "no net_redirect")
    if nets:
        eq("with its target", nets[0]["target"], "198.51.100.5:9999")


# -- everything ordinary is unchanged ------------------------------------

def t_plain_forms():
    z = sh()
    run("echo a > /tmp/p1", z)
    out, _e, _ = run("cat /tmp/p1", z)
    eq("write", out.strip(), "a")
    run("echo b >> /tmp/p1", z)
    out, _e, _ = run("cat /tmp/p1", z)
    eq("append", out.split(), ["a", "b"])
    out, _e, _ = run("echo c > /dev/null; echo done", z)
    eq("/dev/null", out.strip(), "done")
    out, err, rc = run("ls /nope 2>/dev/null", z)
    eq("stderr nulled", (out.strip(), err.strip()), ("", ""))
    eq("rc preserved", rc, 2)
    run("echo d > /tmp/p2", z)
    out, _e, _ = run("cat < /tmp/p2", z)
    eq("stdin from file", out.strip(), "d")


def t_ampersand_forms():
    z = sh()
    run("%s &> /tmp/p3" % BOTH, z)
    out, _e, _ = run("wc -l < /tmp/p3", z)
    eq("&> takes both", out.strip(), "2")
    run("%s &>> /tmp/p3" % BOTH, z)
    out, _e, _ = run("wc -l < /tmp/p3", z)
    eq("&>> appends both", out.strip(), "4")


TESTS = [t_file_then_dup_merges_into_the_file, t_dup_then_file_does_not,
         t_the_two_orders_differ, t_one_to_two_puts_stdout_on_stderr,
         t_nulling_stderr_afterwards_does_not_reach_it,
         t_nulling_stderr_first_does_swallow_it, t_bare_dup_to_stderr,
         t_two_to_one_merges, t_two_to_one_survives_a_pipe,
         t_dup_then_null_stdout_keeps_the_error_visible,
         t_null_stdout_then_dup_swallows_everything,
         t_one_gt_is_a_redirect_not_a_word, t_two_gt_to_a_file,
         t_higher_descriptors_are_left_alone, t_plain_forms,
         t_ampersand_forms]


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
