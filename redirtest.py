#!/usr/bin/env python3
"""Where does the output go?

Every dropper redirects: `>/dev/null 2>&1` to stay quiet, `>>log` to keep
one, `2>&-` to silence an error, `|&` to pipe both streams. The ordering
rules were already right -- an earlier sweep built the descriptor table
that makes `2>&1 >f` differ from `>f 2>&1` -- and these five forms were
not.

  - `cmd |& next`, bash's shorthand for `2>&1 |`, was split on the bare `|`
    and the `&` taken as a background operator: the producer ran detached,
    the consumer got nothing, and the error text the pipe was opened to
    catch went to the terminal. `ls /nope |& wc -l` counted 0.
  - `cmd 2>&-` left the error on the terminal. Closing a descriptor is one
    of the two ways to silence one, and the box ignored it.
  - `echo y >| f` -- the spelling that overrides noclobber -- was split at
    the `|` into a pipeline whose second stage was the filename, so it
    answered "Permission denied" for a write bash performs.
  - `set -o noclobber` was accepted and inert. Careful installer scripts
    set it precisely so a stray `>` cannot destroy a file; here it could.
  - `exec 3>/tmp/log` opened nothing -- the target was consumed as an fd1
    redirect -- so `echo x >&3` wrote to a file called 3 in the current
    directory, and `exec 3>&-` never closed anything.

Every case here was diffed against bash 5.2.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# --- |& ---------------------------------------------------------------------

def t_pipe_ampersand_merges_stderr():
    s = sh()
    o, rc = run(s, "ls /nope |& wc -l")
    eq("the error reached the pipe", o.strip(), "1")
    eq("and nothing leaked past it", "cannot access" in o, False)
    o2, _ = run(s, "ls /nope |& grep -c 'No such file'")
    eq("the text is the error's", o2.strip(), "1")
    o3, _ = run(s, "echo hi |& cat")
    eq("stdout still goes through", o3.strip(), "hi")


def t_pipe_ampersand_is_not_a_background_job():
    s = sh()
    o, _ = run(s, "echo one |& cat | wc -l")
    eq("a three-stage pipeline still works", o.strip(), "1")
    o2, _ = run(s, "jobs")
    eq("and nothing was backgrounded", o2.strip(), "")


# --- closing a descriptor ---------------------------------------------------

def t_closing_stderr_silences_it():
    s = sh()
    o, rc = run(s, "ls /nope 2>&-")
    eq("nothing is printed", o.strip(), "")
    eq("but the status is the command's", rc, 2)
    o2, _ = run(s, "echo kept 2>&-")
    eq("stdout is untouched", o2.strip(), "kept")


# --- noclobber --------------------------------------------------------------

def t_noclobber_refuses_to_overwrite():
    s = sh()
    run(s, "echo first > /tmp/nc")
    run(s, "set -o noclobber")
    o, rc = run(s, "echo second > /tmp/nc")
    eq("rc", rc, 1)
    check("bash's wording", "cannot overwrite existing file" in o, o[:80])
    o2, _ = run(s, "cat /tmp/nc")
    eq("the file is untouched", o2.strip(), "first")


def t_noclobber_allows_the_forms_that_are_allowed():
    s = sh()
    run(s, "echo first > /tmp/nc2; set -o noclobber")
    o, rc = run(s, "echo second >| /tmp/nc2")
    eq(">| overrides it", rc, 0)
    o2, _ = run(s, "cat /tmp/nc2")
    eq("and writes", o2.strip(), "second")
    run(s, "echo third >> /tmp/nc2")
    o3, _ = run(s, "cat /tmp/nc2")
    eq("appending is never refused", o3.split(), ["second", "third"])
    o4, rc4 = run(s, "echo new > /tmp/nc3")
    eq("a file that does not exist yet is fine", rc4, 0)
    run(s, "set +o noclobber")
    o5, rc5 = run(s, "echo fourth > /tmp/nc2")
    eq("and turning it off restores the default", rc5, 0)
    o6, _ = run(s, "cat /tmp/nc2")
    eq("which truncates", o6.strip(), "fourth")


def t_set_C_is_the_same_switch():
    s = sh()
    run(s, "echo x > /tmp/nc4; set -C")
    o, rc = run(s, "echo y > /tmp/nc4")
    eq("rc", rc, 1)
    o2, _ = run(s, "set -o | grep noclobber")
    check("set -o lists it as on", "on" in o2, o2[:40])


def t_a_bare_redirect_still_creates():
    s = sh()
    o, rc = run(s, "> /tmp/created; ls /tmp/created")
    eq("an empty redirect makes the file", (o.strip(), rc),
       ("/tmp/created", 0))


# --- exec's own descriptors -------------------------------------------------

def t_exec_opens_a_descriptor_that_writes():
    s = sh()
    o, rc = run(s, "exec 3> /tmp/log3")
    eq("rc", rc, 0)
    run(s, "echo one >&3")
    run(s, "echo two >&3")
    o2, _ = run(s, "cat /tmp/log3")
    eq("both writes landed in the file", o2.split(), ["one", "two"])
    o3, _ = run(s, "ls -d ./3 2>/dev/null | wc -l")
    eq("and no file called 3 was created", o3.strip(), "0")


def t_exec_append_and_close():
    s = sh()
    run(s, "echo existing > /tmp/log4")
    run(s, "exec 4>> /tmp/log4; echo added >&4")
    o, _ = run(s, "cat /tmp/log4")
    eq(">> keeps what was there", o.split(), ["existing", "added"])
    run(s, "exec 4>&-")
    o2, rc2 = run(s, "echo late >&4")
    eq("a closed descriptor is an error", rc2, 1)
    check("with bash's wording", "Bad file descriptor" in o2, o2[:60])
    o3, _ = run(s, "cat /tmp/log4")
    eq("and nothing more was written", o3.split(), ["existing", "added"])


def t_an_unopened_descriptor_is_an_error():
    s = sh()
    o, rc = run(s, "echo x >&9")
    eq("rc", rc, 1)
    check("named", "9: Bad file descriptor" in o, o[:60])


# --- the orderings an earlier sweep fixed, kept fixed ------------------------

def t_ordering_still_holds():
    s = sh()
    o, _ = run(s, "ls /nope 2>&1 1>/dev/null")
    check("2>&1 before >/dev/null leaves the error visible",
          "cannot access" in o, o[:60])
    o2, _ = run(s, "ls /nope >/dev/null 2>&1")
    eq("the other order hides it", o2.strip(), "")
    o3, _ = run(s, "{ echo out; echo err >&2; } 2>&1 | wc -l")
    eq("a group's stderr can be piped", o3.strip(), "2")
    o4, _ = run(s, "echo z 1>/tmp/both 2>/tmp/both; cat /tmp/both")
    eq("both streams to one file do not truncate each other",
       o4.strip(), "z")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
