#!/usr/bin/env python3
"""Which file descriptor is that, and does the whole parser agree?

Sweep 143. `echo z 3>/tmp/e` printed **`z 3>/tmp/e`** -- the shell handing the
caller back their own redirection, which no shell does. `echo x 12>/tmp/c`
printed `x 1`, leaking the leading digit of a two-digit descriptor into the
command. `echo y 007>/tmp/d` printed nothing at all.

Only fd 1 and fd 2 were ever right, and they were right by two different
mechanisms:

  * fd 1 was decided by scanning the emitted output backwards for a bare
    number, with a check that it begins a word.
  * fd 2 was decided by a `text.startswith("2>", i)` prefix handler with **no
    such check**, running earlier in the same loop.

So the "2" in `12>` matched the fd-2 handler and swallowed `2>/tmp/c`, leaving
the orphaned "1" -- and the branch that would have caught it was never reached,
which is why instrumenting it produced nothing. Two descriptors, two
mechanisms, one of them missing the guard the other had.

Three defects, found together and fixed together:

  (a) the backwards scan read out[-1] and out[-2], i.e. ONE character, so it
      could only ever see a single-digit descriptor;
  (b) the 2> prefix handler had no word-start check;
  (c) descriptors above 2 were re-emitted into the command line so cmd_exec
      could act on `exec 3>/tmp/log` -- correct for exec, and leaked into
      every other command. bash applies a redirection to the shell only for
      exec; every other command consumes it.

The same single-digit assumption ran through the dup handlers: `2>&1` matched
the front of `2>&12`, and the dup regex was `(\\d)>&(\\d|-)`, so `exec 12>&-`
closed nothing.

Every expectation below is diffed against the real bash on this host, so none
of it is remembered. Run from `honeypot/`.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def ours(script):
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    del s._err[:]
    out = s.run(script)
    del s._err[:]
    return out


def real(script):
    return subprocess.run(["bash", "--noprofile", "--norc", "-c", script],
                          capture_output=True, text=True, timeout=15).stdout


def differential(name, script):
    a, b = ours(script), real(script)
    check("%s: %s" % (name, script), a == b, "ours=%r bash=%r" % (a, b))


# -- the three symptoms, each against real bash --------------------------

def t_a_two_digit_descriptor_is_one_number():
    """`12>` is fd 12, not the character "1" followed by fd 2."""
    for sc in ("echo x 12>/tmp/rt_c", "echo x 19>/tmp/rt_c2",
               "echo x 102>/tmp/rt_c3"):
        differential("two-digit", sc)


def t_leading_zeros_are_still_a_number():
    for sc in ("echo y 007>/tmp/rt_d", "echo y 02>/tmp/rt_d2"):
        differential("leading zero", sc)


def t_a_high_descriptor_is_not_echoed_back():
    """The loudest of the three: a shell that prints your redirection at you
    is not a shell. `cmd 3>/dev/null` is not exotic."""
    for sc in ("echo z 3>/tmp/rt_e", "echo z 3>>/tmp/rt_e2",
               "echo z 9>/tmp/rt_e3", "echo f 3>&-", "echo h 4>&1",
               "echo i 5>&2"):
        differential("high fd", sc)


def t_the_two_that_always_worked_still_do():
    """Over-correcting here would break the redirections every dropper uses.
    `2>/dev/null` is in almost every payload this box has seen."""
    for sc in ("echo w 2>/tmp/rt_f", "echo a 1>/tmp/rt_g",
               "echo q 2>>/tmp/rt_h", "echo u 2>&1", "echo b >&2",
               "echo c 1>&2", "echo d 0>&1", "echo g 2>&-",
               "echo v 2>/dev/null", "echo p >/dev/null"):
        differential("unchanged", sc)


def t_a_digit_that_does_not_begin_a_word_is_not_a_descriptor():
    """The guard itself: `x2>` is the word "x2" and a plain redirect."""
    for sc in ("echo r x2>/tmp/rt_i", "echo r a1>/tmp/rt_i2",
               "echo r _2>/tmp/rt_i3"):
        differential("not word-start", sc)


# -- exec is the exception, and has to stay one --------------------------

def t_exec_still_opens_and_closes_high_descriptors():
    """The re-emit exists for exec's sake; the fix must not take it away."""
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    del s._err[:]

    def run(c):
        o = s.run(c)
        del s._err[:]
        return o

    run("exec 3>/tmp/rt_log")
    run("echo kept >&3")
    run("exec 3>&-")
    check("exec 3> opens the file", run("cat /tmp/rt_log").strip() == "kept",
          run("cat /tmp/rt_log")[:30])
    # ...and the same for a two-digit descriptor, which never worked: the dup
    # regex read one digit, so `exec 12>&-` closed nothing.
    run("exec 12>/tmp/rt_log2")
    run("echo two >&12")
    run("exec 12>&-")
    check("exec 12> opens the file too",
          run("cat /tmp/rt_log2").strip() == "two",
          run("cat /tmp/rt_log2")[:30])


def t_the_dup_handlers_read_whole_numbers():
    """`2>&1` must not match the front of `2>&12`."""
    src = open(os.path.join(HERE, "fakeshell.py"), encoding="utf-8").read()
    check("the dup regex takes one or more digits",
          r'r"(\d+)>&(\d+|-)"' in src,
          "still single-digit")
    check("2>&1 checks the next character is not a digit",
          'text.startswith("2>&1", i)' in src
          and "text[i + 4:i + 5].isdigit()" in src)


# -- the predicate the whole thing turns on ------------------------------

def t_pending_fd_does_not_depend_on_chunking():
    """The property that let the four sites be replaced at all: the answer
    must be the same whether the scanner emitted one character per element or
    a whole run in one. Without it, no bulk-copy fast path is possible."""
    f = getattr(fs, "_pending_fd", None)
    if f is None:
        check("fakeshell exposes _pending_fd", False, "absent")
        return
    for text, want in (("echo a 2", 2), ("echo a 12", 12), ("exec 3", 3),
                       ("echo 007", 7), ("x3", None), ("echo x2", None),
                       ("", None), ("echo ", None)):
        per_char = f(list(text))
        bulk = f([text]) if text else f([])
        half = (f([text[:len(text) // 2], text[len(text) // 2:]])
                if text else f([]))
        got = per_char[0] if per_char else None
        check("_pending_fd(%r) == %r" % (text, want), got == want,
              "got %r" % (got,))
        check("_pending_fd(%r) ignores chunking" % text,
              per_char == bulk == half,
              "%r %r %r" % (per_char, bulk, half))


def t_dup_order_against_real_bash():
    """`2>&1 >file` is not `>file 2>&1`, and the difference is the point.

    A dup copies the *destination* at the moment it is written, so
    `2>&1 >/dev/null` leaves stderr on the terminal and sends stdout to the
    bin, while `>/dev/null 2>&1` sends both. This emulator got the file half
    right -- the redirect correctly took stdout only -- and then dropped the
    duplicated stderr instead of returning it, so `cmd 2>&1 >/dev/null`,
    which is the standard way to keep the errors and discard the output,
    printed nothing at all.

    Found while writing holdtest: the check for apt-mark's error message
    used that idiom and came back empty, and the suite was wrong for a
    moment before the shell turned out to be.
    """
    for script in (
            "ls /etc/hostname /nosuchfile",
            "ls /etc/hostname /nosuchfile 2>&1",
            "ls /etc/hostname /nosuchfile 2>/dev/null",
            "ls /etc/hostname /nosuchfile >/dev/null",
            "ls /etc/hostname /nosuchfile >/dev/null 2>&1",
            "ls /etc/hostname /nosuchfile 2>&1 >/dev/null",
            "ls /nosuchfile 2>&1 >/dev/null",
            "ls /etc/hostname 2>&1 >/dev/null",
            "ls /nosuchfile 2>&1 1>/dev/null",
    ):
        differential("dup order", script)


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            try:
                fn()
            except Exception as exc:                          # noqa: BLE001
                check(name, False, "crashed: %r" % (exc,))
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
