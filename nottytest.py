#!/usr/bin/env python3
"""What changes when there is no terminal to write to.

Seventy-fourth coherence sweep. The axis is the tty test itself: an exec
channel has no terminal, that is what almost every automated visitor
gets, and a program that behaves the same either way is a program that
has not noticed. Three sessions this week found the same shape from three
directions -- mc, htop and fastfetch -- so this asks it of the ones that
are supposed to *work* without a terminal rather than refuse.

  * **`less <file>` had no implementation at all.** It reached the
    stock-binary answer:

        less 668
        Usage: less [OPTION]... [FILE]...

    a coreutils usage line, from a program that is not coreutils, for a
    completely valid invocation. `less /var/log/auth.log` is how anybody
    reads a log over ssh. Real less, with stdout not a terminal, writes
    the file out and exits 0.

  * **`more <file>` delegated straight to cat.** Real more names each
    file first when it is not paging:

        ::::::::::::::
        /tmp/a
        ::::::::::::::
        hello

    for a single file as well as for several. With a terminal it pages
    and there is no banner, so this is keyed on the same tty test.

  * **`visudo -c` answered with visudo's version over a coreutils usage
    line and exit 1** -- which reads as "your sudoers is broken" to
    anything checking the status. It is one line per file and exit 0.

Measured on the guest and in a debian:trixie container with the real
packages:

    less /tmp/a                  hello                            rc 0
    less /tmp/a /tmp/b           hello / world                    rc 0
    less /nosuch                 /nosuch: No such file...         rc 0
    less --version               less 668 (GNU regular expressions)
    more /tmp/a                  :::: banner :::: then the file   rc 0
    visudo -c                    /etc/sudoers: parsed OK ...      rc 0
    visudo                       still the stock answer, still a gap

Two details worth keeping: less names a missing file *without naming
itself* -- "/nosuch: No such file or directory", where cat's wording
would have put "cat:" in front of a program the caller never ran -- and
it carries on to the next file and still exits 0.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(tty=False):
    ev = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user="root",
                 log=lambda **k: ev.append(k))
    s.exec_mode = not tty
    s.run("printf 'hello\\n' > /tmp/a; printf 'world\\n' > /tmp/b")
    s._err.clear()
    ev.clear()
    s._events = ev
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return out, err, s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def t_less_writes_the_file_out():
    s = sh()
    out, err, rc = run(s, "less /tmp/a")
    eq("one file", out, "hello\n")
    eq("no stderr", err, "")
    eq("rc", rc, 0)
    out, _err, rc = run(s, "less /tmp/a /tmp/b")
    eq("two files, concatenated, no banner", out, "hello\nworld\n")
    eq("two files rc", rc, 0)


def t_less_does_not_say_cat():
    s = sh()
    out, err, rc = run(s, "less /nosuch")
    eq("stdout", out, "")
    eq("it names the file and not itself", err,
       "/nosuch: No such file or directory\n")
    check("nothing says cat", "cat:" not in err, err)
    eq("and still exits 0", rc, 0)
    out, err, rc = run(s, "less /nosuch /tmp/a")
    eq("it carries on to the next file", out, "hello\n")
    check("and still reports the missing one",
          "/nosuch: No such file or directory" in err, err)
    eq("rc", rc, 0)


def t_less_version():
    s = sh()
    for flag in ("--version", "-V"):
        out, _err, rc = run(s, "less %s" % flag)
        eq("%s" % flag, out, "less 668 (GNU regular expressions)\n")
        eq("%s rc" % flag, rc, 0)


def t_less_is_not_answering_as_a_stock_binary():
    s = sh()
    out, err, _rc = run(s, "less /tmp/a")
    body = out + err
    check("no coreutils usage line",
          "[OPTION]... [FILE]..." not in body, body[:80])
    check("no version banner in front of the file",
          not body.startswith("less "), body[:40])
    gaps = [e for e in s._events
            if e.get("event") == "unknown_command" and e.get("gap")]
    eq("and it is no longer a gap", gaps, [])


def t_more_names_each_file():
    s = sh()
    out, _err, rc = run(s, "more /tmp/a")
    eq("single file gets the banner too", out,
       "::::::::::::::\n/tmp/a\n::::::::::::::\nhello\n")
    eq("rc", rc, 0)
    out, _err, _rc = run(s, "more /tmp/a /tmp/b")
    eq("one banner per file", out,
       "::::::::::::::\n/tmp/a\n::::::::::::::\nhello\n"
       "::::::::::::::\n/tmp/b\n::::::::::::::\nworld\n")


def t_more_on_a_terminal_pages_without_the_banner():
    s = sh(tty=True)
    out, _err, rc = run(s, "more /tmp/a")
    eq("no banner with a tty", out, "hello\n")
    eq("rc", rc, 0)


def t_visudo_c_checks_and_says_so():
    s = sh()
    out, err, rc = run(s, "visudo -c")
    eq("rc is zero -- nothing is broken", rc, 0)
    eq("no stderr", err, "")
    lines = out.splitlines()
    eq("it starts with the main file", lines[0], "/etc/sudoers: parsed OK")
    check("and names every drop-in",
          all(l.endswith(": parsed OK") for l in lines), out)
    check("README is one of them",
          "/etc/sudoers.d/README: parsed OK" in lines, out)


def t_visudo_without_c_is_still_a_gap():
    """It is an editor, and that half is not implemented."""
    s = sh()
    out, err, rc = run(s, "visudo")
    eq("rc", rc, 1)
    body = out + err
    check("it identifies itself", body.startswith("visudo "), body[:40])
    check("with visudo's own usage, not coreutils'",
          "usage: visudo [-chqsV] [[-f] sudoers ]" in body, body[:120])
    gaps = [e for e in s._events
            if e.get("event") == "unknown_command" and e.get("gap")]
    eq("and the gap is recorded", len(gaps), 1)


def t_the_neighbours_still_work():
    """cat, head and tail are what less and more delegate to."""
    s = sh()
    eq("cat", run(s, "cat /tmp/a")[0], "hello\n")
    eq("cat two", run(s, "cat /tmp/a /tmp/b")[0], "hello\nworld\n")
    eq("head", run(s, "head -1 /tmp/b")[0], "world\n")
    out, err, rc = run(s, "cat /nosuch")
    eq("cat still says cat", err, "cat: /nosuch: No such file or directory\n")
    eq("and still fails", rc, 1)


TESTS = [t_less_writes_the_file_out,
         t_less_does_not_say_cat,
         t_less_version,
         t_less_is_not_answering_as_a_stock_binary,
         t_more_names_each_file,
         t_more_on_a_terminal_pages_without_the_banner,
         t_visudo_c_checks_and_says_so,
         t_visudo_without_c_is_still_a_gap,
         t_the_neighbours_still_work]


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
