#!/usr/bin/env python3
"""Does the box agree with itself about how big the terminal is?

The SSH client negotiates a window size in its pty-req, so "how wide is
this terminal" has five places to ask it: stty, tput, $COLUMNS/$LINES, the
pty-req itself, and the column layout ls chooses. They did not agree,
because the negotiated size was thrown away.

  - check_channel_pty_request(*_args) discarded the term type and the
    dimensions, and $COLUMNS/$LINES were the literals 80 and 24. A client
    that asked for 220x50 was told 80x24 by everything, and $TERM was
    always "xterm" whatever it had said.
  - A window-change request (SIGWINCH) was not handled at all, so a client
    that resized got the old numbers back afterwards.
  - `stty size` printed nothing while `stty -a`, one flag away, said rows 24
    columns 80.
  - `tput` was an unimplemented stock binary, so `tput cols` -- the one
    command a script uses to size its own output -- answered "missing
    operand" while stty and $COLUMNS both had the number. So did infocmp
    and tset.
  - ls never column-formatted: not to a terminal, and not even with -C,
    which forces columns regardless. An interactive `ls /usr/bin` printed
    700 lines down a 220-column terminal. -w was parsed and dropped, so
    `ls -w 40 /etc` listed a directory named 40 and then /etc.

The column layout is externally defined, so it is checked against a real
coreutils rather than against itself: identical bytes at five widths, for
both -C and -m, including ls.c's tab rule -- a tab is emitted only where it
is shorter than the spaces it replaces, which is why "alpha" is followed by
a tab and "epsilon" by two spaces in the same column.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []
NAMES = ("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda "
         "mu nu xi omicron pi rho sigma verylongname_here tau")


def sh(cols=80, rows=24, term="xterm", interactive=False):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = not interactive
    s.cols, s.rows, s.term = cols, rows, term
    s.vars["TERM"] = term
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


def t_every_view_of_the_size_agrees():
    """The contradiction this sweep started from."""
    for cols, rows in ((80, 24), (220, 50), (132, 43), (100, 30)):
        s = sh(cols, rows)
        o, rc = run(s, "stty size")
        eq("stty size at %dx%d" % (cols, rows), o.strip(),
           "%d %d" % (rows, cols))
        eq("stty size rc", rc, 0)
        o, _ = run(s, "stty -a | head -1")
        check("stty -a rows/columns at %dx%d" % (cols, rows),
              "rows %d; columns %d" % (rows, cols) in o, o.strip()[:70])
        o, rc = run(s, "tput cols")
        eq("tput cols at %d" % cols, (o.strip(), rc), (str(cols), 0))
        o, rc = run(s, "tput lines")
        eq("tput lines at %d" % rows, (o.strip(), rc), (str(rows), 0))
        o, _ = run(s, "echo $COLUMNS $LINES")
        eq("$COLUMNS $LINES at %dx%d" % (cols, rows), o.strip(),
           "%d %d" % (cols, rows))


def t_term_type_is_the_one_negotiated():
    for term in ("xterm", "xterm-256color", "screen", "vt100"):
        s = sh(term=term)
        o, _ = run(s, "echo $TERM")
        eq("$TERM is %s" % term, o.strip(), term)
        o, rc = run(s, "tset -q")
        eq("tset -q agrees", o.strip(), term)
        o, _ = run(s, "infocmp | head -2")
        check("infocmp names %s" % term, term in o, o[:80])
    s = sh(term="xterm-256color")
    o, _ = run(s, "tput colors")
    eq("a 256color term reports 256", o.strip(), "256")
    s = sh(term="xterm")
    o, _ = run(s, "tput colors")
    eq("a plain xterm reports 8", o.strip(), "8")


def t_stty_can_change_the_size_and_everything_follows():
    s = sh(80, 24)
    run(s, "stty columns 132")
    run(s, "stty rows 43")
    for probe, want in (("stty size", "43 132"), ("tput cols", "132"),
                        ("tput lines", "43"), ("echo $COLUMNS", "132"),
                        ("echo $LINES", "43")):
        o, _ = run(s, probe)
        eq("after stty columns/rows: %s" % probe, o.strip(), want)


def t_tput_emits_real_escapes():
    s = sh()
    for cap, want in (("bold", "\x1b[1m"), ("sgr0", "\x1b(B\x1b[m"),
                      ("smso", "\x1b[7m"), ("rmso", "\x1b[27m"),
                      ("el", "\x1b[K"), ("clear", "\x1b[H\x1b[2J"),
                      ("civis", "\x1b[?25l")):
        o, rc = run(s, "tput %s" % cap)
        eq("tput %s" % cap, (o, rc), (want, 0))
    o, _ = run(s, "tput setaf 1")
    eq("tput setaf 1", o, "\x1b[31m")
    o, _ = run(s, "tput setaf 196")
    eq("tput setaf 196", o, "\x1b[38;5;196m")
    o, _ = run(s, "tput setab 4")
    eq("tput setab 4", o, "\x1b[44m")
    o, _ = run(s, "tput cup 3 5")
    eq("tput cup 3 5 is 1-based on the wire", o, "\x1b[4;6H")
    o, rc = run(s, "tput nosuchcapability")
    eq("an unknown capability is an error", rc, 4)
    check("with tput's wording", "unknown terminfo capability" in o, o[:70])
    o, rc = run(s, "tput")
    eq("bare tput is a usage error", rc, 2)


def t_ls_columns_match_real_coreutils():
    """The layout is externally defined, so compare against the real thing."""
    import subprocess
    import tempfile
    tmp = tempfile.mkdtemp()
    for n in NAMES.split():
        open(os.path.join(tmp, n), "w").close()
    s = sh()
    run(s, "mkdir -p /lsref && cd /lsref && touch " + NAMES)
    for w in (40, 60, 80, 120, 200):
        for flag in ("-C", "-m"):
            try:
                real = subprocess.run(["ls", flag, "-w", str(w)], cwd=tmp,
                                      capture_output=True, text=True,
                                      timeout=20).stdout
            except Exception:
                check("ls %s -w %d (no reference ls available)" % (flag, w),
                      True)
                continue
            ours, _ = run(s, "cd /lsref && ls %s -w %d" % (flag, w))
            eq("ls %s -w %d matches coreutils byte for byte" % (flag, w),
               ours, real)


def t_ls_respects_where_its_output_goes():
    s = sh(cols=200)
    run(s, "mkdir -p /lsref && cd /lsref && touch " + NAMES)
    # Not a terminal: one per line, which is what every pipeline sees.
    o, _ = run(s, "cd /lsref && ls")
    eq("piped ls is one name per line", len(o.strip().splitlines()),
       len(NAMES.split()))
    check("and has no padding", "\t" not in o and "  " not in o, repr(o[:60]))
    # A terminal: columns.
    t = sh(cols=200, interactive=True)
    t.run("mkdir -p /lsref && cd /lsref && touch " + NAMES)
    o, _ = run(t, "cd /lsref && ls")
    check("interactive ls uses columns",
          len(o.strip().splitlines()) < len(NAMES.split()),
          "%d lines" % len(o.strip().splitlines()))
    # -1 forces one per line even on a terminal.
    o, _ = run(t, "cd /lsref && ls -1")
    eq("-1 forces one per line", len(o.strip().splitlines()),
       len(NAMES.split()))
    # -C forces columns even into a pipe.
    o, _ = run(s, "cd /lsref && ls -C")
    check("-C forces columns into a pipe",
          len(o.strip().splitlines()) < len(NAMES.split()),
          "%d lines" % len(o.strip().splitlines()))


def t_ls_width_flag_is_not_a_path():
    s = sh()
    run(s, "mkdir -p /lsref && cd /lsref && touch " + NAMES)
    o, rc = run(s, "ls -w 40 /lsref")
    eq("ls -w 40 rc", rc, 0)
    check("ls -w 40 does not report a directory named 40",
          "40" not in o.split("\n")[0] and "No such file" not in o, o[:80])
    check("and does not print a path header", ":" not in o, o[:80])
    a, _ = run(s, "ls -C -w 40 /lsref")
    b, _ = run(s, "ls -C --width=40 /lsref")
    eq("--width= is the same as -w", b, a)
    c, _ = run(s, "ls -C -w40 /lsref")
    eq("-w40 attached is the same", c, a)


def t_ls_column_count_follows_the_terminal_width():
    s = sh(interactive=True)
    s.run("mkdir -p /lsref && cd /lsref && touch " + NAMES)
    prev = None
    for w in (40, 80, 160, 240):
        s.cols = w
        o, _ = run(s, "cd /lsref && ls")
        lines = len(o.strip().splitlines())
        check("at %d columns ls uses at most the width" % w,
              max(len(l.expandtabs()) for l in o.splitlines()) <= w,
              "longest %d" % max(len(l.expandtabs())
                                 for l in o.splitlines()))
        if prev is not None:
            check("a wider terminal needs no more rows (%d -> %d)" % (w // 2, w),
                  lines <= prev, "%d then %d" % (prev, lines))
        prev = lines


def t_a_session_with_no_pty_still_answers():
    """ssh host 'cmd' has no terminal; the defaults must still be sane."""
    s = sh(80, 24, term="dumb")
    o, rc = run(s, "tput cols")
    eq("tput cols without a pty", (o.strip(), rc), ("80", 0))
    o, _ = run(s, "stty size")
    eq("stty size without a pty", o.strip(), "24 80")
    o, _ = run(s, "echo $TERM")
    eq("$TERM is dumb", o.strip(), "dumb")


def t_geometry_is_plumbed_from_the_pty_request():
    """The server has to keep what the client asked for.

    This one reads ssh_honeypot.py rather than the emulator, so it is the
    only check in here that is about the *deployment* and not about the
    shell. It skips when that file is not beside it: the emulator ships
    without the SSH server in some checkouts, and crashing with a bare
    FileNotFoundError there tells the reader nothing about what is wrong.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "ssh_honeypot.py")
    if not os.path.exists(path):
        check("pty geometry plumbing (skipped: no ssh_honeypot.py here)", True)
        return
    src = open(path).read()
    check("pty-req handler takes the dimensions",
          "def check_channel_pty_request(self, channel, term, width, height"
          in src, "still uses *_args")
    check("a window-change handler exists",
          "def check_channel_window_change_request" in src, "missing")
    check("the shell is given the negotiated columns",
          "shell.cols, shell.rows = getattr(server" in src, "missing")
    check("and the negotiated term", 'shell.vars["TERM"] = shell.term' in src,
          "missing")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


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
