#!/usr/bin/env python3
"""What `mc` says on a box with no terminal.

Found by a live attacker, not by a sweep.

On 2026-09-06, 203.0.113.72 -- client `Renci.SshNet.SshClient.0.0.1`,
zero prior failures, so it already had the credential -- logged in three
times in twenty-one minutes. Each session ran exactly 31 seconds: connect,
authenticate, wait half a minute, send one command, disconnect. The
command was

    mc

Somebody had run `apt-get install mc -y` on this box earlier, and the
install works: dpkg lists it, /usr/bin/mc exists, `which` finds it. So
running it reached the generic stock-binary answer,

    mc 4.8.33
    Usage: mc [OPTION]... [FILE]...

which is not a sentence mc has ever printed -- its real usage line takes
two directories, not FILEs -- and the box logged it as an emulator gap,
correctly, three times.

An exec channel has no terminal, and that is what an automated visitor
gets. Measured against the real package (3:4.8.33-1+deb13u1) in a
debian:trixie container:

    TERM unset          The TERM environment variable is unset!       rc 1
    TERM set, no tty    Cannot get terminal settings: Inappropriate
                        ioctl for device (25)
                        Failed to open terminal.                      rc 1
    --version, -V       GNU Midnight Commander 4.8.33 + build lines   rc 0
    --help, -h          Usage: / mc [OPTION?] [this_dir] ...          rc 0
    unknown option      Failed to run: / Unknown option --x / usage   rc 1

Two spellings of one usage line, both real: `--help` prints `[OPTION?]`
and the option-parse failure prints `[OPTION…]` with a Unicode ellipsis.
That is glib's doing, and copying only one of them would be the tell.

The full-screen half is not implemented. A session with a real terminal
still falls through to the stock answer and still reports the gap,
because there it still is one -- this suite checks that too, so the
alert cannot be silently lost.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(install=True, tty=False):
    ev = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user="root",
                 log=lambda **k: ev.append(k))
    s.exec_mode = not tty
    if install:
        s.run("apt-get install mc -y")
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


def t_it_is_not_there_until_it_is_installed():
    s = sh(install=False)
    out, err, rc = run(s, "mc")
    eq("command not found", err.strip(),
       "bash: line 1: mc: command not found")
    eq("rc", rc, 127)
    eq("stdout", out, "")
    eq("which finds nothing", run(s, "which mc")[0], "")


def t_installing_it_makes_every_reader_agree():
    s = sh()
    eq("which", run(s, "which mc")[0].strip(), "/usr/bin/mc")
    row = run(s, "dpkg -l mc")[0].splitlines()[-1]
    check("dpkg says installed", row.startswith("ii"), row)
    check("and names the Debian version", "3:4.8.33-1+deb13u1" in row, row)
    check("dpkg -S resolves the path",
          run(s, "dpkg -S /usr/bin/mc")[0].startswith("mc:"),
          run(s, "dpkg -S /usr/bin/mc")[0])
    check("the file is there and executable",
          run(s, "test -x /usr/bin/mc && echo yes")[0].strip(), "yes")


def t_no_terminal_is_the_answer_an_exec_channel_gets():
    s = sh()
    out, err, rc = run(s, "mc")
    eq("stdout is empty", out, "")
    eq("stderr", err,
       "Cannot get terminal settings: Inappropriate ioctl for device (25)\n"
       "Failed to open terminal.\n")
    eq("rc", rc, 1)


def t_no_term_variable_is_a_different_complaint():
    s = sh()
    out, err, rc = run(s, "unset TERM; mc")
    eq("stderr", err.strip(), "The TERM environment variable is unset!")
    eq("rc", rc, 1)
    eq("stdout is empty", out, "")


def t_version():
    s = sh()
    for flag in ("--version", "-V"):
        out, err, rc = run(s, "mc %s" % flag)
        lines = out.splitlines()
        eq("%s: rc" % flag, rc, 0)
        eq("%s: no stderr" % flag, err, "")
        eq("%s: first line" % flag, lines[0],
           "GNU Midnight Commander 4.8.33")
        check("%s: names its S-Lang" % flag,
              "Built with S-Lang 2.3.3 with terminfo database" in lines,
              str(lines[:4]))
        check("%s: lists the virtual filesystems" % flag,
              " cpiofs, tarfs, sfs, extfs, ext2undelfs, ftpfs, sftpfs, shell"
              in lines, str(lines))
        check("%s: ends with the data types" % flag,
              lines[-1].startswith(" char: 8; int: 32; long: 64;"), lines[-1])
        eq("%s: line count" % flag, len(lines), 16)


def t_help():
    s = sh()
    for flag in ("--help", "-h"):
        out, err, rc = run(s, "mc %s" % flag)
        lines = out.splitlines()
        eq("%s: rc" % flag, rc, 0)
        eq("%s: no stderr" % flag, err, "")
        eq("%s: usage" % flag, lines[:2],
           ["Usage:", "  mc [OPTION?] [this_dir] [other_panel_dir]"])
        check("%s: has the Application Options block" % flag,
              "Application Options:" in lines, str(lines[:12]))
        check("%s: documents -P" % flag,
              any(l.startswith("  -P, --printwd=<file>") for l in lines), "")
        check("%s: ends with the bug-report address" % flag,
              lines[-1] == "as tickets at www.midnight-commander.org",
              lines[-1])


def t_an_unknown_option_fails_the_way_glib_fails():
    s = sh()
    out, err, rc = run(s, "mc --nosuchflag")
    lines = (out + err).splitlines()
    eq("rc", rc, 1)
    eq("the first three lines", lines[:3],
       ["Failed to run:", "Unknown option --nosuchflag", ""])
    eq("then the usage, with an ellipsis and not a question mark",
       lines[3:5],
       ["Usage:", "  mc [OPTION…] [this_dir] [other_panel_dir]"])


def t_the_two_usage_lines_really_do_differ():
    """--help says [OPTION?] and the failure says [OPTION…]. Both real."""
    s = sh()
    helped = run(s, "mc --help")[0]
    failed = "".join(run(s, "mc --zzz")[:2])
    check("--help uses a question mark", "[OPTION?]" in helped, helped[:60])
    check("the failure uses an ellipsis", "[OPTION…]" in failed,
          failed[:80])
    check("and neither uses the other's", "[OPTION…]" not in helped
          and "[OPTION?]" not in failed, "")


def t_the_documented_options_are_not_rejected():
    s = sh()
    for flag in ("-f", "--datadir", "-F", "--datadir-info",
                 "--configure-options", "-U", "--subshell",
                 "-u", "--nosubshell"):
        out, err, _rc = run(s, "mc %s" % flag)
        check("%s is not an unknown option" % flag,
              "Unknown option" not in out + err, (out + err)[:60])


def t_a_real_terminal_still_reports_the_gap():
    """The file manager is not implemented and the alert must survive."""
    s = sh(tty=True)
    run(s, "mc")
    kinds = [e for e in s._events if e.get("event") == "unknown_command"]
    check("an unknown_command event was logged", len(kinds) == 1, str(kinds))
    if kinds:
        eq("and it is flagged as a gap", kinds[0].get("gap"), True)


def t_no_terminal_does_not_report_a_gap():
    """...and the case we now answer correctly must not."""
    s = sh()
    run(s, "mc")
    kinds = [e for e in s._events if e.get("event") == "unknown_command"]
    eq("no unknown_command event", kinds, [])


TESTS = [t_it_is_not_there_until_it_is_installed,
         t_installing_it_makes_every_reader_agree,
         t_no_terminal_is_the_answer_an_exec_channel_gets,
         t_no_term_variable_is_a_different_complaint,
         t_version,
         t_help,
         t_an_unknown_option_fails_the_way_glib_fails,
         t_the_two_usage_lines_really_do_differ,
         t_the_documented_options_are_not_rejected,
         t_a_real_terminal_still_reports_the_gap,
         t_no_terminal_does_not_report_a_gap]


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
