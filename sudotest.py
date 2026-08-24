#!/usr/bin/env python3
"""What does sudo tell someone probing what they can do?

203.0.113.34 runs `echo '123456' | sudo -S sh -c 'nproc ...'` on every
visit, which is what made this worth looking at. The privilege decisions
turned out to be right -- www-data is refused with Debian's exact wording,
deploy is allowed, and `sudo -l` matches for both. What was wrong were the
flags that take no command at all:

  - `sudo -V`, `-h`, `--help` and `-v` fell through to the dispatcher,
    which tried to *run* them. `sudo -V` answered
    "bash: line 1: -V: command not found" -- naming bash for a flag sudo
    owns, on the first thing anybody types when working out their
    privileges.
  - A command sudo cannot find is sudo's error. This gave the shell's:
    "bash: line 1: foo: command not found" with status 127, where real
    sudo says "sudo: foo: command not found" and exits 1. The same
    program-name leak the lzma family had.
  - Shell functions are not commands. sudo execs a binary, so it cannot
    see one, and `f(){ :; }; sudo f` is a command-not-found on a real box
    even though the caller's own shell runs f happily.

Formats checked against sudo 1.9.16p2 on a real trixie -- the same version
this box's dpkg claims.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def auth(s):
    """Give a non-root user its password once.

    sudo caches the timestamp for 15 minutes, so every later sudo in the same
    session runs without asking -- which is what a real box does and what the
    checks below assume. They used to assume it without authenticating at all,
    because sudo took any password, including none.
    """
    s.run("echo 'deploy123' | sudo -S true")
    s._err.clear()


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def t_version_is_sudos_own_output():
    """`sudo -V` was dispatched as a command named "-V"."""
    for user in ("root", "deploy", "www-data"):
        out, rc = run(sh(user), "sudo -V")
        eq("%s: rc" % user, rc, 0)
        lines = out.strip().splitlines()
        eq("%s: version line" % user, lines[0], "Sudo version 1.9.16p2")
        check("%s: names the policy plugin" % user,
              any(l.startswith("Sudoers policy plugin version")
                  for l in lines), out[:60])
        check("%s: and the grammar version" % user,
              lines[-1] == "Sudoers file grammar version 50", lines[-1])
        check("%s: no shell error" % user, "command not found" not in out,
              out[:60])
    # The version agrees with what dpkg says is installed.
    out, _rc = run(sh(), "dpkg -l sudo | tail -1")
    check("dpkg agrees on 1.9.16p2", "1.9.16p2" in out, out[:70])


def t_help_is_sudos_usage():
    out, rc = run(sh(), "sudo -h")
    eq("rc", rc, 0)
    check("names itself", out.startswith("sudo - execute a command as"),
          out[:50])
    for line in ("usage: sudo -h | -K | -k | -V", "usage: sudo -v",
                 "usage: sudo -l"):
        check("has %r" % line, line in out, out[:80])


def t_validate_says_nothing_when_it_works():
    """Root needs no password, so -v validates silently and succeeds.

    deploy does need one. This used to assert that deploy validated silently
    too -- which is the behaviour sudo has only for uid 0, as the first line
    of this docstring already said. The assertion contradicted the comment
    directly above it, and passed because sudo accepted any password at all.
    """
    out, rc = run(sh(), "sudo -v")
    eq("root: rc", rc, 0)
    eq("root: silent", out, "")
    d = sh("deploy")
    out, rc = run(d, "sudo -n -v")
    eq("deploy unauthenticated: rc", rc, 1)
    check("deploy unauthenticated: is asked for a password",
          "a password is required" in out, out[:70])
    auth(d)
    out, rc = run(d, "sudo -v")
    eq("deploy authenticated: rc", rc, 0)
    eq("deploy authenticated: silent", out, "")
    out, rc = run(sh("www-data"), "sudo -v")
    eq("www-data: rc", rc, 1)
    check("www-data: refused by name",
          "Sorry, user www-data may not run sudo" in out, out[:70])


def t_remove_timestamp_is_quiet():
    for flag in ("-k", "-K"):
        out, rc = run(sh(), "sudo %s" % flag)
        eq("sudo %s rc" % flag, rc, 0)
        eq("sudo %s silent" % flag, out, "")


def t_a_missing_command_is_sudos_error():
    """It was the shell's, with the shell's exit code."""
    s = sh()
    out, rc = run(s, "sudo definitely-not-a-cmd")
    eq("rc is 1, not 127", rc, 1)
    eq("and sudo names itself", out.strip(),
       "sudo: definitely-not-a-cmd: command not found")
    check("bash is not mentioned", "bash" not in out, out[:60])
    out, rc = run(s, "sudo /nonexistent/path")
    eq("absolute path rc", rc, 1)
    eq("absolute path message", out.strip(),
       "sudo: /nonexistent/path: command not found")


def t_sudo_cannot_run_a_shell_function():
    """sudo execs a binary. The caller's own shell runs the function."""
    s = sh()
    out, rc = run(s, "greet(){ echo hello; }; sudo greet")
    eq("rc", rc, 1)
    eq("message", out.strip(), "sudo: greet: command not found")
    out, rc = run(s, "greet(){ echo hello; }; greet")
    eq("but the shell still runs it", (out.strip(), rc), ("hello", 0))


def t_commands_that_do_exist_still_run():
    """The not-found check must not swallow anything real."""
    s = sh()
    for cmd, want in (("sudo id", "uid=0(root)"),
                      ("sudo /bin/id", "uid=0(root)"),
                      ("sudo whoami", "root"),
                      ("sudo nproc", "4"),
                      ('sudo sh -c "echo hi"', "hi")):
        out, rc = run(s, cmd)
        eq("%s rc" % cmd, rc, 0)
        check("%s output" % cmd, want in out, out[:50])


def t_the_privilege_decisions_are_unchanged():
    """These were already right and are the point of the command."""
    out, rc = run(sh("www-data"), "sudo id")
    eq("www-data refused", rc, 1)
    check("with Debian's wording",
          "www-data is not in the sudoers file." in out, out[:70])
    d = sh("deploy")
    auth(d)
    out, rc = run(d, "sudo id")
    eq("deploy elevated", rc, 0)
    check("to root", "uid=0(root)" in out, out[:50])
    out, _rc = run(d, "sudo -l")
    check("and -l says so", "(ALL : ALL) ALL" in out, out[:70])
    out, rc = run(sh("www-data"), "sudo -l")
    eq("www-data -l rc", rc, 1)
    check("www-data -l refused",
          "may not run sudo" in out, out[:70])


def t_the_live_actors_own_line():
    """`echo '123456' | sudo -S sh -c 'nproc ...'`, verbatim."""
    s = sh()
    out, rc = run(
        s, "echo '123456' | sudo -S sh -c 'nproc 2>/dev/null || "
           "grep -c ^processor /proc/cpuinfo'")
    eq("rc", rc, 0)
    eq("answers the cpu count", out.strip(), "4")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:6]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
