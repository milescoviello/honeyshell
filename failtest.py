#!/usr/bin/env python3
"""The wording and exit status of every way a command can fail.

This axis is not speculative. The kit that logged in from 203.0.113.34
at 02:32 and again at 07:33 today runs, under its own
`===SHELL_BEHAVIOR===` banner:

    path_err=    ( ./xxxxxx 2>&1 )        first 250 bytes
    cmd_err=     ( xxxxxx 2>&1 )          first 250 bytes
    execute_err= write filter, chmod +x, ./filter, rm -rf filter

and ships the results home. It is measuring our error strings directly.
Those three matched the guest byte for byte -- so this suite starts from
the probe the attacker actually sends, and then covers the neighbourhood
it did not reach, where nine answers were wrong:

    ./loop (symlink loop)  silence and rc 0, where the kernel gives ELOOP
    PATH=/tmp/pt mybin     "command not found" for a payload the box had
                           just created, chmod'd and listed -- PATH was
                           ignored entirely, so a staging directory an
                           attacker prepends does not work
    PATH= ls               ran ls anyway
    command nosuchcmd      silence and rc 1; bare `command` runs its
                           target, it does not look it up
    env/xargs/timeout/nohup/setsid/nice/find -exec
                           all answered in bash's voice for a failure
                           bash never saw, from commands that name
                           themselves -- and they do not agree with each
                           other: coreutils uses curly quotes, nohup uses
                           ASCII ones, setsid uses none
    sh -c / sh script      answered as bash, on a box that says dash
                           everywhere else ($0, export -p, BASH_VERSION)

Every string and status below was measured on the guest.
"""
import sys

import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.200")
    s.exec_mode = True
    s.run("""cd /tmp && rm -rf ep && mkdir ep && cd ep
mkdir adir
echo hello > noexec.sh; chmod 644 noexec.sh
printf '#!/nonexistent/interp\\necho hi\\n' > badinterp.sh; chmod +x badinterp.sh
printf '\\x7fELFgarbage' > badelf; chmod +x badelf
: > empty.sh; chmod +x empty.sh
ln -s loop loop""")
    return v, s


def fail(s, cmd):
    """(first stderr line, rc) for a command run in the scratch dir."""
    s._err = []
    s.run("cd /tmp/ep && " + cmd)
    return ("".join(s._err).splitlines() or [""])[0], s.last_rc


def main():
    v, s = sh()

    # -- the probe the kit actually sends -------------------------------------
    probe = (r"""( export LANG=C LC_ALL=C; echo '===SHELL_BEHAVIOR==='; """
             r"""printf 'path_err='; ( ./xxxxxx 2>&1 || true ) | head -c 250 """
             r"""| tr -d '\n'; printf '\n'; printf 'cmd_err='; """
             r"""( xxxxxx 2>&1 || true ) | head -c 250 | tr -d '\n'; """
             r"""printf '\n'; printf 'execute_err='; out=$(bash -c 'printf """
             r""""#!/bin/bash\necho \"xxxxxx\"\n" > filter && chmod +x filter """
             r"""&& ./filter && rm -rf filter' 2>&1); printf '%s' "$out" """
             r"""| head -c 250 | tr -d '\n'; printf '\n'; echo '===DONE===' ) 2>&1""")
    check("the kit's own probe answers as the guest does",
          s.run("cd /tmp/ep && " + probe),
          "===SHELL_BEHAVIOR===\n"
          "path_err=bash: line 1: ./xxxxxx: No such file or directory\n"
          "cmd_err=bash: line 1: xxxxxx: command not found\n"
          "execute_err=xxxxxx\n"
          "===DONE===\n")

    # -- every exec failure, message and status -------------------------------
    for cmd, want in (
            ("./nosuchfile",
             ("bash: line 1: ./nosuchfile: No such file or directory", 127)),
            ("nosuchcmd",
             ("bash: line 1: nosuchcmd: command not found", 127)),
            ("./adir", ("bash: line 1: ./adir: Is a directory", 126)),
            ("./noexec.sh",
             ("bash: line 1: ./noexec.sh: Permission denied", 126)),
            ("./badinterp.sh",
             ("bash: line 1: ./badinterp.sh: cannot execute: "
              "required file not found", 127)),
            ("./badelf",
             ("bash: line 1: ./badelf: cannot execute binary file: "
              "Exec format error", 126)),
            ("./empty.sh", ("", 0)),
            ("./loop",
             ("bash: line 1: ./loop: Too many levels of symbolic links", 126)),
            ("/etc/passwd",
             ("bash: line 1: /etc/passwd: Permission denied", 126)),
            ("/bin/nosuchfile",
             ("bash: line 1: /bin/nosuchfile: No such file or directory",
              127))):
        check("%s" % cmd, fail(s, cmd), want)

    # 126 is "found but could not run", 127 is "not found". Those two
    # statuses are what a loader branches on.
    check("a missing target is 127, an unrunnable one 126",
          (fail(s, "./nosuchfile")[1], fail(s, "./noexec.sh")[1]), (127, 126))

    # -- each wrapper in its own voice ----------------------------------------
    for cmd, want in (
            ("env nosuchcmd",
             ("env: ‘nosuchcmd’: No such file or directory", 127)),
            ("nice nosuchcmd",
             ("nice: ‘nosuchcmd’: No such file or directory", 127)),
            ("timeout 1 nosuchcmd",
             ("timeout: failed to run command ‘nosuchcmd’: "
              "No such file or directory", 127)),
            ("nohup nosuchcmd",
             ("nohup: failed to run command 'nosuchcmd': "
              "No such file or directory", 127)),
            ("setsid nosuchcmd",
             ("setsid: failed to execute nosuchcmd: "
              "No such file or directory", 127)),
            ("xargs nosuchcmd </dev/null",
             ("xargs: nosuchcmd: No such file or directory", 127)),
            ("stdbuf -o0 nosuchcmd",
             ("stdbuf: failed to run command ‘nosuchcmd’: "
              "No such file or directory", 127))):
        check("%s" % cmd.split()[0], fail(s, cmd), want)
    # nohup's quotes are ASCII and coreutils' are curly. Getting that
    # backwards is the kind of thing only a diff catches.
    check("nohup quotes with ASCII, env with curly",
          ("'nosuchcmd'" in fail(s, "nohup nosuchcmd")[0],
           "‘nosuchcmd’" in fail(s, "env nosuchcmd")[0]),
          (True, True))
    check("find names itself and keeps going",
          fail(s, r"find . -maxdepth 0 -exec nosuchcmd {} \;"),
          ("find: ‘nosuchcmd’: No such file or directory", 0))
    # ...and each of them still runs a command that does exist.
    for wrapper in ("env", "nice", "timeout 1", "setsid", "stdbuf -o0"):
        s._err = []
        out = s.run("cd /tmp/ep && %s echo ran" % wrapper)
        check("%s still runs a real command" % wrapper.split()[0],
              "ran" in out, True)
    # nohup is the exception: it runs the command and sends the output to
    # nohup.out, so stdout is empty by design. The first draft of this
    # check expected "ran" on stdout, which is the one wrapper where that
    # is wrong -- the box was right.
    s._err = []
    out = s.run("cd /tmp/ep && nohup echo ran")
    check("nohup runs it and redirects the output", out.strip(), "")
    check("...into nohup.out",
          s.run("cd /tmp/ep && cat nohup.out").strip(), "ran")
    check("...saying so on stderr",
          "appending output to" in "".join(s._err), True)

    # -- sh is dash ------------------------------------------------------------
    check("sh -c on a missing path", fail(s, "sh -c ./nosuchfile"),
          ("sh: 1: ./nosuchfile: not found", 127))
    check("sh -c on a missing command", fail(s, "sh -c nosuchcmd"),
          ("sh: 1: nosuchcmd: not found", 127))
    check("sh on a missing script", fail(s, "sh nosuchfile"),
          ("sh: 0: cannot open nosuchfile: No such file", 2))
    check("bash on a missing script", fail(s, "bash nosuchfile"),
          ("bash: nosuchfile: No such file or directory", 127))
    check("and bash -c keeps bash's wording", fail(s, "bash -c nosuchcmd"),
          ("bash: line 1: nosuchcmd: command not found", 127))

    # -- PATH is a path --------------------------------------------------------
    v2, s2 = sh()
    s2.run("mkdir -p /tmp/pt && printf '#!/bin/sh\\necho MINE\\n' "
           "> /tmp/pt/mybin && chmod +x /tmp/pt/mybin")
    check("a dropped binary on PATH runs",
          s2.run("PATH=/tmp/pt mybin").strip(), "MINE")
    check("...and prepending to PATH works too",
          s2.run("export PATH=/tmp/pt:$PATH; mybin").strip(), "MINE")
    # `PATH=/tmp/pt which mybin` cannot work: which is not in /tmp/pt
    # either. The guest answers "which: command not found" for exactly the
    # same reason, which is what the first draft of this check missed.
    s2._err = []
    s2.run("PATH=/tmp/pt which mybin")
    check("which is itself subject to PATH",
          "which: command not found" in "".join(s2._err), True)
    check("which finds it when PATH can reach both",
          s2.run("PATH=/tmp/pt:$PATH which mybin").strip(), "/tmp/pt/mybin")
    check("command -v agrees",
          s2.run("PATH=/tmp/pt command -v mybin").strip(), "/tmp/pt/mybin")
    check("type agrees",
          s2.run("PATH=/tmp/pt type mybin").strip(), "mybin is /tmp/pt/mybin")
    # ...and a PATH that cannot reach a command breaks it, differently
    # depending on whether PATH is empty or merely wrong.
    s2._err = []
    s2.run("PATH=/nonexistent ls")
    check("PATH without the directory is command not found",
          ("".join(s2._err).strip(), s2.last_rc),
          ("bash: line 1: ls: command not found", 127))
    s2._err = []
    s2.run("PATH= ls")
    check("an empty PATH is No such file or directory",
          ("".join(s2._err).strip(), s2.last_rc),
          ("bash: line 1: ls: No such file or directory", 127))
    s2._err = []
    s2.run("PATH=/tmp/pt which mybin >/dev/null; PATH=/tmp/pt ls")
    check("a stock binary PATH cannot reach is not found either",
          "command not found" in "".join(s2._err), True)
    check("and the default PATH still finds everything",
          s2.run("which ls").strip(), "/usr/bin/ls")

    # -- command runs, it does not look up -------------------------------------
    v3, s3 = sh()
    check("command runs its target",
          s3.run("command echo hi").strip(), "hi")
    s3._err = []
    s3.run("command nosuchcmd")
    check("...and reports a missing one like bash",
          ("".join(s3._err).strip(), s3.last_rc),
          ("bash: line 1: nosuchcmd: command not found", 127))
    check("command -v is still the lookup",
          s3.run("command -v ls").strip(), "/usr/bin/ls")
    check("command -v on a missing name is silent rc 1",
          (s3.run("command -v nosuchcmd"), s3.last_rc), ("", 1))
    check("command -V still describes",
          s3.run("command -V cd").strip(), "cd is a shell builtin")

    # -- and the lookup commands agree with each other -------------------------
    check("which, command -v and type name the same file",
          (s3.run("which ls").strip(),
           s3.run("command -v ls").strip(),
           s3.run("type ls").strip().split()[-1]),
          ("/usr/bin/ls", "/usr/bin/ls", "/usr/bin/ls"))
    check("...and all three fail together on a missing one",
          (s3.run("which nosuchcmd; echo $?").strip(),
           s3.run("command -v nosuchcmd; echo $?").strip(),
           s3.run("type nosuchcmd >/dev/null 2>&1; echo $?").strip()),
          ("1", "1", "1"))

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("failtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
