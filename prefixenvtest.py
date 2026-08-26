#!/usr/bin/env python3
"""VAR=value cmd -- what the command is actually given, and where its errors go.

Two bugs in one form, both found while measuring something else, and both
affecting a shape that is everywhere in attacker traffic:

    DEBIAN_FRONTEND=noninteractive apt-get install -y x 2>&1
    LC_ALL=C sort ... 2>&1
    LD_PRELOAD=./hide.so ./payload
    $( ( export LANG=C LC_ALL=C; ... ) 2>&1 )        <- the recon payload

**The redirection went nowhere.** The command ran in a recursive frame after
`_run_simple_inner` had already stripped the redirections from the text, so
that frame had nowhere to send its stderr -- and the outer frame returned
its value directly, skipping the epilogue that folds stderr into stdout.
The error was produced and thrown away:

    ls /nosuchdir 2>&1             ls: cannot access ...
    FOO=1 ls /nosuchdir 2>&1       (nothing)
    FOO=1 ls /nosuchdir 2>/tmp/b   an empty file

Real bash reports it in all three. The unstripped tail is handed down now,
so the frame that runs the command parses its own redirections like any
other command does.

**The assignment was not in the environment.** It set the shell variable and
stopped there, so `FOO=bar env` and `FOO=bar printenv FOO` both printed
nothing, and `LD_PRELOAD=x cmd` set something no child could see -- which is
the entire purpose of the form. Measured against bash:

    FOO=bar env | grep ^FOO        FOO=bar
    FOO=bar printenv FOO           bar
    FOO=bar; env | grep -c ^FOO    0        <- a bare assignment does not export
    FOO=bar true; echo "[$FOO]"    []       <- and does not outlive the command
    export Z=1; Z=2 printenv Z     2
                 printenv Z        1        <- the override is temporary

That last pair is the one worth having: an existing exported variable must
come back afterwards with its old value, not stay overridden and not vanish.

Usage:  python3 prefixenvtest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    s = fakeshell.Shell(fakeshell.VFS(), peer="203.0.113.9", peer_port=44321)
    return s


def main():
    s = sh()

    # -- the environment the command is given -------------------------------
    check("env sees a prefix assignment",
          s.run("FOO=bar env | grep ^FOO"), "FOO=bar\n")
    check("printenv sees it", s.run("FOO=bar printenv FOO"), "bar\n")
    check("two at once", s.run('A=1 B=2 env | grep -cE "^(A|B)="').strip(),
          "2")
    check("a child shell inherits it",
          s.run('FOO=bar sh -c "env | grep ^FOO"'), "FOO=bar\n")

    # ...and does not leak past the command
    check("it does not outlive the command",
          s.run('FOO=bar true; echo "[$FOO]"'), "[]\n")
    check("...not even in the environment",
          s.run("FOO=bar true; env | grep -c ^FOO").strip(), "0")

    # A bare assignment is a shell variable, not an exported one. bash draws
    # this line and so must this: `FOO=bar; env` shows nothing.
    s = sh()
    check("a bare assignment does not export",
          s.run("FOO=bar; env | grep -c ^FOO").strip(), "0")
    check("...but is a shell variable", s.run("FOO=bar; echo $FOO"), "bar\n")

    # An existing exported variable is overridden for one command and comes
    # back afterwards -- not left overridden, not unset.
    s = sh()
    check("an override is temporary",
          s.run("export Z=1; Z=2 printenv Z; printenv Z"), "2\n1\n")
    check("...and the shell variable is restored too",
          s.run("export Z=1; Z=2 true; echo $Z"), "1\n")
    check("...and it is still exported",
          s.run("export Z=1; Z=2 true; env | grep ^Z"), "Z=1\n")

    # -- where the command's errors go --------------------------------------
    s = sh()
    plain = s.run("ls /nosuchdir 2>&1")
    check("the plain form reports the error",
          "No such file or directory" in plain, True)
    check("the prefix form reports the same error",
          s.run("FOO=1 ls /nosuchdir 2>&1"), plain)
    check("...to a file as well",
          "No such file or directory" in
          s.run("FOO=1 ls /nosuchdir 2>/tmp/b; cat /tmp/b"), True)
    check("...and 2>/dev/null still swallows it",
          s.run("FOO=1 ls /nosuchdir 2>/dev/null"), "")
    check("...with several assignments",
          "No such file or directory" in
          s.run("A=1 B=2 ls /nosuchdir 2>&1"), True)

    # stdout redirection was never broken; check it did not become so.
    s = sh()
    check("stdout still redirects",
          s.run("FOO=1 echo hi > /tmp/o; cat /tmp/o"), "hi\n")
    check("...and appends", s.run("FOO=1 echo a > /tmp/o2; "
                                  "FOO=1 echo b >> /tmp/o2; cat /tmp/o2"),
          "a\nb\n")
    check("stdout to a file leaves stderr on the terminal",
          "No such file or directory" in
          s.run("FOO=1 ls /nosuchdir > /tmp/o3 2>&1; cat /tmp/o3"), True)

    # -- the exit status is the command's, not the assignment's --------------
    s = sh()
    check("a failing command's status survives the prefix",
          s.run("FOO=1 ls /nosuchdir 2>/dev/null; echo $?").strip(), "2")
    check("...and a succeeding one's",
          s.run("FOO=1 true; echo $?").strip(), "0")

    # -- the form that started this ------------------------------------------
    # LD_PRELOAD is only meaningful if the child can see it, and the loader
    # message is only useful if it lands where the attacker redirected it.
    s = sh()
    out = s.run("LD_PRELOAD=/opt/nope.so id 2>&1")
    check("LD_PRELOAD as a prefix reaches the loader",
          out.splitlines()[0] if out else "",
          "ERROR: ld.so: object '/opt/nope.so' from LD_PRELOAD cannot be "
          "preloaded (cannot open shared object file): ignored.")
    check("...and the command still runs", "uid=0(root)" in out, True)
    check("...and it does not persist to the next command",
          s.run("id 2>&1"), "uid=0(root) gid=0(root) groups=0(root)\n")

    # -- and the locale case that always worked ------------------------------
    # LC_ALL=C is the one prefix that was special-cased, so it is the control:
    # if this breaks, the change went too far.
    s = sh()
    check("LC_ALL=C still reaches the command",
          bool(s.run("LC_ALL=C date +%A").strip()), True)
    check("...and does not leak",
          s.run("LC_ALL=C true; echo \"[$LC_ALL]\""), "[]\n")

    for name, got, want in FAILS:
        print("  FAIL %-56s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("prefixenvtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
