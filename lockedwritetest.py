#!/usr/bin/env python3
"""Every writer has to fail the same way on a locked file.

The loader that landed here at 04:30 does this to the ssh key it plants:

    chattr -ia ~/.ssh/authorized_keys      # unlock, in case a previous run locked it
    echo "ssh-rsa AAAA..." > ~/.ssh/authorized_keys
    chattr +ai ~/.ssh/authorized_keys      # append-only AND immutable

and its clean.sh runs `sed -i` over cron files it has just chattr'd. So the
box gets asked "what happens when you write to a locked file" several times
per visit, by a script that set the lock itself and knows what the answer
should be.

Five writers gave five answers, and four of them were wrong in the same
direction -- claiming the file did not exist:

    cp     cp: cannot create regular file 'imm': No such file or directory
    tee    tee: imm: No such file or directory
    dd     6 bytes copied, then failed to open ... No such file or directory
    sed -i (silent, exit 0)
    >      bash: imm: Operation not permitted            <- the only right one

`ls -l` lists the file and `cat` reads it, so "No such file or directory" is
two commands on one box disagreeing about whether it is there. And dd
reported a transfer that then failed, which is a copy that both happened and
did not.

Measured on the guest (Debian 13.6, ext4, chattr as root):

    echo B > imm      bash: line 4: imm: Operation not permitted     rc 1
    echo B >> imm     the same                                       rc 1
    : > imm           the same                                       rc 1
    echo B > app      bash: line 6: app: Operation not permitted     rc 1
    echo B >> app     appends -- append-only permits appends         rc 0
    cp x imm          cp: cannot create regular file 'imm': Operation not permitted
    tee imm           tee: imm: Operation not permitted
    dd of=imm         dd: failed to open 'imm': Operation not permitted
                      ...and no statistics at all
    sed -i s/A/Z/ imm sed: cannot rename ./sedNulwxv: Operation not permitted  rc 4
    truncate -s 0 imm truncate: cannot open 'imm' for writing: Operation not permitted
    touch imm         touch: cannot touch 'imm': Operation not permitted
    chmod 600 imm     chmod: changing permissions of 'imm': Operation not permitted

sed's temp name is mkstemp's six mixed-case alphanumerics, not six hex
digits -- a %X of a hash has its own look. sed's exit status is 4.

Writing this suite turned up a second bug, in the harness's own way of
measuring: `{ cmd; } 2>file` and `( cmd ) 2>file` both wrote an **empty
file** while `cmd 2>file` beside them worked. The group branch folded
`2>&1` and dropped `2>file` on the floor -- two spellings of "put this
group's errors in a file", one of them silent. `2>&1` on the same group
always worked, which is why nobody had noticed. Same family as sweep 170:
an epilogue that handles one redirection form and forgets another.

One thing that was already right and worth not breaking: `echo B > imm 2>&1`
shows *nothing* on stdout. bash applies redirections left to right, so the
failing `> imm` aborts the command before `2>&1` is in effect and the error
goes to the original stderr. A first pass at measuring this read the silence
as a missing message; it is bash being bash.

Usage:  python3 lockedwritetest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []
EPERM = "Operation not permitted"


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def box():
    fs = fakeshell.VFS()
    sh = fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321)
    sh.run("mkdir -p /var/tmp/w && cd /var/tmp/w")
    return fs, sh


def locked(sh, flags="+i", name="imm"):
    sh.run("cd /var/tmp/w && echo A > %s && chattr %s %s" % (name, flags, name))
    return name


def run_one(sh, cmd):
    """(stderr, rc) from one run, without disturbing the command's own fds.

    The first version of this appended `>/dev/null 2>&1` to capture the
    status -- which gives the tested command *two* stdout redirects, so
    `echo B > imm` wrote to /dev/null and never touched the locked file at
    all. Every check then passed or failed for the wrong reason. Same trap
    as sweep 163's `echo pwned > file >/dev/null 2>&1`.

    Wrapping in `{ ...; } 2>file` puts the capture on the group, leaving the
    inner redirections alone -- which is how you would do it in a real
    shell, and is the only way to ask this question without changing it.
    """
    out = sh.run("cd /var/tmp/w && { %s ; } 2>/var/tmp/w/.e; echo rc=$?"
                 % cmd)
    rc = ""
    for line in out.splitlines():
        if line.startswith("rc="):
            rc = line[3:].strip()
    return sh.run("cat /var/tmp/w/.e").strip(), rc


def err_of(sh, cmd):
    return run_one(sh, cmd)[0]


def rc_of(sh, cmd):
    return run_one(sh, cmd)[1]


def main():
    # -- the lock is visible ------------------------------------------------
    fs, sh = box()
    locked(sh, "+ai")
    la = sh.run("cd /var/tmp/w && lsattr imm").split()[0]
    check("lsattr shows both flags the loader sets",
          set("ai") <= set(la), True)
    check("...and the file is plainly there",
          sh.run("cd /var/tmp/w && cat imm"), "A\n")

    # -- bash's own redirects ------------------------------------------------
    fs, sh = box()
    locked(sh)
    for cmd in ("echo B > imm", "echo B >> imm", ": > imm"):
        check("%s says EPERM" % cmd, EPERM in err_of(sh, cmd), True)
        check("%s exits 1" % cmd, rc_of(sh, cmd), "1")
    check("the file is untouched", sh.run("cd /var/tmp/w && cat imm"), "A\n")

    # A failing redirect aborts before 2>&1 takes effect -- bash, not a bug.
    check("2>&1 does not capture a failed redirect's own error",
          sh.run("cd /var/tmp/w && echo B > imm 2>&1"), "")

    # -- append-only permits appends and refuses truncation ------------------
    fs, sh = box()
    locked(sh, "+a", "app")
    check("append-only lets an append through",
          rc_of(sh, "echo B >> app"), "0")
    check("...and the content grew",
          sh.run("cd /var/tmp/w && cat app"), "A\nB\n")
    check("but a truncating redirect is refused",
          EPERM in err_of(sh, "echo C > app"), True)
    check("...with status 1", rc_of(sh, "echo C > app"), "1")
    check("...and the content did not change",
          sh.run("cd /var/tmp/w && cat app"), "A\nB\n")

    # -- and every other writer says the same thing --------------------------
    fs, sh = box()
    locked(sh)
    cases = [
        ("cp /etc/hostname imm", "cp: cannot create regular file 'imm': "
         + EPERM),
        ("echo B | tee imm", "tee: imm: " + EPERM),
        ("dd if=/etc/hostname of=imm", "dd: failed to open 'imm': " + EPERM),
        ("truncate -s 0 imm",
         "truncate: cannot open 'imm' for writing: " + EPERM),
        ("touch imm", "touch: cannot touch 'imm': " + EPERM),
        ("chmod 600 imm",
         "chmod: changing permissions of 'imm': " + EPERM),
    ]
    for cmd, want in cases:
        got = err_of(sh, cmd)
        check("%s names the right reason" % cmd.split()[0],
              want in got, True)
        check("%s does not claim the file is missing" % cmd.split()[0],
              "No such file" in got, False)
    check("nothing got through", sh.run("cd /var/tmp/w && cat imm"), "A\n")

    # dd prints no statistics when it cannot open the output.
    got = err_of(sh, "dd if=/etc/hostname of=imm")
    check("dd reports no transfer it did not make",
          "copied" in got or "records" in got, False)
    # ...but a dd that works still reports them.
    ok = err_of(sh, "dd if=/etc/hostname of=fine")
    check("a dd that works still prints its statistics",
          "records in" in ok and "copied" in ok, True)

    # -- sed -i, which is what clean.sh runs ---------------------------------
    fs, sh = box()
    locked(sh)
    got = err_of(sh, "sed -i s/A/Z/ imm")
    check("sed -i reports the rename it could not do",
          got.endswith(EPERM) and got.startswith("sed: cannot rename ./sed"),
          True)
    m = re.match(r"^sed: cannot rename \./sed([A-Za-z0-9]{6}): ", got)
    check("...with mkstemp's six alphanumerics, not six hex digits",
          bool(m) and not re.fullmatch(r"[0-9A-F]{6}", m.group(1)), True)
    check("sed -i exits 4", rc_of(sh, "sed -i s/A/Z/ imm"), "4")
    check("...and the file is unchanged",
          sh.run("cd /var/tmp/w && cat imm"), "A\n")
    # The same sed on an unlocked file still works.
    sh.run("cd /var/tmp/w && echo A > free")
    check("sed -i still edits a file it may edit",
          sh.run("cd /var/tmp/w && sed -i s/A/Z/ free && cat free"), "Z\n")

    # -- unlocking restores every one of them --------------------------------
    # The loader's first move is `chattr -ia`, so this is the path it takes.
    fs, sh = box()
    locked(sh, "+ai")
    check("locked first", EPERM in err_of(sh, "cp /etc/hostname imm"), True)
    sh.run("cd /var/tmp/w && chattr -ia imm")
    check("after chattr -ia, the redirect works",
          sh.run("cd /var/tmp/w && echo KEY > imm && cat imm"), "KEY\n")
    check("...and cp works", rc_of(sh, "cp /etc/hostname imm"), "0")
    check("...and sed -i works",
          rc_of(sh, "sed -i s/web01/x/ imm"), "0")

    # -- the group redirection this suite needed to measure any of it --------
    # `{ cmd; } 2>file` wrote an empty file while `cmd 2>file` worked.
    fs, sh = box()
    for form in ("{ ls /nosuch ; }", "( ls /nosuch )"):
        sh.run("cd /var/tmp/w && %s 2>/var/tmp/w/.g" % form)
        check("%s 2>file captures the error" % form,
              "No such file or directory" in sh.run("cat /var/tmp/w/.g"), True)
    check("...and 2>&1 on a group still works",
          "No such file or directory" in
          sh.run("cd /var/tmp/w && { ls /nosuch ; } 2>&1"), True)
    check("...and 2>/dev/null on a group still swallows it",
          sh.run("cd /var/tmp/w && { ls /nosuch ; } 2>/dev/null"), "")
    sh.run("cd /var/tmp/w && { echo hi ; } 2>/var/tmp/w/.g2")
    check("a group with no errors truncates the target",
          sh.run("cat /var/tmp/w/.g2"), "")
    sh.run("cd /var/tmp/w && rm -f .g3")
    sh.run("cd /var/tmp/w && { ls /nosuch ; } 2>>.g3")
    sh.run("cd /var/tmp/w && { ls /nosuch2 ; } 2>>.g3")
    check("2>> appends across two groups",
          sh.run("cd /var/tmp/w && grep -c cannot .g3").strip(), "2")

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("lockedwritetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
