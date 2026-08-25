#!/usr/bin/env python3
"""Files the box's own configuration says exist.

Sweep 149. Two halves of one question, both found by comparing what is in
/etc against what is in the guest's /etc rather than by asking two commands
to disagree.

**The four backups.** Every Debian box that has ever had an account added
carries passwd-, group-, shadow- and gshadow-. This one carried none. That
matters more than most absences: `ls -la /etc` shows them, and the
dash-suffixed pairs are a shape people recognise without looking for.
/etc/shadow- is a credential target in its own right -- it holds the PREVIOUS
hashes, so on a real box it sometimes yields an older password that still
works somewhere else, and reading /etc/shadow to find no /etc/shadow- says
something. And they are evidence of history: their absence claims no account
has ever been added, on a box whose /etc/passwd plainly contains a `deploy`
account added after the image was built.

Each backup is the state before that file's LAST write, and the two pairs
were written by different commands, so they are snapshots of different
moments:

    useradd deploy            wrote passwd and shadow
    usermod -aG sudo deploy   wrote group and gshadow

So passwd- predates the account entirely while group- already has the deploy
group and lacks only the sudo membership. `diff /etc/passwd /etc/passwd-`
shows exactly the deploy line; `diff /etc/group /etc/group-` shows exactly
the sudo membership. That internal consistency is what makes the set read as
history rather than as four files someone generated.

**The dangling PAM reference.** /etc/pam.d/login and /etc/pam.d/sshd both
carry `session optional pam_motd.so motd=/run/motd.dynamic`, and neither
/run/motd.dynamic nor /etc/update-motd.d existed. A config file pointing at a
path the box does not have is a one-command tell.

This does NOT conflict with `PrintMotd no` in sshd_config, which is correct
and must stay: on Debian the MOTD is printed by pam_motd, not by sshd. The
defect was never that a banner appears -- it is that the machinery the PAM
stack names was missing.

Run from `honeypot/`.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-54s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


def sh():
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    del s._err[:]
    return s


def run(s, cmd):
    out = s.run(cmd)
    del s._err[:]
    return out


# -- the four backups ----------------------------------------------------

PAIRS = [
    ("/etc/passwd",  "/etc/passwd-",  "644", "root:root"),
    ("/etc/group",   "/etc/group-",   "644", "root:root"),
    ("/etc/shadow",  "/etc/shadow-",  "640", "root:shadow"),
    ("/etc/gshadow", "/etc/gshadow-", "640", "root:shadow"),
]


def t_the_backups_exist_with_the_right_mode():
    s = sh()
    for live, back, mode, owner in PAIRS:
        got = run(s, "stat -c '%%a %%U:%%G' %s" % back).strip()
        eq("%s is %s %s" % (back, mode, owner), got, "%s %s" % (mode, owner))


def t_a_backup_is_older_than_its_live_file():
    """They are the PREVIOUS contents. A backup with the same mtime as its
    live file would say the two were written together, which is not what a
    backup is."""
    s = sh()
    for live, back, _m, _o in PAIRS:
        a = run(s, "stat -c %Y " + live).strip()
        b = run(s, "stat -c %Y " + back).strip()
        check("%s is older than %s" % (back, live),
              a.isdigit() and b.isdigit() and int(b) < int(a),
              "live=%s back=%s" % (a, b))


def t_the_diffs_say_exactly_what_happened():
    """The point of the set. One useradd and one usermod, each visible in the
    file it touched and nowhere else."""
    s = sh()
    d = run(s, "diff /etc/passwd /etc/passwd-")
    check("passwd- differs only by the deploy account",
          d.count("\n") <= 3 and "deploy:x:1000:1000:" in d, repr(d[:80]))
    d = run(s, "diff /etc/shadow /etc/shadow-")
    check("shadow- differs only by the deploy hash",
          "deploy:$y$" in d, repr(d[:60]))
    d = run(s, "diff /etc/group /etc/group-")
    check("group- differs only by the sudo membership",
          "sudo:x:27:deploy" in d and "deploy:x:1000:" not in d, repr(d[:80]))
    d = run(s, "diff /etc/gshadow /etc/gshadow-")
    check("gshadow- differs only by the sudo membership",
          "sudo:*::deploy" in d, repr(d[:60]))


def t_shadow_backup_is_not_world_readable():
    """It holds password hashes. Getting the mode wrong here would hand them
    to any account on the box."""
    s = sh()
    for path in ("/etc/shadow-", "/etc/gshadow-"):
        mode = run(s, "stat -c %a " + path).strip()
        check("%s is not world-readable" % path,
              mode.endswith("0"), mode)
    w = fs.Shell(fs.VFS(), user="www-data", peer="198.51.100.7")
    del w._err[:]
    out = w.run("cat /etc/shadow-")
    err = "".join(w._err)
    del w._err[:]
    check("www-data cannot read it", "Permission denied" in err and not out,
          "%r / %r" % (out[:30], err[:40]))


def t_ls_la_etc_shows_the_pairs():
    """One command, which is how anyone would notice them missing."""
    s = sh()
    listing = run(s, "ls -la /etc")
    for _live, back, _m, _o in PAIRS:
        name = back.rsplit("/", 1)[1]
        check("ls -la /etc lists %s" % name, name in listing)


# -- the MOTD chain ------------------------------------------------------

def t_the_pam_reference_resolves():
    s = sh()
    pam = run(s, "grep -h pam_motd /etc/pam.d/login /etc/pam.d/sshd")
    check("pam.d names /run/motd.dynamic", "/run/motd.dynamic" in pam,
          pam[:70])
    check("and the file is there",
          run(s, "test -f /run/motd.dynamic && echo yes").strip() == "yes")
    mode = run(s, "stat -c '%a %U:%G' /run/motd.dynamic").strip()
    eq("motd.dynamic mode", mode, "644 root:root")


def t_the_generators_are_there_and_executable():
    s = sh()
    listing = sorted(run(s, "ls /etc/update-motd.d").split())
    eq("update-motd.d holds the guest's two", listing,
       ["10-uname", "92-unattended-upgrades"])
    for name, size in (("10-uname", 23), ("92-unattended-upgrades", 165)):
        path = "/etc/update-motd.d/" + name
        eq("%s size" % name, len(run(s, "cat " + path)), size)
        eq("%s is executable" % name,
           run(s, "stat -c %a " + path).strip(), "755")


def t_motd_dynamic_is_what_the_generator_would_produce():
    """It is generated from the same constants uname reads, so the file and
    the command that writes it cannot drift."""
    s = sh()
    eq("motd.dynamic == uname -snrvm",
       run(s, "cat /run/motd.dynamic"), run(s, "uname -snrvm"))


def t_printmotd_no_is_correct_and_still_there():
    """A banner with PrintMotd no is what a real Debian box looks like,
    because pam_motd prints it rather than sshd. This is here so the next
    person does not 'fix' it."""
    s = sh()
    conf = run(s, "grep -E '^PrintMotd' /etc/ssh/sshd_config").strip()
    eq("sshd_config still says PrintMotd no", conf, "PrintMotd no")


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
