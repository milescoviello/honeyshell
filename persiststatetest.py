#!/usr/bin/env python3
"""What an attacker changes has to survive a restart, or none of it should.

The replay journal is why a file an attacker wrote is still there when they
reconnect. The bytes came back and the mode came back -- and three other
things they had set did not:

  * `chattr +i` was not journalled at all, so the immutable flag vanished on
    every restart. A returning actor found the file they had locked
    unlocked, and `rm` working again. The honeypot has restarted twenty
    times this month, so this was not hypothetical, and RedTail's setup.sh
    runs `chattr -ia` before writing precisely because it expects the flag
    to be there.
  * a package hold lived in a dict on the VFS, so `apt-mark showhold` was
    empty again afterwards while nothing on disk had ever recorded it.
  * `systemctl mask` set a flag instead of creating the /dev/null symlink
    systemd actually creates, so the mask went away too -- and
    `ls -l /etc/systemd/system/cron.service` disagreed with `is-enabled`
    even before any restart.

The fix for the last two was not to journal more, it was to **put the state
where the real box puts it**: a hold is the first word of the package's
Status line in /var/lib/dpkg/status, and a mask is a symlink to /dev/null.
Both are then files, and files already survive. One copy of the answer
instead of two, and persistence for free.

And `chattr -R` was not recursing. The real one sets the flag on the
directory and on every file beneath it; this set it only on the name given.
So `chattr -R +i /usr/bin` -- the last thing the miner installer runs --
locked the directory against new names and left every binary in it
writable, and `echo pwned > /usr/bin/curl` went straight through.

Usage:  python3 persiststatetest.py
"""

import sys

import fakeshell as F

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def restart(vfs):
    """A fresh filesystem with the journal replayed, as a restart does."""
    v2 = F.VFS()
    v2.load_journal(vfs.dump_journal())
    return F.Shell(vfs=v2)


def staged():
    """A box an attacker has been on."""
    v = F.VFS()
    s = F.Shell(vfs=v)
    s.run("echo IMPLANT > /root/.hidden")
    s.run("chmod 4755 /root/.hidden")
    s.run("chattr +i /root/.hidden")
    s.run("apt-mark hold procps")
    s.run("systemctl mask cron.service")
    return v, s


def t_everything_they_set_comes_back():
    v, s = staged()
    s2 = restart(v)
    for label, cmd in (("contents", "cat /root/.hidden"),
                       ("mode", "stat -c %a /root/.hidden"),
                       ("attrs", "lsattr /root/.hidden"),
                       ("hold", "apt-mark showhold"),
                       ("mask", "systemctl is-enabled cron")):
        check("%s survives a restart" % label,
              s2.run(cmd).strip(), s.run(cmd).strip())
    # And the flag still *does* something afterwards.
    check("the immutable file still refuses rm",
          s2.run("rm -f /root/.hidden >/dev/null 2>&1; echo $?").strip(), "1")
    check("...and is still there",
          s2.run("cat /root/.hidden").strip(), "IMPLANT")


def t_a_hold_is_the_dpkg_status_field():
    """Not a side dict: the place dpkg keeps it."""
    v = F.VFS()
    s = F.Shell(vfs=v)
    s.run("apt-mark hold procps")
    line = [l for l in s.run("grep -A4 '^Package: procps$' /var/lib/dpkg/status")
            .splitlines() if l.startswith("Status:")]
    check("the Status line says hold", line[:1], ["Status: hold ok installed"])
    check("dpkg --get-selections agrees",
          s.run("dpkg --get-selections procps").split()[1], "hold")
    check("apt-mark showhold agrees", s.run("apt-mark showhold").strip(),
          "procps")
    s.run("apt-mark unhold procps")
    line2 = [l for l in s.run("grep -A4 '^Package: procps$' /var/lib/dpkg/status")
             .splitlines() if l.startswith("Status:")]
    check("unhold puts the Status line back", line2[:1],
          ["Status: install ok installed"])
    check("and showhold is empty again", s.run("apt-mark showhold").strip(), "")


def t_a_mask_is_a_symlink_to_dev_null():
    v = F.VFS()
    s = F.Shell(vfs=v)
    out = s.run("systemctl mask cron.service 2>&1").strip().splitlines()
    check("mask narrates exactly once", len(out), 1)
    check("...with systemd's arrow",
          out[0] if out else "",
          "Created symlink '/etc/systemd/system/cron.service' → '/dev/null'.")
    check("the symlink is there",
          s.run("readlink /etc/systemd/system/cron.service").strip(),
          "/dev/null")
    check("is-enabled reads it",
          s.run("systemctl is-enabled cron").strip(), "masked")
    # A timer keeps its own suffix -- this used to hardcode ".service".
    s.run("systemctl mask apt-daily.timer")
    check("a timer is masked under its own name",
          s.run("readlink /etc/systemd/system/apt-daily.timer").strip(),
          "/dev/null")
    off = s.run("systemctl unmask cron.service 2>&1").strip().splitlines()
    check("unmask narrates exactly once", len(off), 1)
    check("...and removes it",
          s.run("test -e /etc/systemd/system/cron.service; echo $?").strip(),
          "1")
    check("unmasking twice is quiet",
          s.run("systemctl unmask cron.service 2>&1").strip(), "")


def t_chattr_R_recurses():
    v = F.VFS()
    s = F.Shell(vfs=v)
    s.run("chattr -R +i /usr/bin")
    check("the directory is locked",
          "i" in s.run("lsattr -d /usr/bin").split()[0], True)
    for f in ("/usr/bin/curl", "/usr/bin/wget"):
        check("%s is locked too" % f,
              "i" in s.run("lsattr %s" % f).split()[0], True)
    # The point of it: the bytes are protected, not just the names.
    # Only ONE stdout redirection: `> file >/dev/null` sends the write to
    # /dev/null instead, so the first version of this check passed the write
    # nowhere near the locked file and read rc 0 as a failure to protect it.
    check("an existing binary cannot be overwritten",
          s.run("echo pwned > /usr/bin/curl 2>/dev/null; echo $?").strip(),
          "1")
    # `file`, not od: od prints the bytes space-separated ("177 E L F"), so
    # looking for "ELF" as a substring of that never matches.
    check("...and is intact", "ELF" in s.run("file /usr/bin/curl"), True)
    # Without -R only the named directory changes.
    s3 = F.Shell()
    s3.run("chattr +i /usr/bin")
    check("without -R the contents are untouched",
          "i" in s3.run("lsattr /usr/bin/curl").split()[0], False)
    # And the recursion survives a restart.
    s2 = restart(v)
    check("after a restart the contents are still locked",
          "i" in s2.run("lsattr /usr/bin/curl").split()[0], True)
    check("...and still refuse a write",
          s2.run("echo x > /usr/bin/curl 2>/dev/null; echo $?").strip(), "1")


def t_the_installers_own_sequence():
    """chattr -R +i on all four bin directories, then a restart."""
    v = F.VFS()
    s = F.Shell(vfs=v)
    s.run("chattr -R +i /bin /usr/bin /sbin /usr/sbin")
    s2 = restart(v)
    for d in ("/usr/bin", "/usr/sbin"):
        check("%s still locked after a restart" % d,
              "i" in s2.run("lsattr -d %s" % d).split()[0], True)
        check("nothing can be added to %s" % d,
              s2.run("touch %s/newtool >/dev/null 2>&1; echo $?" % d).strip(),
              "1")


def main():
    for fn in (t_everything_they_set_comes_back,
               t_a_hold_is_the_dpkg_status_field,
               t_a_mask_is_a_symlink_to_dev_null,
               t_chattr_R_recurses,
               t_the_installers_own_sequence):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-52s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("persiststatetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
