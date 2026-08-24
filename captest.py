#!/usr/bin/env python3
"""The privilege-escalation recon surface, and whether it agrees with itself.

Every actor that lands on this box asks the same three questions before it
decides what it can do: what is setuid, what carries capabilities, and what is
on my PATH. They are three readings of one thing -- who is allowed to do what
-- and the box answered them from four unrelated places.

Measured against the guest on 2026-08-24:

  SUID/SGID was already right and is pinned here rather than changed. Twelve
  setuid files, four setgid, and the one difference from the guest --
  /usr/lib/polkit-1/polkit-agent-helper-1 -- is correct, because this persona
  does not run polkit while the guest does. `find -perm` tracks a chmod in
  both directions, so find, ls -l and stat cannot drift.

  Capabilities did not exist. The guest has libcap2-bin 1:2.75-10+deb13u1+b1
  with getcap, setcap, capsh and getpcaps in /usr/sbin; the persona had
  neither the package nor the binaries, so `getcap -r / 2>/dev/null` -- which
  sits directly beside `find / -perm -4000` in every privesc script --
  answered "command not found". The numbers were also written down three
  times: /proc/<pid>/status had two literals for CapPrm and CapEff and a
  third for CapBnd, and capsh would have been a fourth.

  PATH was root's, for everybody. /etc/profile in this same persona says a
  non-root user gets "/usr/local/bin:/usr/bin:/bin:/usr/games" and root gets
  the sbin-bearing one -- and every session, whatever its uid, got root's.
  So `echo $PATH` and `cat /etc/profile` contradicted each other in two
  commands, and `which useradd`, `which iptables` and `which getcap` all
  succeeded from a www-data webshell.

  Fixing PATH exposed the next one: an absolute path was still subject to
  PATH. dispatch resolved /usr/sbin/useradd, found its handler, then recursed
  with the bare name and re-ran the PATH gate, so a file `ls -l` had just
  listed came back "command not found". Invisible while everyone had root's
  PATH.

  And fixing *that* made the privilege checks load-bearing. useradd, usermod,
  groupadd and gpasswd had none: the PATH accident was the only thing stopping
  a www-data webshell from calling /usr/sbin/useradd by absolute path and
  really creating an account.

Run from ~/opsec/honeypot:  python3 -W ignore captest.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell                                                # noqa: E402

#: `find / -perm -4000 -type f` on the guest, sorted.
GUEST_SUID = (
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/sudo",
    "/usr/bin/umount", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
)
#: ...minus the one that belongs to polkit, which this persona does not run.
PERSONA_SUID_OMITS = ("/usr/lib/polkit-1/polkit-agent-helper-1",)
#: `find / -perm -2000 -type f` on the guest. The persona adds crontab,
#: because it installs cron and the guest does not.
GUEST_SGID = ("/usr/bin/chage", "/usr/bin/expiry", "/usr/bin/ssh-agent",
              "/usr/sbin/unix_chkpwd")
PERSONA_SGID_ADDS = ("/usr/bin/crontab",)

#: dpkg -L libcap2-bin, binaries only. All four are in /usr/sbin.
GUEST_LIBCAP_BINS = ("capsh", "getcap", "getpcaps", "setcap")
GUEST_LIBCAP_VERSION = "1:2.75-10+deb13u1+b1"
#: PATH, measured in three contexts on the guest.
GUEST_PATH_ROOT = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
GUEST_PATH_USER = "/usr/local/bin:/usr/bin:/bin:/usr/games"
GUEST_PATH_USER_LOGIN = ("/usr/local/bin:/usr/bin:/bin:"
                         "/usr/local/games:/usr/games")
#: capsh --print's bounding set, which is what makes CapBnd 000001ffffffffff.
GUEST_CAP_COUNT = 41
GUEST_CAPBND_HEX = "000001ffffffffff"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  %s  %s%s" % ("ok  " if cond else "FAIL", name,
                          "" if cond else "  " + str(detail)[:240]))
    return bool(cond)


def eq(name, got, want):
    return check(name, got == want, "got %r want %r" % (got, want))


class Sh:
    def __init__(self, user="root"):
        self.sh = fakeshell.Shell(user=user)
        self.sh.exec_mode = True

    def run(self, cmd):
        self.sh._err = []
        out = self.sh.run(cmd)
        return out, "".join(self.sh._err).rstrip("\n"), self.sh.last_rc


def main():
    root = Sh()

    # ---- SUID and SGID: pinned, not changed ----------------------------
    suid = tuple(root.run("find / -perm -4000 -type f")[0].split())
    sgid = tuple(root.run("find / -perm -2000 -type f")[0].split())
    want_suid = tuple(p for p in GUEST_SUID if p not in PERSONA_SUID_OMITS)
    eq("the setuid set is the guest's, less polkit's helper",
       tuple(sorted(suid)), tuple(sorted(want_suid)))
    eq("the setgid set is the guest's, plus crontab",
       tuple(sorted(sgid)),
       tuple(sorted(GUEST_SGID + PERSONA_SGID_ADDS)))
    check("this persona really does not run polkit",
          "polkitd" not in root.run("ps -eo comm --no-headers")[0],
          root.run("ps -eo comm --no-headers")[0][:120])
    check("...and really does run cron, which is why crontab is setgid",
          "cron" in root.run("ps -eo comm --no-headers")[0].split())

    # find, ls and stat are three ways to ask "is this setuid".
    for path in ("/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd"):
        mode = root.run("stat -c %%a %s" % path)[0].strip()
        ls = root.run("ls -l %s" % path)[0].strip()
        check("%s: stat says setuid" % path, mode.startswith("4"), mode)
        check("%s: ls -l agrees" % path, ls[3] == "s", ls[:12])
        check("%s: find agrees" % path, path in suid)
    # ...and they track a change, in both directions.
    s2 = Sh()
    s2.run("touch /tmp/probe")
    eq("a fresh file is not setuid",
       s2.run("find /tmp -perm -4000 -type f")[0].strip(), "")
    s2.run("chmod 4755 /tmp/probe")
    eq("chmod 4755 shows in stat", s2.run("stat -c %a /tmp/probe")[0].strip(),
       "4755")
    eq("...and in ls", s2.run("ls -l /tmp/probe")[0].strip()[:10],
       "-rwsr-xr-x")
    eq("...and in find", s2.run("find /tmp -perm -4000 -type f")[0].strip(),
       "/tmp/probe")
    s2.run("chmod 755 /tmp/probe")
    eq("and it drops back off all three",
       s2.run("find /tmp -perm -4000 -type f")[0].strip(), "")

    # ---- capabilities: the package, and one source for the numbers -----
    pkgs = dict((p[0], p[1]) for p in fakeshell.Shell.PACKAGES)
    eq("libcap2-bin is installed at the guest's version",
       pkgs.get("libcap2-bin"), GUEST_LIBCAP_VERSION)
    eq("dpkg -L lists the guest's four binaries",
       tuple(fakeshell.Shell._PKG_FILES.get("libcap2-bin", ())),
       GUEST_LIBCAP_BINS)
    for b in GUEST_LIBCAP_BINS:
        check("%s has a handler" % b,
              hasattr(fakeshell.Shell, "cmd_" + b))
        eq("%s is in /usr/sbin, as the guest ships it" % b,
           root.run("which %s" % b)[0].strip(), "/usr/sbin/%s" % b)
        eq("dpkg -S names %s's owner" % b,
           root.run("dpkg -S /usr/sbin/%s" % b)[0].strip(),
           "libcap2-bin: /usr/sbin/%s" % b)
    have_caps = all(hasattr(fakeshell, n) for n in
                    ("CAP_NAMES", "CAP_BOUND_MASK", "cap_hex",
                     "cap_mask_for", "cap_to_text"))
    if not check("fakeshell has one table for the capability set", have_caps,
                 "CAP_NAMES/cap_hex/cap_mask_for/cap_to_text missing"):
        fakeshell.CAP_NAMES = ()
        fakeshell.CAP_BOUND_MASK = 0
        fakeshell.cap_hex = lambda m: "%016x" % m
        fakeshell.cap_mask_for = lambda uid: 0
        fakeshell.cap_to_text = lambda m: "="
    eq("there are as many capability names as the guest's bounding set",
       len(fakeshell.CAP_NAMES), GUEST_CAP_COUNT)
    eq("...which is what makes CapBnd that number",
       fakeshell.cap_hex(fakeshell.CAP_BOUND_MASK), GUEST_CAPBND_HEX)
    eq("root's set renders as =ep",
       fakeshell.cap_to_text(fakeshell.cap_mask_for(0)), "=ep")
    eq("a normal user's renders as =",
       fakeshell.cap_to_text(fakeshell.cap_mask_for(1000)), "=")

    # capsh, /proc and getpcaps are three readers of one mask.
    for user, uid in (("root", 0), ("deploy", 1000), ("www-data", 33)):
        sh = Sh(user)
        # By absolute path for a non-root caller: libcap2-bin lives in
        # /usr/sbin, which is not on their PATH -- on the guest either.
        capsh = "capsh" if uid == 0 else "/usr/sbin/capsh"
        getpcaps = "getpcaps" if uid == 0 else "/usr/sbin/getpcaps"
        if uid != 0:
            eq("%s: the bare name is not on their PATH" % user,
               sh.run("which capsh")[0].strip(), "")
        printed = sh.run("%s --print" % capsh)[0]
        cur = re.search(r"^Current: (.*)$", printed, re.M)
        eff = re.search(r"^CapEff:\t(\S+)$",
                        sh.run("cat /proc/self/status")[0], re.M)
        prm = re.search(r"^CapPrm:\t(\S+)$",
                        sh.run("cat /proc/self/status")[0], re.M)
        bnd = re.search(r"^CapBnd:\t(\S+)$",
                        sh.run("cat /proc/self/status")[0], re.M)
        check("%s: capsh prints a Current line" % user, cur is not None,
              printed[:80])
        check("%s: /proc reports CapEff" % user, eff is not None)
        if cur and eff:
            eq("%s: capsh and /proc agree on the effective set" % user,
               cur.group(1),
               fakeshell.cap_to_text(int(eff.group(1), 16)))
            eq("%s: CapPrm matches CapEff, as on the guest" % user,
               prm.group(1), eff.group(1))
            eq("%s: CapBnd is the full set whatever the uid" % user,
               bnd.group(1), GUEST_CAPBND_HEX)
            eq("%s: and the mask is the one for this uid" % user,
               eff.group(1), fakeshell.cap_hex(fakeshell.cap_mask_for(uid)))
        # capsh's own uid/gid line must agree with id.
        idline = sh.run("id")[0].strip()
        u = re.search(r"^uid=(\d+)\(([^)]+)\)", idline)
        cu = re.search(r"^uid=(\d+)\(([^)]+)\) euid=", printed, re.M)
        if u and cu:
            eq("%s: capsh and id agree on uid" % user, cu.group(1), u.group(1))
            eq("%s: ...and on the name" % user, cu.group(2), u.group(2))
        # getpcaps on pid 1 must be what /proc/1/status says.
        g = sh.run("%s 1" % getpcaps)[0].strip()
        e1 = re.search(r"^CapEff:\t(\S+)$",
                       sh.run("cat /proc/1/status")[0], re.M)
        if e1:
            eq("%s: getpcaps 1 agrees with /proc/1/status" % user, g,
               "1: %s" % fakeshell.cap_to_text(int(e1.group(1), 16)))

    # getcap's measured behaviour, and the setcap round trip.
    out, err, rc = root.run("getcap")
    eq("bare getcap exits 1", rc, 1)
    check("...with the usage on stderr, not stdout",
          err.startswith("usage: getcap [-h] [-l] [-n] [-r] [-v]") and not out,
          (err[:60], out[:40]))
    out, err, rc = root.run("getcap --version")
    check("getcap has no long options, and says which character it choked on",
          "invalid option -- '-'" in err, err[:70])
    out, err, rc = root.run("getcap /nope")
    eq("a missing file is reported but does not fail", rc, 0)
    eq("...with the guest's wording", out.strip(),
       "/nope (No such file or directory)")
    eq("a file with no capabilities prints nothing",
       root.run("getcap /bin/ls")[0], "")
    eq("...and nothing on this box has any",
       root.run("getcap -r /usr")[0], "")

    s3 = Sh()
    s3.run("touch /tmp/cp")
    eq("setcap as root is silent", s3.run("setcap cap_net_raw+ep /tmp/cp")[0],
       "")
    eq("getcap now reports it", s3.run("getcap /tmp/cp")[0].strip(),
       "/tmp/cp cap_net_raw+ep")
    eq("...and so does a recursive walk",
       s3.run("getcap -r /tmp")[0].strip(), "/tmp/cp cap_net_raw+ep")
    check("a capability is not a mode bit, so ls -l is unchanged",
          s3.run("ls -l /tmp/cp")[0].strip().startswith("-rw-r--r--"),
          s3.run("ls -l /tmp/cp")[0].strip()[:14])
    eq("...and find -perm does not see one",
       s3.run("find /tmp -perm -4000 -type f")[0].strip(), "")
    s3.run("setcap -r /tmp/cp")
    eq("setcap -r takes it away", s3.run("getcap /tmp/cp")[0], "")
    # It has to survive a restart, like every other attacker change.
    kinds = [e[0] for e in s3.sh.rawfs.dump_journal()]
    s3.run("setcap cap_sys_admin+ep /tmp/cp")
    dump = s3.sh.rawfs.dump_journal()
    check("the capability is journalled", "k" in [e[0] for e in dump],
          [e[0] for e in dump][-4:])
    fresh = fakeshell.VFS()
    fresh.load_journal(dump)
    node = fresh.nodes.get("/tmp/cp")
    eq("...and comes back after a reload",
       getattr(node, "caps", None) if node else None, "cap_sys_admin+ep")
    # Defensive field order, for the same reason link_capture uses one.
    kents = [e for e in dump if e[0] == "k"]
    check("the entry puts the capability where an older loader would "
          "read a path",
          bool(kents) and not str(kents[-1][1]).startswith("/"),
          kents[-1] if kents else "no 'k' entry")
    del kinds

    # ---- PATH ----------------------------------------------------------
    eq("root's PATH is the guest's", Sh("root").run("echo $PATH")[0].strip(),
       GUEST_PATH_ROOT)
    for user in ("deploy", "www-data"):
        eq("%s gets the non-root PATH, not root's" % user,
           Sh(user).run("echo $PATH")[0].strip(), GUEST_PATH_USER)
    # ...and the box's own /etc/profile has to say the same thing.
    prof = Sh("deploy").run("cat /etc/profile")[0]
    check("/etc/profile carries root's branch", GUEST_PATH_ROOT in prof, prof)
    check("...and the login-shell branch for everyone else",
          GUEST_PATH_USER_LOGIN in prof, prof)
    eq("both come from one place, so they cannot drift",
       (getattr(fakeshell, "PATH_ROOT", None),
        getattr(fakeshell, "PATH_USER_LOGIN", None)),
       (GUEST_PATH_ROOT, GUEST_PATH_USER_LOGIN))

    # ---- what a non-root caller can actually reach ---------------------
    for user in ("deploy", "www-data"):
        sh = Sh(user)
        for tool in ("useradd", "iptables", "getcap", "usermod"):
            eq("%s: which %s finds nothing" % (user, tool),
               sh.run("which %s" % tool)[0].strip(), "")
            out, err, rc = sh.run("%s --help" % tool)
            eq("%s: bare %s is command not found" % (user, tool), rc, 127)
            check("%s: ...%s in bash's wording" % (user, tool),
                  "command not found" in err, err[:60])
        # But an absolute path is not subject to PATH -- that is the point
        # of spelling it out, and it answered "command not found" for a file
        # ls -l had just listed.
        eq("%s: ls -l sees the file" % user,
           sh.run("ls -l /usr/sbin/useradd")[0].strip()[:10], "-rwxr-xr-x")
        out, err, rc = sh.run("/usr/sbin/useradd bob")
        check("%s: the absolute path is not command-not-found" % user,
              "command not found" not in err, err[:70])
        eq("%s: it refuses on privilege, as the guest does" % user, rc, 1)
        eq("%s: ...with the guest's two lines" % user, err,
           "useradd: Permission denied.\n"
           "useradd: cannot lock /etc/passwd; try again later.")
        # ...and it really did not create the account.
        check("%s: and no account was created" % user,
              "bob" not in sh.run("cat /etc/passwd")[0],
              sh.run("grep bob /etc/passwd")[0][:60])
        for tool, lock in (("groupadd", "/etc/group"),
                           ("usermod", "/etc/passwd"),
                           ("gpasswd", "/etc/group")):
            arg = {"groupadd": "grp", "usermod": "-aG sudo deploy",
                   "gpasswd": "-a deploy sudo"}[tool]
            binp = "/usr/bin/gpasswd" if tool == "gpasswd" \
                else "/usr/sbin/%s" % tool
            out, err, rc = sh.run("%s %s" % (binp, arg))
            eq("%s: %s refuses with rc 1" % (user, tool), rc, 1)
            eq("%s: %s names the file it could not lock" % (user, tool), err,
               "%s: Permission denied.\n"
               "%s: cannot lock %s; try again later." % (tool, tool, lock))
        # userdel reports a missing user before it reports the permission.
        out, err, rc = sh.run("/usr/sbin/userdel nosuchuser")
        eq("%s: userdel reports the missing user first" % user, err,
           "userdel: user 'nosuchuser' does not exist")
        # setcap needs CAP_SETFCAP, which this caller does not have.
        out, err, rc = sh.run("/usr/sbin/setcap cap_net_raw+ep /tmp/x")
        eq("%s: setcap refuses" % user, err,
           "unable to set CAP_SETFCAP effective capability: "
           "Operation not permitted")
        eq("%s: ...with rc 1" % user, rc, 1)

    # ---- and root can still do all of it -------------------------------
    r2 = Sh()
    out, err, rc = r2.run("/usr/sbin/useradd carol")
    eq("root: useradd by absolute path succeeds", rc, 0)
    check("root: the account exists afterwards",
          "carol" in r2.run("cat /etc/passwd")[0])
    eq("root: and id agrees", r2.run("id -u carol")[0].strip() != "", True)

    print("\ncaptest: passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
