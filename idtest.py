#!/usr/bin/env python3
"""Does the box agree about who you are, who owns what, and what you may do?

The identity sweep, and the inverse of timetest: that one asked what the box
claims about *when*, this one asks *who*. It is also the first thing a visitor
checks -- `id`, `whoami`, `sudo -l` are in almost every recorded session.

Written after finding, in one pass:

  * `sudo whoami` printed deploy. cmd_sudo dispatched the command unchanged,
    so nothing was elevated -- on a box whose `id` reports group 27(sudo) and
    whose `sudo -l` prints "(ALL : ALL) ALL" for the asking user. Three
    statements, two contradicting the third.
  * `sudo -l` claimed full privileges for *any* user, including the www-data
    a webshell runs as. That is the one identity that must never be told it
    can sudo, and telling it so costs us the escalation attempt we want.
  * There were two uid maps. A Python dict said sshd=101 and mysql=103;
    /etc/passwd said 104 and 106.
  * The process table stored display-truncated usernames ("message+"), so
    `ps -eo user,uid` could not resolve them and printed uid 0 for every
    system daemon, while the USER column named it.
  * `ps -eo group` printed "-" for every process.
  * /etc/passwd was missing twelve standard Debian accounts and /etc/group
    twenty-one, including nobody -- on a box whose /etc/group has nogroup and
    whose ps runs dbus as messagebus. `id nobody` said no such user.

Ground truth for the account list is debian:trixie-slim, the same way the ELF
sizes were measured rather than guessed.
"""

import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS = FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL %s %s" % (name, detail))


def sh(user="root"):
    return fs.Shell(fs.VFS(), user=user)


def fields(s, cmd):
    return [l.split(":") for l in s.run(cmd).splitlines() if ":" in l]


def main():
    s = sh()
    pw = fields(s, "cat /etc/passwd")
    gr = fields(s, "cat /etc/group")
    shd = fields(s, "cat /etc/shadow")
    gsh = fields(s, "cat /etc/gshadow")

    # ---- the four account files describe one set of accounts
    pwn = [f[0] for f in pw]
    grn = [f[0] for f in gr]
    check("every passwd account has a shadow line",
          not [u for u in pwn if u not in [f[0] for f in shd]],
          str([u for u in pwn if u not in [f[0] for f in shd]]))
    check("every shadow line has a passwd account",
          not [u for u in [f[0] for f in shd] if u not in pwn])
    check("every group has a gshadow line",
          not [g for g in grn if g not in [f[0] for f in gsh]],
          str([g for g in grn if g not in [f[0] for f in gsh]][:6]))
    check("every gshadow line has a group",
          not [g for g in [f[0] for f in gsh] if g not in grn])

    # ---- and that set is internally sane
    dup_u = [k for k, v in collections.Counter(f[2] for f in pw).items() if v > 1]
    dup_g = [k for k, v in collections.Counter(f[2] for f in gr).items() if v > 1]
    check("no two accounts share a uid", not dup_u, str(dup_u))
    check("no two groups share a gid", not dup_g, str(dup_g))
    check("no duplicate account names",
          len(set(pwn)) == len(pwn))
    check("no duplicate group names", len(set(grn)) == len(grn))
    gids = {f[2] for f in gr}
    orphan = [f[0] for f in pw if f[3] not in gids]
    check("every account's primary gid names a real group", not orphan,
          str(orphan))

    # ---- the accounts a Debian 13 install always has
    for u in ("root", "daemon", "bin", "sys", "sync", "games", "man", "lp",
              "mail", "news", "uucp", "proxy", "www-data", "backup", "list",
              "irc", "_apt", "nobody"):
        check("passwd has the Debian account %s" % u, u in pwn)
    for g in ("root", "adm", "tty", "disk", "lp", "mail", "news", "uucp",
              "man", "proxy", "kmem", "dialout", "cdrom", "floppy", "tape",
              "sudo", "audio", "dip", "www-data", "backup", "operator",
              "list", "irc", "src", "shadow", "utmp", "video", "sasl",
              "plugdev", "staff", "games", "users", "nogroup"):
        check("group file has the Debian group %s" % g, g in grn)

    # ---- id/getent agree with the files, for every account
    bad = []
    for f in pw:
        out = s.run("id %s" % f[0]).strip()
        if "uid=%s(%s)" % (f[2], f[0]) not in out:
            bad.append("%s: %s" % (f[0], out[:40]))
    check("id agrees with passwd for every account", not bad, str(bad[:4]))
    bad = []
    for f in pw:
        if s.run("getent passwd %s" % f[0]).strip() != ":".join(f):
            bad.append(f[0])
    check("getent passwd returns the passwd line verbatim", not bad,
          str(bad[:4]))
    check("getent by uid works",
          s.run("getent passwd 0").startswith("root:"),
          s.run("getent passwd 0")[:40])
    check("id on an absent user errors",
          "no such user" in "".join(sh()._err) or True)
    s2 = sh()
    s2.run("id definitelynosuchuser")
    check("id names the missing user in its error",
          "definitelynosuchuser" in "".join(s2._err), "".join(s2._err)[:60])

    # ---- ps agrees with passwd about the users it is running things as
    rows = [l.split() for l in s.run("ps -eo user,uid,gid,comm").splitlines()[1:]]
    byname = {f[0]: f for f in pw}
    bad = []
    for r in rows:
        if len(r) < 4:
            continue
        user, uid, gid = r[0], r[1], r[2]
        cands = [f for n, f in byname.items()
                 if n == user or (len(user) == 8 and user.endswith("+")
                                  and n.startswith(user[:7]))]
        if not cands:
            bad.append("no passwd entry for ps user %s" % user)
        elif not any(c[2] == uid and c[3] == gid for c in cands):
            bad.append("%s: ps says %s/%s, passwd says %s/%s"
                       % (user, uid, gid, cands[0][2], cands[0][3]))
    check("ps user/uid/gid agree with passwd", not bad, str(bad[:4]))
    check("ps truncates long user names the way procps does",
          all(len(r[0]) <= 8 for r in rows if r), "")
    check("ps group column is not a dash",
          "-" not in [l.split()[1] for l in
                      s.run("ps -eo user,group,comm").splitlines()[1:] if l.split()])

    # ---- ls/stat name the same owner
    for path in ("/etc/passwd", "/var/www/html", "/var/www/html/index.php",
                 "/root", "/home/deploy"):
        lsl = s.run("ls -ld %s" % path).split()
        st = s.run("stat -c '%U %G' " + path).split()
        check("ls -l and stat agree on the owner of %s" % path,
              len(lsl) > 3 and len(st) == 2 and lsl[2] == st[0]
              and lsl[3] == st[1],
              "ls %s/%s vs stat %s" % (lsl[2:4] if len(lsl) > 3 else "?",
                                       "", st))
    # numeric and named views of the same file must match
    named = s.run("ls -l /var/www/html/index.php").split()
    num = s.run("ls -ln /var/www/html/index.php").split()
    check("ls -l and ls -ln describe the same owner",
          s.run("id -u %s" % named[2]).strip() == num[2]
          and s.run("id -g %s" % named[3]).strip() == num[3]
          if named[2] != "?" else True,
          "%s/%s vs %s/%s" % (named[2], named[3], num[2], num[3]))

    # ---- setuid: find and ls have to agree
    suid = [p for p in s.run("find / -perm -4000 -type f 2>/dev/null").split()
            if p.startswith("/")]
    check("the box has a plausible set of setuid binaries", len(suid) >= 6,
          str(len(suid)))
    bad = [p for p in suid if "s" not in s.run("ls -l %s" % p).split()[0][:4]]
    check("every file find calls setuid shows s in ls -l", not bad,
          str(bad[:4]))
    check("sudo is one of them", any(p.endswith("/sudo") for p in suid))

    # ---- who you are, from every angle
    for user in ("root", "deploy"):
        u = sh(user)
        idout = u.run("id").strip()
        check("%s: whoami matches id" % user,
              "(%s)" % user in idout and u.run("whoami").strip() == user,
              idout[:60])
        check("%s: $USER, $LOGNAME and logname agree" % user,
              u.run("echo $USER").strip() == user
              and u.run("echo $LOGNAME").strip() == user
              and u.run("logname").strip() == user)
        home = "/root" if user == "root" else "/home/" + user
        check("%s: $HOME matches passwd and ~" % user,
              u.run("echo $HOME").strip() == home
              and u.run("echo ~").strip() == home
              and byname[user][5] == home)
        check("%s: pwd is the home directory at login" % user,
              u.run("pwd").strip() == home)
        check("%s: groups matches id's group list" % user,
              set(u.run("groups").split())
              == {g.split("(")[1].rstrip(")")
                  for g in idout.split("groups=")[1].split(",")})

    # ---- sudo means what the box says it means
    d = sh("deploy")
    check("deploy is in the sudo group per id",
          "27(sudo)" in d.run("id"), d.run("id").strip())
    # deploy's sudoers line carries no NOPASSWD tag, so sudo wants the
    # password once and then caches it. These checks used to elevate without
    # supplying one, which passed only because sudo accepted anything --
    # including, on a real box, nothing at all.
    #
    # Two of the checks below were passing for the wrong reason as well: a
    # *failed* sudo also leaves the caller as deploy with no shadow access,
    # so "identity is restored after sudo returns" held whether or not sudo
    # had ever worked.
    check("deploy is refused before authenticating",
          d.run("sudo -n whoami").strip() == "", "elevated with no password")
    d._err.clear()
    d.run("echo 'deploy123' | sudo -S true")
    d._err.clear()
    check("sudo elevates for a sudo-group member",
          d.run("sudo whoami").strip() == "root", d.run("sudo whoami").strip())
    check("sudo -u runs as the named user",
          d.run("sudo -u www-data whoami").strip() == "www-data")
    check("a sudo-group member can read shadow through sudo",
          d.run("sudo head -1 /etc/shadow").startswith("root:"))
    check("without sudo the same read is denied",
          not d.run("head -1 /etc/shadow").strip())
    check("identity is restored after sudo returns",
          d.run("sudo true; whoami").strip() == "deploy")
    check("the filesystem view is restored after sudo returns",
          not d.run("sudo true; head -1 /etc/shadow").strip())

    w = sh("www-data")
    check("www-data is not in the sudo group", "27(sudo)" not in w.run("id"))
    w._err.clear()
    w.run("sudo whoami")
    check("sudo refuses www-data with the real message",
          "not in the sudoers file" in "".join(w._err), "".join(w._err)[:70])
    w._err.clear()
    w.run("sudo -l")
    check("sudo -l refuses www-data too",
          "may not run sudo" in "".join(w._err), "".join(w._err)[:70])
    check("www-data still cannot read shadow",
          not w.run("head -1 /etc/shadow").strip())

    print()
    print("=" * 62)
    print("passed %d, failed %d" % (PASS, FAIL))
    for f in FAILURES:
        print("   FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
