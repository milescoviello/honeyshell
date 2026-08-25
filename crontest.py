r"""crontab: one crontab for everyone, and no validation at all.

Fifty-seventh coherence sweep. cron_install is one of the few things this
box is set up to shout about, RedTail installed a crontab here on
2026-08-21 and again on the 22nd, and Diicot opens every session with
`crontab -r`. So: do the ways of reading and writing a crontab agree?

The common path did, and is pinned rather than changed: `echo ... |
crontab -` installs, `crontab -l` reads it back, `crontab -r` removes
both the listing and the spool file, writing
/var/spool/cron/crontabs/root directly shows up in `crontab -l`, and the
spool file is -rw------- root:crontab as Debian writes it.

Three other paths did not.

  1. `crontab FILE` was not handled at all. It returned 0 and installed
     nothing, while the identical content piped in worked. Writing a file
     and loading it is as ordinary as the pipe, and the caller gets rc 0
     either way -- so a bot using that form believed it had persistence
     it did not have. (We would also not have raised cron_install for it.)

  2. -u was ignored, so every account shared root's crontab.
     `crontab -u deploy -` wrote /var/spool/cron/crontabs/root, and
     `crontab -u deploy -l` read root's back. No deploy spool file was
     ever created, and a per-user install would have been logged against
     the wrong path -- straight into the alert this box exists to raise.

  3. Nothing was validated. `echo garbage | crontab -` returned 0 and
     `crontab -l` read the garbage back, so a crontab no cron could ever
     run was indistinguishable from a working one. Real crontab names the
     offending line and installs nothing, leaving any previous crontab in
     place.

Reference measured against real crontab (cron 3.0pl1) on the dev host:

    echo 'this is not a crontab line' | crontab -
        "-":0: bad minute
        errors in crontab file, can't install.        rc 1
    printf '* * * * * /bin/true\nbadline here\n' | crontab -
        "-":1: bad minute                             rc 1
    crontab -u nosuchuser -l
        crontab:  user `nosuchuser' unknown           rc 1
    crontab /nope/ct.txt
        /nope/ct.txt: No such file or directory       rc 1

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def shell(user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def run(s, cmd):
    o = s.run(cmd)
    e = "".join(s._err)
    s._err.clear()
    return o, e, s.last_rc


def out(s, cmd):
    o, e, _ = run(s, cmd)
    return (o + e).strip()


# -- the path that already worked ----------------------------------------

def t_stdin_install_and_list():
    s = shell()
    run(s, "echo '* * * * * /tmp/x.sh' | crontab -")
    eq("crontab -l", out(s, "crontab -l"), "* * * * * /tmp/x.sh")
    eq("spool file agrees",
       out(s, "cat /var/spool/cron/crontabs/root"), "* * * * * /tmp/x.sh")


def t_spool_file_metadata():
    s = shell()
    run(s, "echo '* * * * * /tmp/x.sh' | crontab -")
    eq("mode", out(s, "stat -c '%a' /var/spool/cron/crontabs/root"), "600")
    eq("owner:group",
       out(s, "stat -c '%U:%G' /var/spool/cron/crontabs/root"), "root:crontab")


def t_remove():
    s = shell()
    run(s, "echo '* * * * * /tmp/x.sh' | crontab -")
    _o, _e, rc = run(s, "crontab -r")
    eq("crontab -r rc", rc, 0)
    check("listing gone", "no crontab" in out(s, "crontab -l"), "")
    eq("spool gone",
       out(s, "test -f /var/spool/cron/crontabs/root || echo gone"), "gone")


def t_remove_when_there_is_none():
    s = shell()
    _o, e, rc = run(s, "crontab -r")
    check("reports there is none", "no crontab for root" in e, e)
    eq("rc", rc, 1)


def t_direct_spool_write_is_visible():
    s = shell()
    run(s, "mkdir -p /var/spool/cron/crontabs && "
           "printf '*/5 * * * * /tmp/z.sh\\n' > /var/spool/cron/crontabs/root")
    eq("crontab -l sees it", out(s, "crontab -l"), "*/5 * * * * /tmp/z.sh")


# -- crontab FILE --------------------------------------------------------

def t_file_operand_installs():
    s = shell()
    run(s, "printf '*/2 * * * * /tmp/a.sh\\n' > /tmp/ct.txt")
    _o, _e, rc = run(s, "crontab /tmp/ct.txt")
    eq("rc", rc, 0)
    eq("installed", out(s, "crontab -l"), "*/2 * * * * /tmp/a.sh")
    eq("spool agrees", out(s, "cat /var/spool/cron/crontabs/root"),
       "*/2 * * * * /tmp/a.sh")


def t_file_and_pipe_agree():
    """The two ways of loading the same content must land identically."""
    a = shell()
    run(a, "printf '*/2 * * * * /tmp/a.sh\\n' > /tmp/ct.txt; crontab /tmp/ct.txt")
    b = shell()
    run(b, "printf '*/2 * * * * /tmp/a.sh\\n' | crontab -")
    eq("same listing", out(a, "crontab -l"), out(b, "crontab -l"))


def t_missing_file_operand():
    s = shell()
    _o, e, rc = run(s, "crontab /nope/ct.txt")
    check("reports it", "No such file or directory" in e, e)
    eq("rc", rc, 1)
    check("nothing installed", "no crontab" in out(s, "crontab -l"), "")


# -- -u ------------------------------------------------------------------

def t_dash_u_writes_that_users_spool():
    s = shell()
    run(s, "echo '0 3 * * * /tmp/b.sh' | crontab -u deploy -")
    eq("deploy's listing", out(s, "crontab -u deploy -l"), "0 3 * * * /tmp/b.sh")
    eq("deploy's spool exists",
       out(s, "cat /var/spool/cron/crontabs/deploy"), "0 3 * * * /tmp/b.sh")


def t_a_normal_user_owns_their_own_crontab():
    """crontab(1) is setgid crontab, which is the whole reason it is setgid.

    Every crontab operation by a non-root user answered
    "crontab: /var/spool/cron/crontabs/deploy: Permission denied", because
    the spool was reached through the session's credential view and
    /var/spool/cron/crontabs is 1730 root:crontab. Diicot's `crontab -r` as
    `deploy` got exactly that on 2026-08-24, and a cron persistence install
    from any non-root session would have been refused -- losing the capture
    this honeypot most wants.
    """
    for user in ("deploy", "www-data"):
        s = shell(user=user)
        _o, e, rc = run(s, "crontab -l")
        check("%s: -l with none says so, not denied" % user,
              "no crontab for %s" % user in e and "Permission denied" not in e,
              e)
        eq("%s: -l rc" % user, rc, 1)
        _o, e, rc = run(s, "crontab -r")
        check("%s: -r with none says so, not denied" % user,
              "no crontab for %s" % user in e and "Permission denied" not in e,
              e)
        _o, e, rc = run(s, "echo '*/5 * * * * /var/tmp/x' | crontab -")
        eq("%s: install rc" % user, rc, 0)
        check("%s: install was not denied" % user,
              "Permission denied" not in e, e)
        eq("%s: their own listing" % user, out(s, "crontab -l"),
           "*/5 * * * * /var/tmp/x")
        _o, e, rc = run(s, "crontab -r")
        eq("%s: remove rc" % user, rc, 0)
        check("%s: gone afterwards" % user,
              "no crontab for %s" % user in run(s, "crontab -l")[1], "")
        # ...and still cannot reach anyone else's.
        _o, e, rc = run(s, "crontab -u root -l")
        check("%s: -u on another user is refused" % user,
              "must be privileged to use -u" in e, e)
        eq("%s: -u rc" % user, rc, 1)


def t_dash_u_does_not_touch_root():
    s = shell()
    run(s, "echo '0 3 * * * /tmp/b.sh' | crontab -u deploy -")
    check("root still has none", "no crontab for root" in out(s, "crontab -l"),
          out(s, "crontab -l"))
    eq("no root spool",
       out(s, "test -f /var/spool/cron/crontabs/root || echo gone"), "gone")


def t_two_users_two_crontabs():
    s = shell()
    run(s, "echo '1 1 * * * /tmp/r.sh' | crontab -")
    run(s, "echo '2 2 * * * /tmp/d.sh' | crontab -u deploy -")
    eq("root's", out(s, "crontab -l"), "1 1 * * * /tmp/r.sh")
    eq("deploy's", out(s, "crontab -u deploy -l"), "2 2 * * * /tmp/d.sh")


def t_dash_u_unknown_user():
    s = shell()
    _o, e, rc = run(s, "crontab -u nosuchuser -l")
    check("names the user", "user `nosuchuser' unknown" in e, e)
    eq("rc", rc, 1)


def t_dash_u_remove_is_scoped():
    s = shell()
    run(s, "echo '1 1 * * * /tmp/r.sh' | crontab -")
    run(s, "echo '2 2 * * * /tmp/d.sh' | crontab -u deploy -")
    run(s, "crontab -u deploy -r")
    check("deploy's gone", "no crontab for deploy" in out(s, "crontab -u deploy -l"), "")
    eq("root's survives", out(s, "crontab -l"), "1 1 * * * /tmp/r.sh")


# -- validation ----------------------------------------------------------

def bad(s, text):
    _o, e, rc = run(s, "printf '%s\\n' | crontab -" % text.replace("'", "'\\''"))
    m = re.search(r'"-":(\d+): (.+)', e)
    return (m.group(2) if m else e.strip()), rc


def t_garbage_is_refused():
    s = shell()
    why, rc = bad(s, "this is not a crontab line")
    eq("message", why, "bad minute")
    eq("rc", rc, 1)
    check("nothing installed", "no crontab" in out(s, "crontab -l"),
          out(s, "crontab -l"))


def t_each_field_is_named():
    s = shell()
    for text, want in (("99 * * * * /bin/true", "bad minute"),
                       ("* 99 * * * /bin/true", "bad hour"),
                       ("* * 99 * * /bin/true", "bad day-of-month"),
                       ("* * * 99 * /bin/true", "bad month"),
                       ("* * * * 99 /bin/true", "bad day-of-week"),
                       ("* * * * *", "bad command")):
        why, _rc = bad(s, text)
        eq("%s" % text[:26], why, want)


def t_the_line_number_is_reported():
    s = shell()
    _o, e, rc = run(s, "printf '* * * * * /bin/true\\nbadline here\\n' | crontab -")
    check("second line, 0-indexed", '"-":1: bad minute' in e, e)
    eq("rc", rc, 1)


def t_a_rejected_crontab_leaves_the_old_one():
    """Real crontab installs nothing on error; the previous one survives."""
    s = shell()
    run(s, "echo '5 5 * * * /tmp/good.sh' | crontab -")
    bad(s, "garbage line")
    eq("previous crontab intact", out(s, "crontab -l"), "5 5 * * * /tmp/good.sh")


def t_valid_forms_are_accepted():
    s = shell()
    for text in ("*/5 1-3 1,15 jan mon /bin/true",
                 "0-59/10 * * * * /bin/true",
                 "@reboot /tmp/y.sh",
                 "@daily /tmp/y.sh",
                 "# just a comment",
                 "MAILTO=root",
                 "SHELL=/bin/sh"):
        _o, _e, rc = run(s, "printf '%s\\n' | crontab -" % text)
        eq("accepted: %s" % text[:28], rc, 0)


def t_an_unknown_special_is_refused():
    s = shell()
    why, rc = bad(s, "@bogus /tmp/y.sh")
    eq("message", why, "bad minute")
    eq("rc", rc, 1)


def t_a_realistic_persistence_crontab():
    """The shape a dropper actually installs."""
    s = shell()
    body = ("SHELL=/bin/sh\\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:"
            "/usr/bin:/sbin:/bin\\n*/3 * * * * /root/.x/kswapd0 >/dev/null "
            "2>&1\\n@reboot /root/.x/kswapd0 >/dev/null 2>&1\\n")
    _o, _e, rc = run(s, "printf '%s' | crontab -" % body)
    eq("installed", rc, 0)
    listing = out(s, "crontab -l")
    check("kept every line", listing.count("\n") == 3, repr(listing))
    check("survives a read-back", "kswapd0" in listing, listing)


# -- the other cron locations are untouched ------------------------------

def t_etc_cron_locations_still_there():
    s = shell()
    check("/etc/crontab exists", out(s, "head -1 /etc/crontab") != "", "")
    check("cron.d has e2scrub_all", "e2scrub_all" in out(s, "ls /etc/cron.d"),
          out(s, "ls /etc/cron.d"))
    # The guest's cron.daily holds apt-compat, dpkg and man-db -- and no
    # logrotate, which runs from a systemd timer on trixie. This used to
    # assert logrotate was present, which pinned the emulator's own stub set
    # rather than anything measured off the box it copies.
    _daily = sorted(out(s, "ls /etc/cron.daily").split())
    check("cron.daily holds the guest's three", _daily ==
          ["apt-compat", "dpkg", "man-db"], _daily)
    check("...and they are real scripts, not stubs",
          len(out(s, "cat /etc/cron.daily/man-db")) > 200,
          out(s, "cat /etc/cron.daily/man-db")[:40])
    check("cron.daily populated", "man-db" in out(s, "ls /etc/cron.daily"),
          out(s, "ls /etc/cron.daily"))
    eq("cron is running", out(s, "systemctl is-active cron"), "active")


def t_a_cron_d_dropin_does_not_change_crontab_l():
    s = shell()
    run(s, "printf '*/1 * * * * root /tmp/c.sh\\n' > /etc/cron.d/evil")
    check("the file is there", "/tmp/c.sh" in out(s, "cat /etc/cron.d/evil"), "")
    check("crontab -l unaffected", "no crontab" in out(s, "crontab -l"),
          out(s, "crontab -l"))


TESTS = [t_a_normal_user_owns_their_own_crontab,
         t_stdin_install_and_list, t_spool_file_metadata, t_remove,
         t_remove_when_there_is_none, t_direct_spool_write_is_visible,
         t_file_operand_installs, t_file_and_pipe_agree,
         t_missing_file_operand, t_dash_u_writes_that_users_spool,
         t_dash_u_does_not_touch_root, t_two_users_two_crontabs,
         t_dash_u_unknown_user, t_dash_u_remove_is_scoped,
         t_garbage_is_refused, t_each_field_is_named,
         t_the_line_number_is_reported, t_a_rejected_crontab_leaves_the_old_one,
         t_valid_forms_are_accepted, t_an_unknown_special_is_refused,
         t_a_realistic_persistence_crontab, t_etc_cron_locations_still_there,
         t_a_cron_d_dropin_does_not_change_crontab_l]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
