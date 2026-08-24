#!/usr/bin/env python3
"""sudo said a password was required, and then took any password at all.

Sweep 142. `sudo -l` reported `(ALL : ALL) ALL` with no NOPASSWD tag -- i.e.
that a password is required -- while `sudo` itself accepted a wrong password,
an empty one, or none. `sudo -n`, which exists to mean "do not prompt, fail
instead", succeeded. Three statements about one question, two of them wrong,
on a box whose /etc/shadow publishes a real yescrypt hash of the very password
that was not being checked.

The cost is one command. An attacker who types a deliberately bogus password
and gets root has identified this box, and testing with a bogus password is a
normal thing to do when you are not sure the credential you have is the one
that worked.

Reference measured on Debian 13 with sudo 1.9.16p2, in a container rather than
on the guest -- the guest's own admin user is `NOPASSWD:ALL`, so it cannot
exercise a failed-password path at all and is the wrong reference for this:

    root                uid 0 is never prompted, and a piped password is
                        ignored entirely
    correct via -S      runs, and caches the timestamp for 15 minutes
    wrong or empty -S   "Sorry, try again.", then EOF, so sudo reports ONE
                        incorrect attempt rather than three -- with -S there
                        is no second line to read. Reporting three would be
                        the tell.
    -n, uncached        "sudo: a password is required"
    no -S and no tty    "a terminal is required to read the password; ..."
    cached              proceeds without reading stdin, so a wrong password
                        after a right one is irrelevant
    sudo -l, sudo -v    also require a password
    not in sudoers      refused before any password question

The root exemption is the part that must not regress. Every loader that has
ever landed on this box logs in as root and runs
`echo '123456' | sudo -S sh -c '...'`; ten did it in one day. If requiring a
password broke that, the fix would cost far more than the bug.

The auth.log side is measured too, in the end. It was first recorded here as
a gap that would not be guessed at -- a container has no syslog and the
guest's admin is NOPASSWD, so neither could produce a failed-password line --
and then measured properly by installing rsyslog in the container and
allocating a pty with script(1). The details a guess gets wrong: logname= and
rhost= are empty, there are two spaces between "rhost=" and "user=", and it
reports ONE incorrect attempt rather than three, because with the password on
stdin there is no second line to read.

Only the message bodies come from that container. Its rsyslog wrote RFC3339
timestamps and no pid tag, while the guest's auth.log is traditional
"Aug 24 20:52:43 web01 sudo[23283]:" -- so mixing the two would have produced
a format matching neither box. logname= was empty under both su and script,
but was never measured over SSH, where it may carry the login name.

Still not measured, so still not emitted: the lines a failed `sudo -l` writes.
The fourth line's shape differs there because there is no COMMAND.

Run from `honeypot/`.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


def sh(user):
    s = fs.Shell(fs.VFS(), user=user, peer="198.51.100.7")
    del s._err[:]
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    del s._err[:]
    return s.last_rc, out, err


# -- the passwords sudo checks must be the ones the box publishes ----------

def t_the_password_table_matches_etc_shadow():
    """Anti-drift. sudo checks a plaintext table so the shell never needs
    libcrypt to let someone in; this proves the table still describes the
    hashes the box hands out in /etc/shadow."""
    table = getattr(fs.Shell, "ACCOUNT_PW", None)
    check("Shell declares ACCOUNT_PW", table is not None)
    if not table:
        return
    spec = importlib.util.spec_from_file_location(
        "_sudopw_shadowtest", os.path.join(HERE, "shadowtest.py"))
    st = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(st)
    crypt_fn = getattr(st, "_load_crypt", lambda: None)()
    if crypt_fn is None:
        check("a crypt(3) is reachable to check the hashes", False,
              "no crypt module and no libcrypt")
        return
    s = sh("root")
    _, shadow, _ = run(s, "cat /etc/shadow")
    hashes = {}
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1].startswith("$"):
            hashes[parts[0]] = parts[1]
    for user, pw in sorted(table.items()):
        h = hashes.get(user)
        check("%s has a hash in /etc/shadow" % user, h is not None)
        if h:
            eq("ACCOUNT_PW[%r] verifies against the shadow hash" % user,
               crypt_fn(pw, h), h)
    # ...and no account with a real hash is missing from the table, or sudo
    # would refuse a password sshd accepts.
    for user in sorted(hashes):
        check("%s is in ACCOUNT_PW" % user, user in table,
              "sshd would accept it and sudo would not")


# -- root: the path every loader uses ------------------------------------

def t_root_is_never_asked_for_a_password():
    s = sh("root")
    for cmd in ("sudo -n id -u", "sudo id -u",
                "echo '123456' | sudo -S id -u",
                "echo 'totally-wrong' | sudo -S id -u",
                "echo '' | sudo -S id -u"):
        rc, out, err = run(s, cmd)
        check("root: %s" % cmd, rc == 0, "rc=%s %s" % (rc, err.strip()[:50]))
        check("root: %s gives uid 0" % cmd, out.strip() == "0", out[:20])


def t_the_real_loader_line_still_works():
    """Verbatim from a capture: ten addresses ran this shape in one day."""
    s = sh("root")
    rc, out, _ = run(
        s, "echo '123456' | sudo -S sh -c 'nproc 2>/dev/null || "
           "grep -c ^processor /proc/cpuinfo'")
    check("the loader's own sudo line runs", rc == 0, "rc=%s" % rc)
    check("...and produces a CPU count", out.strip().isdigit(), out[:20])


# -- deploy: a password is required, and it is checked -------------------

def t_the_correct_password_works():
    s = sh("deploy")
    rc, out, _ = run(s, "echo 'deploy123' | sudo -S id -u")
    eq("correct password elevates", (rc, out.strip()), (0, "0"))


WRONG = ("[sudo] password for deploy: Sorry, try again.\n"
         "[sudo] password for deploy: \n"
         "sudo: no password was provided\n"
         "sudo: 1 incorrect password attempt\n")


def t_a_wrong_password_is_refused():
    for pw in ("wrong", "123456", ""):
        s = sh("deploy")
        rc, out, err = run(s, "echo '%s' | sudo -S id -u" % pw)
        check("password %r is refused" % pw, rc == 1, "rc=%s" % rc)
        check("password %r elevates nothing" % pw, out == "", out[:20])
        eq("wording for %r" % pw, err, WRONG)


def t_non_interactive_says_so():
    s = sh("deploy")
    rc, out, err = run(s, "sudo -n id -u")
    eq("sudo -n", (rc, out, err), (1, "", "sudo: a password is required\n"))


def t_no_stdin_and_no_tty_says_so():
    s = sh("deploy")
    rc, out, err = run(s, "sudo id -u")
    eq("sudo with nowhere to read a password", (rc, out), (1, ""))
    eq("...and its wording", err,
       "sudo: a terminal is required to read the password; either use the "
       "-S option to read from standard input or configure an askpass "
       "helper\nsudo: a password is required\n")


def t_listing_and_validating_need_a_password_too():
    s = sh("deploy")
    rc, out, err = run(s, "sudo -n -l")
    eq("sudo -n -l", (rc, out, err), (1, "", "sudo: a password is required\n"))
    rc, _, err = run(s, "sudo -n -v")
    eq("sudo -n -v", (rc, err), (1, "sudo: a password is required\n"))
    # ...and with a password it lists.
    rc, out, _ = run(s, "echo 'deploy123' | sudo -S -l")
    check("sudo -l with the password lists the rules",
          rc == 0 and "(ALL : ALL) ALL" in out, out[:60])


# -- the timestamp cache -------------------------------------------------

def t_the_credential_is_cached_then_dropped_by_dash_k():
    s = sh("deploy")
    run(s, "echo 'deploy123' | sudo -S true")
    rc, out, _ = run(s, "sudo -n id -u")
    eq("a second sudo is cached", (rc, out.strip()), (0, "0"))
    # Real sudo does not read stdin at all while cached, so a wrong password
    # after a right one is irrelevant.
    rc, out, _ = run(s, "echo 'wrong' | sudo -S id -u")
    eq("a wrong password while cached is ignored", (rc, out.strip()), (0, "0"))
    rc, _, _ = run(s, "sudo -k")
    eq("sudo -k succeeds", rc, 0)
    rc, _, err = run(s, "sudo -n id -u")
    eq("and drops the cache", (rc, err), (1, "sudo: a password is required\n"))


def t_the_cache_is_per_session():
    """One source's shell must not inherit another's authentication."""
    a = sh("deploy")
    run(a, "echo 'deploy123' | sudo -S true")
    b = sh("deploy")
    rc, _, err = run(b, "sudo -n id -u")
    eq("a fresh session is not authenticated",
       (rc, err), (1, "sudo: a password is required\n"))


# -- and the identity that must never be told it can sudo ----------------

def t_a_non_sudoer_is_refused_before_the_password_question():
    s = sh("www-data")
    for cmd in ("echo 'deploy123' | sudo -S id -u", "sudo -n id -u",
                "sudo id -u"):
        rc, out, err = run(s, cmd)
        check("www-data: %s refused" % cmd, rc == 1, "rc=%s" % rc)
        check("www-data: %s is not asked for a password" % cmd,
              "password is required" not in err and "Sorry, try again" not in err,
              err.strip()[:60])
        eq("www-data: %s wording" % cmd, err.strip(),
           "www-data is not in the sudoers file.  This incident will be "
           "reported.")
    rc, _, err = run(s, "sudo -l")
    eq("www-data: sudo -l wording", (rc, err.strip()),
       (1, "Sorry, user www-data may not run sudo on web01."))


# -- sudo's own options, whatever order they arrive in -------------------

def t_sudos_own_options_are_never_treated_as_commands():
    """The leak is the wording, not the exit code: reached through the
    dispatcher these answered "sudo: -V: command not found" -- sudo naming
    its own option as a missing command, which no real sudo ever says.

    Measured: -V and -h are exclusive of every other option and produce the
    usage line with rc 1; -v tolerates -n and asks for a password instead."""
    s = sh("deploy")
    for cmd in ("sudo -n -V", "sudo -E -V", "sudo -n -h", "sudo -n --help"):
        rc, out, err = run(s, cmd)
        check("%s is not a command lookup" % cmd,
              "command not found" not in (out + err), (out + err)[:60])
        eq("%s gives sudo's usage line" % cmd, (rc, out),
           (1, "usage: sudo -h | -K | -k | -V\n"))
    rc, out, err = run(s, "sudo -n -v")
    check("sudo -n -v is not a command lookup",
          "command not found" not in (out + err), (out + err)[:60])
    eq("sudo -n -v asks for a password", (rc, err),
       (1, "sudo: a password is required\n"))


def t_standalone_flags_still_take_no_command():
    s = sh("deploy")
    for cmd in ("sudo -k", "sudo -K"):
        rc, out, err = run(s, cmd)
        eq("%s is complete on its own" % cmd, (rc, out, err), (0, "", ""))
    for cmd in ("sudo", "sudo --"):
        rc, out, _ = run(s, cmd)
        eq("%s is a usage error" % cmd, (rc, out),
           (1, "usage: sudo -h | -K | -k | -V\n"))


# -- and the file an attacker greps afterwards --------------------------

def _authlog_delta(user, cmd):
    """Run `cmd` as `user` and return the auth.log lines it added.

    Two shells over one VFS: auth.log is root:adm 0640, so the user who
    triggers the line cannot read it back.
    """
    v = fs.VFS()
    u = fs.Shell(v, user=user, peer="198.51.100.7")
    del u._err[:]
    root = fs.Shell(v, user="root", peer="198.51.100.7")
    del root._err[:]

    def lines():
        out = root.run("cat /var/log/auth.log")
        del root._err[:]
        return out.splitlines()

    before = lines()
    u.run(cmd)
    del u._err[:]
    return lines()[len(before):]


def t_a_rejected_password_reaches_auth_log():
    """The one outcome that used to leave no trace at all. A successful sudo
    wrote three lines and a not-in-sudoers refusal wrote one, so grepping
    auth.log after a fumbled sudo and finding nothing was the tell."""
    added = _authlog_delta("deploy", "echo 'wrong-password' | sudo -S true")
    eq("a rejected password writes four lines", len(added), 4)
    if len(added) != 4:
        return
    checks = [
        ("names the pam module and the failure",
         "pam_unix(sudo:auth): authentication failure;" in added[0]),
        ("logname is empty, as measured", "logname= uid=1000" in added[0]),
        ("euid is root", "euid=0" in added[0]),
        ("carries the tty in full", "tty=/dev/pts/0" in added[0]),
        ("rhost is empty with two spaces before user",
         "rhost=  user=deploy" in added[0]),
        ("conversation failed", added[1].endswith(
            "pam_unix(sudo:auth): conversation failed")),
        ("could not identify password", added[2].endswith(
            "pam_unix(sudo:auth): auth could not identify password "
            "for [deploy]")),
        ("counts ONE attempt, not three",
         "1 incorrect password attempt" in added[3]),
        ("short TTY on the command line", "TTY=pts/0 ;" in added[3]),
        ("resolves the command to a full path",
         "COMMAND=/usr/bin/true" in added[3]),
    ]
    for name, cond in checks:
        check("auth.log: %s" % name, cond, added[0][:100])
    # The framing is the guest's, not the container the bodies came from.
    for i, ln in enumerate(added):
        check("auth.log line %d uses the guest's sudo[pid] framing" % i,
              " web01 sudo[" in ln, ln[:60])


def t_the_other_two_outcomes_still_log_what_they_did():
    """Regression guard: adding the failure path must not change these."""
    ok = _authlog_delta("deploy", "echo 'deploy123' | sudo -S true")
    eq("a successful sudo still writes three lines", len(ok), 3)
    refused = _authlog_delta("www-data", "sudo id")
    eq("a not-in-sudoers refusal still writes one line", len(refused), 1)
    if refused:
        check("and says NOT in sudoers", "NOT in sudoers" in refused[0],
              refused[0][:70])


# -- and it must not be bypassable by changing your name ----------------

def t_su_carries_the_uid_and_not_just_the_name():
    """`su deploy` used to set the name and leave the number behind.

    id and whoami read the name, so they reported deploy; every privilege
    decision reads self.uid, which was still 0. Six commands consult it --
    sudo, crontab -u, setcap, capsh, pslog and the shadow tools -- so the
    password check this suite exists to enforce could be walked around with
    `su deploy -c "sudo ..."`, which is a shorter command than the one it
    bypasses. cmd_sudo had always set user, uid and gid together; su was the
    odd one out.
    """
    s = sh("root")
    rc, out, _ = run(s, 'su -c "id -u" deploy')
    eq("su reports the target's uid", (rc, out.strip()), (0, "1000"))
    rc, out, _ = run(s, 'su -c "whoami" deploy')
    eq("su reports the target's name", (rc, out.strip()), (0, "deploy"))

    # The bypass itself.
    rc, out, err = run(s, 'su -c "sudo -n id -u" deploy')
    check("sudo under su is not silently elevated", rc != 0,
          "rc=%s out=%r -- the password check was walked around" % (rc, out))
    check("...and says why", "a password is required" in err, err[:60])

    # The other decisions that read the same field.
    rc, _, err = run(s, 'su -c "crontab -u root -l" deploy')
    check("crontab -u under su is refused", rc != 0, "rc=%s" % rc)
    check("...with crontab's wording",
          "must be privileged to use -u" in err, err[:60])
    _, out, _ = run(s, 'su -c "capsh --print" deploy')
    check("capsh under su shows no capabilities",
          "Current: =ep" not in out, out[:60])

    # ...and the caller gets their own identity back.
    rc, out, _ = run(s, "id -u")
    eq("root is root again afterwards", (rc, out.strip()), (0, "0"))
    rc, out, _ = run(s, "sudo -n id -u")
    eq("and still needs no password", (rc, out.strip()), (0, "0"))


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            try:
                fn()
            except Exception as exc:                          # noqa: BLE001
                check(name, False, "crashed: %r" % (exc,))
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
