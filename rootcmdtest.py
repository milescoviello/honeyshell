#!/usr/bin/env python3
"""The box's record of who ran what as root.

/etc/sudoers here says `Defaults mail_badpass`, sudo is built
--with-logging=syslog, and the box's own auth.log carries a worked example
of the format -- deploy restarting nginx through sudo, with the pam session
line under it. Then sudo logged nothing at all for the caller:

    sudo true
    grep -c sudo /var/log/auth.log      2      (the two seeded lines)

Ten recon bots ran `echo '123456' | sudo -S sh -c 'nproc ...'` on this box
today and not one of them left a line. The file an attacker greps before
deciding what to clean up is the file that had no record of them -- while
sitting three lines above an example of exactly what the record should
look like.

A refusal is worse, because sudo says out loud that it logged one:

    nobody2 is not in the sudoers file.  This incident will be reported.

...and no incident was reported anywhere.

And /etc/sudoers ends with `@includedir /etc/sudoers.d` pointing at an
empty directory. The sudo package ships a README there explaining the
directive; it is 1068 bytes and mode 440 on the guest, and this is the
first place anyone looks for a dropped-in rule.

Format measured on the guest: two spaces after the pid's colon for a
permitted command and three for a refusal, a TTY field only when there is
one, an opened *and* a closed pam_unix line, and a pid of its own per
invocation.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402
import skeldb                                                   # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


def R(cmd, s):
    s._err = []
    out = s.run(cmd)
    return out or "", "".join(s._err), s.last_rc


def sudo_lines(s):
    return [l for l in R("cat /var/log/auth.log", s)[0].splitlines()
            if " sudo[" in l or " sudo: " in l]


# ---------------------------------------------------------------------------
# every invocation leaves a record
# ---------------------------------------------------------------------------
def t_a_permitted_command_is_logged():
    s = sh()
    before = len(sudo_lines(s))
    R("sudo true", s)
    after = sudo_lines(s)
    check("sudo wrote three lines", len(after) - before == 3,
          "%d new" % (len(after) - before))
    got = after[-3:]
    m = re.match(r"^\w{3} [ \d]\d [\d:]{8} web01 sudo\[(\d+)\]:  root : "
                 r"TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=(\S+)$", got[0])
    check("the command line has the guest's shape", m is not None, got[0])
    if not m:
        return
    pid, cmd = m.group(1), m.group(2)
    check("the command is an absolute path", cmd.startswith("/"), cmd)
    check("...and it is the binary which resolves",
          cmd == R("which true", s)[0].strip(), cmd)
    check("a pam session was opened",
          got[1] == got[1] and "pam_unix(sudo:session): session opened for "
          "user root(uid=0) by root(uid=0)" in got[1], got[1][-70:])
    check("and closed", "session closed for user root" in got[2],
          got[2][-50:])
    check("all three share one pid",
          all(("sudo[%s]:" % pid) in l for l in got), str([l[:40] for l in got]))


def t_each_invocation_gets_its_own_pid():
    s = sh()
    R("sudo true", s)
    R("sudo id", s)
    lines = sudo_lines(s)[-6:]
    pids = {re.search(r"sudo\[(\d+)\]", l).group(1) for l in lines
            if re.search(r"sudo\[(\d+)\]", l)}
    check("two invocations, two pids", len(pids) == 2, str(sorted(pids)))
    cmds = [l for l in lines if "COMMAND=" in l]
    check("each names its own command",
          len(cmds) == 2 and cmds[0] != cmds[1],
          str([c[-30:] for c in cmds]))


def t_the_command_recorded_is_the_command_run():
    s = sh()
    R("sudo -u deploy id", s)
    line = [l for l in sudo_lines(s) if "COMMAND=" in l][-1]
    check("the target user is recorded", "USER=deploy ; " in line, line[-60:])
    check("and the command with it", line.rstrip().endswith("/usr/bin/id"),
          line[-40:])
    check("the working directory is this shell's",
          "PWD=%s ;" % R("pwd", s)[0].strip() in line, line[-70:])
    # A command with arguments keeps them.
    R("sudo sh -c 'nproc'", s)
    line = [l for l in sudo_lines(s) if "COMMAND=" in l][-1]
    check("arguments are kept", "sh -c nproc" in line or "sh -c 'nproc'"
          in line, line[-50:])


def t_a_refusal_is_reported():
    s = sh()
    R("useradd -m nobody2", s)
    before = len(sudo_lines(s))
    out, err, rc = R("su - nobody2 -c 'sudo id'", s)
    check("sudo refuses", rc != 0 or "not in the sudoers file" in err,
          err[:60])
    check("and says it will report it",
          "This incident will be reported" in err, err[:80])
    after = sudo_lines(s)
    check("...and does", len(after) > before,
          "%d then %d" % (before, len(after)))
    if len(after) <= before:
        return
    line = after[-1]
    check("the refusal names the user twice, as sudo does",
          re.search(r"sudo\[\d+\]:   nobody2 : nobody2 NOT in sudoers ; ",
                    line), line[-90:])
    check("with the command it refused",
          line.rstrip().endswith("/usr/bin/id"), line[-40:])
    check("a refusal is one line, not three",
          len(after) - before == 1, "%d" % (len(after) - before))


# ---------------------------------------------------------------------------
# ...and the readers of that record agree
# ---------------------------------------------------------------------------
def t_the_journal_shows_what_auth_log_shows():
    s = sh()
    R("sudo true", s)
    auth = sudo_lines(s)[-3:]
    jrnl = R("journalctl -t sudo -n 3 --no-pager", s)[0].splitlines()
    check("journalctl -t sudo has the same three lines", jrnl == auth,
          "%s vs %s" % (jrnl[-1:], auth[-1:]))
    # ...and -u, which is the other way of asking.
    check("the identifier filter is sudo's",
          all(" sudo[" in l for l in jrnl), str(jrnl[:1]))
    check("a different identifier does not show them",
          not any("COMMAND=/usr/bin/true" in l
                  for l in R("journalctl -t CRON -n 20", s)[0].splitlines()),
          "leaked into CRON")


def t_the_seeded_example_and_a_live_one_look_alike():
    """The box shipped one sudo line. A new one has to be the same shape."""
    s = sh()
    seeded = [l for l in sudo_lines(s) if "deploy" in l and "COMMAND=" in l]
    check("the seeded deploy line is there", bool(seeded), "missing")
    R("sudo true", s)
    live = [l for l in sudo_lines(s) if "COMMAND=" in l][-1]
    if not seeded:
        return
    def fields(l):
        """The field names, in order, after the syslog tag."""
        tail = l.split(": ", 1)[1] if ": " in l else l
        # Drop the "user :" prefix on the first field; the names are what
        # is being compared, not who ran it.
        parts = [p.split("=")[0].strip() for p in tail.split(" ; ")]
        if parts and " : " in parts[0]:
            parts[0] = parts[0].split(" : ", 1)[1]
        return parts
    check("the live line has the seeded line's fields",
          fields(live) == fields(seeded[0]),
          "%s vs %s" % (fields(live), fields(seeded[0])))
    # ...including the pid syslog puts after the tag, which the seeded
    # example did not have.
    for label, l in (("seeded", seeded[0]), ("live", live)):
        check("the %s line carries a pid" % label,
              re.search(r" sudo\[\d+\]: ", l), l[:60])


# ---------------------------------------------------------------------------
# the include directory the sudoers file points at
# ---------------------------------------------------------------------------
def t_sudoers_d_has_the_readme():
    s = sh()
    check("/etc/sudoers includes the directory",
          "@includedir /etc/sudoers.d" in R("cat /etc/sudoers", s)[0],
          R("cat /etc/sudoers", s)[0][-60:])
    check("the directory is not empty",
          "README" in R("ls /etc/sudoers.d/", s)[0],
          R("ls -a /etc/sudoers.d/", s)[0].split())
    check("README is the guest's 1068 bytes",
          R("stat -c %s /etc/sudoers.d/README", s)[0].strip() == "1068",
          R("stat -c %s /etc/sudoers.d/README", s)[0].strip())
    check("and its content", R("cat /etc/sudoers.d/README", s)[0]
          == skeldb.SUDOERS_README, "differs")
    check("mode 440, like /etc/sudoers itself",
          R("stat -c %a /etc/sudoers.d/README", s)[0].strip() == "440",
          R("stat -c %a /etc/sudoers.d/README", s)[0].strip())
    check("the directory is 750",
          R("stat -c %a /etc/sudoers.d", s)[0].strip() == "750",
          R("stat -c %a /etc/sudoers.d", s)[0].strip())
    check("it explains the directive it is there for",
          "@includedir" in R("cat /etc/sudoers.d/README", s)[0],
          "no mention")


def t_sudo_l_matches_the_sudoers_file():
    s = sh()
    out = R("sudo -l", s)[0]
    body = R("cat /etc/sudoers", s)[0]
    check("sudo -l names the Defaults the file sets",
          "env_reset" in out and "env_reset" in body, out[:60])
    check("and the secure_path the file sets",
          "secure_path" in out and "secure_path" in body, out[:80])
    check("root may run everything, as the file says",
          "(ALL : ALL) ALL" in out and "root\tALL=(ALL:ALL) ALL" in body,
          out[-40:])
    # deploy is in the sudo group, and %sudo has a rule.
    check("deploy is in the sudo group",
          "sudo" in R("id -Gn deploy", s)[0].split(),
          R("id -Gn deploy", s)[0])
    check("and %sudo has a rule", "%sudo\tALL=(ALL:ALL) ALL" in body,
          body[-60:])
    # deploy's rule has no NOPASSWD tag, so sudo -l wants the password
    # first -- which is the point of the rule this check is reading. It used
    # to elevate without one, because sudo accepted anything.
    err = R("su - deploy -c 'sudo -n -l'", s)[1]
    check("deploy is asked for a password before -l will list",
          "a password is required" in err, err[:70])
    out = R("""su - deploy -c "echo 'deploy123' | sudo -S -l" """, s)[0]
    check("so sudo -l says so for deploy", "(ALL : ALL) ALL" in out,
          out[-60:])


TESTS = [t_a_permitted_command_is_logged,
         t_each_invocation_gets_its_own_pid,
         t_the_command_recorded_is_the_command_run,
         t_a_refusal_is_reported,
         t_the_journal_shows_what_auth_log_shows,
         t_the_seeded_example_and_a_live_one_look_alike,
         t_sudoers_d_has_the_readme,
         t_sudo_l_matches_the_sudoers_file]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
