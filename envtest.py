r"""The environment, from four directions.

Fifty-eighth coherence sweep. Reading /proc/<pid>/environ is how you look
for credentials on a box you have just landed on -- it is where database
passwords and API tokens sit when a service was started with them in its
unit file -- and this persona is built around a leaked .env. So: do the
four things that answer "what is in the environment" agree?

env and printenv already agreed, and that is pinned rather than changed:
identical output but for the `_` line, which really does differ because
bash sets it to the command being run.

Two others did not.

  1. env and export -p listed bash's own shell variables as exported.
     BASH, BASH_VERSION, EUID, UID, HOSTTYPE, MACHTYPE, OSTYPE, IFS, PS1
     and HOSTNAME all appeared, and none of them is ever in a real
     environment -- they live in the shell's namespace, `set` lists them,
     and no child process sees them. `env | grep BASH_VERSION` returning
     a value is a single-command tell that no Linux box produces.

  2. /proc/<pid>/environ was a fixed eight-entry blob for every pid
     alike, carrying INVOCATION_ID and JOURNAL_STREAM -- a systemd
     *service's* environment -- including for the attacker's own shell.
     So /proc/self/environ and env described two different processes,
     and SSH_CLIENT and SSH_CONNECTION appeared in neither the file
     people read specifically to find that kind of thing. It is now the
     shell's own exported environment, snapshotted at construction
     because that is what a process's environ is: the environment it was
     exec'd with, not a live view. A daemon still gets the systemd
     variables, because a daemon really was started by systemd.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

# What bash keeps to itself. Every one of these was being exported.
SHELL_ONLY = ("BASH", "BASH_VERSION", "BASH_VERSINFO", "BASHPID", "EUID",
              "UID", "PPID", "HOSTTYPE", "MACHTYPE", "OSTYPE", "IFS", "PS1",
              "PS2", "HOSTNAME", "OPTIND", "SHELLOPTS")

# What a login shell genuinely does export.
REAL_ENV = ("HOME", "LANG", "LOGNAME", "PATH", "PWD", "SHELL", "SHLVL",
            "SSH_CLIENT", "SSH_CONNECTION", "TERM", "USER")


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


def out(s, cmd):
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


def names(s, cmd):
    return sorted(l.split("=", 1)[0] for l in out(s, cmd).splitlines()
                  if "=" in l)


# -- env and printenv --------------------------------------------------

def t_env_and_printenv_agree():
    s = shell()
    a = [l for l in out(s, "env").splitlines() if not l.startswith("_=")]
    b = [l for l in out(s, "printenv").splitlines() if not l.startswith("_=")]
    eq("same lines", sorted(b), sorted(a))


def t_printenv_one_variable():
    s = shell()
    eq("printenv HOME", out(s, "printenv HOME"), "/root")
    eq("missing var rc", out(s, "printenv NOSUCHVAR; echo rc=$?"), "rc=1")


# -- shell variables are not environment variables ---------------------

def t_env_does_not_leak_shell_variables():
    s = shell()
    listed = names(s, "env")
    for v in SHELL_ONLY:
        check("env has no %s" % v, v not in listed, "")


def t_export_p_does_not_leak_them_either():
    s = shell()
    body = out(s, "export -p")
    for v in SHELL_ONLY:
        check("export -p has no %s" % v,
              ("declare -x %s=" % v) not in body and
              ("declare -x %s\n" % v) not in body, "")


def t_set_still_has_them():
    """They must exist as shell variables -- just not exported."""
    s = shell()
    body = out(s, "set")
    for v in ("BASH_VERSION", "EUID", "UID", "HOSTTYPE", "OSTYPE", "PS1"):
        check("set has %s" % v, ("%s=" % v) in body, "")
    check("BASH_VERSION still readable",
          out(s, "echo $BASH_VERSION").startswith("5."),
          out(s, "echo $BASH_VERSION"))
    eq("EUID still readable", out(s, "echo $EUID"), "0")


def t_the_real_environment_is_all_there():
    s = shell()
    listed = names(s, "env")
    for v in REAL_ENV:
        check("env has %s" % v, v in listed, str(listed))


def t_a_child_does_not_see_shell_variables():
    """The point of the distinction: what a subprocess inherits."""
    s = shell()
    eq("subshell sees no BASH_VERSION in env",
       out(s, "bash -c 'env | grep -c \"^BASH_VERSION=\"'"), "0")
    eq("but HOME is inherited",
       out(s, "bash -c 'env | grep -c \"^HOME=\"'"), "1")


def t_export_makes_it_visible():
    s = shell()
    out(s, "MYVAR=hello")
    eq("unexported is not in env", out(s, "env | grep -c '^MYVAR='"), "0")
    check("but set has it", "MYVAR=hello" in out(s, "set"), "")
    out(s, "export MYVAR")
    eq("exported is in env", out(s, "env | grep '^MYVAR='"), "MYVAR=hello")
    out(s, "unset MYVAR")
    eq("unset removes it", out(s, "env | grep -c '^MYVAR='"), "0")


# -- /proc/<pid>/environ -------------------------------------------------

def t_proc_self_environ_matches_env():
    s = shell()
    a = sorted(l for l in out(s, "env").splitlines()
               if "=" in l and not l.startswith("_="))
    b = sorted(l for l in
               out(s, "tr '\\0' '\\n' < /proc/self/environ").splitlines() if l)
    eq("env == /proc/self/environ", b, a)


def t_proc_self_environ_has_the_ssh_variables():
    """The reason anyone reads this file."""
    s = shell()
    body = out(s, "tr '\\0' '\\n' < /proc/self/environ")
    for v in ("SSH_CLIENT", "SSH_CONNECTION", "USER", "HOME", "PATH"):
        check("environ has %s" % v, ("%s=" % v) in body, body[:120])
    check("peer address is in it", "203.0.113.77" in body, body[:120])


def t_proc_self_environ_is_nul_separated():
    s = shell()
    raw = s.run("cat /proc/self/environ")
    s._err.clear()
    check("uses NUL separators", "\0" in raw, repr(raw[:60]))
    check("no stray newlines", "\n" not in raw.strip("\n"), repr(raw[:60]))


def t_environ_does_not_carry_service_variables():
    s = shell()
    body = out(s, "tr '\\0' '\\n' < /proc/self/environ")
    for v in ("INVOCATION_ID", "JOURNAL_STREAM"):
        check("shell environ has no %s" % v, v not in body, body[:120])


def t_a_daemon_still_looks_like_a_daemon():
    """systemd really does set these for a service."""
    s = shell()
    body = out(s, "tr '\\0' '\\n' < /proc/701/environ")
    for v in ("INVOCATION_ID", "JOURNAL_STREAM"):
        check("nginx environ has %s" % v, v in body, body[:120])
    check("and no SSH_CLIENT", "SSH_CLIENT" not in body, body[:120])


def t_environ_is_a_snapshot_not_a_live_view():
    """A running process's environ does not change when it exports."""
    s = shell()
    out(s, "export LATEVAR=x")
    eq("env has it", out(s, "env | grep -c '^LATEVAR='"), "1")
    eq("environ does not",
       out(s, "tr '\\0' '\\n' < /proc/self/environ | grep -c '^LATEVAR='"), "0")


def t_environ_permissions():
    s = shell()
    eq("mode 400", out(s, "stat -c '%a' /proc/self/environ"), "400")


# -- the deploy user's view ----------------------------------------------

def t_a_non_root_shell_reports_itself():
    s = shell(user="deploy")
    body = out(s, "tr '\\0' '\\n' < /proc/self/environ")
    check("USER=deploy", "USER=deploy" in body, body[:140])
    check("HOME=/home/deploy", "HOME=/home/deploy" in body, body[:140])
    a = sorted(l for l in out(s, "env").splitlines()
               if "=" in l and not l.startswith("_="))
    b = sorted(l for l in body.splitlines() if l)
    eq("still matches env", b, a)


TESTS = [t_env_and_printenv_agree, t_printenv_one_variable,
         t_env_does_not_leak_shell_variables,
         t_export_p_does_not_leak_them_either, t_set_still_has_them,
         t_the_real_environment_is_all_there,
         t_a_child_does_not_see_shell_variables, t_export_makes_it_visible,
         t_proc_self_environ_matches_env,
         t_proc_self_environ_has_the_ssh_variables,
         t_proc_self_environ_is_nul_separated,
         t_environ_does_not_carry_service_variables,
         t_a_daemon_still_looks_like_a_daemon,
         t_environ_is_a_snapshot_not_a_live_view, t_environ_permissions,
         t_a_non_root_shell_reports_itself]


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
