#!/usr/bin/env python3
"""/etc/sudoers says env_reset. Did sudo ever read its own file?

Sweep 144. The box publishes /etc/sudoers and will show it to anyone who asks.
That file says:

    Defaults env_reset
    Defaults secure_path="/usr/local/sbin:..."

secure_path was honoured. env_reset was not. Every variable the caller had
went straight through, including **LD_PRELOAD** -- which real sudo strips
unconditionally, even under -E, because preserving it would turn every sudo
into an arbitrary-code-execution primitive. That is one of the few things sudo
absolutely guarantees, and checking it costs an attacker one command.

Three readers disagreed with one written promise:

  * env_reset      -- not performed at all
  * the -E flag    -- indistinguishable from not passing it, so a script that
                      uses -E deliberately could not tell whether it worked
  * SUDO_*         -- real sudo sets five variables describing the caller;
                      this one set none

The cheap tell here is not LD_PRELOAD. It is SSH_CONNECTION: seeing it survive
a sudo says the environment was never reset, in one command, with nothing
exotic involved. This box was passing SSH_CLIENT, SSH_CONNECTION, SSH_TTY and
the whole XDG_* set straight through.

Measured on sudo 1.9.16p2, deploy -> root, with LANG/LC_ALL/DISPLAY/LS_COLORS/
PS1/EVIL/LD_PRELOAD all set in the caller:

  plain sudo   HOME and MAIL become the TARGET's; USER and LOGNAME become the
               target; PATH is secure_path; DISPLAY, LANG, LC_*, LS_COLORS,
               PS1 and TERM survive; EVIL, PWD and SHLVL do not.
  sudo -E      the caller's HOME, MAIL, PWD, SHLVL and EVIL survive; USER,
               LOGNAME and PATH still become the target's.
  both         LD_PRELOAD is gone and SUDO_* is set.

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


def caller_shell():
    """A deploy session carrying the variables a real one would, plus the
    ones an attacker would plant."""
    s = fs.Shell(fs.VFS(), user="deploy", peer="198.51.100.7")
    del s._err[:]
    s.run("export EVIL=payload LD_PRELOAD=/tmp/eve.so "
          "LD_LIBRARY_PATH=/tmp LANG=en_GB.UTF-8 LC_ALL=C DISPLAY=:0 "
          "LS_COLORS=xx BASH_ENV=/tmp/b.sh")
    del s._err[:]
    s.run("echo 'deploy123' | sudo -S true")     # authenticate once
    del s._err[:]
    return s


def env_after(s, flags=""):
    out = s.run("sudo %sprintenv" % (flags + " " if flags else ""))
    del s._err[:]
    env = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


# -- the guarantee ------------------------------------------------------

def t_the_loader_variables_never_survive():
    """LD_PRELOAD and friends are stripped whether or not -E is given. This
    is the check that would tell an attacker the most if it failed."""
    s = caller_shell()
    for flags in ("", "-E"):
        env = env_after(s, flags)
        for var in ("LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV"):
            check("sudo %s strips %s" % (flags or "(plain)", var),
                  var not in env, "%s=%r survived" % (var, env.get(var)))


def t_the_cheap_tell_is_gone():
    """SSH_CONNECTION surviving a sudo says the environment was never reset,
    and needs nothing exotic to notice."""
    s = caller_shell()
    env = env_after(s)
    for var in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "XDG_SESSION_ID",
                "XDG_RUNTIME_DIR", "MOTD_SHOWN", "SHLVL", "PWD"):
        check("plain sudo drops %s" % var, var not in env,
              "%s=%r survived" % (var, env.get(var)))


# -- what env_reset keeps, and what it replaces -------------------------

def t_env_reset_keeps_only_what_env_keep_lists():
    s = caller_shell()
    env = env_after(s)
    for var in ("DISPLAY", "LANG", "LC_ALL", "LS_COLORS", "TERM"):
        check("env_keep preserves %s" % var, var in env, "dropped")
    check("a variable on no list is dropped", "EVIL" not in env,
          "EVIL=%r survived" % env.get("EVIL"))


def t_the_identity_variables_become_the_targets():
    s = caller_shell()
    env = env_after(s)
    eq("USER is the target", env.get("USER"), "root")
    eq("LOGNAME is the target", env.get("LOGNAME"), "root")
    eq("HOME is the target's", env.get("HOME"), "/root")
    eq("MAIL is the target's", env.get("MAIL"), "/var/mail/root")
    eq("SHELL is set", env.get("SHELL"), "/bin/bash")


def t_path_is_secure_path_and_the_file_still_says_so():
    """The file and the behaviour are written from one constant, so they
    cannot drift into disagreeing."""
    s = caller_shell()
    env = env_after(s)
    eq("PATH is secure_path", env.get("PATH"), fs.PATH_ROOT)
    # /etc/sudoers is 0440 root:root, so the deploy session that ran the
    # sudo above cannot read it back. Ask as root -- the point is that the
    # file and the behaviour agree, not who can see the file.
    root = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    del root._err[:]
    sudoers = root.run("cat /etc/sudoers")
    del root._err[:]
    check("and /etc/sudoers still publishes that exact path",
          fs.PATH_ROOT in sudoers, sudoers[:80])


# -- sudo's own variables, which describe the caller --------------------

def t_sudo_sets_the_five_variables_that_describe_the_caller():
    s = caller_shell()
    env = env_after(s)
    eq("SUDO_USER is the caller", env.get("SUDO_USER"), "deploy")
    eq("SUDO_UID is the caller's", env.get("SUDO_UID"), "1000")
    eq("SUDO_GID is the caller's", env.get("SUDO_GID"), "1000")
    eq("SUDO_HOME is the caller's", env.get("SUDO_HOME"), "/home/deploy")
    check("SUDO_COMMAND names the resolved command",
          env.get("SUDO_COMMAND") == "/usr/bin/printenv",
          "got %r" % env.get("SUDO_COMMAND"))


def t_sudo_user_is_readable_by_a_child():
    """The way a script actually reads it. Setting the variable without
    exporting it left `sudo sh -c 'echo $SUDO_USER'` empty while `printenv`
    would have shown it -- two answers to one question."""
    s = caller_shell()
    out = s.run("sudo sh -c 'echo [$SUDO_USER]'")
    del s._err[:]
    eq("a child sees SUDO_USER", out.strip(), "[deploy]")


# -- -E has to mean something -------------------------------------------

def t_preserve_env_preserves_and_is_distinguishable():
    s = caller_shell()
    plain, preserved = env_after(s), env_after(s, "-E")
    check("-E keeps a custom variable", preserved.get("EVIL") == "payload",
          "got %r" % preserved.get("EVIL"))
    check("...which plain sudo dropped", "EVIL" not in plain)
    eq("-E keeps the caller's HOME", preserved.get("HOME"), "/home/deploy")
    eq("...where plain sudo used the target's", plain.get("HOME"), "/root")
    check("-E is distinguishable from plain sudo", plain != preserved,
          "identical environments")
    # ...but the identity still switches.
    eq("-E still becomes the target", preserved.get("USER"), "root")
    eq("-E still uses secure_path", preserved.get("PATH"), fs.PATH_ROOT)


# -- and none of it leaks back into the caller --------------------------

def t_the_callers_environment_is_restored():
    s = caller_shell()
    env_after(s)
    env_after(s, "-E")
    for var, want in (("EVIL", "payload"), ("LD_PRELOAD", "/tmp/eve.so"),
                      ("LANG", "en_GB.UTF-8")):
        got = s.run("echo $%s" % var).strip()
        del s._err[:]
        eq("caller keeps its own %s" % var, got, want)
    eq("caller is deploy again", s.run("whoami").strip(), "deploy")
    del s._err[:]
    check("and SUDO_USER is not left behind",
          s.run("echo [$SUDO_USER]").strip() == "[]")
    del s._err[:]


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
