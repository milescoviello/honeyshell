#!/usr/bin/env python3
"""What a launched process inherits, and whether the shell survives it.

A loader starts its payload and then looks around. That is the moment three
of /proc's files stopped answering.

`nohup ./x &` builds a subshell, and `Shell.__init__` takes the next pid and
registers it as *the* session shell -- shell_env_pid, an entry in the
per-shell environment table, and the /proc rows the constructor publishes.
Both call sites that build a subshell already knew `$$` stays the parent's
and set it back. Neither put the VFS back. So after a launch:

    cat /proc/$$/environ    empty      (385 bytes a second earlier)
    cat /proc/$$/cgroup     empty
    cat /proc/$$/limits     empty
    readlink /proc/self     a pid ps does not list

A file that answers, then answers nothing after an unrelated command, on a
box where nothing was killed, is not something a real kernel does.

The payload's own view was wrong in the other direction. It was treated as a
systemd service because it has no tty -- the same proxy that put its cwd at
`/` and its descriptors on a journal socket in the previous sweep -- so:

    /proc/<pid>/cgroup   0::/system.slice/svc.service
    /proc/<pid>/environ  NOTIFY_SOCKET, INVOCATION_ID, JOURNAL_STREAM
                         ...and no variable the launching shell exported

while `systemctl status svc.service` said "Unit svc.service could not be
found" and `systemctl list-units` had never heard of it. `systemd-cgls`
sided with the cgroup file, so two of the box's own tools disagreed about
whether a unit existed.

Measured on the guest (Debian 13.6, systemd):

    nohup sleep 60 &
    /proc/<pid>/cgroup   0::/user.slice/user-1001.slice/session-6715.scope
    /proc/$$/cgroup      the same scope, exactly
    NOTIFY_SOCKET count  0
    environ              SHELL, PWD, LOGNAME, XDG_SESSION_TYPE ...

A child is in its session's scope and carries its parent's environment,
because that is what fork does.

Usage:  python3 procselftest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def box():
    fs = fakeshell.VFS()
    return fs, fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321)


def env_of(sh, pid):
    raw = sh.run("cat /proc/%s/environ" % pid)
    return dict(p.split("=", 1) for p in raw.split("\0")
                if "=" in p)


def launch(sh, path="/root/.x/svc", pre=""):
    sh.run("mkdir -p %s" % path.rsplit("/", 1)[0])
    sh.run("echo x > %s; chmod 755 %s" % (path, path))
    sh.run("%snohup %s &" % (pre, path))
    pids = [int(l.split()[0]) for l in
            sh.run("ps -eo pid,args --no-headers").splitlines() if path in l]
    return max(pids) if pids else None


def main():
    # -- the shell's own files survive a launch -----------------------------
    fs, sh = box()
    sp = sh.shell_pid
    before = {f: sh.run("cat /proc/%d/%s" % (sp, f))
              for f in ("environ", "cgroup", "limits")}
    check("the shell has an environ to begin with",
          len(before["environ"]) > 100, True)
    check("...a cgroup", before["cgroup"].strip().startswith("0::/"), True)
    check("...and limits", len(before["limits"]) > 100, True)

    pid = launch(sh, pre="export EVILVAR=hello; ")
    check("the payload is in ps", pid is not None, True)
    for f in ("environ", "cgroup", "limits"):
        check("the shell's %s survives a launch" % f,
              sh.run("cat /proc/%d/%s" % (sp, f)), before[f])

    # -- and /proc/self still means the shell -------------------------------
    check("$$ is unchanged", sh.run("echo $$").strip(), str(sp))
    check("/proc/self is a pid ps lists",
          sh.run("readlink /proc/self").strip() in
          sh.run("ps -eo pid --no-headers").split(), True)
    check("/proc/self is not the attacker's payload",
          sh.run("readlink /proc/self").strip() != str(pid), True)
    for f in ("environ", "cgroup", "limits"):
        check("/proc/self/%s agrees with /proc/$$/%s" % (f, f),
              sh.run("cat /proc/self/%s" % f),
              sh.run("cat /proc/%d/%s" % (sp, f)))

    # -- the payload is a child, not a unit ---------------------------------
    if pid:
        cg = sh.run("cat /proc/%d/cgroup" % pid).strip()
        check("the payload is in a session scope, not a service",
              ".scope" in cg and "system.slice" not in cg, True)
        check("...the same scope as the shell that started it",
              cg, sh.run("cat /proc/%d/cgroup" % sp).strip())
        # The contradiction this closes: a cgroup naming a unit that
        # systemctl denies exists.
        unit = cg.rsplit("/", 1)[-1]
        if unit.endswith(".service"):
            check("a named unit is one systemctl knows",
                  "could not be found" not in
                  sh.run("systemctl status %s 2>&1" % unit), True)

        env = env_of(sh, pid)
        check("the payload inherited the shell's exported variable",
              env.get("EVILVAR"), "hello")
        for k in ("NOTIFY_SOCKET", "INVOCATION_ID", "JOURNAL_STREAM",
                  "SYSTEMD_EXEC_PID"):
            check("a forked child has no %s" % k, k in env, False)
        for k in ("HOME", "PATH", "USER", "SHELL"):
            check("...but does have %s" % k, k in env, True)
        check("its PWD is where it was launched", env.get("PWD"),
              sh.run("readlink /proc/%d/cwd" % pid).strip())

    # -- a daemon is still a daemon -----------------------------------------
    # If this had been fixed by tty rather than by ownership, nginx would
    # have moved into a login session it was never part of.
    fs, sh = box()
    ng = None
    for line in sh.run("ps -eo pid,comm --no-headers").splitlines():
        if line.split()[-1] == "nginx":
            ng = int(line.split()[0])
            break
    check("nginx is running", ng is not None, True)
    if ng:
        check("nginx is still in system.slice",
              sh.run("cat /proc/%d/cgroup" % ng).strip(),
              "0::/system.slice/nginx.service")
        nenv = env_of(sh, ng)
        check("a real service still has INVOCATION_ID",
              "INVOCATION_ID" in nenv, True)
        check("...and JOURNAL_STREAM", "JOURNAL_STREAM" in nenv, True)

    # -- several launches do not each claim the session ---------------------
    fs, sh = box()
    sp = sh.shell_pid
    for n in range(3):
        launch(sh, "/root/.x/p%d" % n)
    check("three launches later the shell still has an environ",
          len(sh.run("cat /proc/%d/environ" % sp)) > 100, True)
    check("...and $$ has not moved", sh.run("echo $$").strip(), str(sp))
    scopes = set()
    for line in sh.run("ps -eo pid,args --no-headers").splitlines():
        if "/root/.x/p" in line:
            scopes.add(sh.run("cat /proc/%s/cgroup"
                              % line.split()[0]).strip())
    check("every payload is in one shared session scope", len(scopes), 1)
    check("...which is the shell's",
          scopes.pop() if scopes else None,
          sh.run("cat /proc/%d/cgroup" % sp).strip())

    # -- tripwire: /proc/self is the shell, not the reader ------------------
    # On the guest, `readlink /proc/self` is the pid of the readlink
    # process itself and `readlink /proc/self/exe` is /usr/bin/readlink.
    # Here /proc/self is the session's shell, so cmdline and exe describe
    # bash. That is wrong, and it is much less wrong than what it replaced:
    # /proc/self used to be the highest pid in the table, which after a
    # launch is the attacker's own payload -- so `readlink /proc/self/exe`
    # handed them its path. Modelling a transient process per command is
    # its own sweep. This asserts today's answer so it cannot drift
    # unnoticed.
    fs, sh = box()
    check("KNOWN GAP: /proc/self/exe is the shell, not the reader",
          sh.run("readlink /proc/self/exe").strip(), "/usr/bin/bash")
    check("...and it is at least not a payload",
          launch(sh, "/root/.x/q") != int(
              sh.run("readlink /proc/self").strip()), True)

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("procselftest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
