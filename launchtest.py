#!/usr/bin/env python3
"""What a process the attacker just started looks like to every reader.

The axis: `nohup ./miner >/dev/null 2>&1 &`, then the self-check every
loader runs -- `ps aux | grep miner`, `pgrep`, `pidof`, /proc. Six
readers, and they described six different processes:

    ps       nohup /root/miner > /dev/null 2>&1
    comm     nohup
    exe      /usr/bin/nohup
    PPID     1
    pgrep miner   (nothing)
    TIME     00:01:14 for a process one second old

No cmdline on Linux contains a shell redirection -- the shell consumes it
before exec. nohup execs its target, so nohup is not in the listing at
all. A #! script runs as "INTERP script", keeps the *script's* name as
its comm, and points exe at the interpreter. And nohup does not reparent:
the process stays a child of the shell that started it.

203.0.113.40 ran `ps | grep '[Mm]iner'` and `ps -ef | grep '[Mm]iner'`
on this box on 2026-08-22, which is exactly this listing.

Reference behaviour measured on the guest (Debian 13).
"""
import sys
import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.77")
    s.exec_mode = True
    return v, s


def launch(s, body="#!/bin/sh\nsleep 999\n", path="/root/miner",
           how="nohup %s > /dev/null 2>&1 &"):
    s.fs.write(path, body.encode())
    s.run("chmod +x %s" % path)
    s.run(how % path)
    return s.run("pgrep -f %s" % path.rsplit("/", 1)[-1]).strip()


def main():
    # -- the listing ------------------------------------------------------
    v, s = sh()
    pid = launch(s)
    check("the process exists", pid.isdigit(), True)
    row = s.run("ps aux | grep '[m]iner'").strip()
    check("ps shows the interpreter and the script",
          row.endswith("/bin/sh /root/miner"), True)
    check("no redirection in the command line",
          ">" in row or "2>&1" in row, False)
    check("nohup is not in the listing", "nohup" in row, False)
    check("state is S, not Sl -- one thread, no LWPs",
          " S " in row, True)

    # -- names ------------------------------------------------------------
    check("cmdline is argv, not the typed line",
          s.run("cat /proc/%s/cmdline | tr '\\0' ' '" % pid),
          "/bin/sh /root/miner ")
    check("comm is the script's own name",
          s.run("cat /proc/%s/comm" % pid).strip(), "miner")
    check("exe is the interpreter",
          s.run("readlink /proc/%s/exe" % pid).strip(), "/usr/bin/dash")
    check("and the interpreter exists",
          s.run("test -f /usr/bin/dash && echo yes").strip(), "yes")

    # -- the self-checks a loader runs -------------------------------------
    check("pgrep -f finds it", s.run("pgrep -f miner").strip(), pid)
    check("pgrep by name finds it -- comm is 'miner'",
          s.run("pgrep miner").strip(), pid)
    check("pidof does not: it skips scripts",
          s.run("pidof miner; echo rc=$?").strip(), "rc=1")
    check("pidof -x does", s.run("pidof -x miner").strip(), pid)
    check("pgrep -c counts one", s.run("pgrep -cf miner").strip(), "1")
    check("kill -0 says it is alive",
          s.run("kill -0 %s; echo rc=$?" % pid).strip(), "rc=0")

    # -- the parent --------------------------------------------------------
    check("its parent is the shell, not init",
          s.run("ps -o ppid= -p %s" % pid).strip(), str(s.shell_pid))
    check("/proc agrees",
          [l for l in s.run("cat /proc/%s/status" % pid).splitlines()
           if l.startswith("PPid")][0].split()[1], str(s.shell_pid))

    # -- the clocks --------------------------------------------------------
    cells = s.run("ps -o etimes,times,%cpu --no-headers -p " + pid).split()
    check("elapsed is seconds, not 41 days", int(cells[0]) < 3600, True)
    check("cpu time does not exceed elapsed",
          int(cells[1]) <= int(cells[0]), True)
    check("a sleeping process has burned no cpu",
          s.run("ps -o times= -p %s" % pid).strip(), "0")
    check("TIME column agrees with times",
          s.run("ps -o time= -p %s" % pid).strip(), "00:00:00")
    # etime and etimes are the same number in two formats.
    et = s.run("ps -o etime= -p %s" % pid).strip()
    ets = int(s.run("ps -o etimes= -p %s" % pid).strip())
    mins, secs = et.split(":")[-2:]
    check("etime and etimes agree",
          int(mins) * 60 + int(secs), ets)
    # pid 1 still reports the uptime, which is where it came from.
    check("init's elapsed time is the uptime",
          int(s.run("ps -o etimes= -p 1").strip()) > 86400, True)

    # -- a binary, not a script --------------------------------------------
    v, s = sh()
    s.run("nohup /usr/bin/curl -s http://example.test/x > /tmp/o 2>&1 &")
    row = s.run("ps aux | grep '[c]url'").strip()
    check("a real binary keeps its own argv",
          row.endswith("/usr/bin/curl -s http://example.test/x"), True)
    cpid = s.run("pgrep -f curl").strip().split("\n")[0]
    check("its comm is the binary", s.run("cat /proc/%s/comm" % cpid).strip(),
          "curl")
    check("its exe is the binary",
          s.run("readlink /proc/%s/exe" % cpid).strip(), "/usr/bin/curl")
    check("pidof finds a binary without -x",
          s.run("pidof curl").strip(), cpid)

    # -- the wrappers that exec ---------------------------------------------
    for how, label in (("setsid %s &", "setsid"),
                       ("env FOO=bar %s &", "env"),
                       ("FOO=bar %s &", "an assignment prefix"),
                       ("nohup setsid %s &", "nohup setsid")):
        v, s = sh()
        launch(s, how=how)
        row = s.run("ps aux | grep '[m]iner'").strip()
        check("%s is exec'd through, not listed" % label,
              row.endswith("/bin/sh /root/miner"), True)

    # A plain foreground launch is on the tty, not "?".
    v, s = sh()
    s.fs.write("/root/miner", b"#!/bin/sh\nsleep 999\n")
    s.run("chmod +x /root/miner")
    s.run("/root/miner &")
    check("a backgrounded job has no controlling tty",
          s.run("ps -o tty= -p %s"
                % s.run("pgrep miner").strip()).strip(), "?")

    # -- jobs still line up with the process --------------------------------
    v, s = sh()
    pid = launch(s)
    check("jobs knows the same pid",
          s.run("jobs -p").strip(), pid)
    check("$! is the same pid", s.run("echo $!").strip(), pid)
    check("only one process was registered for one launch",
          s.run("pgrep -cf miner").strip(), "1")
    s.run("kill %s" % pid)
    check("killing it removes it from ps",
          s.run("pgrep -f miner").strip(), "")
    check("...and from /proc",
          s.run("test -d /proc/%s || echo gone" % pid).strip(), "gone")

    # -- hostname: static is the file, transient is the kernel --------------
    v, s = sh()
    check("hostnamectl --static reads /etc/hostname",
          s.run("hostnamectl --static").strip(),
          s.run("cat /etc/hostname").strip())
    s.run("hostname evilbox")
    check("hostname sets the transient name",
          s.run("hostname").strip(), "evilbox")
    check("the file is untouched",
          s.run("cat /etc/hostname").strip(), "web01")
    check("so the static name is still web01",
          s.run("hostnamectl --static").strip(), "web01")
    check("and the transient one is not",
          s.run("hostnamectl --transient").strip(), "evilbox")
    check("hostnamectl prints both when they differ",
          "Transient hostname: evilbox" in s.run("hostnamectl"), True)
    check("uname -n follows the kernel",
          s.run("uname -n").strip(), "evilbox")
    check("$HOSTNAME does not -- bash set it at startup",
          s.run("echo $HOSTNAME").strip(), "web01")
    # The interactive prompt expands \h from the same value, but it is
    # rendered by ssh_honeypot rather than by the shell, so it is verified
    # live over a pty rather than here. (${PS1@P} is not implemented, which
    # is why this cannot be asserted in-process.)
    s.run("hostnamectl set-hostname realbox")
    check("set-hostname writes the file",
          s.run("cat /etc/hostname").strip(), "realbox")
    check("...and both names agree again",
          (s.run("hostnamectl --static").strip(),
           s.run("hostname").strip()), ("realbox", "realbox"))

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("launchtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
