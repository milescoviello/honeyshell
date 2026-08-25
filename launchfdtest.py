#!/usr/bin/env python3
"""Where a launched process thinks it is, and what it is writing to.

`nohup ./x &` is how nearly every loader that gets this far starts its
payload, and afterwards /proc said:

    /proc/<pid>/cwd     -> /                      (it was launched from /root)
    /proc/<pid>/fd/1    -> socket:[14101]         (nohup.out, actually)
    /proc/<pid>/fd/2    -> socket:[14101]
    all three fds        lrwx------

The cwd one needs no outside reference to see: the same nohup had just
printed "appending output to 'nohup.out'" and created that file **in the
launching directory**, so the emulator placed the file by the shell's cwd
and reported the process's cwd as `/` in the same breath. Two answers to
"where is this process", one of them from the file it had just written.

The cause is that "has no tty" was standing in for "is a system daemon".
That is right for nginx and mariadbd -- cwd `/`, stdin `/dev/null`, stdout
and stderr on one shared journald socket -- and wrong for a background job
started from a shell. `proc_meta` holds exactly what this session launched,
so it is the reliable way to tell them apart.

Reference measured on debian:trixie under a pty:

    nohup ./svc &
    lr-x------ 0 -> /dev/null
    l-wx------ 1 -> /root/nohup.out
    l-wx------ 2 -> /root/nohup.out
    cwd: /root
    ...and from /tmp/w, nohup.out and cwd both follow to /tmp/w.

The permission bits on an fd link are the **open mode**, not the target
type: `<>` gives lrwx, `>` gives l-wx, read-only gives lr-x. Measured the
same way. Everything here was lrwx, which says an append-only log is also
readable.

Usage:  python3 launchfdtest.py
"""

import re
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


def newest(sh, needle):
    pids = [int(l.split()[0]) for l in
            sh.run("ps -eo pid,args --no-headers").splitlines()
            if needle in l]
    return max(pids) if pids else None


def fdmap(sh, pid):
    """{fd: (mode string, target)} from `ls -l /proc/<pid>/fd`."""
    out = {}
    for line in sh.run("ls -l /proc/%d/fd" % pid).splitlines():
        m = re.match(r"^(l\S{9})\s+\S+\s+\S+\s+\S+\s+\d+\s+"
                     r"\S+\s+\S+\s+\S+\s+(\d+) -> (.+)$", line)
        if m:
            out[m.group(2)] = (m.group(1), m.group(3).strip().strip("'"))
    return out


def main():
    fs, sh = box()
    sh.run("mkdir -p /root/.x /tmp/w /var/tmp/d")
    sh.run("echo x > /root/.x/svc; chmod 755 /root/.x/svc")

    # -- launched from three different directories --------------------------
    for cwd in ("/root", "/tmp/w", "/var/tmp/d"):
        sh.run("cd %s" % cwd)
        check("the shell really is in %s" % cwd, sh.run("pwd").strip(), cwd)
        sh.run("nohup /root/.x/svc &")
        pid = newest(sh, "/root/.x/svc")
        check("launched from %s: it is in ps" % cwd, pid is not None, True)
        if pid is None:
            continue
        # The internal contradiction, with no outside reference: nohup put
        # the file here, so the process is here.
        out = sh.run("ls -l %s/nohup.out" % cwd).strip()
        check("nohup.out was created in %s" % cwd, bool(out), True)
        check("cwd agrees with where nohup.out went",
              sh.run("readlink /proc/%d/cwd" % pid).strip(), cwd)

        fds = fdmap(sh, pid)
        check("%s: three descriptors" % cwd, sorted(fds), ["0", "1", "2"])
        if sorted(fds) == ["0", "1", "2"]:
            check("%s: fd 0 is /dev/null" % cwd, fds["0"][1], "/dev/null")
            check("%s: fd 0 is read-only" % cwd, fds["0"][0], "lr-x------")
            check("%s: fd 1 is the nohup.out it made" % cwd, fds["1"][1],
                  "%s/nohup.out" % cwd)
            check("%s: fd 2 is the same file" % cwd, fds["2"][1], fds["1"][1])
            check("%s: fd 1 is write-only" % cwd, fds["1"][0], "l-wx------")
            check("%s: fd 2 is write-only" % cwd, fds["2"][0], "l-wx------")
            check("%s: no descriptor names a socket" % cwd,
                  [f for f, (_m, t) in fds.items() if t.startswith("socket:")],
                  [])
            # readlink and ls -l are two readers of one link.
            check("%s: readlink agrees with ls -l" % cwd,
                  sh.run("readlink /proc/%d/fd/1" % pid).strip(), fds["1"][1])

    # -- an explicit redirect wins over nohup.out ---------------------------
    fs, sh = box()
    sh.run("mkdir -p /root/.x; echo x > /root/.x/svc; chmod 755 /root/.x/svc")
    sh.run("nohup /root/.x/svc >/dev/null 2>&1 &")
    pid = newest(sh, "/root/.x/svc")
    fds = fdmap(sh, pid) if pid else {}
    check("redirected: fd 1 follows the redirect",
          fds.get("1", ("", ""))[1], "/dev/null")
    check("redirected: fd 2 too", fds.get("2", ("", ""))[1], "/dev/null")

    sh.run("nohup /root/.x/svc > /var/log/x.log 2>&1 &")
    pid = newest(sh, "/root/.x/svc")
    fds = fdmap(sh, pid) if pid else {}
    check("redirected to a file: fd 1 names it",
          fds.get("1", ("", ""))[1], "/var/log/x.log")

    # -- a stock daemon keeps the shape it should have ----------------------
    # If the fix had been applied by tty rather than by ownership, nginx
    # would have lost its journal socket and its cwd of /.
    fs, sh = box()
    ng = None
    for line in sh.run("ps -eo pid,comm --no-headers").splitlines():
        if line.split()[-1] == "nginx":
            ng = int(line.split()[0])
            break
    check("nginx is running", ng is not None, True)
    if ng:
        fds = fdmap(sh, ng)
        check("nginx cwd is still /",
              sh.run("readlink /proc/%d/cwd" % ng).strip(), "/")
        check("nginx stdout is still a journal socket",
              fds.get("1", ("", ""))[1].startswith("socket:["), True)
        check("nginx stdout and stderr share one inode",
              fds.get("1"), fds.get("2"))
        check("a socket descriptor is read-write",
              fds.get("1", ("", ""))[0], "lrwx------")

    # -- and the login shell still sits in its home -------------------------
    fs, sh = box()
    me = int(sh.run("echo $$").strip())
    check("the shell's own cwd is /root",
          sh.run("readlink /proc/%d/cwd" % me).strip(), "/root")
    sh.run("cd /tmp")
    check("...and follows cd", sh.run("readlink /proc/%d/cwd" % me).strip(),
          "/tmp")

    # -- it has to survive the reconnect ------------------------------------
    # cwd and the stdout target live in proc_meta, which is persisted with
    # the process list. A payload that came back running out of the wrong
    # directory would be a returning attacker's first surprise.
    fs, sh = box()
    sh.run("mkdir -p /var/tmp/.q; echo x > /var/tmp/.q/d; chmod 755 /var/tmp/.q/d")
    sh.run("cd /var/tmp/.q")
    sh.run("nohup /var/tmp/.q/d &")
    pid = newest(sh, "/var/tmp/.q/d")
    fs2 = fakeshell.VFS()
    fs2.load_journal(fs.dump_journal())
    fs2.load_procs(fs.dump_procs())
    sh2 = fakeshell.Shell(vfs=fs2, peer="203.0.113.9", peer_port=44322)
    check("the process came back", str(pid) in sh2.run("ps -eo pid --no-headers"),
          True)
    if pid:
        check("...in the directory it was started from",
              sh2.run("readlink /proc/%d/cwd" % pid).strip(), "/var/tmp/.q")
        check("...still writing to the same file",
              fdmap(sh2, pid).get("1", ("", ""))[1], "/var/tmp/.q/nohup.out")

    # -- tripwire: socket inodes that no table knows ------------------------
    # Not fixed here, and deliberately. Every socket:[N] in /proc/*/fd
    # should be findable in /proc/net/unix or /proc/net/tcp -- that join is
    # the basis of socket-to-process attribution. The journal sockets are
    # not, and completing /proc/net/unix from the descriptors turned a
    # 6-row table into a 45-row one while `ss -xa` and `netstat -x` kept
    # rendering their own lists, which is a worse disagreement than the one
    # it fixed. Three readers have to be unified at once; that is its own
    # sweep. This asserts today's wrong answer so it cannot change silently:
    # if it fails, either the tables were unified (good -- update this) or
    # something else moved.
    fs, sh = box()
    known = set()
    for line in sh.run("cat /proc/net/tcp").splitlines()[1:]:
        f = line.split()
        if len(f) > 9:
            known.add(f[9])
    for line in sh.run("cat /proc/net/unix").splitlines()[1:]:
        f = line.split()
        if len(f) > 6:
            known.add(f[6])
    unresolved = 0
    for pid in [int(x) for x in
                sh.run("ls /proc | grep -E '^[0-9]+$'").split()]:
        for m in re.finditer(r"socket:\[(\d+)\]",
                             sh.run("ls -l /proc/%d/fd 2>/dev/null" % pid)):
            if m.group(1) not in known:
                unresolved += 1
    check("KNOWN GAP: journal socket fds still resolve to no table row",
          unresolved > 0, True)
    check("...and it is only the daemons, not anything we launch",
          all(not t.startswith("socket:")
              for _m, t in fdmap(sh, me).values()), True)

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("launchfdtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
