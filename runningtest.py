#!/usr/bin/env python3
"""Does the box remember what it is running?

reconntest.py asked whether the files an attacker left behind survive their
next login. This asks the same of the processes, which turned out to be a
different answer: the payload came back and the thing it started did not.

Two defects, and they are opposite halves of the same omission.

A process the attacker started did not survive. The comment on VFS.procs
has always claimed these live on the VFS "so it survives across their
reconnections, like a real box would", and within one service lifetime they
did, because the VFS is cached per source IP. Nothing ever wrote them down,
so restarting the honeypot -- or evicting the VFS from its 200-entry cache
-- kept every dropped file and forgot every process. `ls /tmp/miner` found
the payload, `ps aux | grep miner` found nothing, and uptime still said 41
days: a box that lost its processes without rebooting.

A process the attacker killed did not stay dead. _killed_pids lived on the
Shell, which is one session, so it was forgotten at logout. Killing an nginx
worker makes the master refork a replacement -- correct, and that lives on
the VFS in respawned -- and then the next login showed the killed pid back
alongside its replacement: four nginx processes where the box has three,
with a pid returned from the dead. Killing one worker permanently grew the
listing on every reconnect. Killing a unit's *main* pid was durable the
whole time, because that routes through unit_state, which is persisted, so
the box had two ways of killing something and remembered only one of them.

Measured on the guest rather than assumed: over a non-interactive ssh exec,
`sleep &`, `nohup sleep &` and `setsid sleep &` all three survive the logout
and all three come back with ppid 1. There is no nohup distinction to model
-- the shell exits without signalling its children -- but the reparenting is
real, and every reader has to agree about it.

The invariant needs no reference machine: save, reload, and every command
that reports on a process answers as it did before, except the parent, which
becomes init because the shell that started it is gone.

Run from ~/opsec/honeypot:  python3 -W ignore runningtest.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

START = [
    "printf '#!/bin/sh\\nsleep 999\\n' > /tmp/miner",
    "chmod +x /tmp/miner",
    "nohup /tmp/miner > /dev/null 2>&1 &",
    "printf 'x' > /tmp/kworker",
    "chmod +x /tmp/kworker",
    "setsid /tmp/kworker > /dev/null 2>&1 &",
    "sleep 300 &",
]

# Everything that reports on a process. PID is filled in per run.
QUERIES = [
    "pgrep -a miner",
    "pgrep -x sleep",
    "pgrep -c sleep",
    "pgrep -a kworker",
    "ps -eo pid,stat,comm | grep -E 'miner|sleep'",
    "ps -o pid,cmd -p PID",
    "ps aux | grep -c miner",
    "top -bn1 | grep -c miner",
    "cat /proc/PID/cmdline | tr '\\0' ' '",
    "cat /proc/PID/comm",
    "readlink /proc/PID/exe",
    "ls -d /proc/PID",
    "awk '{print $1, $3}' /proc/PID/stat",
    "grep -E '^(Name|State)' /proc/PID/status",
    "ls /proc/PID/fd | head -3",
    "kill -0 PID; echo kill0=$?",
    "test -d /proc/PID && echo procdir=yes || echo procdir=no",
]

# The parent is the one thing that legitimately changes, and every reader of
# it has to change together.
PARENT = [
    "ps -o ppid= -p PID",
    "awk '{print $4}' /proc/PID/stat",
    "grep '^PPid' /proc/PID/status",
    "ps -eo pid,ppid | awk '$1==PID {print $2}'",
]


def ask(sh, q, pid):
    q = q.replace("PID", str(pid))
    del sh._err[:]
    return (sh.run(q), "".join(sh._err), sh.last_rc)


def restart(vfs, gap=3600):
    """A fresh VFS loading that state, `gap` seconds later -- what a service
    restart or a cache eviction looks like to the attacker."""
    # getattr rather than a direct call, so this suite runs against a build
    # that has no process persistence at all and reports what that build
    # actually does instead of dying on the missing method.
    j = vfs.dump_journal()
    dump = getattr(vfs, "dump_procs", None)
    pr = dump() if dump else None
    json.dumps({"journal": j, "procs": pr})    # it has to survive the file
    real = time.time
    time.time = lambda: real() + gap
    try:
        v = fs.VFS()
        v.load_journal(j)
        if pr is not None and hasattr(v, "load_procs"):
            v.load_procs(pr)
    finally:
        time.time = real
    sh = fs.Shell(v)
    sh.exec_mode = True
    return v, sh


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0

    def check(label, got, want):
        nonlocal ok, bad
        if got == want:
            ok += 1
            if verbose:
                print("  ok    %s" % label)
        else:
            bad += 1
            print("  FAIL  %s" % label)
            print("        got  %r" % (got,))
            print("        want %r" % (want,))

    # ---- a process they started survives ---------------------------------
    a = fs.VFS()
    sha = fs.Shell(a)
    sha.exec_mode = True
    for cmd in START:
        sha.run(cmd)
    pid = int(sha.run("pgrep -x miner").split()[0])
    before = {q: ask(sha, q, pid) for q in QUERIES}
    parent_before = ask(sha, PARENT[0], pid)[0].strip()
    check("the shell is the parent while the session is up",
          parent_before != "1" and parent_before != "", True)

    _, shb = restart(a)
    for q in QUERIES:
        check("survives the restart: %s" % q, ask(shb, q, pid), before[q])
    for q in PARENT:
        got = ask(shb, q, pid)[0]
        check("reparented to init: %s" % q, "1" in got.split(), True)

    # ...and a second restart is not different from the first
    b, _ = restart(a)
    _, shc = restart(b, gap=7200)
    for q in QUERIES[:8]:
        check("survives a second restart: %s" % q, ask(shc, q, pid),
              before[q])

    # ---- a process they killed stays dead --------------------------------
    k = fs.VFS()
    shk = fs.Shell(k)
    shk.exec_mode = True
    workers = [r.split()[0] for r in
               shk.run("pgrep -a nginx").strip().splitlines()]
    check("nginx starts with more than one process", len(workers) > 1, True)
    victim = workers[-1]
    shk.run("kill -9 %s" % victim)
    after_kill = [r.split()[0] for r in
                  shk.run("pgrep -a nginx").strip().splitlines()]
    check("the killed pid is gone in the session that killed it",
          victim in after_kill, False)
    check("the master reforked a replacement",
          len(after_kill), len(workers))

    # a plain reconnect: same VFS, new Shell, no restart at all
    shk2 = fs.Shell(k)
    shk2.exec_mode = True
    recon = [r.split()[0] for r in
             shk2.run("pgrep -a nginx").strip().splitlines()]
    check("the killed pid does not come back on reconnect",
          victim in recon, False)
    check("and the listing did not grow", recon, after_kill)

    _, shk3 = restart(k)
    rest = [r.split()[0] for r in
            shk3.run("pgrep -a nginx").strip().splitlines()]
    check("the killed pid does not come back after a restart",
          victim in rest, False)
    check("the listing is the same after a restart", rest, after_kill)
    check("nothing else answers differently about it",
          shk3.run("ps -eo pid | grep -cx ' *%s' || true" % victim).strip(),
          shk2.run("ps -eo pid | grep -cx ' *%s' || true" % victim).strip())

    # ---- killing an attacker's own process is durable too ----------------
    o = fs.VFS()
    sho = fs.Shell(o)
    sho.exec_mode = True
    sho.run("printf '#!/bin/sh\\nsleep 9\\n' > /tmp/p; chmod +x /tmp/p")
    sho.run("nohup /tmp/p >/dev/null 2>&1 &")
    opid = int(sho.run("pgrep -x p").split()[0])
    sho.run("kill -9 %d" % opid)
    check("their own killed process is gone", sho.run("pgrep -x p").strip(),
          "")
    _, sho2 = restart(o)
    check("...and stays gone after a restart",
          sho2.run("pgrep -x p").strip(), "")
    check("...and /proc agrees",
          sho2.run("test -d /proc/%d && echo yes || echo no" % opid).strip(),
          "no")

    # ---- pids are not handed out twice -----------------------------------
    _, shn = restart(a)
    shn.run("nohup /tmp/miner >/dev/null 2>&1 &")
    pids = shn.run("pgrep -a miner").strip().splitlines()
    check("a new process after a restart gets a fresh pid",
          len({p.split()[0] for p in pids}), len(pids))

    print("\nrunningtest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
