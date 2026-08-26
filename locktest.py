#!/usr/bin/env python3
"""Who is holding this lock, and does the box know that process?

/proc/locks was three literal rows:

    1: POSIX  ADVISORY  WRITE 412 08:02:262151 0 EOF
    2: FLOCK  ADVISORY  WRITE 1   08:02:131103 0 EOF
    3: POSIX  ADVISORY  WRITE 685 08:02:393228 0 EOF

on a box whose highest pid is 4100 and whose process table contains
neither 412 nor 685. `ps -p 412` answers "no such process" about a lock
the kernel is supposedly holding for it -- and the kernel drops a
process's locks when it dies, so a lock held by nobody cannot exist. The
inodes named no file on the box either.

`flock` was worse, because it is the command an attacker actually runs:

    flock -n /var/lock/x -c '<script>'
    bash: <script>: command not found

-c takes a shell command line and it was being used as a program name --
so the standard cron wrapper, and the "don't start twice" guard every
loader ships, failed outright. And nothing was ever locked: /proc/locks
did not change while flock ran, and a second `flock -n` on the same file
succeeded, which is the one thing flock exists to prevent.

Measured on the guest:

    flock -n /tmp/x -c 'echo held; id -u'    held / 1001, rc 0
    (while held) flock -n /tmp/x -c '...'    rc 1, no output
    while held, /proc/locks gains
        N: FLOCK  ADVISORY  WRITE <pid> <dev>:<ino> 0 EOF
    at rest, on a box running journald and cron   /proc/locks is empty

and on a busy host, 72 rows mixing POSIX and FLOCK, READ and WRITE, with
byte ranges. This persona's only justified resting lock is InnoDB's write
lock on ibdata1, which is what stops two servers opening one datadir.

One more of the same shape while checking the counts: /proc/loadavg's
fourth field read "1/28" while `ps -e -o stat=` listed no R at all. One
runnable task claimed, none nameable. On the guest there is exactly one R
and it is whatever is doing the looking.

Usage:  python3 locktest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.15", peer_port=40444)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def locks(sh):
    """Parsed /proc/locks rows, or [] if the file is empty."""
    rows = []
    for line in out(sh, "cat /proc/locks").splitlines():
        m = re.match(r"^(\d+): (\S+)\s+ADVISORY\s+(\S+) (\d+) "
                     r"(\S+):(\d+) (\S+) (\S+)$", line)
        if m:
            rows.append({"n": int(m.group(1)), "kind": m.group(2),
                         "mode": m.group(3), "pid": int(m.group(4)),
                         "dev": m.group(5), "ino": int(m.group(6)),
                         "start": m.group(7), "end": m.group(8)})
        else:
            rows.append({"raw": line})
    return rows


S = shell()

# ------------------------------------------------- every row is well formed
rows = locks(S)
check("every line parses", [r for r in rows if "raw" in r][:2], [])
check("there is at least one lock", len(rows) > 0, True,
      "a box running a database holds its datadir open")
check("the rows are numbered from 1",
      [r["n"] for r in rows if "n" in r],
      list(range(1, len([r for r in rows if "n" in r]) + 1)))

# ------------------------------------------------- and names a real process
alive = {}
for line in out(S, "ps -e -o pid=,comm=").splitlines():
    f = line.split()
    if len(f) >= 2 and f[0].isdigit():
        alive[int(f[0])] = f[1]
missing = [r["pid"] for r in rows if "pid" in r and r["pid"] not in alive]
check("every holder is a live process", missing, [],
      "the kernel drops a dead process's locks; 412 and 685 were in this "
      "file and in nothing else on the box")
check("...and ps -p agrees one at a time",
      [r["pid"] for r in rows if "pid" in r
       and not out(S, "ps -p %d -o pid=" % r["pid"]).strip()][:2], [])

# ------------------------------------------------- and a real file
for r in rows:
    if "ino" not in r:
        continue
    hit = out(S, "find / -xdev -inum %d 2>/dev/null | head -1" % r["ino"])
    check("inode %d belongs to a file" % r["ino"], bool(hit.strip()), True,
          "the inodes were 262151, 131103 and 393228, none of which is "
          "anything on this filesystem")
    check("...on the root device", r["dev"], "08:01",
          "08:02 is not a device this box has -- sda1 is 8:1")

check("the resting lock is the database's",
      sorted({alive.get(r["pid"], "?") for r in rows if "pid" in r}),
      ["mariadbd"])

# ------------------------------------------------------------- flock works
T = shell()
check("flock -c runs a command line, not a program",
      out(T, "touch /tmp/x; flock -n /tmp/x -c 'echo held; id -u'").strip(),
      "held\n0",
      "-c was passed to the dispatcher as a program name, so every real "
      "use of it -- the cron wrapper, the don't-start-twice guard -- came "
      "back 'command not found'")
check("...and exits with the command's status",
      out(T, "flock -n /tmp/x -c 'exit 7'; echo $?").strip(), "7")
check("the multi-word form works too",
      out(T, "flock -n /tmp/x echo viacmd").strip(), "viacmd")

check("a held lock refuses a second taker",
      out(T, "flock -n /tmp/x -c 'flock -n /tmp/x -c \"echo inner\"; "
             "echo rc=$?'").strip(), "rc=1",
      "this is the only thing flock exists to do")
check("...and the inner command did not run",
      "inner" in out(T, "flock -n /tmp/x -c 'flock -n /tmp/x -c "
                        "\"echo inner\"'"), False)

held = out(T, "flock -n /tmp/x -c 'cat /proc/locks'")
check("the lock is visible while it is held",
      any(l.split()[1] == "FLOCK" for l in held.splitlines()
          if len(l.split()) > 1), True,
      "/proc/locks did not move while flock ran")
check("...held by this shell",
      [l.split()[4] for l in held.splitlines()
       if len(l.split()) > 4 and l.split()[1] == "FLOCK"],
      [out(T, "echo $$").strip()])
check("...and released afterwards",
      any(l.split()[1] == "FLOCK" for l in out(T, "cat /proc/locks"
                                               ).splitlines()
          if len(l.split()) > 1), False,
      "a lock that outlives the command holding it locks the box out of "
      "its own file")
check("...leaving the resting set as it was",
      len(locks(T)), len(rows))

check("a lock on a new path creates the file",
      out(T, "flock -n /tmp/fresh.lock -c 'true'; ls /tmp/fresh.lock"
          ).strip(), "/tmp/fresh.lock",
      "flock opens the file with O_CREAT")
check("flock with no arguments is a usage error",
      out(T, "flock >/dev/null 2>&1; echo $?").strip(), "64")

# ------------------------------------------------- the runnable-task count
U = shell()
la = out(U, "cat /proc/loadavg").split()
check("loadavg has five fields", len(la), 5)
running = int(la[3].split("/")[0]) if len(la) > 3 and "/" in la[3] else -1
total = int(la[3].split("/")[1]) if len(la) > 3 and "/" in la[3] else -1
ps_r = len([l for l in out(U, "ps -e -o stat=").splitlines()
            if l.strip().startswith("R")])
check("the runnable count is what ps shows", running, ps_r,
      "it said 1 and ps listed none -- a runnable task nothing on the box "
      "can name")
check("there is exactly one runnable task", ps_r, 1,
      "measured on the guest: one R in the whole table, and it is the "
      "process doing the looking")
check("/proc/stat agrees",
      out(U, "awk '/^procs_running/{print $2}' /proc/stat").strip(),
      str(running))
check("the total is the process count", total,
      len([l for l in out(U, "ps -e --no-headers").splitlines() if l.strip()]))
check("the last pid is not below the highest live one",
      int(la[4]) >= max(alive) if len(la) > 4 and la[4].isdigit() else False,
      True)
check("the shell that is looking is the one running",
      out(U, "ps -p $$ -o stat=").strip().startswith("R"), True)

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
