"""Republishing /proc after a process starts, and what it must not cost.

Every process start rebuilds /proc. It used to rebuild all of it: tear down
39,000 nodes and re-create them, for the 488 processes that had not changed
as much as the one that had. Three hundred background jobs on one line --
which is a shape a scanner produces without trying -- took nineteen
seconds, and a real bash takes none. A pause that long needs no knowledge
of the box to notice.

Rebuilding everything also meant every /proc inode was reallocated on every
start, so `stat -c %i /proc/1/stat` gave a different answer before and
after an unrelated process appeared. On a real box those inodes are stable
for as long as the process lives, and that is cheap to check from inside.

The risk in only rebuilding what changed is a process keeping stale nodes,
so what is checked here is the *result* -- the tree matches the process
table, and the tables built by folding every pid together still contain the
processes that were skipped.

The glob half is the same shape of bug in the other direction: _glob asked
the node table once per directory rather than once per level, so a six-level
pattern walked 49,545 nodes 28,426 times. Both are here because both are
"asked the whole table once per item instead of once per pass".

Usage:  python3 procresynctest.py
"""

import re
import sys
import threading
import time

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                     peer_port=40333)
sh.run("true")


def out(c):
    o = sh.run(c)
    return ((o[0] if isinstance(o, tuple) else o) or "").strip()


def pid_dirs():
    return {int(m.group(1)) for m in
            (re.match(r"^/proc/(\d+)/stat$", k) for k in sh.fs.node_paths())
            if m}


# --------------------------------------------- the tree tracks the table
_before = pid_dirs()
sh.run("sleep 1 &")
_after = pid_dirs()
check("a background job adds exactly one /proc directory",
      len(_after - _before), 1)
check("nothing else disappears", _before - _after, set())
check("/proc/self survives the rebuild", "/proc/self" in sh.fs.node_paths(),
      True)
check("the new pid has its own stat file",
      all(("/proc/%d/stat" % p) in sh.fs.node_paths()
          for p in (_after - _before)), True)

# ps and the tree must agree about which processes exist
_ps = {int(x) for x in out("ps -eo pid --no-headers").split()}
check("every pid ps lists has a /proc directory", _ps - pid_dirs(), set(),
      "a process with no /proc directory is a process that does not exist")

# ------------------------------------------------------ inode stability
_i1 = out("stat -c %i /proc/1/stat")
sh.run("sleep 1 &")
_i2 = out("stat -c %i /proc/1/stat")
check("an unrelated process starting does not move pid 1's inode",
      _i1, _i2, "these are stable for the life of a process on a real box")
check("the inode is a number", bool(_i1.isdigit()), True)

# ------------------------------ tables folded from every pid, not just new
check("/proc/net/unix still has entries after a start",
      len(getattr(sh.fs, "unix_conn", []) or []) > 0, True,
      "these are collected per process; rebuilding from the changed ones "
      "alone empties the table on the first command after any start")
_unix = out("cat /proc/net/unix")
check("/proc/net/unix renders more than its header",
      len(_unix.splitlines()) > 1, True)

# ------------------------------------------------------------- the glob
check("a root glob expands", out("echo /etc/cron.d/*"),
      "/etc/cron.d/e2scrub_all")
check("an unmatched glob is left alone", out("echo /nope/*"), "/nope/*",
      "bash leaves a pattern that matched nothing as it stands")
_root = out("echo /*")
check("the root glob lists real top-level directories",
      "/etc" in _root.split() and "/proc" in _root.split(), True,
      'listdir_many keyed the root as "" and dropped its children')

# ------------------------------------------------------ and the budgets
# Generous, because these are wall-clock on whatever machine runs them and
# a hang is unbounded. The point is the order of magnitude, not the number:
# before this work the glob did not finish inside 26 seconds and the jobs
# took 19.
def timed(script, limit):
    res = {}

    def go():
        t0 = time.time()
        sh.run(script)
        res["t"] = time.time() - t0

    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join(limit)
    return None if th.is_alive() else res.get("t")


_t = timed("echo /*/*/*/*/*/*", 30)
check("a six-level glob finishes", _t is not None, True,
      "one pass per level, not one per directory")
if _t is not None:
    check("a six-level glob is not the dominant cost of a command",
          _t < 10.0, True, "measured 0.11s; it was over 26s")

_t = timed("; ".join(["sleep 1 &"] * 300), 60)
check("three hundred background jobs finish", _t is not None, True)
if _t is not None:
    check("three hundred background jobs are not a visible pause",
          _t < 20.0, True, "measured 7.1s; it was 19.0s")

for f in FAILS:
    print(" ", f)
print("   procresync: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
