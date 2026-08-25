#!/usr/bin/env python3
"""Several channels on one connection, all touching one filesystem.

SSH multiplexes, and this honeypot gives every channel of a connection the
same VFS. That makes the node table genuinely concurrent, and it was not
written for that.

Two bugs, both found on 2026-08-25 chasing what had looked for weeks like
flakiness in chantest:

  1. Shell.__init__ -> absorb_seed -> _alloc_blocks walked self.nodes while
     another channel's constructor was adding to it, and raised
     "RuntimeError: dictionary changed size during iteration". That
     exception propagated out of the session handler, so the *transport*
     went down: a third exec was logged by the request handler and then
     never ran. The capture claimed a command we never executed, which is
     the worst failure this box has -- worse than missing it, because it is
     wrong rather than absent.

     It reproduced about one round in fifteen over SSH, which is exactly
     the rate that reads as a flaky test rather than a bug.

  2. Even without crashing, the block accounting was wrong. Each
     constructor takes a mark, seeds its share of the persona, and absorbs
     the difference. Interleave two and A's mark predates B's seeding, so
     A absorbs B's blocks and then B absorbs them again. Measured, 24
     concurrent constructions left _base_blocks anywhere from 95938 to
     109772 where the sequential answer is 95917 -- df's used figure
     drifting upward while nobody wrote anything.

The second is the one worth having a test for. A crash is loud; a df that
disagrees with the tree is the quiet kind of wrong that this whole emulator
exists to prevent, and no amount of single-threaded testing sees it.

Usage:  python3 concurtest.py
"""

import sys
import threading

import fakeshell as F

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def _run_threads(fns):
    """Run all of them at once and collect whatever they raise."""
    errs = []
    start = threading.Barrier(len(fns))

    def wrap(f):
        def go():
            try:
                start.wait(timeout=30)
                f()
            except Exception as exc:                          # noqa: BLE001
                errs.append("%s: %s" % (type(exc).__name__, exc))
        return go

    ts = [threading.Thread(target=wrap(f)) for f in fns]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=120)
    return errs


def t_concurrent_construction_does_not_raise():
    """The crash, directly: N constructors on one shared VFS."""
    for _ in range(3):
        v = F.VFS()

        def one(i=0):
            sh = F.Shell(vfs=v, user="root")
            sh.run("echo hi > /tmp/c%d" % i)

        errs = _run_threads([lambda i=i: one(i) for i in range(24)])
        check("24 concurrent constructions raise nothing", errs, [])


def t_block_accounting_is_interleaving_independent():
    """The quiet one: df must not depend on thread scheduling.

    A barrier makes every constructor start together, which is the
    interleaving that double-counted. The answer has to equal the
    sequential one exactly -- "close" is not a property a filesystem can
    have.
    """
    seq = F.VFS()
    for i in range(24):
        F.Shell(vfs=seq, user="root").run("echo hi > /tmp/s%d" % i)
    want = seq._base_blocks

    for _ in range(3):
        v = F.VFS()

        def one(i=0):
            F.Shell(vfs=v, user="root").run("echo hi > /tmp/s%d" % i)

        _run_threads([lambda i=i: one(i) for i in range(24)])
        check("concurrent base_blocks equals sequential",
              v._base_blocks, want)


def t_df_agrees_after_concurrent_sessions():
    """And the same thing as an attacker would see it."""
    def used(vfs):
        sh = F.Shell(vfs=vfs, user="root")
        row = sh.run("df -k / | tail -1").split()
        return row[2] if len(row) > 2 else "?"

    seq = F.VFS()
    for i in range(12):
        F.Shell(vfs=seq, user="root").run("echo hi > /tmp/d%d" % i)

    con = F.VFS()

    def one(i=0):
        F.Shell(vfs=con, user="root").run("echo hi > /tmp/d%d" % i)

    _run_threads([lambda i=i: one(i) for i in range(12)])
    check("df used is the same either way", used(con), used(seq))


def t_walkers_survive_concurrent_writes():
    """listdir/ls/du walk the node table; a write must not break them.

    Every one of these walked self.nodes live. The comprehension form
    (`[k for k in self.nodes if ...]`) is no safer than the loop form --
    it iterates the same live dict.
    """
    v = F.VFS()
    reader = F.Shell(vfs=v, user="root")
    writer = F.Shell(vfs=v, user="root")
    stop = threading.Event()

    def write():
        i = 0
        while not stop.is_set() and i < 400:
            writer.run("echo x > /tmp/w%d; rm -f /tmp/w%d" % (i, i - 5))
            i += 1

    def read():
        for _ in range(60):
            reader.run("ls /tmp >/dev/null")
            reader.run("ls -l /etc >/dev/null")
            reader.run("du -s /etc >/dev/null")
            reader.run("df -k / >/dev/null")

    errs = _run_threads([write, read])
    stop.set()
    check("walking the tree during writes raises nothing", errs, [])


def t_remove_during_listdir():
    """rm -rf deletes whole subtrees while another channel lists them."""
    v = F.VFS()
    a = F.Shell(vfs=v, user="root")
    b = F.Shell(vfs=v, user="root")
    a.run("mkdir -p /tmp/tree/%s" % "/".join(str(i) for i in range(6)))
    for i in range(40):
        a.run("mkdir -p /tmp/tree/d%d; echo y > /tmp/tree/d%d/f" % (i, i))

    def rm():
        for i in range(40):
            a.run("rm -rf /tmp/tree/d%d" % i)

    def ls():
        for _ in range(80):
            b.run("ls -R /tmp/tree >/dev/null")

    errs = _run_threads([rm, ls])
    check("rm -rf during ls -R raises nothing", errs, [])


def main():
    for fn in (t_concurrent_construction_does_not_raise,
               t_block_accounting_is_interleaving_independent,
               t_df_agrees_after_concurrent_sessions,
               t_walkers_survive_concurrent_writes,
               t_remove_during_listdir):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-52s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("concurtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
