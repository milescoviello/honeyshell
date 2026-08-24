#!/usr/bin/env python3
"""Do the differential suites know a host difference from an emulator bug?

Sweep 139. Five suites failed in CI and none of them had found an emulator
bug. They had all made the same unexamined assumption -- that the machine
running the suite resembles the machine being emulated -- and when it did
not, they reported the host's difference as if it were the emulator's. That
is precisely the failure mode the README warns readers about, living inside
the suites that are supposed to be the evidence.

What went wrong, measured in a debian:trixie container:

  difftest3   the container has no wget, so `command -v wget || ...` and the
              `for b in wget curl` loop compared our persona (which has wget)
              against a host that does not. Nothing about the emulator tested.
  difftest4   no hexdump -- it lives in bsdextrautils -- so two cases diffed
              our output against "command not found".
  lsargtest   `ls -U` means do not sort, so the order is readdir order, i.e.
              the filesystem's choice. Passed on ext4, btrfs and a local
              overlayfs; failed on the overlayfs CI hands a container.
  texttest    `ps aux | awk '{print $2}'` prints the *host's* PIDs. A booted
              machine gives 1 and 2, which happens to equal the persona's
              first two; a PID namespace gives 1 and 9, which does not.
  shadowtest  py3.13 removed the crypt module, so the single most valuable
              assertion in the suite -- the passwords this box accepts really
              do verify against /etc/shadow -- stopped running on the guest
              and in CI, and reported itself red while not running.

The distinction this suite defends: a case the host cannot answer is neither
a match nor a difference, and it must not be folded into either. It also
must not be parked in a KNOWN list, because KNOWN tolerates it forever --
including on hosts that *can* answer it, where a real regression would then
hide. It needs a third verdict, decided at runtime.

Run from `honeypot/`.
"""

import ast
import importlib.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


def load(fn):
    """Import a suite module without running it."""
    spec = importlib.util.spec_from_file_location(
        "_hs_" + fn[:-3], os.path.join(HERE, fn))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def literals(fn, *names):
    """Pull top-level literal assignments out of a suite without importing.

    difftest3.py has no `if __name__` guard -- importing it runs the whole
    comparison and calls sys.exit -- so the cross-checks below read the
    source instead. That works for every suite regardless.
    """
    tree = ast.parse(open(os.path.join(HERE, fn), encoding="utf-8").read())
    out = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in names:
                try:
                    out[t.id] = ast.literal_eval(node.value)
                except ValueError:
                    pass
    return out


# -- a declared exception must name a case that exists ---------------------
#
# A key that matches no case is a silent no-op: the suite keeps failing and
# the entry that was supposed to fix it sits there looking like it did.

def t_difftest3_needs_name_real_cases():
    d = literals("difftest3.py", "CASES", "NEEDS", "KNOWN")
    names = {c[0] for c in d["CASES"]}
    check("difftest3 declares NEEDS", "NEEDS" in d)
    for k in d.get("NEEDS", {}):
        check("difftest3 NEEDS[%r] is a real case" % k, k in names)
    for k in d.get("KNOWN", {}):
        check("difftest3 KNOWN[%r] is a real case" % k, k in names)


def t_difftest4_needs_name_real_cases():
    d = literals("difftest4.py", "CASES", "NEEDS")
    check("difftest4 declares NEEDS", "NEEDS" in d)
    for k in d.get("NEEDS", {}):
        check("difftest4 NEEDS[%r] is a real case" % k, k in d["CASES"])


def t_lsargtest_fs_order_names_real_cases():
    d = literals("lsargtest.py", "CASES", "FS_ORDER")
    check("lsargtest declares FS_ORDER", "FS_ORDER" in d)
    for k in d.get("FS_ORDER", set()):
        check("lsargtest FS_ORDER %r is a real case" % k, k in d["CASES"])
    # ...and every one of them is actually an unsorted listing, or it does
    # not need the exemption and should be diffed strictly.
    for k in d.get("FS_ORDER", set()):
        check("lsargtest FS_ORDER %r really uses -U" % k, "-U" in k)


def t_texttest_shape_names_real_cases():
    tt = load("texttest.py")
    names = {c[0] for c in tt.CASES}
    check("texttest declares SHAPE", hasattr(tt, "SHAPE"))
    for k in getattr(tt, "SHAPE", {}):
        check("texttest SHAPE %r is a real case" % k, k in names)


# -- the normalisers do what they claim ------------------------------------

def t_pid_shape_collapses_host_pids_only():
    tt = load("texttest.py")
    f = getattr(tt, "_pid_shape", None)
    if f is None:
        check("texttest has _pid_shape", False, "absent")
        return
    eq("a booted host and a container agree after shaping",
       f("PID\n1\n2\n"), f("PID\n1\n9\n"))
    eq("the header survives", f("PID\n1\n"), "PID\n<pid>\n")
    # It must not flatten everything: a missing header or a non-numeric
    # second field is a real difference and has to stay visible.
    check("a missing header is still a difference",
          f("PID\n1\n2\n") != f("1\n2\n"))
    check("a non-numeric field is still a difference",
          f("PID\n1\n2\n") != f("PID\n1\nbash\n"))


def t_unordered_ignores_order_and_nothing_else():
    ls = load("lsargtest.py")
    f = getattr(ls, "unordered", None)
    if f is None:
        check("lsargtest has unordered", False, "absent")
        return
    eq("two readdir orders of one directory agree",
       f("d1:\na\nb\nc"), f("d1:\nc\na\nb"))
    check("a missing entry is still a difference",
          f("d1:\na\nb\nc") != f("d1:\na\nb"))
    check("a renamed entry is still a difference",
          f("d1:\na\nb\nc") != f("d1:\na\nb\nz"))


# -- crypt(3) is reachable without the stdlib module ----------------------

# A real yescrypt hash of "123456", generated by libxcrypt. Fixed here so the
# check does not merely confirm the implementation agrees with itself.
YESCRYPT = ("$y$j9T$LdVLIu9Yk8gTZ0nEuGKlS0$"
            "8OYlLnw0vU6wXnh.zs0JqsmHWN7sazHicl5.ymZt718")


def t_crypt_still_works_with_the_module_gone():
    """Setting sys.modules['crypt'] = None makes `import crypt` raise, which
    is exactly what py3.13 does -- so this runs the 3.13 path on any host."""
    sh = load("shadowtest.py")
    loader = getattr(sh, "_load_crypt", None)
    if loader is None:
        check("shadowtest has _load_crypt", False,
              "still relying on the stdlib crypt module")
        return
    sentinel = object()
    saved = sys.modules.get("crypt", sentinel)
    sys.modules["crypt"] = None
    try:
        fn = loader()
        check("a crypt(3) is found with the stdlib module blocked",
              fn is not None, "no libcrypt either")
        if fn is None:
            return
        eq("the right password verifies", fn("123456", YESCRYPT), YESCRYPT)
        check("the wrong password does not",
              fn("hunter2", YESCRYPT) != YESCRYPT)
    finally:
        if saved is sentinel:
            sys.modules.pop("crypt", None)
        else:
            sys.modules["crypt"] = saved


def t_shadowtest_verifies_rather_than_skipping_here():
    """The whole point of the change: on this host, whatever its Python, the
    hash checks must actually run."""
    r = subprocess.run([sys.executable, "-W", "ignore", "shadowtest.py"],
                       cwd=HERE, capture_output=True, text=True, timeout=300)
    tail = (r.stdout or "").strip().splitlines()[-1:] or [""]
    check("shadowtest passes here", r.returncode == 0, tail[0])
    check("shadowtest did not skip the hash checks",
          "crypt" not in r.stdout, tail[0])


# -- two runners must not race ------------------------------------------

# This repo calls its runner runall.sh; the published fork calls it
# run-suites.sh. Either is the gate, and the requirement is the same for both,
# so find whichever is here rather than pinning the private name.
RUNNERS = ("runall.sh", "run-suites.sh")


def _runner():
    for n in RUNNERS:
        p = os.path.join(HERE, n)
        if os.path.exists(p):
            return p
    return None


def t_the_gate_runner_is_tracked_and_locks():
    p = _runner()
    check("a suite runner is in the repo", p is not None,
          "the gate deciding what ships was a file in /tmp")
    if p is None:
        return
    check("%s is executable" % os.path.basename(p), os.access(p, os.X_OK))
    src = open(p, encoding="utf-8").read()
    check("%s takes a lock" % os.path.basename(p), "flock" in src)


def t_a_second_runner_refuses():
    """Behavioural, not textual: hold the lock and confirm it bails out."""
    p = _runner()
    if p is None:
        check("a second runner refuses", False, "no runner to test")
        return
    src = open(p, encoding="utf-8").read()
    lock = "/tmp/honeypot-suites.lock"
    for ln in src.splitlines():
        if ln.startswith("LOCK="):
            lock = ln.split("=", 1)[1].strip()
            break
    holder = subprocess.Popen(
        ["flock", lock, "-c", "sleep 20"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # Give flock a moment to actually acquire it.
        for _ in range(50):
            r = subprocess.run([p], capture_output=True, text=True, timeout=60)
            if r.returncode == 2:
                break
            if holder.poll() is not None:
                break
        check("a second runner exits 2 rather than corrupting the first",
              r.returncode == 2, "rc=%s out=%r" % (r.returncode,
                                                   (r.stderr or "")[:80]))
    finally:
        holder.kill()
        holder.wait()


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            fn()
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
