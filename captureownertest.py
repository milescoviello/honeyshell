#!/usr/bin/env python3
"""A file belongs to whoever created it, whatever path created it.

Found from a live capture. On 2026-08-27 203.0.113.64 logged in as `deploy`,
ran GPU-aware recon (lscpu, two nvidia-smi probes) and curled a 46,578,712
byte UPX/LZMA-packed Go binary to ~/.sysmonitor. The next command was:

    chmod +x ~/.sysmonitor
    chmod: /home/deploy/.sysmonitor: Permission denied

The loader stopped there. The file was in the attacker's own home directory
and they had just created it, which a real box always lets them chmod.

Cause: a large payload is not copied into the per-source filesystem, it is
pointed at the capture store by VFS.link_capture. That method lives on the
VFS, so CredFS.__getattr__ handed it straight through, and the self.write()
inside it was VFS.write rather than CredFS.write -- the one that assigns
ownership. The node kept the default uid 0.

So ownership depended on the size of the file:

    small drop (inlined by write)      deploy deploy    chmod works
    large drop (link_capture)          root   root      chmod denied

`ls -l` showing `root root` on a file the attacker downloaded into their own
home is a tell on its own, before the chmod fails.

The same omission was in symlink(), which had the permission check but not
the uid assignment, so on one box:

    mkdir d      ->  drwxr-xr-x 2 deploy deploy
    ln -s x l    ->  lrwxrwxrwx 1 root   root

Measured on a real Debian 13.6 box, where `ln -s` reports the symlink
as owned by the calling user, not by root.

The structural check below is the real guard: every public VFS method that
creates a node must have a CredFS override, so the next one added cannot
inherit the same silent uid 0.

Usage:  python3 captureownertest.py
"""

import inspect
import os
import sys
import tempfile

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell(user="deploy"):
    return fakeshell.Shell(vfs=fakeshell.VFS(), user=user,
                           peer="198.51.100.23", peer_port=41999)


def run(sh, cmd):
    """(stdout, rc, stderr). Guarded: a suite must survive the broken tree."""
    before = len(getattr(sh, "_err", []) or [])
    try:
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return ("<raised %s: %s>" % (type(exc).__name__, exc), -1, "")
    err = "".join((getattr(sh, "_err", []) or [])[before:])
    return (out, getattr(sh, "last_rc", None), err)


def owner(sh, path):
    """(uid, gid) of a node, or a sentinel rather than an exception."""
    fs = getattr(sh, "fs", None)
    nodes = getattr(fs, "nodes", None)
    if nodes is None:
        return ("<no nodes>", "<no nodes>")
    node = nodes.get(path)
    if node is None and hasattr(fs, "resolve"):
        try:
            node = nodes.get(fs.resolve(path))
        except Exception:                                      # noqa: BLE001
            node = None
    if node is None:
        return ("<missing>", "<missing>")
    return (getattr(node, "uid", "<no uid>"), getattr(node, "gid", "<no gid>"))


def capture(sh, path, size, mode=0o600):
    """link_capture a real temp file, returning True/False or a sentinel."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".cap")
    try:
        tmp.write(b"\x7fELF\x02\x01\x01\x00" + b"A" * 4200)
        tmp.close()
        fs = getattr(sh, "fs", None)
        fn = getattr(fs, "link_capture", None)
        if fn is None:
            return "<no link_capture>"
        try:
            return fn(path, tmp.name, size, prefix=b"\x7fELF\x02\x01\x01\x00",
                      mode=mode)
        except Exception as exc:                               # noqa: BLE001
            return "<raised %s: %s>" % (type(exc).__name__, exc)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


BIG = 46578712          # the size 203.0.113.64 actually downloaded

# ------------------------------------------------ the capture the box lost
sh = shell()
uid = getattr(getattr(sh, "fs", None), "uid", None)
check("the session is not root to begin with", uid, 1000,
      "the whole finding is about a non-root attacker; if this changed, "
      "the rest of the suite is not testing what it says")

ok = capture(sh, "/home/deploy/.sysmonitor", BIG)
check("a large payload is captured", ok, True)
check("...and it belongs to the user who downloaded it",
      owner(sh, "/home/deploy/.sysmonitor"), (1000, 1000),
      "came back (0, 0): link_capture bypassed CredFS.write, so the node "
      "kept the default root ownership")

out, rc, err = run(sh, "chmod +x ~/.sysmonitor")
check("chmod on it exits 0", rc, 0,
      "this is the command 203.0.113.64's loader died on")
check("...and prints no error", err, "",
      "live box said: chmod: /home/deploy/.sysmonitor: Permission denied")

listing, _, _ = run(sh, "ls -l /home/deploy/.sysmonitor")
fields = listing.split()
check("...and ls -l does not show it as root's",
      fields[2:4] if len(fields) > 3 else listing, ["deploy", "deploy"],
      "a downloaded file owned by root in your own home is a tell on its "
      "own, before anything is executed")
check("...and it still reports the full captured size",
      fields[4] if len(fields) > 4 else listing, str(BIG),
      "ownership must not have cost the link_capture size behaviour")

# -------------------------------- size must not decide ownership either way
sh2 = shell()
run(sh2, "mkdir -p /home/deploy/w")
small_ok = getattr(sh2.fs, "write")(b"/home/deploy/w/small".decode(),
                                    b"\x7fELF" + b"B" * 200, mode=0o600)
check("a small payload is written", bool(small_ok), True)
capture(sh2, "/home/deploy/w/large", BIG)
check("small and large drops agree about ownership",
      owner(sh2, "/home/deploy/w/small"), owner(sh2, "/home/deploy/w/large"),
      "the size of a file decided who owned it")

# ------------------------------------------- every creating path, one rule
sh3 = shell()
run(sh3, "mkdir -p /home/deploy/all/dir")
run(sh3, "ln -s /etc/passwd /home/deploy/all/link")
run(sh3, "echo x > /home/deploy/all/file")
capture(sh3, "/home/deploy/all/cap", BIG)
made = {}
for label, path in (("mkdir", "/home/deploy/all/dir"),
                    ("ln -s", "/home/deploy/all/link"),
                    ("redirect", "/home/deploy/all/file"),
                    ("capture", "/home/deploy/all/cap")):
    made[label] = owner(sh3, path)
    check("%s gives the file to the caller" % label, made[label], (1000, 1000))
check("all four creating paths agree", len(set(made.values())), 1,
      "got %r -- two ways of making a file on one box, two owners" % (made,))

link_ls, _, _ = run(sh3, "ls -l /home/deploy/all/link")
lf = link_ls.split()
check("ls -l on the symlink shows the user, not root",
      lf[2:4] if len(lf) > 3 else link_ls, ["deploy", "deploy"],
      "a real box gives the symlink to the caller, not to root")

# ---------------------------------------------------- root is still root
shr = shell(user="root")
capture(shr, "/root/.sysmonitor", BIG)
check("a root session's capture is root's",
      owner(shr, "/root/.sysmonitor"), (0, 0),
      "the fix must assign the session's uid, not unconditionally 1000")

# ------------------------------------- an existing file does not change hands
sh4 = shell()
run(sh4, "mkdir -p /home/deploy/x")
capture(sh4, "/home/deploy/x/f", BIG)
fs4 = getattr(sh4, "fs", None)
if hasattr(fs4, "chown"):
    try:
        getattr(fs4, "_fs", fs4).chown("/home/deploy/x/f", 33, 33)
    except Exception:                                          # noqa: BLE001
        pass
capture(sh4, "/home/deploy/x/f", BIG)
check("re-capturing over an existing file does not reassign it",
      owner(sh4, "/home/deploy/x/f"), (33, 33),
      "writing to a file you do not own does not make it yours on a real "
      "box, and write() already models that")

# ------------------------------------ the permission check is still enforced
sh5 = shell()
res = capture(sh5, "/root/nope/deep", BIG)
check("a capture into a directory the user cannot write is refused",
      isinstance(res, str) and "PermissionDenied" in res
      or res is False, True,
      "got %r -- adding ownership must not have dropped the access check"
      % (res,))

# ------------------------------------------------------ the standing invariant
# Every public VFS method that creates a node needs a CredFS override, or it
# inherits VFS.write and silently produces root-owned files. Counted, so a
# new one cannot be added without this failing.
SEEDING = {"load_journal", "seed_binaries", "sync_cgroups", "sync_proc"}
creators, unguarded = [], []
vfs_cls = getattr(fakeshell, "VFS", None)
cred_cls = getattr(fakeshell, "CredFS", None)
if vfs_cls is None or cred_cls is None:
    FAILS.append("FAIL fakeshell has no VFS/CredFS to inspect")
    CHECKS.append(False)
else:
    for name, fn in sorted(vars(vfs_cls).items()):
        if name.startswith("_") or not callable(fn) or name in SEEDING:
            continue
        try:
            body = inspect.getsource(fn)
        except (OSError, TypeError):
            continue
        if "FileNode(" in body or "self.write(" in body:
            creators.append(name)
            if name not in vars(cred_cls):
                unguarded.append(name)
    check("every public node-creating VFS method is overridden in CredFS",
          unguarded, [],
          "%r create nodes but CredFS does not override them, so "
          "__getattr__ sends them to the uncredentialed filesystem and "
          "whatever they make comes out owned by root" % (unguarded,))
    check("...and there are still exactly four of them", len(creators), 4,
          "found %r. A new creating method must be given a CredFS override "
          "and added here deliberately -- this count is the only thing that "
          "notices one appearing." % (creators,))

for f in FAILS:
    print(" ", f)
print("   captureowner: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
