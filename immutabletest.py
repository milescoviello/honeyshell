#!/usr/bin/env python3
"""chattr said the file was locked -- did every writer believe it?

Sweep 140. `lsattr` reported a file immutable while `chmod`, `chown`, `touch`,
`truncate` and `ln` changed it anyway: two commands answering one question two
different ways, on the precise flag an anti-forensics loader sets and then
verifies.

This is not hypothetical here. On 2026-08-24 at 07:49, 203.0.113.33 ran an
SRBMiner installer that did exactly this to seven process tools --

    rm -f /bin/ps ; tee /bin/ps ; chmod 111 /bin/ps ; chattr +i /bin/ps

repeated for /usr/bin/top, /usr/bin/htop, /bin/kill, /usr/bin/kill,
/usr/bin/pkill and /usr/bin/killall -- and finished with

    chattr -R +i /bin /usr/bin /sbin /usr/sbin

whose entire purpose is that nothing can be added to those directories
afterwards. Without the parent-directory check that was decorative: the files
it had just locked could not be replaced, but a new file could be dropped
beside them. Earlier, 203.0.113.24 ran `chattr -ia ~/.ssh/authorized_keys`
before writing its key, which is a loader clearing a flag it expects to be
enforced.

Every expectation below was measured on the real Debian 13 guest as root, in
/tmp, against a file with `----i----------------- f`. All eight file
operations and all three directory operations return "Operation not permitted"
with rc 1, root included -- +i locks the inode, not just its contents.

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


def shell(where="/tmp/imm"):
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    s.run("rm -rf %s; mkdir -p %s" % (where, where))
    s.cwd = where
    del s._err[:]
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    del s._err[:]
    return s.last_rc, err.strip(), out


# Exactly what the guest printed, for each operation on a +i file.
FILE_OPS = [
    ("chmod 755 f",     "chmod: changing permissions of 'f': "
                        "Operation not permitted"),
    ("chown nobody f",  "chown: changing ownership of 'f': "
                        "Operation not permitted"),
    ("chgrp nogroup f", "chgrp: changing group of 'f': "
                        "Operation not permitted"),
    ("touch f",         "touch: cannot touch 'f': Operation not permitted"),
    ("truncate -s 0 f", "truncate: cannot open 'f' for writing: "
                        "Operation not permitted"),
    ("ln f hard",       "ln: failed to create hard link 'hard' => 'f': "
                        "Operation not permitted"),
    ("rm -f f",         "rm: cannot remove 'f': Operation not permitted"),
    ("mv f g",          "mv: cannot move 'f' to 'g': Operation not permitted"),
]


def t_every_writer_refuses_an_immutable_file():
    for cmd, want in FILE_OPS:
        s = shell()
        run(s, "echo original > f")
        run(s, "chattr +i f")
        rc, err, _ = run(s, cmd)
        check("+i refuses: %s" % cmd, rc != 0, "rc=%s" % rc)
        check("+i wording: %s" % cmd, err == want, "got %r" % err[:70])


def t_the_content_actually_survives():
    """rc is not the point on its own -- the bytes have to still be there."""
    s = shell()
    run(s, "echo original > f")
    run(s, "chattr +i f")
    for cmd in ("echo clobbered > f", "truncate -s 0 f", "rm -f f"):
        run(s, cmd)
    _, _, out = run(s, "cat f")
    check("the protected bytes are unchanged", out == "original\n",
          "got %r" % out[:40])


def t_lsattr_and_the_writers_agree():
    """The coherence question. Whatever lsattr says must be what happens."""
    s = shell()
    run(s, "echo x > f")
    for state, expect_locked in (("+i", True), ("-i", False)):
        run(s, "chattr %s f" % state)
        _, _, ls = run(s, "lsattr f")
        says_locked = "i" in ls.split()[0] if ls.split() else False
        rc, _, _ = run(s, "chmod 700 f")
        check("lsattr %s and chmod agree" % state,
              says_locked == expect_locked and (rc != 0) == expect_locked,
              "lsattr=%r chmod rc=%s" % (ls[:24], rc))


def t_an_ordinary_file_is_not_caught_by_this():
    """Over-blocking would be a worse bug than under-blocking: it would break
    every attacker who never touched chattr at all."""
    s = shell()
    run(s, "echo x > plain")
    for cmd in ("chmod 755 plain", "chown nobody plain", "touch plain",
                "truncate -s 2 plain", "ln plain h2", "echo y > plain",
                "mv plain moved", "rm -f moved"):
        rc, err, _ = run(s, cmd)
        check("unlocked file allows: %s" % cmd, rc == 0,
              "rc=%s %s" % (rc, err[:50]))


def t_unlocking_restores_every_operation():
    s = shell()
    run(s, "echo x > f")
    run(s, "chattr +i f")
    locked, _, _ = run(s, "chmod 700 f")
    run(s, "chattr -i f")
    freed, _, _ = run(s, "chmod 700 f")
    check("chmod is refused while +i", locked != 0)
    check("chmod works again after -i", freed == 0)
    _, _, mode = run(s, "stat -c %a f")
    check("and the mode really changed", mode.strip() == "700", mode[:20])


DIR_OPS = [
    ("touch d/new",     "touch: cannot touch 'd/new': "
                        "Operation not permitted"),
    ("rm -rf d",        "rm: cannot remove 'd': Operation not permitted"),
    ("mv d d2",         "mv: cannot move 'd' to 'd2': "
                        "Operation not permitted"),
]


def t_an_immutable_directory_refuses_new_names():
    """`chattr -R +i /bin /usr/bin /sbin /usr/sbin` is the last line of the
    installer, and this is the half of it that did nothing."""
    for cmd, want in DIR_OPS:
        s = shell()
        run(s, "mkdir -p d")
        run(s, "chattr +i d")
        rc, err, _ = run(s, cmd)
        check("+i dir refuses: %s" % cmd, rc != 0, "rc=%s" % rc)
        check("+i dir wording: %s" % cmd, err == want, "got %r" % err[:70])


def t_a_redirect_into_a_locked_directory_fails():
    s = shell()
    run(s, "mkdir -p d")
    run(s, "chattr +i d")
    rc, _, _ = run(s, "echo z > d/new")
    check("a redirect cannot create in a +i directory", rc != 0, "rc=%s" % rc)
    _, _, listing = run(s, "ls d")
    check("and nothing appeared", listing.strip() == "", "%r" % listing[:30])


def t_append_only_still_behaves():
    """+a is the neighbouring flag and must not have been broken by this."""
    s = shell()
    run(s, "echo base > a.log")
    run(s, "chattr +a a.log")
    rc_app, _, _ = run(s, "echo more >> a.log")
    rc_clob, _, _ = run(s, "echo clobber > a.log")
    rc_rm, _, _ = run(s, "rm -f a.log")
    check("+a allows an append", rc_app == 0, "rc=%s" % rc_app)
    check("+a refuses a clobber", rc_clob != 0)
    check("+a refuses unlink", rc_rm != 0)
    # ...but +a must NOT block metadata: the kernel allows chmod on an
    # append-only file, and blocking it would be over-reach.
    rc_chmod, _, _ = run(s, "chmod 640 a.log")
    check("+a still allows chmod", rc_chmod == 0, "rc=%s" % rc_chmod)


def t_the_installer_sequence_end_to_end():
    """Replay what 203.0.113.33 actually ran and check the box behaves the
    way its own lsattr claims."""
    s = shell()
    run(s, "mkdir -p bin")
    run(s, "echo realps > bin/ps")
    for cmd in ("rm -f bin/ps", "echo fakeps > bin/ps",
                "chmod 111 bin/ps", "chattr +i bin/ps"):
        run(s, cmd)
    _, _, mode = run(s, "stat -c %a bin/ps")
    check("the replacement has the mode it was given", mode.strip() == "111",
          mode[:12])
    _, _, ls = run(s, "lsattr bin/ps")
    check("and lsattr reports it immutable", "i" in ls.split()[0] if ls.split()
          else False, ls[:30])
    # A defender's first two moves, both of which must fail.
    rc1, _, _ = run(s, "chmod 755 bin/ps")
    rc2, _, _ = run(s, "rm -f bin/ps")
    check("a defender cannot chmod it back", rc1 != 0)
    check("a defender cannot delete it", rc2 != 0)
    # And the recursive lock stops a second stage dropping a new file.
    run(s, "chattr -R +i bin")
    rc3, _, _ = run(s, "touch bin/newtool")
    check("nothing new can be created beside it", rc3 != 0, "rc=%s" % rc3)


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            try:
                fn()
            except Exception as exc:                          # noqa: BLE001
                check(name, False, "crashed: %r" % (exc,))
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:12]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
