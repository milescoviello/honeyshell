#!/usr/bin/env python3
"""Do ext2 file attributes actually do anything, or only print?

Twenty-seventh coherence sweep. The axis is chattr/lsattr, picked because
both RedTail staging scripts open the same way:

    chattr -ia ~/.ssh/authorized_keys
    ... write the key ...
    chattr +ai ~/.ssh/authorized_keys

That is a loader clearing a flag it expects to be there, doing its work,
then locking the file so nobody else can undo it. A box where the flag is
decoration answers every step with success and none of the consequences.

What one pass found:

  * `lsattr` reported the flag and `chattr` accepted it, but only *writes*
    honoured it. `chattr +i key; rm key` deleted the file -- the single
    operation immutability exists to prevent. Same for `mv`: renaming a
    +i file out of the way succeeded, which is the obvious way round a
    flag that only guards overwrites.
  * +a (append-only) was worse than cosmetic. `>>` and `>` behaved
    identically, so `echo x > /var/log/wtmp` on an append-only log
    truncated it and exited 0. On a real box that is EPERM and the bytes
    survive -- the entire point of the attribute.
  * When a write did fail, every redirect site said "No such file or
    directory". A loader that has just run `chattr +i` on its own key and
    then tests it reads ENOENT as "my key never landed" -- the opposite
    of the truth -- where EPERM confirms the lock took.

Expectations here are hard-coded rather than diffed against local bash,
which is deliberate: chattr +i needs CAP_LINUX_IMMUTABLE, so a suite run
as an ordinary user on the dev host measures "Operation not permitted"
from chattr itself and calls the emulator correct for the wrong reason.
Every string below was measured on the guest, as root, on ext4:

    write while +i : bash: imm.txt: Operation not permitted
    rm    while +i : rm: cannot remove 'imm.txt': Operation not permitted
    mv    while +i : mv: cannot move 'imm.txt' to 'imm2.txt': Operation not permitted
    append while +a: (allowed)
    trunc  while +a: bash: ao.txt: Operation not permitted, content survives
    rm    while +a : rm: cannot remove 'ao.txt': Operation not permitted

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def has(name, got, want):
    check(name, want in got, "want %r in %r" % (want, got))


# -- the attribute is visible ------------------------------------------------

def t_lsattr_shows_what_chattr_set():
    s = sh()
    run(s, "echo x > /tmp/f")
    out, _ = run(s, "lsattr /tmp/f")
    check("lsattr clean before", "i" not in out.split()[0], out)
    run(s, "chattr +i /tmp/f")
    out, _ = run(s, "lsattr /tmp/f")
    check("lsattr shows i after +i", "i" in out.split()[0], out)
    run(s, "chattr -i /tmp/f")
    out, _ = run(s, "lsattr /tmp/f")
    check("lsattr clean after -i", "i" not in out.split()[0], out)


def t_combined_flags_round_trip():
    s = sh()
    run(s, "echo x > /tmp/f; chattr +ai /tmp/f")
    out, _ = run(s, "lsattr /tmp/f")
    f = out.split()[0]
    check("+ai sets both", "a" in f and "i" in f, out)
    run(s, "chattr -ia /tmp/f")
    out, _ = run(s, "lsattr /tmp/f")
    f = out.split()[0]
    check("-ia clears both", "a" not in f and "i" not in f, out)


# -- immutable: every mutating path must refuse ------------------------------

def t_immutable_refuses_write():
    s = sh()
    run(s, "echo original > /tmp/f; chattr +i /tmp/f")
    out, rc = run(s, "echo clobber > /tmp/f")
    check("write to +i fails", rc == 1, "rc=%d" % rc)
    has("write to +i says EPERM", out, "Operation not permitted")
    body, _ = run(s, "cat /tmp/f")
    eq("write to +i left content", body.strip(), "original")


def t_immutable_refuses_append():
    s = sh()
    run(s, "echo original > /tmp/f; chattr +i /tmp/f")
    out, rc = run(s, "echo more >> /tmp/f")
    check("append to +i fails", rc == 1, "rc=%d" % rc)
    has("append to +i says EPERM", out, "Operation not permitted")
    body, _ = run(s, "cat /tmp/f")
    eq("append to +i left content", body.strip(), "original")


def t_immutable_refuses_rm():
    s = sh()
    run(s, "echo original > /tmp/f; chattr +i /tmp/f")
    out, rc = run(s, "rm /tmp/f")
    check("rm of +i fails", rc == 1, "rc=%d" % rc)
    eq("rm of +i wording", out.strip(),
       "rm: cannot remove '/tmp/f': Operation not permitted")
    check("rm of +i left the file", s.fs.exists("/tmp/f"))


def t_immutable_refuses_rm_dash_f():
    """-f suppresses "no such file", not EPERM."""
    s = sh()
    run(s, "echo original > /tmp/f; chattr +i /tmp/f")
    out, rc = run(s, "rm -f /tmp/f")
    check("rm -f of +i still fails", rc == 1, "rc=%d" % rc)
    has("rm -f of +i says EPERM", out, "Operation not permitted")
    check("rm -f of +i left the file", s.fs.exists("/tmp/f"))
    out, rc = run(s, "rm -f /tmp/never-existed")
    eq("rm -f of a missing file is quiet", (out.strip(), rc), ("", 0))


def t_immutable_refuses_mv():
    s = sh()
    run(s, "echo original > /tmp/f; chattr +i /tmp/f")
    out, rc = run(s, "mv /tmp/f /tmp/g")
    check("mv of +i fails", rc == 1, "rc=%d" % rc)
    eq("mv of +i wording", out.strip(),
       "mv: cannot move '/tmp/f' to '/tmp/g': Operation not permitted")
    check("mv of +i left the source", s.fs.exists("/tmp/f"))
    check("mv of +i made no target", not s.fs.exists("/tmp/g"))


def t_clearing_i_restores_everything():
    """The RedTail sequence depends on -i actually giving the file back."""
    s = sh()
    run(s, "echo original > /tmp/f; chattr +i /tmp/f; chattr -i /tmp/f")
    _, rc = run(s, "echo new > /tmp/f")
    eq("write after -i works", rc, 0)
    body, _ = run(s, "cat /tmp/f")
    eq("write after -i took effect", body.strip(), "new")
    _, rc = run(s, "rm /tmp/f")
    eq("rm after -i works", rc, 0)
    check("rm after -i removed it", not s.fs.exists("/tmp/f"))


# -- append-only: appends pass, everything else refuses ----------------------

def t_append_only_allows_append():
    s = sh()
    run(s, "echo base > /tmp/l; chattr +a /tmp/l")
    _, rc = run(s, "echo more >> /tmp/l")
    eq("append to +a works", rc, 0)
    body, _ = run(s, "cat /tmp/l")
    eq("append to +a appended", body.split(), ["base", "more"])


def t_append_only_refuses_truncation():
    s = sh()
    run(s, "echo base > /tmp/l; chattr +a /tmp/l")
    out, rc = run(s, "echo clobber > /tmp/l")
    check("truncate of +a fails", rc == 1, "rc=%d" % rc)
    has("truncate of +a says EPERM", out, "Operation not permitted")
    body, _ = run(s, "cat /tmp/l")
    eq("truncate of +a left content", body.strip(), "base")


def t_append_only_refuses_rm_and_mv():
    s = sh()
    run(s, "echo base > /tmp/l; chattr +a /tmp/l")
    out, rc = run(s, "rm /tmp/l")
    check("rm of +a fails", rc == 1, "rc=%d" % rc)
    has("rm of +a says EPERM", out, "Operation not permitted")
    check("rm of +a left the file", s.fs.exists("/tmp/l"))
    out, rc = run(s, "mv /tmp/l /tmp/m")
    check("mv of +a fails", rc == 1, "rc=%d" % rc)
    has("mv of +a says EPERM", out, "Operation not permitted")


# -- the failure must be distinguishable from a missing file -----------------

def t_eperm_is_not_enoent():
    """A loader tests its own lock; the two errnos mean opposite things."""
    s = sh()
    run(s, "echo x > /tmp/f; chattr +i /tmp/f")
    locked, _ = run(s, "echo y > /tmp/f")
    missing, rc = run(s, "echo y > /nope/dir/f")
    has("locked file says EPERM", locked, "Operation not permitted")
    has("missing dir says ENOENT", missing, "No such file or directory")
    check("missing dir does not say EPERM",
          "Operation not permitted" not in missing, missing)
    eq("missing dir still rc=1", rc, 1)


def t_unflagged_files_are_untouched():
    """The guard must not leak onto ordinary files."""
    s = sh()
    run(s, "echo a > /tmp/p")
    _, rc = run(s, "echo b > /tmp/p")
    eq("plain overwrite works", rc, 0)
    body, _ = run(s, "cat /tmp/p")
    eq("plain overwrite took", body.strip(), "b")
    _, rc = run(s, "mv /tmp/p /tmp/q")
    eq("plain mv works", rc, 0)
    check("plain mv moved it",
          s.fs.exists("/tmp/q") and not s.fs.exists("/tmp/p"))
    _, rc = run(s, "rm /tmp/q")
    eq("plain rm works", rc, 0)
    check("plain rm removed it", not s.fs.exists("/tmp/q"))


# -- the actual attacker sequence -------------------------------------------

def t_redtail_authorized_keys_sequence():
    """chattr -ia; write key; chattr +ai -- then the lock must hold."""
    s = sh()
    run(s, "mkdir -p /root/.ssh; echo old > /root/.ssh/authorized_keys")
    run(s, "chattr +i /root/.ssh/authorized_keys")
    _, rc = run(s, "chattr -ia /root/.ssh/authorized_keys")
    eq("chattr -ia succeeds", rc, 0)
    _, rc = run(s, "echo 'ssh-rsa AAAAB3 attacker' > "
                   "/root/.ssh/authorized_keys")
    eq("key write succeeds after -ia", rc, 0)
    body, _ = run(s, "cat /root/.ssh/authorized_keys")
    has("key landed", body, "attacker")
    _, rc = run(s, "chattr +ai /root/.ssh/authorized_keys")
    eq("chattr +ai succeeds", rc, 0)
    out, rc = run(s, "rm -f /root/.ssh/authorized_keys")
    check("locked key survives rm -f", rc == 1 and
          s.fs.exists("/root/.ssh/authorized_keys"), out)
    out, rc = run(s, "echo mine > /root/.ssh/authorized_keys")
    check("locked key survives overwrite", rc == 1, out)
    body, _ = run(s, "cat /root/.ssh/authorized_keys")
    has("locked key still theirs", body, "attacker")


TESTS = [t_lsattr_shows_what_chattr_set, t_combined_flags_round_trip,
         t_immutable_refuses_write, t_immutable_refuses_append,
         t_immutable_refuses_rm, t_immutable_refuses_rm_dash_f,
         t_immutable_refuses_mv, t_clearing_i_restores_everything,
         t_append_only_allows_append, t_append_only_refuses_truncation,
         t_append_only_refuses_rm_and_mv, t_eperm_is_not_enoent,
         t_unflagged_files_are_untouched,
         t_redtail_authorized_keys_sequence]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
