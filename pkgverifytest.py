#!/usr/bin/env python3
"""The package database and the filesystem: does anything reconcile them?

Sweep 141. `dpkg -S /usr/bin/ps` named procps, `dpkg -L procps` listed the
file, `md5sum` handed over a hash -- and `dpkg -V`, the one action that joins
those facts, answered "dpkg: need an action option". Every neighbour worked:
-l, -S, -s, -L, --audit, --get-selections, -W. So the box could tell you
everything about a packaged file except whether it was still the file the
package shipped.

That is the command a defender reaches for after what 203.0.113.33 ran here
on 2026-08-24 at 07:49: seven packaged binaries replaced, each `chmod 111`
then `chattr +i`. It is also what an attacker runs to find out whether a host
is already someone else's.

Measured on the guest, as root:

    clean                 no output, rc 0
    contents replaced     "??5??????   /usr/bin/ps"      rc 0
    file deleted          "missing     /usr/bin/pgrep"   rc 0
    both                  sorted by path                 rc 0
    no package argument   verifies everything            rc 0
    unknown package       "dpkg: package 'x' is not installed"  rc 1

Two details that are easy to get wrong and were measured rather than assumed:
the exit status stays **0** even when tampering is found, so a script gating on
`dpkg -V && echo ok` learns nothing; and dpkg verifies **md5sums only** --
every column but the third is always '?' -- so a chmod on a packaged file
reports clean. Scope here is the binaries a package ships, which is what this
emulator models; it does not verify doc files.

Finding the above turned up a worse bug underneath it. `seed_binaries` runs
from `Shell.__init__`, and `fs_for()` builds a VFS, replays the journal, and
only *then* constructs a Shell -- so at replay time the packaged binaries do
not exist yet, `remove()` bailed out before recording anything, and every
binary the attacker had deleted was seeded back in. `rm -f /usr/bin/pgrep`
survived until the service restarted or the per-IP filesystem was evicted, and
then the file was back. Every anti-forensics script opens by deleting /bin/ps
and friends, and a returning attacker who finds them restored knows exactly
what this is.

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
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


def box():
    v = fs.VFS()
    return v, fs.Shell(v, user="root", peer="198.51.100.7")


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    del s._err[:]
    return s.last_rc, out, err.strip()


def restart(v):
    """What the service does: fresh VFS, replay, then build a Shell.

    Through dump_journal(), not the in-memory list. The two are not the same
    thing -- dump_journal base64-encodes write payloads and load_journal
    decodes them -- and handing the raw list over decodes bytes that were
    never encoded. `b64decode(b"tampered")` is six bytes of plausible-looking
    binary, which is exactly what a corrupted ELF would look like, so the
    mistake reads as a product bug rather than a harness one.
    """
    v2 = fs.VFS()
    v2.load_journal(v.dump_journal())
    return v2, fs.Shell(v2, user="root", peer="198.51.100.7")


# -- dpkg -V is an action at all ------------------------------------------

def t_verify_is_a_recognised_action():
    _, s = box()
    rc, out, err = run(s, "dpkg -V procps")
    check("dpkg -V is an action", "need an action option" not in err, err[:60])
    eq("a pristine package verifies silently", (rc, out), (0, ""))


def t_a_replaced_binary_is_reported():
    _, s = box()
    run(s, "echo tampered > /usr/bin/ps")
    rc, out, _ = run(s, "dpkg -V procps")
    eq("a rewritten binary", out, "??5??????   /usr/bin/ps\n")
    eq("...and the status stays 0", rc, 0)


def t_a_deleted_binary_is_reported_as_missing():
    _, s = box()
    run(s, "rm -f /usr/bin/pgrep")
    rc, out, _ = run(s, "dpkg -V procps")
    eq("a deleted binary", out, "missing     /usr/bin/pgrep\n")
    eq("...and the status stays 0", rc, 0)


def t_both_kinds_sort_by_path():
    _, s = box()
    run(s, "rm -f /usr/bin/pgrep")
    run(s, "echo tampered > /usr/bin/ps")
    _, out, _ = run(s, "dpkg -V procps")
    eq("sorted by path, not by kind", out,
       "missing     /usr/bin/pgrep\n??5??????   /usr/bin/ps\n")
    # Both flag strings pad into the same 12-wide column, so the paths align.
    cols = {ln.index("/") for ln in out.splitlines() if "/" in ln}
    eq("the paths line up in one column", cols, {12})


def t_the_long_form_is_identical():
    _, s = box()
    run(s, "echo tampered > /usr/bin/ps")
    a = run(s, "dpkg -V procps")
    b = run(s, "dpkg --verify procps")
    eq("--verify matches -V", b, a)


def t_an_unknown_package_is_an_error():
    _, s = box()
    rc, out, err = run(s, "dpkg -V nosuchpkg")
    eq("unknown package rc", rc, 1)
    eq("unknown package message", err,
       "dpkg: package 'nosuchpkg' is not installed")
    eq("...and nothing on stdout", out, "")


def t_no_argument_verifies_everything():
    _, s = box()
    run(s, "echo tampered > /usr/bin/ps")
    rc, out, _ = run(s, "dpkg -V")
    check("bare dpkg -V finds it", "/usr/bin/ps" in out, out[:60])
    eq("bare dpkg -V status", rc, 0)


def t_a_mode_change_alone_is_not_tampering():
    """dpkg verifies md5sums only. Reporting a chmod would be over-reach --
    and 203.0.113.33 chmod 111'd every file it replaced, so getting this
    backwards would flag the mode instead of the content."""
    _, s = box()
    run(s, "chmod 700 /usr/bin/top")
    _, out, _ = run(s, "dpkg -V procps")
    eq("chmod alone reports clean", out, "")
    # ...but the mode really did change, so this is not a no-op emulator.
    _, mode, _ = run(s, "stat -c %a /usr/bin/top")
    eq("and the chmod did take effect", mode.strip(), "700")


def t_verify_agrees_with_listfiles_about_paths():
    """-L and -V derive their paths from one rule. Two copies of a rule is
    how two readers end up disagreeing about the same file."""
    _, s = box()
    _, listed, _ = run(s, "dpkg -L procps")
    files = {ln for ln in listed.split() if ln.startswith("/usr/")
             and "/doc/" not in ln}
    run(s, "rm -f /usr/bin/pgrep")
    _, out, _ = run(s, "dpkg -V procps")
    reported = {ln.split()[-1] for ln in out.splitlines()}
    check("every path -V reports was one -L listed",
          reported <= files, "extra: %s" % (reported - files))


# -- the deletion has to survive a restart --------------------------------

def t_a_deleted_binary_stays_deleted_across_a_restart():
    v, s = box()
    run(s, "rm -f /usr/bin/pgrep")
    v2, s2 = restart(v)
    check("the binary is still gone", not v2.exists("/usr/bin/pgrep"),
          "seed_binaries put it back")
    rc, _, _ = run(s2, "command -v pgrep")
    eq("command -v still fails", rc, 1)
    _, _, err = run(s2, "ls /usr/bin/pgrep")
    check("ls still says it is absent", "No such file" in err, err[:60])
    _, out, _ = run(s2, "dpkg -V procps")
    eq("and dpkg -V still says missing", out,
       "missing     /usr/bin/pgrep\n")


def t_a_replaced_binary_stays_replaced_across_a_restart():
    v, s = box()
    run(s, "echo tampered > /usr/bin/ps")
    v2, s2 = restart(v)
    _, out, _ = run(s2, "dpkg -V procps")
    eq("still reported after a restart", out, "??5??????   /usr/bin/ps\n")
    _, body, _ = run(s2, "cat /usr/bin/ps")
    eq("and the attacker's bytes are what is there", body, "tampered\n")


def t_delete_then_recreate_reads_as_modified_not_missing():
    """The exact anti-forensics sequence: rm, then write a wrapper."""
    v, s = box()
    run(s, "rm -f /usr/bin/ps")
    run(s, "echo '#!/bin/sh' > /usr/bin/ps")
    run(s, "chmod 111 /usr/bin/ps")
    _, out, _ = run(s, "dpkg -V procps")
    eq("present but wrong, not missing", out, "??5??????   /usr/bin/ps\n")
    v2, s2 = restart(v)
    _, out2, _ = run(s2, "dpkg -V procps")
    eq("...and the same after a restart", out2,
       "??5??????   /usr/bin/ps\n")
    check("the file exists again after restart",
          v2.exists("/usr/bin/ps"))


def t_an_untouched_box_is_clean_after_a_restart():
    """The other half: the fix must not make a pristine box look tampered."""
    v, _s = box()
    v2, s2 = restart(v)
    _, out, _ = run(s2, "dpkg -V")
    eq("a box nobody touched verifies silently", out, "")
    check("and its binaries are all present", v2.exists("/usr/bin/pgrep")
          and v2.exists("/usr/bin/ps"))


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            try:
                fn()
            except Exception as exc:                          # noqa: BLE001
                check(name, False, "crashed: %r" % (exc,))
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
