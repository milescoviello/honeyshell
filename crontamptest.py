#!/usr/bin/env python3
"""A wipe, a gutting and an install all logged as cron_install.

Sweep 145. Every successful write to a scheduled-task file logged
`event="cron_install"`, whatever the write actually did. Measured over the
whole capture history: **every external cron_install this box has ever
recorded was a wipe.** 203.0.113.24 is the only outside address that has
triggered one, three times, and each was its clean.sh stripping crontabs
rather than adding to one. The other seventeen are loopback -- our own
testing, correctly filtered.

That inverts the signal on the highest-priority event class the box has.
cron_install is on the push-notify list and intel.py files it as
`persistence`, so the one actor that fires it is *removing* persistence, not
establishing it.

The discriminator is the line delta, not the content:

    prior lines non-empty, none left      -> cron_cleared
    lines removed and none added          -> cron_stripped
    any line added                        -> cron_install

"Has no schedule line" would not work: /etc/cron.daily/* are shell scripts and
never have one.

Finding this turned up something underneath it. The four /etc/cron.daily
scripts were 17-byte stubs -- a shebang and `set -e` -- for all four names,
which is exactly what a gutted script looks like *after* a cleaner has run. So
clean.sh's strip was a no-op against them and logged `unchanged=True`: the
attacker spent its visit cleaning files that were already empty. They now
carry the guest's real content, byte for byte, and /etc/cron.daily/logrotate
is gone because the guest has no such file -- logrotate runs from a systemd
timer on trixie.

Run from `honeypot/`.
"""

import hashlib
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


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="198.51.100.7")
    del s._err[:]
    seen = []
    s.log = lambda **e: seen.append(e)
    return s, seen


def cron_events(seen):
    return [e.get("event") for e in seen
            if str(e.get("event", "")).startswith("cron")]


def run(s, cmd):
    s.run(cmd)
    del s._err[:]


# -- the three verdicts --------------------------------------------------

def t_emptying_a_file_is_not_an_install():
    s, seen = shell()
    run(s, "printf '' > /etc/cron.daily/man-db")
    eq("emptying reports cron_cleared", cron_events(seen), ["cron_cleared"])


def t_stripping_lines_is_not_an_install():
    """What clean.sh actually does: grep out the lines it dislikes and write
    back the remainder."""
    s, seen = shell()
    run(s, "head -20 /etc/cron.daily/man-db > /tmp/h && "
           "cat /tmp/h > /etc/cron.daily/man-db")
    eq("truncating reports cron_stripped", cron_events(seen),
       ["cron_stripped"])

    s, seen = shell()
    run(s, "printf '#!/bin/sh\\nset -e\\n' > /etc/cron.daily/apt-compat")
    eq("gutting to a stub reports cron_stripped", cron_events(seen),
       ["cron_stripped"])


def t_adding_a_line_is_still_an_install():
    """The alarm must keep working for the thing it was built for."""
    s, seen = shell()
    run(s, "printf '*/5 * * * * root /tmp/x\\n' > /etc/cron.d/evil")
    eq("a new cron.d job reports cron_install", cron_events(seen),
       ["cron_install"])

    s, seen = shell()
    run(s, "printf '17 * * * * root /usr/bin/foo\\n' >> /etc/crontab")
    eq("appending to /etc/crontab reports cron_install", cron_events(seen),
       ["cron_install"])


def t_the_verdict_function_itself():
    f = getattr(fs.Shell, "_cron_verdict", None)
    if f is None:
        check("Shell exposes _cron_verdict", False, "absent")
        return
    fz = frozenset
    eq("cleared", f(fz({"a", "b"}), fz()), "cron_cleared")
    eq("stripped", f(fz({"a", "b"}), fz({"a"})), "cron_stripped")
    eq("install (added)", f(fz({"a"}), fz({"a", "b"})), "cron_install")
    eq("install (new file)", f(fz(), fz({"a"})), "cron_install")
    eq("re-assertion of the same lines", f(fz({"a"}), fz({"a"})),
       "cron_install")
    # A file that was already empty and stays empty is not a wipe.
    eq("empty to empty", f(fz(), fz()), "cron_install")


def t_comments_do_not_count_as_content():
    """A crontab holding only its header comment has been emptied, whatever
    its byte count says."""
    g = getattr(fs.Shell, "_cron_lines", None)
    if g is None:
        check("Shell exposes _cron_lines", False, "absent")
        return
    eq("comments and blanks are dropped",
       g(b"# a comment\n\n   \n# another\n"), frozenset())
    eq("real lines survive", g(b"# c\n*/5 * * * * root /x\n"),
       frozenset({"*/5 * * * * root /x"}))


# -- and the files those verdicts are measured against -------------------

REAL = {
    "/etc/cron.daily/apt-compat": (1478, "1400ab07a4a2905b04c33e3e93d42b7b"),
    "/etc/cron.daily/dpkg":       (123,  "94bb6c1363245e46256908a5d52ba4fb"),
    "/etc/cron.daily/man-db":     (1395, "62423d7fa68568c9c0aefceac182d9ea"),
    "/etc/cron.weekly/man-db":    (1055, "eebc5bb3e1dac973301570da3f453334"),
}


def t_the_cron_scripts_are_the_guests_own():
    """Byte-for-byte, because `cat /etc/cron.daily/*` is a normal move when
    hunting cron persistence and four identical 17-byte files are not what a
    real box looks like."""
    s, _ = shell()
    for path, (size, md5) in sorted(REAL.items()):
        body = s.run("cat " + path)
        del s._err[:]
        raw = body.encode("latin-1", "replace")
        eq("%s size" % path, len(raw), size)
        eq("%s md5" % path, hashlib.md5(raw).hexdigest(), md5)
        mode = s.run("stat -c %%a %s" % path).strip()
        del s._err[:]
        eq("%s is executable" % path, mode, "755")


def t_logrotate_is_absent_because_the_guest_has_none():
    """It runs from a systemd timer on trixie. Seeding a file the real box
    does not have is the same class of tell as omitting one it does."""
    s, _ = shell()
    rc_out = s.run("ls /etc/cron.daily/logrotate")
    err = "".join(s._err)
    del s._err[:]
    check("no /etc/cron.daily/logrotate",
          "No such file" in err or "cannot access" in err,
          "%r / %r" % (rc_out[:40], err[:60]))
    listing = sorted(s.run("ls /etc/cron.daily").split())
    del s._err[:]
    eq("cron.daily holds exactly the guest's three",
       listing, ["apt-compat", "dpkg", "man-db"])


def t_a_stub_would_have_made_the_strip_a_noop():
    """The bug underneath the bug: against 17-byte stubs, clean.sh's strip
    changed nothing, so the write logged unchanged=True and the classifier
    would have had nothing to classify."""
    s, _ = shell()
    body = s.run("cat /etc/cron.daily/man-db")
    del s._err[:]
    check("man-db is not a stub", len(body) > 200, "%d bytes" % len(body))
    check("...and it has real lines to strip",
          len(fs.Shell._cron_lines(body.encode())) > 3,
          "%d lines" % len(fs.Shell._cron_lines(body.encode())))


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            try:
                fn()
            except Exception as exc:                          # noqa: BLE001
                check(name, False, "crashed: %r" % (exc,))
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
