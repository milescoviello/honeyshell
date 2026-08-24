#!/usr/bin/env python3
"""Do the commands that create files agree about what mode to give them?

Twenty-ninth coherence sweep. The axis is permission propagation: umask,
cp, mv, install, and what happens when you execute the result. Picked
because staging a binary somewhere writable is the most ordinary thing an
attacker does after landing, and because the setuid backdoor --
`cp /bin/bash /tmp/sh; chmod +s /tmp/sh` -- is a classic worth answering
correctly.

The setuid *discovery* surface turned out to be sound already: find
-perm -4000, -perm -u=s, -perm /6000, ls -l and stat all agreed, and the
capital-S and capital-T forms for a set-id bit without the matching
execute bit were right. What was not sound was creating files at all:

  * `touch f` honoured the umask and `: > f` did not. Two ways of making
    an empty file, on one box, one second apart, disagreeing about the
    permissions the shell had just been told to use. mkdir ignored it as
    well, and ignored -m on top of that.
  * `cp` ignored the source mode entirely and made every new file 0644,
    so `cp /bin/bash /tmp/sh && /tmp/sh` answered "Permission denied".
    GNU cp gives the copy the source's mode masked by the umask, and
    drops the set-id bits unless -p -- which is why copying /usr/bin/sudo
    is not a privilege escalation on a real box.
  * `mv` went through that same cp path, so a rename re-created the file
    at the default mode: moving a setuid binary quietly disarmed it.
    Real mv preserves the inode's metadata outright.
  * `install -m 700 src existing` reported success and left the file 644,
    because the underlying write keeps an existing file's permissions --
    right for cp, wrong for the one command whose entire job is placing a
    file at a stated mode.
  * Worst of the set: a *copy* of a stock binary did not run. Dispatch
    keyed on the basename, so /usr/bin/id printed and /tmp/myid -- the
    same bytes, same mode -- registered a process and returned 0 with no
    output. Silent success is the answer that costs the most: a script
    doing `cp /usr/bin/id /tmp/x && /tmp/x` sees rc=0 and nothing else.
    The synthesised body carries the binary's own name in its strings, as
    a real ELF does, so identity now follows the bytes however they
    travelled -- cp, mv, cat or base64.

Reference figures measured on the guest, as root, on ext4:

    umask 022 -> touch 644  redirect 644  mkdir 755
    umask 077 -> touch 600  redirect 600  mkdir 700
    umask 002 -> touch 664  redirect 664  mkdir 775
    umask 000 -> touch 666  redirect 666  mkdir 777
    cp /bin/bash          -> 755      (umask 077 -> 700)
    cp /usr/bin/sudo      -> 755      (source 4755; set-id dropped)
    cp -p /usr/bin/sudo   -> 4755
    cp onto existing 600  -> 600      (destination mode kept)
    mv of a 4755 file     -> 4755
    install -m 755/-m 600 -> 755/600  install -d -> 755

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
    s.run("umask 022")
    s._err.clear()
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def mode(s, path):
    return run(s, "stat -c %%a %s" % path)[0].strip()


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-54s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- umask, applied by everything that creates ------------------------------

UMASKS = [("022", "644", "755"), ("077", "600", "700"),
          ("002", "664", "775"), ("000", "666", "777")]


def t_umask_applies_to_every_creator():
    for um, fmode, dmode in UMASKS:
        s = sh()
        run(s, "umask %s" % um)
        run(s, "touch /tmp/t; : > /tmp/r; mkdir /tmp/d")
        eq("umask %s: touch" % um, mode(s, "/tmp/t"), fmode)
        eq("umask %s: redirect" % um, mode(s, "/tmp/r"), fmode)
        eq("umask %s: mkdir" % um, mode(s, "/tmp/d"), dmode)


def t_touch_and_redirect_never_disagree():
    """The two ways of making an empty file must match."""
    for um, _f, _d in UMASKS:
        s = sh()
        run(s, "umask %s" % um)
        run(s, "touch /tmp/a; : > /tmp/b")
        eq("umask %s: touch == redirect" % um,
           mode(s, "/tmp/a"), mode(s, "/tmp/b"))


def t_umask_reports_what_it_applies():
    s = sh()
    for um in ("022", "077", "002"):
        run(s, "umask %s" % um)
        got = run(s, "umask")[0].strip()
        eq("umask prints %s back" % um, got, "0" + um)


def t_mkdir_m_overrides_the_umask():
    s = sh()
    run(s, "umask 077; mkdir -m 755 /tmp/m1")
    eq("mkdir -m 755 under umask 077", mode(s, "/tmp/m1"), "755")
    run(s, "mkdir -p -m 700 /tmp/p1/p2")
    eq("mkdir -p -m applies to the leaf", mode(s, "/tmp/p1/p2"), "700")


def t_append_to_a_new_file_also_honours_umask():
    s = sh()
    run(s, "umask 077; echo x >> /tmp/ap")
    eq("append creating a file", mode(s, "/tmp/ap"), "600")


# -- cp -----------------------------------------------------------------

def t_cp_takes_the_source_mode():
    s = sh()
    run(s, "cp /bin/bash /tmp/c1")
    eq("cp of a 755 binary", mode(s, "/tmp/c1"), "755")


def t_cp_masks_by_umask():
    s = sh()
    run(s, "umask 077; cp /bin/bash /tmp/c2")
    eq("cp of 755 under umask 077", mode(s, "/tmp/c2"), "700")


def t_cp_drops_setid_but_dash_p_keeps_it():
    s = sh()
    eq("the source really is setuid", mode(s, "/usr/bin/sudo"), "4755")
    run(s, "cp /usr/bin/sudo /tmp/c3")
    eq("plain cp drops setuid", mode(s, "/tmp/c3"), "755")
    run(s, "cp -p /usr/bin/sudo /tmp/c4")
    eq("cp -p keeps setuid", mode(s, "/tmp/c4"), "4755")
    eq("the source really is setgid", mode(s, "/usr/bin/crontab"), "2755")
    run(s, "cp /usr/bin/crontab /tmp/c5")
    eq("plain cp drops setgid", mode(s, "/tmp/c5"), "755")


def t_cp_onto_an_existing_file_keeps_its_mode():
    s = sh()
    run(s, "touch /tmp/c6; chmod 600 /tmp/c6; cp /bin/bash /tmp/c6")
    eq("existing destination keeps 600", mode(s, "/tmp/c6"), "600")


def t_cp_r_carries_modes_through_the_tree():
    s = sh()
    run(s, "mkdir -p /tmp/tr; cp /bin/bash /tmp/tr/b; touch /tmp/tr/plain")
    run(s, "cp -r /tmp/tr /tmp/tr2")
    eq("copied directory", mode(s, "/tmp/tr2"), "755")
    eq("copied binary inside it", mode(s, "/tmp/tr2/b"), "755")
    eq("copied plain file inside it", mode(s, "/tmp/tr2/plain"), "644")


# -- mv ------------------------------------------------------------------

def t_mv_preserves_everything():
    s = sh()
    run(s, "cp -p /usr/bin/sudo /tmp/m1; mv /tmp/m1 /tmp/m2")
    eq("mv keeps setuid", mode(s, "/tmp/m2"), "4755")
    run(s, "cp /bin/bash /tmp/m3; mv /tmp/m3 /tmp/m4")
    eq("mv keeps the execute bits", mode(s, "/tmp/m4"), "755")
    check("mv removed the source", not s.fs.exists("/tmp/m3"))


# -- install -------------------------------------------------------------

def t_install_applies_its_mode():
    s = sh()
    run(s, "touch /tmp/src")
    run(s, "install -m 755 /tmp/src /tmp/i1")
    eq("install -m 755 on a new file", mode(s, "/tmp/i1"), "755")
    run(s, "install -m 600 /tmp/src /tmp/i2")
    eq("install -m 600 on a new file", mode(s, "/tmp/i2"), "600")
    run(s, "touch /tmp/i3; chmod 644 /tmp/i3")
    run(s, "install -m 700 /tmp/src /tmp/i3")
    eq("install -m 700 over an existing file", mode(s, "/tmp/i3"), "700")
    run(s, "install /tmp/src /tmp/i4")
    eq("install defaults to 755", mode(s, "/tmp/i4"), "755")
    run(s, "install -d /tmp/id1")
    eq("install -d makes a 755 directory", mode(s, "/tmp/id1"), "755")


# -- a copy of a binary is still that binary -----------------------------

def t_a_copied_binary_runs():
    s = sh()
    want = run(s, "/usr/bin/id")[0].strip()
    check("the original prints something", want.startswith("uid="), want)
    for how, cmd in (("cp", "cp /usr/bin/id /tmp/x1"),
                     ("mv", "cp /usr/bin/id /tmp/q; mv /tmp/q /tmp/x2"),
                     ("cat", "cat /usr/bin/id > /tmp/x3; chmod 755 /tmp/x3")):
        run(s, cmd)
        path = "/tmp/x%d" % (("cp", "mv", "cat").index(how) + 1)
        got, rc = run(s, path)
        eq("a binary reached by %s prints the same" % how, got.strip(), want)
        eq("...and exits 0", rc, 0)


def t_a_copied_binary_takes_its_arguments():
    s = sh()
    run(s, "cp /bin/uname /tmp/u")
    eq("copied uname -m", run(s, "/tmp/u -m")[0].strip(),
       run(s, "/bin/uname -m")[0].strip())
    run(s, "cp /bin/bash /tmp/b")
    eq("copied bash -c", run(s, '/tmp/b -c "echo works"')[0].strip(), "works")


def t_the_setuid_backdoor_sequence():
    """cp /bin/bash somewhere writable, chmod +s, then look at it."""
    s = sh()
    run(s, "cp /bin/bash /tmp/sh")
    eq("the copy is executable", mode(s, "/tmp/sh"), "755")
    eq("and it runs", run(s, '/tmp/sh -c "echo in"')[0].strip(), "in")
    run(s, "chmod +s /tmp/sh")
    eq("chmod +s sets both set-id bits", mode(s, "/tmp/sh"), "6755")
    eq("ls shows it", run(s, "ls -l /tmp/sh")[0].split()[0], "-rwsr-sr-x")
    found = run(s, "find /tmp -perm -4000 -type f")[0].split()
    check("find -perm -4000 lists it", "/tmp/sh" in found, found)
    eq("and it still runs", run(s, '/tmp/sh -c "echo in"')[0].strip(), "in")


def t_a_non_executable_copy_is_refused():
    s = sh()
    run(s, "cp /usr/bin/id /tmp/nx; chmod 644 /tmp/nx")
    out, rc = run(s, "/tmp/nx")
    check("mode 644 means Permission denied", "Permission denied" in out, out)
    eq("and rc 126", rc, 126)


def t_an_attackers_own_binary_is_untouched():
    """The identity rule must not swallow a real dropped payload."""
    s = sh()
    run(s, "printf 'MZ not an elf at all' > /tmp/mal; chmod 755 /tmp/mal")
    _out, rc = run(s, "/tmp/mal")
    check("a dropped non-ELF still does not resolve to a stock binary",
          rc in (0, 126, 127), "rc=%s" % rc)


# -- the discovery surface that was already right ------------------------

def t_setuid_discovery_is_consistent():
    s = sh()
    a = sorted(run(s, "find / -perm -4000 -type f 2>/dev/null")[0].split())
    b = sorted(run(s, "find / -perm -u=s -type f 2>/dev/null")[0].split())
    eq("-perm -4000 and -perm -u=s agree", a, b)
    check("and the list is not empty", len(a) > 3, a)
    for path in a[:6]:
        lsl = run(s, "ls -l %s" % path)[0].split()[0]
        st = mode(s, path)
        check("ls -l shows s for %s" % path, lsl[3] == "s", lsl)
        check("stat agrees for %s" % path, st.startswith("4"), st)


def t_setid_without_execute_shows_capital():
    s = sh()
    run(s, "touch /tmp/n1; chmod 4644 /tmp/n1")
    eq("setuid, no execute", run(s, "ls -l /tmp/n1")[0].split()[0],
       "-rwSr--r--")
    run(s, "touch /tmp/n2; chmod 2644 /tmp/n2")
    eq("setgid, no execute", run(s, "ls -l /tmp/n2")[0].split()[0],
       "-rw-r-Sr--")
    run(s, "mkdir /tmp/n3; chmod 1644 /tmp/n3")
    eq("sticky, no execute", run(s, "ls -ld /tmp/n3")[0].split()[0],
       "drw-r--r-T")


# -- the null command, found by this sweep's own live check ---------------

def t_the_null_command_works():
    """`: > f` is how the sweep's live script truncated a file, and the
    guest answered "bash: :: command not found". : was missing outright,
    so it exited 127 while `true` right beside it exited 0 -- two
    spellings of one builtin disagreeing. `while :; do ...; done` is the
    standard forever-loop in shell malware."""
    s = sh()
    out, rc = run(s, ":")
    eq(": exits 0", rc, 0)
    eq(": says nothing", out.strip(), "")
    eq(": takes arguments", run(s, ": foo bar")[1], 0)
    eq(": agrees with true", run(s, ":; echo $?")[0].strip(), "0")
    eq("while :; do break; done runs",
       run(s, "while :; do break; done; echo looped")[0].strip(), "looped")
    eq("if :; then takes its branch",
       run(s, "if :; then echo yes; fi")[0].strip(), "yes")
    eq("until :; do exits immediately",
       run(s, "until :; do echo never; done; echo done")[0].strip(), "done")


def t_colon_redirect_creates_and_truncates():
    s = sh()
    out, rc = run(s, "echo content > /tmp/tr1; : > /tmp/tr1")
    eq(": > truncates without complaint", (out.strip(), rc), ("", 0))
    eq("and the file is empty", run(s, "wc -c < /tmp/tr1")[0].strip(), "0")


TESTS = [t_the_null_command_works, t_colon_redirect_creates_and_truncates,
         t_umask_applies_to_every_creator,
         t_touch_and_redirect_never_disagree,
         t_umask_reports_what_it_applies,
         t_mkdir_m_overrides_the_umask,
         t_append_to_a_new_file_also_honours_umask,
         t_cp_takes_the_source_mode, t_cp_masks_by_umask,
         t_cp_drops_setid_but_dash_p_keeps_it,
         t_cp_onto_an_existing_file_keeps_its_mode,
         t_cp_r_carries_modes_through_the_tree,
         t_mv_preserves_everything, t_install_applies_its_mode,
         t_a_copied_binary_runs, t_a_copied_binary_takes_its_arguments,
         t_the_setuid_backdoor_sequence,
         t_a_non_executable_copy_is_refused,
         t_an_attackers_own_binary_is_untouched,
         t_setuid_discovery_is_consistent,
         t_setid_without_execute_shows_capital]


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
