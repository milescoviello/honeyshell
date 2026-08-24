#!/usr/bin/env python3
"""Do the commands that follow a symlink agree about where it goes?

Thirty-first coherence sweep. The axis is symlink semantics, chosen partly
because it is untouched and partly as a follow-up: the previous sweep
changed symlink resolution in remove(), chmod, chattr and find, and that
machinery deserved to be pinned down properly rather than left where those
fixes happened to leave it.

The ordinary cases were already right -- ls -l shows the arrow, readlink
gives the raw target, readlink -f and realpath canonicalise, stat and
stat -L differ correctly, find -type l finds links and -type f does not,
rm of a link leaves the target, and a dangling link is -L true and -e
false. What was not right was every path where resolution *fails*:

  * resolve() gave up after twelve hops and returned the last link it
    stood on, with no way for a caller to know. Every consumer then read
    "gave up" as "here is the answer". `cat loop` printed nothing and
    exited 0. `[ -e loop ]` said yes. `readlink -f loop` printed
    /tmp/sy/loopb and exited 0. `realpath loop` did the same. `stat -L
    loop` reported "symbolic link" and exited 0, which is also what plain
    stat says -- so -L and no -L gave the same answer, the one thing -L
    exists to change.
  * `cp link copy` took the *link's* 0777 mode instead of the target's, so
    the copy landed at 755 where a real cp gives 644. cp follows the link
    for its bytes and has to follow it for the mode too.
  * -P/-d were not implemented at all, so `cp -P link copy` produced a
    regular file -- precisely what the flag exists to prevent.

Everything hangs off one flag: resolve() now records that it hit the hop
limit, and the consumers ask.

Reference measured on the guest, as root, with
loopa -> loopb -> loopa:

    cat loopa          cat: loopa: Too many levels of symbolic links   rc=1
    readlink -f loopa  (no output)                                     rc=1
    realpath loopa     realpath: loopa: Too many levels of ...         rc=1
    ls -l loopa        lrwxrwxrwx ...                                  rc=0
    stat -c %F loopa   symbolic link                                   rc=0
    stat -L -c %F      stat: cannot statx 'loopa': Too many levels ... rc=1
    [ -e loopa ]       false
    realpath dangling  /nowhere                                        rc=0
    cp link c1         c1 is a regular file holding "real", mode 644
    cp -P link c2      c2 is a symlink to target
    rm link            target survives

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

SETUP = ("umask 022; mkdir -p /tmp/sy; cd /tmp/sy; echo real > target; "
         "ln -s target link; ln -s /nowhere dangling; "
         "ln -s loopa loopb; ln -s loopb loopa")


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    s.run(SETUP)
    s._err.clear()
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


# -- a link that works ---------------------------------------------------

def t_a_working_link_reads_through():
    s = sh()
    eq("cat follows it", run(s, "cat /tmp/sy/link")[0].strip(), "real")
    eq("readlink gives the raw target",
       run(s, "readlink /tmp/sy/link")[0].strip(), "target")
    eq("readlink -f canonicalises",
       run(s, "readlink -f /tmp/sy/link")[0].strip(), "/tmp/sy/target")
    eq("realpath agrees with readlink -f",
       run(s, "realpath /tmp/sy/link")[0].strip(),
       run(s, "readlink -f /tmp/sy/link")[0].strip())
    check("ls -l shows the arrow",
          "-> target" in run(s, "ls -l /tmp/sy/link")[0],
          run(s, "ls -l /tmp/sy/link")[0])


def t_stat_and_stat_L_differ():
    s = sh()
    eq("stat reports the link",
       run(s, "stat -c %F /tmp/sy/link")[0].strip(), "symbolic link")
    eq("stat -L reports the target",
       run(s, "stat -L -c %F /tmp/sy/link")[0].strip(), "regular file")


def t_test_predicates_on_a_working_link():
    s = sh()
    for flag, want in (("-L", "yes"), ("-e", "yes"), ("-f", "yes")):
        eq("[ %s link ]" % flag,
           run(s, "[ %s /tmp/sy/link ] && echo yes || echo no"
               % flag)[0].strip(), want)


def t_find_classifies_links():
    s = sh()
    links = sorted(run(s, "find /tmp/sy -type l")[0].split())
    eq("find -type l lists every link", links,
       ["/tmp/sy/dangling", "/tmp/sy/link", "/tmp/sy/loopa",
        "/tmp/sy/loopb"])
    eq("find -type f lists only the real file",
       run(s, "find /tmp/sy -type f")[0].split(), ["/tmp/sy/target"])


def t_removing_a_link_leaves_the_target():
    s = sh()
    _o, rc = run(s, "rm /tmp/sy/link")
    eq("rm of the link succeeds", rc, 0)
    eq("the target is still there",
       run(s, "cat /tmp/sy/target")[0].strip(), "real")
    check("and the link is gone", not s.fs.exists("/tmp/sy/link"))


# -- a link that points nowhere ------------------------------------------

def t_dangling():
    s = sh()
    eq("[ -L dangling ]",
       run(s, "[ -L /tmp/sy/dangling ] && echo yes || echo no")[0].strip(),
       "yes")
    eq("[ -e dangling ]",
       run(s, "[ -e /tmp/sy/dangling ] && echo yes || echo no")[0].strip(),
       "no")
    out, rc = run(s, "cat /tmp/sy/dangling")
    check("cat says ENOENT, not ELOOP",
          "No such file" in out and "symbolic links" not in out, out)
    eq("and exits 1", rc, 1)
    eq("realpath still prints the last component",
       run(s, "realpath /tmp/sy/dangling")[0].strip(), "/nowhere")


# -- a link that never terminates ----------------------------------------

def t_cat_reports_eloop():
    """It printed nothing and exited 0."""
    s = sh()
    out, rc = run(s, "cat /tmp/sy/loopa")
    check("cat says Too many levels", "Too many levels of symbolic links"
          in out, out)
    eq("cat exits 1", rc, 1)


def t_readlink_f_refuses_a_loop():
    s = sh()
    out, rc = run(s, "readlink -f /tmp/sy/loopa")
    eq("prints nothing", out.strip(), "")
    eq("exits 1", rc, 1)


def t_realpath_refuses_a_loop():
    s = sh()
    out, rc = run(s, "realpath /tmp/sy/loopa")
    check("says Too many levels",
          "Too many levels of symbolic links" in out, out)
    eq("exits 1", rc, 1)


def t_stat_L_refuses_a_loop_and_plain_stat_does_not():
    """-L and no -L must not give the same answer here."""
    s = sh()
    plain, prc = run(s, "stat -c %F /tmp/sy/loopa")
    eq("plain stat still describes the link", plain.strip(), "symbolic link")
    eq("and succeeds", prc, 0)
    out, rc = run(s, "stat -L -c %F /tmp/sy/loopa")
    check("stat -L says cannot statx",
          "cannot statx" in out and "Too many levels" in out, out)
    eq("stat -L exits 1", rc, 1)


def t_test_e_is_false_for_a_loop():
    s = sh()
    eq("[ -e loop ]",
       run(s, "[ -e /tmp/sy/loopa ] && echo yes || echo no")[0].strip(), "no")
    eq("[ -f loop ]",
       run(s, "[ -f /tmp/sy/loopa ] && echo yes || echo no")[0].strip(), "no")
    eq("but [ -L loop ] is true",
       run(s, "[ -L /tmp/sy/loopa ] && echo yes || echo no")[0].strip(),
       "yes")


def t_a_loop_does_not_poison_later_lookups():
    """The flag is per-resolve; a loop must not make the next call fail."""
    s = sh()
    run(s, "cat /tmp/sy/loopa")
    eq("a good path still reads",
       run(s, "cat /tmp/sy/link")[0].strip(), "real")
    eq("and still resolves",
       run(s, "readlink -f /tmp/sy/link")[1], 0)


# -- copying links -------------------------------------------------------

def t_cp_follows_the_link_for_bytes_and_mode():
    s = sh()
    run(s, "cd /tmp/sy && cp link c1")
    eq("the copy holds the target's bytes",
       run(s, "cat /tmp/sy/c1")[0].strip(), "real")
    eq("and the target's mode, not the link's",
       run(s, "stat -c %a /tmp/sy/c1")[0].strip(), "644")
    eq("and it is a regular file",
       run(s, "stat -c %F /tmp/sy/c1")[0].strip(), "regular file")


def t_cp_P_keeps_the_link():
    s = sh()
    for flag in ("-P", "-d"):
        run(s, "cd /tmp/sy && cp %s link c_%s" % (flag, flag.strip("-")))
        p = "/tmp/sy/c_%s" % flag.strip("-")
        eq("cp %s makes a symlink" % flag,
           run(s, "stat -c %%F %s" % p)[0].strip(), "symbolic link")
        eq("pointing at the same place" ,
           run(s, "readlink %s" % p)[0].strip(), "target")


def t_cp_of_an_ordinary_file_is_unchanged():
    s = sh()
    run(s, "cd /tmp/sy && cp target c9; cp /bin/bash c8")
    eq("a plain copy is 644", run(s, "stat -c %a /tmp/sy/c9")[0].strip(),
       "644")
    eq("an executable copy is 755",
       run(s, "stat -c %a /tmp/sy/c8")[0].strip(), "755")


TESTS = [t_a_working_link_reads_through, t_stat_and_stat_L_differ,
         t_test_predicates_on_a_working_link, t_find_classifies_links,
         t_removing_a_link_leaves_the_target, t_dangling,
         t_cat_reports_eloop, t_readlink_f_refuses_a_loop,
         t_realpath_refuses_a_loop,
         t_stat_L_refuses_a_loop_and_plain_stat_does_not,
         t_test_e_is_false_for_a_loop,
         t_a_loop_does_not_poison_later_lookups,
         t_cp_follows_the_link_for_bytes_and_mode, t_cp_P_keeps_the_link,
         t_cp_of_an_ordinary_file_is_unchanged]


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
