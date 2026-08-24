#!/usr/bin/env python3
"""Can an attacker actually replace the system binaries, and do we parse
the script that tries?

Thirtieth coherence sweep, and the fourth taken straight from a captured
payload rather than a chosen axis. On 2026-08-22 at 07:17, 203.0.113.33
logged in with no prior failures and ran srb.sh, an SRBMiner installer
whose first act is anti-forensics: delete 26 monitoring tools, replace
each with a "Command disabled" stub, chmod 111 it, chattr +i it, hold the
packages that would reinstall them, then chattr -R +i /bin /usr/bin /sbin
/usr/sbin.

Reading what the box did with it turned up five faults, and the loop
achieved nothing at all:

  * `"$(dirname "$t")"` -- nested double quotes inside a command
    substitution. The quoted-body scanner stopped at the first bare '"',
    so the string ended early, $t expanded loose and a literal ")" was
    left behind. dirname ran with no operand and the caller received
    "/usr/bin/top)". The intel digest showed the damage plainly: sudo
    calls logged as `rm -f `, `chmod 111 `, `chattr +i ` with empty
    arguments and `mkdir -p )`. That idiom appears in nearly every
    installer; this one also ends with `rm -f "$(realpath "$0")"`.
  * Overwriting a stock binary reported success and changed nothing. A
    stock binary's bytes are synthesised from (name, size) on read, and
    that took precedence over the content written, so
    `echo stub > /usr/bin/top` left the size at 174080 and still read
    back as the original ELF.
  * /bin/ps and /usr/bin/ps were two separate nodes with two different
    inodes, even though /bin is a symlink to usr/bin. `ls -i` disagreed
    with itself about one file, and `rm -f /bin/ps` deleted one of the
    pair and left the other, so the binary reappeared the moment anything
    resolved the other spelling. Every anti-forensics script starts with
    /bin/ps.
  * With the two spellings aliased, `find / -perm -4000` then listed
    /bin/mount *and* /usr/bin/mount, because find was descending the
    symlink. find is -P by default and treats a symlink as a leaf even
    when it is named on the command line -- on the guest, `find /bin`
    prints exactly one line.
  * -P/-H/-L were parsed as predicates, so find's documented way to
    follow a symlink died with "unknown predicate `/bin'".

Reference figures measured on the guest, as root:

    ls -ld /bin                  -> lrwxrwxrwx ... /bin -> usr/bin
    find /bin | wc -l            -> 1
    find -L /bin | wc -l         -> 581
    find / -perm -4000 -type f   -> /usr/bin/{chfn,chsh,gpasswd,mount,
                                    newgrp,passwd,su,sudo,umount} and two
                                    under /usr/lib -- no /bin/* at all

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
        print("  FAIL %-54s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# -- nested quotes in a command substitution -----------------------------

def t_nested_quotes_in_command_substitution():
    s = sh()
    run(s, "t=/usr/bin/top")
    eq("dirname keeps its operand",
       run(s, 'echo "$(dirname "$t")"')[0].strip(), "/usr/bin")
    eq("basename keeps its operand",
       run(s, 'echo "$(basename "$t")"')[0].strip(), "top")
    eq("no stray paren leaks out",
       run(s, 'echo "[$(basename "$t")]"')[0].strip(), "[top]")


def t_substitution_nests_more_than_once():
    s = sh()
    eq("two deep", run(s, 'echo "$(echo "$(echo deep)")"')[0].strip(), "deep")
    eq("a plain one still works",
       run(s, 'echo "[$(echo hi)]"')[0].strip(), "[hi]")


def t_the_installers_own_loop_runs():
    """The exact shape srb.sh uses to walk its kill-list."""
    s = sh()
    out, _ = run(s, '''TOOLS=("/usr/bin/top" "/usr/bin/pkill")
for tool in "${TOOLS[@]}"; do
  mkdir -p "$(dirname "$tool")"
  echo disabled > "$tool"
  chmod 111 "$tool"
done''')
    check("the loop reports no errors", "missing operand" not in out, out[:150])
    for t in ("/usr/bin/top", "/usr/bin/pkill"):
        eq("%s was replaced" % t, run(s, "cat %s" % t)[0].strip(), "disabled")
        eq("%s is mode 111" % t,
           run(s, "stat -c %%a %s" % t)[0].strip(), "111")


def t_realpath_of_dollar_zero():
    s = sh()
    eq("the script deletes itself by realpath",
       run(s, 'set -- x; f=/tmp/srb.sh; echo "$(realpath "$f")"')[0].strip(),
       "/tmp/srb.sh")


# -- replacing a stock binary --------------------------------------------

def t_overwriting_a_stock_binary_takes():
    s = sh()
    before = run(s, "stat -c %s /usr/bin/top")[0].strip()
    check("it starts out ELF-sized", int(before) > 1000, before)
    run(s, "echo disabled > /usr/bin/top")
    eq("the content is what was written",
       run(s, "cat /usr/bin/top")[0].strip(), "disabled")
    eq("and the size followed it",
       run(s, "stat -c %s /usr/bin/top")[0].strip(), "9")


def t_a_replaced_binary_is_visible_by_either_name():
    s = sh()
    run(s, "echo disabled > /usr/bin/top")
    eq("through /bin too", run(s, "cat /bin/top")[0].strip(), "disabled")


# -- one file, one identity ----------------------------------------------

def t_bin_and_usr_bin_are_the_same_file():
    s = sh()
    for name in ("bash", "cat", "ls", "kill"):
        a = run(s, "ls -i /bin/%s" % name)[0].split()[0]
        b = run(s, "ls -i /usr/bin/%s" % name)[0].split()[0]
        eq("%s has one inode" % name, a, b)
        sa = run(s, "stat -c %%s /bin/%s" % name)[0].strip()
        sb = run(s, "stat -c %%s /usr/bin/%s" % name)[0].strip()
        eq("%s has one size" % name, sa, sb)


def t_deleting_through_either_name_removes_the_file():
    s = sh()
    _out, rc = run(s, "rm -f /bin/ps")
    eq("rm through the symlink succeeds", rc, 0)
    check("gone by the /bin name", "No such file" in
          run(s, "ls /bin/ps")[0], run(s, "ls /bin/ps")[0])
    check("gone by the /usr/bin name too", "No such file" in
          run(s, "ls /usr/bin/ps")[0], run(s, "ls /usr/bin/ps")[0])
    check("and which no longer finds it",
          run(s, "which ps")[0].strip() == "", run(s, "which ps")[0])


def t_a_hard_link_is_not_a_symlink_twin():
    """The twin rule must not take hard links with it."""
    s = sh()
    run(s, "cd /tmp; touch a; ln a b; echo x > a")
    out, _ = run(s, "cd /tmp; rm a; cat b; stat -c %h b")
    eq("the other name survives with the content", out.split(), ["x", "1"])


# -- find and the merged-/usr symlinks -----------------------------------

def t_find_does_not_descend_a_symlink():
    s = sh()
    eq("find /bin prints only the link",
       run(s, "find /bin")[0].split(), ["/bin"])
    eq("so does find -P /bin",
       run(s, "find -P /bin")[0].split(), ["/bin"])


def t_find_L_follows():
    s = sh()
    n = len(run(s, "find -L /bin")[0].split())
    check("find -L descends into it", n > 10, "got %d entries" % n)
    run(s, "mkdir -p /tmp/z; touch /tmp/z/q")
    eq("and still works on an ordinary directory",
       sorted(run(s, "find -L /tmp/z")[0].split()), ["/tmp/z", "/tmp/z/q"])


def t_the_setuid_set_has_no_duplicates():
    """What a privesc script collects first."""
    s = sh()
    got = run(s, "find / -perm -4000 -type f 2>/dev/null")[0].split()
    eq("no path appears twice", len(got), len(set(got)))
    names = sorted(os.path.basename(x) for x in got)
    eq("no basename appears twice", len(names), len(set(names)))
    check("nothing is reported under /bin",
          not [g for g in got if g.startswith("/bin/")], got)
    for want in ("/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount"):
        check("%s is still there" % want, want in got, got)


def t_ordinary_walking_is_unaffected():
    s = sh()
    run(s, "mkdir -p /tmp/t1/t2; touch /tmp/t1/f /tmp/t1/t2/g")
    eq("a normal tree still walks",
       sorted(run(s, "find /tmp/t1")[0].split()),
       ["/tmp/t1", "/tmp/t1/f", "/tmp/t1/t2", "/tmp/t1/t2/g"])
    eq("and ls of a symlinked dir still lists it",
       run(s, "ls /bin")[0].split()[:2], run(s, "ls /usr/bin")[0].split()[:2])


def t_metadata_ops_resolve_the_symlink_too():
    """Found by running this sweep's own loop against the live guest:
    `stat -c %a /bin/ps` answered 644 while `chmod 111 /bin/ps` said
    "cannot access". chown resolved a symlinked parent; chmod, chattr and
    lsattr looked the path up literally."""
    s = sh()
    run(s, "rm -f /bin/ps; echo stub > /bin/ps")
    eq("stat sees it", run(s, "stat -c %a /bin/ps")[0].strip(), "644")
    _out, rc = run(s, "chmod 111 /bin/ps")
    eq("chmod succeeds", rc, 0)
    eq("and both spellings show it",
       run(s, "stat -c %a /bin/ps")[0].strip(),
       run(s, "stat -c %a /usr/bin/ps")[0].strip())
    eq("chattr works through the link",
       run(s, "chattr +i /bin/ps")[1], 0)
    check("lsattr shows it", "i" in
          run(s, "lsattr /bin/ps")[0].split()[0],
          run(s, "lsattr /bin/ps")[0])
    _o, rc = run(s, "rm -f /usr/bin/ps")
    eq("and the lock holds from the other name", rc, 1)
    out, rc = run(s, "chmod 755 /nope/x")
    check("a genuinely missing path still errors",
          rc == 1 and "No such file" in out, out)


TESTS = [t_metadata_ops_resolve_the_symlink_too,
         t_nested_quotes_in_command_substitution,
         t_substitution_nests_more_than_once,
         t_the_installers_own_loop_runs, t_realpath_of_dollar_zero,
         t_overwriting_a_stock_binary_takes,
         t_a_replaced_binary_is_visible_by_either_name,
         t_bin_and_usr_bin_are_the_same_file,
         t_deleting_through_either_name_removes_the_file,
         t_a_hard_link_is_not_a_symlink_twin,
         t_find_does_not_descend_a_symlink, t_find_L_follows,
         t_the_setuid_set_has_no_duplicates,
         t_ordinary_walking_is_unaffected]


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
