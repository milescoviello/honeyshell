r"""Hard links: the two ways of asking, and only one answered.

Sixty-fourth coherence sweep. linktest covers symlinks -- whether the
commands that follow one agree about where it goes. Nothing had asked the
same question of hard links, where the interesting property is that two
names share one inode and the box has several ways to notice.

Most of it was already right and is pinned rather than changed: `ln`
creates the link, both names report nlink 2 to `ls -l` and to `stat -c
%h`, `ls -i` and `stat -c %i` give them the same inode, writing through
one name is visible through the other, `du` counts the data once,
removing one name decrements the other's link count and leaves the data
readable, and hard-linking a directory is refused with the real message.

Two ways of finding the links were not.

  1. `find -samefile` was not implemented at all -- an unknown predicate,
     which makes find reject the whole expression -- while `-inum`, which
     answers the same question the long way round, worked. -samefile is
     what anyone actually types.

  2. `find -links` stripped the +/- sign and compared for equality, so
     `-links +1`, the ordinary way to ask which files are hard-linked,
     returned exactly the files that are not. `-links -2` returned the
     ones with two. Bare `-links N` was right, and -size next to it
     handled the sign correctly all along.

And a smaller one found on the way: `-samefile` and `-newer` both
returned False for every node when their reference file did not exist,
so a typo in the reference was indistinguishable from "nothing matched".
find reports the missing reference and exits 1.

Reference measured against GNU findutils 4.9.0 at /usr/bin/find. Worth
saying explicitly: bare `find` on the dev host is bfs, not findutils, and
the first pass of this sweep compared against that by accident. bfs
agreed on every case here, but the numbers below are the GNU ones.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

# one.txt: 1 link.  two/two2: 2 links.  three/t3b/t3c: 3 links.
SETUP = ("cd /tmp && rm -rf hl && mkdir hl && cd hl && "
         "echo a > one.txt && echo b > two.txt && ln two.txt two2.txt && "
         "echo c > three.txt && ln three.txt t3b.txt && ln three.txt t3c.txt")


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    s.run(SETUP)
    s._err.clear()
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(s, cmd):
    o = s.run("cd /tmp/hl && " + cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


def names(s, cmd):
    return sorted(x for x in out(s, cmd + " | sort").split() if x)


# -- what was already right ----------------------------------------------

def t_ln_creates_a_second_name():
    s = shell()
    eq("two2 exists", out(s, "test -f two2.txt && echo y"), "y")
    eq("same content", out(s, "cat two2.txt"), "b")


def t_nlink_agrees_between_ls_and_stat():
    s = shell()
    for f, n in (("one.txt", "1"), ("two.txt", "2"), ("two2.txt", "2"),
                 ("three.txt", "3")):
        eq("ls -l nlink %s" % f, out(s, "ls -l %s | awk '{print $2}'" % f), n)
        eq("stat %h " + f, out(s, "stat -c '%h' " + f), n)


def t_the_inode_is_shared():
    s = shell()
    a = out(s, "stat -c '%i' two.txt")
    b = out(s, "stat -c '%i' two2.txt")
    eq("stat agrees", b, a)
    eq("ls -i agrees", out(s, "ls -i two2.txt | awk '{print $1}'"), a)
    check("and differs from an unrelated file",
          out(s, "stat -c '%i' one.txt") != a, a)


def t_writing_through_one_name_shows_in_the_other():
    s = shell()
    out(s, "echo more >> two.txt")
    eq("two2 sees it", out(s, "cat two2.txt"), "b\nmore")


def t_du_counts_the_data_once():
    """du counts an inode once however many names point at it -- that is
    the whole difference between du and the sum of `ls -l`."""
    s = shell()
    one = int(out(s, "du -s . | awk '{print $1}'"))
    out(s, "ln three.txt t3d.txt")
    two = int(out(s, "du -s . | awk '{print $1}'"))
    eq("a new link adds no blocks", two, one)


def t_du_l_counts_every_name():
    s = shell()
    plain = int(out(s, "du -s . | awk '{print $1}'"))
    linked = int(out(s, "du -sl . | awk '{print $1}'"))
    check("-l is larger", linked > plain, "%d vs %d" % (linked, plain))


def t_du_a_lists_one_name_per_inode():
    s = shell()
    listed = [l.split()[-1] for l in out(s, "du -a .").splitlines()
              if l.split()[-1].endswith(".txt")]
    three = [x for x in listed
             if x.endswith(("three.txt", "t3b.txt", "t3c.txt"))]
    eq("one of the three names", len(three), 1)
    check("and the unlinked file is there",
          any(x.endswith("one.txt") for x in listed), str(listed))
    # -l lists them all
    listed_l = [l.split()[-1] for l in out(s, "du -al .").splitlines()
                if l.split()[-1].endswith(".txt")]
    three_l = [x for x in listed_l
               if x.endswith(("three.txt", "t3b.txt", "t3c.txt"))]
    eq("-l lists all three", len(three_l), 3)


def t_removing_one_name_keeps_the_data():
    s = shell()
    out(s, "rm two2.txt")
    eq("nlink back to 1", out(s, "stat -c '%h' two.txt"), "1")
    eq("still readable", out(s, "cat two.txt"), "b")


def t_a_directory_cannot_be_hard_linked():
    s = shell()
    out(s, "mkdir d")
    o = out(s, "ln d d2")
    check("refused", "hard link not allowed for directory" in o, o)
    _o, rc = s.run("cd /tmp/hl && ln d d2"), s.last_rc
    s._err.clear()
    eq("rc 1", rc, 1)


# -- find -samefile -------------------------------------------------------

def t_samefile_finds_every_name():
    s = shell()
    eq("two links", names(s, "find . -samefile two.txt"),
       ["./two.txt", "./two2.txt"])
    eq("three links", names(s, "find . -samefile three.txt"),
       ["./t3b.txt", "./t3c.txt", "./three.txt"])


def t_samefile_on_an_unlinked_file():
    s = shell()
    eq("just itself", names(s, "find . -samefile one.txt"), ["./one.txt"])


def t_samefile_agrees_with_inum():
    """The long way round and the short way must give the same answer."""
    s = shell()
    ino = out(s, "stat -c '%i' three.txt")
    eq("same set", names(s, "find . -samefile three.txt"),
       names(s, "find . -inum %s" % ino))


def t_samefile_is_not_an_unknown_predicate():
    s = shell()
    o = out(s, "find . -samefile two.txt")
    check("no unknown predicate", "unknown predicate" not in o, o[:70])


# -- find -links ----------------------------------------------------------

def t_links_exact():
    s = shell()
    eq("-links 1", names(s, "find . -type f -links 1"), ["./one.txt"])
    eq("-links 2", names(s, "find . -type f -links 2"),
       ["./two.txt", "./two2.txt"])
    eq("-links 3", names(s, "find . -type f -links 3"),
       ["./t3b.txt", "./t3c.txt", "./three.txt"])


def t_links_more_than():
    s = shell()
    eq("-links +1", names(s, "find . -type f -links +1"),
       ["./t3b.txt", "./t3c.txt", "./three.txt", "./two.txt", "./two2.txt"])
    eq("-links +2", names(s, "find . -type f -links +2"),
       ["./t3b.txt", "./t3c.txt", "./three.txt"])
    eq("-links +3", names(s, "find . -type f -links +3"), [])


def t_links_fewer_than():
    s = shell()
    eq("-links -2", names(s, "find . -type f -links -2"), ["./one.txt"])
    eq("-links -3", names(s, "find . -type f -links -3"),
       ["./one.txt", "./two.txt", "./two2.txt"])


def t_plus_one_is_not_the_unlinked_file():
    """The exact inversion this sweep found."""
    s = shell()
    got = names(s, "find . -type f -links +1")
    check("one.txt is not in it", "./one.txt" not in got, str(got))
    check("two.txt is", "./two.txt" in got, str(got))


def t_links_and_size_read_the_sign_the_same_way():
    s = shell()
    small = names(s, "find . -type f -size -1k")
    check("-size -1k matches the small files", len(small) >= 4, str(small))
    eq("-size +1k matches none", names(s, "find . -type f -size +1k"), [])


# -- a missing reference is an error, not an empty result -----------------

def t_samefile_missing_reference():
    s = shell()
    o = out(s, "find . -samefile /nope")
    check("names the file", "/nope" in o, o)
    check("says no such file", "No such file or directory" in o, o)
    _o, rc = s.run("cd /tmp/hl && find . -samefile /nope"), s.last_rc
    s._err.clear()
    eq("rc 1", rc, 1)


def t_newer_missing_reference():
    s = shell()
    o = out(s, "find . -newer /nope")
    check("says no such file", "No such file or directory" in o, o)
    _o, rc = s.run("cd /tmp/hl && find . -newer /nope"), s.last_rc
    s._err.clear()
    eq("rc 1", rc, 1)


def t_the_quoting_matches_a_missing_path_operand():
    """find quotes both the same way; coreutils uses plain apostrophes."""
    s = shell()
    a = out(s, "find . -samefile /nope")
    b = out(s, "find /nope -name x")
    eq("same message", a, b.replace("find /nope", "find ."))
    check("uses GNU's quotes", "‘/nope’" in a, repr(a))


def t_a_present_reference_still_works():
    s = shell()
    o = out(s, "find . -newer one.txt -type f")
    check("no error", "No such file" not in o, o[:70])


TESTS = [t_ln_creates_a_second_name, t_nlink_agrees_between_ls_and_stat,
         t_the_inode_is_shared,
         t_writing_through_one_name_shows_in_the_other,
         t_du_counts_the_data_once, t_du_l_counts_every_name,
         t_du_a_lists_one_name_per_inode,
         t_removing_one_name_keeps_the_data,
         t_a_directory_cannot_be_hard_linked, t_samefile_finds_every_name,
         t_samefile_on_an_unlinked_file, t_samefile_agrees_with_inum,
         t_samefile_is_not_an_unknown_predicate, t_links_exact,
         t_links_more_than, t_links_fewer_than,
         t_plus_one_is_not_the_unlinked_file,
         t_links_and_size_read_the_sign_the_same_way,
         t_samefile_missing_reference, t_newer_missing_reference,
         t_the_quoting_matches_a_missing_path_operand,
         t_a_present_reference_still_works]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
