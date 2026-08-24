#!/usr/bin/env python3
"""How many names does this file have, and what inode is behind them?

Four commands answer that -- `ls -i`, `ls -l`'s second column, `stat`, and
find's -inum/-links/-printf -- and they were reading a filesystem that gave
impossible answers to all four.

    stat -c %i /usr/sbin/init      0
    ls -i /usr/sbin/init           0 /usr/sbin/init

No filesystem hands out inode 0, and 949 of the 6379 nodes on this box had
it. The baseline walks the tree once and numbers everything; seed_binaries
runs later, from the Shell, and created those 949 without numbering any of
them -- so every binary it made shared one inode with every other, which
is a filesystem saying they are all the same file. Inodes are allocated on
demand now, so a file created at runtime gets one too.

    stat -c %h /usr/bin/bash       2
    ls -l /usr/bin/bash            -rwxr-xr-x 2 root root ...

/bin, /sbin, /lib and /lib64 are symlinks into /usr on a merged-/usr
Debian, so a binary reachable by both spellings still has exactly one
directory entry. Both keys are bound to one node here, which is what makes
`ls -i /bin/bash` and `ls -i /usr/bin/bash` agree -- and it also made the
name count come out 2 for 28 files in /usr/bin, where the guest reports 1.

And two more from the same walk:

  * `stat -c %h /` said 18 with fifteen subdirectories, because the root's
    prefix is "/" and it matched its own test: it counted itself as one of
    its own children. Every other directory satisfied 2 + subdirs.
  * /etc/nginx/sites-enabled/default was a second name for the file in
    sites-available -- same inode, two links, mode -rw-r--r--. Debian
    enables a site by symlinking it, and `ls -l sites-enabled/` shows an
    l-mode entry.
  * `find -printf "%i"` printed the two characters back at the caller,
    and so did %n and every %T date field. One of the two ways to ask a
    filesystem for an inode did not know the question.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


S = sh()


def R(cmd, s=None):
    t = s or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


# ---------------------------------------------------------------------------
# Every file has an inode, and it is its own
# ---------------------------------------------------------------------------
def t_no_file_has_inode_zero():
    inos = [int(x) for x in R("find / -xdev -printf '%i\\n'")[0].split()
            if x.isdigit()]
    check("find -printf %i produced numbers", len(inos) > 1000, str(len(inos)))
    check("none of them is zero", 0 not in inos,
          "%d zeros" % inos.count(0))
    check("the lowest is a plausible inode", min(inos) > 1, str(min(inos)))
    # The binaries seeded after the baseline are the ones that had none.
    for p in ("/usr/sbin/init", "/usr/bin/bash", "/usr/bin/systemctl",
              "/usr/sbin/nginx", "/usr/bin/python3"):
        got = R("stat -c %%i %s" % p)[0].strip()
        check("%s has a real inode" % p, got.isdigit() and int(got) > 0, got)


def t_inodes_are_not_shared_by_accident():
    """Two files with one inode are one file. Only real links may repeat."""
    pairs = R("find / -xdev -type f -printf '%i %p\\n'")[0].splitlines()
    byino = {}
    for line in pairs:
        f = line.split(None, 1)
        if len(f) == 2 and f[0].isdigit():
            byino.setdefault(f[0], []).append(f[1])
    shared = {k: v for k, v in byino.items() if len(v) > 1}
    check("find walked the tree", len(byino) > 1000, str(len(byino)))
    # A merged-/usr twin is one file under two spellings, which is the only
    # legitimate repeat here.
    bad = {k: v for k, v in shared.items()
           if not all(os.path.basename(x) == os.path.basename(v[0])
                      for x in v)}
    check("no two unrelated files share an inode", not bad,
          str(list(bad.items())[:2]))


def t_the_three_readers_agree_about_one_file():
    for p in ("/etc/passwd", "/usr/bin/bash", "/usr/sbin/init"):
        st = R("stat -c '%%i %%h' %s" % p)[0].split()
        lsi = R("ls -i %s" % p)[0].split()
        pf = R("find %s -printf '%%i %%n\\n'" % p)[0].split()
        check("%s: ls -i is stat's inode" % p, lsi[:1] == st[:1],
              "%s vs %s" % (lsi[:1], st[:1]))
        check("%s: find -printf %%i is stat's inode" % p, pf[:1] == st[:1],
              "%s vs %s" % (pf[:1], st[:1]))
        check("%s: find -printf %%n is stat's link count" % p,
              pf[1:2] == st[1:2], "%s vs %s" % (pf[1:2], st[1:2]))
        lsl = R("ls -l %s" % p)[0].split()
        check("%s: ls -l's second column is the link count" % p,
              lsl[1:2] == st[1:2], "%s vs %s" % (lsl[1:2], st[1:2]))
        # ...and -inum finds it by that number.
        found = R("find / -xdev -inum %s -not -type l 2>/dev/null" % st[0])[0]
        check("%s: find -inum finds it again" % p, p in found.split(),
              found[:70])


# ---------------------------------------------------------------------------
# Merged /usr: one entry, two spellings
# ---------------------------------------------------------------------------
def t_merged_usr_twins_have_one_link():
    check("/bin is a symlink into /usr",
          R("readlink /bin")[0].strip() == "usr/bin",
          R("readlink /bin")[0].strip())
    for d in ("/sbin", "/lib"):
        check("%s is a symlink too" % d,
              R("readlink %s" % d)[0].strip().startswith("usr/"),
              R("readlink %s" % d)[0].strip())
    for b in ("bash", "cat", "ls", "mount", "cp"):
        u, l = "/usr/bin/" + b, "/bin/" + b
        check("%s exists under both spellings" % b,
              R("test -e %s" % l)[2] == 0 and R("test -e %s" % u)[2] == 0,
              "missing")
        iu = R("stat -c %%i %s" % u)[0].strip()
        il = R("stat -c %%i %s" % l)[0].strip()
        check("%s: both spellings are one inode" % b, iu == il,
              "%s vs %s" % (iu, il))
        nu = R("stat -c %%h %s" % u)[0].strip()
        check("%s: and one directory entry" % b, nu == "1", nu)
    check("nothing in /usr/bin claims two links",
          R("find /usr/bin -maxdepth 1 -type f -links 2")[0].strip() == "",
          R("find /usr/bin -maxdepth 1 -type f -links 2")[0][:60])
    check("nothing on the whole filesystem does either",
          R("find / -xdev -type f -links 2 2>/dev/null")[0].strip() == "",
          R("find / -xdev -type f -links 2 2>/dev/null")[0][:70])


# ---------------------------------------------------------------------------
# Directories count their children
# ---------------------------------------------------------------------------
def t_directory_link_counts_are_two_plus_subdirs():
    dirs = ["/", "/etc", "/usr", "/var", "/root", "/tmp", "/home", "/opt",
            "/usr/bin", "/usr/share", "/etc/nginx", "/var/log", "/usr/lib"]
    for d in dirs:
        nl = R("stat -c %%h %s" % d)[0].strip()
        subs = R("find %s -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l"
                 % d)[0].strip()
        if not (nl.isdigit() and subs.isdigit()):
            check("%s: both numbers read" % d, False, "%r %r" % (nl, subs))
            continue
        check("%s: nlink is 2 plus its subdirectories" % d,
              int(nl) == int(subs) + 2,
              "nlink %s, subdirs %s" % (nl, subs))
    # The root's own symlinked children do not count towards it.
    links = R("find / -maxdepth 1 -mindepth 1 -type l 2>/dev/null")[0].split()
    check("/bin, /lib, /lib64 and /sbin are those symlinks",
          sorted(links) == ["/bin", "/lib", "/lib64", "/sbin"], str(links))


# ---------------------------------------------------------------------------
# nginx enables a site the way Debian does
# ---------------------------------------------------------------------------
def t_the_enabled_site_is_a_symlink():
    out = R("ls -l /etc/nginx/sites-enabled/")[0]
    check("sites-enabled/default is an l-mode entry",
          re.search(r"^l.* default -> \.\./sites-available/default$", out,
                    re.M), out[:80])
    check("stat calls it a symbolic link",
          R("stat -c %F /etc/nginx/sites-enabled/default")[0].strip()
          == "symbolic link",
          R("stat -c %F /etc/nginx/sites-enabled/default")[0].strip())
    check("readlink gives the relative target",
          R("readlink /etc/nginx/sites-enabled/default")[0].strip()
          == "../sites-available/default",
          R("readlink /etc/nginx/sites-enabled/default")[0].strip())
    a = R("stat -c %i /etc/nginx/sites-available/default")[0].strip()
    b = R("stat -Lc %i /etc/nginx/sites-enabled/default")[0].strip()
    check("following it lands on the same inode", a == b, "%s vs %s" % (a, b))
    check("but the link itself has its own",
          R("stat -c %i /etc/nginx/sites-enabled/default")[0].strip() != a,
          "same as target")
    check("and the file has one link, not two",
          R("stat -c %h /etc/nginx/sites-available/default")[0].strip()
          == "1", R("stat -c %h /etc/nginx/sites-available/default")[0])
    check("reading through the link still gives the config",
          "server {" in R("head -1 /etc/nginx/sites-enabled/default")[0],
          R("head -1 /etc/nginx/sites-enabled/default")[0][:40])
    # nginx.conf includes that directory, so the link has to be reachable.
    check("nginx.conf includes sites-enabled",
          "sites-enabled" in R("cat /etc/nginx/nginx.conf")[0],
          "not included")


# ---------------------------------------------------------------------------
# find -printf speaks stat's language
# ---------------------------------------------------------------------------
def t_find_printf_knows_the_same_fields():
    # find spells the owner's *name* %u and the number %U; stat is the
    # other way round. Comparing them needs the pairs crossed over.
    st = R("stat -c '%i %h %s %U %G %a' /etc/passwd")[0].split()
    pf = R("find /etc/passwd -printf '%i %n %s %u %g %m'")[0].split()
    check("find -printf and stat agree field for field", pf == st,
          "%s vs %s" % (pf, st))
    stn = R("stat -c '%u %g' /etc/passwd")[0].split()
    pfn = R("find /etc/passwd -printf '%U %G'")[0].split()
    check("and on the numeric ids the other way round", pfn == stn,
          "%s vs %s" % (pfn, stn))
    d = R("find /etc/passwd -printf '%TY-%Tm-%Td %TH:%TM:%TS'")[0].strip()
    sd = R("date -d @$(stat -c %Y /etc/passwd) '+%Y-%m-%d %H:%M'")[0].strip()
    check("the %T fields are the mtime date returns",
          d.startswith(sd), "%r vs %r" % (d, sd))
    check("no unexpanded specifier is left behind", "%" not in d, d)
    check("%T@ is the raw mtime",
          R("find /etc/passwd -printf '%T@'")[0].split(".")[0]
          == R("stat -c %Y /etc/passwd")[0].strip(),
          R("find /etc/passwd -printf '%T@'")[0][:20])
    check("%y says f for a file and d for a directory",
          R("find /etc/passwd -printf '%y'")[0] == "f"
          and R("find /etc -maxdepth 0 -printf '%y'")[0] == "d",
          "%r %r" % (R("find /etc/passwd -printf '%y'")[0],
                     R("find /etc -maxdepth 0 -printf '%y'")[0]))


# ---------------------------------------------------------------------------
# ...and a file made now behaves like the rest
# ---------------------------------------------------------------------------
def t_a_new_file_gets_an_inode_of_its_own():
    s = sh()
    R("echo hello > /tmp/newfile", s)
    got = R("stat -c '%i %h' /tmp/newfile", s)[0].split()
    check("a file created in the session has an inode",
          got and got[0].isdigit() and int(got[0]) > 0, str(got))
    check("and exactly one link", got[1:2] == ["1"], str(got))
    check("ls -i agrees", R("ls -i /tmp/newfile", s)[0].split()[:1] == got[:1],
          R("ls -i /tmp/newfile", s)[0][:40])
    other = R("stat -c %i /etc/passwd", s)[0].strip()
    check("and it is not some other file's inode", got[0] != other,
          "%s == %s" % (got[0], other))
    R("ln /tmp/newfile /tmp/newlink", s)
    both = R("stat -c '%i %h' /tmp/newfile /tmp/newlink", s)[0].split()
    if len(both) == 4:
        check("a hard link shares the inode", both[0] == both[2],
              "%s vs %s" % (both[0], both[2]))
        check("and both report two links",
              both[1] == both[3] == "2", "%s %s" % (both[1], both[3]))


TESTS = [t_no_file_has_inode_zero,
         t_inodes_are_not_shared_by_accident,
         t_the_three_readers_agree_about_one_file,
         t_merged_usr_twins_have_one_link,
         t_directory_link_counts_are_two_plus_subdirs,
         t_the_enabled_site_is_a_symlink,
         t_find_printf_knows_the_same_fields,
         t_a_new_file_gets_an_inode_of_its_own]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
