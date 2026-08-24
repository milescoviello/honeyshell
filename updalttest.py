#!/usr/bin/env python3
"""Which program is this name, and does everything that names it agree?

`editor`, `awk`, `pager`, `php` and `mysql` are not programs on a Debian
box -- they are alternatives, and four things describe each one: the
symlink in /etc/alternatives, the administrative file in
/var/lib/dpkg/alternatives, what `update-alternatives` reports, and
whatever picks the program at run time.

/var/lib/dpkg/alternatives was an empty directory while --display, --query
and --get-selections all answered in full. The tool and the state it is
supposed to be reading described different boxes, and `ls
/var/lib/dpkg/alternatives` is how you spot a group someone has
redirected. The admin files are written from the same table the tool
answers from now, in the format the guest uses.

    cat /root/.selected_editor    SELECTED_EDITOR="/usr/bin/vim.basic"
    ls /usr/bin/vim.basic         No such file or directory
    readlink -f /usr/bin/editor   /usr/bin/nano

Three answers to "what is the editor", one of them naming a binary the box
does not have.

And man-db: the box behaved as though it were installed everywhere except
in dpkg. man-db.timer in list-timers, /etc/cron.daily/man-db,
/var/cache/man owned by man:man, and apt printing "Processing triggers for
man-db (2.13.1-1)" after every install -- while `dpkg -l man-db` said no
such package and `man` was command not found. It is installed now, at the
version apt was already quoting. /usr/share/man is still absent, and
/etc/dpkg/dpkg.cfg.d/excludes is why -- which is how every minimal Debian
image is built, and which makes `man ls` answer "No manual entry for ls"
with rc 16 rather than nothing at all.

Messages and exit codes measured on the guest.
"""

import os
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


S = fs.Shell(fs.VFS())
S.exec_mode = True


def R(cmd, s=None):
    t = s or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


def groups():
    return [l.split()[0] for l in
            R("update-alternatives --get-selections")[0].splitlines()
            if l.split()]


# ---------------------------------------------------------------------------
# the tool and the files it reads
# ---------------------------------------------------------------------------
def t_every_group_has_an_admin_file():
    names = groups()
    check("get-selections lists groups", len(names) >= 5, str(names))
    have = set(R("ls /var/lib/dpkg/alternatives/")[0].split())
    check("every group has an administrative file",
          set(names) <= have, str(sorted(set(names) - have)))
    check("and there are no files for groups the tool denies",
          have <= set(names), str(sorted(have - set(names))))


def t_the_admin_file_says_what_the_tool_says():
    for name in groups():
        body = R("cat /var/lib/dpkg/alternatives/%s" % name)[0].splitlines()
        check("%s: the file opens with the mode" % name,
              body[:1] == ["auto"], str(body[:1]))
        q = R("update-alternatives --query %s" % name)[0]
        link = [l.split(": ", 1)[1] for l in q.splitlines()
                if l.startswith("Link: ")]
        check("%s: the file's second line is the link --query names" % name,
              body[1:2] == link, "%s vs %s" % (body[1:2], link))
        # The mode the file records is the mode --query reports.
        st = [l.split(": ", 1)[1] for l in q.splitlines()
              if l.startswith("Status: ")]
        check("%s: the mode matches Status" % name, body[:1] == st,
              "%s vs %s" % (body[:1], st))
        # Every alternative path in the file is one the tool lists.
        listed = set(R("update-alternatives --list %s" % name)[0].split())
        infile = {l for l in body if l.startswith("/") and l in listed}
        check("%s: the file's alternatives are the tool's" % name,
              infile == listed, str(sorted(listed - infile)))


def t_the_link_the_file_names_is_the_link_on_disk():
    for name in groups():
        q = R("update-alternatives --query %s" % name)[0]
        link = [l.split(": ", 1)[1] for l in q.splitlines()
                if l.startswith("Link: ")]
        if not link:
            continue
        check("%s: the link exists" % name,
              R("test -L %s" % link[0])[2] == 0, "%s not a symlink" % link[0])
        check("%s: it points into /etc/alternatives" % name,
              R("readlink %s" % link[0])[0].strip()
              == "/etc/alternatives/" + name,
              R("readlink %s" % link[0])[0].strip())
        # ...and /etc/alternatives/<name> points at the chosen alternative.
        chosen = [l.split()[-1] for l in
                  R("update-alternatives --get-selections")[0].splitlines()
                  if l.split()[:1] == [name]]
        check("%s: /etc/alternatives points at the choice" % name,
              R("readlink /etc/alternatives/%s" % name)[0].strip() == chosen[0],
              "%s vs %s" % (R("readlink /etc/alternatives/%s" % name)[0].strip(),
                            chosen))
        check("%s: and that binary exists" % name,
              R("test -x %s" % chosen[0])[2] == 0, "%s missing" % chosen[0])
        # readlink -f on the master lands on the same binary.
        check("%s: readlink -f agrees" % name,
              R("readlink -f %s" % link[0])[0].strip().endswith(
                  os.path.basename(chosen[0])),
              R("readlink -f %s" % link[0])[0].strip())


def t_etc_alternatives_has_no_dangling_links():
    bad = []
    for l in R("ls /etc/alternatives/")[0].split():
        p = "/etc/alternatives/" + l
        if R("test -L %s" % p)[2] != 0:
            continue
        if R("test -e %s" % p)[2] != 0:
            bad.append("%s -> %s" % (l, R("readlink %s" % p)[0].strip()))
    check("no alternative points at a missing file", not bad, str(bad[:3]))
    check("the directory has Debian's README",
          "update-alternatives(1)" in R("cat /etc/alternatives/README")[0],
          R("cat /etc/alternatives/README")[0][:50])


# ---------------------------------------------------------------------------
# the thing that picks an editor
# ---------------------------------------------------------------------------
def t_the_selected_editor_is_a_program_that_exists():
    body = R("cat /root/.selected_editor")[0]
    check(".selected_editor is there", "SELECTED_EDITOR=" in body, body[:40])
    path = body.split("=", 1)[1].strip().strip('"') if "=" in body else ""
    check("it names a binary that exists", path and
          R("test -x %s" % path)[2] == 0, path)
    check("and it is the alternatives choice",
          R("readlink -f %s" % path)[0].strip()
          == R("readlink -f /usr/bin/editor")[0].strip(),
          "%s vs %s" % (R("readlink -f %s" % path)[0].strip(),
                        R("readlink -f /usr/bin/editor")[0].strip()))
    check("$EDITOR is unset or points at the same thing",
          not R("echo $EDITOR")[0].strip()
          or R("readlink -f $EDITOR")[0].strip()
          == R("readlink -f /usr/bin/editor")[0].strip(),
          R("echo $EDITOR")[0].strip())


# ---------------------------------------------------------------------------
# man-db: installed, or not, but the same answer everywhere
# ---------------------------------------------------------------------------
def t_man_db_is_installed_where_everything_says_it_is():
    row = [l for l in R("dpkg -l man-db")[0].splitlines()
           if l.startswith("ii")]
    check("dpkg says man-db is installed", bool(row),
          R("dpkg -l man-db")[1][:50])
    check("at the version apt quotes in its trigger line",
          row and "2.13.1-1" in row[0], (row or [""])[0][:60])
    for b in ("man", "apropos", "whatis", "mandb", "manpath"):
        check("%s is on PATH" % b, R("which %s" % b)[0].strip()
              == "/usr/bin/" + b, R("which %s" % b)[0].strip())
        check("%s is owned by man-db" % b,
              "man-db" in R("dpkg -S /usr/bin/%s" % b)[0],
              R("dpkg -S /usr/bin/%s" % b)[0][:50])
    check("the timer that regenerates it is still listed",
          "man-db.timer" in R("systemctl list-timers --no-pager")[0],
          "missing")
    check("and its cron.daily entry is still there",
          "man-db" in R("ls /etc/cron.daily/")[0].split(), "missing")
    check("/var/cache/man belongs to man",
          R("stat -c '%U %G' /var/cache/man")[0].split() == ["man", "man"],
          R("stat -c '%U %G' /var/cache/man")[0])


def t_man_answers_the_way_man_does():
    out, err, rc = R("man ls")
    check("man exits 16 for a page it has not got", rc == 16, "rc=%s" % rc)
    check("with man's wording", err.strip() == "No manual entry for ls",
          err[:50])
    check("man --version names the package version",
          R("man --version")[0].strip()
          == "man " + [l.split()[2] for l in R("dpkg -l man-db")[0]
                       .splitlines() if l.startswith("ii")][0].split("-")[0],
          R("man --version")[0].strip())
    out, err, rc = R("apropos nosuchthing")
    check("apropos exits 16 too", rc == 16, "rc=%s" % rc)
    check("with its own wording",
          err.strip() == "nosuchthing: nothing appropriate.", err[:50])
    check("whatis says the same", R("whatis nosuchthing")[1].strip()
          == "nosuchthing: nothing appropriate.",
          R("whatis nosuchthing")[1][:50])
    check("manpath names the directory man would search",
          "/usr/share/man" in R("manpath")[0], R("manpath")[0][:60])


def t_the_missing_pages_have_a_reason_on_disk():
    check("/usr/share/man really is absent",
          R("test -d /usr/share/man")[2] != 0, "it exists after all")
    body = R("cat /etc/dpkg/dpkg.cfg.d/excludes")[0]
    check("dpkg has an excludes file", "path-exclude" in body, body[:50])
    check("and it excludes exactly that directory",
          "path-exclude=/usr/share/man/*" in body, body[:80])
    check("manpath still names it, as man-db's config does",
          "/usr/share/man" in R("manpath")[0], R("manpath")[0])
    # The exclusion is dpkg's, so dpkg -L must not claim pages either.
    pages = [p for p in R("dpkg -L man-db")[0].split()
             if p.startswith("/usr/share/man/")]
    check("dpkg -L man-db lists no pages", not pages, str(pages[:3]))


TESTS = [t_every_group_has_an_admin_file,
         t_the_admin_file_says_what_the_tool_says,
         t_the_link_the_file_names_is_the_link_on_disk,
         t_etc_alternatives_has_no_dangling_links,
         t_the_selected_editor_is_a_program_that_exists,
         t_man_db_is_installed_where_everything_says_it_is,
         t_man_answers_the_way_man_does,
         t_the_missing_pages_have_a_reason_on_disk]


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
