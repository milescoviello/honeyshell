#!/usr/bin/env python3
"""Which commands actually walk the tree?

"Everything under this directory" is one question, and the box answered it
two ways. `cp -r`, `rm -rf`, `find`, `du -a`, `grep -r` and `tar` all
walked. `ls -R`, `chmod -R`, `chown -R` and `chgrp -R` did not:

  - `ls -R /var/www` listed one directory, with none of the `path:` headers
    real ls prints, on a box where `du -a` of the same path walks it all.
    It is the recon listing -- `ls -laR /home`, `ls -R /var/www` -- and it
    was quietly showing one level.
  - `chmod -R 777 /tmp/x` changed the directory and nothing inside it, and
    `chown -R www-data /var/www` the same. Both report success, which makes
    the wrong permissions look applied: the attacker's next step fails for
    a reason the box has already lied about.

Globbing had the matching hole. `shopt -s globstar` returned 0 for any name
at all and recorded nothing, so `shopt globstar` immediately afterwards
answered "invalid shell option name" -- and `**` went on behaving like `*`.
shopt's table was 13 of bash 5.2's 55 options, and the five that change how
globs match (globstar, dotglob, nullglob, failglob, nocaseglob) all did
nothing. A subshell's `shopt -s` also leaked into the parent, so one
`( shopt -s dotglob; ... )` changed every later glob in the session.

`ls -R` output shape, the shopt table and its defaults, and globstar's
matching were all measured against GNU ls 9.4 and bash 5.2.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
    s.exec_mode = True
    s.run("mkdir -p /tmp/w/sub/deep /tmp/w/.git; echo x > /tmp/w/a.txt; "
          "echo y > /tmp/w/sub/b.txt; echo z > /tmp/w/sub/deep/c.txt; "
          "echo h > /tmp/w/.hidden.txt; echo g > /tmp/w/.git/cfg.txt; "
          "ln -s /etc /tmp/w/link")
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


# --- ls -R ------------------------------------------------------------------

def t_ls_R_walks_and_heads_each_directory():
    s = sh()
    o, rc = run(s, "ls -R /tmp/w")
    eq("rc", rc, 0)
    blocks = o.split("\n\n")
    heads = [b.splitlines()[0] for b in blocks if b.strip()]
    eq("a header per directory, depth first",
       heads, ["/tmp/w:", "/tmp/w/sub:", "/tmp/w/sub/deep:"])
    eq("the top block lists the top", blocks[0].splitlines()[1:],
       ["a.txt", "link", "sub"])
    eq("the deepest block lists the deepest file",
       blocks[2].splitlines()[1:], ["c.txt"])


def t_ls_R_does_not_follow_symlinks():
    s = sh()
    o, _ = run(s, "ls -R /tmp/w")
    check("the link is listed", "link" in o, o[:60])
    check("but not descended into", "passwd" not in o, o[:200])


def t_ls_R_cannot_be_made_to_loop():
    s = sh()
    run(s, "mkdir -p /tmp/lp; ln -s /tmp/lp /tmp/lp/self")
    o, rc = run(s, "ls -R /tmp/lp")
    eq("rc", rc, 0)
    eq("a self-referential link is listed once and not followed",
       [l for l in o.splitlines() if l.strip()], ["/tmp/lp:", "self"])


def t_ls_R_relative_and_hidden():
    s = sh()
    o, _ = run(s, "cd /tmp/w && ls -R")
    check("with no operand the headers are relative",
          o.startswith(".:\n"), o[:20])
    check("and so are the subdirectory ones", "./sub:" in o, o[:80])
    check("hidden directories are skipped without -a",
          "./.git" not in o, o[:120])
    o2, _ = run(s, "cd /tmp/w && ls -Ra")
    check("-a walks them", "./.git:" in o2, o2[:200])


def t_ls_R_agrees_with_the_walkers():
    s = sh()
    o, _ = run(s, "ls -R /tmp/w")
    listed = {l for l in o.splitlines()
              if l.strip() and not l.endswith(":")}
    o2, _ = run(s, "find /tmp/w -not -path '*/.*' -printf '%f\\n'")
    found = {l for l in o2.split() if l and l != "w"}
    missing = found - listed
    eq("everything find reports under the path, ls -R printed", missing,
       set())


# --- the recursive ownership flags -----------------------------------------

def t_chmod_R_walks():
    s = sh()
    o, rc = run(s, "chmod -R 700 /tmp/w")
    eq("rc", rc, 0)
    for p in ("/tmp/w", "/tmp/w/a.txt", "/tmp/w/sub",
              "/tmp/w/sub/deep/c.txt"):
        o2, _ = run(s, "stat -c %%a %s" % p)
        eq("%s is 700" % p, o2.strip(), "700")


def t_chmod_without_R_does_not():
    s = sh()
    run(s, "chmod 700 /tmp/w")
    o, _ = run(s, "stat -c %a /tmp/w/a.txt")
    eq("a file under it keeps its mode", o.strip(), "644")


def t_chown_R_and_chgrp_R_walk():
    s = sh()
    run(s, "chown -R deploy:deploy /tmp/w")
    for p in ("/tmp/w", "/tmp/w/sub/b.txt", "/tmp/w/sub/deep/c.txt"):
        o, _ = run(s, "stat -c '%%U:%%G' %s" % p)
        eq("%s is deploy:deploy" % p, o.strip(), "deploy:deploy")
    run(s, "chgrp -R adm /tmp/w")
    o2, _ = run(s, "stat -c %G /tmp/w/sub/deep/c.txt")
    eq("chgrp -R reaches the bottom too", o2.strip(), "adm")


def t_cp_r_keeps_symlinks_as_symlinks():
    s = sh()
    run(s, "cp -r /tmp/w /tmp/w3")
    o, _ = run(s, "find /tmp/w3 -type l")
    check("the link survived as a link", "/tmp/w3/link" in o, o[:80])
    o2, _ = run(s, "readlink /tmp/w3/link")
    eq("pointing where it pointed", o2.strip(), "/etc")
    a, _ = run(s, "find /tmp/w -type f | wc -l")
    b, _ = run(s, "find /tmp/w3 -type f | wc -l")
    eq("and the file count did not grow", b.strip(), a.strip())


def t_the_recursive_family_agrees():
    """cp -r, rm -rf and find already walked; now the others do."""
    s = sh()
    run(s, "cp -r /tmp/w /tmp/w2")
    o, _ = run(s, "find /tmp/w2 -type f | wc -l")
    o2, _ = run(s, "find /tmp/w -type f | wc -l")
    eq("cp -r copied every file", o.strip(), o2.strip())
    run(s, "chmod -R 705 /tmp/w2")
    o3, _ = run(s, "find /tmp/w2 -type f -perm 705 | wc -l")
    eq("and chmod -R changed every one of them", o3.strip(), o2.strip())
    run(s, "rm -rf /tmp/w2")
    o4, rc = run(s, "ls -d /tmp/w2")
    eq("rm -rf removed the tree", rc, 2)


# --- shopt ------------------------------------------------------------------

def t_shopt_remembers():
    s = sh()
    o, rc = run(s, "shopt globstar")
    eq("globstar is off by default", o.split(), ["globstar", "off"])
    eq("and the status says so", rc, 1)
    run(s, "shopt -s globstar")
    o2, rc2 = run(s, "shopt globstar")
    eq("after -s it is on", o2.split(), ["globstar", "on"])
    eq("and the status agrees", rc2, 0)
    o3, rc3 = run(s, "shopt -q globstar")
    eq("-q is the status alone", (o3.strip(), rc3), ("", 0))
    o4, _ = run(s, "shopt -p globstar")
    eq("-p prints the command that would set it", o4.strip(),
       "shopt -s globstar")
    run(s, "shopt -u globstar")
    o5, rc5 = run(s, "shopt -q globstar")
    eq("and -u turns it off again", rc5, 1)


def t_shopt_knows_bashs_options():
    s = sh()
    o, _ = run(s, "shopt")
    names = [l.split()[0] for l in o.splitlines() if l.strip()]
    check("the table is bash-sized", len(names) > 50, len(names))
    for nm in ("dotglob", "nullglob", "failglob", "nocaseglob", "extglob",
               "huponexit", "lastpipe", "checkjobs", "globskipdots"):
        check("shopt knows %s" % nm, nm in names, names[:6])
    o2, rc = run(s, "shopt -s nosuchoption")
    eq("an invented name is refused", rc, 1)
    check("with bash's wording", "invalid shell option name" in o2, o2[:70])


def t_globstar_crosses_directories():
    s = sh()
    o, _ = run(s, "echo /tmp/w/**/*.txt")
    eq("without it, ** is just *", o.split(), ["/tmp/w/sub/b.txt"])
    run(s, "shopt -s globstar")
    o2, _ = run(s, "echo /tmp/w/**/*.txt")
    eq("with it, every depth matches", o2.split(),
       ["/tmp/w/a.txt", "/tmp/w/sub/b.txt", "/tmp/w/sub/deep/c.txt"])
    check("and hidden paths still are not matched",
          ".hidden" not in o2 and ".git" not in o2, o2)
    o3, _ = run(s, "cd /tmp/w && echo **/*.txt")
    eq("a relative pattern stays relative", o3.split(),
       ["a.txt", "sub/b.txt", "sub/deep/c.txt"])


def t_dotglob_nullglob_failglob():
    s = sh()
    o, _ = run(s, "echo /tmp/w/*.txt")
    check("dotfiles are hidden by default", ".hidden" not in o, o)
    run(s, "shopt -s dotglob")
    o2, _ = run(s, "echo /tmp/w/*.txt")
    check("dotglob shows them", "/tmp/w/.hidden.txt" in o2, o2)
    s2 = sh()
    o3, _ = run(s2, "echo /tmp/w/*.nope")
    eq("an unmatched pattern is left alone", o3.strip(), "/tmp/w/*.nope")
    run(s2, "shopt -s nullglob")
    o4, _ = run(s2, "echo /tmp/w/*.nope")
    eq("nullglob removes it", o4.strip(), "")
    s3 = sh()
    run(s3, "shopt -s failglob")
    o5, rc5 = run(s3, "echo /tmp/w/*.nope")
    check("failglob refuses the command", "no match" in o5, o5[:60])
    check("and prints nothing on stdout", not o5.startswith("/tmp"), o5[:40])


def t_nocaseglob():
    s = sh()
    run(s, "touch /tmp/w/UPPER.TXT")
    o, _ = run(s, "echo /tmp/w/upper*")
    eq("case matters by default", o.strip(), "/tmp/w/upper*")
    run(s, "shopt -s nocaseglob")
    o2, _ = run(s, "echo /tmp/w/upper*")
    eq("nocaseglob matches it", o2.strip(), "/tmp/w/UPPER.TXT")


def t_a_subshell_does_not_leak_its_options():
    s = sh()
    o, _ = run(s, "(shopt -s dotglob; echo /tmp/w/*.txt)")
    check("the subshell saw its own option", "/tmp/w/.hidden.txt" in o, o)
    o2, _ = run(s, "echo /tmp/w/*.txt")
    check("the parent did not", ".hidden" not in o2, o2)
    o3, _ = run(s, "shopt dotglob")
    eq("and shopt agrees", o3.split(), ["dotglob", "off"])


def t_a_child_shell_starts_from_the_defaults():
    s = sh()
    run(s, "shopt -s globstar")
    o, _ = run(s, "bash -c 'shopt globstar'")
    eq("a new bash has its own", o.split(), ["globstar", "off"])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
