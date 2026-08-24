#!/usr/bin/env python3
"""Does the box agree with itself about what `editor` actually runs?

Debian's alternatives system is four views of one fact: the database
update-alternatives prints, the /usr/bin/<name> symlink, the
/etc/alternatives/<name> symlink it points through, and what `which` and
the shell resolve. All four disagreed.

  - `update-alternatives --display editor` reported "link editor is
    /usr/bin/editor" on a box with no /usr/bin/editor, and the same for
    pager. The database described links that were not on disk.
  - `--display awk` said /usr/bin/awk was a link to mawk while the
    filesystem had it as a plain 170KB binary.
  - `--display pager` named the *link* as the best version -- "link best
    version is /usr/bin/pager" -- where the best version is the
    alternative behind it, /usr/bin/less.
  - `--get-selections` listed an `sh` alternative, which Debian does not
    have; /bin/sh is a plain symlink to dash, not an alternative.
  - `--query` was rejected by an error message that lists --query among the
    options it accepts.
  - Priorities were invented as 10, 11, 12 in registration order. Debian's
    are mawk 5, nano 40, more 50, less 77, xz 20.
  - No slave links were reported at all, and /etc/alternatives had no
    README.
  - Following the chain by hand worked, but running the command did not:
    `which editor` printed a path and `editor` answered command not found,
    because dispatch never followed the symlink.

The formats are dpkg's, so --display and --query are checked against a real
update-alternatives on the trixie guest rather than against this
implementation.

Run from `honeypot/`, or on the guest.
"""

import os
import re
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


def names():
    return [row[0] for row in fs.Shell.ALTERNATIVES]


def t_every_link_the_database_claims_exists():
    """The contradiction this sweep started from."""
    s = sh()
    for name in names():
        o, rc = run(s, "update-alternatives --display %s" % name)
        eq("--display %s rc" % name, rc, 0)
        m = re.search(r"link %s is (\S+)" % re.escape(name), o)
        check("--display %s names its link" % name, m, o[:80])
        if not m:
            continue
        link = m.group(1)
        o2, rc2 = run(s, "test -L %s && echo yes" % link)
        eq("%s exists and is a symlink" % link, (o2.strip(), rc2), ("yes", 0))
        tgt, _ = run(s, "readlink %s" % link)
        eq("%s points into /etc/alternatives" % link, tgt.strip(),
           "/etc/alternatives/" + name)


def t_the_chain_ends_where_the_database_says():
    s = sh()
    for name in names():
        o, _ = run(s, "update-alternatives --display %s" % name)
        m = re.search(r"link currently points to (\S+)", o)
        check("--display %s says where it points" % name, m, o[:80])
        if not m:
            continue
        want = m.group(1)
        got, rc = run(s, "readlink /etc/alternatives/%s" % name)
        eq("/etc/alternatives/%s points at the same place" % name,
           got.strip(), want)
        real, _ = run(s, "readlink -f /usr/bin/%s" % name)
        # /bin and /usr/bin are the same directory on a merged-usr system.
        eq("resolving the link lands on the target (%s)" % name,
           real.strip().rsplit("/", 1)[-1], want.rsplit("/", 1)[-1])
        o2, rc2 = run(s, "test -e %s && echo yes" % want)
        eq("and the target exists (%s)" % want, (o2.strip(), rc2),
           ("yes", 0))


def t_best_version_is_an_alternative_not_the_link():
    s = sh()
    for name in names():
        o, _ = run(s, "update-alternatives --display %s" % name)
        best = re.search(r"link best version is (\S+)", o)
        link = re.search(r"link %s is (\S+)" % re.escape(name), o)
        check("%s reports a best version" % name, best, o[:80])
        if not (best and link):
            continue
        check("%s best version is not the link itself" % name,
              best.group(1) != link.group(1), best.group(1))
        listed = re.findall(r"^(/\S+) - priority (\d+)$", o, re.M)
        check("%s lists its alternatives with priorities" % name, listed,
              o[:120])
        if listed:
            top = max(listed, key=lambda x: int(x[1]))[0]
            eq("%s best version is the highest priority" % name,
               best.group(1), top)


def t_pager_matches_the_real_debian_output():
    """dpkg's format, so compare with the guest's own update-alternatives."""
    s = sh()
    o, rc = run(s, "update-alternatives --display pager")
    eq("rc", rc, 0)
    eq("display pager", o,
       "pager - auto mode\n"
       "  link best version is /usr/bin/less\n"
       "  link currently points to /usr/bin/less\n"
       "  link pager is /usr/bin/pager\n"
       "  slave pager.1.gz is /usr/share/man/man1/pager.1.gz\n"
       "/bin/more - priority 50\n"
       "  slave pager.1.gz: /usr/share/man/man1/more.1.gz\n"
       "/usr/bin/less - priority 77\n"
       "  slave pager.1.gz: /usr/share/man/man1/less.1.gz\n")
    o, rc = run(s, "update-alternatives --query pager")
    eq("query rc", rc, 0)
    eq("query pager", o,
       "Name: pager\n"
       "Link: /usr/bin/pager\n"
       "Slaves:\n"
       " pager.1.gz /usr/share/man/man1/pager.1.gz\n"
       "Status: auto\n"
       "Best: /usr/bin/less\n"
       "Value: /usr/bin/less\n"
       "\nAlternative: /bin/more\nPriority: 50\n"
       "Slaves:\n pager.1.gz /usr/share/man/man1/more.1.gz\n"
       "\nAlternative: /usr/bin/less\nPriority: 77\n"
       "Slaves:\n pager.1.gz /usr/share/man/man1/less.1.gz\n")


def t_running_the_name_runs_the_target():
    """which found a path that the shell then said did not exist."""
    s = sh()
    for name, target in (("editor", "nano"), ("pager", "less"),
                         ("nawk", "awk")):
        w, rc = run(s, "command -v %s" % name)
        eq("command -v %s" % name, rc, 0)
        a, rca = run(s, "%s 2>&1 | head -1" % name)
        b, rcb = run(s, "%s 2>&1 | head -1" % target)
        check("`%s` behaves as `%s` does" % (name, target), a == b,
              "%r vs %r" % (a, b))
        check("and does not say command not found",
              "command not found" not in a, a[:60])
    # lzma resolves through the same machinery but is NOT simply xz: on a
    # real trixie xz-utils reads argv[0] and writes the legacy container,
    # so `lzma f` leaves f.lzma where `xz f` leaves f.xz. This loop used to
    # assert the two were interchangeable, which froze that bug in place.
    # t_lzma_writes_the_legacy_container pins the real behaviour.
    w, rc = run(s, "command -v lzma")
    eq("command -v lzma", rc, 0)
    o, _ = run(s, "lzma 2>&1 | head -c1")
    check("lzma runs", "command not found" not in o, o[:60])
    # awk must still work through its new symlink.
    o, rc = run(s, "printf 'a b\\n' | awk '{print $2}'")
    eq("awk still runs after becoming a symlink", (o.strip(), rc), ("b", 0))


def t_awk_is_a_link_not_a_binary():
    s = sh()
    o, rc = run(s, "test -L /usr/bin/awk && echo yes")
    eq("/usr/bin/awk is a symlink", (o.strip(), rc), ("yes", 0))
    o, _ = run(s, "readlink -f /usr/bin/awk")
    eq("and resolves to mawk", o.strip(), "/usr/bin/mawk")
    o, _ = run(s, "ls -l /usr/bin/mawk")
    check("mawk itself is a real binary", o.startswith("-rwx"), o[:40])
    v, rc = run(s, "dpkg-query -W -f '${Version}' mawk")
    eq("and mawk is an installed package", rc, 0)


def t_get_selections_lists_only_real_alternatives():
    s = sh()
    o, rc = run(s, "update-alternatives --get-selections")
    eq("rc", rc, 0)
    rows = dict((l.split()[0], l.split()[2]) for l in o.splitlines()
                if len(l.split()) >= 3)
    eq("every alternative is listed", sorted(rows), sorted(names()))
    check("sh is not an alternative on Debian", "sh" not in rows,
          "sh listed")
    o2, _ = run(s, "readlink /bin/sh")
    eq("/bin/sh is a plain symlink to dash", o2.strip(), "dash")
    for name, value in rows.items():
        cur, _ = run(s, "readlink /etc/alternatives/%s" % name)
        eq("--get-selections agrees with the link for %s" % name,
           value, cur.strip())
    eq("every row is in auto mode",
       set(l.split()[1] for l in o.splitlines() if len(l.split()) >= 3),
       {"auto"})


def t_etc_alternatives_holds_what_the_database_holds():
    s = sh()
    o, _ = run(s, "ls /etc/alternatives")
    entries = set(o.split())
    check("there is a README", "README" in entries, sorted(entries))
    body, _ = run(s, "cat /etc/alternatives/README")
    check("which points at the man page", "update-alternatives(1)" in body,
          body[:60])
    for name in names():
        check("/etc/alternatives has %s" % name, name in entries,
              sorted(entries))
    for name in names():
        o2, rc = run(s, "test -L /etc/alternatives/%s && echo yes" % name)
        eq("/etc/alternatives/%s is a symlink" % name, (o2.strip(), rc),
           ("yes", 0))


def t_query_and_list_and_errors():
    s = sh()
    o, rc = run(s, "update-alternatives --query editor")
    eq("--query is accepted", rc, 0)
    d = dict(l.split(": ", 1) for l in o.splitlines() if ": " in l)
    eq("query Name", d.get("Name"), "editor")
    eq("query Link", d.get("Link"), "/usr/bin/editor")
    eq("query Status", d.get("Status"), "auto")
    eq("query Best", d.get("Best"), "/bin/nano")
    eq("query Value matches the link", d.get("Value"),
       run(s, "readlink /etc/alternatives/editor")[0].strip())
    o, rc = run(s, "update-alternatives --list pager")
    eq("--list rc", rc, 0)
    eq("--list gives every alternative", sorted(o.split()),
       ["/bin/more", "/usr/bin/less"])
    for flag in ("--display", "--query", "--list"):
        o, rc = run(s, "update-alternatives %s nosuchalt" % flag)
        eq("%s of an unknown name is rc 2" % flag, rc, 2)
        check("%s error wording" % flag,
              "no alternatives for nosuchalt" in o, o[:80])


def t_setting_an_alternative_moves_the_link():
    s = sh()
    before, _ = run(s, "readlink /etc/alternatives/pager")
    eq("pager starts on less", before.strip(), "/usr/bin/less")
    o, rc = run(s, "update-alternatives --set pager /bin/more")
    eq("--set rc", rc, 0)
    after, _ = run(s, "readlink /etc/alternatives/pager")
    eq("the link moved", after.strip(), "/bin/more")
    o, _ = run(s, "update-alternatives --display pager")
    m = re.search(r"link currently points to (\S+)", o)
    eq("and --display follows it", m and m.group(1), "/bin/more")
    m = re.search(r"link best version is (\S+)", o)
    eq("while best version is unchanged", m and m.group(1), "/usr/bin/less")
    sel, _ = run(s, "update-alternatives --get-selections")
    check("--get-selections follows too",
          re.search(r"^pager\s+auto\s+/bin/more$", sel, re.M), sel[:200])
    o, rc = run(s, "update-alternatives --set pager /usr/bin/nosuch")
    eq("setting an unregistered path fails", rc, 2)
    check("with dpkg's wording", "not registered" in o, o[:90])


def alt_binaries():
    """Every alternative name plus its slave links, minus the man pages --
    the slaves are commands too: lzcat and unlzma are how most callers reach
    xz-utils, and nawk is how a script reaches mawk."""
    out = []
    for name, _link, _alts, slaves in fs.Shell.ALTERNATIVES:
        out.append(name)
        out.extend(k for k in slaves if not k.endswith(".gz"))
    return sorted(set(out))


def t_an_alternative_answers_the_same_by_either_spelling():
    """The bare name followed the symlink and the absolute path did not.

    `editor` printed nano's usage; `/usr/bin/editor` returned 0 with no
    output at all, because dispatch looked for cmd_editor, missed, and fell
    through to the branch that registers an unknown dropped binary. Anything
    checking that its tool exists by full path got silence and success.
    """
    for name in alt_binaries():
        a, rca = run(sh(), name)
        b, rcb = run(sh(), "/usr/bin/%s" % name)
        eq("%s: same status either way" % name, rcb, rca)
        eq("%s: same output either way" % name, b, a)


def t_no_alternative_succeeds_silently():
    """rc 0 with nothing on either stream is the one answer a caller cannot
    act on, and it is what every one of these gave by absolute path."""
    for name in alt_binaries():
        if name == "php":
            # php with no operands reads the script from stdin, so an empty
            # stdin really is an empty program: no output, status 0. That is
            # a silent success a real box also gives, not a missing handler.
            continue
        o, rc = run(sh(), name)
        check("%s says something or fails" % name,
              not (rc == 0 and not o.strip()), "rc=%s out=%r" % (rc, o[:40]))


def t_lzma_writes_the_legacy_container():
    """lzma is not a spelling of xz: it writes .lzma, and the bytes are the
    alone-format header, not \xfd7zXZ. This produced f.xz."""
    s = sh()
    run(s, "echo hello > /tmp/a.txt")
    o, rc = run(s, "lzma /tmp/a.txt")
    eq("lzma succeeds", rc, 0)
    o, _ = run(s, "ls /tmp/a.txt*")
    eq("lzma leaves .lzma and removes the input", o.strip(), "/tmp/a.txt.lzma")
    head, _ = run(s, "head -c1 /tmp/a.txt.lzma")
    eq("alone-format magic, not xz's", head[:1], "]")


def t_xz_still_writes_xz():
    """Guard the sibling: teaching lzma its own container must not move xz."""
    s = sh()
    run(s, "echo x > /tmp/c.txt")
    run(s, "xz /tmp/c.txt")
    o, _ = run(s, "ls /tmp/c.txt*")
    eq("xz still writes .xz", o.strip(), "/tmp/c.txt.xz")
    o, rc = run(s, "unxz /tmp/c.txt.xz; cat /tmp/c.txt")
    eq("and round trips", (o.strip(), rc), ("x", 0))


def t_lzma_round_trips_through_all_three_names():
    s = sh()
    run(s, "echo world > /tmp/b.txt")
    run(s, "lzma /tmp/b.txt")
    o, rc = run(s, "lzcat /tmp/b.txt.lzma")
    eq("lzcat prints the plaintext", (o.strip(), rc), ("world", 0))
    o, _ = run(s, "ls /tmp/b.txt*")
    eq("lzcat keeps the archive", o.strip(), "/tmp/b.txt.lzma")
    run(s, "unlzma /tmp/b.txt.lzma")
    o, _ = run(s, "cat /tmp/b.txt; ls /tmp/b.txt*")
    eq("unlzma restores and removes", o.split()[0], "world")
    eq("nothing left compressed", o.strip().splitlines()[-1], "/tmp/b.txt")


def t_lzma_keeps_the_input_with_dash_k():
    s = sh()
    run(s, "echo k > /tmp/d.txt")
    run(s, "lzma -k /tmp/d.txt")
    o, _ = run(s, "ls /tmp/d.txt*")
    eq("-k keeps both", o.split(), ["/tmp/d.txt", "/tmp/d.txt.lzma"])


def t_the_lzma_family_names_itself_in_its_errors():
    """One binary under four names, and the error carries the name the
    caller typed. `lzcat bad` answered "unxz: ..." -- naming a binary that
    was never on the command line."""
    for prog in ("lzcat", "unlzma", "xzcat", "unxz"):
        o, rc = run(sh(), "%s /nope" % prog)
        eq("%s: missing file fails" % prog, rc, 1)
        check("%s: names itself" % prog, o.startswith(prog + ":"), o[:60])
    for prog in ("lzcat", "unlzma", "xzcat", "unxz"):
        o, rc = run(sh(), prog)
        eq("%s: empty stdin is rejected" % prog, rc, 1)
        eq("%s: and blames (stdin)" % prog, o.strip(),
           "%s: (stdin): File format not recognized" % prog)


def t_a_bad_archive_is_not_silently_accepted():
    s = sh()
    o, rc = run(s, "lzcat /etc/hostname")
    eq("plaintext is not an archive", rc, 1)
    eq("and lzcat says so", o.strip(),
       "lzcat: /etc/hostname: File format not recognized")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


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
