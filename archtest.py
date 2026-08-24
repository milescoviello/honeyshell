#!/usr/bin/env python3
"""Does the box agree with itself about what is inside an archive?

An archive is a second copy of a file, so every question has two places to
ask it: the file on disk and the member in the tarball. They disagreed, and
two of the answers were destructive.

  - `gzip -dc f.gz` printed nothing and DELETED f.gz. The bundled short
    option was only recognised as the literal string "-dc", and matching it
    stripped the whole token, so -c was lost and gunzip ran in its
    replace-the-file mode. Anyone doing `gzip -dc payload.gz | tar x` lost
    the payload and got nothing out.
  - -k was not recognised by gzip, bzip2 or xz, so all three removed their
    input however you asked them to keep it.
  - `tar` never set a member's mode, mtime or owner, so a 0750 file owned by
    www-data was archived as 0644 root/root: `ls -l f` and `tar tvf` of an
    archive containing f described different files, and extracting silently
    widened the permissions. Extraction as root now restores owner too,
    which is GNU tar's default there.
  - `file` guessed a gzip member's uncompressed size as 3.5x the compressed
    size, so it said 567 for an archive `zcat | wc -c` measured at 10240.
    The real figure is in the last four bytes.
  - gzip did not store the original filename in its header, so `file`
    could not report `was "p.txt"` and the compressed size was six bytes
    short of what real gzip produces for the same input.
  - `gzip -l` printed nothing at all.
  - bzcat, xzcat and zgrep did not exist, on a box whose dpkg says bzip2,
    xz-utils and gzip are installed and own exactly those paths.

Checked against a real gzip where the format is externally defined: the
-l output for an 8-byte input is byte-identical, including the -25.0%
ratio, which is computed over the deflate stream and not the whole file.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
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


def tree(s, root="/w"):
    run(s, "rm -rf %s; mkdir -p %s/d" % (root, root))
    run(s, "echo hello > %s/f.txt" % root)
    run(s, "echo world > %s/d/g.txt" % root)
    run(s, "chmod 750 %s/f.txt" % root)
    run(s, "chmod 600 %s/d/g.txt" % root)
    run(s, "chown www-data:adm %s/f.txt" % root)
    return root


def t_compressing_with_c_or_k_keeps_the_input():
    """The destructive one this sweep started from."""
    s = sh()
    run(s, "mkdir -p /w && echo payload > /w/p.txt && gzip /w/p.txt")
    o, rc = run(s, "gzip -dc /w/p.txt.gz")
    eq("gzip -dc writes the plaintext to stdout", o, "payload\n")
    eq("gzip -dc rc", rc, 0)
    o, rc = run(s, "test -f /w/p.txt.gz && echo yes")
    eq("and does NOT delete its input", (o.strip(), rc), ("yes", 0))
    o, _ = run(s, "gunzip -c /w/p.txt.gz")
    eq("gunzip -c gives the same bytes", o, "payload\n")
    o, _ = run(s, "zcat /w/p.txt.gz")
    eq("zcat gives the same bytes", o, "payload\n")
    o, rc = run(s, "test -f /w/p.txt.gz && echo yes")
    eq("all three left the file alone", (o.strip(), rc), ("yes", 0))
    for tool, ext in (("gzip", "gz"), ("bzip2", "bz2"), ("xz", "xz")):
        run(s, "echo keepme > /w/k.txt")
        o, rc = run(s, "cd /w && %s -k k.txt" % tool)
        eq("%s -k rc" % tool, rc, 0)
        o, rc = run(s, "test -f /w/k.txt && echo yes")
        eq("%s -k keeps the input" % tool, (o.strip(), rc), ("yes", 0))
        o, rc = run(s, "test -f /w/k.txt.%s && echo yes" % ext)
        eq("%s -k made the archive" % tool, (o.strip(), rc), ("yes", 0))
        run(s, "rm -f /w/k.txt /w/k.txt.%s" % ext)


def t_compressing_without_k_removes_the_input():
    """The other half: the default really is destructive."""
    s = sh()
    for tool, ext in (("gzip", "gz"), ("bzip2", "bz2"), ("xz", "xz")):
        run(s, "mkdir -p /w && echo x > /w/r.txt")
        run(s, "cd /w && %s r.txt" % tool)
        o, rc = run(s, "test -e /w/r.txt && echo yes")
        eq("%s without -k removes the input" % tool, rc, 1)
        o, rc = run(s, "test -f /w/r.txt.%s && echo yes" % ext)
        eq("%s without -k made the archive" % tool, (o.strip(), rc),
           ("yes", 0))
        run(s, "rm -f /w/r.txt.%s" % ext)


def t_round_trip_through_every_compressor():
    s = sh()
    run(s, "mkdir -p /w")
    body = "line one\nline two\n"
    for tool, cat, ext in (("gzip", "zcat", "gz"),
                           ("bzip2", "bzcat", "bz2"),
                           ("xz", "xzcat", "xz")):
        run(s, "printf 'line one\\nline two\\n' > /w/rt.txt")
        o, rc = run(s, "cd /w && %s rt.txt" % tool)
        eq("%s rc" % tool, rc, 0)
        o, rc = run(s, "%s /w/rt.%s" % (cat, "txt." + ext))
        eq("%s rc" % cat, rc, 0)
        eq("%s round trips the bytes" % tool, o, body)
        o, rc = run(s, "cd /w && %s -d rt.txt.%s && cat rt.txt" % (tool, ext))
        eq("%s -d restores the file" % tool, o, body)
        run(s, "rm -f /w/rt.txt /w/rt.txt.%s" % ext)


def t_tar_member_matches_the_file_on_disk():
    s = sh()
    root = tree(s)
    src, _ = run(s, "ls -l %s/f.txt" % root)
    src_mode, src_user, src_grp = src.split()[0], src.split()[2], src.split()[3]
    o, rc = run(s, "cd %s && tar cf a.tar f.txt d" % root)
    eq("tar cf rc", rc, 0)
    lst, rc = run(s, "cd %s && tar tvf a.tar" % root)
    eq("tar tvf rc", rc, 0)
    line = [l for l in lst.splitlines() if l.endswith("f.txt")]
    check("tar tvf lists f.txt", line, lst[:120])
    if line:
        f = line[0].split()
        eq("tar tvf mode matches ls -l", f[0], src_mode)
        eq("tar tvf owner matches ls -l", f[1], "%s/%s" % (src_user, src_grp))
        eq("tar tvf size matches ls -l", f[2], src.split()[4])
    gline = [l for l in lst.splitlines() if l.endswith("d/g.txt")]
    if gline:
        g_src, _ = run(s, "ls -l %s/d/g.txt" % root)
        eq("the 0600 member keeps its mode", gline[0].split()[0],
           g_src.split()[0])


def t_extracting_reproduces_the_original():
    s = sh()
    root = tree(s)
    run(s, "cd %s && tar cf a.tar f.txt d" % root)
    o, rc = run(s, "cd %s && mkdir -p out && tar xf a.tar -C out" % root)
    eq("tar xf rc", rc, 0)
    for rel in ("f.txt", "d/g.txt"):
        a, _ = run(s, "ls -l %s/%s" % (root, rel))
        b, _ = run(s, "ls -l %s/out/%s" % (root, rel))
        eq("extracted %s has the original mode" % rel,
           b.split()[0], a.split()[0])
        eq("extracted %s has the original owner" % rel,
           b.split()[2:4], a.split()[2:4])
        eq("extracted %s has the original size" % rel,
           b.split()[4], a.split()[4])
        ca, _ = run(s, "cat %s/%s" % (root, rel))
        cb, _ = run(s, "cat %s/out/%s" % (root, rel))
        eq("extracted %s has the original bytes" % rel, cb, ca)
    a, _ = run(s, "cd %s && find . -path ./out -prune -o -name '*.txt' -print "
                  "| sort" % root)
    b, _ = run(s, "cd %s/out && find . -name '*.txt' | sort" % root)
    eq("the extracted tree has the same shape", b.split(), a.split())


def t_gzip_and_zcat_and_file_agree_on_the_size():
    s = sh()
    root = tree(s)
    run(s, "cd %s && tar cf plain.tar f.txt d" % root)
    run(s, "cd %s && tar czf comp.tgz f.txt d" % root)
    plain, _ = run(s, "wc -c < %s/plain.tar" % root)
    viazcat, _ = run(s, "zcat %s/comp.tgz | wc -c" % root)
    eq("zcat of the .tgz is the size of the .tar", viazcat.strip(),
       plain.strip())
    f, _ = run(s, "file %s/comp.tgz" % root)
    m = re.search(r"original size modulo 2\^32 (\d+)", f)
    check("file reports an original size", m, f[:100])
    if m:
        eq("file agrees with zcat", m.group(1), plain.strip())
    l, rc = run(s, "cd %s && gzip -l comp.tgz" % root)
    eq("gzip -l rc", rc, 0)
    rows = l.strip().splitlines()
    check("gzip -l has a header and a row", len(rows) == 2, l[:120])
    if len(rows) == 2:
        cols = rows[1].split()
        comp, _ = run(s, "wc -c < %s/comp.tgz" % root)
        eq("gzip -l compressed column is the file size", cols[0],
           comp.strip())
        eq("gzip -l uncompressed column agrees with zcat", cols[1],
           plain.strip())


def t_gzip_l_matches_real_gzip_byte_for_byte():
    """The one format here that is externally defined."""
    s = sh()
    run(s, "mkdir -p /w && printf 'payload\\n' > /w/p.txt && gzip /w/p.txt")
    o, rc = run(s, "cd /w && gzip -l p.txt.gz")
    eq("gzip -l rc", rc, 0)
    eq("gzip -l header", o.splitlines()[0],
       "         compressed        uncompressed  ratio uncompressed_name")
    # Verified against a real gzip 1.13 on an 8-byte input.
    eq("gzip -l row", o.splitlines()[1],
       "                 34                   8 -25.0% p.txt")


def t_gzip_stores_the_original_name():
    s = sh()
    run(s, "mkdir -p /w && echo payload > /w/named.txt && gzip /w/named.txt")
    o, _ = run(s, "file /w/named.txt.gz")
    check('file reports the stored name', 'was "named.txt"' in o, o[:120])
    check("file reports a modification time", "last modified" in o, o[:120])
    o, _ = run(s, "cd /w && gzip -l named.txt.gz | tail -1")
    check("gzip -l strips the .gz for the name column",
          o.strip().endswith("named.txt"), o.strip())
    o, _ = run(s, "gunzip /w/named.txt.gz && cat /w/named.txt")
    eq("and it still round trips", o, "payload\n")


def t_every_compression_tool_has_an_owning_package():
    s = sh()
    for tool in ("gzip", "gunzip", "zcat", "zgrep", "bzip2", "bunzip2",
                 "bzcat", "xz", "unxz", "xzcat", "tar"):
        path, rc = run(s, "command -v %s" % tool)
        eq("%s is on PATH" % tool, rc, 0)
        if rc:
            continue
        o, rc2 = run(s, "dpkg -S %s" % path.strip())
        eq("dpkg -S knows %s" % tool, rc2, 0)
        pkg = o.split(":")[0].strip()
        _v, rc3 = run(s, "dpkg-query -W -f '${Version}' %s" % pkg)
        eq("%s belongs to installed package %s" % (tool, pkg), rc3, 0)
    # zip/unzip are genuinely absent; dpkg must agree they are.
    for tool in ("zip", "unzip"):
        _o, rc = run(s, "command -v %s" % tool)
        eq("%s is absent" % tool, rc, 1)
        _o, rc = run(s, "dpkg-query -W -f '${Version}' %s" % tool)
        check("and dpkg does not claim %s" % tool, rc != 0, "dpkg has it")


def t_zgrep_reads_through_the_compression():
    s = sh()
    run(s, "mkdir -p /w && printf 'alpha\\nbeta\\ngamma\\n' > /w/z.txt")
    run(s, "gzip -k /w/z.txt")
    o, rc = run(s, "zgrep beta /w/z.txt.gz")
    eq("zgrep finds a line", o.strip(), "beta")
    eq("zgrep rc on a hit", rc, 0)
    o, rc = run(s, "zgrep nomatch /w/z.txt.gz")
    eq("zgrep rc on a miss", rc, 1)
    eq("and prints nothing", o.strip(), "")
    # It has to agree with grepping the uncompressed original.
    a, _ = run(s, "grep beta /w/z.txt")
    eq("zgrep matches grep of the plaintext", o == "" and a.strip(), "beta")
    o, rc = run(s, "zgrep alpha /w/missing.gz")
    eq("a missing file is an error", rc, 2)
    for ext, tool in (("bz2", "bzip2"), ("xz", "xz")):
        run(s, "printf 'alpha\\nbeta\\n' > /w/y.txt && %s /w/y.txt" % tool)
        o, rc = run(s, "zgrep beta /w/y.txt.%s" % ext)
        eq("zgrep reads .%s too" % ext, o.strip(), "beta")
        run(s, "rm -f /w/y.txt.%s" % ext)


def t_tar_reports_a_bad_archive_rather_than_succeeding():
    s = sh()
    run(s, "mkdir -p /w && echo '<html>404</html>' > /w/fake.tgz")
    o, rc = run(s, "cd /w && tar xzf fake.tgz")
    check("a non-archive fails", rc != 0, "rc=%d" % rc)
    check("with tar's wording", "not in gzip format" in o or "Error" in o,
          o[:100])
    o, rc = run(s, "cd /w && tar tf /w/nosuch.tar")
    check("a missing archive fails", rc != 0, "rc=%d" % rc)
    check("naming the file", "nosuch.tar" in o, o[:100])


def t_tar_sizes_are_whole_blocks():
    s = sh()
    root = tree(s)
    run(s, "cd %s && tar cf a.tar f.txt d" % root)
    n, _ = run(s, "wc -c < %s/a.tar" % root)
    v = int(n.strip())
    check("a tar is a multiple of 512", v % 512 == 0, n.strip())
    check("and of the 10240-byte default blocking factor", v % 10240 == 0,
          n.strip())
    o, _ = run(s, "file %s/a.tar" % root)
    check("file recognises it as a tar", "tar archive" in o, o[:80])
    v, _ = run(s, "tar --version")
    check("tar says it is GNU tar", "GNU tar" in v, v[:40])
    check("and file agrees the archive is GNU format", "(GNU)" in o, o[:80])
    pkg, _ = run(s, "dpkg-query -W -f '${Version}' tar")
    check("tar --version matches the tar package (%s)" % pkg.strip(),
          v.split()[3] in pkg, "%r vs %r" % (v.split()[3], pkg))


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
