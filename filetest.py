#!/usr/bin/env python3
"""Diff the file, archive and encoding commands against real bash, deeply.

The companion to texttest.py, from the same sweep and for the same reason: a
tool that answers plausibly instead of erroring corrupts a capture without
anyone noticing. This half found `find -exec` running nothing, `find -delete`
deleting nothing, `cp -r` copying nothing, `chmod u+x` setting all three
execute bits, `dd` ignoring count= and skip=, `umask` not applying to new
files, `wc -l -w -c` printing one number, `sha1sum -c` hashing the checksum
file, `env -i FOO=bar cmd` never running cmd, and tar omitting directory
members so its own archives listed differently from real tar's.

Each case is a complete snippet run in a scratch directory both sides. Nothing
here depends on the persona: no case compares a username, a hostname or a
clock, because those are supposed to differ. Run from `honeypot/`, or on the
guest.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402


CASES = [
 # find -- predicates and actions
 ("find -type f",      "mkdir -p d/s; touch d/a d/s/b; find d -type f | sort"),
 # Symbolic modes. -perm took an octal string only; int(body, 8) raised on
 # a symbolic one and the predicate then matched nothing at all, silently.
 # RedTail's setup.sh picks its working directory with
 #   find / -type d -user $(whoami) -perm -u=rwx ...
 # so on this box that search came back empty on every run.
 ("find -perm -u=rwx",  "mkdir -p d/a d/b; chmod 755 d/a; chmod 700 d/b;"
                        " find d -type d -perm -u=rwx | sort"),
 ("find -perm -g=w",    "mkdir -p d/a d/b; chmod 775 d/a; chmod 700 d/b;"
                        " find d -type d -perm -g=w | sort"),
 ("find -perm /u=w",    "mkdir -p d/a d/b; chmod 555 d/a; chmod 700 d/b;"
                        " find d -type d -perm /u=w | sort"),
 ("find -perm u=rwx",   "mkdir -p d/a d/b; chmod 700 d/a; chmod 755 d/b;"
                        " find d -type d -perm u=rwx | sort"),
 ("find -perm -u=rwx,g=rx", "mkdir -p d/a d/b; chmod 750 d/a; chmod 700 d/b;"
                        " find d -type d -perm -u=rwx,g=rx | sort"),
 ("find -perm octal still", "mkdir -p d/a d/b; chmod 755 d/a; chmod 700 d/b;"
                        " find d -type d -perm -755 | sort"),
 ("find -perm -u+w",    "mkdir -p d/a; chmod 500 d/a; find d -type d -perm -u+w | sort"),
 # The start path is listed once. For any ordinary path it could not repeat,
 # but the root prefix is "/" and every key matches it, so `find /` printed
 # the root twice.
 ("find start once",    "mkdir -p d/a; find d -maxdepth 0"),
 ("find start not dup",  "mkdir -p d/a d/b; find d | sort"),
 ("find -type d",      "mkdir -p d/s; touch d/a; find d -type d | sort"),
 ("find -name glob",   "touch a.txt b.log; find . -maxdepth 1 -name '*.txt'"),
 ("find -iname",       "touch A.TXT; find . -maxdepth 1 -iname '*.txt'"),
 ("find -maxdepth",    "mkdir -p d/s; touch d/a d/s/b; find d -maxdepth 1 | sort"),
 ("find -mindepth",    "mkdir -p d/s; touch d/a d/s/b; find d -mindepth 2 | sort"),
 ("find -exec",        r"touch a b; find . -maxdepth 1 -name 'a' -exec echo FOUND {} \;"),
 ("find -exec plus",   "touch a; find . -maxdepth 1 -name a -exec echo X {} +"),
 ("find -delete",      "touch zz; find . -maxdepth 1 -name zz -delete; ls zz 2>&1 | head -1"),
 ("find -size",        "dd if=/dev/zero of=big bs=1024 count=2 2>/dev/null; find . -maxdepth 1 -size +1k -name big"),
 ("find -empty",       "touch e; echo x > ne; find . -maxdepth 1 -empty -name 'e'"),
 ("find -newer",       "touch -d '@0' old; touch new; find . -maxdepth 1 -newer old -name new"),
 ("find -perm",        "touch p; chmod 755 p; find . -maxdepth 1 -perm 755 -name p"),
 ("find -o or",        "touch a.c a.h; find . -maxdepth 1 \\( -name '*.c' -o -name '*.h' \\) | sort"),
 ("find -printf",      "touch pf; find . -maxdepth 1 -name pf -printf '%f\\n'"),
 ("find -print0|xargs","touch q1; find . -maxdepth 1 -name q1 -print0 | xargs -0 echo"),
 ("find missing dir",  "find /nope 2>&1 | head -1; echo rc=$?"),
 # stat formats
 ("stat -c %s",        "echo -n abc > f; stat -c %s f"),
 ("stat -c multi",     "echo -n abc > f; stat -c '%n %s %F' f"),
 ("stat -c %a",        "touch f; chmod 640 f; stat -c %a f"),
 # %U/%G are deliberately not compared: the persona is always root, and the
 # host running the test is not.
 ("stat -c %n %s",     "echo -n abcd > f; stat -c '%n %s' f"),
 ("stat --format",     "echo -n ab > f; stat --format=%s f"),
 ("stat -c %Y vs date","touch f; a=$(stat -c %Y f); b=$(date +%s); [ $((b-a)) -lt 5 ] && echo fresh"),
 # tar / gzip / base64 / checksums
 ("tar create list",   "mkdir t; echo hi > t/f; tar cf a.tar t; tar tf a.tar | sort"),
 ("tar czf list",      "mkdir t; echo hi > t/f; tar czf a.tgz t; tar tzf a.tgz | sort"),
 ("tar extract",       "mkdir t; echo hi > t/f; tar cf a.tar t; rm -rf t; tar xf a.tar; cat t/f"),
 ("tar -C",            "mkdir t o; echo hi > t/f; tar cf a.tar t; tar xf a.tar -C o; cat o/t/f"),
 ("tar -C on create",  "mkdir -p sub/z/a; echo hi > sub/z/a/f; tar czf out.tgz -C sub z; tar tzf out.tgz"),
 ("tar two operands",  "mkdir d1 d2; echo a > d1/f; echo b > d2/g; tar cf m.tar d1 d2; tar tf m.tar | sort"),
 ("tar tvf shape",     "echo hi > f; tar cf a.tar f; tar tvf a.tar | awk '{print $1, $NF}'"),
 ("gzip roundtrip",    "echo hello > g; gzip g; gunzip g.gz; cat g"),
 ("gzip -c",           "echo hello | gzip -c | gunzip -c"),
 ("zcat",              "echo hello > g; gzip g; zcat g.gz"),
 ("base64 roundtrip",  "echo hello | base64 | base64 -d"),
 ("base64 -w0",        "printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' | base64 -w0"),
 ("md5sum",            "echo -n abc | md5sum"),
 ("sha256sum",         "echo -n abc | sha256sum"),
 ("sha1sum -c",        "echo -n abc > f; sha1sum f > f.sha; sha1sum -c f.sha"),
 ("cksum",             "echo -n abc | cksum"),
 # od / xxd / dd / split / truncate
 ("od -An -tx1",       "printf 'AB' | od -An -tx1"),
 ("od -c",             "printf 'A\\n' | od -c | head -1"),
 ("dd count",          "printf 'abcdefgh' | dd bs=1 count=3 2>/dev/null"),
 ("dd skip",           "printf 'abcdefgh' | dd bs=1 skip=2 count=3 2>/dev/null"),
 ("split -b",          "printf 'abcdef' > s; split -b 2 s part_; cat part_aa part_ab part_ac"),
 ("truncate -s",       "echo hello > t2; truncate -s 2 t2; wc -c < t2"),
 # cp / mv / ln / chmod / mkdir
 ("cp -r",             "mkdir -p a/b; echo x > a/b/f; cp -r a c; cat c/b/f"),
 ("cp -p keeps mode",  "touch f; chmod 700 f; cp -p f g; stat -c %a g"),
 ("mv into dir",       "mkdir d; echo x > f; mv f d/; cat d/f"),
 ("ln hard",           "echo x > f; ln f g; cat g"),
 ("ln -sf overwrite",  "echo x > f; ln -s f l; ln -sf /etc/hostname l; readlink l"),
 ("mkdir -p nested",   "mkdir -p a/b/c && echo ok"),
 ("mkdir existing rc", "mkdir d; mkdir d 2>/dev/null; echo rc=$?"),
 ("rmdir empty",       "mkdir d; rmdir d && echo gone"),
 ("chmod symbolic",    "touch f; chmod u+x f; stat -c %a f"),
 ("chmod go-rwx",      "touch f; chmod 777 f; chmod go-rwx f; stat -c %a f"),
 ("umask affects",     "umask 077; touch f; stat -c %a f"),
 # test operators
 ("test -f -d -e",     "touch f; mkdir d; [ -f f ] && [ -d d ] && [ -e f ] && echo yes"),
 ("test -x",           "touch f; chmod +x f; [ -x f ] && echo exec"),
 ("test -s",           "touch e; echo x > ne; [ ! -s e ] && [ -s ne ] && echo sizes"),
 ("test string cmp",   "[ abc = abc ] && [ abc != abd ] && echo strcmp"),
 ("test numeric",      "[ 5 -gt 3 ] && [ 3 -le 3 ] && echo nums"),
 # Timestamps are pinned with -t rather than raced: two bare `touch` calls
 # land in the same millisecond often enough on ext4 that real bash reports
 # them equal, so the reference answer depended on scheduling, not semantics.
 ("test -nt",          "touch -t 202001010000 a; touch -t 202101010000 b; "
                       "[ b -nt a ] && echo newer"),
 # -nt/-ot/-ef were absent entirely: the operands fell through to an integer
 # comparison and every one of them answered false. Only -nt was covered, and
 # it passed on a filesystem whose timestamp granularity made real bash agree.
 ("test -nt reversed",  "touch -t 202001010000 a; touch -t 202101010000 b; "
                        "[ a -nt b ] || echo not-newer"),
 ("test -ot",           "touch -t 202001010000 a; touch -t 202101010000 b; "
                        "[ a -ot b ] && echo older"),
 ("test -nt equal",     "touch -t 202001010000 a b; [ a -nt b ] || echo not-newer"),
 # the inode number itself will never match a real filesystem's; what has
 # to match is that both names carry the same one
 ("ln shares an inode", "touch a; ln a b; "
                        "[ \"$(stat -c %i a)\" = \"$(stat -c %i b)\" ] "
                        "&& echo same-inode; stat -c '%h' a b"),
 ("ln then write",      "touch a; ln a b; echo x > a; cat b"),
 ("ln then unlink",     "touch a; ln a b; echo x > a; rm a; cat b; "
                        "stat -c '%h' b"),
 ("ln -s is not hard",  "touch a; ln -s a b; stat -c '%h' a"),
 ("test -nt absent",    "touch a; [ a -nt nosuch ] && echo newer"),
 ("test -ot absent",    "touch a; [ nosuch -ot a ] && echo older || echo no"),
 ("test -ef self",      "touch a; [ a -ef a ] && echo same"),
 ("test -ef different", "touch a b; [ a -ef b ] && echo same || echo differ"),
 ("test -ef hardlink",  "touch a; ln a b; [ a -ef b ] && echo same"),
 # realpath / readlink / basename / dirname
 ("readlink -f chain", "mkdir d; echo x > d/f; ln -s d/f l1; ln -s l1 l2; readlink -f l2 | sed 's|.*/||'"),
 ("realpath",          "mkdir d; realpath d | sed 's|.*/||'"),
 ("basename suffix",   "basename /a/b/c.txt .txt"),
 ("dirname root",      "dirname /a; dirname a; dirname /"),
 # misc encoding / text
 ("wc -c -l -w -m",    "printf 'ab cd\\nef\\n' | wc -l -w -c"),
 ("nl",                "printf 'a\\nb\\n' | nl"),
 ("paste",             "printf 'a\\nb\\n' > p1; printf '1\\n2\\n' > p2; paste p1 p2"),
 ("comm",              "printf 'a\\nb\\n' > c1; printf 'b\\nc\\n' > c2; comm c1 c2"),
 ("join",              "printf '1 a\\n2 b\\n' > j1; printf '1 x\\n2 y\\n' > j2; join j1 j2"),
 ("expand tabs",       "printf 'a\\tb\\n' | expand -t4"),
 ("fold -w",           "echo abcdef | fold -w2"),
 ("rev file",          "printf 'abc\\ndef\\n' | rev"),
 ("tac",               "printf 'a\\nb\\nc\\n' | tac"),
 ("shuf -n deterministic","printf 'a\\n' | shuf -n1"),
 ("seq",               "seq 3; seq 2 4; seq 1 2 5"),
 ("printf %s multiple","printf '%s|' a b c; echo"),
 ("date fmt",          "date -u -d @0 '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u -r 0 '+%Y-%m-%d %H:%M:%S'"),
 ("env -i",            "env -i FOO=bar sh -c 'echo $FOO'"),
 ("timeout returns",   "timeout 5 echo ok"),
 ("tee to file",       "echo hi | tee tf > /dev/null; cat tf"),
 ("tee -a",            "echo a > tf; echo b | tee -a tf >/dev/null; cat tf"),
]

def real(snippet, cwd):
    # umask 022, always. The reference host's own umask leaked into the
    # comparison: on Ubuntu, which defaults to 002 for per-user groups,
    # `touch f; chmod u+x f` gives 764 and `tar tvf` shows -rw-rw-r--, while
    # the Debian 13 persona we emulate uses 022 and gives 744 / -rw-r--r--.
    # Two of these "failures" were the dev box disagreeing with the target
    # box, not the emulator disagreeing with either.
    p = subprocess.run(["bash", "-c", "umask 022\n" + snippet],
                       capture_output=True, text=True, cwd=cwd, timeout=20)
    return p.stdout


def ours(snippet):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.cwd = "/tmp"
    sh.run("rm -rf /tmp/w; mkdir -p /tmp/w; cd /tmp/w")
    return sh.run(snippet)


def main():
    verbose = "-v" in sys.argv
    only = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else None
    ok = bad = 0
    for name, snip in CASES:
        if only and only not in name:
            continue
        with tempfile.TemporaryDirectory() as d:
            try:
                want = real(snip, d)
            except (OSError, subprocess.TimeoutExpired):
                continue
        try:
            got = ours(snip)
        except Exception as exc:                      # noqa: BLE001
            got = "<crash: %r>" % (exc,)
        if want == got:
            ok += 1
            if verbose:
                print("  ok   %-24s %r" % (name, got[:46]))
        else:
            bad += 1
            print("  DIFF %-24s %s" % (name, snip[:60]))
            print("       real %r" % want[:90])
            print("       ours %r" % got[:90])
    print()
    print("=" * 60)
    print("%d/%d match  (%d differ)" % (ok, ok + bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
