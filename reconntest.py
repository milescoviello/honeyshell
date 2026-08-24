#!/usr/bin/env python3
"""Does the box tell the same story when the attacker comes back?

Every source IP gets its own filesystem, persisted as a replay journal in
/var/lib/honeypot/fsstate and reloaded on the next connection. That journal
is the only thing standing between a returning attacker and a box that has
forgotten what they did. 203.0.113.46 dropped /root/filter on 2026-08-21 and
again at 04:18 on 2026-08-24; hosts like it reconnect constantly, so the
round trip is exercised far more often than any single session is.

Nothing tested it. The invariant needs no reference machine, because a real
box satisfies it trivially: run a session, save, reload, and every command
that reports on a file must answer exactly as it did before. Anything that
changes is something an attacker can notice for free.

Five defects it froze:

  * the "w" entry carried path, bytes and mode -- no clocks. Every file an
    attacker dropped came back stamped with the moment of their *next*
    login, and all of them with the same one, since a replay is a single
    instant. `ls -lt /root` showed the payload as brand new on a box
    claiming 43 days of uptime. Worse, `touch -d` had its own entry and did
    survive, so backdating a file made its timestamp durable and leaving it
    alone did not.
  * mkdir's mode was not recorded, so `mkdir -m 700 /var/tmp/.stage` came
    back 0755 while `mkdir` followed by `chmod 700` came back 0700 -- two
    routes to one directory, one of which quietly opened it up.
  * cp -p assigned owner and times onto the node instead of calling the
    journalled setters, so the one command whose whole purpose is preserving
    metadata was the one that lost it across a reconnect.
  * tar did the same with the archived mtime: `tar xzf kit.tar.gz` then
    reconnect turned a 2021 binary into one made today.
  * useradd -m did the same with the home directory, so the account came
    back in /etc/passwd with its home owned by root at 0755 -- a user listed
    on the box who could not write to their own home.

Known and deliberately not fixed: inode numbers are reallocated on replay,
so `ls -i` on an attacker's own file returns a different number next login.
Hard links still agree with each other and the link count is right, so the
box stays self-consistent; only the absolute value moves, and noticing costs
an attacker a recorded inode number across two sessions.

Run from ~/opsec/honeypot:  python3 -W ignore reconntest.py
"""
import base64
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

# How long the attacker stays away. Long enough that any clock the replay
# re-stamps lands visibly in the wrong place.
GAP = 7200

DROP = [
    "mkdir -p /root/.cache/sysmon",
    "chmod 700 /root/.cache/sysmon",
    "printf 'ELFPAYLOAD-STAGE1\\n' > /root/.cache/sysmon/loader",
    "chmod 4755 /root/.cache/sysmon/loader",
    "touch -d '2024-03-11 04:05:06' /root/.cache/sysmon/loader",
    "mkdir -m 700 /var/tmp/.stage",
    "printf 'second\\n' > /var/tmp/.stage/b",
    "chown deploy:deploy /var/tmp/.stage/b",
    "ln -s /root/.cache/sysmon/loader /usr/bin/sysmon",
    "printf 'hard\\n' > /tmp/orig",
    "ln /tmp/orig /tmp/link2",
    "printf 'gone\\n' > /tmp/doomed",
    "rm -f /tmp/doomed",
    "echo '* * * * * root /root/.cache/sysmon/loader' > /etc/cron.d/sysmon",
    "mkdir -p /opt/.d/deep/nest",
    "chmod 750 /opt/.d/deep",
    "printf 'base\\n' > /opt/.d/deep/nest/f",
    "printf 'more\\n' >> /opt/.d/deep/nest/f",
    "chmod 600 /opt/.d/deep/nest/f",
    "printf 'rewritten\\n' > /opt/.d/deep/nest/f",
    "printf 'trunc-me-please\\n' > /tmp/tr",
    "truncate -s 4 /tmp/tr",
    "printf 'own\\n' > /tmp/owned",
    "chown deploy:staff /tmp/owned",
    "head -c 8388608 /dev/zero > /tmp/bigsparse",
    "mkdir -p /tmp/tree/a/b",
    "printf 'x\\n' > /tmp/tree/a/b/leaf",
    "rm -rf /tmp/tree",
    "printf 'k\\n' > /tmp/h1",
    "ln /tmp/h1 /tmp/h2",
    "rm -f /tmp/h1",
    "mkdir -p /root/.ssh",
    "chmod 700 /root/.ssh",
    "echo 'ssh-rsa AAAAKEY attacker@evil' > /root/.ssh/authorized_keys",
    "chmod 600 /root/.ssh/authorized_keys",
    "install -m 4755 /tmp/tr /usr/local/bin/suid",
    "cp -p /tmp/owned /tmp/copy",
    "touch -d '2019-06-05 01:02:03' /tmp/stomped",
    "mkdir -p /tmp/src/bin",
    "printf 'payload\\n' > /tmp/src/bin/run",
    "chmod 4755 /tmp/src/bin/run",
    "touch -d '2021-02-03 04:05:06' /tmp/src/bin/run",
    "cd /tmp/src && tar czf /tmp/kit.tar.gz bin",
    "mkdir -p /opt/unpacked && cd /opt/unpacked && tar xzf /tmp/kit.tar.gz",
    "cd /",
    "useradd -m -s /bin/bash svcacct",
    "printf 'k\\n' > /home/svcacct/.marker",
    "systemctl stop nginx",
]

# Everything a returning attacker might use to look at what they left.
QUERIES = [
    "ls -l /root/.cache/sysmon/loader",
    "ls -ld /root/.cache/sysmon",
    "ls -ld /var/tmp/.stage",
    "ls -l /var/tmp/.stage/b",
    "stat -c '%n %s %a %U:%G %Y %X' /root/.cache/sysmon/loader",
    "stat -c '%n %s %a %U:%G' /root/.cache/sysmon",
    "stat -c '%n %s %a %U:%G' /var/tmp/.stage",
    "stat -c '%n %s %a %U:%G' /var/tmp/.stage/b",
    "stat -c '%n %h' /tmp/link2",
    "md5sum /root/.cache/sysmon/loader /var/tmp/.stage/b /tmp/orig",
    "cat /etc/cron.d/sysmon",
    "readlink -f /usr/bin/sysmon",
    "ls -l /usr/bin/sysmon",
    "du -sk /root/.cache/sysmon",
    "ls /tmp/doomed",
    "find /root/.cache -type f",
    "ls -a /var/tmp/.stage",
    "ls -1 /etc/cron.d",
    "ls -l /opt/.d/deep/nest/f",
    "stat -c '%n %s %a %U:%G' /opt/.d/deep/nest/f",
    "cat /opt/.d/deep/nest/f",
    "stat -c '%n %a' /opt/.d /opt/.d/deep /opt/.d/deep/nest",
    "stat -c '%n %s' /tmp/tr",
    "cat /tmp/tr",
    "stat -c '%n %s %a %U:%G' /tmp/owned",
    "cat /tmp/owned",
    "ls -l /tmp/bigsparse",
    "stat -c '%n %s %b' /tmp/bigsparse",
    "du -sk /tmp/bigsparse",
    "ls -d /tmp/tree",
    "find /tmp/tree",
    "stat -c '%n %h' /tmp/h2",
    "ls /tmp/h1",
    "cat /tmp/h2",
    "stat -c '%n %a' /root/.ssh /root/.ssh/authorized_keys",
    "cat /root/.ssh/authorized_keys",
    "stat -c '%n %s %a' /usr/local/bin/suid",
    "stat -c '%n %s %a %U:%G %Y' /tmp/copy",
    "stat -c '%n %Y' /tmp/stomped",
    "ls -lt /tmp",
    "ls -1 /opt/.d/deep/nest",
    "du -sk /opt/.d",
    "stat -c '%n %a %U:%G %Y' /opt/unpacked/bin/run",
    "stat -c '%n %a' /opt/unpacked/bin",
    "cat /opt/unpacked/bin/run",
    "ls -l /opt/unpacked/bin",
    "stat -c '%n %a %U:%G' /home/svcacct",
    "grep '^svcacct' /etc/passwd",
    "stat -c '%n %a %U:%G' /home/svcacct/.marker",
    "ls -la /root",
    "ls -la /tmp",
]


def ask(sh, q):
    del sh._err[:]
    return (sh.run(q), "".join(sh._err), sh.last_rc)


def replay(journal, gap=GAP):
    """A fresh VFS loading that journal, `gap` seconds later."""
    real = time.time
    time.time = lambda: real() + gap
    try:
        v = fs.VFS()
        v.load_journal(journal)
    finally:
        time.time = real
    return v


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0

    def check(label, got, want):
        nonlocal ok, bad
        if got == want:
            ok += 1
            if verbose:
                print("  ok    %s" % label)
        else:
            bad += 1
            print("  FAIL  %s" % label)
            print("        got  %r" % (got if not isinstance(got, str)
                                       else got[:200],))
            print("        want %r" % (want if not isinstance(want, str)
                                       else want[:200],))

    # ---- the round trip itself ------------------------------------------
    a = fs.VFS()
    sha = fs.Shell(a)
    sha.exec_mode = True
    for cmd in DROP:
        sha.run(cmd)
        time.sleep(0.004)     # so the files have distinguishable mtimes
    journal = a.dump_journal()
    before = {q: ask(sha, q) for q in QUERIES}

    shb = fs.Shell(replay(journal))
    shb.exec_mode = True
    for q in QUERIES:
        check("survives the reconnect: %s" % q, ask(shb, q), before[q])

    # ---- and it has to be idempotent ------------------------------------
    b = replay(journal)
    twice = b.dump_journal()
    check("dumping a loaded journal reproduces it", twice, journal)
    check("a loaded journal does not grow", len(twice), len(journal))
    shc = fs.Shell(replay(twice, gap=GAP * 2))
    shc.exec_mode = True
    for q in QUERIES[:12]:
        check("survives a second reconnect: %s" % q, ask(shc, q), before[q])

    # ---- journals written before the new fields still load ---------------
    # There are ~400 of these on the guest; a load that dropped them would
    # forget every actor at once.
    old = [
        ["d", "/opt/legacy", 1787000000.0],
        ["w", "/opt/legacy/loader",
         base64.b64encode(b"OLDPAYLOAD\n").decode(), 0o755],
        ["m", "/opt/legacy/loader", 0o700],
        ["l", "/usr/bin/legacysym", "/opt/legacy/loader"],
        ["t", "/opt/legacy/loader", 1700000000.0, 1700000000.0],
        ["o", "/opt/legacy/loader", 1000, 1000],
        ["r", "/tmp/legacy-gone", False],
    ]
    v = replay(old)
    sho = fs.Shell(v)
    sho.exec_mode = True
    check("pre-clock journal: contents", sho.run("cat /opt/legacy/loader"),
          "OLDPAYLOAD\n")
    check("pre-clock journal: mode and owner survive",
          sho.run("stat -c '%a %U:%G' /opt/legacy/loader").strip(),
          "700 deploy:deploy")
    check("pre-clock journal: timestomp survives",
          sho.run("stat -c '%Y' /opt/legacy/loader").strip(), "1700000000")
    check("pre-clock journal: symlink survives",
          sho.run("readlink /usr/bin/legacysym").strip(),
          "/opt/legacy/loader")
    check("pre-clock journal: length is unchanged by a reload",
          len(v.dump_journal()), len(old))

    # ---- the entries that carry the new fields ---------------------------
    w = [e for e in journal if e[0] == "w"]
    d = [e for e in journal if e[0] == "d"]
    check("every write records its clocks",
          sorted({len(e) for e in w}), [7])
    check("every mkdir records its mode",
          sorted({len(e) for e in d}), [4])
    check("every symlink records its mtime",
          sorted({len(e) for e in journal if e[0] == "l"}), [4])
    check("the journal is JSON-serialisable", _json_ok(journal), True)

    print("\nreconntest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


def _json_ok(journal):
    import json
    try:
        json.dumps({"journal": journal})
        return True
    except (TypeError, ValueError):
        return False


if __name__ == "__main__":
    sys.exit(main())
