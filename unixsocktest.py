#!/usr/bin/env python3
"""One unix socket table, read four ways.

Left over from the previous sweep as an explicit tripwire: every
`socket:[N]` a descriptor names has to be findable in a socket table. That
join is the whole basis of socket-to-process attribution -- it is what
`lsof`, `ss -p` and every incident-response runbook do with an unexpected
descriptor -- and 67 of them resolved to nothing. Each journald-managed
service holds a connected stream socket to /run/systemd/journal/stdout, and
only the single *listening* row was ever in the table.

The first attempt at this failed instructively. Writing the missing rows
straight into /proc/net/unix fixed the join and broke something worse:
`ss -xa` and `netstat -x` render from `UNIX_SOCKETS` directly, so the file
said 45 and the two commands an operator is more likely to run both said 6.
One contradiction traded for a louder one. The rows now come from
`unix_rows()`, which all three readers walk, and its extra entries are
derived from the descriptors the process publisher emitted -- so the table
cannot drift from the thing it describes.

Reference measured on the guest (Debian 13.6, systemd):

    /proc/net/unix       107 rows, 45 with a path, 62 without
    ss -xl                18 listening
    grep -c journal        15

and the kernel's own format string for the file is

    "%pK: %08X %08X %08X %04X %02X %5lu"

a 16-hex-digit pointer with the inode right-aligned in five. Ours printed a
10-digit pointer and an unpadded inode, so anything lining up columns
against a real capture was a field adrift.

Usage:  python3 unixsocktest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def box(**kw):
    fs = fakeshell.VFS()
    return fs, fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321,
                               **kw)


def proc_unix(sh):
    """[(inode, path, state_code, type_code)] from /proc/net/unix."""
    rows = []
    for line in sh.run("cat /proc/net/unix").splitlines()[1:]:
        f = line.split()
        if len(f) >= 7:
            rows.append((f[6], (f[7] if len(f) > 7 else ""), f[5], f[4]))
    return rows


def ss_unix(sh, args="-xa"):
    """`unix  STATE  Recv-Q  Send-Q  <path or *>  <inode>  <peer>`."""
    out = []
    for line in sh.run("ss %s" % args).splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[0] == "unix":
            out.append((f[5], "" if f[4] == "*" else f[4]))
    return out


def netstat_unix(sh, args="-xa"):
    """The Flags column is `[ ACC ]`, which splits into three tokens -- a
    naive field index reads the type column as the inode."""
    out = []
    pat = re.compile(r"^unix\s+\d+\s+\[[^\]]*\]\s+(\S+)\s+(\S+)"
                     r"\s+(\d+)\s*(.*)$")
    for line in sh.run("netstat %s" % args).splitlines():
        m = pat.match(line)
        if m:
            out.append((m.group(3), m.group(4).strip()))
    return out


def fd_sockets(sh):
    """Every socket inode named by a descriptor, with the pid that holds it."""
    found = []
    for pid in sh.run("ls /proc").split():
        if not pid.isdigit():
            continue
        for m in re.finditer(r"socket:\[(\d+)\]",
                             sh.run("ls -l /proc/%s/fd 2>/dev/null" % pid)):
            found.append((m.group(1), int(pid)))
    return found


def main():
    fs, sh = box()

    # -- the join that matters ----------------------------------------------
    unix = proc_unix(sh)
    tcp = set()
    for line in sh.run("cat /proc/net/tcp").splitlines()[1:]:
        f = line.split()
        if len(f) > 9:
            tcp.add(f[9])
    udp = set()
    for line in sh.run("cat /proc/net/udp").splitlines()[1:]:
        f = line.split()
        if len(f) > 9:
            udp.add(f[9])
    known = {i for i, _p, _s, _t in unix} | tcp | udp

    fds = fd_sockets(sh)
    check("descriptors do name sockets", len(fds) > 20, True)
    missing = sorted({i for i, _p in fds} - known)
    check("every socket descriptor resolves to a table row", missing, [])

    # -- and the three readers agree ----------------------------------------
    ss_all = ss_unix(sh, "-xa")
    ns_all = netstat_unix(sh, "-xa")
    check("ss -xa and /proc/net/unix have the same count",
          len(ss_all), len(unix))
    check("netstat -xa too", len(ns_all), len(unix))
    check("ss -xa reports the same inodes",
          sorted(i for i, _p in ss_all), sorted(i for i, _p, _s, _t in unix))
    check("netstat -xa reports the same inodes",
          sorted(i for i, _p in ns_all), sorted(i for i, _p, _s, _t in unix))

    # -- listening is a subset, and the named sockets are the listeners -----
    ss_l = ss_unix(sh, "-xl")
    listening = [(i, p) for i, p, st, _t in unix if st == "01"]
    check("ss -xl matches the listening rows", len(ss_l), len(listening))
    check("every listening socket has a path",
          [i for i, p in listening if not p], [])
    check("no connected socket has a path",
          [i for i, p, st, _t in unix if st != "01" and p], [])
    check("ss -xl is a subset of ss -xa",
          set(i for i, _p in ss_l) <= set(i for i, _p in ss_all), True)

    # -- the named sockets still exist on disk as sockets -------------------
    for _i, path in listening:
        if not path:
            continue
        line = sh.run("ls -ld %s" % path).strip()
        check("%s is a socket on disk" % path, line[:1], "s")

    # -- format, against the kernel's own printf ----------------------------
    raw = sh.run("cat /proc/net/unix").splitlines()
    check("the header is the kernel's", raw[0],
          "Num       RefCount Protocol Flags    Type St Inode Path")
    bad_ptr = [l for l in raw[1:]
               if not re.match(r"^[0-9a-f]{16}: ", l)]
    check("every row starts with a 16-hex-digit pointer", bad_ptr, [])
    bad_ref = [l for l in raw[1:] if l.split()[1] != "00000003"]
    check("RefCount is 3, as measured on the guest", bad_ref, [])
    # %5lu: right-aligned in five, so a 5-digit inode has one leading space
    # after the two-digit state and a 4-digit one has two.
    sample = [l for l in raw[1:] if l.split()[6].isdigit()]
    check("there are rows to check the padding on", bool(sample), True)
    for line in sample[:6]:
        ino = line.split()[6]
        check("inode %s is right-aligned in five" % ino,
              (" %5s " % ino) in line or line.rstrip().endswith(
                  " %5s" % ino) or len(ino) > 5, True)

    # -- a returning attacker's own connection is in there too --------------
    est = [l for l in sh.run("cat /proc/net/tcp").splitlines()[1:]
           if l.split()[3] == "01"]
    check("the session's own connection is ESTABLISHED in /proc/net/tcp",
          len(est) >= 1, True)
    ssn = sh.run("ss -tnp state established")
    check("ss shows it too", "203.0.113.9" in ssn, True)

    # -- the table tracks the process table ---------------------------------
    # Kill a daemon and its journal socket has to go with it, or the count
    # drifts upward every time anything changes.
    fs, sh = box()
    before = len(proc_unix(sh))
    pid = None
    for line in sh.run("ps -eo pid,comm --no-headers").splitlines():
        if line.split()[-1] == "mariadbd":
            pid = int(line.split()[0])
            break
    check("mariadbd is running", pid is not None, True)
    if pid:
        sh.run("kill -9 %d" % pid)
        after = proc_unix(sh)
        check("killing a daemon removes its socket row",
              len(after) < before, True)
        check("...and ss agrees", len(ss_unix(sh, "-xa")), len(after))
        still = [i for i, _p in fd_sockets(sh)]
        check("...and no descriptor is left naming a missing socket",
              sorted(set(still) - {i for i, _p, _s, _t in after} - tcp - udp),
              [])

    # -- rebuilding the table is not attacker state -------------------------
    # The first version wrote /proc/net/unix through write(), which
    # journals. Every reconnect then added one entry to that source's replay
    # journal, for ever, and the journal claimed the attacker had written a
    # /proc file. reconntest caught it -- "a loaded journal does not grow" --
    # but only because that invariant already existed; nothing about sockets
    # would have.
    fs = fakeshell.VFS()
    fs.load_journal([["d", "/opt/legacy", 1787000000.0],
                     ["r", "/tmp/gone", False]])
    n0 = len(fs.dump_journal())
    sh = fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321)
    check("building /proc/net/unix does not journal",
          len(fs.dump_journal()), n0)
    sh.run("kill -9 1234")          # forces another republish
    sh.run("ls /proc/net/unix > /dev/null")
    check("...and neither does rebuilding it", len(fs.dump_journal()), n0)
    check("no journal entry names a /proc path",
          [e for e in fs.dump_journal() if str(e[1]).startswith("/proc")], [])

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("unixsocktest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
