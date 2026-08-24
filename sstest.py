#!/usr/bin/env python3
"""ss's extended columns and filters, against the socket underneath.

`ss -tulpn` is the single most common thing an attacker types on a box
they have just taken, and the detail flags are what they reach for next.
Every one of them was accepted and ignored:

    ss -e    no uid, ino, sk or cgroup -- the columns the flag exists for
    ss -o    no timer:(keepalive,...)
    ss -m    no skmem: line
    ss -i    no congestion-control line
    ss -tlnp '( sport = :22 )'
             printed every listener, so narrowing the question did not
             narrow the answer -- the same shape as `ip link show eth0`
             listing lo in sweep 92
    ss -tan state established
             kept the State column, which ss drops when the filter names
             exactly one state, so `... | awk '{print $1}'` read "ESTAB"
             where a real box gives the receive queue

And the number that matters most: `ss -e`'s ino must be the one
/proc/<pid>/fd and /proc/net/tcp already give for that socket, because
joining them on it is the whole basis of socket-to-process attribution.

Reference output measured on the guest (Debian 13, iproute2 6.x).
"""
import re
import sys

import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.44")
    s.exec_mode = True
    return v, s


def rows(text):
    """Data rows -- not the header, not the indented detail lines."""
    return [l for l in text.splitlines()
            if l.strip() and not l.startswith(("State", "Recv-Q", "\t"))]


def main():
    v, s = sh()

    # -- -e: uid, inode, cookie, cgroup ---------------------------------------
    line = [l for l in rows(s.run("ss -tlnpe")) if ":22 " in l][0]
    for field in ("uid:", "ino:", "sk:", "cgroup:"):
        check("ss -e has %s" % field, field in line, True)
    check("...and the <-> terminator", line.rstrip().endswith("<->"), True)
    check("the cgroup is the unit's",
          re.search(r"cgroup:(\S+)", line).group(1),
          "/system.slice/ssh.service")
    check("the uid is the one ps gives the process",
          re.search(r"uid:(\d+)", line).group(1), "0")
    # A daemon that does not run as root says so.
    dns = [l for l in rows(s.run("ss -ulnpe")) if "systemd-resolve" in l]
    if dns:
        check("a non-root listener has its own uid",
              re.search(r"uid:(\d+)", dns[0]).group(1) != "0", True)
    check("without -e the columns are absent",
          "ino:" in s.run("ss -tlnp"), False)

    # -- the inode is *the* inode ----------------------------------------------
    ino = re.search(r"ino:(\d+)", line).group(1)
    check("/proc/<pid>/fd names the same socket",
          any("socket:[%s]" % ino in l
              for l in s.run("ls -l /proc/412/fd").splitlines()), True)
    check("/proc/net/tcp names it too",
          any(f.split()[9] == ino
              for f in s.run("cat /proc/net/tcp").splitlines()[1:]
              if len(f.split()) > 9), True)
    # ...and the same again for a connected socket, which uses the other
    # inode function.
    est = [l for l in rows(s.run("ss -tne")) if "ESTAB" in l]
    check("the established socket is listed", len(est), 1)
    eino = re.search(r"ino:(\d+)", est[0]).group(1)
    check("its inode differs from the listener's", eino == ino, False)
    check("and /proc/net/tcp has that one as well",
          any(f.split()[9] == eino
              for f in s.run("cat /proc/net/tcp").splitlines()[1:]
              if len(f.split()) > 9), True)

    # -- -o, -m, -i -------------------------------------------------------------
    out = s.run("ss -tno")
    check("ss -o gives the established socket a timer",
          bool(re.search(r"timer:\(keepalive,\d+min,0\)", out)), True)
    check("...and a listener does not get one",
          "timer:" in s.run("ss -tlno"), False)

    out = s.run("ss -tnm")
    mem = [l for l in out.splitlines() if l.startswith("\t")]
    check("ss -m adds one indented line per socket", len(mem), 1)
    check("...in skmem form",
          bool(re.match(r"^\t skmem:\(r\d+,rb\d+,t\d+,tb\d+,f\d+,w\d+,"
                        r"o\d+,bl\d+,d\d+\)$", mem[0])), True)
    check("without -m there is no such line",
          any(l.startswith("\t") for l in s.run("ss -tn").splitlines()),
          False)

    out = s.run("ss -tni")
    info = [l for l in out.splitlines() if l.startswith("\t")]
    check("ss -i adds a tcp_info line", len(info), 1)
    check("...naming the congestion control",
          info[0].strip().startswith("cubic "), True)
    for field in ("rto:", "rtt:", "mss:", "cwnd:", "bytes_sent:",
                  "bytes_acked:", "segs_out:", "minrtt:"):
        check("tcp_info has %s" % field, field in info[0], True)
    check("the two detail flags compose",
          len([l for l in s.run("ss -tnmi").splitlines()
               if l.startswith("\t")]), 2)

    # -- filters filter ---------------------------------------------------------
    only22 = rows(s.run("ss -tlnp '( sport = :22 )'"))
    check("a sport filter returns one socket", len(only22), 1)
    check("...and it is port 22", ":22 " in only22[0], True)
    check("a different port returns that one",
          [":80 " in l for l in rows(s.run("ss -tlnp '( sport = :80 )'"))],
          [True])
    check("a port nothing listens on returns nothing",
          rows(s.run("ss -tlnp '( sport = :9999 )'")), [])
    check("dport selects on the peer",
          len(rows(s.run("ss -tn '( dport = :%d )'" % s.peer_port))), 1)
    check("dst selects on the peer address",
          len(rows(s.run("ss -tn '( dst = 203.0.113.44 )'"))), 1)
    check("...and a dst nobody is talking to returns nothing",
          rows(s.run("ss -tn '( dst = 10.9.9.9 )'")), [])
    check("no filter still lists everything",
          len(rows(s.run("ss -tln"))) > 1, True)

    # -- a single-state filter drops the State column ---------------------------
    est_out = s.run("ss -tan state established")
    check("the header loses State",
          est_out.splitlines()[0].split()[:2], ["Recv-Q", "Send-Q"])
    check("...and so do the rows",
          rows(est_out)[0].split()[0], "0")
    check("the plain form keeps it",
          s.run("ss -tan").splitlines()[0].split()[0], "State")
    check("...and its rows lead with the state",
          rows(s.run("ss -tan"))[0].split()[0] in ("LISTEN", "ESTAB",
                                                   "UNCONN"), True)

    # -- and the rest of the box still agrees -----------------------------------
    check("ss and netstat report the same listeners",
          sorted(l.split()[3].rsplit(":", 1)[-1] for l in rows(s.run("ss -tln"))),
          sorted(l.split()[3].rsplit(":", 1)[-1]
                 for l in s.run("netstat -tln").splitlines()
                 if l.startswith("tcp")))
    check("-H drops the header",
          len(s.run("ss -H -tln").splitlines()),
          len(s.run("ss -tln").splitlines()) - 1)
    check("the process column names a pid ps knows",
          all(pid in s.run("ps -eo pid --no-headers").split()
              for pid in re.findall(r"pid=(\d+)", s.run("ss -tlnp"))), True)

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("sstest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
