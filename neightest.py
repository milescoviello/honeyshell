#!/usr/bin/env python3
"""The neighbour table: four readers, two ways to change it.

`arp -a`, `arp -n`, `ip neigh` and /var/../proc/net/arp all describe one
table, and `arp -d` and `ip neigh flush` both change it. Each reader was a
separate literal that printed the gateway unconditionally, so:

    arp -d 172.31.16.1     printed the whole table back and deleted nothing
    ip neigh flush dev eth0  did nothing at all
    arp -a                 printed the Linux table, not the BSD format

Flushing ARP is what someone does around moving laterally, and checking it
took is one command. A table that cannot be emptied answers that check with
a flat contradiction: the delete "succeeded" and the entry is still in all
four readers.

Measured on debian:trixie with net-tools 2.10 and iproute2, in a container
with NET_ADMIN so the deletes really happen:

    arp -a          ? (172.17.0.1) at e6:75:0f:1a:3a:63 [ether] on eth0
    arp -n          Address  HWtype  HWaddress  Flags Mask  Iface (table)
    arp             the table -- bare arp is -n, not -a
    ip neigh        172.17.0.1 dev eth0 lladdr e6:75:0f:1a:3a:63 REACHABLE
                    ...with a trailing space, which `cat -A` shows as
                    "REACHABLE $"
    arp -d <entry>          silent, rc 0
    arp -d <on-subnet miss> No ARP entry for 172.17.0.99      rc 0
    arp -d <no route>       SIOCDARP(dontpub): Network is unreachable  rc 0
    ip neigh flush dev eth0 silent, rc 0

and with the table empty, `arp -n`, `arp -a` and `ip neigh` print **nothing
at all** -- not even a header -- while /proc/net/arp keeps its header row.
That asymmetry is easy to get wrong in the direction of printing a lonely
header, which no version of net-tools does.

Note that `arp -d` exits 0 even when it fails. That is net-tools, not a
mistake here, and a script branching on its status learns nothing.

Usage:  python3 neightest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []
MAC = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})")


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    return fakeshell.Shell(fakeshell.VFS(), peer="203.0.113.9",
                           peer_port=44321)


def gw_of(s):
    m = re.search(r"default via (\S+)", s.run("ip route"))
    return m.group(1) if m else ""


def readers(s):
    return {"arp -a": s.run("arp -a"), "arp -n": s.run("arp -n"),
            "arp": s.run("arp"), "ip neigh": s.run("ip neigh"),
            "proc": s.run("cat /proc/net/arp")}


def main():
    s = sh()
    gw = gw_of(s)
    check("there is a default gateway to have a neighbour for", bool(gw), True)

    # -- the formats are different, and each is its own -----------------------
    r = readers(s)
    check("arp -a is BSD format",
          r["arp -a"].strip(), "? (%s) at %s [ether] on eth0"
          % (gw, MAC.search(r["arp -a"]).group(1)
             if MAC.search(r["arp -a"]) else "?"))
    check("arp -n is the table", r["arp -n"].startswith("Address "), True)
    check("bare arp is the table too, not BSD",
          r["arp"].startswith("Address "), True)
    check("-a and -n really do differ",
          r["arp -a"] == r["arp -n"], False)
    check("arp -an is still BSD", s.run("arp -an").startswith("? ("), True)

    check("ip neigh has the trailing space iproute2 prints",
          s.run("ip neigh").rstrip("\n").endswith("REACHABLE "), True)

    # -- but they describe one table ------------------------------------------
    macs = {k: (MAC.search(v).group(1) if MAC.search(v) else None)
            for k, v in r.items()}
    check("every reader names a MAC", all(macs.values()), True)
    check("...and it is the same one", len(set(macs.values())), 1)
    check("every reader names the gateway",
          all(gw in v for v in r.values()), True)

    # -- deleting it empties all four ----------------------------------------
    out = s.run("arp -d %s" % gw)
    check("arp -d is silent", out, "")
    check("...and exits 0", s.run("arp -d %s; echo $?" % gw).strip()
          .splitlines()[-1], "0")
    r = readers(s)
    check("arp -n prints nothing at all, not a lone header",
          r["arp -n"], "")
    check("arp -a prints nothing", r["arp -a"], "")
    check("ip neigh prints nothing", r["ip neigh"], "")
    check("/proc/net/arp keeps its header",
          r["proc"].strip(), "IP address       HW type     Flags       "
          "HW address            Mask     Device")
    check("...and has no rows under it",
          len([l for l in r["proc"].splitlines() if l.strip()]), 1)

    # -- the failure messages -------------------------------------------------
    s = sh()
    onsub = s.run("arp -d 172.31.16.55 2>&1").strip()
    check("deleting an on-subnet address with no entry says so",
          onsub, "No ARP entry for 172.31.16.55")
    off = s.run("arp -d 10.99.99.99 2>&1").strip()
    check("deleting an unroutable address is the raw ioctl failure",
          off, "SIOCDARP(dontpub): Network is unreachable")
    check("...and both still exit 0, as net-tools does",
          s.run("arp -d 10.99.99.99 >/dev/null 2>&1; echo $?").strip(), "0")
    check("neither of those removed the real entry",
          gw in s.run("arp -n"), True)

    # -- ip neigh flush -------------------------------------------------------
    s = sh()
    check("flush is silent", s.run("ip neigh flush dev eth0"), "")
    r = readers(s)
    check("flush empties ip neigh", r["ip neigh"], "")
    check("...and arp sees the same", r["arp -n"], "")
    check("...and so does /proc",
          len([l for l in r["proc"].splitlines() if l.strip()]), 1)

    # -- ip neigh del ---------------------------------------------------------
    s = sh()
    check("ip neigh del is silent",
          s.run("ip neigh del %s dev eth0" % gw), "")
    check("...and it is gone from arp too", s.run("arp -a"), "")
    check("deleting a neighbour that is not there is an RTNETLINK error",
          s.run("ip neigh del 10.0.0.5 dev eth0 2>&1").strip(),
          "RTNETLINK answers: No such file or directory")

    # -- one table, whichever door you change it through ----------------------
    # The point of the sweep: a mutation through either tool has to be
    # visible through both, and through /proc.
    for how in ("arp -d %s", "ip neigh del %s dev eth0"):
        s = sh()
        before = readers(s)
        check("%s: the entry is there first" % how.split()[0],
              all(gw in v for v in before.values()), True)
        s.run(how % gw)
        after = readers(s)
        check("%s: gone from every reader" % how.split()[0],
              [k for k, v in after.items() if gw in v], [])

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("neightest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
