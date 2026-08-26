#!/usr/bin/env python3
"""The routing table: four readers, two writers, and nothing stuck.

`ip route`, `route -n`, `netstat -rn` and /proc/net/route all describe one
table, and `ip route add/del` and `route add/del` all change it. Every
reader was a separate literal and every writer printed the table back and
returned 0:

    ip route add 10.99.0.0/16 via 172.31.16.1
    default via 172.31.16.1 dev eth0 proto dhcp src ... metric 100
    172.31.16.0/20 dev eth0 proto kernel scope link src ... metric 100
    $ echo $?
    0
    $ ip route | grep -c 10.99
    0

Two failures in one line. The route was not added -- setting one up is
what somebody does before pivoting, and `ip route` is the next thing they
type -- and the command *printed the whole table*, where the real one is
silent. `ip route add X && echo ok` came back with the routing table in
front of the ok.

`ip route del default` did the same, so the default gateway could not be
removed. `route add -net ... gw ...` did the same. `ip route flush cache`
did the same.

Measured in a network namespace on a real Debian 13 box, so the reference
host's own routing was never touched:

    ip route add <net> via <gw>        silent, rc 0
    ...the same route again            RTNETLINK answers: File exists, rc 2
    ...a second default                RTNETLINK answers: File exists, rc 2
    ip route del <net>                 silent, rc 0
    ...one that is not there           RTNETLINK answers: No such process,
                                       rc 2 -- ESRCH, not ENOENT
    add via an unreachable gateway     Error: Nexthop has invalid gateway.
                                       rc 2
    ip route flush cache               silent, rc 0
    as a non-root user                 RTNETLINK answers: Operation not
                                       permitted, rc 2

and /proc/net/route gains a row whose fields are little-endian:
10.99.0.0 is 0000630A and a /16 mask is 0000FFFF.

`ip route get` has to follow the table too. With `10.99.0.0/16 via
172.31.16.9` installed, the real one answers "10.99.5.5 via 172.31.16.9";
ours answered "via 172.31.16.1" -- the default -- so the route existed in
every listing and changed nothing about where a packet would go, which is
the one question that command is for.

Usage:  python3 routetest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.19", peer_port=40666)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def dests(sh):
    """Destinations as `ip route` lists them."""
    return [l.split()[0] for l in out(sh, "ip route").splitlines() if l.strip()]


def proc_route(sh):
    """(dest, gw, mask) hex triples from /proc/net/route."""
    rows = []
    for line in out(sh, "cat /proc/net/route").splitlines()[1:]:
        f = line.split()
        if len(f) >= 8:
            rows.append((f[1], f[2], f[7]))
    return rows


GW = getattr(fakeshell, "GATEWAY", "172.31.16.1")
S = shell()

# --------------------------------------------------------- adding one works
base = dests(S)
check("the table starts with a default and a link route", base,
      ["default", "%s/%d" % (fakeshell.SUBNET, fakeshell.PREFIX)])
check("ip route add is silent",
      out(S, "ip route add 10.99.0.0/16 via %s 2>&1" % GW), "",
      "it printed the whole routing table, which the real one never does")
check("...and exits 0",
      out(S, "ip route add 10.98.0.0/16 via %s >/dev/null 2>&1; echo $?"
          % GW).strip(), "0")
check("...and the route is there", "10.99.0.0/16" in dests(S), True,
      "rc 0 and nothing added is the shape this whole sweep is about")
check("...in the order iproute2 prints",
      dests(S)[0], "default",
      "default first, then by prefix")

# ------------------------------------------------- and every reader sees it
check("route -n sees it",
      bool(re.search(r"^10\.99\.0\.0\s+%s\s+255\.255\.0\.0\s+UG"
                     % re.escape(GW), out(S, "route -n"), re.M)), True)
check("netstat -rn sees it",
      bool(re.search(r"^10\.99\.0\.0\s+%s\s+255\.255\.0\.0\s+UG"
                     % re.escape(GW), out(S, "netstat -rn"), re.M)), True,
      "this was the last reader still printing a literal")
check("/proc/net/route sees it",
      ("0000630A", "%08X" % 0x01101FAC, "0000FFFF") in proc_route(S), True,
      "little-endian: 10.99.0.0 is 0000630A and a /16 mask is 0000FFFF")
check("every reader has the same number of rows",
      len({len(dests(S)),
           len([l for l in out(S, "route -n").splitlines()[2:] if l.strip()]),
           len([l for l in out(S, "netstat -rn").splitlines()[2:]
                if l.strip()]),
           len(proc_route(S))}), 1)

# --------------------------------------------------------------- the errors
check("adding it twice",
      out(S, "ip route add 10.99.0.0/16 via %s 2>&1; echo rc=$?"
          % GW).strip().splitlines(),
      ["RTNETLINK answers: File exists", "rc=2"])
check("a second default",
      out(S, "ip route add default via 172.31.16.2 2>&1; echo rc=$?"
          ).strip().splitlines(),
      ["RTNETLINK answers: File exists", "rc=2"])
check("an unreachable gateway",
      out(S, "ip route add 10.77.0.0/16 via 192.0.2.9 2>&1; echo rc=$?"
          ).strip().splitlines(),
      ["Error: Nexthop has invalid gateway.", "rc=2"],
      "a route through an address the box cannot reach is not a route")
check("...and it was not added", "10.77.0.0/16" in dests(S), False)

# ---------------------------------------------------------------- deleting
check("ip route del is silent",
      out(S, "ip route del 10.99.0.0/16 2>&1"), "")
check("...and it is gone", "10.99.0.0/16" in dests(S), False)
check("...from /proc/net/route too",
      any(r[0] == "0000630A" for r in proc_route(S)), False)
check("deleting it again",
      out(S, "ip route del 10.99.0.0/16 2>&1; echo rc=$?"
          ).strip().splitlines(),
      ["RTNETLINK answers: No such process", "rc=2"],
      "ESRCH, not ENOENT -- the two read very differently to someone "
      "checking whether their change took")

D = shell()
check("the default can be removed",
      out(D, "ip route del default 2>&1"), "")
check("...and it is gone", "default" in dests(D), False)
check("...and then re-added",
      (out(D, "ip route add default via %s 2>&1" % GW),
       "default" in dests(D)), ("", True))

# ------------------------------------------------------- net-tools writes too
N = shell()
check("route add is silent",
      out(N, "route add -net 10.50.0.0/16 gw %s 2>&1" % GW), "",
      "it printed the table, exactly as ip route add did")
check("...and ip route sees what route added", "10.50.0.0/16" in dests(N),
      True, "one table, whichever command wrote to it")
check("route del removes it",
      (out(N, "route del -net 10.50.0.0/16 gw %s 2>&1" % GW),
       "10.50.0.0/16" in dests(N)), ("", False))

# ------------------------------------------------------------ ip route get
G = shell()
check("get uses the default", out(G, "ip route get 8.8.8.8").split()[2], GW)
out(G, "ip route add 10.99.0.0/16 via 172.31.16.9")
check("get follows a more specific route",
      out(G, "ip route get 10.99.5.5").split()[2], "172.31.16.9",
      "it answered with the default gateway, so the route changed every "
      "listing and nothing about where a packet goes")
check("...and a longer prefix wins",
      (out(G, "ip route add 10.99.5.0/24 via 172.31.16.20"),
       out(G, "ip route get 10.99.5.5").split()[2]), ("", "172.31.16.20"))
check("an on-link address has no via",
      "via" in out(G, "ip route get 172.31.24.90"), False)
check("with no table at all",
      (out(G, "ip route flush"),
       out(G, "ip route get 8.8.8.8 2>&1; echo rc=$?").strip().splitlines()),
      ("", ["RTNETLINK answers: Network is unreachable", "rc=2"]))

# ------------------------------------------------------------- and the rest
F = shell()
check("flush cache is silent and changes nothing",
      (out(F, "ip route flush cache 2>&1"), dests(F)), ("", base),
      "flushing the cache is not flushing the table")
check("ip rule still answers",
      len([l for l in out(F, "ip rule list").splitlines() if l.strip()]), 3)

U = shell()
U.uid = 1000
check("a normal user may not add a route",
      out(U, "ip route add 10.99.0.0/16 via %s 2>&1; echo rc=$?"
          % GW).strip().splitlines(),
      ["RTNETLINK answers: Operation not permitted", "rc=2"])
check("...and the table did not move", dests(U), base)

# One source's routes are its own.
A, B = shell(), shell()
out(A, "ip route add 10.99.0.0/16 via %s" % GW)
check("a route is per-source",
      ("10.99.0.0/16" in dests(A), "10.99.0.0/16" in dests(B)), (True, False))

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
