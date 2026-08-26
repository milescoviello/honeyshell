#!/usr/bin/env python3
"""The interface: can an address, a link state or an MTU be changed?

`ip addr`, `ip link`, `ifconfig` and /sys/class/net all describe one
interface, and `ip addr add`, `ip link set` and `ifconfig` all change it.
None of them could, and two of them said so in a way nobody would
believe:

    $ ip addr add 10.1.1.5/24 dev eth0
    Device "add" does not exist.
    $ ip link set eth0 down
    Device "set" does not exist.

The verb was being read as a device name, so the box answered with an
error about a device nobody had mentioned. And net-tools took the other
route:

    $ ifconfig eth0 mtu 9000
    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
    ...the whole listing...
    $ echo $?
    0

Printed the interface back, exited 0, changed nothing -- the same shape
the routing table had one sweep ago, and `ifconfig eth0:1 10.2.2.2` did
the same.

Measured in an ip netns on a real Debian 13 box, so its own interfaces
were never touched:

    ip addr add <a>/<p> dev eth0     silent, rc 0
    ...the same address again        Error: ipv4: Address already
                                     assigned.  rc 2
    ip addr del <a>/<p> dev eth0     silent, rc 0
    ...one that is not there         Error: ipv4: Address not found. rc 2
    ip link set eth0 mtu 9000        silent, rc 0, and
                                     /sys/class/net/eth0/mtu reads 9000
    ip link set eth0 down            silent, rc 0, state DOWN,
                                     operstate down
    ...and ip route is empty         every route out of a device that is
                                     down goes with it
    ip link set nosuch up            Cannot find device "nosuch", rc 1
    as a non-root user               RTNETLINK answers: Operation not
                                     permitted, rc 2

That last consequence is the one worth having: bringing the interface
down removes the routes through it, which is the cross-check between this
sweep and the routing table.

Usage:  python3 ifacetest.py
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
    return fakeshell.Shell(vfs=fs, peer="198.51.100.21", peer_port=40777)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def addrs(sh):
    """IPv4 addresses on eth0, as `ip -br addr` lists them."""
    line = out(sh, "ip -br addr show eth0").split()
    return [w for w in line[2:] if re.match(r"^\d+\.\d+\.\d+\.\d+/", w)]


IF = getattr(fakeshell, "IFACE", "eth0")
PRIMARY = "%s/%d" % (fakeshell.LOCAL_IP, fakeshell.PREFIX)
S = shell()

# ------------------------------------------------------------ adding one
check("the interface starts with its own address", addrs(S), [PRIMARY])
check("ip addr add is silent",
      out(S, "ip addr add 10.1.1.5/24 dev %s 2>&1" % IF), "",
      'it answered \'Device "add" does not exist.\' -- the verb was being '
      "read as a device name")
check("...and the address is there", addrs(S), [PRIMARY, "10.1.1.5/24"])
check("ip addr show lists it",
      "inet 10.1.1.5/24" in out(S, "ip addr show %s" % IF), True)
check("ifconfig lists it",
      bool(re.search(r"inet 10\.1\.1\.5\s", out(S, "ifconfig %s" % IF))),
      True, "one interface, and the two commands that describe it")
check("ip -o addr counts it",
      len([l for l in out(S, "ip -o addr show %s" % IF).splitlines()
           if l.strip()]), 3)

check("adding it twice",
      out(S, "ip addr add 10.1.1.5/24 dev %s 2>&1; echo rc=$?"
          % IF).strip().splitlines(),
      ["Error: ipv4: Address already assigned.", "rc=2"],
      "iproute2 words this one 'Error: ipv4:', not RTNETLINK")
check("ip addr del is silent",
      out(S, "ip addr del 10.1.1.5/24 dev %s 2>&1" % IF), "")
check("...and it is gone", addrs(S), [PRIMARY])
check("deleting it again",
      out(S, "ip addr del 10.1.1.5/24 dev %s 2>&1; echo rc=$?"
          % IF).strip().splitlines(),
      ["Error: ipv4: Address not found.", "rc=2"])

# ------------------------------------------------------------------ mtu
M = shell()
check("ip link set mtu is silent",
      out(M, "ip link set %s mtu 9000 2>&1" % IF), "",
      'it answered \'Device "set" does not exist.\'')
check("...ip link shows it",
      out(M, "ip -o link show %s | grep -o 'mtu [0-9]*'" % IF).strip(),
      "mtu 9000")
check("...ifconfig shows it",
      "mtu 9000" in out(M, "ifconfig %s" % IF).splitlines()[0], True)
check("...and so does sysfs",
      out(M, "cat /sys/class/net/%s/mtu" % IF).strip(), "9000",
      "three readers of one number")
check("ifconfig can set it too",
      (out(M, "ifconfig %s mtu 1500 2>&1" % IF),
       out(M, "cat /sys/class/net/%s/mtu" % IF).strip()), ("", "1500"),
      "net-tools is silent for this, and it printed the whole listing")

# --------------------------------------------------------------- up/down
D = shell()
routes_up = [l for l in out(D, "ip route").splitlines() if l.strip()]
check("there are routes to start with", len(routes_up) > 0, True)
check("ip link set down is silent", out(D, "ip link set %s down 2>&1" % IF),
      "")
check("...ip link says DOWN",
      "state DOWN" in out(D, "ip link show %s" % IF), True)
check("...and drops LOWER_UP",
      "LOWER_UP" in out(D, "ip link show %s" % IF), False)
check("...operstate agrees",
      out(D, "cat /sys/class/net/%s/operstate" % IF), "down\n",
      "with the newline: every file under /sys/class/net ends with one, "
      "and without it `cat operstate` runs into the next command's output")
check("...ifconfig drops RUNNING",
      "RUNNING" in out(D, "ifconfig %s" % IF).splitlines()[0], False)
check("...ip -br addr says DOWN",
      out(D, "ip -br addr show %s" % IF).split()[1], "DOWN")
check("...and the routes through it are gone",
      [l for l in out(D, "ip route").splitlines() if l.strip()], [],
      "a route out of a device that is down is not a route -- measured in "
      "a namespace whose only device was brought down")
check("bringing it back up", out(D, "ip link set %s up 2>&1" % IF), "")
check("...and it is UP again",
      out(D, "ip -br addr show %s" % IF).split()[1], "UP")
check("ifconfig down works too",
      (out(D, "ifconfig %s down 2>&1" % IF),
       out(D, "cat /sys/class/net/%s/operstate" % IF).strip()), ("", "down"))

# ------------------------------------------------------- the old alias form
A = shell()
check("ifconfig eth0:1 adds an address",
      (out(A, "ifconfig %s:1 10.2.2.2 netmask 255.255.255.0 2>&1" % IF),
       "10.2.2.2/24" in addrs(A)), ("", True),
      "it printed the listing and added nothing")
check("...and ip addr sees what ifconfig added",
      "inet 10.2.2.2/24" in out(A, "ip addr show %s" % IF), True,
      "one interface, whichever command wrote to it")

# ------------------------------------------------------------- the errors
E = shell()
check("an unknown device, link",
      out(E, "ip link set nosuch up 2>&1; echo rc=$?").strip().splitlines(),
      ['Cannot find device "nosuch"', "rc=1"])
check("an unknown device, addr",
      out(E, "ip addr add 10.3.3.3/24 dev nosuch 2>&1; echo rc=$?"
          ).strip().splitlines(),
      ['Cannot find device "nosuch"', "rc=1"])
U = shell()
U.uid = 1000
check("a normal user may not change the mtu",
      out(U, "ip link set %s mtu 9000 2>&1; echo rc=$?" % IF
          ).strip().splitlines(),
      ["RTNETLINK answers: Operation not permitted", "rc=2"])
check("...nor add an address",
      out(U, "ip addr add 10.1.1.5/24 dev %s 2>&1; echo rc=$?" % IF
          ).strip().splitlines(),
      ["RTNETLINK answers: Operation not permitted", "rc=2"])
check("...and nothing moved",
      (addrs(U), out(U, "cat /sys/class/net/%s/mtu" % IF).strip()),
      ([PRIMARY], "1500"))

# Showing still works, and one source's changes are its own.
P, Q = shell(), shell()
out(P, "ip addr add 10.4.4.4/24 dev %s" % IF)
check("a change is per-source",
      ("10.4.4.4/24" in addrs(P), "10.4.4.4/24" in addrs(Q)), (True, False))
check("ip link show still lists both devices",
      len([l for l in out(Q, "ip link").splitlines()
           if re.match(r"^\d+: ", l)]), 2)
check("ip addr show <dev> still filters",
      len([l for l in out(Q, "ip addr show %s" % IF).splitlines()
           if re.match(r"^\d+: ", l)]), 1)

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
