#!/usr/bin/env python3
"""iproute2's filters and output modes.

The axis: `ip` answers the same question several ways, and the answer has
to change when you narrow it. It did not.

    ip link show eth0   listed lo as well -- the device operand was
                        handled by the addr branch and by no other
    ip rule             printed the routing table, because the branch
                        that knew the answer sat after `startswith("r")`
                        and "rule" starts with "r". Dead code that reads
                        as live, the same shape as the methods found
                        shadowed by a later definition in sweeps 87 and 88
    ip route get 8.8.8.8    printed the whole table instead of resolving
                        one destination -- and that is the question a
                        loader asks to find which way out it has
    ip -j addr          ignored -j and printed the human table, so
                        `ip -j addr | jq` failed to parse on a box where
                        `ip addr` was perfect
    ip -o addr          folded whole interfaces instead of one record per
                        address
    ip maddr            printed nothing at all

Reference output measured on the guest (Debian 13, iproute2 6.x).
"""
import json
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
    s = F.Shell(v, peer="203.0.113.120")
    s.exec_mode = True
    return v, s


def main():
    v, s = sh()
    ip, gw, dev = F.LOCAL_IP, F.GATEWAY, F.IFACE

    # -- narrowing to one device actually narrows -----------------------------
    out = s.run("ip link show %s" % dev)
    check("ip link show DEV names it", out.startswith("2: %s:" % dev), True)
    check("...and not the other one", "lo:" in out, False)
    check("ip link show lo is the other one",
          s.run("ip link show lo").startswith("1: lo:"), True)
    check("both spellings agree",
          s.run("ip l s %s" % dev), s.run("ip link show %s" % dev))
    check("addr show DEV was already right",
          s.run("ip addr show %s" % dev).startswith("2: %s:" % dev), True)
    s._err = []
    _o, rc = s.dispatch("ip", ["link", "show", "nosuch0"], "")
    check("an unknown device is an error", rc, 1)
    check("...named", 'Device "nosuch0" does not exist.'
          in "".join(s._err), True)
    check("the plain form still lists both",
          len(re.findall(r"^\d+: ", s.run("ip link"), re.M)), 2)

    # -- ip rule is not ip route ----------------------------------------------
    check("ip rule prints the three default rules",
          s.run("ip rule"),
          "0:\tfrom all lookup local\n"
          "32766:\tfrom all lookup main\n"
          "32767:\tfrom all lookup default\n")
    check("...and is not the routing table",
          s.run("ip rule") == s.run("ip route"), False)
    check("ip ru is the same thing", s.run("ip ru"), s.run("ip rule"))
    check("ip route still works",
          s.run("ip route").startswith("default via %s dev %s" % (gw, dev)),
          True)

    # -- route get resolves one destination -----------------------------------
    check("a remote address goes via the gateway",
          s.run("ip route get 8.8.8.8"),
          "8.8.8.8 via %s dev %s src %s uid 0 \n    cache \n" % (gw, dev, ip))
    check("an on-link address does not",
          s.run("ip route get %s" % gw),
          "%s dev %s src %s uid 0 \n    cache \n" % (gw, dev, ip))
    check("our own address is local",
          s.run("ip route get %s" % ip),
          "local %s dev lo src %s uid 0 \n    cache <local> \n" % (ip, ip))
    check("127.0.0.1 is local too",
          s.run("ip route get 127.0.0.1").startswith("local 127.0.0.1 dev lo"),
          True)
    check("route get is one destination, not the table",
          len(s.run("ip route get 8.8.8.8").splitlines()), 2)
    # The answer has to agree with the table it came from.
    check("the gateway it names is the default route's",
          s.run("ip route get 1.1.1.1").split()[2],
          s.run("ip route").split()[2])
    check("and the source address is the one on the interface",
          s.run("ip route get 1.1.1.1").split()[6],
          s.run("ip -br -4 addr show %s" % dev).split()[2].split("/")[0])

    # -- -j is JSON -----------------------------------------------------------
    body = s.run("ip -j link")
    try:
        recs = json.loads(body)
    except ValueError:
        recs = None
    check("ip -j link parses as JSON", isinstance(recs, list), True)
    if recs:
        check("two interfaces", len(recs), 2)
        check("the names are there", [r["ifname"] for r in recs],
              ["lo", dev])
        check("the indexes are numbers", [r["ifindex"] for r in recs], [1, 2])
        check("flags are a list",
              recs[1]["flags"], ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"])
        check("the mtu is a number", recs[1]["mtu"], 1500)
        check("the mac is there", recs[1]["address"], F.ETH_MAC)
        check("operstate matches the text form", recs[1]["operstate"], "UP")
    abody = s.run("ip -j addr")
    try:
        arecs = json.loads(abody)
    except ValueError:
        arecs = None
    check("ip -j addr parses as JSON", isinstance(arecs, list), True)
    if arecs:
        check("each interface carries its addresses",
              [len(r.get("addr_info", [])) for r in arecs], [2, 2])
        info = arecs[1]["addr_info"][0]
        check("the address is the one ip -br prints", info["local"], ip)
        check("with its prefix", info["prefixlen"], F.PREFIX)
        check("and its family", info["family"], "inet")
        check("the v6 one is marked as such",
              arecs[1]["addr_info"][1]["family"], "inet6")
    # -j and the human form must describe the same box.
    check("json and text agree on the mac",
          F.ETH_MAC in s.run("ip link"), True)

    # -- -o is one record per line --------------------------------------------
    lines = s.run("ip -o addr").splitlines()
    check("ip -o addr gives one line per address", len(lines), 4)
    check("each starts with index and device",
          [l.split()[1] for l in lines], ["lo", "lo", dev, dev])
    check("the lifetime is joined with a backslash",
          all("\\" in l for l in lines), True)
    check("no link header leaks in", any("mtu" in l for l in lines), False)
    check("-4 halves it",
          len(s.run("ip -o -4 addr").splitlines()), 2)
    check("-6 gives the other half",
          len(s.run("ip -o -6 addr").splitlines()), 2)
    check("-o -4 lists only inet",
          all(" inet " in l for l in s.run("ip -o -4 addr").splitlines()),
          True)
    # ip -o link folds the whole interface, which is a different rule.
    check("ip -o link is one line per interface",
          len(s.run("ip -o link").splitlines()), 2)
    check("...and keeps the header",
          "mtu 1500" in s.run("ip -o link").splitlines()[1], True)

    # -- maddr ----------------------------------------------------------------
    m = s.run("ip maddr")
    check("ip maddr lists both interfaces",
          [l.split("\t")[1] for l in m.splitlines() if not l.startswith("\t")],
          ["lo", dev])
    check("lo has joined all-nodes", "inet  224.0.0.1" in m, True)
    check("and the v6 all-nodes group", "inet6 ff02::1" in m, True)
    check("eth0 has link-layer groups", "link  33:33:00:00:00:01" in m, True)

    # -- -br narrows too ------------------------------------------------------
    # The brief branch returned before the device operand was read, so the
    # shortest way to ask about one interface answered about both.
    check("ip -br addr show DEV is one line",
          s.run("ip -br addr show %s" % dev).count("\n"), 1)
    check("...and it is the right one",
          s.run("ip -br addr show %s" % dev).split()[0], dev)
    check("ip -br link show lo likewise",
          s.run("ip -br link show lo").split()[0], "lo")
    check("ip -br -4 addr show DEV drops the v6",
          "fe80" in s.run("ip -br -4 addr show %s" % dev), False)
    s._err = []
    _o, rc = s.dispatch("ip", ["-br", "addr", "show", "nope0"], "")
    check("an unknown device is still an error in brief mode", rc, 1)

    # -- the readers still agree with each other ------------------------------
    # Whatever narrowing is applied, the facts underneath are one set.
    check("ip -br link and ip link agree on state",
          s.run("ip -br link").splitlines()[1].split()[1], "UP")
    check("ip -br addr and ip addr agree on the address",
          s.run("ip -br addr").splitlines()[1].split()[2],
          "%s/%d" % (ip, F.PREFIX))
    check("ifconfig agrees with ip addr",
          ip in s.run("ifconfig"), True)
    check("/sys agrees on the mac",
          s.run("cat /sys/class/net/%s/address" % dev).strip(), F.ETH_MAC)
    check("/proc/net/dev lists both interfaces",
          sorted(l.split(":")[0].strip()
                 for l in s.run("cat /proc/net/dev").splitlines()[2:]
                 if ":" in l), sorted(["lo", dev]))
    check("ip neigh and arp agree on the gateway's mac",
          s.run("ip neigh").split()[4], s.run("arp -n").split()[-3])

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("iptest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
