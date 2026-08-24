#!/usr/bin/env python3
"""The firewall table, and the three commands that read it.

`iptables -L`, `iptables -S` and `iptables-save` describe one table.
Two of them were right and the loudest one was not:

    iptables -A INPUT -s 1.2.3.4 -j DROP
    iptables -L INPUT -n
      DROP  all  --  0.0.0.0/0  0.0.0.0/0     <- the source is gone

-L printed a constant 0.0.0.0/0 for both addresses and nothing for the
match, so the rule an attacker had just added listed without the only
part that identifies it, while -S and iptables-save had it right. -v
printed the non-verbose header with no counters and no in/out columns,
and --line-numbers added no numbers.

Also here: nftables was claimed installed and `nft list ruleset` printed
nothing on a box whose `iptables -L` held rules. On Debian 13 iptables
*is* iptables-nft, so the two read one table and cannot disagree. The
guest has no nftables at all (dpkg "un", no /usr/sbin/nft), so the
persona no longer claims it -- inventing nft's rendering would be a
guess, and not shipping it is measurable.

Layout measured with cat -A on the guest.
"""
import sys

import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.55")
    s.exec_mode = True
    return v, s


def main():
    v, s = sh()

    # -- an empty table --------------------------------------------------------
    out = s.run("iptables -L -n")
    check("three built-in chains",
          [l for l in out.splitlines() if l.startswith("Chain")],
          ["Chain INPUT (policy ACCEPT)", "Chain FORWARD (policy ACCEPT)",
           "Chain OUTPUT (policy ACCEPT)"])
    check("the header is the guest's, to the byte",
          out.splitlines()[1],
          "target     prot opt source               destination         ")
    vout = s.run("iptables -L -n -v")
    check("-v has its own header",
          vout.splitlines()[1],
          " pkts bytes target     prot opt in     out     "
          "source               destination         ")
    check("-v puts counters on the policy line",
          vout.splitlines()[0],
          "Chain INPUT (policy ACCEPT 37 packets, 6401 bytes)")

    # -- a rule, read three ways ------------------------------------------------
    s.run("iptables -A INPUT -s 1.2.3.4 -j DROP")
    rows = [l for l in s.run("iptables -L INPUT -n").splitlines()
            if l.startswith(("DROP", "ACCEPT", "REJECT"))]
    check("-L lists the rule", len(rows), 1)
    check("...with the source it was given",
          rows[0],
          "DROP       all  --  1.2.3.4              0.0.0.0/0           ")
    check("-S gives the spec back, with the mask iptables adds",
          s.run("iptables -S INPUT").splitlines()[-1],
          "-A INPUT -s 1.2.3.4/32 -j DROP")
    check("iptables-save agrees",
          [l for l in s.run("iptables-save").splitlines()
           if l.startswith("-A")],
          ["-A INPUT -s 1.2.3.4/32 -j DROP"])
    # The three must not disagree about how many rules there are.
    check("all three see one rule",
          (len(rows),
           len([l for l in s.run("iptables -S").splitlines()
                if l.startswith("-A")]),
           len([l for l in s.run("iptables-save").splitlines()
                if l.startswith("-A")])), (1, 1, 1))

    # -- a port rule ------------------------------------------------------------
    s.run("iptables -A INPUT -p tcp --dport 2222 -j ACCEPT")
    rows = [l for l in s.run("iptables -L INPUT -n").splitlines()
            if l.startswith(("DROP", "ACCEPT"))]
    check("the port rule shows its protocol and port",
          rows[1],
          "ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0"
          "            tcp dpt:2222")
    check("-S inserts the -m match iptables implies",
          s.run("iptables -S INPUT").splitlines()[-1],
          "-A INPUT -p tcp -m tcp --dport 2222 -j ACCEPT")

    # -- the flags --------------------------------------------------------------
    numbered = s.run("iptables -L INPUT -n --line-numbers").splitlines()
    check("--line-numbers adds the num column",
          numbered[1].startswith("num  "), True)
    check("...and numbers the rules from 1",
          [l.split()[0] for l in numbered if l[:1].isdigit()], ["1", "2"])
    # The "Chain INPUT (policy ACCEPT ...)" line also contains " ACCEPT ",
    # so match on a row whose first field is a packet count.
    vrows = [l for l in s.run("iptables -L INPUT -n -v").splitlines()
             if l.split() and l.split()[0].isdigit()]
    check("-v shows in and out columns",
          vrows[0].split()[5:7], ["*", "*"])
    check("...and per-rule counters", vrows[0].split()[:2], ["0", "0"])
    check("...and still the source",
          "1.2.3.4" in vrows[0], True)
    check("-L with a chain names only that chain",
          [l for l in s.run("iptables -L INPUT -n").splitlines()
           if l.startswith("Chain")], ["Chain INPUT (policy ACCEPT)"])

    # -- deleting and flushing ---------------------------------------------------
    s.run("iptables -D INPUT -s 1.2.3.4 -j DROP")
    check("a deleted rule is gone from -L",
          "1.2.3.4" in s.run("iptables -L INPUT -n"), False)
    check("...and from -S",
          "1.2.3.4" in s.run("iptables -S"), False)
    check("the other rule survives",
          len([l for l in s.run("iptables -S INPUT").splitlines()
               if l.startswith("-A")]), 1)
    s.run("iptables -F")
    check("flush empties every chain",
          [l for l in s.run("iptables -S").splitlines()
           if l.startswith("-A")], [])
    check("...and -L shows the chains still there",
          len([l for l in s.run("iptables -L -n").splitlines()
               if l.startswith("Chain")]), 3)

    # -- the policy --------------------------------------------------------------
    s.run("iptables -P INPUT DROP")
    check("-P changes the policy -L reports",
          s.run("iptables -L INPUT -n").splitlines()[0],
          "Chain INPUT (policy DROP)")
    check("...and -S reports it too",
          s.run("iptables -S INPUT").splitlines()[0], "-P INPUT DROP")

    # -- v6 is its own table ------------------------------------------------------
    v2, s2 = sh()
    s2.run("iptables -A INPUT -s 1.2.3.4 -j DROP")
    check("an ip6tables listing does not show a v4 rule",
          "1.2.3.4" in s2.run("ip6tables -S"), False)
    check("...and the v4 one still does",
          "1.2.3.4" in s2.run("iptables -S"), True)

    # -- nftables is not installed -------------------------------------------------
    v3, s3 = sh()
    s3._err = []
    out, rc = s3.dispatch("nft", ["list", "ruleset"], "")
    check("nft is not a command here", rc, 127)
    check("...and says so", "nft: command not found" in "".join(s3._err),
          True)
    check("dpkg does not claim the package",
          "no packages found" in s3.run("dpkg -l nftables 2>&1"), True)
    check("and there is no binary on the disk",
          s3.run("test -e /usr/sbin/nft && echo y || echo n").strip(), "n")
    # The tools that *are* here still agree with the package list.
    for tool in ("iptables", "ip6tables", "iptables-save"):
        check("%s is on PATH" % tool,
              s3.run("command -v %s" % tool).strip(), "/usr/sbin/" + tool)
        check("...and dpkg owns it",
              s3.run("dpkg -S /usr/sbin/%s" % tool).strip().split(":")[0],
              "iptables")

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("fwtest2: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
