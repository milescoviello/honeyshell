#!/usr/bin/env python3
"""Does the box agree about where it is and what it is running?

The third of the coherence sweeps: timetest asks *when*, idtest asks *who*,
this one asks *where* -- addresses, routes, neighbours, listening sockets and
the daemons behind them. An attacker deciding whether to pivot reads exactly
these, and they are produced by half a dozen unrelated code paths that have
to arrive at the same answer.

Found in one pass:

  * ifconfig reported 8,200,269 RX packets and /proc/net/dev reported 912,443
    -- for the statistic ifconfig literally reads out of that file. Nine times
    apart, and the /proc counters never moved.
  * `ss -tlnp` and `netstat -tlnp` advertised 127.0.0.1:25 owned by postfix's
    master, pid 645, while nothing else on the box had heard of postfix: no
    package in dpkg, no binary on PATH, no /etc/postfix, no postfix account,
    and no such pid in ps. A listener with no software behind it.
  * systemctl called systemd-networkd, systemd-resolved and postfix inactive
    while ps was running all three.
  * timedatectl reported "NTP service: active" with no timesync daemon and no
    such unit anywhere on the box.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS = FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL %s %s" % (name, detail))


def main():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", peer_port=51234)

    # ---- netstat's own flags, which it used to answer by accident --------
    # The parser split every "-"-prefixed word into single letters, so a
    # long option was read as a bundle: `netstat --version` printed the
    # ROUTING TABLE, because there is an "r" in "version", and
    # `netstat --help` printed the listening sockets, because there is an
    # "l" in "help". Both exited 0, so nothing looked wrong.
    import helpdb
    _usage, _aflist, _ = helpdb.HELP["netstat"]
    for form in ("-V", "--version"):
        out = s.run("netstat %s 2>/dev/null" % form)
        check("netstat %s names net-tools" % form,
              out.startswith("net-tools 2.10\n"), out[:40])
        check("netstat %s is not a table" % form,
              "Kernel IP routing table" not in out
              and "Active Internet" not in out, out[:40])
    out = s.run("netstat -V 2>/dev/null")
    check("...and carries the compile-time feature lines",
          "\nAF: (inet) +UNIX" in out and "\nHW:  +ETHER" in out, out[-60:])
    check("...and the signature line",
          "Fred Baumgarten, Alan Cox" in out, out[:80])

    # --help splits its streams: usage() writes to stdout at status 0 and
    # print_aflist() writes to stderr unconditionally.
    for form in ("-h", "--help"):
        s._err[:] = []
        out = s.run("netstat %s 2>/dev/null" % form)
        err = s.run("netstat %s 2>&1 >/dev/null" % form)
        check("netstat %s prints the usage on stdout" % form,
              out == _usage, "%d bytes" % len(out))
        check("...and the family list on stderr", err.strip() == _aflist.strip(),
              "%d bytes" % len(err))
        check("...and it is not a socket table",
              "Active Internet" not in out, out[:40])

    # An unrecognised option is rc 3 -- E_OPTERR -- with everything on
    # stderr and nothing on stdout.
    out = s.run("netstat --zzz 2>/dev/null")
    err = s.run("netstat --zzz 2>&1 >/dev/null")
    rc = s.run("netstat --zzz >/dev/null 2>&1; echo $?").strip()
    check("an unknown option exits 3", rc == "3", rc)
    check("...with nothing on stdout", out == "", out[:40])
    check("...and names itself and the option",
          err.startswith("netstat: unrecognized option '--zzz'"), err[:50])
    check("...then prints the usage too", "usage: netstat" in err, err[:60])

    # The long options have to mean what their short spellings mean.
    import re as _re
    _mask = lambda t: [_re.sub(r"[0-9]+", "N", l) for l in t.split("\n")]
    for short, lng in (("-r", "--route"),
                       ("-tln", "--tcp --listening --numeric"),
                       ("-i", "--interfaces"),
                       ("-tan", "--tcp --all --numeric")):
        # Masked, because the interface counters advance between two reads
        # -- netstat -i differs from itself for the same reason.
        check("netstat %s == netstat %s" % (short, lng),
              _mask(s.run("netstat %s" % short))
              == _mask(s.run("netstat %s" % lng)), lng)
    check("--numeric-hosts is a real option",
          "unrecognized" not in s.run("netstat -tl --numeric-hosts 2>&1"))
    # ...and -4/-6 select a family instead of being ignored.
    _n = lambda c: len([l for l in s.run(c).split("\n") if l.startswith("tcp")])
    check("netstat -4 and -6 partition the table",
          (_n("netstat -tln -4"), _n("netstat -tln -6")) == (6, 1),
          "%s" % ((_n("netstat -tln -4"), _n("netstat -tln -6")),))

    # ---- and the rest of net-tools, which had the same fault ------------
    # Every one of the nine answered --help and -V by printing its own
    # table. No two of them have the same shape, which is why each is
    # pinned against the shipped binary's own output rather than a rule:
    # ifconfig --help splits 652/799 across the streams, ifconfig -V is
    # the release line alone, route -V carries a feature block that is not
    # netstat's, nameif has no -V and says so on stderr, and slattach
    # --help writes to stderr and exits 3.
    for _nm, (_wo, _we, _wrc) in sorted(helpdb.NETTOOLS_VERSION.items()):
        got_o = s.run("%s -V 2>/dev/null" % _nm)
        got_e = s.run("%s -V 2>&1 >/dev/null" % _nm)
        got_rc = s.run("%s -V >/dev/null 2>&1; echo $?" % _nm).strip()
        check("%s -V matches the binary" % _nm,
              (got_o, got_e.strip(), got_rc) == (_wo, _we.strip(), str(_wrc)),
              "o=%d/%d e=%d/%d rc=%s/%d" % (len(got_o), len(_wo),
                                            len(got_e), len(_we),
                                            got_rc, _wrc))
        _ho, _he, _hrc = helpdb.HELP[_nm]
        got_o = s.run("%s --help 2>/dev/null" % _nm)
        got_e = s.run("%s --help 2>&1 >/dev/null" % _nm)
        got_rc = s.run("%s --help >/dev/null 2>&1; echo $?" % _nm).strip()
        check("%s --help matches the binary" % _nm,
              (got_o, got_e.strip(), got_rc) == (_ho, _he.strip(), str(_hrc)),
              "o=%d/%d e=%d/%d rc=%s/%d" % (len(got_o), len(_ho),
                                            len(got_e), len(_he),
                                            got_rc, _hrc))
    # None of them may answer a help request with their own table.
    for _nm in ("ifconfig", "route", "arp"):
        for _f in ("--help", "-V"):
            _out = s.run("%s %s 2>/dev/null" % (_nm, _f))
            check("%s %s is not a table" % (_nm, _f),
                  not _out.startswith(("eth0:", "Kernel IP routing table",
                                       "Address  ")), _out[:40])
    # ...and they still do their actual jobs.
    check("ifconfig still lists eth0",
          s.run("ifconfig").startswith("eth0:"), s.run("ifconfig")[:40])
    check("route still prints the table",
          s.run("route").startswith("Kernel IP routing table"),
          s.run("route")[:40])

    # ---- one address, however you ask for it


    ipa = s.run("ip a")
    ifc = s.run("ifconfig")
    addr = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+) brd", ipa)
    check("ip a reports an eth0 address", bool(addr), ipa[:80])
    ip = addr.group(1) if addr else ""
    check("ifconfig reports the same address", "inet %s " % ip in ifc, ip)
    check("hostname -I reports the same address",
          s.run("hostname -I").split()[:1] == [ip], s.run("hostname -I").strip())
    check("ip -br a reports the same address", ip in s.run("ip -br a"))
    check("$SSH_CONNECTION names it as the local end",
          s.run("echo $SSH_CONNECTION").split()[2] == ip,
          s.run("echo $SSH_CONNECTION").strip())
    check("ip route's src is the same address",
          ("src %s" % ip) in s.run("ip route"), s.run("ip route")[:70])

    # ---- the MAC, and the link-local derived from it
    mac = re.search(r"link/ether ([0-9a-f:]{17})", ipa)
    check("ip a reports a MAC", bool(mac))
    if mac:
        check("ifconfig reports the same MAC", mac.group(1) in ifc)
        b = [int(x, 16) for x in mac.group(1).split(":")]
        # canonical IPv6 suppresses leading zeros per group, so 52:54:00:...
        # gives fe80::5054:ff:fe9a:... and not ...:00ff:...
        eui = "%x:%x:%x:%x" % ((b[0] ^ 2) << 8 | b[1], b[2] << 8 | 0xff,
                               0xfe << 8 | b[3], b[4] << 8 | b[5])
        check("the IPv6 link-local is the EUI-64 of that MAC",
              "fe80::" + eui in ipa, "expected fe80::%s" % eui)

    # ---- routing and neighbours, two commands each
    check("ip route and route -n name the same gateway",
          re.search(r"default via (\S+)", s.run("ip route")).group(1)
          in s.run("route -n"))
    gw = re.search(r"default via (\S+)", s.run("ip route")).group(1)
    check("the gateway is inside the interface's subnet",
          gw.rsplit(".", 2)[0] == ip.rsplit(".", 2)[0], "%s vs %s" % (gw, ip))
    check("arp -a and ip neigh agree about the gateway",
          gw in s.run("arp -a") and gw in s.run("ip neigh"))
    # Four readers of one table, and `arp -a` is the BSD format -- the MAC
    # comes after "at", not after "ether". This pulled it with a regex for
    # the *tabular* layout, so it was quietly pinning the wrong output shape
    # for `arp -a` as well as checking the MAC.
    macs = {}
    for label, text in (("arp -a", s.run("arp -a")),
                        ("arp -n", s.run("arp -n")),
                        ("ip neigh", s.run("ip neigh")),
                        ("/proc/net/arp", s.run("cat /proc/net/arp"))):
        m = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", text)
        macs[label] = m.group(1) if m else None
    check("all four readers name a MAC for the gateway",
          all(macs.values()), repr(macs))
    check("and it is the same MAC in all four",
          len(set(macs.values())) == 1, repr(macs))
    check("arp -a is the BSD format, not the table",
          s.run("arp -a").startswith("? (%s) at " % gw),
          s.run("arp -a").splitlines()[:1])
    check("arp -n is the table, not BSD",
          s.run("arp -n").startswith("Address "),
          s.run("arp -n").splitlines()[:1])

    # ---- the counters, which are one statistic
    # One command, so both readings share the per-command sample. Across two
    # separate commands the counters legitimately advance -- they are derived
    # from uptime -- and comparing them would be testing the clock.
    both = s.run("ifconfig; echo __SPLIT__; cat /proc/net/dev")
    ifc = both.split("__SPLIT__")[0]
    dev = [l for l in both.split("__SPLIT__")[1].splitlines()
           if l.strip().startswith("eth0:")]
    check("/proc/net/dev has an eth0 row", bool(dev), s.run("cat /proc/net/dev")[:80])
    if dev:
        d = dev[0].replace("eth0:", "").split()
        rxm = re.search(r"RX packets (\d+)\s+bytes (\d+)", ifc)
        txm = re.search(r"TX packets (\d+)\s+bytes (\d+)", ifc)
        rx, tx = rxm, txm
        check("ifconfig RX matches /proc/net/dev",
              rx and (rx.group(1), rx.group(2)) == (d[1], d[0]),
              "ifconfig %s/%s vs proc %s/%s"
              % (rx.group(1), rx.group(2), d[1], d[0]) if rx else "")
        check("ifconfig TX matches /proc/net/dev",
              tx and (tx.group(1), tx.group(2)) == (d[9], d[8]),
              "ifconfig %s/%s vs proc %s/%s"
              % (tx.group(1), tx.group(2), d[9], d[8]) if tx else "")
        check("counters are not all zero", int(d[0]) > 0 and int(d[8]) > 0)

    # ---- listening sockets, from three sources
    def ports(text, col):
        out = []
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) > col and ":" in f[col]:
                try:
                    out.append(int(f[col].rsplit(":", 1)[1]))
                except ValueError:
                    pass
        return sorted(set(out))

    ss_p = ports(s.run("ss -tlnp"), 3)
    ns_p = ports(s.run("netstat -tlnp"), 3)
    tcp_p = sorted({int(l.split()[1].split(":")[1], 16)
                    for l in s.run("cat /proc/net/tcp").splitlines()[1:]
                    if len(l.split()) > 3 and l.split()[3] == "0A"})
    check("ss and netstat list the same listening ports", ss_p == ns_p,
          "%s vs %s" % (ss_p, ns_p))
    check("/proc/net/tcp lists the same listening ports", ss_p == tcp_p,
          "%s vs %s" % (ss_p, tcp_p))
    check("port 22 is open, since we are talking over it", 22 in ss_p)
    check("port 80 is open, since the site answers", 80 in ss_p)

    # ---- and every listener is backed by a process that exists
    psmap = {}
    for line in s.run("ps -eo pid,comm").splitlines()[1:]:
        f = line.split()
        if len(f) == 2:
            psmap[int(f[0])] = f[1]
    bad = []
    for line in s.run("ss -tlnp").splitlines()[1:]:
        m = re.search(r'\(\("([^"]+)",pid=(\d+)', line)
        if not m:
            continue
        name, pid = m.group(1), int(m.group(2))
        if pid not in psmap:
            bad.append("%s pid %d not in ps" % (name, pid))
        elif psmap[pid] != name:
            bad.append("pid %d is %s in ps, %s in ss" % (pid, psmap[pid], name))
    check("every listening socket's process exists in ps", not bad, str(bad))

    # ---- and by software the box admits to having
    for line in s.run("ss -tlnp").splitlines()[1:]:
        m = re.search(r'\(\("([^"]+)",pid=', line)
        if not m:
            continue
        name = m.group(1)
        known = (s.run("command -v %s" % name).strip()
                 or s.run("dpkg -l | grep -ci %s" % name).strip() not in ("", "0")
                 or name in ("mariadbd", "sshd", "nginx"))
        check("the box has the software behind listener %s" % name, bool(known),
              name)

    # ---- systemd and ps describe the same set of daemons
    bad = []
    for unit, (_d, pid, comm) in sorted(fs.Shell._UNITS.items()):
        state = s.run("systemctl is-active %s" % unit).strip()
        if state != "active":
            bad.append("%s is %s" % (unit, state))
        elif pid not in psmap:
            bad.append("%s MainPID %d absent from ps" % (unit, pid))
        elif psmap[pid] != comm:
            bad.append("%s MainPID %d is %s in ps" % (unit, pid, psmap[pid]))
    check("every unit systemd calls active has its process in ps", not bad,
          str(bad[:4]))

    # A daemon is a process systemd is running, and the box says which
    # those are: anything in /system.slice/<unit>. A long-running job in a
    # user's own slice is not a daemon and has no unit by design -- the
    # training run this machine exists for is exactly that, and demanding a
    # unit for it would mean inventing python3.service.
    daemons = set()
    for line in s.run("ps -eo pid,comm,cmd").splitlines()[1:]:
        f = line.split(None, 2)
        if len(f) < 3 or f[2].startswith("["):
            continue
        if f[1] in ("bash", "ps", "sshd", "sshd-session", "agetty",
                    "systemd", "sh", "su"):
            continue
        cg = s.run("cat /proc/%s/cgroup 2>/dev/null" % f[0]).strip()
        if "/system.slice/" not in cg:
            continue
        daemons.add(f[1])
    unit_comms = {c for _u, (_d, _p, c) in fs.Shell._UNITS.items()}
    orphan = sorted(d for d in daemons if d not in unit_comms)
    check("every daemon in ps has a systemd unit", not orphan, str(orphan))

    # ---- claims made by other subsystems about the network
    td = s.run("timedatectl")
    if "NTP service: active" in td:
        check("something is actually doing NTP",
              any("timesyn" in c for c in daemons)
              or s.run("systemctl is-active systemd-timesyncd").strip()
              == "active", str(sorted(daemons)))
    check("timedatectl's timezone matches /etc/timezone",
          s.run("cat /etc/timezone").strip() in td,
          s.run("cat /etc/timezone").strip())
    check("hostname, /etc/hostname and /etc/hosts agree",
          s.run("hostname").strip() == s.run("cat /etc/hostname").strip()
          and s.run("hostname").strip() in s.run("cat /etc/hosts"))
    check("hostname -f matches the /etc/hosts FQDN",
          s.run("hostname -f").strip() in s.run("cat /etc/hosts"),
          s.run("hostname -f").strip())
    check("resolv.conf names at least one nameserver",
          "nameserver" in s.run("cat /etc/resolv.conf"))

    # ---- our own connection shows up in the connection table
    est = s.run("ss -tn state established")
    check("the session we are on appears as established",
          "203.0.113.77" in est and ":51234" in est, est[:100])
    check("who agrees with $SSH_CONNECTION about the peer",
          "203.0.113.77" in s.run("who"), s.run("who").strip())

    # ---- /proc and ps describe the same processes. They computed comm and
    # ppid separately and disagreed 70 times across 27 processes: comm came
    # from basename(cmdline), so kernel threads kept the brackets ps adds
    # for display ([kthreadd]) and pid 1 was "init" rather than "systemd",
    # and ppid was hardcoded to 1 so every kernel thread claimed init as its
    # parent instead of kthreadd.
    import re as _re
    rows = {}
    for line in s.run("ps -eo pid,ppid,user,comm").splitlines()[1:]:
        f = line.split()
        if len(f) >= 4:
            rows[f[0]] = f
    check("ps lists processes", len(rows) > 10, str(len(rows)))
    bad = []
    for pid, (_p, pp, _user, comm) in rows.items():
        stat = s.run("cat /proc/%s/stat" % pid).strip().split()
        status = s.run("cat /proc/%s/status" % pid)
        pcomm = s.run("cat /proc/%s/comm" % pid).strip()
        if len(stat) > 3:
            if stat[3] != pp:
                bad.append("%s stat ppid %s vs ps %s" % (pid, stat[3], pp))
            if stat[1].strip("()") != comm:
                bad.append("%s stat comm %s vs ps %s" % (pid, stat[1], comm))
        if pcomm != comm:
            bad.append("%s /proc/comm %r vs ps %r" % (pid, pcomm, comm))
        m = _re.search(r"^PPid:\s*(\d+)", status, _re.M)
        if m and m.group(1) != pp:
            bad.append("%s status PPid %s vs ps %s" % (pid, m.group(1), pp))
        m = _re.search(r"^Name:\s*(\S+)", status, _re.M)
        if m and m.group(1) != comm:
            bad.append("%s status Name %s vs ps %s" % (pid, m.group(1), comm))
    check("/proc agrees with ps for every process", not bad,
          "%d disagreements: %s" % (len(bad), bad[:3]))

    check("there is a /proc directory per process",
          len([x for x in s.run("ls /proc").split() if x.isdigit()])
          == len(rows),
          "%d vs %d" % (len([x for x in s.run("ls /proc").split()
                             if x.isdigit()]), len(rows)))
    orphans = [p for p, f in rows.items()
               if f[1] not in rows and f[1] != "0"]
    check("no process claims a parent that does not exist", not orphans,
          str(orphans[:4]))
    check("pid 1 is systemd with no parent",
          rows.get("1", ["", "", "", ""])[1] == "0"
          and rows.get("1", ["", "", "", ""])[3] == "systemd",
          str(rows.get("1")))
    check("pid 1's comm is systemd, not init",
          s.run("cat /proc/1/comm").strip() == "systemd",
          s.run("cat /proc/1/comm").strip())
    check("a kernel thread's comm has no brackets",
          s.run("cat /proc/2/comm").strip() == "kthreadd",
          s.run("cat /proc/2/comm").strip())
    check("but ps shows the brackets in the cmd column",
          s.run("ps -o cmd= -p 2").strip() == "[kthreadd]",
          s.run("ps -o cmd= -p 2").strip())
    check("kthreadd is parented to 0, not init",
          s.run("cat /proc/2/stat").split()[3] == "0",
          s.run("cat /proc/2/stat").split()[3])
    check("the shell's $$ is in ps",
          s.run("echo $$").strip() in rows)
    check("the shell's $PPID is its parent in ps",
          rows.get(s.run("echo $$").strip(), ["", "?"])[1]
          == s.run("echo $PPID").strip())
    check("that parent is an sshd",
          "sshd" in s.run("ps -o comm= -p $PPID"),
          s.run("ps -o comm= -p $PPID").strip())

    # a unit systemctl reports on must have a file systemctl can print
    bad = []
    for unit in sorted(fs.Shell._UNITS):
        if s.run("systemctl cat %s" % unit).strip() == "":
            bad.append(unit)
    check("every unit has a unit file systemctl can cat", not bad, str(bad))
    # aliases (mysql -> mariadb) live under /etc/systemd/system as symlinks,
    # which is where Debian's Alias= directive puts them
    bad = [u for u in sorted(fs.Shell._UNITS)
           if all(s.run("ls %s/%s.service" % (d, u)).strip() == ""
                  for d in ("/usr/lib/systemd/system", "/lib/systemd/system",
                            "/etc/systemd/system"))]
    check("every unit has a file on disk", not bad, str(bad))

    # ---- the sshd the attacker came in through has to match the config
    # file the same box serves. sshd -T printed nothing at all, sshd_config
    # Included a directory that did not exist, and openssh-server's moduli
    # was absent.
    cfg = s.run("cat /etc/ssh/sshd_config")
    dump = s.run("sshd -T")
    check("sshd -T dumps an effective config", len(dump.splitlines()) > 20,
          "%d lines" % len(dump.splitlines()))
    # One line per value, not one per key: sshd repeats a repeatable
    # directive rather than joining it. Keeping only the first (setdefault
    # on a string) compared the file's four AcceptEnv values against the
    # dump's first one and called the box inconsistent with itself.
    allvals = {}
    for line in dump.splitlines():
        k, _, v = line.partition(" ")
        allvals.setdefault(k, []).append(v.strip())
    dumped = {k: v[0] for k, v in allvals.items()}
    mismatched = []
    for line in cfg.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2 or line.startswith("#"):
            continue
        key = parts[0].lower()
        # sshd -T normalises whitespace: sshd_config writes
        # "Subsystem\tsftp\t/usr/lib/openssh/sftp-server" and the dump
        # prints it space-separated. Confirmed against real sshd, so the
        # comparison collapses runs of whitespace rather than the emulator
        # being made to copy the tabs.
        want = " ".join(parts[1].split()).lower()
        # sshd_config lists a repeatable directive's values on one line and
        # sshd -T prints one line each -- confirmed on the guest, whose
        # single "AcceptEnv LANG LC_* COLORTERM NO_COLOR" comes back as four
        # acceptenv lines. Join them before comparing, so a directive that
        # really did lose values still fails.
        got = (" ".join(" ".join(allvals[key]).split()).lower()
               if key in allvals else None)
        if got is not None and got != want:
            mismatched.append("%s: file %r vs -T %r" % (key, want, got))
    check("sshd -T agrees with sshd_config on every shared directive",
          not mismatched, str(mismatched))
    check("root login is permitted, as the config claims",
          dumped.get("permitrootlogin") == "yes", dumped.get("permitrootlogin"))
    check("password auth is on, which is how anyone gets in",
          dumped.get("passwordauthentication") == "yes")
    check("the port sshd -T reports is the one that is listening",
          dumped.get("port") == "22" and 22 in ss_p)
    check("the sftp subsystem is declared",
          "sftp" in dumped.get("subsystem", ""), dumped.get("subsystem"))

    inc = [l.split(None, 1)[1] for l in cfg.splitlines()
           if l.startswith("Include ")]
    check("sshd_config Includes a directory", bool(inc), str(inc))
    for pat in inc:
        d = pat.rsplit("/", 1)[0]
        check("the Included directory %s exists" % d,
              s.run("ls -d %s" % d).strip() != "", "".join(s._err)[:50])
        s._err.clear()
    check("openssh-server's moduli is present",
          s.run("ls /etc/ssh/moduli").strip() != "")
    s._err.clear()
    check("moduli has the right shape",
          all(len(l.split()) == 7 for l in
              s.run("grep -v '^#' /etc/ssh/moduli | head -5").splitlines()),
          s.run("grep -v '^#' /etc/ssh/moduli | head -1").strip()[:50])
    check("moduli is a plausible size",
          400000 < int(s.run("stat -c %s /etc/ssh/moduli").strip()) < 900000,
          s.run("stat -c %s /etc/ssh/moduli").strip())
    for k in ("rsa", "ecdsa", "ed25519"):
        check("host key pair %s is present" % k,
              s.run("ls /etc/ssh/ssh_host_%s_key /etc/ssh/ssh_host_%s_key.pub"
                    % (k, k)).count("ssh_host") == 2)
        check("the %s public key names its own type" % k,
              s.run("cut -d' ' -f1 /etc/ssh/ssh_host_%s_key.pub" % k).strip()
              in ("ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"))

    # --- options that were accepted and ignored ----------------------
    # Every bug in this family reads the same way from outside: plausible
    # output, wrong content. ss -H was ignored, so a script doing
    # `ss -H -tln | while read state ...` took the header row as its first
    # record and parsed "State" as a socket state.
    plain = s.run("ss -tln")
    check("ss -tln prints a header",
          plain.splitlines()[0].startswith("State"), plain[:40])
    bare = s.run("ss -H -tln")
    check("ss -H suppresses it",
          not bare.splitlines()[0].startswith("State"), bare[:40])
    check("and removes exactly the header",
          bare.strip().splitlines() == plain.strip().splitlines()[1:],
          bare[:60])
    ux = s.run("ss -x -H")
    check("no Netid header either with -H",
          not ux.strip().splitlines()[0].startswith("Netid"), ux[:40])

    # -4/-6 were applied to `ip addr` but the brief form returned before
    # reaching the filter, so `ip -4 -br addr` -- the one-line form a script
    # uses to read an address -- listed ::1 and the link-local too.
    both = s.run("ip -br addr")
    check("unfiltered brief shows both families",
          "127.0.0.1/8" in both and "::1/128" in both, both[:60])
    v4 = s.run("ip -4 -br addr")
    check("ip -4 -br addr keeps IPv4", "127.0.0.1/8" in v4, v4[:60])
    check("ip -4 -br addr drops IPv6",
          "::1/128" not in v4 and "fe80:" not in v4, v4[:60])
    v6 = s.run("ip -6 -br addr")
    check("ip -6 -br addr keeps IPv6",
          "::1/128" in v6 and "fe80:" in v6, v6[:60])
    check("ip -6 -br addr drops IPv4", "127.0.0.1/8" not in v6, v6[:60])
    check("both still list two interfaces",
          len(v4.strip().splitlines()) == 2, v4[:60])
    check("the long form stays filtered too",
          "inet6" not in s.run("ip -4 addr"), "")

    # -o was ignored, so every continuation line looked like its own record.
    one = s.run("ip -o link")
    lines = one.strip().splitlines()
    check("ip -o link is one line per interface", len(lines) == 2, one[:60])
    for ln in lines:
        check("record %s starts with its index" % ln[:4], ln[0].isdigit(),
              ln[:30])
        check("and folds the continuation after a backslash",
              "\\    link/" in ln, ln[:70])
    check("ip link is still multi-line",
          len(s.run("ip link").strip().splitlines()) > 2, "")

    print()
    print("=" * 62)
    # ---- the interface counters against the traffic this box can account
    # ---- for
    #
    # They averaged ~55 MB/s in, which over 41 days of uptime is 195 TB
    # received and 64 TB sent -- 0.58 Gbit/s sustained, for six weeks, on
    # a host whose own processes moved 1.59 GB in total and whose nginx
    # logged 62 requests carrying 19,529 bytes. Five orders of magnitude
    # between two counters describing one box.
    #
    # They had been raised from 594 B/s because btop's network panel read
    # "0 Byte/s" and flat, which was a real complaint -- but the reason
    # given, that the box pulls training shards over the wire, is not this
    # box: its own config says dataset: /data/shards, a local NVMe volume.
    # So the rate is sized to what it does have, a public IP under
    # continuous brute-force and scanning, and the burst structure is kept
    # so the panel still moves.
    import re as _re
    import time as _time

    def _o(cmd):
        r = s.run(cmd)
        return ((r[0] if isinstance(r, tuple) else r) or "").strip()

    _up = float(_o("cut -d' ' -f1 /proc/uptime") or 1)
    _dev = _o("grep eth0 /proc/net/dev").split()
    _rx, _tx = int(_dev[1]), int(_dev[9])
    _rate = (_rx + _tx) / max(_up, 1.0)
    check("eth0's average rate is a public host's, not a datacentre link",
          20e3 < _rate < 3e6,
          "%.0f KB/s averaged over %.1f days" % (_rate / 1e3, _up / 86400.0))
    check("...so the lifetime total is plausible",
          (_rx + _tx) < 20e12,
          "%.1f TB over %.1f days" % ((_rx + _tx) / 1e12, _up / 86400.0))
    check("rx exceeds tx, as it does on a server being scanned",
          _rx > _tx, "rx %d tx %d" % (_rx, _tx))
    _bpp = _rx / max(int(_dev[2]), 1)
    check("the average packet is a small one",
          40 < _bpp < 1600, "%.0f bytes per packet" % _bpp)
    # every reader of the same counter
    _sys = int(_o("cat /sys/class/net/eth0/statistics/rx_bytes") or 0)
    check("sysfs and /proc/net/dev agree on rx_bytes",
          abs(_sys - _rx) < 5_000_000,
          "sysfs %d vs proc %d" % (_sys, _rx))
    _ipm = _re.findall(r"^\s+(\d+)\s+\d+\s+\d+", _o("ip -s link show eth0"),
                       _re.M)
    if _ipm:
        check("ip -s link agrees too", abs(int(_ipm[0]) - _rx) < 5_000_000,
              "ip %s vs proc %d" % (_ipm[0], _rx))
    # and it still moves, which is why the rate was raised in the first place
    _a = int(_o("grep eth0 /proc/net/dev").split()[1])
    _time.sleep(2)
    _b = int(_o("grep eth0 /proc/net/dev").split()[1])
    check("the counter is strictly increasing", _b >= _a, "%d -> %d" % (_a, _b))
    check("...and moves enough for a graph to show it",
          (_b - _a) / 2.0 > 10e3,
          "%.0f KB/s observed" % ((_b - _a) / 2.0 / 1e3))

    # ---- a daemon with a pid and no socket -------------------------------
    #
    # `ps` showed jupyter-lab, node_exporter and dcgm-exporter running and
    # `ss -tlnp` listed only 22, 80 and 3306. Both are standard recon and
    # the pair contradicts itself. Giving them sockets that then served
    # the WordPress front page would have been worse, so each answers on
    # its own port -- and every number in those answers is read from the
    # same place the shell's own commands read it.
    import re as _re2

    def _o2(cmd):
        r = s.run(cmd)
        return ((r[0] if isinstance(r, tuple) else r) or "").strip()

    _ss = _o2("ss -tlnp")
    # Matched on the argv that is unique to each, not on the comm: several
    # processes are python3, so grepping that picked the wrong pid and the
    # check failed on output that was correct.
    for _proc, _match, _port in (("python3", "jupyter-lab", 8888),
                                 ("node_exporter", "node_exporter", 9100),
                                 ("dcgm-exporter", "dcgm-exporter", 9400)):
        _running = _o2("ps -eo pid,args --no-headers | grep -F %s "
                       "| grep -v grep" % _match)
        check("%s is running" % _proc, bool(_running), "(absent)")
        check("...and %s holds a socket" % _proc, ":%d" % _port in _ss,
              "no :%d in ss -tlnp" % _port)
        if _running:
            _pid = _running.split()[0]
            check("...listed against the same pid ps gives",
                  "pid=%s" % _pid in _ss, "pid=%s not in ss" % _pid)
    # the exporters answer, and answer with this box's own numbers
    _m = _o2("curl -s http://127.0.0.1:9100/metrics")
    check("node_exporter serves metrics", "node_memory_MemTotal_bytes" in _m,
          _m[:60])
    _mt = _re2.search(r"node_memory_MemTotal_bytes (\S+)", _m)
    _pm = _re2.search(r"MemTotal:\s+(\d+)", _o2("grep MemTotal /proc/meminfo"))
    if _mt and _pm:
        check("...and its MemTotal is /proc/meminfo's",
              abs(float(_mt.group(1)) - int(_pm.group(1)) * 1024) < 2,
              "%s vs %d" % (_mt.group(1), int(_pm.group(1)) * 1024))
    _d = _o2("curl -s http://127.0.0.1:9400/metrics")
    _du = _re2.search(r'DCGM_FI_DEV_GPU_UTIL\{gpu="0"[^}]*\} (\d+)', _d)
    _dfb = _re2.search(r'DCGM_FI_DEV_FB_USED\{gpu="0"[^}]*\} (\d+)', _d)
    _smi = _o2("nvidia-smi --query-gpu=utilization.gpu,memory.used "
               "--format=csv,noheader,nounits").splitlines()
    check("dcgm-exporter serves GPU metrics", bool(_du), _d[:60])
    if _du and _dfb and _smi:
        _f = _smi[0].split(", ")
        check("...and gpu0 matches nvidia-smi",
              [_du.group(1), _dfb.group(1)] == _f,
              "dcgm %s/%s vs smi %r" % (_du.group(1), _dfb.group(1), _f))
    check("one metric series per GPU",
          _d.count("DCGM_FI_DEV_GPU_UTIL{") ==
          int(_o2("nvidia-smi -L | wc -l")),
          "%d series" % _d.count("DCGM_FI_DEV_GPU_UTIL{"))
    # ...and a port nothing listens on is still refused
    check("an unbound port is still refused",
          _o2("curl -s -m 2 http://127.0.0.1:9999/") == "", "answered")
    check("a wrong path on an exporter is a 404",
          "404" in _o2("curl -s http://127.0.0.1:9100/nope"),
          _o2("curl -s http://127.0.0.1:9100/nope")[:40])

    print("passed %d, failed %d" % (PASS, FAIL))
    for f in FAILURES:
        print("   FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
