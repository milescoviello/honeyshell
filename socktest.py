r"""Sockets: four tables, four answers.

Fifty-second coherence sweep. Two actors ran `ifconfig` this week, so the
axis was network identity. Interfaces turned out clean and are pinned
here rather than changed: ip addr, ifconfig, hostname -I and
/sys/class/net agree on address, MAC, MTU and broadcast; ip route,
route -n, netstat -rn and /proc/net/route agree on both routes; and
/proc/net/tcp carries the same listeners and the same established
connection that ss and netstat show.

The socket tables did not agree. There were four hardcoded lists -- the
/proc/net/udp seed, the /proc/net/unix seed, LISTENERS, and a fourth one
inside cmd_ss's -x branch -- and no two of them described the same box.

UDP, three views:

    /proc/net/udp   one socket on :68
    ss -uln         nothing at all (there was no UDP branch)
    ss -s           "UDP 2 (IP 1, IPv6 1)"
    netstat -uln    the three TCP listeners, labelled tcp

netstat ignored the protocol family completely: -u, -lu and -uln all
printed the TCP table, so a caller checking whether anything was bound to
a UDP port got three confident wrong answers. -x did the same, printing
internet sockets under a header promising unix ones -- the same shape as
the -r and -i bugs fixed earlier.

Unix sockets, three views:

    /proc/net/unix  /run/systemd/private, /run/dbus/system_bus_socket
    ss -xl          /run/dbus/system_bus_socket, /run/mysqld/mysqld.sock
    the filesystem  /run/php/php8.4-fpm.sock and nothing else

php-fpm's socket -- the one nginx's own config points at, and the only
one that actually existed on disk -- appeared in neither listing. And it
was seeded as a plain empty file, so `ls -l` showed "-rw-rw----" where
every real unix socket shows "s". /run/mysqld and /run/dbus did not exist
on disk at all while ss listed sockets inside them.

Worse, the inodes collided: /proc/net/udp gave inode 18011 to the DHCP
client's :68 while cmd_ss gave 18011 to /run/mysqld/mysqld.sock. One
inode, two sockets, which is the one thing an inode cannot be -- and
inode is exactly how `ss -p` and anyone doing it by hand ties a socket to
a process.

The VFS had no socket file type at all, so `find /run -type s` found
nothing on a box where ls and stat would both call a file a socket. find
was also missing -type b.

Fixed the way LISTENERS already was: UDP_SOCKETS and UNIX_SOCKETS are
defined once and every view reads them -- /proc/net/udp, /proc/net/unix,
ss -u, ss -x, ss -s, netstat -u, netstat -x, and the socket files on
disk.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script, user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="203.0.113.77")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def lines(script):
    out, _ = run(script)
    return [l for l in out.splitlines() if l.strip()]


# -- interfaces and routes already agreed; keep them that way ------------

def t_interface_identity_agrees():
    ipa, _ = run("ip addr")
    ifc, _ = run("ifconfig")
    mac = re.search(r"link/ether (\S+)", ipa).group(1)
    # Scope to the eth0 stanza: the first inet in `ip addr` is lo's
    # 127.0.0.1, which is not what hostname -I reports.
    eth = ipa.split("eth0:", 1)[1]
    addr = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", eth).group(1)
    check("ifconfig has the same MAC", "ether %s" % mac in ifc, ifc[:80])
    check("ifconfig has the same inet", "inet %s" % addr in ifc, ifc[:80])
    out, _ = run("cat /sys/class/net/eth0/address")
    eq("sysfs MAC", out.strip(), mac)
    out, _ = run("hostname -I")
    eq("hostname -I", out.strip(), addr)
    out, _ = run("cat /sys/class/net/eth0/mtu")
    check("sysfs MTU matches ip", "mtu %s" % out.strip() in ipa, out[:20])


def t_routes_agree():
    for cmd in ("route -n", "netstat -rn"):
        out, _ = run(cmd)
        check("%s has a default route" % cmd, "0.0.0.0" in out, out[:60])
        check("%s names eth0" % cmd, "eth0" in out, out[:60])
    ipr, _ = run("ip route")
    gw = re.search(r"default via (\S+)", ipr).group(1)
    out, _ = run("route -n")
    check("route -n has the same gateway", gw in out, out[:80])
    out, _ = run("cat /proc/net/route")
    eq("/proc/net/route rows", len([l for l in out.splitlines()
                                    if l.startswith("eth0")]), 2)


# -- one UDP answer -------------------------------------------------------

def t_udp_appears_at_all():
    rows = [l for l in lines("ss -uln") if l.startswith("UNCONN")]
    check("ss -uln lists sockets", len(rows) > 0, str(lines("ss -uln")))
    check("ss -uln has :68", any(":68" in r for r in rows), str(rows))


def t_udp_agrees_across_views():
    proc, _ = run("cat /proc/net/udp")
    nproc = len([l for l in proc.splitlines() if re.match(r"^\s*\d+:", l)])
    nss = len([l for l in lines("ss -uln") if l.startswith("UNCONN")])
    nnet = len([l for l in lines("netstat -uln") if l.startswith("udp")])
    eq("ss -uln vs /proc/net/udp", nss, nproc)
    eq("netstat -uln vs /proc/net/udp", nnet, nproc)
    out, _ = run("ss -s | awk '/^UDP/{print $3}'")
    eq("ss -s IPv4 UDP count", int(out.strip()), nproc)


def t_udp_ports_match_proc():
    """The port numbers, not just the count."""
    proc, _ = run("cat /proc/net/udp")
    hexports = re.findall(r"^\s*\d+: [0-9A-F]{8}:([0-9A-F]{4})", proc, re.M)
    want = sorted(int(h, 16) for h in hexports)
    got = sorted(int(m) for m in
                 re.findall(r":(\d+)\s", "\n".join(lines("ss -uln"))))
    eq("udp ports agree", got, want)


def t_netstat_u_is_not_tcp():
    out, _ = run("netstat -uln")
    check("no tcp rows under -u", "\ntcp " not in out, out[:120])
    check("proto column says udp", "udp " in out, out[:120])
    for flag in ("-u", "-lu", "-uan"):
        out, _ = run("netstat %s" % flag)
        check("netstat %s has no tcp rows" % flag,
              not re.search(r"^tcp ", out, re.M), out[:80])


def t_tcp_and_udp_together():
    out, _ = run("netstat -tuln")
    check("-tuln has udp", re.search(r"^udp ", out, re.M) is not None, out[:80])
    check("-tuln has tcp", re.search(r"^tcp ", out, re.M) is not None, out[:80])
    out, _ = run("ss -lntu")
    check("ss -lntu has UNCONN", "UNCONN" in out, out[:80])
    check("ss -lntu has LISTEN", "LISTEN" in out, out[:80])


# -- one unix-socket answer ----------------------------------------------

def t_unix_sockets_agree_across_views():
    proc, _ = run("awk 'NR>1 && NF>7 {print $NF}' /proc/net/unix")
    ppaths = sorted(p for p in proc.split() if p.startswith("/"))
    sspaths = sorted(re.findall(r"(/\S+) \d+", "\n".join(lines("ss -xl"))))
    npaths = sorted(re.findall(r"(/\S+)$", "\n".join(lines("netstat -xl")),
                               re.M))
    eq("ss -xl vs /proc/net/unix", sspaths, ppaths)
    eq("netstat -xl vs /proc/net/unix", npaths, ppaths)


def t_netstat_x_is_not_tcp():
    out, _ = run("netstat -xl")
    check("unix header", out.startswith("Active UNIX domain sockets"), out[:60])
    check("no tcp rows", not re.search(r"^tcp ", out, re.M), out[:100])
    check("proto column says unix", re.search(r"^unix ", out, re.M) is not None,
          out[:100])


def t_the_php_socket_is_listed():
    """It is the one socket that always existed on disk."""
    for cmd in ("ss -xl", "netstat -xl", "cat /proc/net/unix"):
        out, _ = run(cmd)
        check("%s lists php-fpm.sock" % cmd, "php8.4-fpm.sock" in out,
              out[:100])


def t_socket_files_exist_on_disk():
    out, _ = run("awk 'NR>1 && NF>7 {print $NF}' /proc/net/unix")
    for path in [p for p in out.split() if p.startswith("/")]:
        o, rc = run("test -e %s && echo yes" % path)
        eq("exists: %s" % path, o.strip(), "yes")


def t_inodes_are_unique():
    """One inode cannot name two different sockets."""
    seen = {}
    for src, pat in (("/proc/net/tcp", r"^\s*\d+:.*?\s(\d+) [12] "),
                     ("/proc/net/udp", r"^\s*\d+:.*?\s(\d+) \d "),
                     ("/proc/net/unix", r"\s(\d+)(?:\s+/\S+)?$")):
        out, _ = run("cat %s" % src)
        for m in re.findall(pat, out, re.M):
            ino = int(m)
            check("inode %d not reused (%s vs %s)" % (ino, src, seen.get(ino)),
                  ino not in seen, "%s already used it" % seen.get(ino))
            seen[ino] = src


# -- the socket file type -------------------------------------------------

def t_ls_stat_file_and_find_agree():
    p = "/run/php/php8.4-fpm.sock"
    out, _ = run("ls -l %s" % p)
    check("ls says s", out.startswith("s"), out[:40])
    out, _ = run("stat -c '%%F' %s" % p)
    eq("stat -c %F", out.strip(), "socket")
    out, _ = run("file %s" % p)
    check("file says socket", out.strip().endswith("socket"), out[:60])
    out, _ = run("find /run -type s")
    check("find -type s finds it", p in out, out[:120])


def t_find_type_s_matches_the_listing():
    found = sorted(l for l in lines("find /run -type s") if l.startswith("/"))
    out, _ = run("awk 'NR>1 && NF>7 {print $NF}' /proc/net/unix")
    listed = sorted(p for p in out.split() if p.startswith("/"))
    eq("find -type s vs /proc/net/unix", found, listed)


def t_find_type_b_works_too():
    out, _ = run("find /dev -type b")
    check("find -type b finds sda", "/dev/sda" in out, out[:80])
    out, _ = run("find /dev -type c")
    check("find -type c finds null", "/dev/null" in out, out[:80])


def t_socket_ownership_is_named_not_numeric():
    out, _ = run("ls -l /run/mysqld/mysqld.sock")
    check("mysqld.sock owned by mysql", "mysql" in out, out[:60])
    check("no bare numeric uid", not re.search(r"\s1\d\d\s+1\d\d\s", out),
          out[:60])


# -- the TCP side must not have moved ------------------------------------

def t_tcp_views_still_agree():
    proc, _ = run("cat /proc/net/tcp")
    nproc = len([l for l in proc.splitlines() if re.match(r"^\s*\d+:", l)])
    nss = len([l for l in lines("ss -tan")
               if l.startswith(("LISTEN", "ESTAB"))])
    nnet = len([l for l in lines("netstat -tan") if l.startswith("tcp")])
    eq("ss -tan vs /proc/net/tcp", nss, nproc)
    eq("netstat -tan vs /proc/net/tcp", nnet, nproc)


def t_listeners_unchanged():
    out, _ = run("ss -tln")
    for port in (":22", ":80", ":3306"):
        check("still listening on %s" % port, port in out, out[:100])
    out, _ = run("netstat -tlnp")
    check("sshd attributed", "412/sshd" in out, out[:120])
    check("nginx attributed", "701/nginx" in out, out[:120])


TESTS = [t_interface_identity_agrees, t_routes_agree, t_udp_appears_at_all,
         t_udp_agrees_across_views, t_udp_ports_match_proc,
         t_netstat_u_is_not_tcp, t_tcp_and_udp_together,
         t_unix_sockets_agree_across_views, t_netstat_x_is_not_tcp,
         t_the_php_socket_is_listed, t_socket_files_exist_on_disk,
         t_inodes_are_unique, t_ls_stat_file_and_find_agree,
         t_find_type_s_matches_the_listing, t_find_type_b_works_too,
         t_socket_ownership_is_named_not_numeric, t_tcp_views_still_agree,
         t_listeners_unchanged]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
