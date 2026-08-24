r"""Resolving a name: a crash, and three views that never agreed.

Sixty-first coherence sweep. A miner resolves its pool before it dials
it, and a loader resolves the host it is about to fetch from, so: do the
commands that answer "what does this name resolve to" agree?

They did not, and one of them did not run at all.

  1. cmd_ping called self._stable_ip(), which is defined nowhere in
     fakeshell.py. `ping any.dotted.name` raised AttributeError -- caught
     upstream and turned into empty output with rc 0, which is not
     something ping has ever done for any input. Only a bare hostname or
     a literal IP took another branch, which is why the two pings in the
     log so far (`ping -c1 10.0.0.5` and `ping -c1 web01`) happened to
     miss it. Nothing else in the file referenced _stable_ip, so it had
     never worked.

  2. `getent hosts` grepped /etc/hosts and stopped there, so every name
     not literally in that file came back empty -- on a box whose
     /etc/resolv.conf names 1.1.1.1 and 1.0.0.1 and whose ps shows
     systemd-resolved running. Meanwhile the download helper resolves and
     fetches from exactly those names, so the box could pull a payload
     from a host it claimed it could not resolve.

  3. resolvectl is in the persona -- /usr/bin/resolvectl exists, dpkg
     knows it, systemd-resolved is in ps -- and every subcommand fell
     through to the unimplemented-binary handler, answering
     "resolvectl: missing operand". `resolvectl status` takes no operand.

One _resolve_host() now answers for all of them: /etc/hosts first, as
this box's nsswitch says (`hosts: files dns`), then a literal address,
then RFC 2606/6761 names that never resolve anywhere, then a synthetic
address derived from the name. Nothing is looked up on the network -- the
address is computed from the name, so it is identical across commands and
across sessions without a packet leaving the box.

Reference for output shapes measured against real getent and resolvectl.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []
IPRE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(s, cmd):
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


# -- ping no longer crashes ----------------------------------------------

def t_ping_a_dotted_name_does_not_crash():
    s = shell()
    o = out(s, "ping -c1 example.com")
    check("no traceback", "AttributeError" not in o, o[:80])
    check("says PING", o.startswith("PING example.com ("), o[:70])
    check("names an address",
          IPRE.match(o.split("(")[1].split(")")[0]) is not None, o[:70])


def t_ping_shapes():
    s = shell()
    eq("literal ip", out(s, "ping -c1 8.8.8.8 | head -1"),
       "PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.")
    eq("from /etc/hosts", out(s, "ping -c1 localhost | head -1"),
       "PING localhost (127.0.0.1) 56(84) bytes of data.")
    o = out(s, "ping -c1 nosuchname")
    check("bare unknown name", "Name or service not known" in o, o)


def t_ping_reports_loss_not_replies():
    """The box answers but never actually pings anything."""
    s = shell()
    o = out(s, "ping -c1 example.com")
    check("100% loss", "100% packet loss" in o, o[:120])
    check("no reply lines", "bytes from" not in o, o[:120])


# -- getent resolves -----------------------------------------------------

def t_getent_hosts_resolves():
    s = shell()
    o = out(s, "getent hosts example.com")
    check("two fields", len(o.split()) == 2, o)
    check("address first", IPRE.match(o.split()[0]) is not None, o)
    eq("name second", o.split()[1], "example.com")


def t_getent_ahosts_shape():
    s = shell()
    lines = out(s, "getent ahosts example.com").splitlines()
    check("three lines", len(lines) == 3, str(lines))
    check("STREAM first", "STREAM example.com" in lines[0], str(lines))
    check("DGRAM second", "DGRAM" in lines[1], str(lines))
    check("RAW third", "RAW" in lines[2], str(lines))


def t_etc_hosts_still_wins():
    s = shell()
    # The answer is the *line*, not the key that was asked for: every name
    # on it, the address padded to 15, and the v6 line preferred when a
    # name is on both. Measured on the guest, where `getent hosts
    # localhost` answers ::1 even though "127.0.0.1 localhost" appears
    # first in the file. This check used to expect the key echoed back
    # beside a bare address, which is neither the file's content nor
    # glibc's format.
    eq("localhost", out(s, "getent hosts localhost"),
       "::1             localhost ip6-localhost ip6-loopback")
    o = out(s, "getent hosts web01")
    check("own name from the file", o.startswith("127.0.1.1"), o)


def t_names_that_never_resolve():
    s = shell()
    for name in ("nosuch.invalid", "a.test", "thing.example", "box.localdomain"):
        o = out(s, "getent hosts %s; echo rc=$?" % name)
        eq("rc 2 for %s" % name, o, "rc=2")


def t_a_bare_word_does_not_resolve():
    s = shell()
    eq("no dot, not in hosts", out(s, "getent hosts nodots; echo rc=$?"),
       "rc=2")


def t_a_literal_address_passes_through():
    s = shell()
    o = out(s, "getent hosts 203.0.113.9")
    check("returns it", o.startswith("203.0.113.9"), o)


# -- the three agree -----------------------------------------------------

def t_ping_getent_and_resolvectl_agree():
    s = shell()
    for name in ("example.com", "pool.minexmr.com", "cdn.jsdelivr.net"):
        p = out(s, "ping -c1 %s | head -1" % name).split("(")[1].split(")")[0]
        g = out(s, "getent hosts %s" % name).split()[0]
        r = out(s, "resolvectl query %s | head -1" % name).split()[1]
        eq("ping vs getent: %s" % name, g, p)
        eq("getent vs resolvectl: %s" % name, r, g)


def t_the_answer_is_stable():
    """Same name, same address, every time and in every command."""
    s = shell()
    first = out(s, "getent hosts pool.minexmr.com")
    for _ in range(3):
        eq("stable within a shell", out(s, "getent hosts pool.minexmr.com"),
           first)
    s2 = shell()
    eq("stable across shells", out(s2, "getent hosts pool.minexmr.com"), first)


def t_different_names_get_different_addresses():
    s = shell()
    seen = set()
    for n in ("a.example.org", "b.example.org", "pool.minexmr.com",
              "xmr.pool.gntl.uk", "cdn.jsdelivr.net"):
        seen.add(out(s, "getent hosts %s" % n).split()[0])
    check("all distinct", len(seen) == 5, str(seen))


def t_the_synthetic_address_is_plausible():
    s = shell()
    for n in ("example.com", "pool.minexmr.com", "a.b.c.example.org",
              "x.test.co.uk", "deb.debian.org"):
        a = out(s, "getent hosts %s" % n).split()[0]
        o = [int(x) for x in a.split(".")]
        check("not reserved: %s -> %s" % (n, a),
              o[0] not in (0, 10, 127, 169, 172, 192) and o[0] < 224,
              a)
        check("valid octets: %s" % a, all(0 <= x <= 255 for x in o), a)


# -- resolvectl ----------------------------------------------------------

def t_resolvectl_query():
    s = shell()
    o = out(s, "resolvectl query example.com")
    check("no missing operand", "missing operand" not in o, o[:70])
    check("names the host", o.startswith("example.com:"), o[:70])
    check("reports the link", "-- link: eth0" in o, o[:90])
    check("has the protocol footer",
          "acquired via protocol DNS" in o, o[:200])


def t_resolvectl_query_nxdomain():
    s = shell()
    o = out(s, "resolvectl query nosuch.invalid")
    check("says not found", "not found" in o, o)
    _o, rc = s.run("resolvectl query nosuch.invalid"), s.last_rc
    s._err.clear()
    eq("rc 1", rc, 1)


def t_resolvectl_status_takes_no_operand():
    s = shell()
    o = out(s, "resolvectl status")
    check("no missing operand", "missing operand" not in o, o[:70])
    check("has a Global block", o.startswith("Global"), o[:60])
    check("names the link", "Link 2 (eth0)" in o, o[:200])


def t_resolvectl_agrees_with_resolv_conf():
    """The servers it names must be the ones the file names."""
    s = shell()
    from_file = out(s, "awk '/^nameserver/{print $2}' /etc/resolv.conf").split()
    body = out(s, "resolvectl status")
    for ns in from_file:
        check("status names %s" % ns, ns in body, body[:200])
    eq("resolvectl dns", out(s, "resolvectl dns").split(), from_file)
    check("current server is the first",
          "Current DNS Server: %s" % from_file[0] in body, body[:200])


def t_resolvectl_unknown_verb():
    s = shell()
    o = out(s, "resolvectl frobnicate")
    check("reports it", "Unknown command verb" in o, o)


# -- the absent tools stay absent ----------------------------------------

def t_dnsutils_is_not_installed():
    """dig/host/nslookup are not in a minimal Debian, and must stay gone."""
    s = shell()
    for tool in ("dig", "host", "nslookup"):
        eq("no %s" % tool, out(s, "command -v %s; echo rc=$?" % tool), "rc=1")
        o = out(s, "%s example.com" % tool)
        check("%s: command not found" % tool, "command not found" in o, o)


TESTS = [t_ping_a_dotted_name_does_not_crash, t_ping_shapes,
         t_ping_reports_loss_not_replies, t_getent_hosts_resolves,
         t_getent_ahosts_shape, t_etc_hosts_still_wins,
         t_names_that_never_resolve, t_a_bare_word_does_not_resolve,
         t_a_literal_address_passes_through,
         t_ping_getent_and_resolvectl_agree, t_the_answer_is_stable,
         t_different_names_get_different_addresses,
         t_the_synthetic_address_is_plausible, t_resolvectl_query,
         t_resolvectl_query_nxdomain, t_resolvectl_status_takes_no_operand,
         t_resolvectl_agrees_with_resolv_conf, t_resolvectl_unknown_verb,
         t_dnsutils_is_not_installed]


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
