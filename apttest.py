#!/usr/bin/env python3
"""If the box can reach the archive, what happens when you install?

`apt-get update` printed three Hit: lines against the full Debian archive
and reported "All packages are up to date". Every install then answered
"E: Unable to locate package" -- for nmap, for gcc, for htop, packages
trixie certainly ships. Two commands, one contradiction, and the attacker
creates it themselves within seconds of landing.

Installing now works for the names loader scripts actually ask for. It is
worth more than the error was: the package appears in dpkg, its binaries
appear in PATH, running one hits the stock-binary path that records an
emulator gap, and the install itself is logged -- what somebody installs is
a statement of what they were about to do. Removal works too, which
matters for the other direction: `apt remove` is how a defence gets turned
off, and the box used to report "0 to remove" and change nothing.

The state is kept where the rest of a source's state lives, so a returning
attacker finds what they installed last visit. Their files were already
journalled; a binary on disk that dpkg denies is worse than either answer.

Output shapes -- the NEW packages block, Get:/Fetched lines, Selecting/
Unpacking/Setting up, the REMOVED block -- were measured by installing and
removing htop on the real trixie guest.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# --- update and install agree ----------------------------------------------

def t_update_and_install_tell_one_story():
    s = sh()
    o, rc = run(s, "apt-get update")
    eq("update rc", rc, 0)
    check("it claims the archive is reachable", "Hit:1 http://deb.debian.org"
          in o, o[:60])
    o2, rc2 = run(s, "apt-get install -y htop")
    eq("so an archive package installs", rc2, 0)
    check("and is not 'unable to locate'",
          "Unable to locate" not in o2, o2[-80:])
    o3, rc3 = run(s, "apt-get install -y nosuchpkgxyz")
    eq("a name that is in no archive still fails", rc3, 100)
    check("with apt's wording",
          "E: Unable to locate package nosuchpkgxyz" in o3, o3[-60:])


def t_install_prints_what_apt_prints():
    s = sh()
    o, _ = run(s, "apt-get install -y htop")
    for frag in ("Reading package lists... Done",
                 "The following NEW packages will be installed:",
                 "0 upgraded, 1 newly installed, 0 to remove",
                 "Need to get 171 kB of archives.",
                 "Get:1 http://deb.debian.org/debian trixie/main amd64 htop",
                 "Fetched 171 kB",
                 "Selecting previously unselected package htop.",
                 "Preparing to unpack .../htop_3.4.1-5_amd64.deb ...",
                 "Unpacking htop (3.4.1-5) ...",
                 "Setting up htop (3.4.1-5) ...",
                 "Processing triggers for man-db"):
        check("the output has: %s" % frag[:44], frag in o, o[:120])


def t_a_second_install_says_so():
    s = sh()
    run(s, "apt-get install -y htop")
    o, rc = run(s, "apt-get install -y htop")
    eq("rc", rc, 0)
    check("it is already the newest version",
          "htop is already the newest version (3.4.1-5)." in o, o[:120])
    check("and nothing is installed twice",
          "0 upgraded, 0 newly installed" in o, o[-80:])


def t_simulate_changes_nothing():
    s = sh()
    o, rc = run(s, "apt-get install -s -y htop")
    eq("rc", rc, 0)
    check("-s prints the Inst lines", "Inst htop (3.4.1-5" in o, o[:200])
    o2, rc2 = run(s, "command -v htop")
    eq("and installs nothing", rc2, 1)


# --- after an install, every reader agrees ---------------------------------

def t_the_package_is_installed_everywhere():
    s = sh()
    run(s, "apt-get install -y nmap")
    o, rc = run(s, "command -v nmap")
    eq("the binary is in PATH", (o.strip(), rc), ("/usr/bin/nmap", 0))
    o2, _ = run(s, "dpkg -l nmap | tail -1")
    check("dpkg lists it", o2.startswith("ii  nmap"), o2[:60])
    check("with the archive's description",
          "The Network Mapper" in o2, o2[:80])
    o3, _ = run(s, "apt list --installed 2>/dev/null | grep nmap")
    check("apt list agrees", "[installed]" in o3, o3[:60])
    o4, _ = run(s, "dpkg -S /usr/bin/nmap")
    eq("dpkg -S names the owner", o4.strip(), "nmap: /usr/bin/nmap")
    o5, _ = run(s, "dpkg -L nmap")
    check("dpkg -L lists its files", "/usr/bin/nmap" in o5, o5[:80])
    o6, rc6 = run(s, "test -x /usr/bin/nmap")
    eq("and the file is executable", rc6, 0)


def t_dependencies_come_with_it():
    s = sh()
    o, _ = run(s, "apt-get install -y build-essential")
    check("gcc and make came along", "gcc" in o and "make" in o, o[:200])
    for b in ("gcc", "make"):
        o2, rc = run(s, "command -v %s" % b)
        eq("%s is on the box" % b, rc, 0)


def t_running_it_records_the_gap():
    """A stock binary with no implementation is a measured gap, not a lie."""
    seen = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77",
                 log=lambda **kw: seen.append(kw))
    s.exec_mode = True
    run(s, "apt-get install -y nmap")
    o, rc = run(s, "nmap -sV 127.0.0.1")
    check("it answers like the binary it claims to be",
          o.startswith("Nmap version 7.95"), o[:80])
    eq("and fails rather than pretending to have scanned", rc, 1)
    gaps = [e for e in seen if e.get("event") == "unknown_command"
            and e.get("command") == "nmap"]
    eq("and the gap is recorded", len(gaps), 1)
    check("marked as a real binary", gaps[0].get("stock_binary"), gaps[0])


def t_the_install_is_logged():
    seen = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77",
                 log=lambda **kw: seen.append(kw))
    s.exec_mode = True
    run(s, "apt-get install -y tcpdump")
    evs = [e for e in seen if e.get("event") == "apt_install"]
    eq("one event", len(evs), 1)
    eq("naming the package", evs[0].get("package"), "tcpdump")
    check("and what it put on the box",
          "tcpdump" in evs[0].get("binaries", ""), evs[0])


# --- removal ----------------------------------------------------------------

def t_remove_actually_removes():
    s = sh()
    run(s, "apt-get install -y htop")
    o, rc = run(s, "apt-get remove -y htop")
    eq("rc", rc, 0)
    check("the REMOVED block is there",
          "The following packages will be REMOVED:" in o, o[:160])
    check("and the Removing line", "Removing htop (3.4.1-5) ..." in o,
          o[-120:])
    o2, rc2 = run(s, "command -v htop")
    eq("the binary is gone", rc2, 1)
    o3, _ = run(s, "dpkg -l htop | tail -1")
    check("dpkg agrees", "no packages found matching htop" in o3, o3[:70])


def t_removing_a_preinstalled_package():
    """`apt remove` is how a defence gets turned off."""
    s = sh()
    o, rc = run(s, "apt-get remove -y curl")
    eq("rc", rc, 0)
    check("it says what it removed", "Removing curl" in o, o[-100:])
    o2, rc2 = run(s, "command -v curl")
    eq("curl is gone from PATH", rc2, 1)
    o3, rc3 = run(s, "curl http://example.com/x")
    eq("and running it is command not found", rc3, 127)
    check("not a stock-binary usage error", "missing operand" not in o3,
          o3[:60])
    o4, _ = run(s, "dpkg -l curl | tail -1")
    check("dpkg has forgotten it",
          "no packages found matching curl" in o4, o4[:70])


def t_the_removal_is_logged():
    seen = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77",
                 log=lambda **kw: seen.append(kw))
    s.exec_mode = True
    run(s, "apt-get purge -y rsyslog")
    evs = [e for e in seen if e.get("event") == "apt_remove"]
    eq("one event", len(evs), 1)
    eq("naming the package", evs[0].get("package"), "rsyslog")
    eq("and that it was a purge", evs[0].get("purge"), True)


# --- the archive itself -----------------------------------------------------

def t_policy_knows_what_is_available():
    s = sh()
    o, rc = run(s, "apt-cache policy tcpdump")
    eq("rc", rc, 0)
    check("not installed", "Installed: (none)" in o, o[:80])
    check("but a candidate exists", "Candidate: 4.99.5-2" in o, o[:120])
    run(s, "apt-get install -y tcpdump")
    o2, _ = run(s, "apt-cache policy tcpdump")
    check("after installing, policy says so",
          "Installed: 4.99.5-2" in o2 or "4.99.5-2" in o2, o2[:120])
    o3, rc3 = run(s, "apt-cache policy nosuchpkgxyz")
    eq("an unknown name is still unknown", rc3, 100)


def t_the_state_survives_a_reconnect():
    """The files are journalled; the package list has to be too."""
    v = fs.VFS()
    s = fs.Shell(v, peer="203.0.113.77")
    s.exec_mode = True
    run(s, "apt-get install -y jq")
    added = {k: list(x) for k, x in getattr(v, "apt_added", {}).items()}
    check("the install is recorded on the filesystem object", "jq" in added,
          added)
    v2 = fs.VFS()
    v2.apt_added = {k: (x[0], x[1], x[2], tuple(x[3]))
                    for k, x in added.items()}
    v2.apt_removed = set(getattr(v, "apt_removed", set()))
    s2 = fs.Shell(v2, peer="203.0.113.77")
    s2.exec_mode = True
    o, _ = run(s2, "dpkg -l jq | tail -1")
    check("and a restored session still has the package",
          o.startswith("ii  jq"), o[:60])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
