#!/usr/bin/env python3
"""What does a program we have not implemented say about itself?

Around 300 binaries on this box are real files with no implementation
behind them. Every one of them answered the same three lines:

    nmap: missing operand
    Try 'nmap --help' for more information.

to everything -- including `--version`, which is the first thing anyone
types at an unfamiliar binary, and including `--help` itself, which told
the caller to run the command they had just run. That loop is not
something any program prints, "missing operand" is GNU coreutils' wording
and nothing else on the box speaks it, and the box answered `--version`
four different ways depending on which command you picked: a real banner
for flock, a coreutils banner for od, nothing at all for tset, and the
usage error for everything else.

They answer with their own version now, taken from the version this box
already publishes for the owning package -- so `nmap --version` and
`dpkg -l nmap` cannot disagree -- and with a usage line rather than a
reference back to themselves. The gap is still recorded on every call:
that is the number that says which of these an attacker actually wanted.

Banners were measured on a trixie container with the packages installed.

Run from `honeypot/`, or on the guest.
"""

import os
import re
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


# --- the banners we measured ------------------------------------------------

MEASURED = {
    "nmap": "Nmap version 7.95 ( https://nmap.org )",
    "htop": "htop 3.4.1",
    "git": "git version 2.47.3",
    "strace": "strace -- version 6.13",
    "tcpdump": "tcpdump version 4.99.5",
    "jq": "jq-1.7",
}


def t_installed_tools_report_their_version():
    s = sh()
    run(s, "apt-get install -y nmap htop git strace tcpdump jq")
    for name, first in MEASURED.items():
        o, rc = run(s, "%s --version" % name)
        eq("%s --version rc" % name, rc, 0)
        eq("%s prints the banner it prints" % name,
           o.splitlines()[0], first)


def t_the_banner_and_dpkg_agree():
    s = sh()
    run(s, "apt-get install -y nmap")
    o, _ = run(s, "nmap --version")
    ver = re.search(r"(\d+\.\d+)", o).group(1)
    d, _ = run(s, "dpkg -l nmap | tail -1")
    check("the version in the banner is the version dpkg reports",
          ver in d, "%s vs %s" % (ver, d[:60]))


def t_dash_capital_v_is_the_same_answer():
    s = sh()
    run(s, "apt-get install -y strace")
    a, _ = run(s, "strace --version")
    b, _ = run(s, "strace -V")
    eq("-V and --version agree", b, a)


def t_help_does_not_point_at_itself():
    s = sh()
    run(s, "apt-get install -y nmap htop")
    for name in ("nmap", "htop"):
        o, rc = run(s, "%s --help" % name)
        eq("%s --help rc" % name, rc, 0)
        check("%s --help does not tell you to run --help" % name,
              "Try '%s --help'" % name not in o, o[:80])
        # Not every --help has a usage line. Measured: real htop prints its
        # version, the copyright, then the option list, with no "Usage:"
        # anywhere -- so the test is that the help documents options, which
        # is the thing it was really asking.
        if name == "htop":
            check("%s --help lists its options" % name,
                  "--no-color" in o and "--help" in o, o[:80])
        else:
            check("%s --help says how to use it" % name,
                  "sage:" in o, o[:80])
    o2, _ = run(s, "nmap --help")
    check("nmap's help head is nmap's",
          o2.startswith("Nmap 7.95 ( https://nmap.org )"), o2[:60])
    check("and its usage line is the real one",
          "Usage: nmap [Scan Type(s)] [Options] {target specification}" in o2,
          o2[:120])


def t_a_stock_binary_with_no_table_entry_still_answers():
    """iconv used to be the example here, and is not one any more.

    It is a real command now -- see loctest -- and prints glibc's own
    four-line banner, so pinning "^iconv <digit>" was pinning the generic
    fallback to a binary that had outgrown it. The point stands for
    anything still in that category.
    """
    s = sh()
    o, rc = run(s, "mkhomedir_helper --version")
    eq("rc", rc, 0)
    check("it names itself and a version",
          re.match(r"^mkhomedir_helper \d", o), o[:40])
    check("not the usage error", "missing operand" not in o, o[:60])
    # ...and iconv answers with the banner every libc-bin tool prints,
    # measured on the guest.
    o, rc = run(s, "iconv --version")
    eq("iconv --version rc", rc, 0)
    check("iconv prints glibc's banner",
          re.match(r"^iconv \(Debian GLIBC \S+\) \d", o), o[:50])
    check("and credits its author", "Written by Ulrich Drepper." in o,
          o[-40:])


def t_the_wrong_arguments_print_usage_not_coreutils_wording():
    s = sh()
    run(s, "apt-get install -y nmap")
    o, rc = run(s, "nmap -sV 127.0.0.1")
    eq("rc", rc, 1)
    check("it identifies itself", o.startswith("Nmap version"), o[:40])
    check("and prints usage", "Usage: nmap" in o, o[:120])
    check("not coreutils' missing operand", "missing operand" not in o,
          o[:80])


def t_nothing_left_speaks_coreutils_wording():
    """Every coreutils program here is implemented, so nothing that falls
    through to the stock answer should sound like one."""
    s = sh()
    stubs = [n for n in sorted(s.fs.stock_bins)
             if not hasattr(s, "cmd_" + n.replace("-", "_"))]
    check("there are stubs to check", len(stubs) > 40, len(stubs))
    check("none of them belongs to coreutils",
          [n for n in stubs if s._owner_of(n) == "coreutils"] == [],
          [n for n in stubs if s._owner_of(n) == "coreutils"][:5])
    for nm in stubs[:12]:
        o, _ = run(s, nm)
        check("%s does not say missing operand" % nm,
              "missing operand" not in o, o[:60])
        check("%s names itself first" % nm, o.startswith(nm) or
              nm.lower() in o.split("\n")[0].lower(), o[:60])


def t_the_gap_is_still_recorded():
    seen = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77",
                 log=lambda **kw: seen.append(kw))
    s.exec_mode = True
    run(s, "apt-get install -y nmap")
    run(s, "nmap --version")
    run(s, "nmap -sS 10.0.0.0/24")
    gaps = [e for e in seen if e.get("event") == "unknown_command"]
    eq("every call is a measured gap", len(gaps), 2)
    check("with the arguments", "-sS 10.0.0.0/24" in gaps[1].get("argv", ""),
          gaps[1])


def t_a_missing_binary_is_still_missing():
    s = sh()
    o, rc = run(s, "nmap --version")
    eq("before installing it, nmap is not there", rc, 127)
    check("command not found", "command not found" in o, o[:60])


def t_implemented_commands_are_untouched():
    """The ones we do implement must not start answering generically."""
    s = sh()
    for cmd, frag in (("ls --version", "ls (GNU coreutils)"),
                      ("bash --version", "GNU bash"),
                      ("curl --version", "curl "),
                      ("python3 --version", "Python 3.")):
        o, rc = run(s, cmd)
        eq("%s rc" % cmd, rc, 0)
        check("%s is the real implementation's answer" % cmd,
              frag in o, o[:60])


def t_a_gap_is_our_failure_and_not_the_attackers_handiwork():
    """gap=True must mean the emulator fell short, never that the box did.

    2026-09-01, 203.0.113.66, one session:

        13:44:39  readlink -f /proc/21401/exe     answered
        13:44:40  rm -rf /usr/bin                 executed
        13:44:41  crontab -l                      gap=True

    We deleted /usr/bin because we were told to, and then filed our own
    correct behaviour as a coverage hole: 38 emulator_gap findings in
    ninety seconds, on the highest-priority alert this operation has.
    A real Debian box with /usr/bin removed answers "command not found"
    to crontab too, so the question is not "is this a Debian command"
    but "is it still installed on the box as it now stands".
    """
    seen = []
    s = fs.Shell(fs.VFS(), peer="203.0.113.77",
                 log=lambda **kw: seen.append(kw))
    s.exec_mode = True

    # Installed and implemented: the classifier is armed for it.
    for c in ("crontab", "readlink", "awk", "grep", "ps", "sort", "rm"):
        check("%s is a gap-worthy command while it is installed" % c,
              s._gap_is_real(c), c)

    # The attacker removes the directory those binaries live in.
    run(s, "rm -rf /usr/bin")
    seen.clear()
    for c in ("crontab -l", "grep -v x", "awk '{print $2}'", "sort -u",
              "readlink -f /proc/1/exe", "rm -rf ."):
        run(s, c)
    gaps = [e for e in seen if e.get("event") == "unknown_command"]
    check("every command is now not-found", len(gaps) >= 6, len(gaps))
    _flagged = [e.get("command") for e in gaps if e.get("gap")]
    check("...and not one of them is reported as our gap",
          _flagged == [], _flagged)

    # A command that never existed is still not a gap, and a Debian
    # command that is genuinely installed still would be: the alert is
    # narrowed, not switched off.
    s2 = sh()
    check("an invented name is not a gap",
          not s2._gap_is_real("zzznotreal"), True)
    check("an installed Debian command still qualifies",
          s2._gap_is_real("crontab") is True, True)


def t_the_two_debian_commands_we_do_not_ship_are_right_to_be_missing():
    """_REAL_DEBIAN_CMDS lists 209 names; two have no binary here.

    Both were checked against the real Debian 13 underneath rather than
    assumed: nftables is `un` in dpkg so /usr/sbin/nft is correctly
    absent, and trixie's login package genuinely ships no /usr/bin/lastlog
    any more -- confirmed with `dpkg -S /usr/bin/lastlog` on a real trixie
    box, which finds no owner. If either ever gains a binary without an
    implementation behind it, the gap alert should fire, and this records
    why it does not today.
    """
    s = sh()
    missing = [c for c in sorted(fs._REAL_DEBIAN_CMDS)
               if not any(s.fs.exists(d + "/" + c)
                          for d in ("/usr/bin", "/bin", "/usr/sbin",
                                    "/sbin"))]
    check("exactly the two known ones", missing == ["lastlog", "nft"],
          missing)
    check("nftables is not installed, so nft is right to be absent",
          run(s, "dpkg -l nftables | tail -1")[0].strip()[:2] == "un",
          run(s, "dpkg -l nftables | tail -1")[0].strip()[:40])


#: (package, command, first line the real tool prints, does it lead with
#: its own banner). Measured in a debian:trixie container with the real
#: packages, run with nothing they can act on. All exit 1.
MISUSE = [
    ("netcat-openbsd", "nc -z 127.0.0.1 22",
     "usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]",
     False),
    ("screen", "screen -dmS x sleep 1",
     "Use: screen [-opts] [cmd [args]]", False),
    ("strace", "strace -p 1",
     "strace: must have PROG [ARGS] or -p PID", False),
    ("socat", "socat TCP-LISTEN:9999 EXEC:/bin/sh",
     "socat: exactly 2 addresses required (there are 0); "
     "use option \"-h\" for help", False),
    ("tmux", "tmux ls",
     "usage: tmux [-2CDlNuVv] [-c shell-command] [-f file] [-L socket-name]",
     False),
    ("gcc", "gcc /tmp/nosuch.c", "gcc: fatal error: no input files", False),
    # protocol 32, not 31. Measured twice in a clean debian:trixie
    # container with rsync 3.4.1+ds1-5+deb13u4 installed: `rsync --version`
    # there says "rsync  version 3.4.1  protocol version 32". 31 is what
    # rsync 3.2 speaks, and this expectation cited no source.
    ("rsync", "rsync -a /tmp/ /var/tmp/",
     "rsync  version 3.4.1  protocol version 32", True),
    ("vim", "vim -es /tmp/f",
     "VIM - Vi IMproved 9.1 (2024 Jan 02, compiled May 23 2025 00:48:59)",
     True),
    ("nmap", "nmap -sn 10.0.0.0/24",
     "Nmap version 7.95 ( https://nmap.org )", True),
]


def t_a_misused_tool_speaks_its_own_language():
    """The fallback usage line is coreutils' shape, and every coreutils
    program here is implemented -- so a tool reaching it was printing a
    sentence from a family it does not belong to. `nc -z 127.0.0.1 22`
    answered "Usage: nc [OPTION]... [FILE]..." where the real one prints
    its flag soup."""
    s = sh()
    for pkg, _cmd, _first, _banner in MISUSE:
        run(s, "apt-get install -y %s" % pkg)
    run(s, ": > /tmp/f")
    for _pkg, cmd, first, _banner in MISUSE:
        out, rc = run(s, cmd)
        name = cmd.split()[0]
        eq("%s: rc" % name, rc, 1)
        eq("%s: first line" % name, out.splitlines()[0] if out else "", first)
        check("%s: no coreutils usage" % name,
              "[OPTION]... [FILE]..." not in out, out[:70])
        check("%s: no coreutils missing operand" % name,
              "missing operand" not in out, out[:70])


def t_only_the_tools_that_do_lead_with_a_banner_lead_with_one():
    """nc, screen, strace, socat, tmux and gcc print their complaint and
    nothing else; rsync, vim and nmap identify themselves first.

    The set is the ones that suppress it, not the ones that keep it. The
    first version had it the other way round, which dropped the banner
    from all ~300 stubs on the box -- caught by procpstest, which checks
    that `slabtop -o` still says which program could not run.
    """
    s = sh()
    for pkg, _cmd, _first, _banner in MISUSE:
        run(s, "apt-get install -y %s" % pkg)
    run(s, ": > /tmp/f")
    for _pkg, cmd, _first, banner in MISUSE:
        name = cmd.split()[0]
        out, _rc = run(s, cmd)
        head = out.splitlines()[0] if out else ""
        ver = s._stock_upstream(name)
        looks_like_a_bare_banner = head == "%s %s" % (name, ver)
        check("%s: not the generic '<name> <version>' banner" % name,
              not looks_like_a_bare_banner, head[:60])
        if not banner:
            check("%s: goes straight to the complaint" % name,
                  head == _first_of(cmd), head[:60])


def t_a_stub_with_no_usage_entry_still_names_itself():
    """The other ~300. Without a measured usage line of their own, the
    banner is the only thing identifying which program refused."""
    s = sh()
    o, rc = run(s, "slabtop -o")
    eq("rc", rc, 1)
    check("it names itself first", o.splitlines()[0].startswith("slabtop"),
          o[:60])
    check("and still falls back to the generic usage",
          "Usage: slabtop [OPTION]... [FILE]..." in o, o[:120])


def _first_of(cmd):
    for _pkg, c, first, _b in MISUSE:
        if c == cmd:
            return first
    return None


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
