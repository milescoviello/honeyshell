#!/usr/bin/env python3
"""What every installable tool says when asked its version.

`<tool> --version` is standard recon, and a wrong string is a fingerprint
that costs nothing to check and cannot be explained away. Found by the
loop's feature-test step: install each tool the way an attacker does, ask
its version, and compare against the same package installed in a
debian:trixie container.

Sixteen tools carry a banner template. With each package installed on both
sides, seventeen of thirty-two comparisons differed. Three were outright
wrong version numbers and are fixed here:

    gdb     was  GNU gdb (Debian 16.2) 16.2
            is   GNU gdb (Debian 16.3-1) 16.3
    rsync   was  rsync  version 3.4.1  protocol version 31
            is   rsync  version 3.4.1  protocol version 32
    screen  was  Screen version 4.9.1 (GNU) 20-Aug-24
            is   Screen version 4.09.01 (GNU) 20-Aug-23

Each needed something the old entry could not express. gdb prints two
different versions on one line -- the Debian revision in the parenthesis
and the upstream version after it -- and the renderer substitutes one
value everywhere, so it is a literal now. screen zero-pads: the package is
4.9.1-3 and the binary says 4.09.01, which no rule derives from it, the
same shape as the jq note already in that table. rsync's protocol 31 is
rsync 3.2's; trixie speaks 32.

The package versions moved with them, so `dpkg -l` and the binary agree:
gdb 16.3-1, rsync 3.4.1+ds1-5+deb13u4, screen 4.9.1-3, all from
dpkg-query in the container.

## a version flag is not one behaviour

Measured per tool in debian:trixie with stdin at /dev/null and the two
streams captured separately, because which stream a tool answers on is
half of what it says. Answering a clean banner to both spellings told an
attacker in one command that this is not the tool it claims to be:

    gdb -V        stderr  gdb: unrecognized option '-V'           rc 1
    git -V        stderr  unknown option: -V, then its usage      rc 129
    ncat -V       stderr  ncat: invalid option -- 'V'             rc 2
    tcpdump -V    stderr  option requires an argument -- 'V'      rc 1
    vim -V        stderr  two warnings about the terminal         rc 1
    screen -V     stdout  its whole 39-line usage                 rc 1
    zsh -V        nothing at all                                  rc 0
    tmux -V       stdout  the banner                              rc 0
    socat -V      stdout  the banner                              rc 0
    tmux --version   stderr  its usage                            rc 1
    lsof --version   stderr  two complaints, version, usage       rc 1
    lsof -v          stderr  the real version flag                rc 0
    ncat --version   stderr  the banner, and still exits 0
    socat --version  stderr  a date- and pid-stamped E line       rc 1

`ncat --version` putting its banner on *stderr* while exiting 0 is the
one that reads like an error and is not. socat stamps its errors with the
date and its own pid, so that message is built at run time from the box's
pid counter rather than being a table entry, and what this suite pins is
its shape.

## first lines are not bodies

The first pass at the table above answered the *first line* of each, which
is a different wrong answer. Real gdb prints two lines, git seven,
tcpdump thirteen, screen thirty-nine, and `2>&1 | wc -l` is cheaper than
reading any of them. The same truncation was in the banners themselves:
`gdb --version` is five lines, `rsync --version` twenty,
`vim --version` forty-seven, `socat -V` forty-nine, and this box answered
one line to each. Every body is now the measured one, and this suite pins
byte counts and line counts as well as text, since a count is what catches
a body that has been cut short.

Two of those bodies are built rather than pasted, and that is the point of
the checks at the end:

  * `tcpdump -V` quotes its own `--version` block in the middle of the
    refusal, so it is the banner there rather than a second copy of the
    same four lines -- and the OpenSSL line in it names *this box's*
    libssl, 3.5.6, which `openssl version` and `dpkg -l libssl3t64` also
    say. The container's 3.5.7 would be a wrong answer here.
  * `socat -V` names the kernel it runs on. That line is composed from the
    constants `uname` reads, because a socat banner naming a kernel
    `uname -a` does not is one box described twice.

Two gaps left on purpose: `lsof -V` really runs lsof and lists open files,
and `vim -V`'s stdout is a 26-line trace of the files vim sourced --
/etc/vim/vimrc, /usr/share/vim/vim91/debian.vim -- which this box's
package install does not create, so inventing the trace would contradict
`ls`. Both are implementations rather than messages. ncat and zsh are also
not installable on this persona, so their rows are what the table would
answer rather than something reachable today. All recorded in
findings/sweep-274.

Usage:  python3 toolvertest.py
"""

import re
import sys

import fakeshell as fs

CHECKS, FAILS = [], []

# (package, binary, exact first line of --version), every row measured
# with that package installed in debian:trixie.
FIXED = [
    ("gdb", "gdb", "GNU gdb (Debian 16.3-1) 16.3"),
    ("rsync", "rsync", "rsync  version 3.4.1  protocol version 32"),
    ("screen", "screen", "Screen version 4.09.01 (GNU) 20-Aug-23"),
]

# Already correct, pinned so they cannot drift the way the three above did.
CORRECT = [
    ("tcpdump", "tcpdump", "tcpdump version 4.99.5"),
    ("nmap", "nmap", "Nmap version 7.95 ( https://nmap.org )"),
    ("htop", "htop", "htop 3.4.1"),
    ("jq", "jq", "jq-1.7"),
    ("net-tools", "netstat", "net-tools 2.10"),
    ("strace", "strace", "strace -- version 6.13"),
    ("git", "git", "git version 2.47.3"),
    ("vim", "vim",
     "VIM - Vi IMproved 9.1 (2024 Jan 02, compiled May 23 2025 00:48:59)"),
]

# What dpkg must say, so the binary and the package database agree.
PKG_VERSION = [
    ("gdb", "16.3-1"),
    ("rsync", "3.4.1+ds1-5+deb13u4"),
    ("screen", "4.9.1-3"),
    # Both of these were wrong, and both are quoted inside a body this
    # suite pins: socat prints its upstream version in its banner, and
    # lsof's -v output names the reproducible-build path that carries
    # +dfsg. A body measured from the real package and a version string
    # that is not that package's is the same contradiction as before.
    ("socat", "1.8.0.3-1+deb13u1"),
    ("lsof", "4.99.4+dfsg-2"),
]


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def nth(text, i):
    """Line i of a body, or "" -- a suite that IndexErrors against the
    previous commit reports a traceback instead of the failures it was
    written to find, and takes the rest of its own run down with it."""
    lines = (text or "").split("\n")
    return lines[i] if len(lines) > i else ""


def after_first(text):
    """Everything past the first line, or ""."""
    parts = (text or "").split("\n", 1)
    return parts[1] if len(parts) > 1 else ""


def streams(pkg, cmd):
    """Install the package the way an attacker does, then run cmd.

    Returns (stdout, stderr, rc) separately: a tool that answers on the
    wrong stream is visible to `cmd 2>/dev/null` and merging them here
    would hide exactly that.
    """
    try:
        sh = fs.Shell(fs.VFS(), peer="203.0.113.88")
        sh.exec_mode = True
        sh.run("apt-get install -y %s" % pkg)
        sh._err = []
        out = sh.run(cmd) or ""
        err = "".join(sh._err)
        sh._err = []
        return out, err, sh.last_rc
    except Exception as exc:                                   # noqa: BLE001
        return "", "<%s>" % exc, None


def installed(pkg, cmd):
    """Merged output, for the first-line checks that predate the bodies."""
    out, err, rc = streams(pkg, cmd)
    return (out + err).strip(), rc


# ======================================= the three that were wrong
for pkg, binary, want in FIXED:
    out, rc = installed(pkg, "%s --version" % binary)
    check("%s --version" % binary, out.split("\n")[0], want,
          "measured with %s installed in debian:trixie" % pkg)
    check("...exits 0: %s" % binary, rc, 0)

# ...and the package database agrees with the binary.
for pkg, want in PKG_VERSION:
    out, _rc = installed(pkg, "dpkg-query -W -f '${Version}' %s" % pkg)
    check("dpkg says %s is %s" % (pkg, want), out.strip(), want,
          "the binary and dpkg -l must not disagree about one package")

# =============================== the ones that were already right
for pkg, binary, want in CORRECT:
    out, rc = installed(pkg, "%s --version" % binary)
    check("%s --version unchanged" % binary, out.split("\n")[0], want,
          "pinned so it cannot drift the way gdb, rsync and screen did")

# =================== a version flag is not one behaviour
# The whole of what each short answer is, byte for byte from a
# debian:trixie container. Anything short enough to read is pinned whole;
# the long bodies are pinned by shape below, because pasting 3 kB of vim
# banner into a test only restates the table it is checking.
GDB_V = (
    "gdb: unrecognized option '-V'\n"
    "Use `gdb --help' for a complete list of options.\n"
)

GIT_V = (
    "unknown option: -V\n"
    "usage: git [-v | --version] [-h | --help] [-C <path>] [-c "
    "<name>=<value>]\n"
    "           [--exec-path[=<path>]] [--html-path] [--man-path] "
    "[--info-path]\n"
    "           [-p | --paginate | -P | --no-pager] [--no-replace-objects] "
    "[--no-lazy-fetch]\n"
    "           [--no-optional-locks] [--no-advice] [--bare] "
    "[--git-dir=<path>]\n"
    "           [--work-tree=<path>] [--namespace=<name>] "
    "[--config-env=<name>=<envvar>]\n"
    "           <command> [<args>]\n"
)

LSOF_LONG = (
    "lsof: illegal option character: -\n"
    "lsof: -e not followed by a file system path: \"rsion\"\n"
    "lsof 4.99.4\n"
    " latest revision: https://github.com/lsof-org/lsof\n"
    " latest FAQ: https://github.com/lsof-org/lsof/blob/master/00FAQ\n"
    " latest (non-formatted) man page: "
    "https://github.com/lsof-org/lsof/blob/master/Lsof.8\n"
    " usage: [-?abhHKlnNoOPRtUvVX] [+|-c c] [+|-d s] [+D D] [+|-E] [+|-e "
    "s] [+|-f[gG]]\n"
    " [-F [f]] [-g [s]] [-i [i]] [+|-L [l]] [+m [m]] [+|-M] [-o [o]] [-p s]\n"
    " [+|-r [t]] [-s [p:s]] [-S [t]] [-T [t]] [-u s] [+|-w] [-x [fl]] [--] "
    "[names]\n"
    "Use the ``-h'' option to get more help information.\n"
)

LSOF_v = (
    "lsof version information:\n"
    "    revision: 4.99.4\n"
    "    copyright notice: Copyright 1998 Purdue Research Foundation. All "
    "rights reserved.\n"
    "    latest revision: https://github.com/lsof-org/lsof\n"
    "    latest FAQ: https://github.com/lsof-org/lsof/blob/master/00FAQ\n"
    "    latest (non-formatted) man page: "
    "https://github.com/lsof-org/lsof/blob/master/Lsof.8\n"
    "    constructed on: x86_64-pc-linux-gnu\n"
    "    compiler: gcc\n"
    "    compiler flags: -g -O2 -Werror=implicit-function-declaration "
    "-ffile-prefix-map=/build/reproducible-path/lsof-4.99.4+dfsg=. "
    "-fstack-protector-strong -fstack-clash-protection -Wformat "
    "-Werror=format-security -fcf-protection -D_FILE_OFFSET_BITS=64 "
    "-I/usr/include/tirpc \n"
    "    loader flags: -Wl,-z,relro -Wl,-z,now -ltirpc  -lselinux\n"
    "    features enabled: ipv6 ptyept rpc selinux soopt sostate tasks "
    "uxsockept\n"
    "    Anyone can list all files.\n"
    "    /dev warnings are disabled.\n"
    "    Kernel ID check is disabled.\n"
)

TMUX_LONG = (
    "usage: tmux [-2CDlNuVv] [-c shell-command] [-f file] [-L socket-name]\n"
    "            [-S socket-path] [-T features] [command [flags]]\n"
)

VIM_V_ERR = ("Vim: Warning: Output is not to a terminal\n"
             "Vim: Warning: Input is not from a terminal\n")

# (package, binary, flag, stdout, stderr, rc)
FLAG_BODIES = [
    ("gdb", "gdb", "-V", "", GDB_V, 1),
    ("git", "git", "-V", "", GIT_V, 129),
    ("lsof", "lsof", "--version", "", LSOF_LONG, 1),
    ("lsof", "lsof", "-v", "", LSOF_v, 0),
    ("tmux", "tmux", "--version", "", TMUX_LONG, 1),
    ("vim", "vim", "-V", "", VIM_V_ERR, 1),
]

for pkg, binary, flag, w_out, w_err, w_rc in FLAG_BODIES:
    out, err, rc = streams(pkg, "%s %s" % (binary, flag))
    check("%s %s -> stdout" % (binary, flag), out, w_out,
          "which stream it uses is part of the answer")
    check("%s %s -> all of stderr" % (binary, flag), err, w_err,
          "the first line on its own was the previous wrong answer")
    check("%s %s -> rc" % (binary, flag), rc, w_rc)
    pout, perr, prc = streams(pkg, "/usr/bin/%s %s" % (binary, flag))
    check("...and /usr/bin/%s %s answers the same" % (binary, flag),
          (pout, perr, prc), (out, err, rc),
          "the name form reaches the central version hook and the path "
          "form lands in the stub answerer; those two generators have "
          "disagreed about the same binary before")

# ================================ the long bodies, pinned by shape
# (package, binary, flag, stream, bytes, lines, first, last, an interior
# line). Byte and line counts are what catch a body cut short, which is
# how the first version of this table was wrong.
SHAPES = [
    ("screen", "screen", "-V", "stdout", 2074, 39,
     "Use: screen [-opts] [cmd [args]]",
     "Error: Unknown option -V",
     "-dmS name     Start as daemon: Screen session in detached mode."),
    ("socat", "socat", "-V", "stdout", 1341, 49,
     "socat by Gerhard Rieger and contributors - see www.dest-unreach.org",
     "  #define WITH_DEFAULT_IPV 4",
     "  #define WITH_TUN 1"),
    ("vim", "vim", "--version", "stdout", 3243, 47,
     "VIM - Vi IMproved 9.1 (2024 Jan 02, compiled May 23 2025 00:48:59)",
     "Linking: gcc -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -o vim -lm "
     "-ltinfo -lselinux -lsodium -lacl -lattr -lgpm ",
     "Huge version without GUI.  Features included (+) or not (-):"),
    ("rsync", "rsync", "--version", "stdout", 850, 20,
     "rsync  version 3.4.1  protocol version 32",
     "General Public Licence for details.",
     "Checksum list:"),
    ("gdb", "gdb", "--version", "stdout", 278, 5,
     "GNU gdb (Debian 16.3-1) 16.3",
     "There is NO WARRANTY, to the extent permitted by law.",
     "Copyright (C) 2024 Free Software Foundation, Inc."),
    ("strace", "strace", "--version", "stdout", 327, 6,
     "strace -- version 6.13",
     "Optional features enabled: stack-trace=libunwind stack-demangle "
     "m32-mpers mx32-mpers",
     "Copyright (c) 1991-2025 The strace developers <https://strace.io>."),
    ("tcpdump", "tcpdump", "-V", "stderr", 660, 13,
     "tcpdump: option requires an argument -- 'V'",
     "\t\t[ -z postrotate-command ] [ -Z user ] [ expression ]",
     "libpcap version 1.10.5 (with TPACKET_V3)"),
    ("tcpdump", "tcpdump", "--version", "stdout", 117, 4,
     "tcpdump version 4.99.5",
     "64-bit build, 64-bit time_t",
     "libpcap version 1.10.5 (with TPACKET_V3)"),
]

for pkg, binary, flag, stream, nbytes, nlines, first, last, mid in SHAPES:
    out, err, rc = streams(pkg, "%s %s" % (binary, flag))
    body, other = (out, err) if stream == "stdout" else (err, out)
    check("%s %s uses %s only" % (binary, flag, stream), other, "",
          "a body on the wrong stream is visible to 2>/dev/null")
    check("%s %s is %d bytes" % (binary, flag, nbytes), len(body), nbytes,
          "measured in debian:trixie; a short count means a cut body")
    check("%s %s is %d lines" % (binary, flag, nlines),
          body.count("\n"), nlines,
          "`2>&1 | wc -l` is cheaper than reading the text")
    lines = body.split("\n")[:-1]
    check("%s %s first line" % (binary, flag), lines[0] if lines else "",
          first)
    check("%s %s last line" % (binary, flag), lines[-1] if lines else "",
          last, "the tail is what a first-line-only answer loses")
    check("%s %s keeps its middle" % (binary, flag), mid in lines, True,
          "got %d lines" % len(lines))

# ============== the flags that really are the banner, both spellings
for pkg, binary in (("htop", "htop"), ("jq", "jq"), ("nmap", "nmap"),
                    ("rsync", "rsync"), ("strace", "strace"),
                    ("net-tools", "netstat")):
    long_out, long_err, long_rc = streams(pkg, "%s --version" % binary)
    short_out, short_err, short_rc = streams(pkg, "%s -V" % binary)
    check("%s -V is the banner, same as --version" % binary,
          (short_out, short_err, short_rc),
          (long_out, long_err, long_rc),
          "these six really do answer both spellings identically, which "
          "is why the table names the ones that do not")
    check("...and it is not empty: %s" % binary, bool(short_out.strip()),
          True)

# tmux and socat answer the banner to the short spelling only.
out, err, rc = streams("tmux", "tmux -V")
check("tmux -V is the banner", (out, err, rc), ("tmux 3.5a\n", "", 0))
out, err, rc = streams("socat", "socat -V")
check("socat -V leads with its own name", out.split("\n")[0],
      "socat by Gerhard Rieger and contributors - see www.dest-unreach.org")
check("...on stdout, exit 0", (err, rc), ("", 0))

# ===================== the two bodies that are built, not pasted
# tcpdump quotes its own --version block inside the refusal, so the two
# must be the same four lines rather than two copies that can drift.
ver_out, _ver_err, _rc = streams("tcpdump", "tcpdump --version")
_out, dash_v_err, _rc = streams("tcpdump", "tcpdump -V")
check("tcpdump -V quotes its --version block verbatim",
      after_first(dash_v_err).startswith(ver_out) and bool(ver_out), True,
      "got %r" % after_first(dash_v_err)[:60])

# ...and the OpenSSL line in it is this box's own libssl, not the
# container's 3.5.7.
ssl_out, _e, _rc = streams("openssl", "openssl version")
ssl_line = "OpenSSL " + " ".join(ssl_out.split()[1:5])
check("...naming the libssl this box actually claims",
      ssl_line in ver_out.split("\n"), True,
      "openssl version says %r; the banner has %r"
      % (ssl_out.strip(), nth(ver_out, 2)))

# socat names the kernel it runs on, and uname is the other reader of the
# same three values.
sh = fs.Shell(fs.VFS(), peer="203.0.113.88")
sh.exec_mode = True
sh.run("apt-get install -y socat")
kver = (sh.run("uname -v") or "").strip()
krel = (sh.run("uname -r") or "").strip()
kmac = (sh.run("uname -m") or "").strip()
sh._err = []
socat_out = sh.run("socat -V") or ""
check("socat -V names the kernel uname names",
      nth(socat_out, 2),
      "   running on Linux version %s, release %s, machine %s"
      % (kver, krel, kmac),
      "a banner naming a kernel uname does not is one box described twice")

# socat's own version line quotes the upstream half of the package version.
pkg_ver, _rc = installed("socat", "dpkg-query -W -f '${Version}' socat")
upstream = re.split(r"[-+~]", pkg_ver.strip().split(":")[-1])[0]
check("...and its version line is dpkg's upstream version",
      nth(socat_out, 1),
      "socat version %s on 03 Sep 2026 20:58:48" % upstream,
      "dpkg says %r" % pkg_ver.strip())

# lsof -v prints the same revision dpkg does.
pkg_ver, _rc = installed("lsof", "dpkg-query -W -f '${Version}' lsof")
upstream = re.split(r"[-+~]", pkg_ver.strip().split(":")[-1])[0]
_o, lsof_v_err, _rc = streams("lsof", "lsof -v")
check("lsof -v prints dpkg's revision",
      "    revision: %s" % upstream in lsof_v_err.split("\n"), True,
      "dpkg says %r" % pkg_ver.strip())

# socat stamps its own errors with the date and its pid, so the shape is
# what can be pinned, not the text.
out, err, rc = streams("socat", "socat --version")
err = err.strip()
check("socat --version exits 1", rc, 1)
check("...writes nothing to stdout", out, "")
check("...and stamps the E line with a date and its own pid",
      bool(re.match(r'^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d socat\[\d+\] '
                    r'E unknown option "--version"; '
                    r'use option "-h" for help$', err)), True,
      "got %r (%d chars)" % (err, len(err)))

# ================== the two rows that are measured but unreachable
# ncat is not in this box's package list and zsh installs without
# delivering a runnable binary, so neither row can be exercised here.
# They stay in the table with their measurements, and this check keeps
# them from being deleted as dead weight before they become reachable --
# both are recorded in findings/sweep-274.
for row in (("ncat", "-V"), ("ncat", "--version"), ("zsh", "-V")):
    check("the table still carries %s %s" % row,
          row in getattr(fs.Shell, "TOOL_VERSION_FLAG", {}), True,
          "measured in debian:trixie even though this persona cannot "
          "reach it yet")

# ============ a tool nobody installed is still absent, not versioned
sh = fs.Shell(fs.VFS(), peer="203.0.113.88")
sh.exec_mode = True
out = sh.run("gdb --version")
err = "".join(sh._err)
sh._err = []
check("gdb is absent until installed", "command not found" in (out + err),
      True, "the banner must come from the package, not from thin air")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
