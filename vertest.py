#!/usr/bin/env python3
"""When the box is asked its own version numbers, do the answers agree?

Every command that reports a version is reporting the same handful of facts
about the same installation, and an attacker gets several of those answers
for free while doing something else. `ssh -V` and `sshd -V` come out of one
source package linked against one libssl. `openssl version` reads that same
library. `curl -V` names it. `dpkg -l` lists the package it came in. If any
two of them disagree, there is no configuration of a real Debian box that
explains it.

They disagreed. The OpenSSL build was written out in six places and those
six held three different answers:

    ssh -V, openssl version      OpenSSL 3.5.4 9 Sep 2025
    sshd -V, nginx -V            OpenSSL 3.5.6 7 Apr 2026
    tcpdump --version            OpenSSL 3.5.4 30 Sep 2025
    nmap --version               openssl-3.5.4
    dpkg -l openssl              3.5.4-1

while the guest says 3.5.6 7 Apr 2026 throughout. Two commands out of one
package is the cheapest contradiction on this list to find: type them in
either order and read two lines.

The same axis turned up the version *flag* surface being wrong in both
directions at once:

  * `curl -V` -- the spelling loaders actually use, to see whether they can
    fetch over HTTP/3 before choosing how -- answered "curl: try 'curl
    --help'" with rc 2, and `wget -V` answered "wget: missing URL", while
    `--version` worked for both.
  * `--version` was accepted by all five OpenSSH tools and answered with a
    clean banner and rc 0. Not one of them accepts it: they print "unknown
    option -- -" and their usage. `ssh --version; echo $?` gives 0 here and
    255 on the guest.
  * `scp -V` and `sftp -V` ignored the flag entirely and tried to open a
    connection to a host named "-V", and `ssh-keygen -V` generated a key
    pair -- where -V is a certificate validity interval and needs an
    argument.

And, on the way through, `openssl version -r` printed OPENSSLDIR -- the same
line as -d -- because -a had been written out a second time by hand and the
two copies had drifted; `lsb_release` was missing from a box whose guest has
it installed, though /etc/os-release names trixie; and the CPUINFO line
claimed AVX2, BMI2 and AVX-512 on a CPU whose /proc/cpuinfo advertises none
of them.

Reference output measured on the guest, not recalled.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


S = sh()


def R(cmd, shell=None):
    """(stdout, stderr, rc)."""
    t = shell or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-52s %s" % (name, detail))


def openssl_from(text):
    """The `OpenSSL <ver> <date>` a line carries, or None."""
    m = re.search(r"OpenSSL (\d+\.\d+\.\d+) (\d+ \w+ \d{4})", text or "")
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# One OpenSSL build, however you ask
# ---------------------------------------------------------------------------
def t_openssl_is_one_build():
    ref = openssl_from(R("openssl version")[0])
    check("openssl version names a build", ref is not None,
          R("openssl version")[0][:80])

    _o, e, _r = R("ssh -V")
    check("ssh -V agrees with openssl version", openssl_from(e) == ref,
          "%s != %s" % (openssl_from(e), ref))

    _o, e, _r = R("sshd -V")
    check("sshd -V agrees with ssh -V", openssl_from(e) == ref,
          "%s != %s" % (openssl_from(e), ref))

    _o, e, _r = R("nginx -V")
    check("nginx -V agrees", openssl_from(e) == ref,
          "%s != %s" % (openssl_from(e), ref))

    ver = ref.split()[1]
    out, _e, _r = R("curl -V")
    m = re.search(r"OpenSSL/(\d+\.\d+\.\d+)", out)
    check("curl -V names the same library version",
          m and m.group(1) == ver, "%s != %s" % (m and m.group(1), ver))

    # dpkg is the source these are derived from, so it cannot disagree.
    for pkg in ("openssl", "libssl3t64"):
        out, _e, _r = R("dpkg -l %s" % pkg)
        row = [l for l in out.splitlines() if l.startswith("ii")]
        check("dpkg -l %s is installed" % pkg, bool(row), out[-80:])
        if row:
            pv = row[0].split()[2].split("-")[0].split("+")[0]
            check("dpkg -l %s matches the banner" % pkg, pv == ver,
                  "%s != %s" % (pv, ver))

    out, _e, _r = R("apt-cache policy openssl")
    m = re.search(r"Version: (\S+)", out)
    dv = R("dpkg -l openssl")[0].splitlines()
    dv = [l.split()[2] for l in dv if l.startswith("ii")]
    check("apt-cache policy matches dpkg", m and dv and m.group(1) == dv[0],
          "%s != %s" % (m and m.group(1), dv))


def t_openssl_version_flags_agree_with_a():
    """Every flag prints the line -a prints for it, and -r is not -d."""
    a_out, _e, rc = R("openssl version -a")
    check("openssl version -a rc 0", rc == 0, str(rc))
    lines = a_out.splitlines()
    base = R("openssl version")[0].strip()
    check("-a opens with the plain version line",
          lines and lines[0] == base, (lines or [""])[0])

    want = {
        "-b": "built on: ",
        "-p": "platform: ",
        "-f": "compiler: ",
        "-d": "OPENSSLDIR: ",
        "-e": "ENGINESDIR: ",
        "-m": "MODULESDIR: ",
        "-r": "Seeding source: ",
    }
    for flag, prefix in want.items():
        out, _e, rc = R("openssl version %s" % flag)
        got = out.strip()
        check("openssl version %s has the right subject" % flag,
              got.startswith(prefix), got[:70])
        check("openssl version %s matches its line in -a" % flag,
              got in lines, got[:70])

    # -r printed OPENSSLDIR, which is what -d prints. Two flags, one answer.
    check("-r is not a second spelling of -d",
          R("openssl version -r")[0] != R("openssl version -d")[0],
          R("openssl version -r")[0].strip())

    check("-v is the plain version line",
          R("openssl version -v")[0].strip() == base,
          R("openssl version -v")[0].strip()[:70])

    # Several flags at once come out in the order -a uses.
    two = R("openssl version -m -d")[0].splitlines()
    check("-m -d print in -a's order",
          two == [l for l in lines if l in two], str(two))


def t_cpuinfo_line_matches_the_cpu():
    a_out = R("openssl version -a")[0]
    cpu = [l for l in a_out.splitlines() if l.startswith("CPUINFO:")]
    check("openssl version -a has a CPUINFO line", bool(cpu), a_out[-60:])
    if not cpu:
        return
    words = cpu[0].split("=", 1)[1].split(":")
    check("CPUINFO has the five words OpenSSL 3.5 prints",
          len(words) == 5, "%d words" % len(words))
    flags = R("grep -m1 ^flags /proc/cpuinfo")[0]
    flags = set(flags.split(":", 1)[1].split()) if ":" in flags else set()
    check("/proc/cpuinfo was readable", bool(flags), "no flags line")
    if len(words) < 2 or not flags:
        return
    ext = int(words[1], 16)
    # cpuid leaf 7 EBX: bit 5 AVX2, bit 8 BMI2, bit 16 AVX512F.
    for bit, name in ((5, "avx2"), (8, "bmi2"), (16, "avx512f")):
        check("CPUINFO and /proc/cpuinfo agree about %s" % name,
              bool(ext & (1 << bit)) == (name in flags),
              "ia32cap bit %d set=%s, cpuinfo has %s=%s"
              % (bit, bool(ext & (1 << bit)), name, name in flags))
    check("CPUINFO claims fsgsbase, which /proc/cpuinfo lists",
          bool(ext & 1) == ("fsgsbase" in flags), hex(ext))


# ---------------------------------------------------------------------------
# -V, where it really is the version flag
# ---------------------------------------------------------------------------
def t_dash_v_is_version_for_curl_and_wget():
    for tool in ("curl", "wget"):
        short_o, short_e, short_rc = R("%s -V" % tool)
        long_o, long_e, long_rc = R("%s --version" % tool)
        check("%s -V exits 0" % tool, short_rc == 0,
              "rc=%s %s" % (short_rc, (short_o + short_e)[:60]))
        check("%s -V is the same as --version" % tool,
              (short_o, short_e) == (long_o, long_e),
              (short_o + short_e)[:70])
    # Clustered, the way it is actually typed inside a script.
    check("curl -sV is still the version flag",
          R("curl -sV")[0] == R("curl --version")[0],
          R("curl -sV")[0][:60])
    _o, e, rc = R("ssh -V")
    check("ssh -V still prints to stderr with rc 0",
          rc == 0 and e.startswith("OpenSSH_"), "rc=%s %s" % (rc, e[:50]))


# ---------------------------------------------------------------------------
# --version, which no OpenSSH tool accepts
# ---------------------------------------------------------------------------
LONG_REFUSED = {
    # cmd:            (rc, first stderr line, must the usage follow?)
    "ssh":        (255, "unknown option -- -"),
    "sshd":       (1,   "unknown option -- -"),
    "scp":        (1,   "scp: unknown option -- -"),
    "sftp":       (1,   "unknown option -- -"),
    "ssh-keygen": (1,   "unknown option -- -"),
}


def t_openssh_refuses_long_version():
    for cmd, (rc_want, first) in LONG_REFUSED.items():
        out, err, rc = R("%s --version" % cmd)
        lines = err.splitlines()
        check("%s --version exits %d" % (cmd, rc_want), rc == rc_want,
              "rc=%s" % rc)
        check("%s --version says unknown option" % cmd,
              lines and lines[0] == first, (lines or [""])[0][:70])
        check("%s --version prints nothing on stdout" % cmd, out == "",
              out[:60])
        check("%s --version prints its usage" % cmd,
              any(l.startswith("usage: " + cmd) for l in lines),
              err[:70])
    # sshd is the one that prints its banner as well, before the usage.
    err = R("sshd --version")[1]
    check("sshd --version still prints its banner",
          any(l.startswith("OpenSSH_") for l in err.splitlines()), err[:70])
    check("ssh --version does not print a banner",
          "OpenSSH_" not in R("ssh --version")[1], "banner leaked")


def t_dash_v_is_not_a_version_flag_for_the_rest():
    out, err, rc = R("scp -V")
    check("scp -V exits 1", rc == 1, "rc=%s" % rc)
    check("scp -V rejects the option",
          err.splitlines()[:1] == ["scp: unknown option -- V"], err[:70])
    check("scp -V does not dial a host called -V",
          "connect to host" not in err, err[:70])

    out, err, rc = R("sftp -V")
    check("sftp -V exits 1", rc == 1, "rc=%s" % rc)
    check("sftp -V rejects the option, unprefixed",
          err.splitlines()[:1] == ["unknown option -- V"], err[:70])
    check("sftp -V does not dial a host called -V",
          "connect to host" not in err, err[:70])

    # An option that is real still gets through to the connection attempt.
    err = R("scp -q /tmp/x user@host:/tmp/")[1]
    check("scp with real flags still connects", "connect to host host" in err,
          err[:70])
    err = R("sftp -P 2222 user@host")[1]
    check("sftp -P consumes its argument", "connect to host" in err
          and "unknown option" not in err, err[:70])
    err = R("scp -Z x host:/tmp")[1]
    check("scp rejects other unknown options too",
          "scp: unknown option -- Z" in err, err[:70])


def t_scp_server_modes_are_not_unknown_options():
    """-t and -f are scp's server halves, absent from the usage line.

    Adding option validation here rejected them, and the very next visitor
    needed them: 203.0.113.28 probed seven directories with
    `scp -t <dir>/k0juji2awtsdowvw72bx7huep0` and got "unknown option -- t"
    seven times. On the exec channel these reach scp_sink and never get
    here at all -- see chantest -- but the answer when they do get here has
    to be scp's, not a usage error.

    Measured on the guest: `scp -t /tmp/x </dev/null` writes one NUL and
    exits 0, even for a directory it cannot write to, because all it has
    done is say it is ready. `scp -f` on a missing file exits 1 silently.
    """
    for path in ("/tmp/x", "/bin/y", "/dev/shm/z"):
        out, err, rc = R("scp -t %s" % path)
        check("scp -t %s acks with one NUL" % path, out == "\0", repr(out))
        check("scp -t %s exits 0" % path, rc == 0, "rc=%s" % rc)
        check("scp -t %s says nothing on stderr" % path, err == "", err[:60])
        check("scp -t %s does not dial out" % path,
              "connect to host" not in err, err[:60])
    out, err, rc = R("scp -f /tmp/definitely-not-here")
    check("scp -f on a missing file exits 1", rc == 1, "rc=%s" % rc)
    check("scp -f prints nothing", (out, err) == ("", ""), repr(out + err))
    # The real unknown options still are unknown.
    check("scp -V is still rejected",
          "unknown option -- V" in R("scp -V")[1], R("scp -V")[1][:60])


def t_ssh_keygen_dash_v_wants_an_argument():
    s2 = sh()
    out, err, rc = R("ssh-keygen -V", s2)
    check("ssh-keygen -V exits 1", rc == 1, "rc=%s" % rc)
    check("ssh-keygen -V asks for the argument",
          err.splitlines()[:1] == ["option requires an argument -- V"],
          err[:70])
    check("ssh-keygen -V prints its usage",
          "usage: ssh-keygen" in err, err[:70])
    check("ssh-keygen -V generates nothing", "Generating" not in (out + err),
          (out + err)[:70])
    for p in ("/root/.ssh/id_ed25519", "/root/.ssh/id_rsa"):
        check("ssh-keygen -V left no %s" % p,
              R("test -e %s" % p, s2)[2] != 0, "file exists")
    # With an interval it is a real flag again and the command proceeds.
    out, err, rc = R("ssh-keygen -V +52w -t ed25519 -f /tmp/k -N ''", sh())
    check("ssh-keygen -V with an argument still works",
          "Generating" in (out + err), (out + err)[:70])


# ---------------------------------------------------------------------------
# lsb_release, and its agreement with /etc/os-release
# ---------------------------------------------------------------------------
def t_lsb_release_reads_os_release():
    rel = {}
    for line in R("cat /etc/os-release")[0].splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            rel[k] = v.strip('"')
    check("os-release parsed", "PRETTY_NAME" in rel, str(list(rel)[:3]))

    check("which finds lsb_release",
          R("which lsb_release")[0].strip() == "/usr/bin/lsb_release",
          R("which lsb_release")[0].strip())
    row = [l for l in R("dpkg -l lsb-release")[0].splitlines()
           if l.startswith("ii")]
    check("dpkg lists the package that ships it", bool(row),
          R("dpkg -l lsb-release")[1][:60])

    out, _e, rc = R("lsb_release -a")
    check("lsb_release -a exits 0", rc == 0, "rc=%s" % rc)
    got = dict(l.split(":\t", 1) for l in out.splitlines() if ":\t" in l)
    check("-a prints four fields", len(got) == 4, str(sorted(got)))
    check("Description is PRETTY_NAME",
          got.get("Description") == rel.get("PRETTY_NAME"),
          "%s != %s" % (got.get("Description"), rel.get("PRETTY_NAME")))
    check("Release is VERSION_ID",
          got.get("Release") == rel.get("VERSION_ID"),
          "%s != %s" % (got.get("Release"), rel.get("VERSION_ID")))
    check("Codename is VERSION_CODENAME",
          got.get("Codename") == rel.get("VERSION_CODENAME"),
          "%s != %s" % (got.get("Codename"), rel.get("VERSION_CODENAME")))
    check("Distributor ID is ID, capitalised",
          got.get("Distributor ID") == rel.get("ID", "").capitalize(),
          got.get("Distributor ID"))

    # /etc/debian_version is a third answer to "which release", and the
    # major number has to be the same one.
    dv = R("cat /etc/debian_version")[0].strip()
    check("debian_version agrees with lsb_release -sr",
          dv.split(".")[0] == R("lsb_release -sr")[0].strip(),
          "%s vs %s" % (dv, R("lsb_release -sr")[0].strip()))

    for flag, field in (("-sd", "Description"), ("-sr", "Release"),
                        ("-sc", "Codename"), ("-si", "Distributor ID")):
        check("lsb_release %s is the bare value" % flag,
              R("lsb_release %s" % flag)[0].strip() == got.get(field),
              R("lsb_release %s" % flag)[0].strip())
    check("lsb_release -as drops every label",
          R("lsb_release -as")[0].splitlines()
          == [got["Distributor ID"], got["Description"], got["Release"],
              got["Codename"]],
          R("lsb_release -as")[0].replace("\n", "|"))

    out, err, rc = R("lsb_release")
    check("lsb_release with no arguments prints nothing",
          (out, err, rc) == ("", "", 0), "%r %r %s" % (out, err, rc))
    out, err, rc = R("lsb_release -Z")
    check("an invalid option exits 2", rc == 2, "rc=%s" % rc)
    check("an invalid option names itself",
          err.strip() == "lsb_release: invalid option -- 'Z'", err[:60])
    out, _e, rc = R("lsb_release -h")
    check("-h prints the option list",
          out.startswith("Usage: lsb_release [options]")
          and out.count("\n  -") == 8, out[:60])


# ---------------------------------------------------------------------------
# curl's own detail, re-measured
# ---------------------------------------------------------------------------
def t_curl_version_block():
    out = R("curl -V")[0]
    ver = R("dpkg -l curl")[0].splitlines()
    ver = [l.split()[2] for l in ver if l.startswith("ii")][0]
    check("curl -V names the packaged version",
          out.startswith("curl " + ver.split("-")[0] + " "), out[:40])
    check("curl -V reports the Debian patch level",
          "security patched: " + ver in out,
          out.splitlines()[1] if "\n" in out else out[:60])
    check("nghttp3 is in the library list", "nghttp3/" in out, out[:80])
    feats = [l for l in out.splitlines() if l.startswith("Features:")]
    check("HTTP3 is in the feature list",
          feats and " HTTP3 " in feats[0], (feats or [""])[0][:80])
    check("libpsl is the version the guest has", "libpsl/0.21.2" in out,
          out[:90])


def t_package_descriptions_are_not_the_fallback():
    for pkg in ("openssl", "libssl3t64", "lsb-release"):
        row = [l for l in R("dpkg -l %s" % pkg)[0].splitlines()
               if l.startswith("ii")]
        desc = " ".join(row[0].split()[4:]) if row else ""
        check("dpkg -l %s has a real description" % pkg,
              desc and desc != "Debian %s package" % pkg, desc[:60])


TESTS = [t_openssl_is_one_build,
         t_openssl_version_flags_agree_with_a,
         t_cpuinfo_line_matches_the_cpu,
         t_dash_v_is_version_for_curl_and_wget,
         t_openssh_refuses_long_version,
         t_dash_v_is_not_a_version_flag_for_the_rest,
         t_scp_server_modes_are_not_unknown_options,
         t_ssh_keygen_dash_v_wants_an_argument,
         t_lsb_release_reads_os_release,
         t_curl_version_block,
         t_package_descriptions_are_not_the_fallback]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
