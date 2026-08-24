#!/usr/bin/env python3
"""Does every binary the box says it has actually run?

Diicot's eviction step on 2026-08-24 was three `killall` calls -- java, cnrig,
xmrig -- and all three answered "bash: line 1: killall: command not found" on a
box that presents itself as this guest, which has psmisc 23.7-2 and
/usr/bin/killall. `pkill xmrig` on the same box worked. Two ways to kill a
process by name, one of which claimed the command did not exist.

Adding the package is not enough on its own: `dpkg -L psmisc` names seven
binaries, and a name dpkg -L prints has to run, or the fix trades one gap for
six. So the axis here is the package manifest against the shell -- for every
binary every installed package claims, does the shell answer as that program
rather than as the generic unimplemented-binary fallback?

Reference values measured on the guest (psmisc 23.7-2, Debian 13) on
2026-08-24:

    killall java                 stderr "java: no process found", rc 1
    killall                      usage on stderr, rc 1
    killall --bogus              usage on stderr, rc 1
    killall -l                   31 names on two lines, rc 0; signal 29 is
                                 POLL, where bash's `kill -l` says IO
    fuser /tmp                   no output, rc 1
    fuser -v /var/log/syslog     "Specified filename ... does not exist." when
                                 the path is absent
    prtstat 999999               "Process with pid 999999 does not exist.",
                                 rc 0 -- psmisc really does exit 0 there
    pslog 1        as non-root   "opendir: Permission denied"
                   as root       "Pid no 1:"
    peekfd                       10-line usage on stderr, rc 1

Run from ~/opsec/honeypot:  python3 -W ignore psmisctest.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell                                                # noqa: E402

#: killall -l on the guest, verbatim.
GUEST_SIGNAL_LINES = (
    "HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1 SEGV USR2 PIPE ALRM TERM "
    "STKFLT",
    "CHLD CONT STOP TSTP TTIN TTOU URG XCPU XFSZ VTALRM PROF WINCH POLL PWR "
    "SYS",
)
#: dpkg -L psmisc on the guest, binaries only.
GUEST_PSMISC_BINS = ("fuser", "killall", "peekfd", "prtstat", "pslog",
                     "pstree", "pstree.x11")

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("  %s  %s%s" % ("ok  " if cond else "FAIL", name,
                          "" if cond else "  " + str(detail)[:240]))
    return bool(cond)


def eq(name, got, want):
    return check(name, got == want, "got %r want %r" % (got, want))


class Sh:
    """A shell whose stderr and rc are visible."""

    def __init__(self, **kw):
        self.sh = fakeshell.Shell(**kw)
        self.sh.exec_mode = True

    def run(self, cmd):
        self.sh._err = []
        out = self.sh.run(cmd)
        return out, self._err(), None

    def call(self, name, argv):
        """Straight into the handler, so the rc is the program's own."""
        self.sh._err = []
        fn = getattr(self.sh, "cmd_" + name, None)
        if fn is None:
            # Reported, not raised: against a build without the handler the
            # whole list has to run.
            return "", "no cmd_%s handler" % name, None
        out, rc = fn(list(argv))
        return out, self._err(), rc

    def _err(self):
        """stderr as one string. err() keeps each line newline-terminated,
        so joining with a newline doubles them."""
        return "".join(self.sh._err).rstrip("\n")


def main():
    s = Sh()

    # ---- the package is there, and dpkg agrees with itself --------------
    eq("psmisc is in the package list",
       "psmisc" in dict((p[0], p[1]) for p in fakeshell.Shell.PACKAGES),
       True)
    eq("...at the guest's version",
       dict((p[0], p[1]) for p in fakeshell.Shell.PACKAGES).get("psmisc"),
       "23.7-2")
    eq("dpkg -L lists the guest's seven binaries",
       tuple(fakeshell.Shell._PKG_FILES.get("psmisc", ())),
       GUEST_PSMISC_BINS)
    listed = s.run("dpkg -L psmisc")[0]
    for b in GUEST_PSMISC_BINS:
        check("dpkg -L psmisc names /usr/bin/%s" % b,
              "/usr/bin/%s\n" % b in listed, listed[:200])
    eq("dpkg -l psmisc shows it installed",
       bool(re.search(r"^ii\s+psmisc\s+23\.7-2\s", s.run("dpkg -l psmisc")[0],
                      re.M)), True)
    eq("dpkg -S finds the owner of killall",
       s.run("dpkg -S /usr/bin/killall")[0].strip(), "psmisc: /usr/bin/killall")
    eq("which finds killall", s.run("which killall")[0].strip(),
       "/usr/bin/killall")
    eq("command -v agrees with which",
       s.run("command -v killall")[0].strip(), "/usr/bin/killall")
    check("the binary is on disk with a plausible size",
          re.search(r"^-rwxr-xr-x .* \d{4,} .* /usr/bin/killall$",
                    s.run("ls -l /usr/bin/killall")[0].strip()) is not None,
          s.run("ls -l /usr/bin/killall")[0])

    # ---- the whole manifest, not just the one an attacker ran ----------
    # This is the check that would have caught the gap before Diicot did:
    # every binary every installed package claims, answered by a handler of
    # its own rather than by the generic fallback.
    missing = []
    for pkg, names in sorted(fakeshell.Shell._PKG_FILES.items()):
        for n in names:
            base = n.replace(".", "_").replace("-", "_")
            if not hasattr(fakeshell.Shell, "cmd_" + base) and \
                    not hasattr(fakeshell.Shell, "cmd_" + n):
                missing.append("%s/%s" % (pkg, n))
    # Recorded rather than asserted at zero: the fallback is a deliberate
    # answer for the long tail, and the number is what matters -- it must not
    # grow, and psmisc's seven must not be in it.
    print("  note: %d package binaries fall through to the generic fallback"
          % len(missing))
    for b in GUEST_PSMISC_BINS:
        if b == "pstree.x11":
            continue
        # Asserted on the handler, not on the fallback list: a build that
        # does not declare the package at all has nothing on the list for
        # psmisc and passed a check phrased the other way round.
        check("psmisc/%s has a handler of its own" % b,
              hasattr(fakeshell.Shell, "cmd_" + b),
              "cmd_%s missing" % b)

    # ---- killall, the command that failed ------------------------------
    out, err, rc = s.call("killall", ["java"])
    eq("killall on a name with no process says so", err, "java: no process found")
    eq("...and exits 1", rc, 1)
    eq("...and prints nothing on stdout", out, "")
    out, err, rc = s.call("killall", [])
    eq("bare killall exits 1", rc, 1)
    check("...with the usage on stderr, not stdout",
          err.startswith("Usage: killall [OPTION]... [--] NAME...") and not out,
          (err[:80], out[:40]))
    out, err, rc = s.call("killall", ["--bogus"])
    eq("an unknown option exits 1", rc, 1)
    check("...with the same usage", err.startswith("Usage: killall"), err[:60])
    out, err, rc = s.call("killall", ["-l"])
    eq("killall -l exits 0", rc, 0)
    eq("killall -l matches the guest, both lines",
       tuple(out.rstrip("\n").split("\n")), GUEST_SIGNAL_LINES)
    check("killall -l says POLL where kill -l says IO",
          "POLL" in out.split() and "IO" not in out.split(), out)
    # bash writes the SIG prefix; psmisc does not. Both name signal 29
    # their own way and both have to keep doing it.
    check("kill -l still says SIGIO, because bash does",
          "SIGIO" in s.run("kill -l")[0], s.run("kill -l")[0][:80])
    out, err, rc = s.call("killall", ["-V"])
    check("killall -V prints the psmisc banner on stderr",
          err.startswith("killall (PSmisc) 23.7"), err[:60])
    out, err, rc = s.call("killall", ["-q", "nosuchthing"])
    eq("-q suppresses the complaint", err, "")
    eq("...but not the exit status", rc, 1)

    # ---- and it kills, rather than reporting that it did ----------------
    s2 = Sh()
    procs = s2.run("ps -eo pid,comm --no-headers")[0]
    victim = None
    for line in procs.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in ("nginx", "mariadbd", "cron"):
            victim = parts[1]
            break
    if check("there is a daemon to kill", victim is not None, procs[:200]):
        out, err, rc = s2.call("killall", [victim])
        eq("killall on a running daemon exits 0", rc, 0)
        after = s2.run("ps -eo comm --no-headers")[0].split()
        check("...and ps no longer shows it",
              victim not in after, after[:20])
        # pkill and killall have to agree about the same name.
        s3 = Sh()
        s3.call("pkill", [victim])
        eq("pkill leaves ps in the same state killall did",
           victim in s3.run("ps -eo comm --no-headers")[0].split(),
           victim in after)

    # ---- pstree reads the field ps prints ------------------------------
    s4 = Sh()
    ps = s4.run("ps -eo pid,ppid,comm --no-headers")[0]
    parents = {}
    for line in ps.splitlines():
        f = line.split()
        if len(f) == 3:
            parents[int(f[0])] = (int(f[1]), f[2])
    tree, err, rc = s4.call("pstree", [])
    eq("pstree exits 0", rc, 0)
    check("pstree is rooted at systemd", tree.startswith("systemd"), tree[:40])
    # Every non-kernel child of pid 1 has to appear.
    for pid, (ppid, comm) in sorted(parents.items()):
        if ppid != 1:
            continue
        check("pstree shows %s, which ps parents to init" % comm,
              comm[:15] in tree, tree[:300])
    check("pstree collapses identical siblings the way psmisc does",
          re.search(r"\d\*\[", tree) is not None, tree)
    ptree, _e, _rc = s4.call("pstree", ["-p"])
    check("pstree -p carries pids", "systemd(1)" in ptree, ptree[:60])
    check("pstree -p does not collapse, because the pids differ",
          re.search(r"\d\*\[", ptree) is None, ptree[:400])
    for pid, (ppid, comm) in sorted(parents.items()):
        if ppid == 1 and comm != "kthreadd":
            check("pstree -p agrees with ps about %s's pid" % comm,
                  "%s(%d)" % (comm[:15], pid) in ptree, ptree[:400])
    # A chain, checked against ps rather than against a fixed string.
    chain = [(p, v) for p, v in parents.items() if v[1] == "bash"]
    if chain:
        bpid, (bppid, _c) = chain[0]
        check("pstree -p shows bash under the pid ps gives as its parent",
              "%s(%d)" % (parents[bppid][1][:15], bppid) in ptree
              and "bash(%d)" % bpid in ptree, ptree[-200:])

    # ---- the rest of the package --------------------------------------
    out, err, rc = s4.call("fuser", ["/tmp"])
    eq("fuser on a file nobody has open exits 1", rc, 1)
    eq("...silently", (out, err), ("", ""))
    out, err, rc = s4.call("fuser", ["-v", "/var/log/nope"])
    eq("fuser names a path that does not exist", err,
       "Specified filename /var/log/nope does not exist.")
    out, err, rc = s4.call("prtstat", ["1"])
    eq("prtstat 1 exits 0", rc, 0)
    check("prtstat names the process", out.startswith("Process: systemd"),
          out[:60])
    first = out.splitlines()[0] if out.splitlines() else ""
    check("prtstat's first line carries the two tabs the guest's does",
          re.match(r"^Process: \S+ *\t\tState: S \(sleeping\)$", first)
          is not None, repr(first))
    check("prtstat agrees with ps about the parent",
          "Parent ID: 0" in out, out[:300])
    out, err, rc = s4.call("prtstat", ["999999"])
    eq("prtstat on a missing pid says so",
       out.strip(), "Process with pid 999999 does not exist.")
    eq("...and exits 0, as psmisc does", rc, 0)
    out, err, rc = s4.call("pslog", ["1"])
    eq("pslog as root prints the header", out, "Pid no 1:\n")
    nr = Sh(user="deploy")
    out, err, rc = nr.call("pslog", ["1"])
    eq("pslog as a normal user cannot read /proc/1/fd", err,
       "opendir: Permission denied")
    out, err, rc = s4.call("peekfd", [])
    eq("bare peekfd exits 1", rc, 1)
    check("...with the guest's usage on stderr",
          err.startswith("Usage: peekfd [-8] [-n] [-c] [-d] [-V] [-h] <pid>")
          and err.rstrip().endswith("Press CTRL-C to end output."),
          err[:80])

    print("\npsmisctest: passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
