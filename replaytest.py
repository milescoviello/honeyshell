#!/usr/bin/env python3
"""Replay the fingerprinting probes attackers actually sent, against real Debian.

Not a hand-written idea of what a detector might check -- every probe here was
pulled verbatim out of `/var/log/honey/ssh.jsonl`, and carries the number of
times we have seen it and from how many distinct sources. The reference is a
throwaway `debian:trixie-slim` container with no network, which is the machine
the persona claims to be, so "does the emulator behave like the box we say we
are" gets answered by diffing rather than by argument.

Captured payloads are never run on the host. `clean.sh` from the RedTail set
does `chattr -ia`, stops services and strips other people's cron entries;
running attacker shell outside a disposable container would be reckless. Only
inert probes are replayed even so.

Needs docker, and skips loudly rather than passing silently without it.

Usage:  python3 replaytest.py
"""

import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import fakeshell as fs

IMAGE = "debian:trixie-slim"
PASSED, FAILED = [], []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name)
    print("  %-4s %-30s %s" % ("ok" if cond else "FAIL", name, detail), flush=True)


def real(script):
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-w", "/tmp", IMAGE,
         "bash", "-c", script],
        capture_output=True, text=True, timeout=180)
    return r.stdout, r.stderr, r.returncode


def ours(script):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True          # `ssh host '<cmd>'` is never interactive
    out = sh.run(script)
    return out, "".join(sh._err), sh.last_rc


def cmp_exact(ro, re_, rc, oo, oe, orc):
    ok = (ro, re_, rc) == (oo, oe, orc)
    return ok, "" if ok else "real=%r/%r/%s ours=%r/%r/%s" % (
        ro[:60], re_[:60], rc, oo[:60], oe[:60], orc)


def cmp_shell_behavior(ro, re_, rc, oo, oe, orc):
    """Only the SHELL_BEHAVIOR lines: the rest is machine-specific by design."""
    keys = ("path_err=", "cmd_err=", "execute_err=")
    a = [l for l in ro.splitlines() if l.startswith(keys)]
    b = [l for l in oo.splitlines() if l.startswith(keys)]
    ok = a == b
    return ok, (" | ".join(x.split("=", 1)[0] for x in b) if ok
                else "real=%r ours=%r" % (a, b))



def cmp_shape(ro, re_, rc, oo, oe, orc):
    """Same shape and exit status; the bytes are random by construction.

    Used for the randomness helpers a loader calls to name its own files.
    Comparing them exactly would fail on every run for the right reason and
    tell us nothing.
    """
    def shape(t):
        return (len(t.split()), len(t.strip()) // 8, t.strip().isdigit())
    ok = shape(ro) == shape(oo) and rc == orc
    return ok, "" if ok else "real=%r/%s ours=%r/%s" % (
        ro[:50], rc, oo[:50], orc)


def cmp_nonempty(ro, re_, rc, oo, oe, orc):
    """Both must answer something and agree on the exit status.

    For commands whose content is host-specific -- which mounts are noexec
    depends on the machine -- but where silence is the failure we care
    about.
    """
    ok = bool(ro.strip()) == bool(oo.strip()) and rc == orc
    return ok, "" if ok else "real=%r/%s ours=%r/%s" % (
        ro[:50], rc, oo[:50], orc)



def cmp_reference_lacks_it(expect):
    """For a binary our persona has and debian:trixie-slim does not.

    The reference is a *slim* image; our persona is a server with nginx,
    php, mariadb and openssl, all of which dpkg lists and PATH resolves. So
    "openssl rand" working here and not in the container is correct, and
    diffing them would be comparing against the wrong machine -- the same
    mistake as measuring the dev host instead of the guest, one layer out.
    Assert both halves explicitly: the reference must genuinely not have it,
    and ours must produce the expected shape.
    """
    def cmp(ro, re_, rc, oo, oe, orc):
        missing = "command not found" in re_
        ok = missing and oo.strip() == expect
        return ok, "" if ok else (
            "reference unexpectedly has it" if not missing
            else "ours=%r want=%r" % (oo.strip()[:40], expect))
    return cmp


PROBES = [
    # --- lifted from the RedTail staging scripts captured 2026-08-21 -----
    # setup.sh and clean.sh from 203.0.113.24. Not the scripts themselves --
    # clean.sh strips other people's cron entries and chattr -ia's its way
    # there, and this harness runs its reference in a real container. These
    # are the individual commands they call, which are inert. Every one of
    # them was wrong here before that capture arrived.
    ("od -N byte limit", 1, 1,
     "od -An -N2 -i /dev/urandom", cmp_shape),
    ("loader random length", 1, 1,
     "expr $(od -An -N2 -i /dev/urandom | tr -d ' ') % 32 + 4", cmp_shape),
    # 32 random bytes -> 44 base64 chars + newline; 8 -> 16 hex + newline.
    ("openssl rand -base64", 1, 1,
     "openssl rand -base64 32 | wc -c", cmp_reference_lacks_it("45")),
    ("openssl rand -hex", 1, 1,
     "openssl rand -hex 8 | wc -c", cmp_reference_lacks_it("17")),
    ("urandom string helper", 1, 1,
     "tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12 | wc -c", cmp_exact),
    ("truncate size suffix", 1, 1,
     "truncate -s 2M /tmp/_p && stat -c %s /tmp/_p; rm -f /tmp/_p",
     cmp_exact),
    ("truncate 512K", 1, 1,
     "truncate -s 512K /tmp/_q && stat -c %s /tmp/_q; rm -f /tmp/_q",
     cmp_exact),
    ("findmnt combined flags", 1, 1,
     "findmnt -rn -O noexec -o TARGET >/dev/null 2>&1; echo $?", cmp_exact),
    ("findmnt noexec listing", 1, 1,
     "findmnt -rn -O noexec -o TARGET", cmp_nonempty),
    ("noexec via /proc/mounts", 1, 1,
     "cat /proc/mounts | grep 'noexec' | awk '{print $2}' | wc -l",
     cmp_nonempty),
    ("uname -mp", 1, 1, "uname -mp", cmp_exact),
    ("dd 2M probe", 1, 1,
     "cd /tmp && dd if=/dev/zero of=.t2 bs=2M count=1 >/dev/null 2>&1; "
     "echo $?; rm -f .t2", cmp_exact),
    ("grep -vE cleaner", 1, 1,
     "printf 'keep\\nwget evil\\nkeep2\\n' | "
     "grep -vE 'wget|curl|/dev/tcp|/tmp|\\.sh|nc|bash -i|sh -i|base64 -d'",
     cmp_exact),
    ("echo round-trip", 1577, 2, "echo xsec", cmp_exact),
    ("RouterOS probe", 2, 2, "/ip cloud print", cmp_exact),
    ("/bin/echo size", 1, 1,
     "echo 1 > /dev/null && cat /bin/echo | wc -c", cmp_exact),
    ("/bin/echo ELF header", 1, 1,
     "head -c 20 /bin/echo | od -An -tx1", cmp_exact),
    ("busybox absent as on Debian", 0, 0,
     "busybox uname -m 2>&1; echo rc=$?", cmp_exact),
    ("SHELL_BEHAVIOR block", 79, 9, 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH\nuname=$(uname -s -v -n -m 2>/dev/null || /bin/uname -s -v -n -m 2>/dev/null || /usr/bin/uname -s -v -n -m 2>/dev/null || busybox uname -s -v -n -m 2>/dev/null || ( [ -f /proc/version ] && head -1 /proc/version | cut -d\' \' -f1 ) || ( [ -f /etc/os-release ] && grep \'^ID=\' /etc/os-release | cut -d= -f2 | tr -d \'"\' ) || echo "")\narch=$(uname -m 2>/dev/null || /bin/uname -m 2>/dev/null || /usr/bin/uname -m 2>/dev/null || busybox uname -m 2>/dev/null || ( [ -f /proc/cpuinfo ] && grep -q "lm" /proc/cpuinfo && echo x86_64 ) || ( [ -f /proc/cpuinfo ] && grep -q "CPU architecture: 8" /proc/cpuinfo && echo aarch64 ) || ( [ -f /proc/cpuinfo ] && grep -q "CPU architecture: 7" /proc/cpuinfo && echo armv7l ) || echo "")\nuptime=$(cat /proc/uptime 2>/dev/null || busybox cat /proc/uptime 2>/dev/null)\ncpus=$(nproc 2>/dev/null || /usr/bin/nproc 2>/dev/null || busybox nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null)\ncpu_model=$( { lscpu 2>/dev/null | awk -F: \'/Model name/ {print $2}\'; grep -m1 -E "^model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2-; grep -m1 -E "^Hardware" /proc/cpuinfo 2>/dev/null | cut -d: -f2-; cat /proc/device-tree/model 2>/dev/null; } | sed \'/^$/d; /unknown/d; s/^[[:space:]]*//; s/[[:space:]]*$//; s/ AArch64 Processor$//; s/ Processor$//; s/ CPU$//\' | head -1 )\ngpu_info=$( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia; busybox lspci 2>/dev/null | grep -i vga; busybox lspci 2>/dev/null | grep -i nvidia) 2>/dev/null )\nlast_output=$(last 2>/dev/null)\nfilter_output=$( ( export LANG=C LC_ALL=C; echo \'===SHELL_BEHAVIOR===\'; printf \'path_err=\'; ( ./xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d \'\\n\' 2>/dev/null || busybox tr -d \'\\n\' 2>/dev/null || cat ); printf \'\\n\'; printf \'cmd_err=\'; ( xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d \'\\n\' 2>/dev/null || busybox tr -d \'\\n\' 2>/dev/null || cat ); printf \'\\n\'; printf \'execute_err=\'; out=$(bash -c \'printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter\' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(/bin/bash -c \'printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter\' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(/usr/bin/bash -c \'printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter\' 2>&1); case "$out" in *xxxxxx*) ;; *) out=$(busybox sh -c \'printf "#!/bin/sh\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter\' 2>&1 || sh -c \'printf "#!/bin/sh\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter\' 2>&1); esac; esac; esac; printf \'%s\' "$out" | ( head -c 250 2>/dev/null || busybox head -c 250 2>/dev/null || dd bs=250 count=1 2>/dev/null ) | ( tr -d \'\\n\' 2>/dev/null || busybox tr -d \'\\n\' 2>/dev/null || cat ); printf \'\\n\'; echo \'===DONE===\' ) 2>&1 )\necho "UNAME:$uname"\necho "ARCH:$arch"\necho "UPTIME:$uptime"\necho "CPUS:$cpus"\necho "CPU_MODEL:$cpu_model"\necho "GPU:$gpu_info"\necho "LAST:$last_output"\necho "FILTER:$filter_output"', cmp_shell_behavior),
]


def main():
    try:
        subprocess.run(["docker", "image", "inspect", IMAGE],
                       capture_output=True, check=True, timeout=60)
    except Exception:
        print("SKIP: %s not present. Run:  docker pull %s" % (IMAGE, IMAGE))
        return 0
    for name, times, ips, script, cmp in PROBES:
        seen = "%dx/%dIP" % (times, ips) if times else "synthetic"
        try:
            ro, re_, rc = real(script)
            oo, oe, orc = ours(script)
        except Exception as exc:
            check(name, False, repr(exc)[:110])
            continue
        ok, detail = cmp(ro, re_, rc, oo, oe, orc)
        check(name, ok, ("%-10s %s" % (seen, detail))[:100])
    print("\n" + "=" * 58)
    print("passed %d, failed %d" % (len(PASSED), len(FAILED)))
    if FAILED:
        print("failed: " + ", ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
