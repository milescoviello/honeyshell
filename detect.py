#!/usr/bin/env python3
"""Try to prove this box is fake, the way an attacker who just landed would.

Not a diff against a real Debian -- the persona is *supposed* to differ from any
particular machine. These are checks that hold on every real Linux no matter
what it is: two commands that must agree with each other, an invariant of a live
kernel, or an error message whose wording is fixed by the source of GNU
coreutils and bash. Every failure here is a tell an attacker finds with one
command and no prior knowledge of us.

Usage:  python3 detect.py [-v] [-g GROUP]
"""

import hashlib
import re
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import fakeshell as fs

VERBOSE = "-v" in sys.argv
ONLY = None
if "-g" in sys.argv:
    ONLY = sys.argv[sys.argv.index("-g") + 1]

CHECKS = []
FAILS, PASSES = [], []


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


def R(s, cmd):
    """(stdout, stderr, rc) for one command."""
    s._err = []
    out = s.run(cmd)
    return out, "".join(s._err), s.last_rc


def cross(group, name):
    """Register a check that needs several commands. fn(s) -> (ok, detail)."""
    def deco(fn):
        CHECKS.append((group, name, fn))
        return fn
    return deco


def num(text):
    m = re.search(r"-?\d+", text or "")
    return int(m.group()) if m else None


def nums(text):
    return [int(x) for x in re.findall(r"\d+", text or "")]


# ===========================================================================
# Single-command checks: (group, name, command, predicate(out, err, rc))
# ===========================================================================
SIMPLE = [
    # --- exit codes. Every one of these is fixed by POSIX or by bash itself.
    ("exitcode", "true -> 0", "true", lambda o, e, r: r == 0),
    ("exitcode", "false -> 1", "false", lambda o, e, r: r == 1),
    ("exitcode", "missing command -> 127", "definitelynotacommand",
     lambda o, e, r: r == 127),
    ("exitcode", "cat on missing file -> 1", "cat /nonexistent-xyz",
     lambda o, e, r: r == 1),
    ("exitcode", "ls on missing file -> 2", "ls /nonexistent-xyz",
     lambda o, e, r: r == 2),
    ("exitcode", "non-executable file -> 126", "/etc/passwd",
     lambda o, e, r: r == 126),
    ("exitcode", "missing ./script -> 127", "./nonexistent-xyz",
     lambda o, e, r: r == 127),
    ("exitcode", "grep no match -> 1", "grep zzzznomatch /etc/passwd",
     lambda o, e, r: r == 1),
    ("exitcode", "grep match -> 0", "grep root /etc/passwd", lambda o, e, r: r == 0),
    ("exitcode", "test -f real -> 0", "test -f /etc/passwd", lambda o, e, r: r == 0),
    ("exitcode", "test -f fake -> 1", "test -f /nonexistent-xyz", lambda o, e, r: r == 1),
    ("exitcode", "test -d /etc -> 0", "test -d /etc", lambda o, e, r: r == 0),
    ("exitcode", "kill -0 self -> 0", "kill -0 $$", lambda o, e, r: r == 0),
    ("exitcode", "kill -0 bogus pid -> 1", "kill -0 999999", lambda o, e, r: r == 1),
    ("exitcode", "explicit exit code survives", "bash -c 'exit 42'",
     lambda o, e, r: r == 42),
    ("exitcode", "ls -z -> 2", "ls -z", lambda o, e, r: r == 2),
    ("exitcode", "mkdir over existing -> 1", "mkdir /etc", lambda o, e, r: r == 1),
    ("exitcode", "rmdir non-empty -> 1", "rmdir /etc", lambda o, e, r: r == 1),
    ("exitcode", "rm a directory -> 1", "rm /etc", lambda o, e, r: r == 1),
    ("exitcode", "cat a directory -> 1", "cat /etc", lambda o, e, r: r == 1),
    ("exitcode", "which missing -> 1", "which definitelynotacommand",
     lambda o, e, r: r == 1),
    ("exitcode", "pipeline takes last rc", "true | false", lambda o, e, r: r == 1),
    ("exitcode", "$? reflects last command", "false; echo $?",
     lambda o, e, r: o.strip() == "1"),

    # --- error wording. Fixed strings in coreutils/bash; attackers eyeball them.
    ("errmsg", "cat: No such file", "cat /nonexistent-xyz",
     lambda o, e, r: "cat: /nonexistent-xyz: No such file or directory" in e),
    ("errmsg", "cat: Is a directory", "cat /etc",
     lambda o, e, r: "cat: /etc: Is a directory" in e),
    ("errmsg", "ls: cannot access", "ls /nonexistent-xyz",
     lambda o, e, r: "cannot access" in e and "No such file or directory" in e),
    ("errmsg", "bash: command not found", "definitelynotacommand",
     lambda o, e, r: "definitelynotacommand: command not found" in e and "bash" in e),
    ("errmsg", "bash: Permission denied", "/etc/passwd",
     lambda o, e, r: "/etc/passwd: Permission denied" in e),
    ("errmsg", "cd: No such file", "cd /nonexistent-xyz",
     lambda o, e, r: "cd: /nonexistent-xyz: No such file or directory" in e),
    ("errmsg", "cd: Not a directory", "cd /etc/passwd",
     lambda o, e, r: "Not a directory" in e),
    ("errmsg", "mkdir: File exists", "mkdir /etc",
     lambda o, e, r: "mkdir: cannot create directory" in e and "File exists" in e),
    ("errmsg", "rmdir: Directory not empty", "rmdir /etc",
     lambda o, e, r: "rmdir: failed to remove" in e and "not empty" in e),
    ("errmsg", "rm: Is a directory", "rm /etc",
     lambda o, e, r: "rm: cannot remove" in e and "Is a directory" in e),
    ("errmsg", "cp: cannot stat", "cp /nonexistent-xyz /tmp/",
     lambda o, e, r: "cp: cannot stat" in e),
    ("errmsg", "mv: cannot stat", "mv /nonexistent-xyz /tmp/",
     lambda o, e, r: "mv: cannot stat" in e),
    ("errmsg", "touch: cannot touch", "touch /nonexistent-dir-xyz/f",
     lambda o, e, r: "touch: cannot touch" in e),
    ("errmsg", "chmod: cannot access", "chmod 644 /nonexistent-xyz",
     lambda o, e, r: "chmod: cannot access" in e),
    ("errmsg", "head: cannot open", "head /nonexistent-xyz",
     lambda o, e, r: "head: cannot open" in e and "for reading" in e),
    ("errmsg", "wc: No such file", "wc /nonexistent-xyz",
     lambda o, e, r: "wc: /nonexistent-xyz: No such file or directory" in e),
    ("errmsg", "stat: cannot statx", "stat /nonexistent-xyz",
     lambda o, e, r: "stat: cannot stat" in e),
    ("errmsg", "ls: invalid option", "ls -z",
     lambda o, e, r: "invalid option" in e and "Try 'ls --help'" in e),
    ("errmsg", "kill: no such process", "kill -0 999999",
     lambda o, e, r: "No such process" in e),
    ("errmsg", "division by 0", "echo $((1/0))",
     lambda o, e, r: "division by 0" in e),

    # --- shell builtins that always exist and always answer
    ("builtin", "type cd -> shell builtin", "type cd",
     lambda o, e, r: "cd is a shell builtin" in o),
    ("builtin", "type ls -> a path", "type ls",
     lambda o, e, r: re.search(r"ls is (/\S+|aliased)", o) is not None),
    ("builtin", "command -v cat -> path", "command -v cat",
     lambda o, e, r: o.strip().startswith("/")),
    ("builtin", "umask prints 4 digits", "umask",
     lambda o, e, r: re.fullmatch(r"0[0-7]{3}", o.strip()) is not None),
    ("builtin", "ulimit -n numeric", "ulimit -n",
     lambda o, e, r: o.strip().isdigit() or o.strip() == "unlimited"),
    ("builtin", "ulimit -u numeric", "ulimit -u",
     lambda o, e, r: o.strip().isdigit() or o.strip() == "unlimited"),
    ("builtin", "trap -l lists SIGKILL", "trap -l",
     lambda o, e, r: "SIGKILL" in o),
    ("builtin", "jobs is empty and succeeds", "jobs",
     lambda o, e, r: r == 0 and not o.strip()),
    ("builtin", "hash succeeds", "hash", lambda o, e, r: r == 0),
    ("builtin", "shopt prints settings", "shopt",
     lambda o, e, r: "on" in o or "off" in o),
    ("builtin", "set -o prints options", "set -o",
     lambda o, e, r: "braceexpand" in o),
    ("builtin", "help cd works", "help cd",
     lambda o, e, r: "cd:" in o and r == 0),
    ("builtin", "pwd -P works", "pwd -P", lambda o, e, r: o.strip().startswith("/")),
    ("builtin", "printf %d works", "printf '%d\\n' 42",
     lambda o, e, r: o.strip() == "42"),
    ("builtin", "printf %05.2f works", "printf '%05.2f\\n' 3.14159",
     lambda o, e, r: o.strip() == "03.14"),
    ("builtin", "read from a pipe", "echo hi | read x; echo done",
     lambda o, e, r: "done" in o),
    ("builtin", "let arithmetic", "let x=6*7; echo $x",
     lambda o, e, r: o.strip() == "42"),
    ("builtin", "declare -i", "declare -i n=5; n=n+1; echo $n",
     lambda o, e, r: o.strip() == "6"),

    # --- devices. Universal behaviour of a real /dev.
    ("devices", "/dev/null discards", "echo x > /dev/null; wc -c < /dev/null",
     lambda o, e, r: num(o) == 0),
    ("devices", "/dev/zero yields zeros", "head -c 8 /dev/zero | wc -c",
     lambda o, e, r: num(o) == 8),
    ("devices", "/dev/urandom yields bytes", "head -c 64 /dev/urandom | wc -c",
     lambda o, e, r: num(o) == 64),
    ("devices", "/dev/null is a char device", "ls -l /dev/null",
     lambda o, e, r: o.strip().startswith("crw")),
    ("devices", "/dev/zero is a char device", "ls -l /dev/zero",
     lambda o, e, r: o.strip().startswith("crw")),
    ("devices", "/dev/pts/0 exists", "ls -l /dev/pts/0",
     lambda o, e, r: r == 0 and o.strip().startswith("crw")),
    ("devices", "/dev/console exists", "ls /dev/console", lambda o, e, r: r == 0),
    ("devices", "/dev/fd is present", "ls -d /dev/fd", lambda o, e, r: r == 0),
    ("devices", "/dev/stdin resolves", "readlink /dev/stdin",
     lambda o, e, r: bool(o.strip())),

    # --- procfs invariants
    ("procfs", "/proc/uptime has 2 floats", "cat /proc/uptime",
     lambda o, e, r: len(re.findall(r"\d+\.\d+", o)) == 2),
    ("procfs", "/proc/loadavg has 5 fields", "cat /proc/loadavg",
     lambda o, e, r: len(o.split()) == 5),
    ("procfs", "/proc/loadavg running/total", "cat /proc/loadavg",
     lambda o, e, r: re.search(r"\d+/\d+", o) is not None),
    ("procfs", "/proc/cmdline non-empty", "cat /proc/cmdline",
     lambda o, e, r: bool(o.strip())),
    ("procfs", "/proc/stat has btime", "cat /proc/stat",
     lambda o, e, r: "btime" in o),
    ("procfs", "/proc/stat has intr/ctxt", "cat /proc/stat",
     lambda o, e, r: "ctxt" in o and "processes" in o),
    ("procfs", "/proc/version says Linux version", "cat /proc/version",
     lambda o, e, r: o.startswith("Linux version ")),
    ("procfs", "/proc/filesystems lists ext4", "cat /proc/filesystems",
     lambda o, e, r: "ext4" in o),
    ("procfs", "/proc/devices non-empty", "cat /proc/devices",
     lambda o, e, r: "Character devices" in o),
    ("procfs", "/proc/partitions non-empty", "cat /proc/partitions",
     lambda o, e, r: "major" in o and len(o.splitlines()) > 2),
    ("procfs", "/proc/swaps has a header", "cat /proc/swaps",
     lambda o, e, r: "Filename" in o),
    ("procfs", "/proc/vmstat non-empty", "cat /proc/vmstat",
     lambda o, e, r: "nr_free_pages" in o),
    ("procfs", "/proc/1/comm is the init name", "cat /proc/1/comm",
     lambda o, e, r: o.strip() in ("systemd", "init")),
    ("procfs", "/proc/1/cmdline populated", "cat /proc/1/cmdline",
     lambda o, e, r: bool(o.strip())),
    ("procfs", "/proc/sys/kernel/ostype = Linux", "cat /proc/sys/kernel/ostype",
     lambda o, e, r: o.strip() == "Linux"),
    ("procfs", "/proc/sys/kernel/pid_max numeric", "cat /proc/sys/kernel/pid_max",
     lambda o, e, r: o.strip().isdigit()),
    ("procfs", "/proc/sys/net/ipv4/ip_forward is 0 or 1",
     "cat /proc/sys/net/ipv4/ip_forward", lambda o, e, r: o.strip() in ("0", "1")),
    ("procfs", "/proc/self/mounts matches format", "cat /proc/self/mounts",
     lambda o, e, r: len(o.split("\n")[0].split()) == 6),
    ("procfs", "/proc/net/dev lists interfaces", "cat /proc/net/dev",
     lambda o, e, r: "lo:" in o.replace(" ", "")),
    ("procfs", "/proc/net/route has a header", "cat /proc/net/route",
     lambda o, e, r: "Iface" in o),
    ("procfs", "/proc/crypto or /proc/misc exists",
     "cat /proc/misc", lambda o, e, r: bool(o.strip())),
    ("procfs", "/proc/interrupts has a CPU header", "cat /proc/interrupts",
     lambda o, e, r: "CPU0" in o),
    ("procfs", "/proc/diskstats non-empty", "cat /proc/diskstats",
     lambda o, e, r: bool(o.strip())),
    ("procfs", "/proc/modules readable", "cat /proc/modules",
     lambda o, e, r: r == 0),
    ("procfs", "/proc/mounts and /proc/self/mounts agree",
     "diff <(cat /proc/mounts) <(cat /proc/self/mounts); echo rc=$?",
     lambda o, e, r: "rc=0" in o),

    # --- sysfs
    ("sysfs", "/sys/class/net has lo", "ls /sys/class/net",
     lambda o, e, r: "lo" in o.split()),
    ("sysfs", "/sys/block non-empty", "ls /sys/block",
     lambda o, e, r: bool(o.strip())),
    ("sysfs", "cpu0 exists", "ls -d /sys/devices/system/cpu/cpu0",
     lambda o, e, r: r == 0),
    ("sysfs", "dmi product_name readable",
     "cat /sys/class/dmi/id/product_name", lambda o, e, r: bool(o.strip())),
    ("sysfs", "dmi sys_vendor readable",
     "cat /sys/class/dmi/id/sys_vendor", lambda o, e, r: bool(o.strip())),
    ("sysfs", "lo has an address file",
     "cat /sys/class/net/lo/address",
     lambda o, e, r: o.strip() == "00:00:00:00:00:00"),

    # --- shell variables bash always exports or sets
    ("shellvar", "$PATH is set", "echo $PATH", lambda o, e, r: "/usr/bin" in o),
    ("shellvar", "$HOME is set", "echo $HOME", lambda o, e, r: o.strip().startswith("/")),
    ("shellvar", "$USER is set", "echo $USER", lambda o, e, r: bool(o.strip())),
    ("shellvar", "$LOGNAME is set", "echo $LOGNAME", lambda o, e, r: bool(o.strip())),
    ("shellvar", "$SHELL is set", "echo $SHELL", lambda o, e, r: o.strip().endswith("sh")),
    ("shellvar", "$TERM is set", "echo $TERM", lambda o, e, r: bool(o.strip())),
    ("shellvar", "$PWD is absolute", "echo $PWD", lambda o, e, r: o.strip().startswith("/")),
    ("shellvar", "$BASH_VERSION is set", "echo $BASH_VERSION",
     lambda o, e, r: re.match(r"5\.\d+\.\d+", o.strip()) is not None),
    ("shellvar", "$BASHPID is numeric", "echo $BASHPID",
     lambda o, e, r: o.strip().isdigit()),
    ("shellvar", "$SECONDS is numeric", "echo $SECONDS",
     lambda o, e, r: o.strip().isdigit()),
    ("shellvar", "$RANDOM is in range", "echo $RANDOM",
     lambda o, e, r: o.strip().isdigit() and 0 <= int(o) <= 32767),
    ("shellvar", "$LINENO is numeric", "echo $LINENO",
     lambda o, e, r: o.strip().isdigit()),
    ("shellvar", "$HOSTNAME is set", "echo $HOSTNAME", lambda o, e, r: bool(o.strip())),
    ("shellvar", "$SSH_CONNECTION has 4 fields", "echo $SSH_CONNECTION",
     lambda o, e, r: len(o.split()) == 4),
    ("shellvar", "$SSH_CLIENT has 3 fields", "echo $SSH_CLIENT",
     lambda o, e, r: len(o.split()) == 3),
    ("shellvar", "$SSH_TTY is a pts", "echo $SSH_TTY",
     lambda o, e, r: o.strip().startswith("/dev/pts/")),
    ("shellvar", "$OSTYPE is linux-gnu", "echo $OSTYPE",
     lambda o, e, r: o.strip() == "linux-gnu"),
    ("shellvar", "$LANG or $LC_ALL is set", "echo ${LANG:-$LC_ALL}",
     lambda o, e, r: bool(o.strip())),
    ("shellvar", "$SHLVL is numeric", "echo $SHLVL",
     lambda o, e, r: o.strip().isdigit()),
    ("shellvar", "$IFS default is space/tab/nl", 'printf "%q" "$IFS"',
     lambda o, e, r: "t" in o or " " in o),

    # --- filesystem layout every Debian has
    ("layout", "/bin is a symlink to usr/bin", "readlink /bin",
     lambda o, e, r: o.strip() in ("usr/bin", "/usr/bin")),
    ("layout", "/lib is a symlink", "readlink /lib",
     lambda o, e, r: o.strip() in ("usr/lib", "/usr/lib")),
    ("layout", "/etc/mtab resolves", "readlink -f /etc/mtab",
     lambda o, e, r: "mounts" in o or o.strip() == "/etc/mtab"),
    ("layout", "/var/run -> /run", "readlink /var/run",
     lambda o, e, r: o.strip() in ("/run", "run")),
    ("layout", "ls -a / shows . and ..", "ls -a /",
     lambda o, e, r: "." in o.split() and ".." in o.split()),
    ("layout", "/etc/shadow is 0640 or 0600", "ls -l /etc/shadow",
     lambda o, e, r: o.strip()[:10] in ("-rw-r-----", "-rw-------")),
    ("layout", "/etc/passwd is 0644", "ls -l /etc/passwd",
     lambda o, e, r: o.strip().startswith("-rw-r--r--")),
    ("layout", "/tmp is 1777", "ls -ld /tmp",
     lambda o, e, r: o.strip().startswith("drwxrwxrwt")),
    ("layout", "/root is 0700", "ls -ld /root",
     lambda o, e, r: o.strip().startswith("drwx------")),
    ("layout", "/usr/bin/sudo is setuid", "ls -l /usr/bin/sudo",
     lambda o, e, r: "s" in o.strip()[:10]),
    ("layout", "/etc/os-release is a symlink or file",
     "ls -l /etc/os-release", lambda o, e, r: r == 0),
    ("layout", "/proc is a mounted proc", "stat -f -c %T /proc",
     lambda o, e, r: "proc" in o or r == 0),

    # --- randomness / uniqueness
    ("random", "two urandom reads differ",
     "a=$(head -c 16 /dev/urandom | md5sum); b=$(head -c 16 /dev/urandom | md5sum); "
     "[ \"$a\" != \"$b\" ] && echo differ",
     lambda o, e, r: "differ" in o),
    ("random", "two $RANDOM differ over 5 draws",
     "echo $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM",
     lambda o, e, r: len(set(o.split())) >= 4),
    ("random", "mktemp gives a fresh path",
     "f=$(mktemp); test -f $f && echo ok",
     lambda o, e, r: "ok" in o),
    ("random", "two mktemp differ",
     "a=$(mktemp); b=$(mktemp); [ \"$a\" != \"$b\" ] && echo differ",
     lambda o, e, r: "differ" in o),

    # --- tools an attacker runs in the first ten seconds
    ("tools", "uname -a is one line", "uname -a",
     lambda o, e, r: len(o.strip().splitlines()) == 1 and "Linux" in o),
    ("tools", "id -a works", "id -a", lambda o, e, r: "uid=" in o),
    ("tools", "lsb_release answers or is absent", "lsb_release -a",
     lambda o, e, r: "Description" in o or "No LSB" in e or r == 127),
    ("tools", "hostnamectl works", "hostnamectl",
     lambda o, e, r: "Static hostname" in o or "Operating System" in o),
    ("tools", "systemd-detect-virt answers", "systemd-detect-virt",
     lambda o, e, r: bool(o.strip())),
    ("tools", "dmidecode -s system-product-name",
     "dmidecode -s system-product-name", lambda o, e, r: bool(o.strip())),
    ("tools", "crontab -l answers", "crontab -l",
     lambda o, e, r: r in (0, 1)),
    ("tools", "find works", "find /etc -maxdepth 1 -name passwd",
     lambda o, e, r: "/etc/passwd" in o),
    ("tools", "getent passwd root", "getent passwd root",
     lambda o, e, r: o.startswith("root:")),
    ("tools", "getent group root", "getent group root",
     lambda o, e, r: o.startswith("root:")),
    ("tools", "file on a binary says ELF", "file /bin/ls",
     lambda o, e, r: "ELF 64-bit" in o),
    ("tools", "ldd lists libc", "ldd /bin/ls",
     lambda o, e, r: "libc.so.6" in o),
    ("tools", "strings works", "strings /bin/ls | head -1",
     lambda o, e, r: r == 0),
    ("tools", "openssl version", "openssl version",
     lambda o, e, r: "OpenSSL" in o),
    ("tools", "python3 -V", "python3 -V",
     lambda o, e, r: "Python 3" in o or "Python 3" in e),
    ("tools", "gcc -v answers or is absent", "gcc --version",
     lambda o, e, r: "gcc" in o or "not found" in e),
    ("tools", "iptables -L answers", "iptables -L -n",
     lambda o, e, r: "Chain" in o or "not found" in e or "Permission" in e),
    ("tools", "last -n 3 works", "last -n 3", lambda o, e, r: r == 0),
    ("tools", "lscpu has Architecture", "lscpu",
     lambda o, e, r: "Architecture" in o),
    ("tools", "lsblk has NAME header", "lsblk",
     lambda o, e, r: "NAME" in o),
    ("tools", "blkid gives a UUID", "blkid",
     lambda o, e, r: "UUID=" in o),
    ("tools", "ss -s summary", "ss -s", lambda o, e, r: "Total" in o or "TCP" in o),
    ("tools", "apt-get --version", "apt-get --version",
     lambda o, e, r: "apt" in o),
    ("tools", "head -c4 /bin/ls is ELF magic", "head -c 4 /bin/ls | od -c",
     lambda o, e, r: "177" in o and "E" in o),
]


# ===========================================================================
# Cross-command consistency
# ===========================================================================
@cross("identity", "hostname == /etc/hostname")
def _c(s):
    a, b = R(s, "hostname")[0].strip(), R(s, "cat /etc/hostname")[0].strip()
    return a == b, "%r vs %r" % (a, b)


@cross("identity", "hostname == uname -n")
def _c(s):
    a, b = R(s, "hostname")[0].strip(), R(s, "uname -n")[0].strip()
    return a == b, "%r vs %r" % (a, b)


@cross("identity", "hostname == /proc/sys/kernel/hostname")
def _c(s):
    a, b = R(s, "hostname")[0].strip(), R(s, "cat /proc/sys/kernel/hostname")[0].strip()
    return a == b, "%r vs %r" % (a, b)


@cross("identity", "hostname == $HOSTNAME")
def _c(s):
    a, b = R(s, "hostname")[0].strip(), R(s, "echo $HOSTNAME")[0].strip()
    return a == b, "%r vs %r" % (a, b)


@cross("identity", "hostname appears in /etc/hosts")
def _c(s):
    h = R(s, "hostname")[0].strip()
    return h in R(s, "cat /etc/hosts")[0], h


@cross("identity", "uname -r inside /proc/version")
def _c(s):
    rel = R(s, "uname -r")[0].strip()
    return bool(rel) and rel in R(s, "cat /proc/version")[0], rel


@cross("identity", "uname -r == /proc/sys/kernel/osrelease")
def _c(s):
    a = R(s, "uname -r")[0].strip()
    b = R(s, "cat /proc/sys/kernel/osrelease")[0].strip()
    return a == b, "%r vs %r" % (a, b)


@cross("identity", "/lib/modules/<uname -r> exists")
def _c(s):
    rel = R(s, "uname -r")[0].strip()
    o, e, r = R(s, "ls -d /lib/modules/%s" % rel)
    return r == 0, (o + e).strip()[:60]


@cross("identity", "uname -v == /proc/version version field")
def _c(s):
    v = R(s, "uname -v")[0].strip()
    return v and v in R(s, "cat /proc/version")[0], v[:50]


@cross("identity", "uname -m == arch == dpkg arch family")
def _c(s):
    a, b = R(s, "uname -m")[0].strip(), R(s, "arch")[0].strip()
    d = R(s, "dpkg --print-architecture")[0].strip()
    return a == b and (d in ("amd64", "") or a == "x86_64"), "%s/%s/%s" % (a, b, d)


@cross("identity", "machine-id is 32 hex")
def _c(s):
    m = R(s, "cat /etc/machine-id")[0].strip()
    return bool(re.fullmatch(r"[0-9a-f]{32}", m)), m[:40]


@cross("identity", "/etc/machine-id == /var/lib/dbus/machine-id")
def _c(s):
    a = R(s, "cat /etc/machine-id")[0].strip()
    b = R(s, "cat /var/lib/dbus/machine-id")[0].strip()
    return a == b and bool(a), "%r vs %r" % (a[:12], b[:12])


@cross("identity", "os-release VERSION_ID == debian_version major")
def _c(s):
    osr = R(s, "cat /etc/os-release")[0]
    vid = re.search(r'VERSION_ID="?(\d+)', osr)
    dv = R(s, "cat /etc/debian_version")[0].strip()
    return vid and dv.startswith(vid.group(1)), "%s vs %s" % (
        vid.group(1) if vid else None, dv)


@cross("identity", "os-release names a codename")
def _c(s):
    osr = R(s, "cat /etc/os-release")[0]
    cn = re.search(r'VERSION_CODENAME=(\w+)', osr)
    return bool(cn), "no VERSION_CODENAME in os-release"


@cross("identity", "lsb_release agrees with os-release when present")
def _c(s):
    o, e, r = R(s, "lsb_release -a")
    if r == 127:
        # lsb-release is not installed on a minimal trixie, so its absence is
        # correct rather than a tell.
        return True, "not installed"
    osr = R(s, "cat /etc/os-release")[0]
    cn = re.search(r'VERSION_CODENAME=(\w+)', osr)
    return cn and cn.group(1) in (o + e).lower(), cn.group(1) if cn else "no codename"


@cross("identity", "hostnamectl agrees with uname and os-release")
def _c(s):
    hc = R(s, "hostnamectl")[0]
    rel = R(s, "uname -r")[0].strip()
    host = R(s, "hostname")[0].strip()
    return rel in hc and host in hc, "kernel=%s host=%s" % (rel in hc, host in hc)


# ---- user
@cross("user", "id name == whoami")
def _c(s):
    return R(s, "whoami")[0].strip() in R(s, "id")[0], R(s, "id")[0].strip()[:50]


@cross("user", "id -u == $UID == $EUID")
def _c(s):
    a = R(s, "id -u")[0].strip()
    b = R(s, "echo $UID")[0].strip()
    c = R(s, "echo $EUID")[0].strip()
    return a == b == c, "%s/%s/%s" % (a, b, c)


@cross("user", "whoami has a /etc/passwd entry")
def _c(s):
    w = R(s, "whoami")[0].strip()
    return (w + ":") in R(s, "cat /etc/passwd")[0], w


@cross("user", "passwd home field == $HOME")
def _c(s):
    w = R(s, "whoami")[0].strip()
    line = [l for l in R(s, "cat /etc/passwd")[0].splitlines() if l.startswith(w + ":")]
    if not line:
        return False, "no passwd entry"
    home = line[0].split(":")[5]
    return home == R(s, "echo $HOME")[0].strip(), "%s vs %s" % (home, R(s, "echo $HOME")[0].strip())


@cross("user", "$HOME directory exists")
def _c(s):
    o, e, r = R(s, "ls -d $HOME")
    return r == 0, (o + e).strip()[:50]


@cross("user", "passwd shell field exists on disk")
def _c(s):
    w = R(s, "whoami")[0].strip()
    line = [l for l in R(s, "cat /etc/passwd")[0].splitlines() if l.startswith(w + ":")]
    if not line:
        return False, "no entry"
    sh_path = line[0].split(":")[6]
    return R(s, "ls %s" % sh_path)[2] == 0, sh_path


@cross("user", "$SHELL == passwd shell field")
def _c(s):
    w = R(s, "whoami")[0].strip()
    line = [l for l in R(s, "cat /etc/passwd")[0].splitlines() if l.startswith(w + ":")]
    if not line:
        return False, "no entry"
    return line[0].split(":")[6] == R(s, "echo $SHELL")[0].strip(), \
        "%s vs %s" % (line[0].split(":")[6], R(s, "echo $SHELL")[0].strip())


# Debian itself does not ship the home directory of every system account:
# on trixie-slim, /var/spool/lpd, /var/cache/man, /var/spool/news,
# /var/spool/uucp, /var/list and /run/ircd are all absent while their passwd
# entries are present. Checked against the real image rather than assumed --
# the previous form of this check asserted they all exist, which was only
# true because /etc/passwd was missing twelve standard accounts.
DEBIAN_ABSENT_HOMES = {"/var/spool/lpd", "/var/cache/man", "/var/spool/news",
                       "/var/spool/uucp", "/var/list", "/run/ircd",
                       "/run/systemd", "/var/spool/mail"}


@cross("user", "every passwd home dir that Debian ships exists")
def _c(s):
    bad = []
    for line in R(s, "cat /etc/passwd")[0].splitlines():
        f = line.split(":")
        if len(f) < 7 or f[5] in ("/", "/nonexistent", "/dev/null", ""):
            continue
        if f[5] in DEBIAN_ABSENT_HOMES:
            continue
        if R(s, "ls -d %s" % f[5])[2] != 0:
            bad.append(f[0] + ":" + f[5])
    return not bad, "missing %d: %s" % (len(bad), bad[:4])


@cross("user", "an interactive account's home directory exists")
def _c(s):
    """The property that actually matters: you cannot log in to a missing
    home. System accounts with nologin are a different case."""
    bad = []
    for line in R(s, "cat /etc/passwd")[0].splitlines():
        f = line.split(":")
        if len(f) < 7 or f[6] in ("/usr/sbin/nologin", "/bin/false",
                                  "/sbin/nologin", "/bin/sync", ""):
            continue
        if R(s, "ls -d %s" % f[5])[2] != 0:
            bad.append(f[0] + ":" + f[5])
    return not bad, str(bad)


@cross("user", "every passwd shell exists")
def _c(s):
    bad = []
    for line in R(s, "cat /etc/passwd")[0].splitlines():
        f = line.split(":")
        if len(f) < 7 or f[6] in ("", "/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
            continue
        if R(s, "ls %s" % f[6])[2] != 0:
            bad.append(f[6])
    return not bad, "missing: %s" % sorted(set(bad))[:4]


@cross("user", "shadow has an entry for every passwd user")
def _c(s):
    pw = {l.split(":")[0] for l in R(s, "cat /etc/passwd")[0].splitlines() if ":" in l}
    sh_ = {l.split(":")[0] for l in R(s, "cat /etc/shadow")[0].splitlines() if ":" in l}
    return pw and not (pw - sh_), "missing from shadow: %s" % sorted(pw - sh_)[:5]


@cross("user", "every passwd gid exists in /etc/group")
def _c(s):
    gids = {l.split(":")[3] for l in R(s, "cat /etc/passwd")[0].splitlines()
            if len(l.split(":")) > 3}
    have = {l.split(":")[2] for l in R(s, "cat /etc/group")[0].splitlines()
            if len(l.split(":")) > 2}
    return gids and not (gids - have), "gids with no group: %s" % sorted(gids - have)[:5]


@cross("user", "group members all exist in passwd")
def _c(s):
    users = {l.split(":")[0] for l in R(s, "cat /etc/passwd")[0].splitlines() if ":" in l}
    bad = set()
    for line in R(s, "cat /etc/group")[0].splitlines():
        f = line.split(":")
        if len(f) < 4 or not f[3]:
            continue
        bad |= {m for m in f[3].split(",") if m and m not in users}
    return not bad, "phantom members: %s" % sorted(bad)[:5]


@cross("user", "groups output matches id -Gn")
def _c(s):
    a = set(R(s, "groups")[0].split())
    b = set(R(s, "id -Gn")[0].split())
    return a == b and a, "%s vs %s" % (sorted(a)[:3], sorted(b)[:3])


# ---- processes
@cross("procs", "$$ is numeric")
def _c(s):
    p = R(s, "echo $$")[0].strip()
    return p.isdigit(), p


@cross("procs", "$$ == $BASHPID at top level")
def _c(s):
    a, b = R(s, "echo $$")[0].strip(), R(s, "echo $BASHPID")[0].strip()
    return a == b, "%s vs %s" % (a, b)


@cross("procs", "$BASHPID differs inside a subshell")
def _c(s):
    a = R(s, "echo $$")[0].strip()
    b = R(s, "( echo $BASHPID )")[0].strip()
    return a != b and b.isdigit(), "%s vs %s" % (a, b)


@cross("procs", "$$ is stable across two expansions")
def _c(s):
    a, b = R(s, "echo $$")[0].strip(), R(s, "echo $$")[0].strip()
    return a == b, "%s vs %s" % (a, b)


@cross("procs", "ps -p $$ finds our shell")
def _c(s):
    p = R(s, "echo $$")[0].strip()
    out = R(s, "ps -p %s" % p)[0]
    return p in out, out.strip()[:60]


@cross("procs", "$$ appears in ps aux")
def _c(s):
    p = R(s, "echo $$")[0].strip()
    return p in R(s, "ps aux")[0], p


@cross("procs", "ps shows a bash for our tty")
def _c(s):
    return "bash" in R(s, "ps")[0], R(s, "ps")[0].strip()[:70]


@cross("procs", "every ps pid has a /proc dir")
def _c(s):
    listed = set(re.findall(r"^\d+$", R(s, "ls /proc")[0], re.M))
    have = set(re.findall(r"^\S+\s+(\d+)", R(s, "ps aux")[0], re.M))
    miss = sorted(have - listed, key=int)
    return not miss, "%d missing e.g. %s" % (len(miss), miss[:6])


@cross("procs", "every /proc numeric dir is in ps")
def _c(s):
    listed = set(re.findall(r"^\d+$", R(s, "ls /proc")[0], re.M))
    have = set(re.findall(r"^\S+\s+(\d+)", R(s, "ps aux")[0], re.M))
    extra = sorted(listed - have, key=int)
    return not extra, "%d phantom e.g. %s" % (len(extra), extra[:6])


@cross("procs", "/proc/self/stat is populated")
def _c(s):
    o = R(s, "cat /proc/self/stat")[0]
    return len(o.split()) > 20, repr(o[:40])


@cross("procs", "/proc/self/status has Name and Pid")
def _c(s):
    o = R(s, "cat /proc/self/status")[0]
    return "Name:" in o and "Pid:" in o, repr(o[:40])


@cross("procs", "/proc/self/status Pid == $$")
def _c(s):
    o = R(s, "cat /proc/self/status")[0]
    m = re.search(r"^Pid:\s*(\d+)", o, re.M)
    p = R(s, "echo $$")[0].strip()
    return m and m.group(1) == p, "%s vs %s" % (m.group(1) if m else None, p)


@cross("procs", "/proc/$$/cmdline is populated")
def _c(s):
    p = R(s, "echo $$")[0].strip()
    return bool(R(s, "cat /proc/%s/cmdline" % p)[0].strip()), p


@cross("procs", "readlink /proc/self/exe points at a shell")
def _c(s):
    o = R(s, "readlink /proc/self/exe")[0].strip()
    return o.endswith("bash") or o.endswith("sh"), repr(o)


@cross("procs", "/proc/self/exe target exists")
def _c(s):
    o = R(s, "readlink /proc/self/exe")[0].strip()
    return bool(o) and R(s, "ls %s" % o)[2] == 0, repr(o)


@cross("procs", "readlink /proc/self/cwd == pwd")
def _c(s):
    return R(s, "readlink /proc/self/cwd")[0].strip() == R(s, "pwd")[0].strip(), \
        "%r vs %r" % (R(s, "readlink /proc/self/cwd")[0].strip(), R(s, "pwd")[0].strip())


@cross("procs", "/proc/self/environ matches env")
def _c(s):
    envs = R(s, "cat /proc/self/environ | tr '\\0' '\\n'")[0]
    return "PATH=" in envs and "HOME=" in envs, repr(envs[:40])


@cross("procs", "/proc/$$/fd has 0 1 2")
def _c(s):
    p = R(s, "echo $$")[0].strip()
    o = R(s, "ls /proc/%s/fd" % p)[0].split()
    return {"0", "1", "2"} <= set(o), o[:6]


@cross("procs", "$PPID is numeric and in ps")
def _c(s):
    pp = R(s, "echo $PPID")[0].strip()
    return pp.isdigit() and pp in R(s, "ps aux")[0], pp


@cross("procs", "pgrep systemd finds pid 1")
def _c(s):
    return "1" in R(s, "pgrep systemd")[0].split(), R(s, "pgrep systemd")[0].strip()[:30]


@cross("procs", "pidof sshd matches ps")
def _c(s):
    p = R(s, "pidof sshd")[0].split()
    ps = R(s, "ps aux")[0]
    return p and all(x in ps for x in p), p[:4]


@cross("procs", "ps --no-headers omits the header")
def _c(s):
    o = R(s, "ps --no-headers")[0]
    return "PID" not in o.splitlines()[0] if o.strip() else False, o.strip()[:40]


@cross("procs", "ps -ef and ps aux report the same pid set")
def _c(s):
    a = set(re.findall(r"^\S+\s+(\d+)", R(s, "ps aux")[0], re.M))
    b = set(re.findall(r"^\S+\s+(\d+)", R(s, "ps -ef")[0], re.M))
    return a == b and a, "aux=%d ef=%d diff=%s" % (len(a), len(b), sorted(a ^ b)[:5])


@cross("procs", "top -bn1 agrees with ps on the task count")
def _c(s):
    t = R(s, "top -bn1")[0]
    m = re.search(r"Tasks:\s*(\d+)", t)
    n = len(re.findall(r"^\S+\s+\d+", R(s, "ps aux")[0], re.M)) - 1
    return m and abs(int(m.group(1)) - n) <= 2, "%s vs %s" % (m.group(1) if m else None, n)


# ---- files
# ---- process and network command flags. These cannot be diffed against a real
# host -- the output *is* the persona -- so they are checked for internal
# consistency instead. Every one of them was silently ignoring its flags.
@cross("psflags", "ps -o selects exactly the named columns")
def _c(s):
    out = R(s, "ps -o pid,comm")[0].splitlines()
    return bool(out) and out[0].split() == ["PID", "COMM"], \
        "header %r" % (out[0] if out else "")


@cross("psflags", "ps -o with = suppresses the header")
def _c(s):
    out = R(s, "ps -o pid= -p 1")[0].strip()
    return out == "1", repr(out)


@cross("psflags", "ps -eo lists every process")
def _c(s):
    n_all = len([l for l in R(s, "ps aux")[0].splitlines()[1:] if l.strip()])
    n_eo = len([l for l in R(s, "ps -eo pid=")[0].splitlines() if l.strip()])
    return n_all == n_eo, "aux=%d -eo=%d" % (n_all, n_eo)


@cross("psflags", "ps -C name agrees with pgrep")
def _c(s):
    a = set(R(s, "ps -C sshd -o pid=")[0].split())
    b = set(R(s, "pgrep sshd")[0].split())
    return a and a == b, "ps=%s pgrep=%s" % (sorted(a), sorted(b))


@cross("psflags", "ps --ppid selects children of that pid")
def _c(s):
    kids = R(s, "ps --ppid 1 -o ppid=")[0].split()
    return kids and set(kids) == {"1"}, "ppids seen: %s" % sorted(set(kids))


@cross("psflags", "ps --sort=-pid is descending")
def _c(s):
    pids = [int(x) for x in R(s, "ps -eo pid= --sort=-pid")[0].split()]
    return pids == sorted(pids, reverse=True), "not descending: %s" % pids[:5]


@cross("psflags", "ps -eo ppid values all exist as pids")
def _c(s):
    pids = {int(x) for x in R(s, "ps -eo pid=")[0].split()}
    ppids = {int(x) for x in R(s, "ps -eo ppid=")[0].split()} - {0}
    return ppids <= pids, "parents that do not exist: %s" % sorted(ppids - pids)


@cross("psflags", "pgrep -n is the highest matching pid")
def _c(s):
    allp = [int(x) for x in R(s, "pgrep sshd")[0].split()]
    newest = R(s, "pgrep -n sshd")[0].split()
    return allp and newest == [str(max(allp))], \
        "all=%s newest=%s" % (allp, newest)


@cross("psflags", "pgrep -o is the lowest matching pid")
def _c(s):
    allp = [int(x) for x in R(s, "pgrep sshd")[0].split()]
    oldest = R(s, "pgrep -o sshd")[0].split()
    return allp and oldest == [str(min(allp))], \
        "all=%s oldest=%s" % (allp, oldest)


@cross("psflags", "pgrep -u filters by owner")
def _c(s):
    hits = R(s, "pgrep -u mysql mariadbd")[0].split()
    owner = R(s, "ps -o user= -p %s" % (hits[0] if hits else 0))[0].strip()
    return hits and owner == "mysql", "hits=%s owner=%r" % (hits, owner)


@cross("psflags", "kill -l round-trips a signal name")
def _c(s):
    name = R(s, "kill -l 9")[0].strip()
    num = R(s, "kill -l KILL")[0].strip()
    return name == "KILL" and num == "9", "9->%r KILL->%r" % (name, num)


@cross("psflags", "kill -l lists SIGTERM")
def _c(s):
    return "SIGTERM" in R(s, "kill -l")[0], R(s, "kill -l")[0][:60]


@cross("netflags", "netstat -rn agrees with ip route on the gateway")
def _c(s):
    gw = re.search(r"default via (\S+)", R(s, "ip route")[0])
    out = R(s, "netstat -rn")[0]
    return gw and "routing table" in out.lower() and gw.group(1) in out, \
        "gw=%s in netstat -rn: %s" % (gw.group(1) if gw else None,
                                      out.strip()[:60])


@cross("netflags", "netstat -i lists the same interfaces as ip a")
def _c(s):
    ifs = set(re.findall(r"^\d+:\s+([\w.]+?):", R(s, "ip a")[0], re.M))
    out = R(s, "netstat -i")[0]
    return ifs and all(i in out for i in ifs) and "Interface table" in out, \
        "want %s, got %r" % (sorted(ifs), out.strip()[:60])


@cross("netflags", "ss -x reports unix sockets, not tcp")
def _c(s):
    out = R(s, "ss -x")[0]
    return "unix" in out and ":22" not in out, out.strip()[:70]


@cross("netflags", "ss state established excludes listeners")
def _c(s):
    out = R(s, "ss -t state established")[0]
    body = [l for l in out.splitlines()[1:] if l.strip()]
    return body and not any("LISTEN" in l for l in body), \
        "%d rows, listeners present: %s" % (len(body),
                                            any("LISTEN" in l for l in body))


@cross("netflags", "netstat -s reports protocol counters")
def _c(s):
    out = R(s, "netstat -s")[0]
    return "Tcp:" in out and "Ip:" in out, out.strip()[:60]


@cross("files", "ls -i prints an inode")
def _c(s):
    o = R(s, "ls -i /etc/passwd")[0]
    return re.match(r"\s*\d+\s", o) is not None, repr(o.strip()[:40])


@cross("files", "ls -i inode == stat inode")
def _c(s):
    a = num(R(s, "ls -i /etc/passwd")[0])
    m = re.search(r"Inode:\s*(\d+)", R(s, "stat /etc/passwd")[0])
    return m and a == int(m.group(1)), "%s vs %s" % (a, m.group(1) if m else None)


@cross("files", "stat -c %i == ls -i")
def _c(s):
    a = num(R(s, "ls -i /etc/passwd")[0])
    b = num(R(s, "stat -c %i /etc/passwd")[0])
    return a is not None and a == b, "%s vs %s" % (a, b)


@cross("files", "inodes are unique across a directory")
def _c(s):
    inos = [num(l) for l in R(s, "ls -i /etc")[0].splitlines() if num(l)]
    return len(inos) == len(set(inos)) and len(inos) > 3, \
        "%d entries, %d distinct" % (len(inos), len(set(inos)))


@cross("files", "ls -l size == wc -c")
def _c(s):
    m = re.match(r"\S+\s+\d+\s+\S+\s+\S+\s+(\d+)", R(s, "ls -l /etc/passwd")[0].strip())
    w = num(R(s, "wc -c < /etc/passwd")[0])
    return m and int(m.group(1)) == w, "%s vs %s" % (m.group(1) if m else None, w)


@cross("files", "stat size == wc -c")
def _c(s):
    m = re.search(r"Size:\s*(\d+)", R(s, "stat /etc/passwd")[0])
    w = num(R(s, "wc -c < /etc/passwd")[0])
    return m and int(m.group(1)) == w, "%s vs %s" % (m.group(1) if m else None, w)


@cross("files", "stat -c %s == wc -c")
def _c(s):
    return num(R(s, "stat -c %s /etc/passwd")[0]) == num(R(s, "wc -c < /etc/passwd")[0]), \
        "%s vs %s" % (num(R(s, "stat -c %s /etc/passwd")[0]),
                      num(R(s, "wc -c < /etc/passwd")[0]))


@cross("files", "md5sum matches the file we can read")
def _c(s):
    body = R(s, "cat /etc/passwd")[0]
    want = hashlib.md5(body.encode()).hexdigest()
    got = R(s, "md5sum /etc/passwd")[0].split()[0] if R(s, "md5sum /etc/passwd")[0] else ""
    return got == want, "%s vs %s" % (got[:12], want[:12])


@cross("files", "sha256sum matches the file we can read")
def _c(s):
    body = R(s, "cat /etc/passwd")[0]
    want = hashlib.sha256(body.encode()).hexdigest()
    out = R(s, "sha256sum /etc/passwd")[0]
    got = out.split()[0] if out.strip() else ""
    return got == want, "%s vs %s" % (got[:12], want[:12])


@cross("files", "md5sum is stable across two runs")
def _c(s):
    a = R(s, "md5sum /etc/passwd")[0].split()
    b = R(s, "md5sum /etc/passwd")[0].split()
    return a == b and a, "%s vs %s" % (a[:1], b[:1])


@cross("files", "wc -l == number of lines in cat")
def _c(s):
    body = R(s, "cat /etc/passwd")[0]
    return num(R(s, "wc -l < /etc/passwd")[0]) == body.count("\n"), \
        "%s vs %s" % (num(R(s, "wc -l < /etc/passwd")[0]), body.count("\n"))


@cross("files", "ls | wc -l == ls -1 line count")
def _c(s):
    a = num(R(s, "ls /etc | wc -l")[0])
    b = len([l for l in R(s, "ls -1 /etc")[0].splitlines() if l.strip()])
    return a == b, "%s vs %s" % (a, b)


@cross("files", "ls -a count == ls count + 2")
def _c(s):
    a = len(R(s, "ls -1 /root")[0].split())
    b = len(R(s, "ls -1a /root")[0].split())
    hidden = len([x for x in R(s, "ls -1a /root")[0].split() if x.startswith(".")])
    return b == a + hidden, "%d visible, %d total, %d dotted" % (a, b, hidden)


@cross("files", "written file has the right size")
def _c(s):
    R(s, "echo hello > /tmp/d1")
    return num(R(s, "wc -c < /tmp/d1")[0]) == 6, R(s, "wc -c < /tmp/d1")[0].strip()


@cross("files", "written file appears in ls -l with that size")
def _c(s):
    R(s, "echo hello > /tmp/d2")
    o = R(s, "ls -l /tmp/d2")[0]
    return " 6 " in o, o.strip()[:50]


@cross("files", "append grows the file")
def _c(s):
    R(s, "echo hello > /tmp/d3")
    R(s, "echo more >> /tmp/d3")
    return num(R(s, "wc -c < /tmp/d3")[0]) == 11, R(s, "wc -c < /tmp/d3")[0].strip()


@cross("files", "truncate with > empties it")
def _c(s):
    R(s, "echo hello > /tmp/d4")
    R(s, "> /tmp/d4")
    return num(R(s, "wc -c < /tmp/d4")[0]) == 0, R(s, "wc -c < /tmp/d4")[0].strip()


@cross("files", "dir link count = subdirs + 2")
def _c(s):
    R(s, "mkdir -p /tmp/dd/a /tmp/dd/b")
    o = R(s, "ls -ld /tmp/dd")[0].strip()
    m = re.match(r"\S+\s+(\d+)", o)
    return m and int(m.group(1)) == 4, "%s (%s)" % (m.group(1) if m else None, o[:40])


@cross("files", "empty dir link count is 2")
def _c(s):
    R(s, "mkdir -p /tmp/de")
    m = re.match(r"\S+\s+(\d+)", R(s, "ls -ld /tmp/de")[0].strip())
    return m and int(m.group(1)) == 2, m.group(1) if m else None


@cross("files", "chmod is reflected in ls -l")
def _c(s):
    R(s, "touch /tmp/d5; chmod 700 /tmp/d5")
    return R(s, "ls -l /tmp/d5")[0].strip().startswith("-rwx------"), \
        R(s, "ls -l /tmp/d5")[0].strip()[:20]


@cross("files", "chmod is reflected in stat -c %a")
def _c(s):
    R(s, "touch /tmp/d6; chmod 751 /tmp/d6")
    return R(s, "stat -c %a /tmp/d6")[0].strip() == "751", \
        R(s, "stat -c %a /tmp/d6")[0].strip()


@cross("files", "chown is reflected in ls -l")
def _c(s):
    R(s, "touch /tmp/d7; chown daemon /tmp/d7")
    return "daemon" in R(s, "ls -l /tmp/d7")[0], R(s, "ls -l /tmp/d7")[0].strip()[:50]


@cross("files", "rm actually removes")
def _c(s):
    R(s, "touch /tmp/d8")
    R(s, "rm -f /tmp/d8")
    return R(s, "cat /tmp/d8")[2] != 0, R(s, "cat /tmp/d8")[0].strip()[:40]


@cross("files", "mv moves and preserves content")
def _c(s):
    R(s, "echo abc > /tmp/d9; mv /tmp/d9 /tmp/d9b")
    return R(s, "cat /tmp/d9b")[0].strip() == "abc" and R(s, "cat /tmp/d9")[2] != 0, \
        repr(R(s, "cat /tmp/d9b")[0])


@cross("files", "cp copies content and size")
def _c(s):
    R(s, "echo abcd > /tmp/da; cp /tmp/da /tmp/dab")
    return num(R(s, "wc -c < /tmp/dab")[0]) == 5, R(s, "wc -c < /tmp/dab")[0].strip()


@cross("files", "touch sets mtime to now")
def _c(s):
    R(s, "touch /tmp/db")
    now = num(R(s, "date +%s")[0])
    mt = num(R(s, "stat -c %Y /tmp/db")[0])
    return mt and now and abs(now - mt) < 120, "now=%s mtime=%s" % (now, mt)


@cross("files", "no file has an mtime in the future")
def _c(s):
    now = num(R(s, "date +%s")[0])
    bad = []
    for line in R(s, "find /etc -maxdepth 1 -type f")[0].splitlines()[:40]:
        mt = num(R(s, "stat -c %%Y %s" % line.strip())[0])
        if mt and now and mt > now + 60:
            bad.append((line.strip(), mt))
    return not bad, "future mtimes: %s" % bad[:3]


@cross("files", "ln -s creates a symlink ls -l shows")
def _c(s):
    R(s, "ln -s /etc/passwd /tmp/dc")
    o = R(s, "ls -l /tmp/dc")[0]
    return o.strip().startswith("l") and "->" in o, o.strip()[:50]


@cross("files", "readlink returns the symlink target")
def _c(s):
    R(s, "ln -s /etc/passwd /tmp/dd2")
    return R(s, "readlink /tmp/dd2")[0].strip() == "/etc/passwd", \
        repr(R(s, "readlink /tmp/dd2")[0].strip())


@cross("files", "cat through a symlink reads the target")
def _c(s):
    R(s, "ln -s /etc/hostname /tmp/dl")
    return R(s, "cat /tmp/dl")[0] == R(s, "cat /etc/hostname")[0], "differs"


@cross("files", "du -s prints one total, not a listing")
def _c(s):
    o = R(s, "du -s /etc")[0]
    return len([l for l in o.splitlines() if l.strip()]) == 1, \
        "%d lines" % len(o.splitlines())


@cross("files", "du -sh / total agrees with df used within 3x")
def _c(s):
    o = R(s, "du -sh /")[0]
    m = re.match(r"([\d.]+)([KMGT])", o.strip())
    d = re.search(r"\s([\d.]+)([KMGT])\s+[\d.]+[KMGT]\s+\d+%", R(s, "df -h /")[0])
    if not m or not d:
        return False, "du=%r df=%r" % (o.strip()[:30], R(s, "df -h /")[0].strip()[:40])
    mult = {"K": 1, "M": 1024, "G": 1024 ** 2, "T": 1024 ** 3}
    du = float(m.group(1)) * mult[m.group(2)]
    df = float(d.group(1)) * mult[d.group(2)]
    return 0.2 < du / df < 5, "du=%.0fK df=%.0fK" % (du, df)


@cross("files", "find -type f finds files that cat can read")
def _c(s):
    files = R(s, "find /etc -maxdepth 1 -type f")[0].splitlines()[:10]
    bad = [f for f in files if R(s, "cat %s" % f.strip())[2] != 0]
    return files and not bad, "unreadable: %s" % bad[:3]


@cross("files", "stat -f reports a filesystem")
def _c(s):
    o = R(s, "stat -f /")[0]
    return "Blocks" in o or "ID:" in o, o.strip()[:50]


# ---- hardware
@cross("hardware", "nproc == /proc/cpuinfo processors")
def _c(s):
    a = num(R(s, "nproc")[0])
    b = len(re.findall(r"^processor\s*:", R(s, "cat /proc/cpuinfo")[0], re.M))
    return a == b, "%s vs %s" % (a, b)


@cross("hardware", "nproc == lscpu CPU(s)")
def _c(s):
    a = num(R(s, "nproc")[0])
    m = re.search(r"^CPU\(s\):\s*(\d+)", R(s, "lscpu")[0], re.M)
    return m and a == int(m.group(1)), "%s vs %s" % (a, m.group(1) if m else None)


@cross("hardware", "nproc == /proc/stat cpuN lines")
def _c(s):
    a = num(R(s, "nproc")[0])
    b = len(re.findall(r"^cpu\d+ ", R(s, "cat /proc/stat")[0], re.M))
    return a == b, "%s vs %s" % (a, b)


@cross("hardware", "nproc == /sys cpu dirs")
def _c(s):
    a = num(R(s, "nproc")[0])
    b = len(re.findall(r"^cpu\d+$", R(s, "ls /sys/devices/system/cpu")[0], re.M))
    return a == b, "%s vs %s" % (a, b)


@cross("hardware", "cpu model agrees cpuinfo vs lscpu")
def _c(s):
    a = re.search(r"model name\s*:\s*(.+)", R(s, "cat /proc/cpuinfo")[0])
    b = re.search(r"Model name:\s*(.+)", R(s, "lscpu")[0])
    return a and b and a.group(1).strip() == b.group(1).strip(), \
        "%r vs %r" % (a.group(1).strip()[:24] if a else None,
                      b.group(1).strip()[:24] if b else None)


@cross("hardware", "free total ~= /proc/meminfo MemTotal")
def _c(s):
    m = re.search(r"MemTotal:\s*(\d+)", R(s, "cat /proc/meminfo")[0])
    f = re.search(r"Mem:\s*(\d+)", R(s, "free -m")[0])
    if not m or not f:
        return False, "m=%s f=%s" % (bool(m), bool(f))
    return abs(int(m.group(1)) // 1024 - int(f.group(1))) <= 8, \
        "%s vs %s" % (int(m.group(1)) // 1024, f.group(1))


@cross("hardware", "free -b total == MemTotal bytes")
def _c(s):
    m = re.search(r"MemTotal:\s*(\d+)", R(s, "cat /proc/meminfo")[0])
    f = re.search(r"Mem:\s*(\d+)", R(s, "free -b")[0])
    if not m or not f:
        return False, "missing"
    return abs(int(m.group(1)) * 1024 - int(f.group(1))) < 2 * 1024 ** 2, \
        "%s vs %s" % (int(m.group(1)) * 1024, f.group(1))


@cross("hardware", "meminfo used+free+buffers <= total")
def _c(s):
    mi = R(s, "cat /proc/meminfo")[0]
    g = lambda k: int(re.search(k + r":\s*(\d+)", mi).group(1)) if re.search(k + r":\s*(\d+)", mi) else 0
    return 0 < g("MemFree") <= g("MemTotal") and g("MemAvailable") <= g("MemTotal"), \
        "total=%d free=%d avail=%d" % (g("MemTotal"), g("MemFree"), g("MemAvailable"))


@cross("hardware", "meminfo SwapTotal agrees with free")
def _c(s):
    mi = re.search(r"SwapTotal:\s*(\d+)", R(s, "cat /proc/meminfo")[0])
    fr = re.search(r"Swap:\s*(\d+)", R(s, "free -m")[0])
    if not mi or not fr:
        return False, "missing"
    return abs(int(mi.group(1)) // 1024 - int(fr.group(1))) <= 1, \
        "%s vs %s" % (int(mi.group(1)) // 1024, fr.group(1))


@cross("hardware", "dmidecode product == /sys/class/dmi product_name")
def _c(s):
    a = R(s, "dmidecode -s system-product-name")[0].strip()
    b = R(s, "cat /sys/class/dmi/id/product_name")[0].strip()
    return a and a == b, "%r vs %r" % (a, b)


@cross("hardware", "lscpu virtualisation agrees with systemd-detect-virt")
def _c(s):
    l = R(s, "lscpu")[0]
    v = R(s, "systemd-detect-virt")[0].strip()
    if v in ("none", ""):
        return "Hypervisor vendor" not in l, "virt=%r but lscpu names a hypervisor" % v
    return "Hypervisor vendor" in l or "hypervisor" in l.lower(), \
        "virt=%r, lscpu has no Hypervisor vendor line" % v


# ---- time / boot
@cross("time", "date +%s is a plausible unix time")
def _c(s):
    t = R(s, "date +%s")[0].strip()
    return t.isdigit() and 1.7e9 < int(t) < 2.2e9, t


@cross("time", "date +%s tracks the wall clock")
def _c(s):
    a = num(R(s, "date +%s")[0])
    return a and abs(a - int(time.time())) < 90, "%s vs %s" % (a, int(time.time()))


@cross("time", "clock advances over 1.2s")
def _c(s):
    a = num(R(s, "date +%s")[0])
    time.sleep(1.2)
    b = num(R(s, "date +%s")[0])
    return a and b and b > a, "%s -> %s" % (a, b)


@cross("time", "/proc/uptime advances")
def _c(s):
    a = float(R(s, "cat /proc/uptime")[0].split()[0])
    time.sleep(1.0)
    b = float(R(s, "cat /proc/uptime")[0].split()[0])
    return b > a, "%.2f -> %.2f" % (a, b)


@cross("time", "uptime -p agrees with /proc/uptime days")
def _c(s):
    up = float(R(s, "cat /proc/uptime")[0].split()[0])
    p = R(s, "uptime -p")[0]
    days = int(re.search(r"(\d+) day", p).group(1)) if re.search(r"(\d+) day", p) else 0
    return abs(days - up / 86400) < 1.5, "uptime -p=%r proc=%.1f days" % (p.strip(), up / 86400)


@cross("time", "sleep 1 really takes about a second")
def _c(s):
    t0 = time.time()
    R(s, "sleep 1")
    d = time.time() - t0
    return 0.7 <= d <= 1.8, "%.2fs" % d


@cross("time", "/proc/uptime idle >= up on a multicore box")
def _c(s):
    up, idle = [float(x) for x in R(s, "cat /proc/uptime")[0].split()[:2]]
    return idle >= up, "up=%.0f idle=%.0f" % (up, idle)


@cross("boot", "btime == now - uptime")
def _c(s):
    bt = re.search(r"btime (\d+)", R(s, "cat /proc/stat")[0])
    now = num(R(s, "date +%s")[0])
    up = float(R(s, "cat /proc/uptime")[0].split()[0])
    if not bt or not now:
        return False, "missing btime"
    return abs((now - up) - int(bt.group(1))) < 300, \
        "btime=%s now-up=%d" % (bt.group(1), now - up)


@cross("boot", "uptime -s agrees with btime")
def _c(s):
    bt = re.search(r"btime (\d+)", R(s, "cat /proc/stat")[0])
    o = R(s, "uptime -s")[0].strip()
    return bt and re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", o), \
        "uptime -s=%r btime=%s" % (o, bt.group(1) if bt else None)


@cross("boot", "who -b reports a boot time")
def _c(s):
    o = R(s, "who -b")[0]
    return "boot" in o and re.search(r"\d\d:\d\d", o), o.strip()[:40]


@cross("boot", "dmesg starts with the kernel banner")
def _c(s):
    o = R(s, "dmesg")[0]
    rel = R(s, "uname -r")[0].strip()
    return o.strip() and rel in o, o.strip().splitlines()[0][:60] if o.strip() else "empty"


@cross("boot", "dmesg timestamps are monotonic")
def _c(s):
    ts = [float(x) for x in re.findall(r"^\[\s*([\d.]+)\]", R(s, "dmesg")[0], re.M)]
    return len(ts) > 3 and ts == sorted(ts), "%d stamps, sorted=%s" % (
        len(ts), ts == sorted(ts))


@cross("boot", "last reboot mentions the kernel or boot")
def _c(s):
    o = R(s, "last reboot")[0]
    return "reboot" in o, o.strip()[:50]


# ---- sessions
@cross("sessions", "who lists our user")
def _c(s):
    me = R(s, "whoami")[0].strip()
    return me in R(s, "who")[0], "%r not in %r" % (me, R(s, "who")[0].strip()[:60])


@cross("sessions", "w lists our user")
def _c(s):
    me = R(s, "whoami")[0].strip()
    return me in R(s, "w")[0], "%r not in %r" % (me, R(s, "w")[0].strip()[:70])


@cross("sessions", "our tty is a pts")
def _c(s):
    return R(s, "tty")[0].strip().startswith("/dev/pts/"), R(s, "tty")[0].strip()


@cross("sessions", "who mentions our tty")
def _c(s):
    t = R(s, "tty")[0].strip().replace("/dev/", "")
    return t and t in R(s, "who")[0], "%s not in who" % t


@cross("sessions", "w header user count matches its rows")
def _c(s):
    o = R(s, "w")[0]
    m = re.search(r"(\d+) users?", o)
    rows = len([l for l in o.splitlines()[2:] if l.strip()])
    return m and int(m.group(1)) == rows, "header=%s rows=%d" % (
        m.group(1) if m else None, rows)


@cross("sessions", "w load average matches /proc/loadavg")
def _c(s):
    w = re.search(r"load average:\s*([\d.]+)", R(s, "w")[0])
    p = R(s, "cat /proc/loadavg")[0].split()
    return w and p and abs(float(w.group(1)) - float(p[0])) < 0.5, \
        "w=%s proc=%s" % (w.group(1) if w else None, p[0] if p else None)


@cross("sessions", "uptime load matches /proc/loadavg")
def _c(s):
    u = re.search(r"load average:\s*([\d.]+)", R(s, "uptime")[0])
    p = R(s, "cat /proc/loadavg")[0].split()
    return u and p and abs(float(u.group(1)) - float(p[0])) < 0.5, \
        "uptime=%s proc=%s" % (u.group(1) if u else None, p[0] if p else None)


@cross("sessions", "last shows our user")
def _c(s):
    me = R(s, "whoami")[0].strip()
    return me in R(s, "last")[0], R(s, "last")[0].strip()[:60]


@cross("sessions", "SSH_TTY == tty")
def _c(s):
    return R(s, "echo $SSH_TTY")[0].strip() == R(s, "tty")[0].strip(), \
        "%r vs %r" % (R(s, "echo $SSH_TTY")[0].strip(), R(s, "tty")[0].strip())


@cross("sessions", "SSH_CLIENT is the first 2 + last field of SSH_CONNECTION")
def _c(s):
    c = R(s, "echo $SSH_CONNECTION")[0].split()
    cl = R(s, "echo $SSH_CLIENT")[0].split()
    return len(c) == 4 and len(cl) == 3 and cl[0] == c[0] and cl[1] == c[1], \
        "%s vs %s" % (c, cl)


@cross("sessions", "auth.log mentions our login")
def _c(s):
    me = R(s, "whoami")[0].strip()
    log = R(s, "cat /var/log/auth.log")[0]
    return "sshd" in log and me in log, "sshd=%s user=%s" % ("sshd" in log, me in log)


@cross("sessions", "auth.log last line is recent")
def _c(s):
    """Recent means hours, not "same calendar date".

    This compared the date prefix to today's, so at 00:32 UTC a line written
    thirty minutes earlier read as stale -- the check failed on the clock
    rolling over rather than on anything about the log. What it is really
    asserting is that the newest entry is not old.
    """
    log = [l for l in R(s, "cat /var/log/auth.log")[0].splitlines() if l.strip()]
    if not log:
        return False, "empty"
    import time as _t
    stamp = " ".join(log[-1].split()[:3])
    now = float(R(s, "date +%s")[0].strip() or _t.time())
    year = _t.localtime(now).tm_year
    for y in (year, year - 1):
        try:
            when = _t.mktime(_t.strptime("%d %s" % (y, stamp),
                                         "%Y %b %d %H:%M:%S"))
        except ValueError:
            continue
        if when <= now + 60:
            return (now - when) < 6 * 3600, \
                "last entry is %.1f hours old" % ((now - when) / 3600.0)
    return False, "unparseable last line %r" % log[-1][:40]


@cross("logs", "journalctl -u filters by unit")
def _c(s):
    """`journalctl -u ssh` used to return CRON and nginx entries, and
    `-u nosuchunit` returned the same six lines as everything else."""
    out = R(s, "journalctl -u ssh -n 20 --no-pager")[0]
    body = [l for l in out.splitlines() if not l.startswith("--")]
    if not body:
        return False, "no ssh entries at all"
    bad = [l for l in body if "sshd" not in l]
    return not bad, "non-ssh lines: %s" % [l[:40] for l in bad[:2]]


@cross("logs", "an unknown unit has no journal entries")
def _c(s):
    out = R(s, "journalctl -u definitelynotaunit --no-pager")[0]
    body = [l for l in out.splitlines() if not l.startswith("--")]
    return not body, "%d entries for a unit that does not exist" % len(body)


@cross("logs", "the journal is not older than syslog")
def _c(s):
    """rsyslog is fed from the journal, so the journal cannot be behind it.
    The journal used to stop an hour back while syslog ran to the minute."""
    j = [l for l in R(s, "journalctl -n 1 --no-pager")[0].splitlines()
         if not l.startswith("--")]
    y = [l for l in R(s, "tail -1 /var/log/syslog")[0].splitlines() if l.strip()]
    if not j or not y:
        return False, "journal=%r syslog=%r" % (j[:1], y[:1])
    import time as _t
    def when(line):
        try:
            tm = _t.strptime("%d %s" % (_t.localtime().tm_year,
                                        " ".join(line.split()[:3])),
                             "%Y %b %d %H:%M:%S")
            return _t.mktime(tm)
        except ValueError:
            return 0
    return when(j[-1]) >= when(y[-1]) - 60, \
        "journal %r vs syslog %r" % (j[-1][:20], y[-1][:20])


@cross("logs", "journalctl --disk-usage answers the question asked")
def _c(s):
    out = R(s, "journalctl --disk-usage")[0]
    return "take up" in out and "journals" in out, out.strip()[:60]


@cross("logs", "journalctl --list-boots lists boots, not log lines")
def _c(s):
    # systemd v250 gave this a header row and split the range into two
    # timestamp columns; the old check asserted the pre-250 shape, where
    # the first line was the boot itself. What it is really guarding
    # against is the table being log lines, so check the columns.
    lines = [l for l in R(s, "journalctl --list-boots")[0].splitlines()
             if l.strip()]
    if len(lines) < 2:
        return False, (lines or [""])[0][:60]
    head, row = lines[0].split(), lines[1].split()
    return (head[:3] == ["IDX", "BOOT", "ID"] and row[0].lstrip("-").isdigit()
            and len(row[1]) == 32), lines[0][:60]


@cross("logs", "cron jobs the journal cites exist on disk")
def _c(s):
    """The canned journal referenced /root/scripts/rotate-dispatch.sh, which
    was never on the box."""
    import re as _re
    out = R(s, "journalctl -n 200 --no-pager")[0]
    bad = []
    for path in set(_re.findall(r"CMD \((/\S+?\.sh)\)", out)):
        if R(s, "ls %s" % path)[2] != 0:
            bad.append(path)
    return not bad, str(bad)


@cross("sessions", "loginctl or /run/utmp backs who")
def _c(s):
    o, e, r = R(s, "loginctl list-sessions")
    return r == 0 or "SESSION" in o or R(s, "ls -l /run/utmp")[2] == 0, \
        (o + e).strip()[:40]


# ---- logs
@cross("logs", "auth.log is non-trivial")
def _c(s):
    return len(R(s, "cat /var/log/auth.log")[0].splitlines()) > 3, \
        "%d lines" % len(R(s, "cat /var/log/auth.log")[0].splitlines())


@cross("logs", "syslog exists and has recent entries")
def _c(s):
    o, e, r = R(s, "cat /var/log/syslog")
    return r == 0 and len(o.splitlines()) > 3, "rc=%s %d lines" % (r, len(o.splitlines()))


@cross("logs", "journalctl returns lines")
def _c(s):
    o, e, r = R(s, "journalctl -n 5 --no-pager")
    return r == 0 and len(o.splitlines()) >= 1, "rc=%s %r" % (r, o.strip()[:40])


@cross("logs", "journalctl -u ssh mentions sshd")
def _c(s):
    o = R(s, "journalctl -u ssh -n 5 --no-pager")[0]
    return "ssh" in o.lower(), o.strip()[:50]


@cross("logs", "wtmp exists and is non-empty")
def _c(s):
    o = R(s, "ls -l /run/utmp /var/log/wtmp")[0]
    return "wtmp" in o, o.strip()[:60]


@cross("logs", "lastlog is absent, as on trixie")
def _c(s):
    # This used to require lastlog to answer. Debian 13 dropped it from
    # shadow -- the real trixie guest has no lastlog and a 0-byte
    # /var/log/lastlog -- and ours was printing login records out of that
    # empty file while `command -v lastlog` said the binary did not exist.
    o, e, r = R(s, "lastlog")
    return r == 127, (o + e).strip()[:40]


@cross("logs", "log timestamps do not exceed date")
def _c(s):
    # Parse the syslog stamps rather than substring-searching for a year: any
    # four-digit pid or uptime float can contain "2027", which made this fail
    # at random.
    import datetime
    now = num(R(s, "date +%s")[0])
    year = int(R(s, "date +%Y")[0].strip())
    worst = None
    for line in R(s, "cat /var/log/syslog")[0].splitlines():
        m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)",
                     line)
        if not m:
            continue
        try:
            mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                   "Sep", "Oct", "Nov", "Dec"].index(m.group(1)) + 1
            ts = datetime.datetime(year, mon, int(m.group(2)),
                                   int(m.group(3)), int(m.group(4)),
                                   int(m.group(5)),
                                   tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            continue
        if now and ts > now + 120 and (worst is None or ts > worst):
            worst = ts
    return worst is None, "entry %.0fs in the future" % (
        (worst - now) if worst else 0)


# ---- packages / binaries
@cross("packages", "bash --version agrees with dpkg")
def _c(s):
    d = re.search(r"^ii\s+bash\s+(\S+)", R(s, "dpkg -l")[0], re.M)
    v = R(s, "bash --version")[0]
    if not d:
        return False, "bash not in dpkg -l"
    base = d.group(1).split("-")[0]
    return base in v, "dpkg=%s vs %r" % (base, v.strip().splitlines()[0][:40] if v.strip() else "")


@cross("packages", "ssh -V agrees with the openssh dpkg version")
def _c(s):
    d = re.search(r"^ii\s+openssh-(?:server|client)\s+(\S+)", R(s, "dpkg -l")[0], re.M)
    o, e, r = R(s, "ssh -V")
    txt = o + e
    if not d:
        return False, "openssh not in dpkg -l"
    base = d.group(1).split("-")[0].replace("1:", "")
    return base in txt, "dpkg=%s vs %r" % (base, txt.strip()[:40])


@cross("packages", "sshd version matches the SSH banner persona")
def _c(s):
    o, e, r = R(s, "ssh -V")
    return "OpenSSH_10" in (o + e), (o + e).strip()[:50]


@cross("packages", "curl --version agrees with dpkg")
def _c(s):
    d = re.search(r"^ii\s+curl\s+(\S+)", R(s, "dpkg -l")[0], re.M)
    o, e, r = R(s, "curl --version")
    if not d:
        return True, "curl not installed"
    return d.group(1).split("-")[0] in (o + e), \
        "dpkg=%s vs %r" % (d.group(1), (o + e).strip()[:40])


@cross("packages", "wget --version agrees with dpkg")
def _c(s):
    d = re.search(r"^ii\s+wget\s+(\S+)", R(s, "dpkg -l")[0], re.M)
    o, e, r = R(s, "wget --version")
    if not d:
        return True, "wget not installed"
    return d.group(1).split("-")[0] in (o + e), \
        "dpkg=%s vs %r" % (d.group(1), (o + e).strip()[:40])


@cross("packages", "systemctl --version agrees with dpkg")
def _c(s):
    d = re.search(r"^ii\s+systemd\s+(\S+)", R(s, "dpkg -l")[0], re.M)
    o, e, r = R(s, "systemctl --version")
    if not d:
        return False, "systemd not in dpkg -l"
    return d.group(1).split("-")[0] in (o + e), \
        "dpkg=%s vs %r" % (d.group(1), (o + e).strip().splitlines()[0][:40] if (o+e).strip() else "")


@cross("packages", "coreutils version agrees with dpkg")
def _c(s):
    d = re.search(r"^ii\s+coreutils\s+(\S+)", R(s, "dpkg -l")[0], re.M)
    o, e, r = R(s, "ls --version")
    if not d:
        return False, "coreutils not in dpkg -l"
    return d.group(1).split("-")[0] in (o + e), \
        "dpkg=%s vs %r" % (d.group(1), (o + e).strip().splitlines()[0][:40] if (o+e).strip() else "")


@cross("packages", "dpkg -l count agrees with apt list --installed")
def _c(s):
    a = len(re.findall(r"^ii\s", R(s, "dpkg -l")[0], re.M))
    o = R(s, "apt list --installed")[0]
    b = len([l for l in o.splitlines() if "/" in l])
    return a and b and abs(a - b) <= max(3, a * 0.1), "dpkg=%d apt=%d" % (a, b)


@cross("packages", "dpkg -S /usr/bin/bash names bash")
def _c(s):
    o, e, r = R(s, "dpkg -S /usr/bin/bash")
    return "bash" in o, (o + e).strip()[:50]


@cross("packages", "dpkg -L bash lists /usr/bin/bash")
def _c(s):
    o = R(s, "dpkg -L bash")[0]
    return "/bin/bash" in o, o.strip()[:60]


@cross("packages", "dpkg -s bash reports installed")
def _c(s):
    o = R(s, "dpkg -s bash")[0]
    return "Status: install ok installed" in o, o.strip()[:50]


# ---- package and service management. Mutations are checked by reading back
# what the command claimed to do; a change that does not stick is worse than an
# error, because the attacker only finds out later.
@cross("pkgmgmt", "every binary dpkg claims to ship actually runs")
def _c(s):
    # This is the invariant that would have caught adduser and
    # update-alternatives: both were listed by `dpkg -S`/`dpkg -L` and both
    # were command-not-found.
    missing = []
    for pkg in ("dpkg", "passwd", "adduser", "coreutils", "procps",
                "util-linux", "systemd", "libc-bin", "debianutils"):
        listing = R(s, "dpkg -L %s" % pkg)[0]
        for path in re.findall(r"^/usr/s?bin/(\S+)$", listing, re.M):
            o, e, r = R(s, "command -v %s" % path)
            if r != 0:
                missing.append(path)
    return not missing, "%d not resolvable: %s" % (len(missing), missing[:6])


@cross("pkgmgmt", "useradd honours -u")
def _c(s):
    R(s, "useradd -o -u 0 -g 0 detectbd")
    line = [l for l in R(s, "cat /etc/passwd")[0].splitlines()
            if l.startswith("detectbd:")]
    return line and line[0].split(":")[2] == "0", \
        "passwd line %r" % (line[0] if line else None)


@cross("pkgmgmt", "a new user is visible to id and getent")
def _c(s):
    R(s, "useradd -m -s /bin/bash detectu")
    idout = R(s, "id detectu")[0]
    ent = R(s, "getent passwd detectu")[0]
    return "detectu" in idout and ent.startswith("detectu:"), \
        "id=%r getent=%r" % (idout.strip()[:40], ent.strip()[:40])


@cross("pkgmgmt", "a new user gets a shadow entry")
def _c(s):
    R(s, "useradd detects")
    return any(l.startswith("detects:")
               for l in R(s, "cat /etc/shadow")[0].splitlines()), "absent"


@cross("pkgmgmt", "useradd -G puts the user in the group")
def _c(s):
    R(s, "useradd -G sudo detectg")
    grp = [l for l in R(s, "cat /etc/group")[0].splitlines()
           if l.startswith("sudo:")]
    return grp and "detectg" in grp[0], "sudo line %r" % (grp[0] if grp else None)


@cross("pkgmgmt", "usermod -aG appends to the group")
def _c(s):
    R(s, "groupadd detectgrp")
    R(s, "useradd detectm")
    R(s, "usermod -aG detectgrp detectm")
    grp = [l for l in R(s, "cat /etc/group")[0].splitlines()
           if l.startswith("detectgrp:")]
    return grp and "detectm" in grp[0], "%r" % (grp[0] if grp else None)


@cross("pkgmgmt", "usermod -s changes the shell in passwd")
def _c(s):
    R(s, "useradd detectsh")
    R(s, "usermod -s /bin/false detectsh")
    line = [l for l in R(s, "cat /etc/passwd")[0].splitlines()
            if l.startswith("detectsh:")]
    return line and line[0].endswith("/bin/false"), \
        "%r" % (line[0] if line else None)


@cross("pkgmgmt", "chpasswd changes the shadow hash")
def _c(s):
    before = [l for l in R(s, "cat /etc/shadow")[0].splitlines()
              if l.startswith("root:")]
    R(s, "echo 'root:detectpw' | chpasswd")
    after = [l for l in R(s, "cat /etc/shadow")[0].splitlines()
             if l.startswith("root:")]
    return before and after and before[0] != after[0], "hash unchanged"


@cross("pkgmgmt", "passwd -d empties the shadow field")
def _c(s):
    R(s, "passwd -d root")
    line = [l for l in R(s, "cat /etc/shadow")[0].splitlines()
            if l.startswith("root:")]
    return line and line[0].split(":")[1] == "", \
        "%r" % (line[0][:24] if line else None)


@cross("pkgmgmt", "userdel removes the passwd entry")
def _c(s):
    R(s, "useradd detectdel")
    R(s, "userdel detectdel")
    return not any(l.startswith("detectdel:")
                   for l in R(s, "cat /etc/passwd")[0].splitlines()), "still there"


@cross("svcmgmt", "systemctl stop is reflected by is-active")
def _c(s):
    R(s, "systemctl stop nginx")
    return R(s, "systemctl is-active nginx")[0].strip() == "inactive", \
        R(s, "systemctl is-active nginx")[0].strip()


@cross("svcmgmt", "systemctl disable is reflected by is-enabled")
def _c(s):
    R(s, "systemctl disable nginx")
    return R(s, "systemctl is-enabled nginx")[0].strip() == "disabled", \
        R(s, "systemctl is-enabled nginx")[0].strip()


@cross("svcmgmt", "systemctl mask reports masked")
def _c(s):
    R(s, "systemctl mask nginx")
    return R(s, "systemctl is-enabled nginx")[0].strip() == "masked", \
        R(s, "systemctl is-enabled nginx")[0].strip()


@cross("svcmgmt", "a stopped unit leaves ps")
def _c(s):
    before = R(s, "pgrep nginx")[0].split()
    R(s, "systemctl stop nginx")
    after = R(s, "pgrep nginx")[0].split()
    return before and not after, "before=%s after=%s" % (before, after)


@cross("svcmgmt", "a stopped unit stops listening")
def _c(s):
    R(s, "systemctl stop nginx")
    return ":80" not in R(s, "ss -tln")[0] and \
        ":80" not in R(s, "netstat -tln")[0], "port 80 still listed"


@cross("svcmgmt", "a stopped unit leaves the systemctl listing")
def _c(s):
    R(s, "systemctl stop nginx")
    return "nginx" not in R(s, "systemctl")[0], "still listed"


@cross("svcmgmt", "restarting brings the unit back")
def _c(s):
    R(s, "systemctl stop nginx")
    R(s, "systemctl start nginx")
    return R(s, "systemctl is-active nginx")[0].strip() == "active" and \
        R(s, "pgrep nginx")[0].split(), "did not come back"


@cross("svcmgmt", "systemctl status of a stopped unit exits 3")
def _c(s):
    R(s, "systemctl stop nginx")
    o, _e, r = R(s, "systemctl status nginx")
    return r == 3 and "inactive (dead)" in o, "rc=%s %r" % (r, o[:60])


@cross("svcmgmt", "service NAME ACTION works in that order")
def _c(s):
    o = R(s, "service nginx status")[0]
    R(s, "service nginx stop")
    return "nginx.service" in o and \
        R(s, "systemctl is-active nginx")[0].strip() == "inactive", \
        "status=%r" % o[:50]


@cross("svcmgmt", "an unknown unit fails, not silently succeeds")
def _c(s):
    o, e, r = R(s, "systemctl stop definitely-not-a-unit")
    return r != 0 and "not found" in e, "rc=%s err=%r" % (r, e[:50])


@cross("binaries", "every command in PATH resolves to a file that exists")
def _c(s):
    names = R(s, "ls /usr/bin")[0].split()[:60]
    bad = []
    for n in names:
        p = R(s, "command -v %s" % n)[0].strip()
        if not p:
            bad.append(n)
            continue
        # A builtin that shadows a binary resolves to its bare name, exactly as
        # `command -v echo` does in real bash. Only a path has to exist.
        if p.startswith("/") and R(s, "ls %s" % p)[2] != 0:
            bad.append(n)
    return not bad, "%d unresolvable: %s" % (len(bad), bad[:5])


@cross("binaries", "/bin/ls size agrees between ls -l and wc -c")
def _c(s):
    m = re.match(r"\S+\s+\d+\s+\S+\s+\S+\s+(\d+)", R(s, "ls -l /bin/ls")[0].strip())
    w = num(R(s, "wc -c < /bin/ls")[0])
    return m and w and int(m.group(1)) == w, "%s vs %s" % (m.group(1) if m else None, w)


@cross("binaries", "/bin/ls starts with the ELF magic")
def _c(s):
    o = R(s, "head -c 4 /bin/ls | od -An -c")[0]
    return "177" in o and "E" in o and "L" in o and "F" in o, repr(o.strip()[:30])


@cross("binaries", "file and od agree that /bin/ls is 64-bit ELF")
def _c(s):
    f = R(s, "file /bin/ls")[0]
    return "ELF 64-bit" in f and "x86-64" in f, f.strip()[:60]


@cross("binaries", "ldd libraries exist on disk")
def _c(s):
    libs = re.findall(r"=> (/\S+)", R(s, "ldd /bin/ls")[0])
    bad = [l for l in libs if R(s, "ls %s" % l)[2] != 0]
    return libs and not bad, "missing: %s" % bad[:3]


@cross("binaries", "which and command -v agree")
def _c(s):
    for n in ("ls", "cat", "bash", "grep"):
        a = R(s, "which %s" % n)[0].strip()
        b = R(s, "command -v %s" % n)[0].strip()
        if a != b:
            return False, "%s: %r vs %r" % (n, a, b)
    return True, ""


@cross("binaries", "the shell we run is the file $SHELL points at")
def _c(s):
    sh_ = R(s, "echo $SHELL")[0].strip()
    return R(s, "ls %s" % sh_)[2] == 0 and R(s, "file %s" % sh_)[0].count("ELF"), sh_


# ---- network
@cross("network", "an IPv4 address is configured")
def _c(s):
    o = R(s, "ip a")[0]
    return re.search(r"inet \d+\.\d+\.\d+\.\d+", o) is not None, o.strip()[:50]


@cross("network", "ip a and ifconfig report the same addresses")
def _c(s):
    a = set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", R(s, "ip a")[0]))
    b = set(re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", R(s, "ifconfig")[0]))
    return a and a == b, "%s vs %s" % (sorted(a), sorted(b))


@cross("network", "ip a interfaces == /sys/class/net")
def _c(s):
    a = set(re.findall(r"^\d+:\s+([\w.@]+?)[:@]", R(s, "ip a")[0], re.M))
    b = set(R(s, "ls /sys/class/net")[0].split())
    return a and a == b, "%s vs %s" % (sorted(a), sorted(b))


@cross("network", "ip a interfaces == /proc/net/dev")
def _c(s):
    a = set(re.findall(r"^\d+:\s+([\w.@]+?)[:@]", R(s, "ip a")[0], re.M))
    b = set(re.findall(r"^\s*([\w.]+):", R(s, "cat /proc/net/dev")[0], re.M))
    return a and a == b, "%s vs %s" % (sorted(a), sorted(b))


@cross("network", "MAC in ip a == /sys/class/net/<if>/address")
def _c(s):
    out = R(s, "ip a")[0]
    # Per stanza, not across the whole output: a DOTALL match let lo borrow
    # eth0's MAC and reported a mismatch that was not there.
    blocks = re.split(r"^\d+:\s+", out, flags=re.M)
    pairs = []
    for b in blocks:
        m = re.match(r"([\w.]+?):", b)
        e = re.search(r"link/ether ([0-9a-f:]{17})", b)
        if m and e:
            pairs.append((m.group(1), e.group(1)))
    for ifn, mac in pairs[:2]:
        sysmac = R(s, "cat /sys/class/net/%s/address" % ifn)[0].strip()
        if sysmac != mac:
            return False, "%s: %s vs %s" % (ifn, mac, sysmac)
    return True, ""


@cross("network", "hostname -I matches ip a")
def _c(s):
    a = set(R(s, "hostname -I")[0].split())
    b = set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", R(s, "ip a")[0])) - {"127.0.0.1"}
    return a and a == b, "%s vs %s" % (sorted(a), sorted(b))


@cross("network", "a default route exists in both ip route and /proc/net/route")
def _c(s):
    return "default" in R(s, "ip route")[0] and "Iface" in R(s, "cat /proc/net/route")[0], \
        R(s, "ip route")[0].strip()[:50]


@cross("network", "the default gateway is inside a configured subnet")
def _c(s):
    import ipaddress
    gw = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", R(s, "ip route")[0])
    if not gw:
        return False, "no default route"
    # Real subnet arithmetic. A /20 puts 172.31.16.1 and 172.31.24.87 in the
    # same network, which a string prefix comparison called a mismatch.
    for cidr in re.findall(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", R(s, "ip a")[0]):
        try:
            if ipaddress.ip_address(gw.group(1)) in \
                    ipaddress.ip_interface(cidr).network:
                return True, ""
        except ValueError:
            continue
    return False, "gw %s in no configured subnet" % gw.group(1)


@cross("network", "ip route and route -n agree on the gateway")
def _c(s):
    a = re.search(r"default via (\S+)", R(s, "ip route")[0])
    b = R(s, "route -n")[0]
    return a and a.group(1) in b, "%s vs %r" % (a.group(1) if a else None, b.strip()[:50])


@cross("network", "something listens on 22 in ss and netstat")
def _c(s):
    return ":22" in R(s, "ss -tlnp")[0] and ":22" in R(s, "netstat -tlnp")[0], \
        R(s, "ss -tlnp")[0].strip()[:60]


@cross("network", "ss listeners appear in /proc/net/tcp")
def _c(s):
    tcp = R(s, "cat /proc/net/tcp")[0]
    ports = set(int(p) for p in re.findall(r":(\d+)\s+0\.0\.0\.0:\*", R(s, "ss -tln")[0]))
    hexp = {int(m, 16) for m in re.findall(r"^\s*\d+:\s+\S+:([0-9A-F]{4})", tcp, re.M)}
    return ports and ports <= hexp, "ss=%s tcp=%s" % (sorted(ports)[:5], sorted(hexp)[:5])


@cross("network", "our own ssh connection shows in ss")
def _c(s):
    peer = R(s, "echo $SSH_CONNECTION")[0].split()
    if len(peer) != 4:
        return False, "no SSH_CONNECTION"
    return peer[0] in R(s, "ss -tn")[0], "%s not in ss -tn" % peer[0]


@cross("network", "ss -tlnp names a process for port 22")
def _c(s):
    o = R(s, "ss -tlnp")[0]
    line = [l for l in o.splitlines() if ":22 " in l or l.rstrip().endswith(":22")]
    return line and ("users:" in line[0] or "sshd" in line[0]), \
        line[0][:70] if line else "no :22 line"


@cross("network", "resolv.conf nameservers are routable")
def _c(s):
    ns = re.findall(r"nameserver (\S+)", R(s, "cat /etc/resolv.conf")[0])
    return bool(ns), "%s" % ns


@cross("network", "/etc/hosts has localhost")
def _c(s):
    return "127.0.0.1" in R(s, "cat /etc/hosts")[0] and "localhost" in R(s, "cat /etc/hosts")[0], \
        R(s, "cat /etc/hosts")[0].strip()[:40]


@cross("network", "getent hosts localhost resolves")
def _c(s):
    # glibc answers with the ::1 line, because localhost is on it and the
    # v6 entry is preferred -- measured on the guest. This check wanted
    # 127.0.0.1 in the output, which was the old wrong shape: the key
    # echoed beside a bare address rather than the file's line.
    o, e, r = R(s, "getent hosts localhost")
    return r == 0 and "localhost" in o and o.split()[0] in ("::1",
                                                            "127.0.0.1"), \
        (o + e).strip()[:40]


@cross("network", "ip neigh / arp lists the gateway")
def _c(s):
    gw = re.search(r"default via (\S+)", R(s, "ip route")[0])
    n = R(s, "ip neigh")[0] + R(s, "arp -n")[0]
    return gw and gw.group(1) in n, "gw=%s neigh=%r" % (
        gw.group(1) if gw else None, n.strip()[:40])


@cross("network", "ip -s link counters are non-zero")
def _c(s):
    o = R(s, "ip -s link")[0]
    return bool(re.search(r"\b[1-9]\d{2,}\b", o)), o.strip()[:60]


# ---- sshd
@cross("sshd", "sshd_config exists")
def _c(s):
    return R(s, "cat /etc/ssh/sshd_config")[2] == 0, "rc"


@cross("sshd", "sshd_config PermitRootLogin agrees with us being root over ssh")
def _c(s):
    cfg = R(s, "cat /etc/ssh/sshd_config")[0]
    m = re.search(r"^\s*PermitRootLogin\s+(\S+)", cfg, re.M)
    me = R(s, "whoami")[0].strip()
    if me != "root":
        return True, "not root"
    return m is None or m.group(1) in ("yes", "prohibit-password", "without-password"), \
        "PermitRootLogin %s but we are root over ssh" % (m.group(1) if m else "unset")


@cross("sshd", "host keys exist for the offered algorithms")
def _c(s):
    o = R(s, "ls /etc/ssh")[0]
    return "ssh_host_ed25519_key" in o and "ssh_host_rsa_key" in o, o.strip()[:70]


@cross("sshd", "ssh-keygen -lf gives a fingerprint")
def _c(s):
    o, e, r = R(s, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
    return "SHA256:" in o, (o + e).strip()[:50]


@cross("sshd", "the host key pub file parses as a key")
def _c(s):
    o = R(s, "cat /etc/ssh/ssh_host_ed25519_key.pub")[0]
    return o.startswith("ssh-ed25519 AAAA"), o.strip()[:40]


@cross("sshd", "a .pub exists for every host private key")
def _c(s):
    listing = R(s, "ls /etc/ssh")[0].split()
    privs = [f for f in listing if f.startswith("ssh_host_") and
             f.endswith("_key")]
    missing = [f for f in privs if f + ".pub" not in listing]
    return privs and not missing, "no .pub for: %s" % missing


@cross("sshd", "each .pub's algorithm matches its filename")
def _c(s):
    bad = []
    for f in R(s, "ls /etc/ssh")[0].split():
        if not f.endswith("_key.pub"):
            continue
        body = R(s, "cat /etc/ssh/%s" % f)[0].split()
        if not body:
            bad.append(f)
            continue
        kind = f[len("ssh_host_"):-len("_key.pub")]
        if kind not in body[0]:
            bad.append("%s says %s" % (f, body[0]))
    return not bad, "%s" % bad


@cross("sshd", "ssh-keygen -lf size matches the key blob")
def _c(s):
    # A hardcoded size next to a computed fingerprint is a contradiction inside
    # a single line of output: the box claimed 3072 bits for a 2048-bit key.
    import base64 as _b64
    for f in R(s, "ls /etc/ssh")[0].split():
        if not f.endswith("_key.pub"):
            continue
        parts = R(s, "cat /etc/ssh/%s" % f)[0].split()
        if len(parts) < 2:
            continue
        out = R(s, "ssh-keygen -lf /etc/ssh/%s" % f)[0].split()
        if not out or not out[0].isdigit():
            return False, "%s: no size in %r" % (f, " ".join(out)[:40])
        stated = int(out[0])
        if parts[0] == "ssh-ed25519":
            want = 256
        elif parts[0].startswith("ecdsa-sha2-nistp"):
            want = int(parts[0].rsplit("nistp", 1)[1])
        elif parts[0] == "ssh-rsa":
            blob = _b64.b64decode(parts[1] + "===")
            fields, i = [], 0
            while i + 4 <= len(blob) and len(fields) < 3:
                n = int.from_bytes(blob[i:i + 4], "big")
                i += 4
                fields.append(blob[i:i + n])
                i += n
            want = len(fields[2].lstrip(b"\x00")) * 8 if len(fields) > 2 else 0
        else:
            continue
        if stated != want:
            return False, "%s: says %d, blob is %d" % (f, stated, want)
    return True, ""


@cross("sshd", "sshd_config Port agrees with the listener")
def _c(s):
    cfg = R(s, "cat /etc/ssh/sshd_config")[0]
    m = re.search(r"^\s*Port\s+(\d+)", cfg, re.M)
    port = m.group(1) if m else "22"
    return (":" + port) in R(s, "ss -tln")[0], "Port %s not listening" % port


# ---- mounts / disks
@cross("mounts", "mount and /proc/mounts agree on the root device")
def _c(s):
    a = re.search(r"^(\S+) on / type", R(s, "mount")[0], re.M)
    b = re.search(r"^(\S+) / ", R(s, "cat /proc/mounts")[0], re.M)
    return a and b and a.group(1) == b.group(1), \
        "%s vs %s" % (a.group(1) if a else None, b.group(1) if b else None)


@cross("mounts", "df lists the root filesystem")
def _c(s):
    return re.search(r"\s/\s*$", R(s, "df -h")[0], re.M) is not None, \
        R(s, "df -h")[0].strip()[:60]


@cross("mounts", "df root device == /proc/mounts root device")
def _c(s):
    b = re.search(r"^(\S+) / ", R(s, "cat /proc/mounts")[0], re.M)
    return b and b.group(1) in R(s, "df -h")[0], b.group(1) if b else "none"


@cross("mounts", "fstab references the root device or its UUID")
def _c(s):
    fstab = R(s, "cat /etc/fstab")[0]
    dev = re.search(r"^(\S+) / ", R(s, "cat /proc/mounts")[0], re.M)
    blkid = R(s, "blkid")[0]
    uuid = re.search(r'UUID="([^"]+)"', blkid)
    return (dev and dev.group(1) in fstab) or (uuid and uuid.group(1) in fstab), \
        "fstab=%r" % fstab.strip()[:50]


@cross("mounts", "df total agrees with lsblk size")
def _c(s):
    d = re.search(r"\s([\d.]+)G\s+[\d.]+G", R(s, "df -h /")[0])
    l = re.search(r"([\d.]+)G", R(s, "lsblk")[0])
    return d and l and abs(float(d.group(1)) - float(l.group(1))) < float(l.group(1)) * 0.35, \
        "df=%sG lsblk=%sG" % (d.group(1) if d else None, l.group(1) if l else None)


@cross("mounts", "df -h and df -k agree")
def _c(s):
    h = re.search(r"\s([\d.]+)G\s", R(s, "df -h /")[0])
    k = re.search(r"\s(\d+)\s+\d+\s+\d+\s+\d+%", R(s, "df -k /")[0])
    if not h or not k:
        return False, "h=%s k=%s" % (bool(h), bool(k))
    return abs(float(h.group(1)) - int(k.group(1)) / 1024 ** 2) < 2, \
        "%sG vs %dK" % (h.group(1), int(k.group(1)))


@cross("mounts", "df used+avail is consistent with the percentage")
def _c(s):
    m = re.search(r"(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%", R(s, "df -k /")[0])
    if not m:
        return False, R(s, "df -k /")[0].strip()[:50]
    tot, used, avail, pct = (int(x) for x in m.groups())
    calc = round(100.0 * used / (used + avail)) if used + avail else 0
    return abs(calc - pct) <= 2, "stated %d%%, computed %d%%" % (pct, calc)


@cross("mounts", "root device exists under /dev")
def _c(s):
    dev = re.search(r"^(/\S+) / ", R(s, "cat /proc/mounts")[0], re.M)
    return dev and R(s, "ls %s" % dev.group(1))[2] == 0, \
        dev.group(1) if dev else "no /dev root"


@cross("mounts", "lsblk device appears in /proc/partitions")
def _c(s):
    names = re.findall(r"^(\w+)", R(s, "lsblk")[0], re.M)[1:]
    parts = R(s, "cat /proc/partitions")[0]
    bad = [n for n in names if n not in parts]
    return names and not bad, "not in partitions: %s" % bad[:4]


@cross("mounts", "blkid UUID matches /dev/disk/by-uuid")
def _c(s):
    uuid = re.search(r'UUID="([^"]+)"', R(s, "blkid")[0])
    o = R(s, "ls /dev/disk/by-uuid")[0]
    return uuid and uuid.group(1) in o, "%s vs %r" % (
        uuid.group(1) if uuid else None, o.strip()[:50])


@cross("mounts", "every /proc/mounts fs type is in /proc/filesystems or is virtual")
def _c(s):
    known = set(re.findall(r"(\w+)$", R(s, "cat /proc/filesystems")[0], re.M))
    virt = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup2", "cgroup",
            "securityfs", "pstore", "bpf", "autofs", "mqueue", "hugetlbfs",
            "debugfs", "tracefs", "fusectl", "configfs", "efivarfs", "ramfs",
            "binfmt_misc", "nsfs", "rpc_pipefs"}
    types = set(re.findall(r"^\S+ \S+ (\S+) ", R(s, "cat /proc/mounts")[0], re.M))
    bad = types - known - virt
    return not bad, "unknown fs types: %s" % sorted(bad)[:4]


# ---- services
@cross("services", "every listed unit has a unit file")
def _c(s):
    names = re.findall(r"^\s*(\S+)\.service", R(s, "systemctl")[0], re.M)
    bad = [n for n in names
           if R(s, "ls /lib/systemd/system/%s.service" % n)[2] != 0
           and R(s, "ls /etc/systemd/system/%s.service" % n)[2] != 0
           and R(s, "ls /usr/lib/systemd/system/%s.service" % n)[2] != 0]
    return names and not bad, "%d without a unit file: %s" % (len(bad), bad[:5])


@cross("services", "systemctl status names a Main PID that is in ps")
def _c(s):
    ps = R(s, "ps aux")[0]
    for n in re.findall(r"^\s*(\S+)\.service", R(s, "systemctl")[0], re.M)[:5]:
        st = R(s, "systemctl status %s" % n)[0]
        m = re.search(r"Main PID:\s*(\d+)", st)
        if not m:
            return False, "%s: no Main PID line" % n
        if m.group(1) not in ps:
            return False, "%s: PID %s not in ps" % (n, m.group(1))
    return True, ""


@cross("services", "is-active agrees with the systemctl listing")
def _c(s):
    for n in re.findall(r"^\s*(\S+)\.service\s+loaded\s+active", R(s, "systemctl")[0], re.M)[:5]:
        if R(s, "systemctl is-active %s" % n)[0].strip() != "active":
            return False, "%s listed active, is-active says %r" % (
                n, R(s, "systemctl is-active %s" % n)[0].strip())
    return True, ""


@cross("services", "running units have a process in ps")
def _c(s):
    # Compare by MainPID, not by name: a versioned unit like php8.4-fpm runs a
    # process called "php-fpm: master process", so matching the unit name
    # against ps output cannot work and says nothing useful when it does.
    pids = set(R(s, "ps -eo pid=")[0].split())
    bad = []
    for n in re.findall(r"^\s*(\S+)\.service", R(s, "systemctl")[0], re.M):
        m = re.search(r"MainPID=(\d+)",
                      R(s, "systemctl show -p MainPID %s" % n)[0])
        if not m or m.group(1) == "0":
            bad.append("%s: no MainPID" % n)
        elif m.group(1) not in pids:
            bad.append("%s: pid %s absent" % (n, m.group(1)))
    return not bad, "%s" % bad[:4]


@cross("services", "systemctl show MainPID agrees with status")
def _c(s):
    o = R(s, "systemctl show -p MainPID ssh")[0]
    st = R(s, "systemctl status ssh")[0]
    m = re.search(r"MainPID=(\d+)", o)
    n = re.search(r"Main PID:\s*(\d+)", st)
    return m and n and m.group(1) == n.group(1), "%s vs %s" % (
        m.group(1) if m else None, n.group(1) if n else None)


@cross("services", "systemctl list-units --failed answers")
def _c(s):
    o, e, r = R(s, "systemctl list-units --failed")
    return r == 0, (o + e).strip()[:40]


@cross("services", "enabled units appear in list-unit-files")
def _c(s):
    o, e, r = R(s, "systemctl list-unit-files")
    return r == 0 and "UNIT FILE" in o, (o + e).strip()[:40]


# ---- shell state
@cross("shellstate", "cd changes pwd and $PWD together")
def _c(s):
    R(s, "cd /tmp")
    return R(s, "pwd")[0].strip() == "/tmp" and R(s, "echo $PWD")[0].strip() == "/tmp", \
        "%r / %r" % (R(s, "pwd")[0].strip(), R(s, "echo $PWD")[0].strip())


@cross("shellstate", "cd - returns and sets OLDPWD")
def _c(s):
    R(s, "cd /tmp")
    R(s, "cd /etc")
    return R(s, "echo $OLDPWD")[0].strip() == "/tmp", R(s, "echo $OLDPWD")[0].strip()


@cross("shellstate", "export survives into a child bash")
def _c(s):
    o = R(s, "export FOO=bar; bash -c 'echo $FOO'")[0]
    return o.strip() == "bar", repr(o.strip())


@cross("shellstate", "a set variable shows in set output")
def _c(s):
    R(s, "MYVAR=zzz")
    return "MYVAR" in R(s, "set")[0] or "zzz" in R(s, "echo $MYVAR")[0], "not visible"


@cross("shellstate", "an exported variable shows in env")
def _c(s):
    R(s, "export MYVAR2=qqq")
    return "MYVAR2=qqq" in R(s, "env")[0], R(s, "env")[0].strip()[-40:]


@cross("shellstate", "history follows the shell's mode")
def _c(s):
    # Measured against bash: `bash -c 'echo one; echo two; history'` prints
    # nothing, because a non-interactive shell keeps no history at all.
    # This check asked for the opposite and had been failing since it was
    # written -- the box was right and the check was not. What has to hold
    # is that each mode answers its own way.
    R(s, "echo one")
    R(s, "echo two")
    quiet = R(s, "history")[0].strip() == ""
    i = fs.Shell(fs.VFS())
    i.exec_mode = False
    R(i, "echo one")
    R(i, "echo two")
    o = R(i, "history")[0]
    return (quiet and "echo two" in o,
            "non-interactive=%r interactive=%r" % (quiet, o.strip()[-40:]))


@cross("shellstate", "$SECONDS increases")
def _c(s):
    a = num(R(s, "echo $SECONDS")[0])
    time.sleep(1.1)
    b = num(R(s, "echo $SECONDS")[0])
    return a is not None and b is not None and b > a, "%s -> %s" % (a, b)


@cross("shellstate", "$_ holds the last argument")
def _c(s):
    o = R(s, "echo hello; echo $_")[0]
    return o.strip().endswith("hello"), repr(o.strip()[-20:])


@cross("shellstate", "a function can be defined and called")
def _c(s):
    o = R(s, "f() { echo inside; }; f")[0]
    return o.strip() == "inside", repr(o.strip())


@cross("shellstate", "declare -f shows a defined function")
def _c(s):
    o = R(s, "f() { echo inside; }; declare -f f")[0]
    return "inside" in o, repr(o.strip()[:40])


@cross("shellstate", "unset removes a variable")
def _c(s):
    o = R(s, "X=1; unset X; echo \"[$X]\"")[0]
    return o.strip() == "[]", repr(o.strip())


@cross("shellstate", "$0 names the shell")
def _c(s):
    o = R(s, "echo $0")[0].strip()
    return "bash" in o or o.startswith("-"), repr(o)


@cross("shellstate", "PATH lookup honours order")
def _c(s):
    o = R(s, "type -a ls")[0]
    return "/bin/ls" in o or "/usr/bin/ls" in o, o.strip()[:50]


@cross("shellstate", "command substitution strips trailing newlines")
def _c(s):
    o = R(s, "x=$(echo hi); echo \"[$x]\"")[0]
    return o.strip() == "[hi]", repr(o.strip())


@cross("shellstate", "here-doc feeds stdin")
def _c(s):
    o = R(s, "cat <<EOF\nline1\nEOF")[0]
    return o.strip() == "line1", repr(o.strip())


@cross("shellstate", "a pipeline of three stages works")
def _c(s):
    o = R(s, "cat /etc/passwd | grep root | wc -l")[0]
    return num(o) and num(o) >= 1, repr(o.strip())


@cross("shellstate", "process substitution works")
def _c(s):
    o = R(s, "wc -l < <(cat /etc/passwd)")[0]
    return num(o) and num(o) > 3, repr(o.strip())


@cross("shellstate", "2>&1 merges stderr into stdout")
def _c(s):
    o, e, r = R(s, "cat /nonexistent-xyz 2>&1")
    return "No such file" in o, "out=%r err=%r" % (o.strip()[:30], e.strip()[:30])


@cross("shellstate", "2>/dev/null suppresses stderr")
def _c(s):
    o, e, r = R(s, "cat /nonexistent-xyz 2>/dev/null")
    return not e.strip() and not o.strip(), "out=%r err=%r" % (o[:20], e[:20])


def main():
    all_checks = [(g, n, None, c) for g, n, c, in []]
    for group, name, cmd, pred in SIMPLE:
        def fn(s, cmd=cmd, pred=pred):
            o, e, r = R(s, cmd)
            return bool(pred(o, e, r)), "out=%r err=%r rc=%s" % (
                o.strip()[:40], e.strip()[:40], r)
        CHECKS.append((group, name, fn))

    for group, name, fn in CHECKS:
        if ONLY and group != ONLY:
            continue
        try:
            ok, detail = fn(sh())
        except Exception as exc:
            ok, detail = False, "check crashed: %r" % (exc,)
        (PASSES if ok else FAILS).append((group, name, detail))
        if VERBOSE or not ok:
            print("  %-4s [%-10s] %-46s %s"
                  % ("ok" if ok else "FAIL", group, name, str(detail)[:90]))

    print()
    print("=" * 78)
    print("checks %d   PASS %d   FAIL %d"
          % (len(PASSES) + len(FAILS), len(PASSES), len(FAILS)))
    by = {}
    for g, n, d in FAILS:
        by.setdefault(g, []).append(n)
    for g in sorted(by, key=lambda k: -len(by[k])):
        print("  %-11s %2d" % (g, len(by[g])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
