# honeypot — a Debian 13 shell emulator, and the test suite that proves it

A shell emulator faithful enough to put behind an SSH honeypot, with **139
test suites** that check it against the real thing rather than against
expectations written by hand.

Nothing it runs is real. There is no subprocess, no `exec`, no shell. Every
command is Python over an in-memory filesystem, so an attacker's `rm -rf /`
rearranges a dictionary.

```python
import fakeshell

sh = fakeshell.Shell()
print(sh.run("uname -a"))
# Linux web01 6.12.101+deb13-cloud-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.101-1 ...

print(sh.run("df -h / | tail -1"))
# /dev/sda1        63G  4.1G   56G   7% /

sh.run("echo 'payload' > /tmp/x; chmod 4755 /tmp/x")
print(sh.run("find /tmp -perm -4000 -type f"))
# /tmp/x
```

## Why bother

A honeypot is rarely detected because it is missing a command. It is detected
because it **contradicts itself**. `df` disagreeing with `stat -f`. `ls -l`
disagreeing with `find -perm`. `/etc/profile` describing a `PATH` the shell
does not have. `dpkg -l` claiming a package whose binary answers "command not
found". Any one of those ends the session, and the interesting traffic is the
traffic that stays.

So the design rule here is not "implement more commands", it is **every way of
asking a question must give the same answer**. That is what the suites test,
and it is why there are more lines of test than of implementation.

| | |
|---|---:|
| Emulator | 36,854 lines |
| Commands | ~700 |
| Suites | 139 |
| Test code | 39,000 lines |

## What is in here

| File | Lines | Job |
|---|---:|---|
| `fakeshell.py` | 36,854 | The emulator: the VFS, the shell language, and every command |
| `awkemu.py` | 1,304 | awk — attackers pipe nearly everything through it |
| `localedb.py` | 1,164 | Locale data, so `LC_ALL=` actually changes what commands print |
| `sedemu.py` | 792 | sed |
| `netbase.py` | 559 | `/etc/services`, protocols, rpc, ethertypes — whole files, not samples |
| `tzdb.py` | | Timezone data |
| `skeldb.py` | | `/etc/skel` |

`SUITES.md` lists all 139 suites and the one question each asks.

## Running the tests

```sh
./run-suites.sh                  # all of them; prints only failures
KNOWN_FAILURES= ./run-suites.sh  # ...and do not tolerate the known one
python3 -W ignore difftest.py    # just one
```

CI runs them in a `debian:trixie` container rather than on `ubuntu-latest`,
for the reason in the next paragraph: on a host that is not Debian 13 the
differential suites report the *host's* differences, which looks like signal
and is not.

Some suites are **differential**: they run the same input through this
emulator and through the real `bash`/`coreutils` on the host and diff the
output. Those need a Debian-ish host to be meaningful — on anything else they
will report differences that are the host's, not the emulator's.

## What it emulates

A Debian 13 (trixie) cloud image with nginx, MariaDB, PHP-FPM and cron
installed. That choice shows up everywhere: package versions, `/proc` and
`/sys` contents, systemd units, log rotation state, the exact wording of
error messages, and the two-decades-old quirks GNU tools have. Examples of the
level it goes to:

- `/proc/<pid>/status` reports the capability mask for that process's uid, and
  `capsh --print`, `getpcaps` and `/proc` are all rendered from one table, so
  they cannot disagree about whether the caller is privileged.
- `stat -c %f` prints lowercase hex with correct file-type bits, so a block
  device is `61b0` and not a regular file.
- The replay journal means a file an attacker wrote is still there when they
  reconnect, with its original mtime rather than the time of the reload.
- `ls -l`, `find -perm`, `stat -c %a` and `getcap` all read one node, so a
  `chmod 4755` shows up in every one of them and a `setcap` shows up in none
  of the mode-bit readers.
- Sizes are honest: `df`, `du`, `stat -f`, `tune2fs` and `statvfs` all come
  from one accounting of the same filesystem, and a 40 MB write moves all of
  them.

## Using it in a honeypot

`fakeshell` is only the shell. Wiring it to a network listener, capturing what
arrives, and containing the host are all yours — and the containment is the
part to take seriously. This code assumes it runs on a machine you have
already decided you are willing to lose.

```python
import fakeshell

sh = fakeshell.Shell(
    vfs=fakeshell.VFS(),          # one per source address is a good idea
    user="root",
    peer="203.0.113.9",           # shows up in `last`, `w`, $SSH_CONNECTION
    log=lambda **ev: print(ev),   # every notable event
)
out = sh.run(attacker_input)
```

Two things worth knowing before you deploy it:

- **The persona is generic here.** Hostname `web01`, `example.com`, a
  plausible but invented site. If you deploy it unchanged, its fingerprint is
  the same as everybody else's who did. Change the hostname, the domain, the
  package set and the file tree.
- **A published emulator is a detectable emulator.** The quirks the suites
  pin down are, from the other side, a signature. That is the cost of
  publishing this, and it is worth being clear-eyed that the cost is real.

## Known differences

`run-suites.sh` should report **one** failure on a Debian host, and it is a
real one rather than a flake:

`run-suites.sh` tolerates this one by name and reports it as `KNOWN`, so CI
stays green without the failure being hidden — an unexpected failure still
turns the build red, and `KNOWN_FAILURES= ./run-suites.sh` tolerates nothing.

- `awktest.py` — 89 of 90 cases match GNU Awk 5.2.1 exactly. The one that
  does not is `gsub(/a/, "\\&")`: real gawk leaves `banana` unchanged and
  warns, this emulator produces `b&n&n&`. Escaped-ampersand replacement is
  a corner of awk's substitution escaping that has not been worked through.

Anything else failing is either a genuine regression or a host that is not
Debian 13 — several suites diff against the host's own `bash` and `coreutils`,
so on a different distribution they will report the host's differences, not
the emulator's.

## Provenance

This was extracted from a private repository that runs a live
internet-facing honeypot. It is a **fork, not a mirror**: the deployment, the
capture pipeline, the persona and the operational notes stayed behind, and
the live box does not run this code, deliberately, so that what is published
is not what is deployed.

Attacker addresses in comments have been replaced with RFC 5737 documentation
addresses (`203.0.113.x`, `198.51.100.x`). The sentences around them are
untouched, because the reason a fix exists is the most useful thing a comment
can say — most of the docstrings in here record a real bug and what it cost,
and that is the actual documentation of why the emulator is shaped as it is.

## Licence

MIT — see `LICENSE`.
