# The design rule

A honeypot is rarely detected because it is missing a command. It is detected
because it **contradicts itself**. `df` disagreeing with `stat -f`. `ls -l`
disagreeing with `find -perm`. `/etc/profile` describing a `PATH` the shell
does not have. `dpkg -l` claiming a package whose binary answers "command not
found". Any one of those ends the session, and the interesting traffic is the
traffic that stays.

So the rule is not "implement more commands", it is **every way of asking a
question must give the same answer**. A command is not finished when its
output looks right on its own; it is finished when it agrees with the other
commands that already knew something about the thing it touched.

That is what the suites test, and it is why there are more lines of test than
of implementation: 50,393 lines across 190 suites against 44,098 lines of
emulator.

## One table, many readers

The pattern throughout is that a fact is stored once and rendered several
ways, rather than being answered independently by each command that is asked
about it.

- **Capabilities.** `/proc/<pid>/status` reports the capability mask for that
  process's uid, and `capsh --print`, `getpcaps` and `/proc` are all rendered
  from one table, so they cannot disagree about whether the caller is
  privileged.
- **Mode bits.** `ls -l`, `find -perm`, `stat -c %a` and `getcap` all read one
  node, so a `chmod 4755` shows up in every one of them and a `setcap` shows
  up in none of the mode-bit readers. `stat -c %f` prints lowercase hex with
  correct file-type bits, so a block device is `61b0` and not a regular file.
- **Filesystem size.** `df`, `du`, `stat -f`, `tune2fs` and `statvfs` all come
  from one accounting of the same filesystem. Write 40 MB and `df`'s used
  column moves by exactly 40960 KB while `stat -f`'s free-block count drops by
  exactly 10240 4K blocks — not "roughly", the same number twice.
- **Identity.** `hostname`, `uname -n`, `/etc/hostname`, `hostnamectl
  --static`, `getent hosts`, `hostname -i` and the parenthesised field in
  `ping`'s first line all resolve through one value at rest — `hostname -i`
  returns `127.0.1.1` where an address belongs rather than echoing the name
  back, and `ping` prints the address it resolved rather than the name twice.
  `hostname newname` then moves the running name that `hostname` and `uname
  -n` report and leaves the static one in `/etc/hostname` and `hostnamectl
  --static`, which is the split a real box has — rather than being a silent
  no-op that moves neither. There is one machine ID and one boot ID, read by
  `hostnamectl`, `/etc/machine-id`, `/proc/sys/kernel/random/boot_id` and
  `journalctl --list-boots` alike.
- **Who is looking.** `kernel.kptr_restrict` is 1, so `/proc/modules` shows
  real kernel addresses to root and zeros to everyone else — the sysctl one
  directory away has to be telling the truth about the file next to it.
- **Packages and binaries.** The `dpkg` database, the `/usr/bin` tree,
  `command -v`, `dpkg -S` and `update-alternatives` describe one installed
  system. `/usr/bin/awk` is a symlink through `/etc/alternatives` to
  `/usr/bin/mawk` in the filesystem, and `update-alternatives --display awk`
  describes that same link with the same slaves — it was once a plain binary
  in one and a link in the other.

## Persistence is part of coherence

State that an attacker changed outlives the session that changed it, because a
box that forgets is a box that contradicts what it said last time.

The VFS keeps a journal of the delta — writes, deletes, chmods, links, killed
pids, stopped units — and only the delta, since the baseline tree is
regenerated from code. `VFS.dump_journal()` returns something JSON-serialisable
and `VFS.load_journal()` replays it onto a fresh baseline.

The subtlety is timestamps. A replayed write stamped with the current time
made every file an attacker had ever dropped come back looking brand new, all
at the same instant, on a box claiming weeks of uptime — so the original
mtimes ride along in the journal entries. Service state does the same thing:
`systemctl stop nginx` in one session is still stopped in the next, which is
what makes a persistence check believable.

## What it emulates

A Debian 13 (trixie) cloud image with nginx, MariaDB, PHP-FPM and cron
installed. That choice shows up everywhere: package versions, `/proc` and
`/sys` contents, systemd units, log rotation state, the exact wording of
error messages, and the two-decades-old quirks GNU tools have.

Concretely, `cat /etc/debian_version` says `13.6`, the kernel is
`6.12.101+deb13-cloud-amd64`, `nginx -v` says `1.26.3`, and `awk` is Debian's
default mawk rather than gawk — which matters, because a persona that claims
mawk and behaves like gawk is a contradiction of exactly the kind this whole
codebase exists to avoid.

It is a specific box, not a generic Linux. Every number above is a value
somebody measured on a real one; see [CONTRIBUTING.md](../CONTRIBUTING.md) for
why none of them may be written from memory.

## The cost

Two costs are worth naming rather than discovering.

The first is that coherence is quadratic in commands. Adding the 366th
command is not one unit of work, it is one unit of work plus checking it
against everything that already had an opinion about what it touched. That is
the reason the suites are structured as questions ("do these five commands
agree?") rather than as assertions ("does this command print this string?").

The second is that a published emulator is a detectable emulator: the quirks
the suites pin down are, from the other side, a signature. See
[embedding.md](embedding.md) before you deploy anything.
