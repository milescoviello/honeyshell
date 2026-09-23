# Changelog

Each entry is a question the emulator used to answer inconsistently, and every
fix is pinned by a suite. The full list of suites, one line each, is in
[SUITES.md](SUITES.md).

## v0.2.0 — 2026-09-23

| | v0.1.0 | v0.2.0 |
|---|---:|---:|
| Suites | 140 | 237 |
| Emulator | 36,854 lines | 60,213 lines |
| Commands | 347 | 378 |
| Known failures tolerated by CI | 1 | 1 |

### Testing

- **awk's escaped-ampersand case is fixed.** `awktest.py`, v0.1.0's one
  tolerated failure, now reports 97/97 against the reference awk and 47/47
  against mawk 1.3.4, and CI no longer tolerates it.
- **One suite is newly declared.** `scripttest.py` differs from Python 3.13.5
  in three of 423 cases, all traceback formatting for an uncaught exception
  under `python3 -c`. It is listed by name in `run-suites.sh` and explained in
  [docs/testing.md](docs/testing.md); every other failure still fails CI.
- **The README's examples are run.** `readmetest.py` executes every Python
  block in it and requires each `print()` to produce the output written
  beneath it, whole. Nothing had checked them before, and one had drifted:
  v0.1.0's `df` example described the disk of an earlier persona.

### What a binary is

- **`file` reads the file.** It used to answer every ELF with one canned
  string, so a static 32-bit i386 binary was described as a 64-bit dynamically
  linked PIE, and every stock binary reported the same BuildID while
  `sha256sum` said they differed. It now reads class, machine, type, linkage,
  interpreter, build id, ABI tag and symbol table from the header, and
  separates a PIE from a shared object by `DF_1_PIE` the way `file` does.
  Measured against `file` 5.46 on a real Debian 13 box: 211 of 217 paths
  byte-identical.
- **A dropped binary is its bytes, not its filename.** An uploaded file named
  `sshd` or `ls` no longer answers as that program.
- **Installable tools answer `--version`** with the text the Debian package
  prints, and agree with `dpkg` about the version. `--help` is measured for the
  96 coreutils programs that have one, and for the interpreters and downloaders.
- Packages and the filesystem reconcile: `dpkg -L`, `dpkg -V`, merged-`/usr`,
  held packages, shared-library ownership, and binaries that were replaced or
  deleted and have to stay that way.

### Persistence surfaces

The places an intruder writes to stay on a box, and the commands that show
them, now agree with each other: cron (including `crontab`'s refusals and
cron's own log), systemd system and `--user` units and the `systemctl` verbs
that inspect them, apt hooks, `/etc/rc.local`, `/etc/profile.d`, udev rules,
`sudoers`, password aging, `chattr +i` on files and directories, and `sshd -T`
against the config it claims to describe.

### Describing the machine

Hardware, storage and devices answer the same question the same way across
every reader: CPU topology and `/sys/devices/system/cpu`, block queues and the
`lsblk` columns that read them, partition UUIDs, `lspci` and `pci.ids`,
virtualisation hints, `/proc/sys` in full, disk usage including running out of
space, and the journal's own size against the disk's.

### Processes

`/proc/<pid>` agrees with `ps`, and `ps` has both its personalities (BSD and
UNIX options). Start times, threads, CPU use, memory maps, locks and the files
a process holds open are consistent across readers. `lsof` is absent until it
is installed, as on stock Debian, and once installed its columns and inodes
agree with `stat`.

### The shell language

`exit` ends the shell from inside loops, branches, `case` and functions; a
malformed line runs none of itself rather than its good half; `PS2` continuation
behaves like bash's; `$?` and `${PIPESTATUS[@]}` agree; operators inside quotes
stay inside quotes; file-descriptor redirections, `VAR=value cmd` prefixes,
`trap`, `nohup`, redirects at directories and the no-terminal case all match
bash.

### Networking and logs

Routes, the neighbour table, interface state and unix sockets have one source
each, read four ways. journald and rsyslog are two stores, messages go where
the box's rsyslog config says, and log rotation times agree everywhere they are
recorded.

## v0.1.0 — 2026-08-24

First public release: the emulator, 140 differential suites, and the
documentation in `docs/`.
