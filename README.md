# honeyshell — a Debian 13 shell emulator, and the test suite that proves it

A shell emulator faithful enough to put behind an SSH honeypot, with **187
test suites** that check it against the real thing rather than against
expectations written by hand.

Nothing it runs is real. There is no subprocess, no `exec`, no shell. Every
command is Python over an in-memory filesystem, so an attacker's `rm -rf /`
rearranges a dictionary.

```python
import fakeshell

sh = fakeshell.Shell()
print(sh.run("uname -r"))
# 6.12.101+deb13-cloud-amd64

print(sh.run("df -h / | tail -1"))
# /dev/sda1        63G  4.1G   56G   7% /

sh.run("echo 'payload' > /tmp/x; chmod 4755 /tmp/x")
print(sh.run("find /tmp -perm -4000 -type f"))
# /tmp/x
```

A honeypot is rarely detected because it is missing a command. It is detected
because it **contradicts itself**. So the design rule here is not "implement
more commands", it is **every way of asking a question must give the same
answer** — see [docs/design.md](docs/design.md) for what that costs and what
it buys.

| | |
|---|---:|
| Emulator | 43,123 lines |
| Commands | 349 |
| Suites | 187 |
| Test code | 49,857 lines |

Command count is `cmd_*` entry points on `Shell` — 348 `def cmd_` definitions
plus 17 aliases such as `cmd_mawk = cmd_awk`; dispatch is
`getattr(self, "cmd_" + name.replace("-", "_"))`, so that attribute count is
the set of names the shell answers to. Count it yourself with
`len([a for a in dir(fakeshell.Shell) if a.startswith("cmd_")])`. Line counts
are plain `wc -l`, suites are what `./run-suites.sh` runs; both move with
every sweep, so treat them as the size of the thing rather than a constant.

## What is in here

| File | Lines | Job |
|---|---:|---|
| `fakeshell.py` | 43,123 | The emulator: the VFS, the shell language, and every command |
| `awkemu.py` | 1,358 | awk — attackers pipe nearly everything through it |
| `localedb.py` | 1,164 | Locale data, so `LC_ALL=` actually changes what commands print |
| `sedemu.py` | 792 | sed |
| `netbase.py` | 559 | `/etc/services`, protocols, rpc, ethertypes — whole files, not samples |
| `tzdb.py` | 536 | Timezone data |
| `skeldb.py` | 29 | `/etc/skel` |

`SUITES.md` lists all 187 suites and the one question each asks. It is
generated from the suites' own docstrings, so it cannot drift from them.

```sh
./run-suites.sh                  # all of them; prints only failures
python3 -W ignore difftest.py    # just one
```

## Documentation

- [docs/design.md](docs/design.md) — why self-consistency is the design rule,
  with the concrete cases, and what the emulated box actually is.
- [docs/embedding.md](docs/embedding.md) — using `fakeshell.Shell` in your own
  listener: the constructor, the VFS and threading contract, persistence
  across reconnects, the log stream, and the deployment warnings.
- [docs/testing.md](docs/testing.md) — running the suites, why CI uses a
  `debian:trixie` container, what "differential" means here, and the one
  known failure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — the bar a patch has to clear.

## Before you deploy it

Both of these are repeated in [docs/embedding.md](docs/embedding.md), because
they are the two things most likely to be skipped and most expensive to skip.

- **The persona is generic here.** A plain hostname, an `example.net` FQDN, a
  plausible but invented site — all of it sitting in constants at the top of
  `fakeshell.py`. If you deploy it unchanged, its fingerprint is the same as
  everybody else's who did. Change the hostname, the domain, the package set
  and the file tree.
- **A published emulator is a detectable emulator.** The quirks the suites
  pin down are, from the other side, a signature. That is the cost of
  publishing this, and it is worth being clear-eyed that the cost is real.

`fakeshell` is only the shell. Wiring it to a network listener, capturing what
arrives, and containing the host are all yours — and the containment is the
part to take seriously. This code assumes it runs on a machine you have
already decided you are willing to lose.

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
