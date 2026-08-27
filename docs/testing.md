# Testing

There is more test than implementation here: 50,937 lines across 193 suites
against 44,474 lines of emulator. That ratio is the point, not an accident —
see [design.md](design.md) for why.

## Running them

```sh
./run-suites.sh                  # all of them; prints only failures
KNOWN_FAILURES= ./run-suites.sh  # ...and do not tolerate the known one
python3 -W ignore difftest.py    # just one
```

`run-suites.sh` runs every `*test*.py` plus `detect.py` and `probesuite.py`,
gives each one a 900-second timeout, prints nothing for a suite that passes,
and exits non-zero if any *unexpected* suite fails. The summary line at the
end is `suites: N   unexpected failures: N   known: N`.

It refuses to run twice at once, via `flock` on
`/tmp/honeyshell-suites.lock`. That is not politeness: the first thing it does
is delete `__pycache__` out from under anything already importing, and the
differential suites each build a temp tree that a concurrent run will race.

`SUITES.md` lists every suite and the single question it asks. It is generated
from the suites' own docstrings, so it cannot drift from them.

## Differential suites

Most of these suites are *differential*: they run the same input through this
emulator and through the host's real `bash` — and so through whatever real
coreutils, `awk`, `hexdump` or `stat` that bash then invokes — and diff the
two outputs. They do not compare against an expected string somebody typed;
they compare against what the real tool actually printed, here, now.

The consequence is that **the host has to be Debian 13** for the result to
mean anything. On anything else the diffs are the *host's* differences from
Debian, not the emulator's, and that is worse than not running them: it looks
like signal. A suite that cannot find its reference tool skips the affected
cases and says so, which is honest but tests nothing.

## CI

`.github/workflows/suites.yml` runs on `ubuntu-latest` but inside a
`debian:trixie` **container**, for exactly the reason above. The runner image
is a Ubuntu; the thing the suites diff against has to be the distribution the
emulator claims to be.

The container is bare, so the workflow installs the tools the diffs are
against before checking out: `gawk` (Debian's default `awk` is mawk),
`coreutils`, `procps`, `psmisc`, `libcap2-bin`, `util-linux`, `bsdextrautils`
for `hexdump`, `findutils`, `grep`, `sed`, `diffutils`, `file`, `dpkg`,
`tzdata`, and `wget` and `curl` so the cases that diff against them actually
run rather than skipping.

One of those is easy to lose and expensive to debug: `ca-certificates`. A bare
`debian:trixie` image has no CA store, and with `--no-install-recommends`
`git` does not pull one in, so `actions/checkout` fails with "Problem with the
SSL CA cert" before a single suite runs.

The job then prints its Python, awk, bash and `/etc/debian_version` versions
before running anything, so a diff that turns out to be the reference's fault
can be traced to which reference.

## The one known failure

`run-suites.sh` should report exactly **one** failure on a Debian host, and it
is a real difference rather than a flake:

- `awktest.py` — 89 of its 90 cases match the reference awk exactly. The one
  that does not is `gsub(/a/, "\\&")`: GNU awk leaves `banana` unchanged and
  warns, this emulator produces `b&n&n&`. Escaped-ampersand replacement is a
  corner of awk's substitution escaping that has not been worked through.

`run-suites.sh` tolerates that one **by name** and reports it as `KNOWN`, so
CI stays green without the failure being hidden. An unexpected failure still
turns the build red, and `KNOWN_FAILURES= ./run-suites.sh` tolerates nothing.
Skipping the suite instead would have hidden the other 89 cases it checks,
which is why it is listed rather than disabled.

`awktest.py`'s reference is whatever `awk` resolves to on `PATH`, and it
prints which one on its first line (`reference: ...`). On CI that is gawk,
because the workflow installs it. On a stock Debian box it is mawk, which is
also what this emulator's own package list claims — so the two are asking
slightly different questions, and the line the suite prints is how you know
which one you asked.

Anything else failing is either a genuine regression or a host that is not
Debian 13.
