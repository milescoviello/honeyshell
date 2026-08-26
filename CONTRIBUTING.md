# Contributing

## The rule that matters

A change is only finished when **every way of asking the same question gives
the same answer**. Adding a command is easy; the work is making sure it agrees
with the five other commands that already knew something about the thing it
touches.

So a patch that adds or changes behaviour wants a suite entry that asks the
coherence question, not just an assertion that the new output is what you
expected. `df` and `stat -f` reading from one accounting is worth more than
either of them being individually correct.
[docs/design.md](docs/design.md) sets out what that means in practice, with
the cases the emulator already holds together.

## Reference values come from a real box

Do not write an expected string from memory. Run the real command on a real
Debian 13 host and paste what it printed — including the column widths and the
trailing spaces, which are load-bearing more often than you would think.

Two ways to get this wrong that have both happened here:

- Measuring on a host that is not the target. The emulator claims a specific
  Debian; a value measured on Ubuntu or a Mac is a value for a different box.
- Measuring with the wrong tool. `resource.getrusage().ru_maxrss` is a
  high-water mark that never falls, so two consecutive measurements read as
  zero growth. Read `/proc/self/statm` if you want a current number.

## A suite can be wrong

Twice in this codebase a suite pinned *incorrect* behaviour as correct, and
the second time two different suites agreed with each other — both having
inherited the same unmeasured premise. Two suites agreeing is not evidence.
If a suite asserts something surprising, check what it was measured against
before you trust it.

## Before you send a patch

```sh
./run-suites.sh
```

On a Debian 13 host that should print `suites: 181   unexpected failures: 0
known: 1` — the one known failure is `awktest.py`, and
[docs/testing.md](docs/testing.md) says why it is tolerated by name rather
than skipped. Anything else failing is either your change or a host that is
not Debian 13; several suites diff against the host's own `bash` and
coreutils, so on another distribution they report the host's differences and
not the emulator's.

If your change makes an unrelated suite fail, that suite has probably just
told you something true.

## Style

Match the file you are editing. Comments in here explain *why* a thing is the
way it is, usually by naming the bug it fixes and what that bug cost — those
comments are the real documentation, so a patch that changes behaviour should
leave one behind.
