# Embedding it

`fakeshell` is only the shell. Wiring it to a network listener, capturing what
arrives, and containing the host are all yours. Read
["Before you deploy it"](#before-you-deploy-it) at the bottom first — it is at
the bottom because it is what you should still be thinking about after you
have finished reading, not because it is optional.

## The smallest thing that works

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

## The constructor

```python
Shell(vfs=None, log=None, download=None, user="root", peer=None,
      peer_port=0, local_port=22, store=None, peer_fails=())
```

- **`vfs`** — a `VFS`, shared by every `Shell` that should see the same
  filesystem. Omit it and each shell gets its own, which means a file written
  in one channel is invisible in the next.
- **`log`** — called as `log(event="...", **fields)`. There are 69 distinct
  event names, covering downloads, payload writes, `su`/`passwd` attempts,
  cron installs, kills, unknown commands, blocked `awk system()` calls and so
  on. Default is a no-op, which throws away most of the value of running this.
- **`download`** — `callable(url) -> dict | None`, called when the attacker
  runs `wget`/`curl`. Returning `{"content": b"...", "sha256": ..., "size":
  ..., "path": "/abs/path"}` makes the emulator write the *real* fetched bytes
  into the VFS. That matters more than it sounds: droppers are staged, so the
  file just downloaded is usually a small shell stager the attacker then
  executes, and if you only kept a truncated head, running it loses the
  second-stage URL. Return `None` and the emulator fabricates a plausible ELF
  of a plausible size, which is enough to keep the session going and captures
  nothing.
- **`store`** — `callable(path, data, via) -> dict | None`, called for bytes
  that arrive in-band with no download and no sftp — a here-doc, a
  base64-decode, an `echo` into a file. Return a dict whose `stored` key says
  whether the bytes were actually kept: a store that was full still returns a
  dict, and reading truthiness off the object rather than off that flag logged
  `stored=true` for an artifact that had been thrown away.
- **`user`** — the account the session is running as. Drives `id`, the prompt
  variables, `$HOME`, and every capability and permission answer.
- **`peer`, `peer_port`, `local_port`** — the connection, as seen by `w`,
  `last`, `who`, `$SSH_CONNECTION`, `$SSH_CLIENT` and `netstat`. `peer`
  defaults to an RFC1918 placeholder; leaving all three empty is both a tell
  and a lost opportunity, since an attacker's own tooling often reads
  `$SSH_CONNECTION` to learn which address it came in on.
- **`peer_fails`** — what this source got wrong on the way in, as
  `(timestamp, username, invalid_user, client_port)` tuples from your SSH
  layer. They are written into `/var/log/btmp` and `/var/log/auth.log`, so
  `lastb` and `grep "Failed password"` agree with what actually happened at
  the door. Without them, a box that refused this caller 320 times before
  letting them in has no record of it, and an attacker checking what the
  machine knows about their own break-in finds nothing.

## `run()`

```python
out = sh.run(script, stdin="")
```

Takes a script fragment, returns combined stdout as a string. `stdin` is
forwarded so a subshell used as a pipeline stage still receives piped data.
Exit status is on `sh.last_rc`.

Two attributes the listener owns:

- **`sh.exec_mode`** — set it `True` for a non-interactive session, i.e. every
  `ssh host '<cmd>'`. Non-interactive bash prefixes errors with the physical
  line number and interactive bash does not, and getting that backwards is
  visible in one malformed command.
- **`sh.term`, `sh.cols`, `sh.rows`** — assign these from the pty-req. They
  default to `xterm`/80/24 and every "how wide is this terminal" answer reads
  them.

There is no prompt renderer here. `PS1` is an ordinary shell variable; drawing
the prompt, echoing input and framing the session belong to your listener.

## The VFS and threading

One `VFS` can be shared by several `Shell`s on several threads — which is what
an SSH connection carrying multiple channels gives you. Construction is
serialised on a lock held by the VFS, and the node table is snapshotted before
it is walked.

That was not true until `concurtest.py` was written. Two constructors racing
raised `RuntimeError: dictionary changed size during iteration` and killed the
whole session thread, so the transport went down while the request handler
went on logging execs that never ran — the capture said we ran it and the box
had already gone. Even when it did not crash, the block accounting
double-counted: measured, 24 concurrent constructions put the base block count
between 95938 and 109772 where the sequential answer is 95917, so `df`'s used
figure drifted upward with nobody having written anything.

The contract, then: share one `VFS` across the channels of one connection,
give a different source address a different `VFS`, and do not reach into
`vfs.nodes` from your own threads.

## Persistence across reconnects

A box that forgets what an attacker did contradicts itself the moment they
come back. The VFS journals the delta — writes, deletes, chmods, links, killed
pids, stopped units — and only the delta, because the baseline tree is
regenerated from code.

```python
entries = vfs.dump_journal()      # JSON-serialisable; file bytes are base64
...
vfs = fakeshell.VFS()
vfs.load_journal(entries)         # replay onto a fresh baseline
```

Replay does not re-journal, so reloading repeatedly cannot make the journal
grow. Original mtimes ride along in the entries, so a file the attacker
dropped last week comes back dated last week rather than dated to the moment
of the reload — which was the bug that made a plain write less durable than a
`touch -d` backdate.

## Containment

This code assumes it runs on a machine you have already decided you are
willing to lose. Nothing in here executes anything: no `subprocess`, no
`exec`, no shell, and the fetched bytes of a payload are written into a Python
dict, not onto your disk, unless your own `download` or `store` callable puts
them there. That is the emulator's whole safety story, and it stops at the
edge of this module — the listener, the payload store, and whatever network
the box can reach are yours to isolate.

## Before you deploy it

- **The persona is generic here.** A plain hostname, an `example.net` FQDN, a
  plausible but invented site — all of it sitting in constants at the top of
  `fakeshell.py`. If you deploy it unchanged, its fingerprint is the same as
  everybody else's who did. Change the hostname, the domain, the package set
  and the file tree.
- **A published emulator is a detectable emulator.** The quirks the suites
  pin down are, from the other side, a signature. That is the cost of
  publishing this, and it is worth being clear-eyed that the cost is real.

The second one has no fix, only a choice. The first one does have a fix and it
takes an afternoon, so there is no excuse for shipping the defaults.
