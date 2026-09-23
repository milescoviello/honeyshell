#!/usr/bin/env python3
"""Materialise the emulator's /proc as a real directory tree.

Why this exists: htop and btop are the two commands where a hand-written
imitation is most obviously an imitation. Rather than keep reimplementing
their rendering, we run the *real* binaries and point them at a real
directory holding this box's fake /proc. Everything they draw -- the
meter layout, the column widths, the footer, the colours -- is then
whatever the actual program does, because it is the actual program.

Two things a naive dump gets wrong, both found by running real htop
against one:

  * htop reads ``task/<tid>/stat`` under every pid. Without those the
    process list is empty and it prints "Tasks: 0".
  * htop takes a process's owner from ``stat()`` on the /proc/<pid>
    directory, not from the Uid line in status. A tree written by one
    user therefore shows every process as that user. The uid map written
    here is applied by the LD_PRELOAD shim.

And one that only shows up over time: CPU% is a delta between two reads,
so a frozen snapshot renders "N/A" forever. refresh() rewrites the files
that move.
"""

import hashlib
import os
import shutil
import time

#: Files that have to be rewritten for a second read to differ.
DYNAMIC = ("/proc/stat", "/proc/loadavg", "/proc/uptime", "/proc/meminfo",
           "/proc/diskstats", "/proc/net/dev")

#: What we export. /proc is the point; the passwd files are how htop and
#: btop turn a uid into a name; /sys is what btop and fastfetch read for
#: disks, network and GPUs, and os-release is what fastfetch calls the OS.
ROOTS = ("/proc", "/etc/passwd", "/etc/group", "/etc/os-release",
         # /etc/os-release is a symlink to this on Debian, and exporting
         # the link without its target left it dangling -- so fastfetch
         # fell through to the *host's* os-release and announced whatever
         # the machine running the honeypot happens to be. On a laptop
         # that reads "Ubuntu 24.04.4 LTS" above a Debian kernel, an
         # Ubuntu logo, and Yaru themes; on the guest it is masked only
         # because the guest is Debian 13 too, which is the worst kind of
         # bug -- correct by coincidence on the one box anyone checks.
         "/usr/lib/os-release",
         # What lsb_release and a dozen scripts fall back to.
         "/etc/debian_version",
         # fastfetch fills its Shell line by resolving the parent's exe
         # link and grepping that binary for "@(#)Bash version". Measured
         # with strace: readlink("/proc/<ppid>/exe") -> "/usr/bin/bash",
         # then openat("/usr/bin/bash"). With nothing here, the only bash
         # it could open was the *host's*, so the honeypot reported the
         # bash of whatever machine it runs on. Right on the guest purely
         # because the guest is also 5.2.37 -- the same coincidence that
         # hid the os-release bug in sweep 241.
         "/usr/bin/bash",
         "/etc/hostname", "/etc/machine-id")



#: Exported once. /sys is thirteen thousand nodes and almost none of it
#: moves, so re-writing it per session would cost seconds for nothing.
STATIC_ROOTS = ("/sys", "/var/lib/dpkg")


def _read(shell, path):
    """The live contents, not the cached node.

    vfs.read() returns whatever was seeded at construction. The moving
    files -- /proc/stat, /proc/<pid>/stat and friends -- are produced by
    the Shell's _dynamic()/_proc_dynamic(), whose own docstring says "a
    frozen /proc/<pid>/stat is as good as a confession". Exporting
    through the VFS froze exactly those, so a refresh rewrote identical
    bytes and every process read 0.0% CPU forever.
    """
    # rawfs first, then the wrapper, then the shell. _dynamic() lives on
    # the VFS, and for a non-root session shell.fs is a CredFS *wrapping*
    # rawfs -- a different object, which is the same trap fakeshell's own
    # comment flags where it sets _net_stats_fn on rawfs rather than fs.
    # `shell._dynamic` does not exist at all: the attribute error was
    # caught here and the read fell through to the seeded node, silently.
    # So every file that is purely generated -- /proc/net/dev, and the
    # sysfs counters derived from it -- exported one frozen snapshot and
    # never moved again, while files that a sync_*() writes into the node
    # kept working. That is why /proc/stat looked fine and the network
    # graph was a flat line.
    for owner in (getattr(shell, "rawfs", None), getattr(shell, "fs", None),
                  shell):
        if owner is None:
            continue
        fn = getattr(owner, "_dynamic", None)
        if fn is None:
            continue
        try:
            d = fn(path)
        except Exception:                                      # noqa: BLE001
            continue
        if d is not None:
            return d
    return shell.fs.read(path)


def _symlink(real, target):
    """Recreate a symlink in the export.

    The exporter only ever wrote files and directories, so every link in
    the VFS was silently dropped -- /sys/bus/pci/devices/<bdf> and
    /sys/class/drm/cardN/device among them. Those two are exactly the
    path fastfetch follows to find a graphics card, so a box with eight
    of them reported none.
    """
    try:
        os.makedirs(os.path.dirname(real), exist_ok=True)
        if os.path.islink(real) or os.path.exists(real):
            if os.path.islink(real) and os.readlink(real) == target:
                return
            try:
                os.unlink(real)
            except OSError:
                return
        os.symlink(target, real)
    except OSError:
        pass


#: Export paths this process could not write, and how many times. An
#: export that cannot write a file used to return silently, and the cost of
#: that was measured rather than imagined: 133 files under
#: /var/lib/honeypot/fakeroot/proc/<pid>/ were left owned by root:root by a
#: session that ran the exporter as root on 2026-08-30, and the service runs
#: as `honey`. Every export since skipped them on EACCES and said nothing,
#: so /proc/4100/stat -- the shell's own -- sat two days stale, and
#: `fastfetch --format json` reported a parent pid that `ps` in the same
#: session disagreed with. A write that silently does nothing is the same
#: shape as the deploy guard that could not fail: it reads as protection.
_unwritable = {}
_UNWRITABLE_REPORT_EVERY = 200


def _note_unwritable(path, exc):
    """Record a failed export write and say so, rarely enough to be read."""
    n = _unwritable.get(path, 0) + 1
    _unwritable[path] = n
    if n == 1 or n % _UNWRITABLE_REPORT_EVERY == 0:
        try:
            import sys as _sys
            print("procexport: cannot write %s: %s (%d time%s)"
                  % (path, exc, n, "" if n == 1 else "s"),
                  file=_sys.stderr, flush=True)
        except Exception:                                      # noqa: BLE001
            pass


def unwritable():
    """{path: failure count} for anything this process could not export."""
    return dict(_unwritable)


def _write(real, data, atomic=False):
    """Write a file, optionally by rename so no reader sees it half done.

    The refresher rewrites /proc/stat and friends underneath a running
    htop or btop. Opening for truncation means a reader can catch the
    file empty or partial, which is exactly what happened:

        ERROR: ... Cpu::collect() : Failed to parse /proc/stat
        ERROR: ... Mem:: -> Failed to get uptime from /proc/uptime

    A rename is atomic within a filesystem, so a reader sees either the
    old contents or the new ones and never a torn file.
    """
    os.makedirs(os.path.dirname(real), exist_ok=True)
    blob = data if isinstance(data, bytes) else str(data).encode()
    if not atomic:
        try:
            with open(real, "wb") as fh:
                fh.write(blob)
        except OSError as exc:
            _note_unwritable(real, exc)
            return False
        return True
    # In place, in one write, keeping the inode -- not a rename.
    #
    # The rename this replaces did stop the torn reads, but it swapped in
    # a new inode every refresh, and a reader holding the old fd then
    # never saw another byte. procps does exactly that: it opens
    # /proc/stat once and rewinds it forever after. Measured with strace
    # over four sampling cycles -- /proc/<pid>/stat opened 5x each,
    # /proc/uptime 14x, /proc/stat exactly once. So top's CPU summary was
    # computed from the same two numbers for the life of the session and
    # came out as a flat "%Cpu(s): 0.0 us, 100.0 id" printed directly
    # above three of its own rows reading 388%, 220% and 96%. One screen
    # contradicting itself, which is the whole thing we are trying not to
    # do. htop and btop were unaffected only because they re-open.
    #
    # A held fd seeing stale data is also just wrong about procfs, where
    # the file has no stored contents at all: it is generated per read,
    # so a rewind on a held fd always yields current values.
    #
    # O_TRUNC is what caused the torn reads in the first place -- it left
    # the file zero-length for as long as it took to write it, and btop
    # caught it there ("Failed to parse /proc/stat"). Opening without it
    # and writing the whole buffer in a single write() never exposes an
    # empty file: a reader gets either the previous contents or the new
    # ones, because a write to a regular file holds the inode lock that
    # a read takes shared.
    try:
        fd = os.open(real, os.O_WRONLY | os.O_CREAT, 0o644)
    except OSError as exc:
        _note_unwritable(real, exc)
        return False
    try:
        n = os.write(fd, blob)
        # A short write would tear. It cannot happen for a buffer this
        # size on a regular file, but if it ever did, finishing the job
        # matters more than the tear we already have.
        while n < len(blob):
            n += os.write(fd, blob[n:])
        # Only when the new contents are shorter, so the common case --
        # counters gaining digits, never losing them -- does not pay it.
        if os.fstat(fd).st_size > len(blob):
            os.ftruncate(fd, len(blob))
    except OSError as exc:
        _note_unwritable(real, exc)
        os.close(fd)
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return True


def export(shell, root):
    """Write the shell's /proc under `root`. Returns the file count."""
    vfs = shell.fs
    # Touch the generated files first: several of them only exist once
    # something has asked for them.
    for probe in DYNAMIC + ("/proc/cpuinfo", "/proc/self/stat",
                            "/proc/version", "/proc/mounts", "/proc/swaps"):
        _read(shell, probe)

    n = 0
    for path, node in list(vfs.node_items()):
        if not any(path == r or path.startswith(r.rstrip("/") + "/")
                   or path == r.rstrip("/") for r in ROOTS):
            continue
        real = root + path
        try:
            link = getattr(node, "link", None)
            if link:
                _symlink(real, link)
                n += 1
                continue
            if getattr(node, "is_dir", False):
                os.makedirs(real, exist_ok=True)
                continue
            data = _read(shell, path)
            if data is None:
                continue
            _write(real, data)
            n += 1
        except OSError:
            continue

    # /etc/mtab, as a real file rather than the symlink it is on a live
    # box. btop prefers it over /proc/self/mounts when it exists -- and
    # it exists on the guest -- so with it absent from the export btop
    # read the *guest's* mount table and showed two filesystems on a box
    # whose df lists a root, an ESP and a 28 T shard volume.
    _mounts = _read(shell, "/proc/mounts")
    if _mounts:
        try:
            _write(root + "/etc/mtab", _mounts, atomic=True)
            n += 1
        except OSError:
            pass

    # /etc/fstab. btop ships use_fstab = True, and with it on btop builds
    # its disk list *only* from fstab -- mtab is just intersected against
    # it, and a mount absent from fstab is dropped before statvfs is ever
    # called, so nothing is logged. With the export missing, btop read the
    # guest's own fstab and drew that box's two entries; /data was never a
    # space or ordering problem, it was never in the list.
    _fstab = _read(shell, "/etc/fstab")
    if _fstab:
        try:
            _write(root + "/etc/fstab", _fstab, atomic=True)
            n += 1
        except OSError:
            pass

    # Also on the first export, not only on refresh: fastfetch runs with
    # wants_pty False, so no refresher thread ever starts for it. Without
    # this the interface file did not exist for the one tool that prints
    # "Local IP", and getifaddrs -- correctly failing closed -- reported
    # no interfaces at all, so the line simply vanished.
    _export_sysfs_counters(shell, root)

    _prune_dead_pids(shell, root)

    n += _export_tasks(shell, root)
    _export_uidmap(shell, root)
    _export_dfmap(shell, root)
    _export_devmap(shell, root)
    export_gpumap(shell, root)
    return n


def export_static(shell, root):
    """/sys, written once. Returns the file count, or 0 if already there."""
    # Versioned: the marker is what makes this cheap, but it also made
    # the tree stick at whatever the first export produced. Adding /sys
    # PCI nodes and /var/lib/dpkg changed nothing on a box that had
    # already exported once.
    # The marker carries the CPU count, so any change to it forces the tree
    # to be rebuilt. /sys is written once because it is thirteen thousand
    # nodes that almost never move -- but some of them are derived from
    # NCPU, and when the persona went from 192 CPUs to 64 the file
    # /sys/devices/system/cpu/online kept saying 0-191. htop counts CPUs
    # from exactly that file, and above 128 it deliberately draws a single
    # average meter instead of one per core, so htop showed one "Avg" bar
    # on a box whose every other reader said 64. A version bump alone would
    # have fixed it once; keying the marker to the count fixes it whenever
    # it changes.
    # Keyed on the content that determines the tree, not on one number
    # out of it. The CPU count was the only input in the key, so the DMI
    # table could change from i440FX to q35 and the PCI table could gain
    # nine root ports and this function would still return 0 and leave the
    # old tree in place -- which is exactly what happened: /sys/class/dmi
    # said Q35 while the exported copy fastfetch reads still said
    # "Standard PC (i440FX + PIIX, 1996)", so the two disagreed about what
    # machine this is. Hashing the inputs means any future change to them
    # rebuilds the tree without anyone having to remember to bump a
    # version, which the comment above had already had to do once.
    #
    # Third time for this shape, so key the two roots by what each one is
    # actually made of. /sys is 7,418 nodes generated from NCPU, DMI and
    # PCI, so hashing those inputs covers it and digesting the tree every
    # start would not be worth it. /var/lib/dpkg is 96 nodes and its
    # inputs are *data*, not hardware -- so it is hashed by content.
    # Without that, adding four packages rewrote /var/lib/dpkg/status and
    # changed nothing in the key: the exported copy the real fastfetch
    # reads went on reporting 186 packages while `dpkg -l` on the same box
    # said 190, which is two readers and one question.
    try:
        import fakeshell as _fsmod
        _ncpu = int(_fsmod.NCPU)
        _dpkg = hashlib.sha256()
        for _p in sorted(_pth for _pth, _ in shell.fs.node_items()
                         if _pth == "/var/lib/dpkg"
                         or _pth.startswith("/var/lib/dpkg/")):
            _dpkg.update(_p.encode("utf-8", "replace"))
            _d = _read(shell, _p)
            if _d is not None:
                _dpkg.update(_d if isinstance(_d, bytes)
                             else str(_d).encode("utf-8", "replace"))
        _sig = hashlib.sha256(
            repr((sorted(_fsmod.VFS.DMI.items()),
                  _fsmod.PCI_DEVICES,
                  _dpkg.hexdigest())).encode()).hexdigest()[:12]
    except Exception:                                          # noqa: BLE001
        _ncpu, _sig = 0, "nosig"
    marker = root + "/.static-done-v5-%d-%s" % (_ncpu, _sig)
    if os.path.exists(marker):
        return 0
    # Rebuilding means replacing, not overlaying. This function only ever
    # wrote, so when the CPU count changed the range files were rewritten to
    # 0-63 while cpu64..cpu191 stayed on disk -- and htop counts the cpuN
    # directories, saw 192, and drew a single average meter because above
    # 128 CPUs it will not draw one bar per core. Same shape as the pid
    # directories that were never reaped: an artefact outliving the fact it
    # came from.
    for _stale in ("sys", "var/lib/dpkg"):
        _p = os.path.join(root, _stale)
        if os.path.isdir(_p):
            shutil.rmtree(_p, ignore_errors=True)
    for _old in os.listdir(root) if os.path.isdir(root) else []:
        if _old.startswith(".static-done-"):
            try:
                os.unlink(os.path.join(root, _old))
            except OSError:
                pass
    n = 0
    for path, node in list(shell.fs.node_items()):
        if not any(path == r or path.startswith(r + "/")
                   for r in STATIC_ROOTS):
            continue
        real = root + path
        try:
            link = getattr(node, "link", None)
            if link:
                _symlink(real, link)
                n += 1
                continue
            if getattr(node, "is_dir", False):
                os.makedirs(real, exist_ok=True)
                continue
            data = _read(shell, path)
            if data is None:
                continue
            _write(real, data)
            n += 1
        except OSError:
            continue
    _write(marker, str(time.time()))
    return n


def _export_devmap(shell, root):
    """"/dev/<name> major minor" per block device.

    fastfetch decides a mount is real by stat()ing its device node and
    checking S_ISBLK. /dev/nvme0n1p1 does not exist on the guest, so the
    28 T shard volume was filtered out as "not a physical device" and
    only the root filesystem was listed. The shim answers stat for these
    paths from this table.
    """
    rows = []
    try:
        import fakeshell
        for maj, mnr, _blocks, name in fakeshell._partition_table():
            rows.append("/dev/%s %d %d" % (name, maj, mnr))
    except Exception:                                          # noqa: BLE001
        pass
    _write(root + "/.devmap", "\n".join(rows) + "\n", atomic=True)


def _export_dfmap(shell, root):
    """"mountpoint total used avail" in 1K blocks, for the shim's statvfs.

    fastfetch and btop do not read df: they statvfs each mount point, so
    without this they report the host's real root filesystem under the
    persona's mount table.
    """
    rows = []
    try:
        # _FILESYSTEMS is the table as the box booted. It does not include
        # what this session has written, and the shell's own `df` does --
        # so an attacker who uploaded a 400 MB payload saw `df` move by
        # exactly 409600 KB while btop, fastfetch and the real df binary,
        # all of which reach statvfs through this file, did not move at
        # all. Measured on the guest:
        #     baseline           shell 402653592   statvfs 402653184
        #     after 400 MB       shell 403063192   statvfs 402653184
        # The write was invisible to every statvfs caller on the box.
        #
        # root_space() is the expression the shell's df already uses, so
        # taking it from there rather than re-deriving it means the two
        # cannot drift again.
        import fakeshell as _fs
        try:
            _blocks, _rused, _rfree, _ravail = _fs.root_space(
                getattr(shell, "rawfs", None) or shell.fs)
        except Exception:                                      # noqa: BLE001
            _blocks = _rused = _ravail = None
        for dev, mnt, _fstype, total, used, avail in shell._FILESYSTEMS:
            if mnt == "/" and _blocks:
                total, used, avail = _blocks, _rused, _ravail
            rows.append("%s %d %d %d" % (mnt, total, used, avail))
    except Exception:                                          # noqa: BLE001
        pass
    # Atomic. The refresher rewrites this underneath a running btop, and
    # fake_statvfs falls back to the *real* statvfs when it cannot parse a
    # line -- so a torn read does not degrade gracefully, it shows the
    # attacker the host's own filesystem.
    _write(root + "/.dfmap", "\n".join(rows) + "\n", atomic=True)


def _export_tasks(shell, root):
    """task/<tid>/ for every process, which is where htop looks.

    Thread ids are allocated from one counter above the highest pid, the
    way the kernel hands them out of the same number space. Deriving them
    as ``pid + 1000 + k`` collided: pid 21428's eighth thread and pid
    21435's first were both tid 22435, each with different contents, and
    htop read the collision as a process of its own using 2400% of the
    CPU under whichever user happened to own the directory.
    """
    n = 0
    pids = sorted(int(p.split("/")[2]) for p, _ in shell.fs.node_items()
                  if p.count("/") == 2 and p.startswith("/proc/")
                  and p.split("/")[2].isdigit())
    next_tid = [max(pids) + 1 if pids else 1000]
    taken = set(pids)
    thread_owner = []

    def alloc():
        while next_tid[0] in taken:
            next_tid[0] += 1
        taken.add(next_tid[0])
        return next_tid[0]

    # One pass to learn how many threads each process claims, then one
    # allocation for the whole box, so the ids do not depend on the order
    # the VFS happened to yield.
    _counts = []
    for _p, _n in list(shell.fs.node_items()):
        _parts = _p.split("/")
        if len(_parts) != 3 or _parts[1] != "proc" or not _parts[2].isdigit():
            continue
        _pid = int(_parts[2])
        _nt = 1
        _st = _read(shell, "/proc/%d/status" % _pid) or b""
        for _line in _st.decode("latin-1").splitlines():
            if _line.startswith("Threads:"):
                _nt = max(1, int(_line.split()[1]))
                break
        _counts.append((_pid, _nt))
    try:
        import fakeshell as _fsmod
        _TIDS = _fsmod.tid_map(_counts)
    except Exception:                                          # noqa: BLE001
        _TIDS = {}

    for path, _node in list(shell.fs.node_items()):
        parts = path.split("/")
        if len(parts) != 3 or parts[1] != "proc" or not parts[2].isdigit():
            continue
        pid = int(parts[2])
        base = "%s/proc/%d" % (root, pid)
        if not os.path.isdir(base):
            continue
        try:
            nthr = 1
            st = _read(shell, "/proc/%d/status" % pid) or b""
            for line in st.decode("latin-1").splitlines():
                if line.startswith("Threads:"):
                    nthr = max(1, int(line.split()[1]))
                    break
            # From fakeshell.tid_map, not a local counter: this allocator
            # walked the VFS in whatever order it yielded, so the ids were
            # not reproducible and `ps -L` could not have named the same
            # threads /proc/<pid>/task holds. One function, both readers.
            tids = _TIDS.get(pid) or ([pid] + [alloc()
                                               for _ in range(nthr - 1)])
            thread_owner.extend((t, pid) for t in tids)
            # Remove the tids this process no longer claims. This loop only
            # ever created directories, so when a thread count changed --
            # or the allocation shifted because some other process's did --
            # the old ones stayed. Measured on the live guest: the export
            # held 584 task directories against the VFS's 565, and the
            # extras were a strict superset, e.g. pid 21428 offering 16
            # where `ps -o nlwp`, `/proc/21428/status` and `ls
            # /proc/21428/task` all said 9. htop reads the export, so htop
            # was listing threads that did not exist anywhere else on the
            # box.
            #
            # Same shape as the stale cpuN directories in sweep 223 and the
            # dead pid directories before them: a writer with no matching
            # remover, and an artefact outliving the fact it came from.
            _keep = {str(t) for t in tids}
            _taskdir = "%s/task" % base
            try:
                for _old in os.listdir(_taskdir):
                    if _old not in _keep:
                        shutil.rmtree(os.path.join(_taskdir, _old),
                                      ignore_errors=True)
            except OSError:
                pass
            for tid in tids:
                td = "%s/task/%d" % (base, tid)
                os.makedirs(td, exist_ok=True)
                for fn in ("stat", "statm", "status", "cmdline", "comm",
                           "io", "wchan"):
                    src = "%s/%s" % (base, fn)
                    if not os.path.exists(src):
                        continue
                    with open(src, "rb") as fh:
                        data = fh.read()
                    if fn == "stat" and tid != pid:
                        head, _, tail = data.partition(b" ")
                        data = str(tid).encode() + b" " + tail
                    _write("%s/%s" % (td, fn), data)
                n += 1
        except (OSError, ValueError):
            continue
    # Threads inherit their process's owner, so the shim can stamp them
    # too rather than falling back to whoever wrote the tree.
    _write(root + "/.tidmap",
           "\n".join("%d %d" % t for t in thread_owner) + "\n")
    return n


def _export_uidmap(shell, root):
    """"pid uid gid" per line, for the shim to stamp onto stat()."""
    names = {}
    for line in (shell.fs.read("/etc/passwd") or b"").decode(
            "latin-1").splitlines():
        f = line.split(":")
        if len(f) > 3:
            names[f[0]] = (f[2], f[3])
    rows = []
    for p in shell._all_procs():
        user, pid = p[0], p[1]
        uid, gid = names.get(user, ("0", "0"))
        rows.append("%d %s %s" % (pid, uid, gid))
    _write(root + "/.uidmap", "\n".join(rows) + "\n")


#: How often the slow half of a refresh is worth doing. btop can be told
#: to sample every 100 ms and that is what it should get, so the fast
#: path has to cost far less than that -- rebuilding the whole process
#: table each tick costs about 11 ms on the build host and several times
#: that on the guest's two cores.
FULL_EVERY = 2.0
_last_full = [0.0]


def export_gpumap(shell, root):
    """The GPUs, in the form the stub NVML library reads.

    btop and fastfetch ask NVML for graphics cards, not /proc or /sys, so
    a box with no driver shows no GPU however complete its sysfs is. The
    numbers here come from the same _gpu_state() nvidia-smi renders, so
    the card in btop and the card in nvidia-smi cannot disagree.
    """
    try:
        import nvidia
    except Exception:                                          # noqa: BLE001
        return
    rows = []
    for i in range(getattr(nvidia, "GPU_COUNT", 0)):
        try:
            g = shell._gpu_state(i)
        except Exception:                                      # noqa: BLE001
            continue
        util = int(g.get("util", 0))
        # Clocks follow load, the way a real card boosts.
        gclk = int(getattr(nvidia, "GPU_MAX_GRAPHICS_MHZ", 2947)
                   * (0.35 + 0.65 * util / 100.0))
        mclk = getattr(nvidia, "GPU_MAX_MEM_MHZ", 14001)
        pstate = int(str(g.get("perf", "P0")).lstrip("Pp") or 0)
        rows.append("%d %d %d %d %d %d %d %d %d %s"
                    % (int(g.get("used", 0)), int(g.get("total", 0)),
                       util, int(g.get("temp", 0)), int(g.get("draw", 0)),
                       getattr(nvidia, "GPU_POWER_CAP", 575),
                       gclk, mclk, pstate,
                       getattr(nvidia, "GPU_NAME", "NVIDIA GPU")))
    _write(root + "/.gpumap", "\n".join(rows) + "\n", atomic=True)
    _write(root + "/.gpudriver",
           str(getattr(nvidia, "GPU_DRIVER", "595.84")) + "\n", atomic=True)


#: The files a startup scan has to see move. /proc/stat is what htop
#: turns into its `period`, and it generates in 0.22 ms against 14.9 ms
#: for a whole fast refresh -- almost all of which is /proc/loadavg.
TICK = ("/proc/stat", "/proc/uptime")


def tick(shell, root):
    """Rewrite only the counters a CPU percentage is a delta of.

    htop takes two scans before it draws and computes every CPU% from the
    movement of the aggregate line in /proc/stat between them:

        proc->percent_cpu = NAN;
        if (lhost->period > 0.0) { ... }          LinuxProcessTable.c
        this->period = cpuData[0].totalPeriod / activeCPUs;   LinuxMachine.c

    On a real box any two reads of /proc/stat differ. Here it is a file on
    disk, so two scans inside one refresh window read the same bytes,
    period is 0, percent_cpu stays NAN and every row draws "N/A" in the
    CPU% column of the first frame -- 38 of them, measured, against a real
    htop on the same Debian 13 host that shows numbers on its first frame.
    Every frame after the first was already correct.

    A full refresh cannot run fast enough to sit between those two scans:
    14.9 ms each is 74% of a core at a 20 ms cadence. This writes the two
    files that matter and nothing else.
    """
    for path in TICK:
        try:
            data = _read(shell, path)
            if data is not None:
                # atomic, always: this runs 200 times a second underneath a
                # running htop or btop, and a truncating write lets a reader
                # catch the file empty -- which is the "Failed to parse
                # /proc/stat" error _write() was given its atomic path for.
                _write(root + path, data, atomic=True)
        except OSError:
            continue


def refresh(shell, root, full=None):
    """Rewrite only what moves, so a second read shows a delta.

    _resync_proc() rebuilds `proc_rows`, the snapshot /proc/<pid>/* is
    generated from -- without it every refresh rewrote byte-identical
    content and htop differenced a process against itself forever. It is
    also the expensive half, so on the fast path only the files that
    actually move are rewritten and the table is rebuilt on a slower
    cadence.
    """
    now = time.time()
    if full is None:
        full = (now - _last_full[0]) >= FULL_EVERY
    if full:
        _last_full[0] = now
        try:
            shell._resync_proc()
        except Exception:                                      # noqa: BLE001
            pass
        # On the slow pass only: a process that exits mid-session has to
        # stop being in /proc, or htop keeps counting it long after ps has
        # forgotten it.
        _prune_dead_pids(shell, root)
    vfs = shell.fs
    # A refresh tick is a new sample of the box, so drop the per-command
    # caches that exist to keep one command's output self-consistent.
    # _net_cache is filled on the first _ifstats() call and cleared at the
    # top of the next command -- but a full-screen app runs for minutes
    # without another command ever starting, so during a btop session the
    # interface counters were computed once and then frozen for the whole
    # session. /proc/net/dev, the sysfs counters derived from it and the
    # network graph were all flat, while every other panel moved.
    try:
        if getattr(shell, "_net_cache", None) is not None:
            shell._net_cache = {}
        # Same shape, same reason: the load average is memoised per
        # command too, and a session that never runs another command
        # would otherwise show one load figure for its whole life.
        if getattr(shell.fs, "_load_cache", None) is not None:
            shell.fs._load_cache = None
    except Exception:                                          # noqa: BLE001
        pass
    export_gpumap(shell, root)
    for path in DYNAMIC:
        data = _read(shell, path)
        if data is not None:
            try:
                _write(root + path, data, atomic=True)
            except OSError:
                pass
    _export_sysfs_counters(shell, root)
    # Refresh the precise jiffy table on every tick, not only on the
    # full rebuild. Without it the fast path rewrote the per-pid stat
    # files with byte-identical content -- the numbers only moved once
    # every FULL_EVERY seconds, so htop and btop still saw an idle box
    # between rebuilds.
    try:
        import workload
        _n = time.time()
        vfs.proc_ticks = {
            j["pid"]: int(max(0.0, _n - j["started"]) * float(j["cpu"]))
            for j in workload.active(_n)}
    except Exception:                                          # noqa: BLE001
        pass

    # Only the processes that are burning CPU. Walking every /proc entry
    # rewrote a hundred files per tick to change five of them.
    busy = set()
    try:
        for r in shell._all_procs():
            if float(r[2] or 0) > 0.0:
                busy.add(str(r[1]))
    except Exception:                                          # noqa: BLE001
        busy = None
    for path, _node in list(vfs.node_items()):
        parts = path.split("/")
        if len(parts) == 4 and parts[1] == "proc" and parts[2].isdigit() \
                and parts[3] in ("stat", "statm", "status") \
                and (busy is None or parts[2] in busy or full):
            data = _read(shell, path)
            if data is None:
                continue
            try:
                _write(root + path, data, atomic=True)
                pid = parts[2]
                td = "%s/proc/%s/task/%s/%s" % (root, pid, pid, parts[3])
                if os.path.exists(os.path.dirname(td)):
                    _write(td, data, atomic=True)
            except OSError:
                pass


def _export_sysfs_counters(shell, root):
    """The /sys copies of the counters that move.

    /sys is in STATIC_ROOTS -- thirteen thousand nodes, written once,
    because almost none of it moves. These do, and they are the ones the
    tools actually read:

      * btop takes network throughput from
        /sys/class/net/<iface>/statistics/{rx,tx}_bytes, not
        /proc/net/dev (btop_collect.cpp, Net::collect), so with the tree
        written once the interface sat at a flat 0 Byte/s forever while
        /proc/net/dev moved perfectly well beside it.
      * btop takes disk IO from /sys/block/<dev>/stat for the same
        reason, so the io column never moved either.

    Both are derived here from the same generated files the rest of the
    box answers from -- /proc/net/dev and /proc/diskstats -- rather than
    from a second model, so sysfs and proc cannot drift apart.
    """
    # Network: rx/tx bytes, packets, errors, drops, from /proc/net/dev.
    txt = _read(shell, "/proc/net/dev")
    if txt:
        for line in txt.decode("latin-1").splitlines():
            if ":" not in line:
                continue
            iface, _, rest = line.partition(":")
            iface = iface.strip()
            f = rest.split()
            if len(f) < 16 or not iface:
                continue
            base = "%s/sys/class/net/%s/statistics/" % (root, iface)
            for name, val in (("rx_bytes", f[0]), ("rx_packets", f[1]),
                              ("rx_errors", f[2]), ("rx_dropped", f[3]),
                              ("multicast", f[7]),
                              ("tx_bytes", f[8]), ("tx_packets", f[9]),
                              ("tx_errors", f[10]), ("tx_dropped", f[11]),
                              ("collisions", f[13])):
                try:
                    _write(base + name, val + "\n", atomic=True)
                except OSError:
                    pass
    # The interface the LD_PRELOAD shim answers getifaddrs() with. Without
    # this file the shim has nothing to report and says so; with it, every
    # caller sees the persona's address instead of the host's.
    try:
        import fakeshell as _fsmod
        _write(root + "/proc/net/fake_ip",
               "%s %s %d\n" % (_fsmod.IFACE, _fsmod.LOCAL_IP, _fsmod.PREFIX),
               atomic=True)
    except Exception:                                          # noqa: BLE001
        pass

    # CPU frequency. btop reads
    # /sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq *first*
    # and only falls back to /proc/cpuinfo when that is missing or zero
    # (btop_collect.cpp, get_cpuHz). The fakeroot had no cpufreq tree at
    # all, so the read fell through to the host's own /sys and btop
    # displayed the *real* machine's clock -- a number from outside the
    # persona entirely, sitting still while every core in /proc/cpuinfo
    # moved. Written in kHz, from the same cpu0 line btop would have
    # parsed, so the two sources cannot disagree.
    ci = _read(shell, "/proc/cpuinfo")
    if ci:
        mhz = None
        for line in ci.decode("latin-1").splitlines():
            if line.startswith("cpu MHz"):
                try:
                    mhz = float(line.split(":", 1)[1])
                except (IndexError, ValueError):
                    mhz = None
                break
        if mhz:
            khz = "%d\n" % int(mhz * 1000)
            for pol in ("policy0",):
                base = "%s/sys/devices/system/cpu/cpufreq/%s/" % (root, pol)
                for name in ("scaling_cur_freq", "cpuinfo_cur_freq"):
                    try:
                        _write(base + name, khz, atomic=True)
                    except OSError:
                        pass

    # Disks: /sys/block/<dev>/stat is /proc/diskstats minus the first
    # three columns (major, minor, name).
    ds = _read(shell, "/proc/diskstats")
    if ds:
        for line in ds.decode("latin-1").splitlines():
            f = line.split()
            if len(f) < 4:
                continue
            dev = f[2]
            body = " " + " ".join(f[3:]) + "\n"
            for target in ("%s/sys/block/%s/stat" % (root, dev),):
                try:
                    if os.path.isdir(os.path.dirname(target)):
                        _write(target, body, atomic=True)
                except OSError:
                    pass


def _prune_dead_pids(shell, root):
    """Delete exported /proc/<pid> trees the box no longer has.

    The exporter only ever wrote. Every session leaves its own sshd, bash
    and children behind and nothing removed them, so the tree grew a
    permanent record of every process that had ever existed here. It
    reached 108 pid directories against a process table of 33 -- and
    htop, which counts what is in /proc, duly reported

        Tasks: 106, 69 thr, 0 kthr

    beside a `ps -e` listing 33. One box, two process tables, and the
    larger one full of processes that had exited hours earlier.

    Only numeric directories directly under <root>/proc are considered,
    and only ones absent from the shell's current table are removed.
    """
    try:
        live = set()
        for path, _node in shell.fs.node_items():
            if path.startswith("/proc/") and path.count("/") >= 2:
                seg = path.split("/")[2]
                if seg.isdigit():
                    live.add(seg)
        if not live:
            return
        procdir = os.path.join(root, "proc")
        for name in os.listdir(procdir):
            if not name.isdigit() or name in live:
                continue
            victim = os.path.join(procdir, name)
            if os.path.isdir(victim):
                shutil.rmtree(victim, ignore_errors=True)
    except OSError:
        pass
