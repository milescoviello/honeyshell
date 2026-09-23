"""What this machine is busy with, defined once.

A box with eight GPUs and nothing running on them is its own tell: an
attacker who lands, sees 640GB of idle VRAM and a load average of zero has
found a machine nobody uses, which is not what an expensive machine looks
like. So it runs work -- and the work has to be the same work everywhere.

One table, read by every surface: the process list ps and top and htop
render, the GPU process table nvidia-smi prints, the memory those jobs
occupy, and the load average. Three of those disagreeing is worse than an
idle box, because an idle box is at least consistent.

Two things make it look lived-in rather than staged:

* Age. The training run started days ago, not at boot and not just now. A
  process whose start time is always "a few minutes ago" is a process that
  restarts whenever someone looks at it.
* A schedule. Some of this only runs at night, the way batch work does.
  Somebody watching across a few hours sees jobs begin and end on the hour
  rather than a photograph that never changes -- and somebody who looks
  once at 03:00 sees a busier machine than somebody who looks at noon.

Everything here is derived from the clock, so two readers a second apart
agree and two readers an hour apart do not have to.
"""

import time

#: (name, user, argv, cpu_pct, rss_kb, gpus, vram_mib_per_gpu, gpu_util,
#:  age_seconds, hours, unit, threads) -- hours is None for "always", else
#: the hours of the day it runs, local time. unit is the systemd unit the
#: process belongs to, or None for "this is somebody's work, put it in
#: their slice".
#:
#: threads is not decoration. A process cannot use more CPU than its
#: threads allow, so a job at 388% needs at least four of them; ps also
#: flags a multi-threaded process with `l` in STAT, and /proc/<pid>/status
#: has to agree. Measured on a real box: 165% CPU, STAT Rl, Threads 2.
JOBS = (
    # ORDER MATTERS: pids are BASE_PID + i*7, so this list has to run
    # oldest-first. Without a pid wrap -- pid_max is 4194304 and the
    # highest pid here is 21435 -- a process with a larger pid cannot have
    # started earlier, and `ps -eo pid,lstart --sort=pid` puts the two
    # columns side by side. The services used to sit last and so held the
    # highest pids while being the oldest things on the box, which that one
    # command showed. Sorted by descending age: services, train, render,
    # prep. procstarttest checks it.
    # Always-on services somebody would actually have on a box like this.
    ("jupyter", "mlops",
     "/usr/bin/python3 /usr/local/bin/jupyter-lab --no-browser "
     "--ip=127.0.0.1 --port=8888",
     0.3, 245760, (), 0, 0, 6 * 86400 + 5 * 3600, None, None, 5),
    ("exporter", "prometheus",
     "/usr/local/bin/node_exporter --collector.systemd "
     "--collector.textfile.directory=/var/lib/node_exporter",
     0.1, 30720, (), 0, 0, 6 * 86400 + 5 * 3600, None,
     "node_exporter.service", 9),
    ("dcgm", "root",
     "/usr/bin/dcgm-exporter -f /etc/dcgm-exporter/dcp-metrics-included.csv",
     0.2, 51200, (), 0, 0, 6 * 86400 + 5 * 3600, None,
     "dcgm-exporter.service", 11),
    # The long-running one. Started six days ago, still going: this is the
    # job that makes the machine worth having.
    # torchrun supervises; it does not train. --nproc_per_node=4 means four
    # worker processes, and the launcher holds no CUDA context of its own,
    # so it must not appear in nvidia-smi and must not be burning 388% of a
    # CPU. See WORKERS below for the children it forks.
    ("train", "mlops",
     "python3 -m torch.distributed.run --nproc_per_node=4 train.py "
     "--config configs/sft-70b.yaml --out /data/runs/sft-70b",
     0.4, 262144, (), 0, 0, 6 * 86400 + 4 * 3600, None, None, 5),
    # Overnight batch. Runs 02:00-07:59 and is simply absent by day.
    ("render", "mlops",
     "python3 tools/batch_infer.py --shard 3 --gpus 4,5,6,7 "
     "--in /data/queue --out /data/out",
     212.0, 18874368, (4, 5, 6, 7), 21440, 88, 3 * 3600,
     (2, 3, 4, 5, 6, 7), None, 8),
    # The dataset builder: hourly, CPU only, short. In HOURLY above, so it
    # is anchored to the top of the current hour and stays minutes old
    # rather than ageing past its own description.
    ("prep", "mlops",
     "python3 tools/prepare_shards.py --src /data/raw --dst /data/shards",
     96.0, 6291456, (), 0, 0, 900, None, None, 2),
)

#: Launchers that fork one worker per GPU, and what those children are.
#:
#: `python3 -m torch.distributed.run --nproc_per_node=4` had no children at
#: all, and the launcher's own pid was listed against all four busy GPUs.
#: Both halves are wrong in the same way and either one gives the box away:
#: torchrun execs four workers, one per local rank, and it is those pids --
#: not the launcher's -- that hold the CUDA contexts. A single pid on four
#: GPUs is what a hand-written table looks like, not what a training run
#: looks like.
#:
#: The launcher's 388% CPU and 40 GB RSS move here too, because they were
#: always the workers' to hold. The totals are unchanged on purpose: 0.4 +
#: 4 x 96.9 = 388.0, and 262144 + 4 x 10366592 = 41728512 kB, so the load
#: average and the memory accounting read exactly as they did before.
#:
#: torch.distributed.elastic spawns each worker as
#: `<sys.executable> -u <script> <args>`, which is why the child argv is
#: the script and not the -m form, and why every one of them is identical
#: apart from the rank it is handed through the environment.
WORKERS = {
    "train": {
        "n": 4,
        "argv": ("/usr/bin/python3 -u train.py "
                 "--config configs/sft-70b.yaml --out /data/runs/sft-70b"),
        "cpu": 96.9,
        "rss": 10366592,
        "vram_mib": 27960,
        "util": 97,
        "threads": 12,
        # Workers come up a few seconds after the launcher that spawns
        # them; identical start times across a parent and its children are
        # a thing real process trees do not have.
        "delay": 9,
    },
}

#: PIDs are fixed per job so they do not move under anyone between two
#: commands, and are chosen well above the seeded daemons. Job i sits at
#: BASE_PID + i*7, and a launcher's workers take the slots immediately
#: after it -- four of them fits inside the stride of seven.
BASE_PID = 21400


def _exe(argv):
    """The path nvidia-smi prints in its process table.

    It prints the executable, not the command line: a real table reads
    `/usr/bin/python3`, never `python3 -m torch.distributed.run --n`.
    """
    head = argv.split()[0]
    return head if head.startswith("/") else "/usr/bin/" + head


#: Jobs that restart every hour, so their start is the top of the current
#: hour rather than a fixed instant. `age` anchors a job to
#: boot + (REF_UPTIME - age), which is correct for something long-running
#: -- train has genuinely been up for weeks -- and wrong for anything
#: recurring: past REF_UPTIME the anchor recedes without bound, so the
#: "hourly, CPU only, short" dataset builder was 15.7 days old on the live
#: box, with `ps` printing an ELAPSED of 15 days beside a 900-second job.
#:
#: It also broke pid ordering. A schedule-anchored job is always recent
#: while an age-anchored one recedes, so the two sort differently as the
#: box ages -- and the local tree sits exactly at REF_UPTIME, where the
#: age-anchored start is still fresh, so the inversion was invisible here
#: and plain on a box with more uptime.
HOURLY = frozenset(("prep",))


def _running(name, hours, now):
    if hours is None:
        return True
    return time.localtime(now).tm_hour in hours


#: The uptime, in seconds, at which the ages in JOBS were written. Job
#: start times are pinned to boot plus (REF_UPTIME - age) so that they
#: were exactly `age` old at that moment and have aged since.
REF_UPTIME = 3549900          # 41.09 days


def _boot_ts():
    """The box's boot instant, from the emulator if it is importable."""
    try:
        import fakeshell
        return fakeshell.BOOT_TS
    except Exception:                                          # noqa: BLE001
        return time.time() - REF_UPTIME


def active(now=None):
    """The jobs running at `now`, as dicts every surface can read."""
    now = time.time() if now is None else now
    boot = _boot_ts()
    out = []
    for i, (name, user, argv, cpu, rss, gpus, vram, util, age,
            hours, unit, threads) in enumerate(JOBS):
        if not _running(name, hours, now):
            continue
        # A scheduled job started when its window opened, not days ago.
        if name in HOURLY:
            lt = time.localtime(now)
            started = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                                   lt.tm_hour, 0, 0, 0, 0, -1))
        elif hours is not None:
            lt = time.localtime(now)
            start_hour = min(hours)
            # The instant itself, not `now` minus an elapsed count. Written
            # as `now - ((tm_hour - start_hour) * 3600 + tm_min * 60 +
            # tm_sec)` the subtrahend is a whole number of seconds while
            # `now` is fractional, so `now - started` came back an exact
            # integer and only moved when tm_sec ticked over. That is the
            # same quantisation the branch below already carries a comment
            # about -- a job at 212% of a core accumulated nothing for most
            # of every second and then jumped a whole one -- and it hid
            # here because the arithmetic looks like it anchors to the
            # window and very nearly does. mktime gives the real epoch of
            # start_hour:00:00 local today, which does not move at all.
            started = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday,
                                   start_hour, 0, 0, 0, 0, -1))
        else:
            # Anchored to boot, not to "now". This was ``now - age``,
            # which made every long-running job *permanently* exactly
            # `age` seconds old: ps's TIME column never moved, and two
            # `ps` calls a minute apart printed byte-identical CPU times
            # on a box whose load average said four cores were busy.
            # Anything that samples twice -- htop, top, pidstat -- read a
            # process using 388% of a CPU and accumulating nothing.
            #
            # REF_UPTIME is the uptime at which the persona's ages were
            # written, so at that instant `ran` was `age` exactly; after
            # it, jobs age the way real ones do.
            started = boot + (REF_UPTIME - age)
        pid = BASE_PID + i * 7
        out.append({
            "name": name, "user": user, "cmd": argv, "pid": pid,
            "exe": _exe(argv), "ppid": 1,
            "cpu": cpu, "rss": rss, "gpus": tuple(gpus),
            "vram_mib": vram, "util": util, "started": started,
            "unit": unit, "threads": threads,
        })
        spec = WORKERS.get(name)
        if not spec:
            continue
        # One worker per local rank, each pinned to the GPU of that rank,
        # each a child of the launcher above.
        for rank in range(spec["n"]):
            out.append({
                "name": name + "-w%d" % rank, "user": user,
                "cmd": spec["argv"], "pid": pid + 1 + rank,
                "exe": _exe(spec["argv"]), "ppid": pid,
                "cpu": spec["cpu"], "rss": spec["rss"],
                "gpus": (rank,), "vram_mib": spec["vram_mib"],
                "util": spec["util"],
                "started": started + spec.get("delay", 0),
                "unit": unit, "threads": spec["threads"],
                "rank": rank,
            })
    return out


def gpu_jobs(now=None):
    """Only the jobs holding a GPU, for nvidia-smi's process table."""
    return [j for j in active(now) if j["gpus"]]


def load_average(now=None):
    """What these jobs put on the run queue.

    Derived from the same table rather than a separate number: a box whose
    load average does not match the processes in ps is a box where one of
    the two was made up.
    """
    now = time.time() if now is None else now
    total = sum(j["cpu"] for j in active(now)) / 100.0
    # A little drift, so three readings in a row are not identical.
    jitter = ((int(now / 30) % 7) - 3) * 0.04
    one = max(0.0, total + jitter)
    return (one, max(0.0, one * 0.94), max(0.0, one * 0.82))


def threads_of(pid, now=None):
    """How many threads a workload pid has, or None if it is not one."""
    for j in active(now):
        if j["pid"] == pid:
            return j["threads"]
    return None
