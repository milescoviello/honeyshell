r"""ulimit said yes and changed nothing.

Fifty-ninth coherence sweep. Raising the open-file limit is the last thing
a miner does before it starts -- `ulimit -n 65535` sits at the top of
almost every mining installer -- so: do the three things that answer "what
are this process's limits" agree, and does changing one work?

At rest they agreed, and that is pinned rather than changed: `ulimit -a`,
each individual `ulimit -X`, /proc/self/limits and prlimit all report the
same soft and hard values, with the unit conversions right (stack is
8192 KB to ulimit and 8388608 bytes to /proc, core is blocks to one and
bytes to the other).

Changing one did not work at all.

  1. Every set form was a silent no-op. `ulimit -n 65535` returned 0 and
     left the limit at 1024 -- and printed "1024", because an operand was
     ignored and the command fell through to the show path. Real ulimit
     prints nothing when it sets. So an installer capturing that output
     got a stray number, and one checking afterwards got the old value
     back from a command that had just reported success.

  2. Because the limits were a module-level constant, nothing downstream
     could move either: /proc/self/limits and prlimit would have gone on
     reporting the boot-time table however many times ulimit claimed to
     have changed it.

  3. Limits are inherited. The child shell rebuilt them from the same
     constant in its own constructor, so even once setting worked,
     `ulimit -n 3000; bash -c 'ulimit -n'` said 1024 -- and since the
     child publishes to the same filesystem under the same pid, it reset
     the parent's /proc/self/limits on its way past.

Semantics follow bash: with neither -H nor -S both limits are set;
lowering a hard limit is allowed for anyone; raising one needs root;
a soft limit above the hard one is "Invalid argument"; and NOFILE cannot
pass /proc/sys/fs/nr_open even for root.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def shell(user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(s, cmd):
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


def proc(s, label):
    """Soft and hard for one row of /proc/self/limits.

    Parsed by column, not by whitespace field: the labels have different
    word counts ("Max core file size" is four), so $4 is the soft value
    for some rows and the word "size" for others.
    """
    for line in out(s, "cat /proc/self/limits").splitlines():
        if line.startswith(label):
            return "%s %s" % (line[26:47].strip(), line[47:68].strip())
    return ""


# -- at rest -------------------------------------------------------------

def t_the_three_views_agree_at_rest():
    s = shell()
    eq("open files soft", out(s, "ulimit -n"), proc(s, "Max open files").split()[0])
    eq("open files hard", out(s, "ulimit -H -n"),
       proc(s, "Max open files").split()[1])
    eq("processes soft", out(s, "ulimit -u"),
       proc(s, "Max processes").split()[0])


def t_unit_conversions():
    """ulimit talks in KB and blocks; /proc talks in bytes."""
    s = shell()
    eq("stack: ulimit KB", out(s, "ulimit -s"), "8192")
    eq("stack: proc bytes", proc(s, "Max stack size").split()[0], "8388608")
    eq("locked: ulimit KB", out(s, "ulimit -l"), "8192")
    eq("locked: proc bytes", proc(s, "Max locked memory").split()[0], "8388608")


def t_ulimit_a_has_every_row():
    s = shell()
    eq("17 rows", out(s, "ulimit -a | wc -l"), "17")
    check("names open files", "open files" in out(s, "ulimit -a"), "")


def t_ulimit_a_agrees_with_the_single_flags():
    s = shell()
    body = out(s, "ulimit -a")
    for flag, label in (("n", "open files"), ("u", "max user processes"),
                        ("s", "stack size"), ("l", "max locked memory")):
        row = [l for l in body.splitlines() if l.startswith(label)]
        check("row exists: %s" % label, bool(row), body[:80])
        if row:
            eq("-%s matches -a" % flag, out(s, "ulimit -%s" % flag),
               row[0].split()[-1])


def t_bare_ulimit_is_file_size():
    s = shell()
    eq("bare ulimit", out(s, "ulimit"), out(s, "ulimit -f"))


# -- setting actually sets ------------------------------------------------

def t_setting_prints_nothing():
    s = shell()
    eq("no output", out(s, "ulimit -n 65535"), "")


def t_the_miner_line():
    """`ulimit -n 65535` is the top of almost every mining installer."""
    s = shell()
    out(s, "ulimit -n 65535")
    eq("soft", out(s, "ulimit -n"), "65535")
    eq("hard", out(s, "ulimit -H -n"), "65535")
    eq("/proc agrees", proc(s, "Max open files"), "65535 65535")


def t_setting_moves_proc_limits():
    s = shell()
    for val in ("4096", "16384", "1024"):
        out(s, "ulimit -n %s" % val)
        eq("proc follows %s" % val, proc(s, "Max open files").split()[0], val)


def t_stack_set_converts_units():
    s = shell()
    out(s, "ulimit -s 16384")
    eq("ulimit KB", out(s, "ulimit -s"), "16384")
    eq("proc bytes", proc(s, "Max stack size").split()[0], "16777216")


def t_unlimited():
    s = shell()
    out(s, "ulimit -c unlimited")
    eq("ulimit says unlimited", out(s, "ulimit -c"), "unlimited")
    eq("proc says unlimited", proc(s, "Max core file size").split()[0],
       "unlimited")


def t_soft_and_hard_separately():
    s = shell()
    out(s, "ulimit -n 8192")
    out(s, "ulimit -S -n 4096")
    eq("soft moved", out(s, "ulimit -n"), "4096")
    eq("hard did not", out(s, "ulimit -H -n"), "8192")


# -- the rules ------------------------------------------------------------

def t_soft_above_hard_is_refused():
    s = shell()
    out(s, "ulimit -n 2048")
    o = out(s, "ulimit -S -n 4096")
    check("Invalid argument", "Invalid argument" in o, o)
    eq("unchanged", out(s, "ulimit -n"), "2048")


def t_root_may_raise_a_hard_limit():
    s = shell()
    out(s, "ulimit -n 2048")
    o = out(s, "ulimit -H -n 8192")
    eq("no error", o, "")
    eq("hard raised", out(s, "ulimit -H -n"), "8192")


def t_a_normal_user_may_not():
    s = shell(user="deploy")
    out(s, "ulimit -n 2048")
    o = out(s, "ulimit -H -n 8192")
    check("Operation not permitted", "Operation not permitted" in o, o)
    eq("hard unchanged", out(s, "ulimit -H -n"), "2048")


def t_a_normal_user_may_lower():
    s = shell(user="deploy")
    eq("no error", out(s, "ulimit -n 512"), "")
    eq("lowered", out(s, "ulimit -n"), "512")


def t_nofile_cannot_pass_nr_open():
    s = shell()
    o = out(s, "ulimit -n 9999999999")
    check("refused even for root", "Operation not permitted" in o, o)


def t_a_bad_number_is_refused():
    s = shell()
    o = out(s, "ulimit -n banana")
    check("reports it", "invalid number" in o, o)


# -- inheritance ----------------------------------------------------------

def t_a_child_inherits_the_limit():
    s = shell()
    out(s, "ulimit -n 3000")
    eq("child ulimit", out(s, "bash -c 'ulimit -n'"), "3000")
    eq("child /proc",
       out(s, "bash -c \"awk '/Max open files/{print \\$4}' /proc/self/limits\""),
       "3000")


def t_a_child_cannot_change_its_parent():
    s = shell()
    out(s, "ulimit -n 3000")
    out(s, "bash -c 'ulimit -n 1500'")
    eq("parent unchanged", out(s, "ulimit -n"), "3000")


def t_a_subshell_does_not_reset_the_parents_proc():
    s = shell()
    out(s, "ulimit -n 3000")
    out(s, "bash -c 'echo hi'")
    eq("still raised", out(s, "ulimit -n"), "3000")
    eq("/proc still raised", proc(s, "Max open files").split()[0], "3000")


# -- the installer shape --------------------------------------------------

def t_the_whole_installer_prologue():
    """What the top of a mining install script actually looks like."""
    s = shell()
    o = out(s, "ulimit -n 65535 2>/dev/null; ulimit -c unlimited 2>/dev/null; "
               "echo nofile=$(ulimit -n) core=$(ulimit -c)")
    eq("both took", o, "nofile=65535 core=unlimited")
    check("nothing stray on stdout", "1024" not in o, o)


TESTS = [t_the_three_views_agree_at_rest, t_unit_conversions,
         t_ulimit_a_has_every_row, t_ulimit_a_agrees_with_the_single_flags,
         t_bare_ulimit_is_file_size, t_setting_prints_nothing,
         t_the_miner_line, t_setting_moves_proc_limits,
         t_stack_set_converts_units, t_unlimited, t_soft_and_hard_separately,
         t_soft_above_hard_is_refused, t_root_may_raise_a_hard_limit,
         t_a_normal_user_may_not, t_a_normal_user_may_lower,
         t_nofile_cannot_pass_nr_open, t_a_bad_number_is_refused,
         t_a_child_inherits_the_limit, t_a_child_cannot_change_its_parent,
         t_a_subshell_does_not_reset_the_parents_proc,
         t_the_whole_installer_prologue]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
