r"""One launch, one process.

Sixty-second coherence sweep. The previous sweep found cmd_ping calling
a method defined nowhere -- a latent AttributeError that the exec handler
turns into empty output with rc 0. That is a whole class of bug, so this
one started as a static audit of the file for self.<attr> references with
no definition anywhere.

The audit came back nearly clean: two nested classes the checker did not
recognise, and two genuine dead references.

  * self._tr_set, in cmd_tr, sits after an unconditional `return`, so it
    could never run. tr itself matches the real one on all fourteen forms
    tried, including -d, -s, -c, -dc and the [:class:] names.
  * self.fs.kill_proc, in the jobspec branch of kill, is guarded by
    hasattr -- and VFS has no such method, so the guard quietly turned it
    into nothing. `kill %1` marked the job Terminated and left the
    process running in ps and in /proc. A loader that backgrounds a stage
    and later kills it by %1 would still have seen it.

Probing around that turned up the substantive one. Backgrounding
registered the process twice: _background allocated a pid for the job and
then ran the segment, and the dispatcher registered a *second* pid for
the binary itself. So `./payload &` put two entries in ps and emitted two
process_started events for a single launch. Both Diicot sessions on this
box did exactly that -- 203.0.113.38 and 203.0.113.44 each logged
"./UhiNJWZV >/dev/null 2>&1" and "./UhiNJWZV" as separate starts -- and a
kit that runs `pgrep -c` before starting, which is the usual way of not
double-starting a miner, would have read its own payload as already
running twice.

The job and the process it runs are one process. The dispatcher's
registration now adopts the pid the job already holds, keeps the more
accurate argv for ps -- a binary's argv has no shell redirections in it
-- and does not announce a second start.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

HDR = ("\\177ELF\\002\\001\\001\\000\\000\\000\\000\\000\\000\\000\\000"
       "\\000\\002\\000>\\000\\001\\000\\000\\000")
MAKE = ("cd /tmp && printf '%s' > m && "
        "printf 'padpadpadpadpadpadpadpad' >> m && chmod +x m" % HDR)


def shell():
    ev = []
    s = fs.Shell(fs.VFS(), log=lambda **k: ev.append(k), user="root",
                 peer="203.0.113.77")
    s.exec_mode = True
    s.events = ev
    s.run(MAKE)
    s._err.clear()
    ev.clear()
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


def starts(s):
    return [e for e in s.events if e.get("event") == "process_started"]


# -- one launch, one process ---------------------------------------------

def t_backgrounding_starts_one_process():
    for launch in ("./m &", "nohup ./m &", "nohup ./m >/dev/null 2>&1 &",
                   "./m >/dev/null 2>&1 &", "setsid ./m &"):
        s = shell()
        s.run(launch)
        eq("one process_started: %s" % launch, len(starts(s)), 1)
        # stdout only: `nohup x &` with no redirection prints its
        # "ignoring input and appending output to 'nohup.out'" notice on
        # stderr, exactly as the real one does.
        n = s.run("ps -e -o args= | grep -c '^\\./m'").strip()
        s._err.clear()
        eq("one ps row: %s" % launch, n, "1")


def t_the_foreground_case_is_unchanged():
    for launch in ("./m", "./m >/dev/null 2>&1", "nohup ./m",
                   "nohup ./m >/dev/null 2>&1"):
        s = shell()
        s.run(launch)
        eq("one process_started: %s" % launch, len(starts(s)), 1)


def t_ps_shows_the_argv_not_the_redirections():
    s = shell()
    s.run("nohup ./m >/dev/null 2>&1 &")
    eq("ps line", out(s, "ps -e -o args= | grep '^\\./m'"), "./m")
    check("no redirection in ps",
          ">" not in out(s, "ps -e -o args= | grep '^\\./m'"), "")


def t_two_launches_are_two_processes():
    s = shell()
    s.run("./m & ./m &")
    eq("two starts", len(starts(s)), 2)
    eq("two ps rows", out(s, "ps -e -o args= | grep -c '^\\./m'"), "2")
    eq("two jobs", out(s, "jobs | wc -l"), "2")


def t_pgrep_counts_it_once():
    """A kit runs this before starting, to avoid double-starting."""
    s = shell()
    s.run("nohup ./m >/dev/null 2>&1 &")
    eq("pgrep -c", out(s, "pgrep -c -f '^\\./m$'"), "1")


# -- the job machinery still works ---------------------------------------

def t_dollar_bang_is_the_process():
    s = shell()
    s.run("nohup ./m >/dev/null 2>&1 &")
    bang = out(s, "echo $!")
    check("$! is a pid", bang.isdigit(), bang)
    eq("and it is the one in ps",
       out(s, "ps -e -o pid=,args= | grep '\\./m' | awk '{print $1}'"), bang)
    eq("and /proc has it", out(s, "test -d /proc/%s && echo y" % bang), "y")


def t_jobs_still_lists_it_with_the_full_command():
    s = shell()
    s.run("nohup ./m >/dev/null 2>&1 &")
    j = out(s, "jobs")
    check("job 1 running", j.startswith("[1]+"), j)
    check("keeps the whole command line", ">/dev/null" in j, j)


def t_job_numbering():
    s = shell()
    s.run("./m & ./m & ./m &")
    j = out(s, "jobs")
    for n in ("[1]", "[2]", "[3]"):
        check("has %s" % n, n in j, j)


# -- kill %1 ends the process --------------------------------------------

def t_kill_by_jobspec_ends_it():
    s = shell()
    s.run("nohup ./m >/dev/null 2>&1 &")
    eq("running first", out(s, "ps -e -o args= | grep -c '^\\./m'"), "1")
    out(s, "kill %1")
    eq("gone from ps", out(s, "ps -e -o args= | grep -c '^\\./m'"), "0")


def t_kill_by_jobspec_clears_proc_too():
    s = shell()
    s.run("nohup ./m >/dev/null 2>&1 &")
    bang = out(s, "echo $!")
    out(s, "kill %1")
    eq("no /proc entry", out(s, "test -d /proc/%s || echo gone" % bang),
       "gone")
    eq("pgrep finds nothing", out(s, "pgrep -c -f '^\\./m$'"), "0")


def t_kill_by_pid_and_by_jobspec_agree():
    a = shell()
    a.run("nohup ./m >/dev/null 2>&1 &")
    out(a, "kill %1")
    b = shell()
    b.run("nohup ./m >/dev/null 2>&1 &")
    out(b, "kill $!")
    eq("same result",
       out(a, "ps -e -o args= | grep -c '^\\./m'"),
       out(b, "ps -e -o args= | grep -c '^\\./m'"))


def t_killing_one_job_leaves_the_other():
    s = shell()
    s.run("./m & ./m &")
    out(s, "kill %1")
    eq("one left", out(s, "ps -e -o args= | grep -c '^\\./m'"), "1")


def t_an_unknown_jobspec_is_still_an_error():
    s = shell()
    o = out(s, "kill %9")
    check("reports it", "no such job" in o, o)


# -- the dead references are gone ----------------------------------------

def t_no_self_reference_is_undefined():
    """The audit that started this sweep, kept as a test.

    Any self.<name> the Shell reads must be defined somewhere: a method, a
    class attribute, a nested class, a __slots__ entry, or something
    assigned to self. cmd_ping's _stable_ip was found exactly this way.
    """
    import ast
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "fakeshell.py")).read()
    tree = ast.parse(src)
    bad = []
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        defined = set()
        for n in ast.walk(cls):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef)):
                defined.add(n.name)
            elif isinstance(n, ast.Attribute) and isinstance(
                    n.value, ast.Name) and n.value.id == "self" and isinstance(
                        n.ctx, ast.Store):
                defined.add(n.attr)
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        defined.add(t.id)
                        if t.id == "__slots__" and isinstance(
                                n.value, (ast.Tuple, ast.List)):
                            for e in n.value.elts:
                                if isinstance(e, ast.Constant):
                                    defined.add(e.value)
        for n in ast.walk(cls):
            if (isinstance(n, ast.Attribute)
                    and isinstance(n.value, ast.Name)
                    and n.value.id == "self"
                    and isinstance(n.ctx, ast.Load)
                    and n.attr not in defined):
                bad.append("%s.%s (line %d)" % (cls.name, n.attr, n.lineno))
    check("every self.<attr> is defined", not bad, "; ".join(bad[:6]))


def t_no_unreachable_code():
    """Dead blocks hide references that can never be checked by running."""
    import ast
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "fakeshell.py")).read()
    tree = ast.parse(src)
    TERM = (ast.Return, ast.Raise, ast.Continue, ast.Break)
    dead = []

    def scan(body, where):
        for i, n in enumerate(body):
            if isinstance(n, TERM) and i + 1 < len(body):
                dead.append("%s line %d" % (where, body[i + 1].lineno))
            if isinstance(n, ast.If) and isinstance(
                    n.test, ast.Constant) and n.test.value is False:
                dead.append("%s if False: line %d" % (where, n.lineno))
            for f in ("body", "orelse", "finalbody"):
                sub = getattr(n, f, None)
                if isinstance(sub, list) and sub and isinstance(sub[0],
                                                                ast.stmt):
                    scan(sub, where)
            for h in getattr(n, "handlers", []) or []:
                scan(h.body, where)

    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scan(n.body, n.name)
    check("no unreachable statements", not dead, "; ".join(dead[:6]))


# -- tr, since the audit pointed at it -----------------------------------

def t_tr_still_matches_the_real_one():
    s = shell()
    for cmd, want in (("echo abc | tr abc ABC", "ABC"),
                      ("echo abc | tr a-c A-C", "ABC"),
                      ("echo aabbcc | tr -s ab", "abcc"),
                      ("echo abc123 | tr -d 0-9", "abc"),
                      ("echo abc123 | tr -dc 0-9", "123"),
                      ("echo abc123 | tr -cd a-z", "abc"),
                      ("echo ABC | tr '[:upper:]' '[:lower:]'", "abc"),
                      ("echo abc | tr -c abc X", "abcX"),
                      ("echo abcdef | tr a-f A-C", "ABCCCC")):
        eq(cmd[:38], out(s, cmd), want)


TESTS = [t_backgrounding_starts_one_process, t_the_foreground_case_is_unchanged,
         t_ps_shows_the_argv_not_the_redirections,
         t_two_launches_are_two_processes, t_pgrep_counts_it_once,
         t_dollar_bang_is_the_process,
         t_jobs_still_lists_it_with_the_full_command, t_job_numbering,
         t_kill_by_jobspec_ends_it, t_kill_by_jobspec_clears_proc_too,
         t_kill_by_pid_and_by_jobspec_agree, t_killing_one_job_leaves_the_other,
         t_an_unknown_jobspec_is_still_an_error,
         t_no_self_reference_is_undefined, t_no_unreachable_code,
         t_tr_still_matches_the_real_one]


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
