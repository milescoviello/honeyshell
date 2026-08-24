r"""How execution fails, and what the box says about it.

Fifty-third coherence sweep. The axis came from the traffic. An operator
now seen from four addresses (203.0.113.34, 203.0.113.31, 203.0.113.32 and
203.0.113.42) sends a recon script with a section literally labelled
===SHELL_BEHAVIOR=== which harvests, verbatim:

    path_err=     the error for executing a path that does not exist
    cmd_err=      the error for a command that does not exist
    execute_err=  whether write + chmod +x + ./run actually works

It writes a 26-byte /root/filter -- `#!/bin/bash` and `echo "xxxxxx"` --
runs it, and checks the output is xxxxxx. That is a fingerprint of the
shell's failure modes, so: do the several ways a command can fail agree
with each other, and with bash?

The two it asks about were right. The ones next to them were not.

  1. `line N: `. Non-interactive bash prefixes every exec error with the
     physical line. "No such file or directory" and "Exec format error"
     had it; "Is a directory" and "Permission denied" did not. Two paths
     to a failed exec, two formats, in the one shell whose prefix this
     bot is collecting.

  2. Exit codes from scripts were hardcoded to 0. `./x` returned 0
     whatever the script did -- `exit 7` gave 0, `false` gave 0. Every
     dropper on this box writes `chmod +x x && ./x && rm x`, and that
     chain took the success branch unconditionally.

  3. The shebang was discarded and the body run as bash regardless. A
     script naming an interpreter that does not exist printed its output
     and returned 0, where bash refuses with rc 127 and "cannot execute:
     required file not found". Nothing consulted the interpreter at all,
     so a python or perl stager silently ran as shell.

  4. `#!/usr/bin/env missing` produced the same silent success. env
     resolves through PATH and complains in its own voice, not bash's.

Reference measured against real bash 5.2, which is what this persona
claims. Note the 5.2 wording: "cannot execute: required file not found",
not the older "bad interpreter".

    ./noexec    bash: line N: ./noexec: Permission denied            126
    ./adir      bash: line N: ./adir: Is a directory                 126
    ./badshb    bash: line N: ./badshb: cannot execute: required
                file not found                                      127
    ./envbad    /usr/bin/env: 'nosuchinterp': No such file or dir    127
    ./fakeelf   bash: line N: ./fakeelf: cannot execute binary
                file: Exec format error                             126

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script, user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="203.0.113.77")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


PRE = "cd /tmp && rm -rf ex && mkdir ex && cd ex && "


def case(setup, invoke, want_err, want_rc):
    out, rc = run(PRE + setup + " && " + invoke)
    eq("out: %s" % invoke[:36], out.strip(), want_err)
    eq("rc:  %s" % invoke[:36], rc, want_rc)


# -- the three the bot actually asks for ---------------------------------

def t_path_err():
    out, rc = run("./xxxxxx")
    eq("path_err text", out.strip(),
       "bash: line 1: ./xxxxxx: No such file or directory")
    eq("path_err rc", rc, 127)


def t_cmd_err():
    out, rc = run("xxxxxx")
    eq("cmd_err text", out.strip(), "bash: line 1: xxxxxx: command not found")
    eq("cmd_err rc", rc, 127)


def t_execute_err_the_filter_probe():
    """The exact write-chmod-run the operator uses, byte for byte."""
    out, rc = run("cd /root && printf '#!/bin/bash\\necho \"xxxxxx\"\\n' "
                  "> filter && chmod +x filter && ./filter && rm -rf filter")
    eq("filter probe output", out.strip(), "xxxxxx")
    eq("filter probe rc", rc, 0)
    out, _ = run("cd /root && printf '#!/bin/bash\\necho \"xxxxxx\"\\n' "
                 "> filter && chmod +x filter && ./filter && rm -rf filter && "
                 "ls filter 2>&1")
    check("the probe cleans up after itself",
          "No such file" in out or "cannot access" in out, out[:70])


# -- every exec error carries the line prefix ----------------------------

def t_permission_denied_has_the_prefix():
    case("echo hi > noexec && chmod 644 noexec", "./noexec",
         "bash: line 1: ./noexec: Permission denied", 126)


def t_is_a_directory_has_the_prefix():
    case("mkdir adir", "./adir",
         "bash: line 1: ./adir: Is a directory", 126)


def t_every_exec_error_is_formatted_the_same_way():
    """One shell must not have two error formats."""
    cases = [("echo hi > f1 && chmod 644 f1", "./f1"),
             ("mkdir d1", "./d1"),
             ("printf '\\x7fELFjunk' > f2 && chmod +x f2", "./f2"),
             ("true", "./nothing-here")]
    for setup, invoke in cases:
        out, _ = run(PRE + setup + " && " + invoke)
        check("prefixed: %s" % invoke,
              out.startswith("bash: line "), out[:70])


def t_exec_format_error_still_right():
    case("printf '\\x7fELFjunk' > fake && chmod +x fake", "./fake",
         "bash: line 1: ./fake: cannot execute binary file: "
         "Exec format error", 126)


# -- exit codes come from the script -------------------------------------

def t_script_exit_code_propagates():
    for code in (0, 1, 7, 42):
        out, rc = run(PRE + "printf '#!/bin/bash\\nexit %d\\n' > s && "
                            "chmod +x s && ./s" % code)
        eq("exit %d propagates" % code, rc, code)


def t_script_failure_breaks_an_and_chain():
    """chmod +x x && ./x && rm x is the shape every dropper uses."""
    out, rc = run(PRE + "printf '#!/bin/bash\\nexit 3\\n' > s && chmod +x s "
                        "&& ./s && echo REACHED")
    check("&& stops on a failing script", "REACHED" not in out, out[:60])
    eq("chain rc", rc, 3)
    out, rc = run(PRE + "printf '#!/bin/bash\\nexit 0\\n' > s && chmod +x s "
                        "&& ./s && echo REACHED")
    check("&& continues on success", "REACHED" in out, out[:60])


def t_false_inside_a_script():
    out, rc = run(PRE + "printf '#!/bin/bash\\nfalse\\n' > s && chmod +x s "
                        "&& ./s")
    eq("last command's rc is the script's", rc, 1)


# -- the interpreter is consulted ----------------------------------------

def t_missing_interpreter_refuses():
    case("printf '#!/nope/interp\\necho x\\n' > b && chmod +x b", "./b",
         "bash: line 1: ./b: cannot execute: required file not found", 127)


def t_missing_interpreter_does_not_run_the_body():
    out, _ = run(PRE + "printf '#!/nope/interp\\necho SHOULD-NOT-RUN\\n' > b "
                       "&& chmod +x b && ./b")
    check("body did not run", "SHOULD-NOT-RUN" not in out, out[:70])


def t_env_shebang_missing_target():
    case("printf '#!/usr/bin/env nosuchinterp\\necho x\\n' > c && chmod +x c",
         "./c", "/usr/bin/env: 'nosuchinterp': No such file or directory", 127)


def t_env_shebang_speaks_as_env_not_bash():
    out, _ = run(PRE + "printf '#!/usr/bin/env nosuchinterp\\necho x\\n' > c "
                       "&& chmod +x c && ./c")
    check("env, not bash, reports it", out.startswith("/usr/bin/env:"),
          out[:70])


def t_real_shebangs_still_work():
    for interp in ("/bin/bash", "/bin/sh", "/usr/bin/env bash"):
        out, rc = run(PRE + "printf '#!%s\\necho ran-ok\\n' > g && "
                            "chmod +x g && ./g" % interp)
        eq("#!%s runs" % interp, out.strip(), "ran-ok")
        eq("#!%s rc" % interp, rc, 0)


def t_no_shebang_runs_as_shell():
    out, rc = run(PRE + "printf 'echo no-shebang-ok\\n' > h && chmod +x h "
                        "&& ./h")
    eq("no shebang still runs", out.strip(), "no-shebang-ok")
    eq("no shebang rc", rc, 0)


def t_a_later_hashbang_is_just_a_comment():
    out, _ = run(PRE + "printf '#!/bin/bash\\necho one\\n#!/nope/x\\n"
                       "echo two\\n' > i && chmod +x i && ./i")
    eq("both lines ran", out.split(), ["one", "two"])


# -- the shell's own name and args ---------------------------------------

def t_a_script_knows_its_name_and_args():
    out, _ = run(PRE + "printf '#!/bin/bash\\necho z=$0 one=$1 n=$#\\n' > j "
                       "&& chmod +x j && ./j alpha beta")
    eq("$0/$1/$# inside a script", out.strip(), "z=./j one=alpha n=2")


TESTS = [t_path_err, t_cmd_err, t_execute_err_the_filter_probe,
         t_permission_denied_has_the_prefix, t_is_a_directory_has_the_prefix,
         t_every_exec_error_is_formatted_the_same_way,
         t_exec_format_error_still_right, t_script_exit_code_propagates,
         t_script_failure_breaks_an_and_chain, t_false_inside_a_script,
         t_missing_interpreter_refuses,
         t_missing_interpreter_does_not_run_the_body,
         t_env_shebang_missing_target, t_env_shebang_speaks_as_env_not_bash,
         t_real_shebangs_still_work, t_no_shebang_runs_as_shell,
         t_a_later_hashbang_is_just_a_comment,
         t_a_script_knows_its_name_and_args]


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
