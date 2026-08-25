#!/usr/bin/env python3
"""What runs at login, and the variable it tests.

Sweep 150. /etc/profile sources /etc/profile.d on every login shell, and ours
held exactly one entry: a symlink to
/usr/lib/systemd/profile.d/70-systemd-shell-extra.sh whose target did not
exist. So the box sourced a dangling link at every login, where a real cloud
image has three files.

Installing the three exposed the next thing, the same way run-parts did in
sweep 146: they *execute*, and one of them gates on a variable this shell did
not have.

    /etc/profile.d/bash_completion.sh:
        if [ "${BASH_VERSINFO[0]}" -gt 4 ] ||
           [ "${BASH_VERSINFO[0]}" -eq 4 -a "${BASH_VERSINFO[1]}" -ge 2 ]

`BASH_VERSINFO` was absent entirely: `${BASH_VERSINFO[0]}` printed nothing
where the guest prints 5, and `${#BASH_VERSINFO[@]}` gave 0 against its 6. So
the version check took the wrong branch and completion was never loaded --
and any script asking the bash major version got the same wrong answer.

It is derived from BASH_VERSION rather than written out, so the two cannot
drift. BASH_VERSION already matched the guest exactly, which is what makes
the derivation land on the guest's array without copying it.

One trap worth recording. "No output" from a newly-sourced script looks
identical to "the script ran cleanly", so the constructs those three files use
were checked individually against the host's bash rather than inferred from a
quiet login. Two of the four apparent differences in that check were the
harness -- bash -c is non-interactive so PS1 is unset, and the two shells have
different HOME -- and only BASH_VERSINFO was real.

Run from `honeypot/`.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


def sh(user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="198.51.100.7")
    del s._err[:]
    return s


def run(s, cmd):
    out = s.run(cmd)
    del s._err[:]
    return out


# -- the directory ------------------------------------------------------

def t_profile_d_holds_the_guests_three():
    s = sh()
    listing = sorted(run(s, "ls /etc/profile.d").split())
    eq("three entries, as the guest has", listing,
       ["70-systemd-shell-extra.sh", "Z99-cloud-locale-test.sh",
        "bash_completion.sh"])


def t_the_symlink_resolves():
    """It was a link to nothing, sourced on every login."""
    s = sh()
    listing = run(s, "ls -l /etc/profile.d/70-systemd-shell-extra.sh")
    check("it is still a symlink", "->" in listing, listing[:70])
    check("and the target exists now",
          run(s, "test -f /usr/lib/systemd/profile.d/"
                 "70-systemd-shell-extra.sh && echo yes").strip() == "yes")
    eq("the target has the guest's size",
       len(run(s, "cat /usr/lib/systemd/profile.d/"
                  "70-systemd-shell-extra.sh")), 855)


def t_the_other_two_have_the_guests_sizes():
    s = sh()
    for name, size in (("Z99-cloud-locale-test.sh", 2664),
                       ("bash_completion.sh", 747)):
        eq("%s size" % name, len(run(s, "cat /etc/profile.d/" + name)), size)


def t_a_login_shell_is_quiet():
    """Sourcing three real scripts must not print anything. This is how the
    run-parts gap announced itself in sweep 146 -- usage text after the uid."""
    for user in ("root", "deploy"):
        s = sh(user)
        out = s.run("bash -lc 'echo MARKER'")
        err = "".join(s._err)
        del s._err[:]
        eq("%s: login shell output is just the marker" % user,
           out.strip(), "MARKER")
        eq("%s: and nothing on stderr" % user, err, "")


# -- the variable one of them tests --------------------------------------

GUEST_VERSINFO = ["5", "2", "37", "1", "release", "x86_64-pc-linux-gnu"]


def t_bash_versinfo_matches_the_guest():
    s = sh()
    eq("the whole array", run(s, 'echo "${BASH_VERSINFO[@]}"').strip(),
       " ".join(GUEST_VERSINFO))
    eq("length", run(s, 'echo "${#BASH_VERSINFO[@]}"').strip(), "6")
    for i, want in enumerate(GUEST_VERSINFO):
        eq("element %d" % i,
           run(s, 'echo "${BASH_VERSINFO[%d]}"' % i).strip(), want)


def t_the_scalar_view_works_too():
    """`$a` and `${a}` give element 0 for any array. Seeding the array without
    the scalar left `echo $BASH_VERSINFO` empty while the subscript worked --
    two spellings of one variable disagreeing."""
    s = sh()
    eq("bare $BASH_VERSINFO", run(s, 'echo "$BASH_VERSINFO"').strip(), "5")
    eq("braced ${BASH_VERSINFO}",
       run(s, 'echo "${BASH_VERSINFO}"').strip(), "5")


def t_it_is_derived_from_bash_version():
    """Not written out twice. BASH_VERSION already agreed with the guest and
    with `bash --version`; the array comes from it, so they cannot drift."""
    s = sh()
    ver = run(s, 'echo "$BASH_VERSION"').strip()
    eq("BASH_VERSION", ver, "5.2.37(1)-release")
    major, minor, patch = ver.split("(")[0].split(".")
    eq("array[0] is the major", run(s, 'echo "${BASH_VERSINFO[0]}"').strip(),
       major)
    eq("array[1] is the minor", run(s, 'echo "${BASH_VERSINFO[1]}"').strip(),
       minor)
    eq("array[2] is the patch", run(s, 'echo "${BASH_VERSINFO[2]}"').strip(),
       patch)


def t_it_is_not_exported():
    """Real bash keeps it a shell variable. Exporting it would show up in
    `env` on a box where the real one does not."""
    s = sh()
    eq("env does not carry it",
       run(s, "env | grep -c BASH_VERSINFO").strip(), "0")


def t_the_completion_gate_takes_the_right_branch():
    """The concrete consequence: this is the test bash_completion.sh runs."""
    s = sh()
    eq("version gate", run(
        s, '[ "${BASH_VERSINFO[0]}" -gt 4 ] && echo newer || echo older'
    ).strip(), "newer")


def t_the_constructs_those_scripts_use():
    """Checked against the host's bash, because a script that silently does
    nothing looks exactly like one that ran."""
    s = sh()
    for script, want in (
            ('unset Y; echo "[${Y-default}]"', "[default]"),
            ('X=; echo "[${X-default}]"', "[]"),
            ('shopt -q progcomp && echo on || echo off', "on"),
            ('SHELL_WELCOME="a\\nb"; printf %b\\\\n "$SHELL_WELCOME"', "a\nb")):
        eq("construct %s" % script[:34], run(s, script).strip(), want)


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("t_") and callable(fn):
            try:
                fn()
            except Exception as exc:                          # noqa: BLE001
                check(name, False, "crashed: %r" % (exc,))
    print("\npassed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
