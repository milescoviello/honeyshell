r"""The user databases disagreed once anything changed.

Fifty-sixth coherence sweep. useradd, usermod and password_set are all
tracked here as persistence events, and every actor cats /etc/passwd, so:
do the commands that answer "who is this account and what can it do"
agree with each other and with the files?

At rest they did, and that is pinned rather than changed: id, groups,
getent passwd/group, /etc/passwd, /etc/group and /etc/shadow all agree,
the three files have the same 25 users, and every gid in passwd exists
in group.

Once an account was created or removed, they stopped agreeing.

  1. groups(1) was a three-branch lookup table -- root, deploy, and "your
     own name" for anyone else -- so it was right only for the two
     accounts that shipped with the persona. After `usermod -aG sudo bob`
     /etc/group listed bob in sudo and `id bob` said sudo, while
     `groups bob` still said just bob. Two commands whose whole job is to
     answer the same question, disagreeing about the account the attacker
     had just given sudo to.

  2. `useradd -m` left the new home owned by root:root, so `id bob`
     reported uid 1001 and the directory that account is supposed to own
     belonged to someone else. The mode was already right and stays:
     this box's login.defs sets no HOME_MODE and UMASK 022, so useradd
     makes 0755. (The seeded /home/deploy is 0700 because adduser made
     it, not useradd -- the two tools genuinely differ, and that is not
     the inconsistency.)

  3. `ls -l`, `stat` and `find -user` resolved uids through a static
     table compiled into the emulator, not through /etc/passwd. A new
     user's home printed a bare "1001" while `id` called the same number
     1001(bob) in the same session.

  4. gpasswd ignored -a and -d entirely and answered every invocation
     with "Changing the password for group" and a PAM failure. It is one
     of the two ordinary ways to grant sudo; the other, usermod -aG,
     worked. Same request, two answers.

  5. userdel rewrote /etc/passwd and nothing else, so a deleted account
     kept its hash in /etc/shadow, stayed listed in sudo in /etc/group,
     and kept its home on disk -- three databases naming a user `id`
     said did not exist. -r did not remove the home it exists to remove.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(s, cmd):
    r = s.run(cmd)
    r += "".join(s._err)
    s._err.clear()
    return r.strip()


# -- at rest -------------------------------------------------------------

def t_the_three_files_describe_the_same_people():
    s = shell()
    pw = out(s, "cut -d: -f1 /etc/passwd | sort").split()
    sh = out(s, "cut -d: -f1 /etc/shadow | sort").split()
    eq("passwd and shadow hold the same users", sh, pw)
    eq("getent passwd matches the file",
       out(s, "getent passwd | wc -l"), out(s, "wc -l < /etc/passwd"))
    eq("getent group matches the file",
       out(s, "getent group | wc -l"), out(s, "wc -l < /etc/group"))


def t_every_primary_gid_exists():
    s = shell()
    missing = out(s, "while IFS=: read -r u x uid gid rest; do "
                     "getent group \"$gid\" >/dev/null || echo $u; "
                     "done < /etc/passwd")
    eq("no user has a gid with no group", missing, "")


def t_id_and_groups_agree_for_seeded_accounts():
    s = shell()
    for user in ("root", "deploy"):
        by_id = out(s, "id -Gn %s" % user).split()
        by_groups = out(s, "groups %s" % user).split(":", 1)[1].split()
        eq("id vs groups: %s" % user, by_groups, by_id)


# -- creating an account -------------------------------------------------

def t_useradd_home_is_owned_by_the_new_user():
    s = shell()
    out(s, "useradd -m -s /bin/bash bob")
    line = out(s, "ls -ld /home/bob").split()
    eq("home owner", line[2], "bob")
    eq("home group", line[3], "bob")
    # HOME_MODE, not the umask: Debian's login.defs sets 0700 and useradd
    # prefers it. The file here had eight directives and no HOME_MODE, so
    # the umask was the only rule there was and a new home came out 0755
    # beside a /home/deploy of 0700. See skeltest.
    eq("home mode from login.defs HOME_MODE 0700",
       out(s, "stat -c '%a' /home/bob"), "700")


def t_a_new_uid_resolves_to_its_name_everywhere():
    s = shell()
    out(s, "useradd -m -s /bin/bash bob")
    eq("ls -l names the owner",
       out(s, "ls -ld /home/bob").split()[2], "bob")
    eq("stat -c %U", out(s, "stat -c '%U' /home/bob"), "bob")
    eq("stat -c %G", out(s, "stat -c '%G' /home/bob"), "bob")
    eq("find -user finds it",
       out(s, "find /home -maxdepth 1 -user bob"), "/home/bob")
    eq("find -printf %u",
       out(s, "find /home -maxdepth 1 -user bob -printf '%u:%g\\n'"),
       "bob:bob")
    check("id agrees", "1001(bob)" in out(s, "id bob"), out(s, "id bob"))


def t_useradd_writes_all_three_files():
    s = shell()
    out(s, "useradd -m -s /bin/bash bob")
    check("in passwd", out(s, "grep -c '^bob:' /etc/passwd") == "1", "")
    check("in shadow", out(s, "grep -c '^bob:' /etc/shadow") == "1", "")
    check("private group", out(s, "getent group bob") != "", "")
    check("getent passwd finds it", out(s, "getent passwd bob") != "", "")


def t_the_private_group_takes_a_free_gid():
    """An occupied gid must not hand the account somebody else's group."""
    s = shell()
    out(s, "groupadd -g 1001 squatter")
    out(s, "useradd -m bob")
    check("bob has his own group", out(s, "getent group bob") != "", "")
    check("not squatter's", "squatter" not in out(s, "id bob"),
          out(s, "id bob"))
    eq("home group", out(s, "stat -c '%G' /home/bob"), "bob")


def t_dash_g_accepts_a_group_name():
    """`useradd -g sudo` is the difference between an ordinary account and
    one that can sudo; only digits used to be accepted."""
    s = shell()
    out(s, "useradd -m -g sudo carol")
    check("primary group is sudo", "gid=27(sudo)" in out(s, "id carol"),
          out(s, "id carol"))
    eq("groups agrees", out(s, "groups carol"), "carol : sudo")
    out(s, "useradd -m -g 27 dave")
    check("numeric -g still works", "gid=27(sudo)" in out(s, "id dave"),
          out(s, "id dave"))
    r = out(s, "useradd -m -g nosuchgrp eve")
    check("unknown group refused", "does not exist" in r, r)


def t_uids_stay_unique():
    s = shell()
    out(s, "useradd -m bob; useradd -m carol")
    eq("no duplicate uid", out(s, "cut -d: -f3 /etc/passwd | sort | uniq -d"),
       "")


# -- granting a group ----------------------------------------------------

def t_usermod_shows_up_in_both_commands():
    s = shell()
    out(s, "useradd -m bob; usermod -aG sudo bob")
    by_id = out(s, "id -Gn bob").split()
    by_groups = out(s, "groups bob").split(":", 1)[1].split()
    eq("id sees sudo", sorted(by_id), ["bob", "sudo"])
    eq("groups agrees with id", sorted(by_groups), sorted(by_id))
    check("/etc/group lists bob", "bob" in out(s, "getent group sudo"),
          out(s, "getent group sudo"))


def t_gpasswd_add_works_like_usermod():
    s = shell()
    out(s, "useradd -m bob; groupadd wheel")
    res = out(s, "gpasswd -a bob wheel")
    check("gpasswd reports the add", "added to group" in res, res)
    check("no PAM failure", "PAM" not in res, res)
    by_id = out(s, "id -Gn bob").split()
    check("id sees wheel", "wheel" in by_id, str(by_id))
    by_groups = out(s, "groups bob").split(":", 1)[1].split()
    eq("groups agrees", sorted(by_groups), sorted(by_id))


def t_gpasswd_delete_works():
    s = shell()
    out(s, "useradd -m bob; groupadd wheel; gpasswd -a bob wheel")
    out(s, "gpasswd -d bob wheel")
    check("wheel is gone from id", "wheel" not in out(s, "id -Gn bob"),
          out(s, "id -Gn bob"))
    check("and from /etc/group", "bob" not in out(s, "getent group wheel"),
          out(s, "getent group wheel"))


def t_gpasswd_rejects_what_does_not_exist():
    s = shell()
    r = out(s, "gpasswd -a nosuchuser sudo")
    check("unknown user refused", "does not exist" in r, r)
    out(s, "useradd -m bob")
    r = out(s, "gpasswd -a bob nosuchgroup")
    check("unknown group refused", "does not exist" in r, r)


# -- removing an account -------------------------------------------------

def t_groupdel_actually_removes_the_group():
    """groupadd wrote the file and groupdel returned 0 without touching it."""
    s = shell()
    out(s, "groupadd wheel")
    check("groupadd took effect", out(s, "getent group wheel") != "", "")
    out(s, "groupdel wheel")
    eq("groupdel took effect", out(s, "getent group wheel"), "")


def t_groupdel_refuses_a_primary_group():
    s = shell()
    out(s, "useradd -m bob")
    r = out(s, "groupdel bob")
    check("refused", "primary group" in r, r)
    check("group survives", out(s, "getent group bob") != "", "")
    r = out(s, "groupdel nosuchgroup")
    check("unknown group reported", "does not exist" in r, r)


def t_userdel_clears_every_database():
    s = shell()
    out(s, "useradd -m bob; usermod -aG sudo bob")
    out(s, "userdel bob")
    eq("gone from passwd", out(s, "grep -c '^bob:' /etc/passwd"), "0")
    eq("gone from shadow", out(s, "grep -c '^bob:' /etc/shadow"), "0")
    check("private group gone", out(s, "getent group bob") == "",
          out(s, "getent group bob"))
    check("stripped from sudo", "bob" not in out(s, "getent group sudo"),
          out(s, "getent group sudo"))
    check("id no longer knows it", "no such user" in out(s, "id bob"),
          out(s, "id bob"))
    check("groups no longer knows it",
          "no such user" in out(s, "groups bob"), out(s, "groups bob"))


def t_userdel_r_removes_the_home():
    s = shell()
    out(s, "useradd -m bob")
    check("home exists first", out(s, "test -d /home/bob && echo y") == "y", "")
    out(s, "userdel -r bob")
    eq("home removed", out(s, "test -d /home/bob || echo gone"), "gone")


def t_userdel_without_r_keeps_the_home():
    s = shell()
    out(s, "useradd -m bob")
    out(s, "userdel bob")
    eq("home kept", out(s, "test -d /home/bob && echo kept"), "kept")


def t_userdel_of_an_unknown_user():
    s = shell()
    r = out(s, "userdel nosuchuser")
    check("reports it", "does not exist" in r, r)


def t_a_deleted_user_leaves_no_trace_in_any_view():
    """The whole point: no database may name someone id denies."""
    s = shell()
    out(s, "useradd -m bob; usermod -aG sudo bob; userdel -r bob")
    for probe in ("getent passwd bob", "getent group bob",
                  "grep '^bob:' /etc/shadow"):
        eq("silent: %s" % probe, out(s, probe), "")
    check("not in any group line",
          out(s, "grep -c bob /etc/group") in ("0", ""),
          out(s, "grep bob /etc/group"))


# -- the seeded persona must not have moved ------------------------------

def t_seeded_accounts_unchanged():
    s = shell()
    eq("deploy home", out(s, "ls -ld /home/deploy").split()[2], "deploy")
    eq("deploy mode", out(s, "stat -c '%a' /home/deploy"), "700")
    eq("root files", out(s, "stat -c '%U %G' /etc/passwd"), "root root")
    eq("id deploy", out(s, "id -Gn deploy"), "deploy sudo")
    eq("groups deploy", out(s, "groups deploy"), "deploy : deploy sudo")


TESTS = [t_the_three_files_describe_the_same_people,
         t_every_primary_gid_exists, t_id_and_groups_agree_for_seeded_accounts,
         t_useradd_home_is_owned_by_the_new_user,
         t_a_new_uid_resolves_to_its_name_everywhere,
         t_useradd_writes_all_three_files,
         t_the_private_group_takes_a_free_gid,
         t_dash_g_accepts_a_group_name, t_uids_stay_unique,
         t_usermod_shows_up_in_both_commands, t_gpasswd_add_works_like_usermod,
         t_gpasswd_delete_works, t_gpasswd_rejects_what_does_not_exist,
         t_groupdel_actually_removes_the_group,
         t_groupdel_refuses_a_primary_group,
         t_userdel_clears_every_database, t_userdel_r_removes_the_home,
         t_userdel_without_r_keeps_the_home, t_userdel_of_an_unknown_user,
         t_a_deleted_user_leaves_no_trace_in_any_view,
         t_seeded_accounts_unchanged]


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
