r"""Word splitting: "$@" versus $@ versus "$*", and whether IFS matters.

Forty-second coherence sweep. The axis is field splitting, which decides
how many arguments a command actually receives -- and srb.sh walks its
kill-list with `for tool in "${TOOLS_TO_REMOVE[@]}"`, so the box has to
get the quoted and unquoted forms apart.

Four faults, and one of them was the shell disagreeing with itself:

  * `"$*"` and `"${a[*]}"` were treated exactly like "$@": one word per
    element rather than a single word joined by IFS. So
    `printf '%s\n' "$*"` printed a line per parameter where bash prints
    one, and `IFS=-; echo "$*"` printed "a b" instead of "a-b".
  * Unquoted `$@` in a for list was treated as the quoted form, so
    `for x in $@` over one/"two three"/four ran three times instead of
    four -- while `printf '%s\n' $@` on the same parameters produced four
    words. Two code paths, two answers, same shell, same expansion.
  * IFS was honoured by read and by nothing else. `IFS=:; for x in $v`
    over "a:b:c" ran once with the colons still in it, which is the exact
    thing setting IFS is for.
  * The for list expanded the whole word string and then split it on
    whitespace, so quoting information was gone before splitting happened.
    Raw words are split first now and each expanded on its own, the way
    the argv path already did it.

Measured and left alone: `v=""; printf "%s\n" $v | wc -l` is 1 on the
guest, not 0 -- printf prints its format once with no arguments. The
first draft of this suite asserted 0 and would have "fixed" correct
behaviour.

Reference measured on the guest, as root, with
set -- one "two three" four; A=(x "y z" w):

    printf '%s\n' "$@"      3 lines      printf '%s\n' $@   4 lines
    printf '%s\n' "$*"      1 line       printf '%s\n' $*   4 lines
    printf '%s\n' "${A[*]}" 1 line
    for x in "$@"           [one] [two three] [four]
    for x in $@             [one] [two] [three] [four]
    IFS=:; for x in $v      [a] [b] [c]      (v=a:b:c)
    IFS=:; echo "$v"        [a:b:c]
    set -- a b; IFS=-; echo "$*"           a-b

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []

S = 'set -- one "two three" four; A=(x "y z" w); '


def run(script):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
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
    eq("out: %s" % script[-44:], out.strip(), want)
    eq("rc:  %s" % script[-44:], got_rc, rc)


# -- how many words come out --------------------------------------------

def t_word_counts():
    case(S + 'printf "%s\\n" "$@" | wc -l', "3")
    case(S + 'printf "%s\\n" $@ | wc -l', "4")
    case(S + 'printf "%s\\n" "$*" | wc -l', "1")
    case(S + 'printf "%s\\n" $* | wc -l', "4")
    case(S + 'printf "%s\\n" "${A[@]}" | wc -l', "3")
    case(S + 'printf "%s\\n" "${A[*]}" | wc -l', "1")
    case(S + 'printf "%s\\n" ${A[@]} | wc -l', "4")
    case(S + "echo $#", "3")


def t_the_two_paths_agree():
    """A for list and an argv list must split a word the same way."""
    for expansion, n in (('"$@"', 3), ("$@", 4), ('"$*"', 1)):
        argv, _ = run(S + 'printf "%%s\\n" %s | wc -l' % expansion)
        loop, _ = run(S + 'n=0; for x in %s; do n=$((n+1)); done; echo $n'
                      % expansion)
        eq("argv and for agree on %s" % expansion, argv.strip(), loop.strip())
        eq("and both say %d for %s" % (n, expansion), argv.strip(), str(n))


# -- boundaries are preserved or not, on purpose -------------------------

def t_for_quoted_keeps_boundaries():
    case(S + 'for x in "$@"; do printf "[%s]" "$x"; done; echo',
         "[one][two three][four]")
    case(S + 'for x in "${A[@]}"; do printf "[%s]" "$x"; done; echo',
         "[x][y z][w]")


def t_for_unquoted_resplits():
    case(S + 'for x in $@; do printf "[%s]" "$x"; done; echo',
         "[one][two][three][four]")
    case(S + 'for x in ${A[@]}; do printf "[%s]" "$x"; done; echo',
         "[x][y][z][w]")


def t_star_is_one_word():
    case(S + 'for x in "$*"; do printf "[%s]" "$x"; done; echo',
         "[one two three four]")
    case(S + 'for x in "${A[*]}"; do printf "[%s]" "$x"; done; echo',
         "[x y z w]")


# -- IFS ------------------------------------------------------------------

def t_ifs_splits_unquoted():
    case('IFS=:; v="a:b:c"; for x in $v; do printf "[%s]" "$x"; done; echo',
         "[a][b][c]")
    case('IFS=:; v="a:b:c"; printf "%s\\n" $v | wc -l', "3")


def t_ifs_does_not_split_quoted():
    case('IFS=:; v="a:b:c"; echo "[$v]"', "[a:b:c]")
    case('IFS=:; v="a:b:c"; for x in "$v"; do printf "[%s]" "$x"; done; echo',
         "[a:b:c]")


def t_ifs_joins_star():
    case('set -- a b; IFS=-; echo "$*"', "a-b")
    case('set -- a b; echo "$*"', "a b")
    case('A=(p q); IFS=,; echo "${A[*]}"', "p,q")


def t_default_splitting_is_whitespace():
    case('v="a b c"; for x in $v; do printf "[%s]" "$x"; done; echo',
         "[a][b][c]")
    case('v="a  b"; printf "%s\\n" $v | wc -l', "2")
    case('v="a  b"; printf "%s\\n" "$v" | wc -l', "1")


def t_printf_with_no_arguments():
    """Measured on the guest: one line, not zero."""
    case('v=""; printf "%s\\n" $v | wc -l', "1")


# -- the rest of the for list must be unchanged --------------------------

def t_ordinary_for_lists():
    case('for x in one two; do printf "[%s]" "$x"; done; echo', "[one][two]")
    case('for i in {1..3}; do printf "%s" "$i"; done; echo', "123")
    case('for x in "a b" c; do printf "[%s]" "$x"; done; echo', "[a b][c]")
    case('mkdir -p /tmp/fg; touch /tmp/fg/a /tmp/fg/b; '
         'for f in /tmp/fg/*; do printf "[%s]" "$f"; done; echo',
         "[/tmp/fg/a][/tmp/fg/b]")


def t_the_installers_own_loop():
    case('TOOLS=("/bin/ps" "/usr/bin/top" "/usr/bin/pkill"); '
         'for t in "${TOOLS[@]}"; do printf "[%s]" "$t"; done; echo',
         "[/bin/ps][/usr/bin/top][/usr/bin/pkill]")


def t_shift_and_positional():
    case(S + 'shift; echo "$# $1"', "2 two three")
    case(S + 'echo "$1|$2|$3"', "one|two three|four")


def t_quotes_inside_a_substitution_are_not_the_words_quotes():
    """`$(cmd "arg")` is an unquoted expansion and still splits.

    The test for "is this expansion quoted" was whether the word contained a
    quote character anywhere, which is a different question: the quotes in
    `$(ls | grep "x")` belong to the inner command. So the most common idiom
    in shell ran exactly once with the whole multi-line result as a single
    item, and `set -- $(echo "one two")` set $# to 1 where bash sets 2. It
    was found by writing a loop of that shape against the live box and
    getting one iteration.
    """
    pre = "printf 'a/bin/x\\nb/sbin/y\\nc/bin/z\\n' > /tmp/_st; "
    case(pre + 'set -- $(grep -E "bin" /tmp/_st); echo $#', "3")
    case(pre + 'set -- $(grep -E bin /tmp/_st); echo $#', "3")
    case(pre + "set -- $(grep -E 'bin' /tmp/_st); echo $#", "3")
    case(pre + 'n=0; for f in $(grep -E "bin" /tmp/_st); do n=$((n+1)); '
               'done; echo $n', "3")
    case('set -- $(echo "one two"); echo $#', "2")
    case('set -- $(echo one two); echo $#', "2")
    case('set -- "$(echo one two)"; echo $#', "1")
    case('set -- "quoted lit" $(echo p q); echo $#', "3")
    # ...and the quoted forms still do not split.
    case('v="a b"; set -- "$v"; echo $#', "1")
    case('v="a b"; set -- $v; echo $#', "2")
    case('echo $(echo "a"; echo "b")', "a b")
    case('printf "%s\\n" "$(echo a; echo b)" | wc -l', "2")
    case('set -- ${HOME}/x; echo $#', "1")
    case('set -- $(echo "a b" | tr " " "\\n"); echo $#', "2")



TESTS = [t_word_counts, t_the_two_paths_agree,
         t_for_quoted_keeps_boundaries, t_for_unquoted_resplits,
         t_star_is_one_word, t_ifs_splits_unquoted,
         t_ifs_does_not_split_quoted, t_ifs_joins_star,
         t_default_splitting_is_whitespace, t_printf_with_no_arguments,
         t_ordinary_for_lists, t_the_installers_own_loop,
         t_shift_and_positional,
         t_quotes_inside_a_substitution_are_not_the_words_quotes]


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
