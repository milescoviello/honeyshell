r"""The disk and the swap: two commands describing another machine.

Sixty-fifth coherence sweep. Miners add swap when the box is short of
RAM -- `fallocate -l 1G /swapfile; mkswap; swapon` is the recipe in half
the installers -- so: do the commands that describe the disk and its swap
agree with each other?

Two of them described a different computer entirely.

  1. `fdisk -l` claimed a 16 GiB disk with a DOS label, an sda1 of 15G,
     no sda14 or sda15, and a /dev/sda2 "Linux swap" partition. lsblk,
     /proc/partitions, /sys/block/sda/size and df all say 64 GiB with
     sda1 at 63G plus sda14 and sda15 -- and sda15 is mounted at
     /boot/efi, which only a GPT disk has. There is no sda2 anywhere
     else on the box.

  2. `swapon --show` answered every invocation with that same invented
     /dev/sda2, 975M, while /proc/swaps was empty, `free` and
     /proc/meminfo both reported no swap, and /etc/fstab had no swap
     line. Five views against one, and the one is what anybody asks
     directly.

Then the recipe itself did not work, in three different ways.

  3. `fallocate -l` stripped every non-digit from its argument, so 1M
     became 1 and `fallocate -l 1G /swapfile` produced a one-byte file
     and reported success. truncate -s beside it parsed suffixes right.

  4. mkswap did not exist, on a box whose dpkg reports util-linux 2.41-5
     installed and which has swapon and swapoff from that same package.

  5. swapon on a file returned 0 and changed nothing, so the sequence
     "succeeded" from end to end and left `free` reporting no swap.

And one that matters more than any of them: truncate materialised the
whole file. `truncate -s 256M` cost 512MB of RSS, so `truncate -s 100G
/tmp/x` -- or the fallocate that begins the recipe above -- was a
one-line way for anyone with a shell to take the honeypot down. fallocate
avoided that only by capping its write at 1MB, which is why it reported
the wrong size. Both allocate sparsely now: the length is recorded, the
bytes are not, and no synthesised file materialises more than
BLOB_READ_CAP on read.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import resource
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
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


# -- one disk, one description -------------------------------------------

def t_the_disk_size_agrees_everywhere():
    s = shell()
    sectors = out(s, "cat /sys/block/sda/size")
    eq("sysfs sectors", sectors, str(fs.DISK_BLOCKS * 2))
    eq("/proc/partitions", out(s, "awk '/ sda$/{print $3}' /proc/partitions"),
       str(fs.DISK_BLOCKS))
    check("fdisk agrees on bytes",
          "%d bytes" % (fs.DISK_BLOCKS * 1024) in out(s, "fdisk -l"),
          out(s, "fdisk -l | head -1"))
    check("fdisk agrees on sectors",
          "%d sectors" % (fs.DISK_BLOCKS * 2) in out(s, "fdisk -l"),
          out(s, "fdisk -l | head -1"))
    check("lsblk agrees", " 64G " in out(s, "lsblk | head -2"),
          out(s, "lsblk | head -2"))


def t_the_partitions_agree():
    s = shell()
    for name in ("sda1", "sda14", "sda15"):
        check("fdisk lists %s" % name, name in out(s, "fdisk -l"), "")
        check("lsblk lists %s" % name, name in out(s, "lsblk"), "")
        check("/proc/partitions lists %s" % name,
              name in out(s, "cat /proc/partitions"), "")


def t_there_is_no_sda2():
    """The phantom this sweep was about."""
    s = shell()
    for cmd in ("fdisk -l", "lsblk", "cat /proc/partitions", "df -h",
                "cat /etc/fstab", "swapon --show", "cat /proc/swaps"):
        check("no sda2 in `%s`" % cmd, "sda2" not in out(s, cmd),
              out(s, cmd)[:80])


def t_the_label_is_gpt():
    """A box with /boot/efi on sda15 does not have a DOS label."""
    s = shell()
    body = out(s, "fdisk -l")
    check("gpt", "Disklabel type: gpt" in body, body[:200])
    check("not dos", "Disklabel type: dos" not in body, body[:200])
    check("EFI System partition named", "EFI System" in body, body[:300])


def t_sda14_is_the_same_size_in_all_three():
    s = shell()
    eq("/proc/partitions", out(s, "awk '/sda14/{print $3}' /proc/partitions"),
       str(fs.BIOS_BOOT_BLOCKS))
    check("lsblk says 4M", "4M" in out(s, "lsblk | grep sda14"),
          out(s, "lsblk | grep sda14"))
    check("fdisk says 4.0M", "4.0M" in out(s, "fdisk -l | grep sda14"),
          out(s, "fdisk -l | grep sda14"))


def t_fdisk_needs_dash_l():
    s = shell()
    eq("bare fdisk prints nothing", out(s, "fdisk"), "")


# -- swap at rest ---------------------------------------------------------

def t_no_swap_means_no_swap_anywhere():
    s = shell()
    eq("swapon --show is empty", out(s, "swapon --show"), "")
    eq("swapon -s is empty", out(s, "swapon -s"), "")
    eq("free says 0", out(s, "free -k | awk '/^Swap:/{print $2}'"), "0")
    eq("meminfo says 0",
       out(s, "awk '/^SwapTotal/{print $2}' /proc/meminfo"), "0")
    eq("/proc/swaps has only a header",
       out(s, "grep -c . /proc/swaps"), "1")
    eq("fstab has no swap line", out(s, "grep -ci swap /etc/fstab"), "0")


# -- fallocate and truncate ----------------------------------------------

def t_fallocate_reads_suffixes():
    s = shell()
    for spec, want in (("4096", 4096), ("1M", 1048576), ("512K", 524288),
                       ("1G", 1073741824), ("2MiB", 2097152),
                       ("1MB", 1000000)):
        out(s, "rm -f /tmp/fa")
        eq("fallocate -l %s" % spec,
           out(s, "fallocate -l %s /tmp/fa; stat -c '%%s' /tmp/fa" % spec),
           str(want))


def t_truncate_and_fallocate_agree():
    s = shell()
    for spec in ("4096", "1M", "64M", "1G"):
        out(s, "rm -f /tmp/t1 /tmp/t2")
        a = out(s, "truncate -s %s /tmp/t1; stat -c '%%s' /tmp/t1" % spec)
        b = out(s, "fallocate -l %s /tmp/t2; stat -c '%%s' /tmp/t2" % spec)
        eq("same size for %s" % spec, b, a)


def t_a_huge_allocation_costs_no_memory():
    """`truncate -s 100G /tmp/x` must not be a way to switch the box off."""
    s = shell()
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    eq("reports the full size",
       out(s, "truncate -s 100G /tmp/huge; stat -c '%s' /tmp/huge"),
       str(100 * 1024 ** 3))
    out(s, "rm -f /tmp/huge2; fallocate -l 40G /tmp/huge2")
    eq("fallocate too",
       out(s, "stat -c '%s' /tmp/huge2"), str(40 * 1024 ** 3))
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    grew = (after - before) // 1024
    check("RSS barely moved", grew < 64, "grew %d MB" % grew)


def t_a_small_allocation_is_still_real_bytes():
    s = shell()
    out(s, "rm -f /tmp/sm; fallocate -l 4096 /tmp/sm")
    eq("size", out(s, "stat -c '%s' /tmp/sm"), "4096")
    eq("and reads back", out(s, "wc -c < /tmp/sm"), "4096")


def t_reading_a_sparse_file_is_bounded():
    s = shell()
    out(s, "rm -f /tmp/big; truncate -s 8G /tmp/big")
    n = out(s, "wc -c < /tmp/big")
    check("read is capped", n.isdigit() and int(n) <= fs.BLOB_READ_CAP,
          "read %s bytes" % n)


# -- mkswap exists, because util-linux ships it --------------------------

def t_util_linux_is_coherent():
    s = shell()
    check("dpkg says installed", "util-linux" in out(s, "dpkg -l util-linux"),
          "")
    for tool in ("swapon", "swapoff", "mkswap"):
        check("%s exists" % tool,
              out(s, "command -v %s" % tool).endswith(tool),
              out(s, "command -v %s" % tool))


def t_mkswap_refuses_something_too_small():
    s = shell()
    out(s, "rm -f /tmp/tiny; fallocate -l 4096 /tmp/tiny")
    o = out(s, "mkswap /tmp/tiny")
    check("refused", "at least" in o, o)


def t_mkswap_reports_what_it_made():
    s = shell()
    out(s, "rm -f /tmp/sw; fallocate -l 64M /tmp/sw")
    o = out(s, "mkswap /tmp/sw")
    check("version line", "Setting up swapspace version 1" in o, o)
    check("size", "64M" in o, o)
    check("uuid", "UUID=" in o, o)


# -- the whole recipe -----------------------------------------------------

def t_the_add_swap_recipe():
    s = shell()
    out(s, "fallocate -l 64M /swapfile && chmod 600 /swapfile && "
           "mkswap /swapfile")
    _o, rc = s.run("swapon /swapfile"), s.last_rc
    s._err.clear()
    eq("swapon rc", rc, 0)
    eq("free sees it", out(s, "free -k | awk '/^Swap:/{print $2}'"), "65536")
    eq("meminfo sees it",
       out(s, "awk '/^SwapTotal/{print $2}' /proc/meminfo"), "65536")
    check("/proc/swaps names it", "/swapfile" in out(s, "cat /proc/swaps"),
          out(s, "cat /proc/swaps"))
    check("swapon --show names it", "/swapfile" in out(s, "swapon --show"),
          out(s, "swapon --show"))
    check("and calls it a file", " file " in out(s, "swapon --show"),
          out(s, "swapon --show"))


def t_swapoff_takes_it_away_everywhere():
    s = shell()
    out(s, "fallocate -l 64M /swapfile && mkswap /swapfile && "
           "swapon /swapfile")
    out(s, "swapoff /swapfile")
    eq("free back to 0", out(s, "free -k | awk '/^Swap:/{print $2}'"), "0")
    eq("meminfo back to 0",
       out(s, "awk '/^SwapTotal/{print $2}' /proc/meminfo"), "0")
    eq("swapon --show empty", out(s, "swapon --show"), "")
    eq("/proc/swaps header only", out(s, "grep -c . /proc/swaps"), "1")


def t_swapon_refuses_a_file_without_a_signature():
    s = shell()
    out(s, "rm -f /tmp/nosig; fallocate -l 64M /tmp/nosig")
    o = out(s, "swapon /tmp/nosig")
    check("refused", "read swap header failed" in o, o)
    eq("still no swap", out(s, "free -k | awk '/^Swap:/{print $2}'"), "0")


def t_swapon_refuses_a_missing_file():
    s = shell()
    o = out(s, "swapon /nope")
    check("reports it", "No such file or directory" in o, o)


def t_top_follows_the_swap_too():
    """top reads the same meminfo free does."""
    s = shell()
    out(s, "fallocate -l 64M /swapfile && mkswap /swapfile && "
           "swapon /swapfile")
    line = out(s, "top -bn1 | sed -n 5p")
    check("top shows 64 MiB swap", "64.0 total" in line, line)


TESTS = [t_the_disk_size_agrees_everywhere, t_the_partitions_agree,
         t_there_is_no_sda2, t_the_label_is_gpt,
         t_sda14_is_the_same_size_in_all_three, t_fdisk_needs_dash_l,
         t_no_swap_means_no_swap_anywhere, t_fallocate_reads_suffixes,
         t_truncate_and_fallocate_agree, t_a_huge_allocation_costs_no_memory,
         t_a_small_allocation_is_still_real_bytes,
         t_reading_a_sparse_file_is_bounded, t_util_linux_is_coherent,
         t_mkswap_refuses_something_too_small, t_mkswap_reports_what_it_made,
         t_the_add_swap_recipe, t_swapoff_takes_it_away_everywhere,
         t_swapon_refuses_a_file_without_a_signature,
         t_swapon_refuses_a_missing_file, t_top_follows_the_swap_too]


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
