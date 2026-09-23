#!/usr/bin/env python3
"""What the non-coreutils programs print for --help, measured on the guest.

The companion to cuhelp.py, which covers coreutils. These are the ones an
attacker's script actually reaches for -- the interpreters and the
downloaders -- and every one of them printed nothing at all:

    python3 --help    (empty)     guest: 2548 bytes
    perl --help       (empty)     guest: 2126
    awk --help        (empty)     guest: 1187, and it says mawk
    xargs --help      (empty)     guest: 3121
    curl --help       45 bytes    guest: 1139
    wget --help       (empty)     guest: 13331

Each entry is (stdout, stderr, rc), because for five of these --help is
not a help request at all and the answer is an error on the other stream:

    which        rc 2, "Usage: /usr/bin/which [-as] args" on stdout and
                 "Illegal option --" on stderr -- it splits across both
    reset, tset  rc 1, entirely on stderr
    ssh-keyscan  rc 1, "unknown option -- -" on stderr
    pidof        rc 1, and genuinely nothing on either stream

Streams were measured separately rather than with 2>&1, because a shell
that puts a help text on the wrong one is visible to `cmd --help 2>/dev/null`.

zcat and gunzip name a path in their usage -- "Usage: /usr/bin/zcat
[OPTION]..." -- and that is correct, not the argv[0] mistake cuhelp.py
warns about: both are /bin/sh scripts that interpolate $0, and $0 is the
resolved path when bash finds them on PATH. A person typing `zcat --help`
sees exactly this.
"""

#: name -> (stdout, stderr, exit status)
HELP = {
    # telinit, which is what /usr/sbin/init is: systemd-sysv links it
    # to /usr/lib/systemd/systemd and systemd reads argv[0]. Measured
    # with systemd-sysv installed, rc 0 on stdout.
    "init": ("init [OPTIONS...] COMMAND\n\nSend control commands to the init daemon.\n\nCommands:\n  0              Power-off the machine\n  6              Reboot the machine\n  2, 3, 4, 5     Start runlevelX.target unit\n  1, s, S        Enter rescue mode\n  q, Q           Reload init daemon configuration\n  u, U           Reexecute init daemon\n\nOptions:\n     --help      Show this help\n     --no-wall   Don't send wall message before halt/power-off/reboot\n\nSee the telinit(8) man page for details.\n", "", 0),
    # Measured on the guest, 650 bytes on stdout at rc 0. The last
    # paragraph is kmod describing the six symlinks that are the
    # reason it exists here at all -- see bindirtest.
    "kmod": ('kmod - Manage kernel modules: list, load, unload, etc\nUsage:\n\tkmod [options] command [command_options]\n\nOptions:\n\t-V, --version     show version\n\t-h, --help        show this help\n\nCommands:\n  help         show help message\n  list         list currently loaded modules\n  static-nodes output the static-node information installed with the currently running kernel\n\nkmod also handles gracefully if called from following symlinks:\n  lsmod        compat lsmod command\n  rmmod        compat rmmod command\n  insmod       compat insmod command\n  modinfo      compat modinfo command\n  modprobe     compat modprobe command\n  depmod       compat depmod command\n', "", 0),
    'awk': (
        (
            'Usage: mawk [Options] [Program] [file ...]\n'
            '\n'
            'Program:\n'
            '    The -f option value is the name of a file containing program text.\n'
            '    If no -f option is given, a "--" ends option processing; the following\n'
            '    parameters are the program text.\n'
            '\n'
            'Options:\n'
            '    -f program-file  Program  text is read from file instead of from the\n'
            '                     command-line.  Multiple -f options are accepted.\n'
            '    -F value         sets the field separator, FS, to value.\n'
            '    -v var=value     assigns value to program variable var.\n'
            '    --               unambiguous end of options.\n'
            '\n'
            '    Implementation-specific options are prefixed with "-W".  They can be\n'
            '    abbreviated:\n'
            '\n'
            '    -W version       show version information and exit.\n'
            '    -W dump          show assembler-like listing of program and exit.\n'
            '    -W help          show this message and exit.\n'
            '    -W interactive   set unbuffered output, line-buffered input.\n'
            '    -W exec file     use file as program as well as last option.\n'
            '    -W posix         stricter POSIX checking.\n'
            '    -W random=number set initial random seed.\n'
            '    -W sprintf=number adjust size of sprintf buffer.\n'
            '    -W traditional   pre-POSIX 2001.\n'
            '    -W usage         show this message and exit.\n'
        ),
        (
            ''
        ), 0),
    'curl': (
        (
            'Usage: curl [options...] <url>\n'
            ' -d, --data <data>           HTTP POST data\n'
            ' -f, --fail                  Fail fast with no output on HTTP errors\n'
            ' -h, --help <subject>        Get help for commands\n'
            ' -o, --output <file>         Write to file instead of stdout\n'
            ' -O, --remote-name           Write output to file named as remote file\n'
            ' -i, --show-headers          Show response headers in output\n'
            ' -s, --silent                Silent mode\n'
            ' -T, --upload-file <file>    Transfer local FILE to destination\n'
            ' -u, --user <user:password>  Server user and password\n'
            ' -A, --user-agent <name>     Send User-Agent <name> to server\n'
            ' -v, --verbose               Make the operation more talkative\n'
            ' -V, --version               Show version number and quit\n'
            '\n'
            'This is not the full help; this menu is split into categories.\n'
            'Use "--help category" to get an overview of all categories, which are:\n'
            'auth, connection, curl, deprecated, dns, file, ftp, global, http, imap, ldap, \n'
            'output, pop3, post, proxy, scp, sftp, smtp, ssh, telnet, tftp, timeout, tls, \n'
            'upload, verbose.\n'
            'Use "--help all" to list all options\n'
            'Use "--help [option]" to view documentation for a given option\n'
        ),
        (
            ''
        ), 0),
    'file': (
        (
            'Usage: file [OPTION...] [FILE...]\n'
            'Determine type of FILEs.\n'
            '\n'
            '      --help                 display this help and exit\n'
            '  -v, --version              output version information and exit\n'
            '  -m, --magic-file LIST      use LIST as a colon-separated list of magic\n'
            '                               number files\n'
            '  -z, --uncompress           try to look inside compressed files\n'
            '  -Z, --uncompress-noreport  only print the contents of compressed files\n'
            '  -b, --brief                do not prepend filenames to output lines\n'
            '  -c, --checking-printout    print the parsed form of the magic file, use in\n'
            '                               conjunction with -m to debug a new magic file\n'
            '                               before installing it\n'
            '  -e, --exclude TEST         exclude TEST from the list of test to be\n'
            '                               performed for file. Valid tests are:\n'
            '                               apptype, ascii, cdf, compress, csv, elf,\n'
            '                               encoding, soft, tar, json, simh,\n'
            '                               text, tokens\n'
            '      --exclude-quiet TEST   like exclude, but ignore unknown tests\n'
            '  -f, --files-from FILE      read the filenames to be examined from FILE\n'
            "  -F, --separator STRING     use string as separator instead of `:'\n"
            '  -i, --mime                 output MIME type strings (--mime-type and\n'
            '                               --mime-encoding)\n'
            '      --apple                output the Apple CREATOR/TYPE\n'
            '      --extension            output a slash-separated list of extensions\n'
            '      --mime-type            output the MIME type\n'
            '      --mime-encoding        output the MIME encoding\n'
            "  -k, --keep-going           don't stop at the first match\n"
            '  -l, --list                 list magic strength\n'
            '  -L, --dereference          follow symlinks (default if POSIXLY_CORRECT is set)\n'
            "  -h, --no-dereference       don't follow symlinks (default if POSIXLY_CORRECT is not set) (default)\n"
            '  -n, --no-buffer            do not buffer output\n'
            '  -N, --no-pad               do not pad output\n'
            '  -0, --print0               terminate filenames with ASCII NUL\n'
            '  -p, --preserve-date        preserve access times on files\n'
            '  -P, --parameter            set file engine parameter limits\n'
            '                                   bytes 7340032 max bytes to look inside file\n'
            '                               elf_notes     256 max ELF notes processed\n'
            '                               elf_phnum    2048 max ELF prog sections processed\n'
            '                               elf_shnum   32768 max ELF sections processed\n'
            '                               elf_shsize 134217728 max ELF section size\n'
            '                                encoding   65536 max bytes to scan for encoding\n'
            '                                   indir      50 recursion limit for indirection\n'
            '                                    name     100 use limit for name/use magic\n'
            '                                   regex    8192 length limit for REGEX searches\n'
            '                                 magwarn      64 maximum number of magic warnings\n'
            "  -r, --raw                  don't translate unprintable chars to \\ooo\n"
            '  -s, --special-files        treat special (block/char devices) files as\n'
            '                             ordinary ones\n'
            '  -S, --no-sandbox           disable system call sandboxing\n'
            '  -C, --compile              compile file specified by -m\n'
            '  -d, --debug                print debugging messages\n'
            '\n'
            'Report bugs to https://bugs.astron.com/\n'
        ),
        (
            ''
        ), 0),
    'gunzip': (
        (
            'Usage: /usr/bin/gunzip [OPTION]... [FILE]...\n'
            'Uncompress FILEs (by default, in-place).\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '\n'
            '  -c, --stdout      write on standard output, keep original files unchanged\n'
            '  -f, --force       force overwrite of output file and compress links\n'
            "  -k, --keep        keep (don't delete) input files\n"
            '  -l, --list        list compressed file contents\n'
            '  -n, --no-name     do not save or restore the original name and timestamp\n'
            '  -N, --name        save or restore the original name and timestamp\n'
            '  -q, --quiet       suppress all warnings\n'
            '  -r, --recursive   operate recursively on directories\n'
            '  -S, --suffix=SUF  use suffix SUF on compressed files\n'
            '      --synchronous synchronous output (safer if system crashes, but slower)\n'
            '  -t, --test        test compressed file integrity\n'
            '  -v, --verbose     verbose mode\n'
            '      --help        display this help and exit\n'
            '      --version     display version information and exit\n'
            '\n'
            'With no FILE, or when FILE is -, read standard input.\n'
            '\n'
            'Report bugs to <bug-gzip@gnu.org>.\n'
        ),
        (
            ''
        ), 0),
    'logger': (
        (
            '\n'
            'Usage:\n'
            ' logger [options] [<message>]\n'
            '\n'
            'Enter messages into the system log.\n'
            '\n'
            'Options:\n'
            " -i                       log the logger command's PID\n"
            '     --id[=<id>]          log the given <id>, or otherwise the PID\n'
            ' -f, --file <file>        log the contents of this file\n'
            ' -e, --skip-empty         do not log empty lines when processing files\n'
            '     --no-act             do everything except the write the log\n'
            ' -p, --priority <prio>    mark given message with this priority\n'
            '     --octet-count        use rfc6587 octet counting\n'
            '     --prio-prefix        look for a prefix on every line read from stdin\n'
            ' -s, --stderr             output message to standard error as well\n'
            ' -S, --size <size>        maximum size for a single message\n'
            ' -t, --tag <tag>          mark every line with this tag\n'
            ' -n, --server <name>      write to this remote syslog server\n'
            ' -P, --port <port>        use this port for UDP or TCP connection\n'
            ' -T, --tcp                use TCP only\n'
            ' -d, --udp                use UDP only\n'
            '     --rfc3164            use the obsolete BSD syslog protocol\n'
            '     --rfc5424[=<snip>]   use the syslog protocol (the default for remote);\n'
            '                            <snip> can be notime, or notq, and/or nohost\n'
            '     --sd-id <id>         rfc5424 structured data ID\n'
            '     --sd-param <data>    rfc5424 structured data name=value\n'
            '     --msgid <msgid>      set rfc5424 message id field\n'
            ' -u, --socket <socket>    write to this Unix socket\n'
            '     --socket-errors on|off|auto\n'
            '                          print connection errors when using Unix sockets\n'
            '     --journald[=<file>]  write journald entry\n'
            '\n'
            ' -h, --help               display this help\n'
            ' -V, --version            display version\n'
            '\n'
            'For more details see logger(1).\n'
        ),
        (
            ''
        ), 0),
    'mawk': (
        (
            'Usage: mawk [Options] [Program] [file ...]\n'
            '\n'
            'Program:\n'
            '    The -f option value is the name of a file containing program text.\n'
            '    If no -f option is given, a "--" ends option processing; the following\n'
            '    parameters are the program text.\n'
            '\n'
            'Options:\n'
            '    -f program-file  Program  text is read from file instead of from the\n'
            '                     command-line.  Multiple -f options are accepted.\n'
            '    -F value         sets the field separator, FS, to value.\n'
            '    -v var=value     assigns value to program variable var.\n'
            '    --               unambiguous end of options.\n'
            '\n'
            '    Implementation-specific options are prefixed with "-W".  They can be\n'
            '    abbreviated:\n'
            '\n'
            '    -W version       show version information and exit.\n'
            '    -W dump          show assembler-like listing of program and exit.\n'
            '    -W help          show this message and exit.\n'
            '    -W interactive   set unbuffered output, line-buffered input.\n'
            '    -W exec file     use file as program as well as last option.\n'
            '    -W posix         stricter POSIX checking.\n'
            '    -W random=number set initial random seed.\n'
            '    -W sprintf=number adjust size of sprintf buffer.\n'
            '    -W traditional   pre-POSIX 2001.\n'
            '    -W usage         show this message and exit.\n'
        ),
        (
            ''
        ), 0),
    'more': (
        (
            '\n'
            'Usage:\n'
            ' more [options] <file>...\n'
            '\n'
            'Display the contents of a file in a terminal.\n'
            '\n'
            'Options:\n'
            ' -d, --silent          display help instead of ringing bell\n'
            ' -f, --logical         count logical rather than screen lines\n'
            ' -l, --no-pause        suppress pause after form feed\n'
            ' -c, --print-over      do not scroll, display text and clean line ends\n'
            ' -p, --clean-print     do not scroll, clean screen and display text\n'
            ' -e, --exit-on-eof     exit on end-of-file\n'
            ' -s, --squeeze         squeeze multiple blank lines into one\n'
            ' -u, --plain           suppress underlining and bold\n'
            ' -n, --lines <number>  the number of lines per screenful\n'
            ' -<number>             same as --lines\n'
            ' +<number>             display file beginning from line number\n'
            ' +/<pattern>           display file beginning from pattern match\n'
            '\n'
            ' -h, --help            display this help\n'
            ' -V, --version         display version\n'
            '\n'
            'For more details see more(1).\n'
        ),
        (
            ''
        ), 0),
    'namei': (
        (
            '\n'
            'Usage:\n'
            ' namei [options] <pathname>...\n'
            '\n'
            'Follow a pathname until a terminal point is found.\n'
            '\n'
            'Options:\n'
            " -x, --mountpoints   show mount point directories with a 'D'\n"
            ' -m, --modes         show the mode bits of each file\n'
            ' -o, --owners        show owner and group name of each file\n'
            ' -l, --long          use a long listing format (-m -o -v) \n'
            " -n, --nosymlinks    don't follow symlinks\n"
            ' -v, --vertical      vertical align of modes and owners\n'
            ' -Z, --context       print any security context of each file \n'
            ' -h, --help          display this help\n'
            ' -V, --version       display version\n'
            '\n'
            'For more details see namei(1).\n'
        ),
        (
            ''
        ), 0),
    'nawk': (
        (
            'Usage: mawk [Options] [Program] [file ...]\n'
            '\n'
            'Program:\n'
            '    The -f option value is the name of a file containing program text.\n'
            '    If no -f option is given, a "--" ends option processing; the following\n'
            '    parameters are the program text.\n'
            '\n'
            'Options:\n'
            '    -f program-file  Program  text is read from file instead of from the\n'
            '                     command-line.  Multiple -f options are accepted.\n'
            '    -F value         sets the field separator, FS, to value.\n'
            '    -v var=value     assigns value to program variable var.\n'
            '    --               unambiguous end of options.\n'
            '\n'
            '    Implementation-specific options are prefixed with "-W".  They can be\n'
            '    abbreviated:\n'
            '\n'
            '    -W version       show version information and exit.\n'
            '    -W dump          show assembler-like listing of program and exit.\n'
            '    -W help          show this message and exit.\n'
            '    -W interactive   set unbuffered output, line-buffered input.\n'
            '    -W exec file     use file as program as well as last option.\n'
            '    -W posix         stricter POSIX checking.\n'
            '    -W random=number set initial random seed.\n'
            '    -W sprintf=number adjust size of sprintf buffer.\n'
            '    -W traditional   pre-POSIX 2001.\n'
            '    -W usage         show this message and exit.\n'
        ),
        (
            ''
        ), 0),
    'newgrp': (
        (
            '\n'
            'Usage:\n'
            ' newgrp <group> [[-c] <command>]\n'
            '\n'
            'Log in to a new group; optionally executing a shell command.\n'
            '\n'
            'Options:\n'
            ' -h, --help     display this help\n'
            ' -V, --version  display version\n'
            '\n'
            'For more details see newgrp(1).\n'
        ),
        (
            ''
        ), 0),
    'perl': (
        (
            '\n'
            'Usage: perl [switches] [--] [programfile] [arguments]\n'
            '  -0[octal/hexadecimal] specify record separator (\\0, if no argument)\n'
            '  -a                    autosplit mode with -n or -p (splits $_ into @F)\n'
            '  -C[number/list]       enables the listed Unicode features\n'
            '  -c                    check syntax only (runs BEGIN and CHECK blocks)\n'
            '  -d[t][:MOD]           run program under debugger or module Devel::MOD\n'
            '  -D[number/letters]    set debugging flags (argument is a bit mask or alphabets)\n'
            "  -e commandline        one line of program (several -e's allowed, omit programfile)\n"
            '  -E commandline        like -e, but enables all optional features\n'
            "  -f                    don't do $sitelib/sitecustomize.pl at startup\n"
            "  -F/pattern/           split() pattern for -a switch (//'s are optional)\n"
            '  -g                    read all input in one go (slurp), rather than line-by-line (alias for -0777)\n'
            '  -i[extension]         edit <> files in place (makes backup if extension supplied)\n'
            "  -Idirectory           specify @INC/#include directory (several -I's allowed)\n"
            '  -l[octnum]            enable line ending processing, specifies line terminator\n'
            '  -[mM][-]module        execute "use/no module..." before executing program\n'
            '  -n                    assume "while (<>) { ... }" loop around program\n'
            '  -p                    assume loop like -n but print line also, like sed\n'
            '  -s                    enable rudimentary parsing for switches after programfile\n'
            '  -S                    look for programfile using PATH environment variable\n'
            '  -t                    enable tainting warnings\n'
            '  -T                    enable tainting checks\n'
            '  -u                    dump core after parsing program\n'
            '  -U                    allow unsafe operations\n'
            '  -v                    print version, patchlevel and license\n'
            '  -V[:configvar]        print configuration summary (or a single Config.pm variable)\n'
            '  -w                    enable many useful warnings\n'
            '  -W                    enable all warnings\n'
            '  -x[directory]         ignore text before #!perl line (optionally cd to directory)\n'
            '  -X                    disable all warnings\n'
            '  \n'
            "Run 'perldoc perl' for more help with Perl.\n"
            '\n'
        ),
        (
            ''
        ), 0),
    'pidof': (
        (
            ''
        ),
        (
            ''
        ), 1),
    'python3': (
        (
            'usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...\n'
            'Options (and corresponding environment variables):\n'
            '-b     : issue warnings about converting bytes/bytearray to str and comparing\n'
            '         bytes/bytearray with str or bytes with int. (-bb: issue errors)\n'
            "-B     : don't write .pyc files on import; also PYTHONDONTWRITEBYTECODE=x\n"
            '-c cmd : program passed in as string (terminates option list)\n'
            '-d     : turn on parser debugging output (for experts only, only works on\n'
            '         debug builds); also PYTHONDEBUG=x\n'
            '-E     : ignore PYTHON* environment variables (such as PYTHONPATH)\n'
            '-h     : print this help message and exit (also -? or --help)\n'
            '-i     : inspect interactively after running script; forces a prompt even\n'
            '         if stdin does not appear to be a terminal; also PYTHONINSPECT=x\n'
            "-I     : isolate Python from the user's environment (implies -E, -P and -s)\n"
            '-m mod : run library module as a script (terminates option list)\n'
            '-O     : remove assert and __debug__-dependent statements; add .opt-1 before\n'
            '         .pyc extension; also PYTHONOPTIMIZE=x\n'
            '-OO    : do -O changes and also discard docstrings; add .opt-2 before\n'
            '         .pyc extension\n'
            "-P     : don't prepend a potentially unsafe path to sys.path; also\n"
            '         PYTHONSAFEPATH\n'
            "-q     : don't print version and copyright messages on interactive startup\n"
            "-s     : don't add user site directory to sys.path; also PYTHONNOUSERSITE=x\n"
            "-S     : don't imply 'import site' on initialization\n"
            '-u     : force the stdout and stderr streams to be unbuffered;\n'
            '         this option has no effect on stdin; also PYTHONUNBUFFERED=x\n'
            '-v     : verbose (trace import statements); also PYTHONVERBOSE=x\n'
            '         can be supplied multiple times to increase verbosity\n'
            '-V     : print the Python version number and exit (also --version)\n'
            '         when given twice, print more information about the build\n'
            '-W arg : warning control; arg is action:message:category:module:lineno\n'
            '         also PYTHONWARNINGS=arg\n'
            '-x     : skip first line of source, allowing use of non-Unix forms of #!cmd\n'
            '-X opt : set implementation-specific option\n'
            '--check-hash-based-pycs always|default|never:\n'
            '         control how Python invalidates hash-based .pyc files\n'
            '--help-env: print help about Python environment variables and exit\n'
            '--help-xoptions: print help about implementation-specific -X options and exit\n'
            '--help-all: print complete help information and exit\n'
            '\n'
            'Arguments:\n'
            'file   : program read from script file\n'
            '-      : program read from stdin (default; interactive mode if a tty)\n'
            'arg ...: arguments passed to program in sys.argv[1:]\n'
        ),
        (
            ''
        ), 0),
    'python3.13': (
        (
            'usage: python3.13 [option] ... [-c cmd | -m mod | file | -] [arg] ...\n'
            'Options (and corresponding environment variables):\n'
            '-b     : issue warnings about converting bytes/bytearray to str and comparing\n'
            '         bytes/bytearray with str or bytes with int. (-bb: issue errors)\n'
            "-B     : don't write .pyc files on import; also PYTHONDONTWRITEBYTECODE=x\n"
            '-c cmd : program passed in as string (terminates option list)\n'
            '-d     : turn on parser debugging output (for experts only, only works on\n'
            '         debug builds); also PYTHONDEBUG=x\n'
            '-E     : ignore PYTHON* environment variables (such as PYTHONPATH)\n'
            '-h     : print this help message and exit (also -? or --help)\n'
            '-i     : inspect interactively after running script; forces a prompt even\n'
            '         if stdin does not appear to be a terminal; also PYTHONINSPECT=x\n'
            "-I     : isolate Python from the user's environment (implies -E, -P and -s)\n"
            '-m mod : run library module as a script (terminates option list)\n'
            '-O     : remove assert and __debug__-dependent statements; add .opt-1 before\n'
            '         .pyc extension; also PYTHONOPTIMIZE=x\n'
            '-OO    : do -O changes and also discard docstrings; add .opt-2 before\n'
            '         .pyc extension\n'
            "-P     : don't prepend a potentially unsafe path to sys.path; also\n"
            '         PYTHONSAFEPATH\n'
            "-q     : don't print version and copyright messages on interactive startup\n"
            "-s     : don't add user site directory to sys.path; also PYTHONNOUSERSITE=x\n"
            "-S     : don't imply 'import site' on initialization\n"
            '-u     : force the stdout and stderr streams to be unbuffered;\n'
            '         this option has no effect on stdin; also PYTHONUNBUFFERED=x\n'
            '-v     : verbose (trace import statements); also PYTHONVERBOSE=x\n'
            '         can be supplied multiple times to increase verbosity\n'
            '-V     : print the Python version number and exit (also --version)\n'
            '         when given twice, print more information about the build\n'
            '-W arg : warning control; arg is action:message:category:module:lineno\n'
            '         also PYTHONWARNINGS=arg\n'
            '-x     : skip first line of source, allowing use of non-Unix forms of #!cmd\n'
            '-X opt : set implementation-specific option\n'
            '--check-hash-based-pycs always|default|never:\n'
            '         control how Python invalidates hash-based .pyc files\n'
            '--help-env: print help about Python environment variables and exit\n'
            '--help-xoptions: print help about implementation-specific -X options and exit\n'
            '--help-all: print complete help information and exit\n'
            '\n'
            'Arguments:\n'
            'file   : program read from script file\n'
            '-      : program read from stdin (default; interactive mode if a tty)\n'
            'arg ...: arguments passed to program in sys.argv[1:]\n'
        ),
        (
            ''
        ), 0),
    'rename.ul': (
        (
            '\n'
            'Usage:\n'
            ' rename.ul [options] <expression> <replacement> <file>...\n'
            '\n'
            'Rename files.\n'
            '\n'
            'Options:\n'
            ' -v, --verbose       explain what is being done\n'
            ' -s, --symlink       act on the target of symlinks\n'
            ' -n, --no-act        do not make any changes\n'
            ' -a, --all           replace all occurrences\n'
            ' -l, --last          replace only the last occurrence\n'
            " -o, --no-overwrite  don't overwrite existing files\n"
            ' -i, --interactive   prompt before overwrite\n'
            '\n'
            ' -h, --help          display this help\n'
            ' -V, --version       display version\n'
            '\n'
            'For more details see rename(1).\n'
        ),
        (
            ''
        ), 0),
    'reset': (
        (
            ''
        ),
        (
            "reset: invalid option -- '-'\n"
            'Usage: reset [options] [terminal]\n'
            '\n'
            'Options:\n'
            '  -c          set control characters\n'
            '  -e ch       erase character\n'
            '  -I          no initialization strings\n'
            '  -i ch       interrupt character\n'
            '  -k ch       kill character\n'
            '  -m mapping  map identifier to type\n'
            '  -Q          do not output control key settings\n'
            '  -q          display term only, do no changes\n'
            '  -r          display term on stderr\n'
            '  -s          output TERM set command\n'
            '  -V          print curses-version\n'
            '  -w          set window-size\n'
            '\n'
            'If neither -c/-w are given, both are assumed.\n'
        ), 1),
    'rev': (
        (
            '\n'
            'Usage:\n'
            ' rev [options] [<file> ...]\n'
            '\n'
            'Reverse lines characterwise.\n'
            '\n'
            'Options:\n'
            ' -0, --zero     use the NUL byte as line separator\n'
            ' -h, --help     display this help\n'
            ' -V, --version  display version\n'
            '\n'
            'For more details see rev(1).\n'
        ),
        (
            ''
        ), 0),
    'setsid': (
        (
            '\n'
            'Usage:\n'
            ' setsid [options] <program> [<argument>...]\n'
            '\n'
            'Run a program in a new session.\n'
            '\n'
            'Options:\n'
            ' -c, --ctty     set the controlling terminal to the current one\n'
            ' -f, --fork     always fork\n'
            ' -w, --wait     wait program to exit, and use the same return\n'
            ' -h, --help     display this help\n'
            ' -V, --version  display version\n'
            '\n'
            'For more details see setsid(1).\n'
        ),
        (
            ''
        ), 0),
    'sg': (
        (
            '\n'
            'Usage:\n'
            ' sg <group> [[-c] <command>]\n'
            '\n'
            'Log in to a new group; optionally executing a shell command.\n'
            '\n'
            'Options:\n'
            ' -h, --help     display this help\n'
            ' -V, --version  display version\n'
            '\n'
            'For more details see newgrp(1).\n'
        ),
        (
            ''
        ), 0),
    'ssh-keyscan': (
        (
            ''
        ),
        (
            'unknown option -- -\n'
            'usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n'
            '                   [-t type] [host | addrlist namelist]\n'
        ), 1),
    'su': (
        (
            '\n'
            'Usage:\n'
            ' su [options] [-] [<user> [<argument>...]]\n'
            '\n'
            'Change the effective user ID and group ID to that of <user>.\n'
            'A mere - implies -l.  If <user> is not given, root is assumed.\n'
            '\n'
            'Options:\n'
            ' -m, -p, --preserve-environment      do not reset environment variables\n'
            " -w, --whitelist-environment <list>  don't reset specified variables\n"
            '\n'
            ' -g, --group <group>             specify the primary group\n'
            ' -G, --supp-group <group>        specify a supplemental group\n'
            '\n'
            ' -, -l, --login                  make the shell a login shell\n'
            ' -c, --command <command>         pass a single command to the shell with -c\n'
            ' --session-command <command>     pass a single command to the shell with -c\n'
            '                                   and do not create a new session\n'
            ' -f, --fast                      pass -f to the shell (for csh or tcsh)\n'
            ' -s, --shell <shell>             run <shell> if /etc/shells allows it\n'
            ' -P, --pty                       create a new pseudo-terminal\n'
            ' -T, --no-pty                    do not create a new pseudo-terminal (bad security!)\n'
            '\n'
            ' -h, --help                      display this help\n'
            ' -V, --version                   display version\n'
            '\n'
            'For more details see su(1).\n'
        ),
        (
            ''
        ), 0),
    'tset': (
        (
            ''
        ),
        (
            "tset: invalid option -- '-'\n"
            'Usage: tset [options] [terminal]\n'
            '\n'
            'Options:\n'
            '  -c          set control characters\n'
            '  -e ch       erase character\n'
            '  -I          no initialization strings\n'
            '  -i ch       interrupt character\n'
            '  -k ch       kill character\n'
            '  -m mapping  map identifier to type\n'
            '  -Q          do not output control key settings\n'
            '  -q          display term only, do no changes\n'
            '  -r          display term on stderr\n'
            '  -s          output TERM set command\n'
            '  -V          print curses-version\n'
            '  -w          set window-size\n'
            '\n'
            'If neither -c/-w are given, both are assumed.\n'
        ), 1),
    'ul': (
        (
            '\n'
            'Usage:\n'
            ' ul [options] [<file> ...]\n'
            '\n'
            'Do underlining.\n'
            '\n'
            'Options:\n'
            ' -t, -T, --terminal TERMINAL  override the TERM environment variable\n'
            ' -i, --indicated              underlining is indicated via a separate line\n'
            ' -h, --help                   display this help\n'
            ' -V, --version                display version\n'
            '\n'
            'For more details see ul(1).\n'
        ),
        (
            ''
        ), 0),
    'wall': (
        (
            '\n'
            'Usage:\n'
            ' wall [options] [<file> | <message>]\n'
            '\n'
            'Write a message to all users.\n'
            '\n'
            'Options:\n'
            ' -g, --group <group>     only send message to group\n'
            ' -n, --nobanner          do not print banner, works only for root\n'
            ' -t, --timeout <timeout> write timeout in seconds\n'
            '\n'
            ' -h, --help              display this help\n'
            ' -V, --version           display version\n'
            '\n'
            'For more details see wall(1).\n'
        ),
        (
            ''
        ), 0),
    'wget': (
        (
            'GNU Wget 1.25.0, a non-interactive network retriever.\n'
            'Usage: wget [OPTION]... [URL]...\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '\n'
            'Startup:\n'
            '  -V,  --version                   display the version of Wget and exit\n'
            '  -h,  --help                      print this help\n'
            '  -b,  --background                go to background after startup\n'
            "  -e,  --execute=COMMAND           execute a `.wgetrc'-style command\n"
            '\n'
            'Logging and input file:\n'
            '  -o,  --output-file=FILE          log messages to FILE\n'
            '  -a,  --append-output=FILE        append messages to FILE\n'
            '  -d,  --debug                     print lots of debugging information\n'
            '  -q,  --quiet                     quiet (no output)\n'
            '  -v,  --verbose                   be verbose (this is the default)\n'
            '  -nv, --no-verbose                turn off verboseness, without being quiet\n'
            '       --report-speed=TYPE         output bandwidth as TYPE.  TYPE can be bits\n'
            '  -i,  --input-file=FILE           download URLs found in local or external FILE\n'
            '  -F,  --force-html                treat input file as HTML\n'
            '  -B,  --base=URL                  resolves HTML input-file links (-i -F)\n'
            '                                     relative to URL\n'
            '       --config=FILE               specify config file to use\n'
            '       --no-config                 do not read any config file\n'
            '       --rejected-log=FILE         log reasons for URL rejection to FILE\n'
            '\n'
            'Download:\n'
            '  -t,  --tries=NUMBER              set number of retries to NUMBER (0 unlimits)\n'
            '       --retry-connrefused         retry even if connection is refused\n'
            '       --retry-on-host-error       consider host errors as non-fatal, transient errors\n'
            '       --retry-on-http-error=ERRORS    comma-separated list of HTTP errors to retry\n'
            '  -O,  --output-document=FILE      write documents to FILE\n'
            '  -nc, --no-clobber                skip downloads that would download to\n'
            '                                     existing files (overwriting them)\n'
            "       --no-netrc                  don't try to obtain credentials from .netrc\n"
            '  -c,  --continue                  resume getting a partially-downloaded file\n'
            '       --start-pos=OFFSET          start downloading from zero-based position OFFSET\n'
            '       --progress=TYPE             select progress gauge type\n'
            '       --show-progress             display the progress bar in any verbosity mode\n'
            "  -N,  --timestamping              don't re-retrieve files unless newer than\n"
            '                                     local\n'
            "       --no-if-modified-since      don't use conditional if-modified-since get\n"
            '                                     requests in timestamping mode\n'
            "       --no-use-server-timestamps  don't set the local file's timestamp by\n"
            '                                     the one on the server\n'
            '  -S,  --server-response           print server response\n'
            "       --spider                    don't download anything\n"
            '  -T,  --timeout=SECONDS           set all timeout values to SECONDS\n'
            '       --dns-timeout=SECS          set the DNS lookup timeout to SECS\n'
            '       --connect-timeout=SECS      set the connect timeout to SECS\n'
            '       --read-timeout=SECS         set the read timeout to SECS\n'
            '  -w,  --wait=SECONDS              wait SECONDS between retrievals\n'
            '                                     (applies if more then 1 URL is to be retrieved)\n'
            '       --waitretry=SECONDS         wait 1..SECONDS between retries of a retrieval\n'
            '                                     (applies if more then 1 URL is to be retrieved)\n'
            '       --random-wait               wait from 0.5*WAIT...1.5*WAIT secs between retrievals\n'
            '                                     (applies if more then 1 URL is to be retrieved)\n'
            '       --no-proxy                  explicitly turn off proxy\n'
            '  -Q,  --quota=NUMBER              set retrieval quota to NUMBER\n'
            '       --bind-address=ADDRESS      bind to ADDRESS (hostname or IP) on local host\n'
            '       --limit-rate=RATE           limit download rate to RATE\n'
            '       --no-dns-cache              disable caching DNS lookups\n'
            '       --restrict-file-names=OS    restrict chars in file names to ones OS allows\n'
            '       --ignore-case               ignore case when matching files/directories\n'
            '  -4,  --inet4-only                connect only to IPv4 addresses\n'
            '  -6,  --inet6-only                connect only to IPv6 addresses\n'
            '       --prefer-family=FAMILY      connect first to addresses of specified family,\n'
            '                                     one of IPv6, IPv4, or none\n'
            '       --user=USER                 set both ftp and http user to USER\n'
            '       --password=PASS             set both ftp and http password to PASS\n'
            '       --ask-password              prompt for passwords\n'
            '       --use-askpass=COMMAND       specify credential handler for requesting \n'
            '                                     username and password.  If no COMMAND is \n'
            '                                     specified the WGET_ASKPASS or the SSH_ASKPASS \n'
            '                                     environment variable is used.\n'
            '       --no-iri                    turn off IRI support\n'
            '       --local-encoding=ENC        use ENC as the local encoding for IRIs\n'
            '       --remote-encoding=ENC       use ENC as the default remote encoding\n'
            '       --unlink                    remove file before clobber\n'
            '       --xattr                     turn on storage of metadata in extended file attributes\n'
            '\n'
            'Directories:\n'
            "  -nd, --no-directories            don't create directories\n"
            '  -x,  --force-directories         force creation of directories\n'
            "  -nH, --no-host-directories       don't create host directories\n"
            '       --protocol-directories      use protocol name in directories\n'
            '  -P,  --directory-prefix=PREFIX   save files to PREFIX/..\n'
            '       --cut-dirs=NUMBER           ignore NUMBER remote directory components\n'
            '\n'
            'HTTP options:\n'
            '       --http-user=USER            set http user to USER\n'
            '       --http-password=PASS        set http password to PASS\n'
            '       --no-cache                  disallow server-cached data\n'
            '       --default-page=NAME         change the default page name (normally\n'
            "                                     this is 'index.html'.)\n"
            '  -E,  --adjust-extension          save HTML/CSS documents with proper extensions\n'
            "       --ignore-length             ignore 'Content-Length' header field\n"
            '       --header=STRING             insert STRING among the headers\n'
            '       --compression=TYPE          choose compression, one of auto, gzip and none. (default: none)\n'
            '       --max-redirect              maximum redirections allowed per page\n'
            '       --proxy-user=USER           set USER as proxy username\n'
            '       --proxy-password=PASS       set PASS as proxy password\n'
            "       --referer=URL               include 'Referer: URL' header in HTTP request\n"
            '       --save-headers              save the HTTP headers to file\n'
            '  -U,  --user-agent=AGENT          identify as AGENT instead of Wget/VERSION\n'
            '       --no-http-keep-alive        disable HTTP keep-alive (persistent connections)\n'
            "       --no-cookies                don't use cookies\n"
            '       --load-cookies=FILE         load cookies from FILE before session\n'
            '       --save-cookies=FILE         save cookies to FILE after session\n'
            '       --keep-session-cookies      load and save session (non-permanent) cookies\n'
            '       --post-data=STRING          use the POST method; send STRING as the data\n'
            '       --post-file=FILE            use the POST method; send contents of FILE\n'
            '       --method=HTTPMethod         use method "HTTPMethod" in the request\n'
            '       --body-data=STRING          send STRING as data. --method MUST be set\n'
            '       --body-file=FILE            send contents of FILE. --method MUST be set\n'
            '       --content-disposition       honor the Content-Disposition header when\n'
            '                                     choosing local file names (EXPERIMENTAL)\n'
            '       --content-on-error          output the received content on server errors\n'
            '       --auth-no-challenge         send Basic HTTP authentication information\n'
            "                                     without first waiting for the server's\n"
            '                                     challenge\n'
            '\n'
            'HTTPS (SSL/TLS) options:\n'
            '       --secure-protocol=PR        choose secure protocol, one of auto, SSLv2,\n'
            '                                     SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 and PFS\n'
            '       --https-only                only follow secure HTTPS links\n'
            "       --no-check-certificate      don't validate the server's certificate\n"
            '       --certificate=FILE          client certificate file\n'
            '       --certificate-type=TYPE     client certificate type, PEM or DER\n'
            '       --private-key=FILE          private key file\n'
            '       --private-key-type=TYPE     private key type, PEM or DER\n'
            '       --ca-certificate=FILE       file with the bundle of CAs\n'
            '       --ca-directory=DIR          directory where hash list of CAs is stored\n'
            '       --crl-file=FILE             file with bundle of CRLs\n'
            '       --pinnedpubkey=FILE/HASHES  Public key (PEM/DER) file, or any number\n'
            '                                   of base64 encoded sha256 hashes preceded by\n'
            "                                   'sha256//' and separated by ';', to verify\n"
            '                                   peer against\n'
            '\n'
            '       --ciphers=STR           Set the priority string (GnuTLS) or cipher list string (OpenSSL) directly.\n'
            '                                   Use with care. This option overrides --secure-protocol.\n'
            '                                   The format and syntax of this string depend on the specific SSL/TLS engine.\n'
            'HSTS options:\n'
            '       --no-hsts                   disable HSTS\n'
            '       --hsts-file                 path of HSTS database (will override default)\n'
            '\n'
            'FTP options:\n'
            '       --ftp-user=USER             set ftp user to USER\n'
            '       --ftp-password=PASS         set ftp password to PASS\n'
            "       --no-remove-listing         don't remove '.listing' files\n"
            '       --no-glob                   turn off FTP file name globbing\n'
            '       --no-passive-ftp            disable the "passive" transfer mode\n'
            '       --preserve-permissions      preserve remote file permissions\n'
            '       --retr-symlinks             when recursing, get linked-to files (not dir)\n'
            '\n'
            'FTPS options:\n'
            '       --ftps-implicit                 use implicit FTPS (default port is 990)\n'
            '       --ftps-resume-ssl               resume the SSL/TLS session started in the control connection when\n'
            '                                         opening a data connection\n'
            '       --ftps-clear-data-connection    cipher the control channel only; all the data will be in plaintext\n'
            '       --ftps-fallback-to-ftp          fall back to FTP if FTPS is not supported in the target server\n'
            'WARC options:\n'
            '       --warc-file=FILENAME        save request/response data to a .warc.gz file\n'
            '       --warc-header=STRING        insert STRING into the warcinfo record\n'
            '       --warc-max-size=NUMBER      set maximum size of WARC files to NUMBER\n'
            '       --warc-cdx                  write CDX index files\n'
            '       --warc-dedup=FILENAME       do not store records listed in this CDX file\n'
            '       --no-warc-compression       do not compress WARC files with GZIP\n'
            '       --no-warc-digests           do not calculate SHA1 digests\n'
            '       --no-warc-keep-log          do not store the log file in a WARC record\n'
            '       --warc-tempdir=DIRECTORY    location for temporary files created by the\n'
            '                                     WARC writer\n'
            '\n'
            'Recursive download:\n'
            '  -r,  --recursive                 specify recursive download\n'
            '  -l,  --level=NUMBER              maximum recursion depth (inf or 0 for infinite)\n'
            '       --delete-after              delete files locally after downloading them\n'
            '  -k,  --convert-links             make links in downloaded HTML or CSS point to\n'
            '                                     local files\n'
            '       --convert-file-only         convert the file part of the URLs only (usually known as the basename)\n'
            '       --backups=N                 before writing file X, rotate up to N backup files\n'
            '  -K,  --backup-converted          before converting file X, back up as X.orig\n'
            '  -m,  --mirror                    shortcut for -N -r -l inf --no-remove-listing\n'
            '  -p,  --page-requisites           get all images, etc. needed to display HTML page\n'
            '       --strict-comments           turn on strict (SGML) handling of HTML comments\n'
            '\n'
            'Recursive accept/reject:\n'
            '  -A,  --accept=LIST               comma-separated list of accepted extensions\n'
            '  -R,  --reject=LIST               comma-separated list of rejected extensions\n'
            '       --accept-regex=REGEX        regex matching accepted URLs\n'
            '       --reject-regex=REGEX        regex matching rejected URLs\n'
            '       --regex-type=TYPE           regex type (posix|pcre)\n'
            '  -D,  --domains=LIST              comma-separated list of accepted domains\n'
            '       --exclude-domains=LIST      comma-separated list of rejected domains\n'
            '       --follow-ftp                follow FTP links from HTML documents\n'
            '       --follow-tags=LIST          comma-separated list of followed HTML tags\n'
            '       --ignore-tags=LIST          comma-separated list of ignored HTML tags\n'
            '  -H,  --span-hosts                go to foreign hosts when recursive\n'
            '  -L,  --relative                  follow relative links only\n'
            '  -I,  --include-directories=LIST  list of allowed directories\n'
            '       --trust-server-names        use the name specified by the redirection\n'
            "                                     URL's last component\n"
            '  -X,  --exclude-directories=LIST  list of excluded directories\n'
            "  -np, --no-parent                 don't ascend to the parent directory\n"
            '\n'
            'Email bug reports, questions, discussions to <bug-wget@gnu.org>\n'
            'and/or open issues at https://savannah.gnu.org/bugs/?func=additem&group=wget.\n'
        ),
        (
            ''
        ), 0),
    'whereis': (
        (
            '\n'
            'Usage:\n'
            ' whereis [options] [-BMS <dir>... -f] <name>\n'
            '\n'
            'Locate the binary, source, and manual-page files for a command.\n'
            '\n'
            'Options:\n'
            ' -b         search only for binaries\n'
            ' -B <dirs>  define binaries lookup path\n'
            ' -m         search only for manuals and infos\n'
            ' -M <dirs>  define man and info lookup path\n'
            ' -s         search only for sources\n'
            ' -S <dirs>  define sources lookup path\n'
            ' -f         terminate <dirs> argument list\n'
            ' -u         search for unusual entries\n'
            ' -g         interpret name as glob (pathnames pattern)\n'
            ' -l         output effective lookup paths\n'
            '\n'
            ' -h, --help     display this help\n'
            ' -V, --version  display version\n'
            '\n'
            'For more details see whereis(1).\n'
        ),
        (
            ''
        ), 0),
    'which': (
        (
            'Usage: /usr/bin/which [-as] args\n'
        ),
        (
            'Illegal option --\n'
        ), 2),
    'xargs': (
        (
            'Usage: xargs [OPTION]... COMMAND [INITIAL-ARGS]...\n'
            'Run COMMAND with arguments INITIAL-ARGS and more arguments read from input.\n'
            '\n'
            'Mandatory and optional arguments to long options are also\n'
            'mandatory or optional for the corresponding short option.\n'
            '  -0, --null                   items are separated by a null, not whitespace;\n'
            '                                 disables quote and backslash processing and\n'
            '                                 logical EOF processing\n'
            '  -a, --arg-file=FILE          read arguments from FILE, not standard input\n'
            '  -d, --delimiter=CHARACTER    items in input stream are separated by CHARACTER,\n'
            '                                 not by whitespace; disables quote and backslash\n'
            '                                 processing and logical EOF processing\n'
            '  -E END                       set logical EOF string; if END occurs as a line\n'
            '                                 of input, the rest of the input is ignored\n'
            '                                 (ignored if -0 or -d was specified)\n'
            '  -e, --eof[=END]              equivalent to -E END if END is specified;\n'
            '                                 otherwise, there is no end-of-file string\n'
            '  -I R                         same as --replace=R\n'
            '  -i, --replace[=R]            replace R in INITIAL-ARGS with names read\n'
            '                                 from standard input, split at newlines;\n'
            '                                 if R is unspecified, assume {}\n'
            '  -L, --max-lines=MAX-LINES    use at most MAX-LINES non-blank input lines per\n'
            '                                 command line\n'
            '  -l[MAX-LINES]                similar to -L but defaults to at most one non-\n'
            '                                 blank input line if MAX-LINES is not specified\n'
            '  -n, --max-args=MAX-ARGS      use at most MAX-ARGS arguments per command line\n'
            '  -o, --open-tty               Reopen stdin as /dev/tty in the child process\n'
            '                                 before executing the command; useful to run an\n'
            '                                 interactive application.\n'
            '  -P, --max-procs=MAX-PROCS    run at most MAX-PROCS processes at a time\n'
            '  -p, --interactive            prompt before running commands\n'
            '      --process-slot-var=VAR   set environment variable VAR in child processes\n'
            '  -r, --no-run-if-empty        if there are no arguments, then do not run COMMAND;\n'
            '                                 if this option is not given, COMMAND will be\n'
            '                                 run at least once\n'
            '  -s, --max-chars=MAX-CHARS    limit length of command line to MAX-CHARS\n'
            '      --show-limits            show limits on command-line length\n'
            '  -t, --verbose                print commands before executing them\n'
            '  -x, --exit                   exit if the size (see -s) is exceeded\n'
            '      --help                   display this help and exit\n'
            '      --version                output version information and exit\n'
            '\n'
            'Please see also the documentation at https://www.gnu.org/software/findutils/.\n'
            'You can report (and track progress on fixing) bugs in the "xargs"\n'
            'program via the GNU findutils bug-reporting page at\n'
            'https://savannah.gnu.org/bugs/?group=findutils or, if\n'
            'you have no web access, by sending email to <bug-findutils@gnu.org>.\n'
        ),
        (
            ''
        ), 0),
    'zcat': (
        (
            'Usage: /usr/bin/zcat [OPTION]... [FILE]...\n'
            'Uncompress FILEs to standard output.\n'
            '\n'
            '  -f, --force       force; read compressed data even from a terminal\n'
            '  -l, --list        list compressed file contents\n'
            '  -q, --quiet       suppress all warnings\n'
            '  -r, --recursive   operate recursively on directories\n'
            '  -S, --suffix=SUF  use suffix SUF on compressed files\n'
            '      --synchronous synchronous output (safer if system crashes, but slower)\n'
            '  -t, --test        test compressed file integrity\n'
            '  -v, --verbose     verbose mode\n'
            '      --help        display this help and exit\n'
            '      --version     display version information and exit\n'
            '\n'
            'With no FILE, or when FILE is -, read standard input.\n'
            '\n'
            'Report bugs to <bug-gzip@gnu.org>.\n'
        ),
        (
            ''
        ), 0),
}


#: A bash builtin prints its own help for --help and exits **2**, not 0.
#: Measured across all 61 builtins of bash 5.2.37: fifty-six do this, and
#: the five that do not are the ones that ignore their arguments -- `:`,
#: test and true exit 0 saying nothing, false exits 1 saying nothing, and
#: echo prints "--help". Those five we already matched.
#:
#: Ours answered: printf --help printed "--help" and exited 0; pwd --help
#: printed the working directory; cd --help said "cd: --help: No such
#: file or directory"; read --help said nothing and exited 1.
#:
#: Position matters and is handled by the caller, not here: --help is only
#: a help request while bash is still reading options. `cd --help` and
#: `pwd -L --help` print help, but `cd / --help` is "too many arguments"
#: and `export FOO=1 --help` is "not a valid identifier", because an
#: operand has already been seen and --help is then just data.
#:
#: Two builtins are deliberately absent. `[` answers a bare `[ --help`
#: with "missing `]'" rather than help, and `[ --help ]` -- which we
#: already answer correctly with rc 0 -- would break if it were routed
#: through a help table. `bind` answers with a readline warning that
#: depends on whether the session has a terminal, and ours can have one.
#:
#: name -> (stdout, stderr, exit status)
BUILTIN = {
    '.': (
        (
            '.: . filename [arguments]\n'
            '    Execute commands from a file in the current shell.\n'
            '    \n'
            '    Read and execute commands from FILENAME in the current shell.  The\n'
            '    entries in $PATH are used to find the directory containing FILENAME.\n'
            '    If any ARGUMENTS are supplied, they become the positional parameters\n'
            '    when FILENAME is executed.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns the status of the last command executed in FILENAME; fails if\n'
            '    FILENAME cannot be read.\n'
        ),
        (
            ''
        ), 2),
    'alias': (
        (
            'alias: alias [-p] [name[=value] ... ]\n'
            '    Define or display aliases.\n'
            '    \n'
            "    Without arguments, `alias' prints the list of aliases in the reusable\n"
            "    form `alias NAME=VALUE' on standard output.\n"
            '    \n'
            '    Otherwise, an alias is defined for each NAME whose VALUE is given.\n'
            '    A trailing space in VALUE causes the next word to be checked for\n'
            '    alias substitution when the alias is expanded.\n'
            '    \n'
            '    Options:\n'
            '      -p\tprint all defined aliases in a reusable format\n'
            '    \n'
            '    Exit Status:\n'
            '    alias returns true unless a NAME is supplied for which no alias has been\n'
            '    defined.\n'
        ),
        (
            ''
        ), 2),
    'bg': (
        (
            'bg: bg [job_spec ...]\n'
            '    Move jobs to the background.\n'
            '    \n'
            '    Place the jobs identified by each JOB_SPEC in the background, as if they\n'
            "    had been started with `&'.  If JOB_SPEC is not present, the shell's notion\n"
            '    of the current job is used.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless job control is not enabled or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'break': (
        (
            'break: break [n]\n'
            '    Exit for, while, or until loops.\n'
            '    \n'
            '    Exit a FOR, WHILE or UNTIL loop.  If N is specified, break N enclosing\n'
            '    loops.\n'
            '    \n'
            '    Exit Status:\n'
            '    The exit status is 0 unless N is not greater than or equal to 1.\n'
        ),
        (
            ''
        ), 2),
    'builtin': (
        (
            'builtin: builtin [shell-builtin [arg ...]]\n'
            '    Execute shell builtins.\n'
            '    \n'
            '    Execute SHELL-BUILTIN with arguments ARGs without performing command\n'
            '    lookup.  This is useful when you wish to reimplement a shell builtin\n'
            '    as a shell function, but need to execute the builtin within the function.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns the exit status of SHELL-BUILTIN, or false if SHELL-BUILTIN is\n'
            '    not a shell builtin.\n'
        ),
        (
            ''
        ), 2),
    'caller': (
        (
            'caller: caller [expr]\n'
            '    Return the context of the current subroutine call.\n'
            '    \n'
            '    Without EXPR, returns "$line $filename".  With EXPR, returns\n'
            '    "$line $subroutine $filename"; this extra information can be used to\n'
            '    provide a stack trace.\n'
            '    \n'
            '    The value of EXPR indicates how many call frames to go back before the\n'
            '    current one; the top frame is frame 0.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns 0 unless the shell is not executing a shell function or EXPR\n'
            '    is invalid.\n'
        ),
        (
            ''
        ), 2),
    'cd': (
        (
            'cd: cd [-L|[-P [-e]] [-@]] [dir]\n'
            '    Change the shell working directory.\n'
            '    \n'
            '    Change the current directory to DIR.  The default DIR is the value of the\n'
            '    HOME shell variable. If DIR is "-", it is converted to $OLDPWD.\n'
            '    \n'
            '    The variable CDPATH defines the search path for the directory containing\n'
            '    DIR.  Alternative directory names in CDPATH are separated by a colon (:).\n'
            '    A null directory name is the same as the current directory.  If DIR begins\n'
            '    with a slash (/), then CDPATH is not used.\n'
            '    \n'
            "    If the directory is not found, and the shell option `cdable_vars' is set,\n"
            '    the word is assumed to be  a variable name.  If that variable has a value,\n'
            '    its value is used for DIR.\n'
            '    \n'
            '    Options:\n'
            '      -L\tforce symbolic links to be followed: resolve symbolic\n'
            "    \t\tlinks in DIR after processing instances of `..'\n"
            '      -P\tuse the physical directory structure without following\n'
            '    \t\tsymbolic links: resolve symbolic links in DIR before\n'
            "    \t\tprocessing instances of `..'\n"
            '      -e\tif the -P option is supplied, and the current working\n'
            '    \t\tdirectory cannot be determined successfully, exit with\n'
            '    \t\ta non-zero status\n'
            '      -@\ton systems that support it, present a file with extended\n'
            '    \t\tattributes as a directory containing the file attributes\n'
            '    \n'
            "    The default is to follow symbolic links, as if `-L' were specified.\n"
            "    `..' is processed by removing the immediately previous pathname component\n"
            '    back to a slash or the beginning of DIR.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns 0 if the directory is changed, and if $PWD is set successfully when\n'
            '    -P is used; non-zero otherwise.\n'
        ),
        (
            ''
        ), 2),
    'command': (
        (
            'command: command [-pVv] command [arg ...]\n'
            '    Execute a simple command or display information about commands.\n'
            '    \n'
            '    Runs COMMAND with ARGS suppressing  shell function lookup, or display\n'
            '    information about the specified COMMANDs.  Can be used to invoke commands\n'
            '    on disk when a function with the same name exists.\n'
            '    \n'
            '    Options:\n'
            '      -p    use a default value for PATH that is guaranteed to find all of\n'
            '            the standard utilities\n'
            "      -v    print a description of COMMAND similar to the `type' builtin\n"
            '      -V    print a more verbose description of each COMMAND\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns exit status of COMMAND, or failure if COMMAND is not found.\n'
        ),
        (
            ''
        ), 2),
    'compgen': (
        (
            'compgen: compgen [-abcdefgjksuv] [-o option] [-A action] [-G globpat] [-W wordlist] [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [word]\n'
            '    Display possible completions depending on the options.\n'
            '    \n'
            '    Intended to be used from within a shell function generating possible\n'
            '    completions.  If the optional WORD argument is supplied, matches against\n'
            '    WORD are generated.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is supplied or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'complete': (
        (
            'complete: complete [-abcdefgjksuv] [-pr] [-DEI] [-o option] [-A action] [-G globpat] [-W wordlist] [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [name ...]\n'
            '    Specify how arguments are to be completed by Readline.\n'
            '    \n'
            '    For each NAME, specify how arguments are to be completed.  If no options\n'
            '    are supplied, existing completion specifications are printed in a way that\n'
            '    allows them to be reused as input.\n'
            '    \n'
            '    Options:\n'
            '      -p\tprint existing completion specifications in a reusable format\n'
            '      -r\tremove a completion specification for each NAME, or, if no\n'
            '    \t\tNAMEs are supplied, all completion specifications\n'
            '      -D\tapply the completions and actions as the default for commands\n'
            '    \t\twithout any specific completion defined\n'
            '      -E\tapply the completions and actions to "empty" commands --\n'
            '    \t\tcompletion attempted on a blank line\n'
            '      -I\tapply the completions and actions to the initial (usually the\n'
            '    \t\tcommand) word\n'
            '    \n'
            '    When completion is attempted, the actions are applied in the order the\n'
            '    uppercase-letter options are listed above. If multiple options are supplied,\n'
            '    the -D option takes precedence over -E, and both take precedence over -I.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is supplied or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'compopt': (
        (
            'compopt: compopt [-o|+o option] [-DEI] [name ...]\n'
            '    Modify or display completion options.\n'
            '    \n'
            '    Modify the completion options for each NAME, or, if no NAMEs are supplied,\n'
            '    the completion currently being executed.  If no OPTIONs are given, print\n'
            '    the completion options for each NAME or the current completion specification.\n'
            '    \n'
            '    Options:\n'
            '    \t-o option\tSet completion option OPTION for each NAME\n'
            '    \t-D\t\tChange options for the "default" command completion\n'
            '    \t-E\t\tChange options for the "empty" command completion\n'
            '    \t-I\t\tChange options for completion on the initial word\n'
            '    \n'
            "    Using `+o' instead of `-o' turns off the specified option.\n"
            '    \n'
            '    Arguments:\n'
            '    \n'
            '    Each NAME refers to a command for which a completion specification must\n'
            "    have previously been defined using the `complete' builtin.  If no NAMEs\n"
            '    are supplied, compopt must be called by a function currently generating\n'
            '    completions, and the options for that currently-executing completion\n'
            '    generator are modified.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is supplied or NAME does not\n'
            '    have a completion specification defined.\n'
        ),
        (
            ''
        ), 2),
    'continue': (
        (
            'continue: continue [n]\n'
            '    Resume for, while, or until loops.\n'
            '    \n'
            '    Resumes the next iteration of the enclosing FOR, WHILE or UNTIL loop.\n'
            '    If N is specified, resumes the Nth enclosing loop.\n'
            '    \n'
            '    Exit Status:\n'
            '    The exit status is 0 unless N is not greater than or equal to 1.\n'
        ),
        (
            ''
        ), 2),
    'declare': (
        (
            'declare: declare [-aAfFgiIlnrtux] [name[=value] ...] or declare -p [-aAfFilnrtux] [name ...]\n'
            '    Set variable values and attributes.\n'
            '    \n'
            '    Declare variables and give them attributes.  If no NAMEs are given,\n'
            '    display the attributes and values of all variables.\n'
            '    \n'
            '    Options:\n'
            '      -f\trestrict action or display to function names and definitions\n'
            '      -F\trestrict display to function names only (plus line number and\n'
            '    \t\tsource file when debugging)\n'
            '      -g\tcreate global variables when used in a shell function; otherwise\n'
            '    \t\tignored\n'
            '      -I\tif creating a local variable, inherit the attributes and value\n'
            '    \t\tof a variable with the same name at a previous scope\n'
            '      -p\tdisplay the attributes and value of each NAME\n'
            '    \n'
            '    Options which set attributes:\n'
            '      -a\tto make NAMEs indexed arrays (if supported)\n'
            '      -A\tto make NAMEs associative arrays (if supported)\n'
            "      -i\tto make NAMEs have the `integer' attribute\n"
            '      -l\tto convert the value of each NAME to lower case on assignment\n'
            '      -n\tmake NAME a reference to the variable named by its value\n'
            '      -r\tto make NAMEs readonly\n'
            "      -t\tto make NAMEs have the `trace' attribute\n"
            '      -u\tto convert the value of each NAME to upper case on assignment\n'
            '      -x\tto make NAMEs export\n'
            '    \n'
            "    Using `+' instead of `-' turns off the given attribute.\n"
            '    \n'
            '    Variables with the integer attribute have arithmetic evaluation (see\n'
            "    the `let' command) performed when the variable is assigned a value.\n"
            '    \n'
            "    When used in a function, `declare' makes NAMEs local, as with the `local'\n"
            "    command.  The `-g' option suppresses this behavior.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is supplied or a variable\n'
            '    assignment error occurs.\n'
        ),
        (
            ''
        ), 2),
    'dirs': (
        (
            'dirs: dirs [-clpv] [+N] [-N]\n'
            '    Display directory stack.\n'
            '    \n'
            '    Display the list of currently remembered directories.  Directories\n'
            "    find their way onto the list with the `pushd' command; you can get\n"
            "    back up through the list with the `popd' command.\n"
            '    \n'
            '    Options:\n'
            '      -c\tclear the directory stack by deleting all of the elements\n'
            '      -l\tdo not print tilde-prefixed versions of directories relative\n'
            '    \t\tto your home directory\n'
            '      -p\tprint the directory stack with one entry per line\n'
            '      -v\tprint the directory stack with one entry per line prefixed\n'
            '    \t\twith its position in the stack\n'
            '    \n'
            '    Arguments:\n'
            '      +N\tDisplays the Nth entry counting from the left of the list\n'
            '    \t\tshown by dirs when invoked without options, starting with\n'
            '    \t\tzero.\n'
            '    \n'
            '      -N\tDisplays the Nth entry counting from the right of the list\n'
            '    \t\tshown by dirs when invoked without options, starting with\n'
            '    \t\tzero.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is supplied or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'disown': (
        (
            'disown: disown [-h] [-ar] [jobspec ... | pid ...]\n'
            '    Remove jobs from current shell.\n'
            '    \n'
            '    Removes each JOBSPEC argument from the table of active jobs.  Without\n'
            '    any JOBSPECs, the shell uses its notion of the current job.\n'
            '    \n'
            '    Options:\n'
            '      -a\tremove all jobs if JOBSPEC is not supplied\n'
            '      -h\tmark each JOBSPEC so that SIGHUP is not sent to the job if the\n'
            '    \t\tshell receives a SIGHUP\n'
            '      -r\tremove only running jobs\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option or JOBSPEC is given.\n'
        ),
        (
            ''
        ), 2),
    'enable': (
        (
            'enable: enable [-a] [-dnps] [-f filename] [name ...]\n'
            '    Enable and disable shell builtins.\n'
            '    \n'
            '    Enables and disables builtin shell commands.  Disabling allows you to\n'
            '    execute a disk command which has the same name as a shell builtin\n'
            '    without using a full pathname.\n'
            '    \n'
            '    Options:\n'
            '      -a\tprint a list of builtins showing whether or not each is enabled\n'
            '      -n\tdisable each NAME or display a list of disabled builtins\n'
            '      -p\tprint the list of builtins in a reusable format\n'
            "      -s\tprint only the names of Posix `special' builtins\n"
            '    \n'
            '    Options controlling dynamic loading:\n'
            '      -f\tLoad builtin NAME from shared object FILENAME\n'
            '      -d\tRemove a builtin loaded with -f\n'
            '    \n'
            '    Without options, each NAME is enabled.\n'
            '    \n'
            "    To use the `test' found in $PATH instead of the shell builtin\n"
            "    version, type `enable -n test'.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless NAME is not a shell builtin or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'eval': (
        (
            'eval: eval [arg ...]\n'
            '    Execute arguments as a shell command.\n'
            '    \n'
            '    Combine ARGs into a single string, use the result as input to the shell,\n'
            '    and execute the resulting commands.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns exit status of command or success if command is null.\n'
        ),
        (
            ''
        ), 2),
    'exec': (
        (
            'exec: exec [-cl] [-a name] [command [argument ...]] [redirection ...]\n'
            '    Replace the shell with the given command.\n'
            '    \n'
            '    Execute COMMAND, replacing this shell with the specified program.\n'
            '    ARGUMENTS become the arguments to COMMAND.  If COMMAND is not specified,\n'
            '    any redirections take effect in the current shell.\n'
            '    \n'
            '    Options:\n'
            '      -a name\tpass NAME as the zeroth argument to COMMAND\n'
            '      -c\texecute COMMAND with an empty environment\n'
            '      -l\tplace a dash in the zeroth argument to COMMAND\n'
            '    \n'
            '    If the command cannot be executed, a non-interactive shell exits, unless\n'
            "    the shell option `execfail' is set.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless COMMAND is not found or a redirection error occurs.\n'
        ),
        (
            ''
        ), 2),
    'exit': (
        (
            'exit: exit [n]\n'
            '    Exit the shell.\n'
            '    \n'
            '    Exits the shell with a status of N.  If N is omitted, the exit status\n'
            '    is that of the last command executed.\n'
        ),
        (
            ''
        ), 2),
    'export': (
        (
            'export: export [-fn] [name[=value] ...] or export -p\n'
            '    Set export attribute for shell variables.\n'
            '    \n'
            '    Marks each NAME for automatic export to the environment of subsequently\n'
            '    executed commands.  If VALUE is supplied, assign VALUE before exporting.\n'
            '    \n'
            '    Options:\n'
            '      -f\trefer to shell functions\n'
            '      -n\tremove the export property from each NAME\n'
            '      -p\tdisplay a list of all exported variables and functions\n'
            '    \n'
            "    An argument of `--' disables further option processing.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or NAME is invalid.\n'
        ),
        (
            ''
        ), 2),
    'fc': (
        (
            'fc: fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]\n'
            '    Display or execute commands from the history list.\n'
            '    \n'
            '    fc is used to list or edit and re-execute commands from the history list.\n'
            '    FIRST and LAST can be numbers specifying the range, or FIRST can be a\n'
            '    string, which means the most recent command beginning with that\n'
            '    string.\n'
            '    \n'
            '    Options:\n'
            '      -e ENAME\tselect which editor to use.  Default is FCEDIT, then EDITOR,\n'
            '    \t\tthen vi\n'
            '      -l \tlist lines instead of editing\n'
            '      -n\tomit line numbers when listing\n'
            '      -r\treverse the order of the lines (newest listed first)\n'
            '    \n'
            "    With the `fc -s [pat=rep ...] [command]' format, COMMAND is\n"
            '    re-executed after the substitution OLD=NEW is performed.\n'
            '    \n'
            "    A useful alias to use with this is r='fc -s', so that typing `r cc'\n"
            "    runs the last command beginning with `cc' and typing `r' re-executes\n"
            '    the last command.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success or status of executed command; non-zero if an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'fg': (
        (
            'fg: fg [job_spec]\n'
            '    Move job to the foreground.\n'
            '    \n'
            '    Place the job identified by JOB_SPEC in the foreground, making it the\n'
            "    current job.  If JOB_SPEC is not present, the shell's notion of the\n"
            '    current job is used.\n'
            '    \n'
            '    Exit Status:\n'
            '    Status of command placed in foreground, or failure if an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'getopts': (
        (
            'getopts: getopts optstring name [arg ...]\n'
            '    Parse option arguments.\n'
            '    \n'
            '    Getopts is used by shell procedures to parse positional parameters\n'
            '    as options.\n'
            '    \n'
            '    OPTSTRING contains the option letters to be recognized; if a letter\n'
            '    is followed by a colon, the option is expected to have an argument,\n'
            '    which should be separated from it by white space.\n'
            '    \n'
            '    Each time it is invoked, getopts will place the next option in the\n'
            '    shell variable $name, initializing name if it does not exist, and\n'
            '    the index of the next argument to be processed into the shell\n'
            '    variable OPTIND.  OPTIND is initialized to 1 each time the shell or\n'
            '    a shell script is invoked.  When an option requires an argument,\n'
            '    getopts places that argument into the shell variable OPTARG.\n'
            '    \n'
            '    getopts reports errors in one of two ways.  If the first character\n'
            '    of OPTSTRING is a colon, getopts uses silent error reporting.  In\n'
            '    this mode, no error messages are printed.  If an invalid option is\n'
            '    seen, getopts places the option character found into OPTARG.  If a\n'
            "    required argument is not found, getopts places a ':' into NAME and\n"
            '    sets OPTARG to the option character found.  If getopts is not in\n'
            "    silent mode, and an invalid option is seen, getopts places '?' into\n"
            "    NAME and unsets OPTARG.  If a required argument is not found, a '?'\n"
            '    is placed in NAME, OPTARG is unset, and a diagnostic message is\n'
            '    printed.\n'
            '    \n'
            '    If the shell variable OPTERR has the value 0, getopts disables the\n'
            '    printing of error messages, even if the first character of\n'
            '    OPTSTRING is not a colon.  OPTERR has the value 1 by default.\n'
            '    \n'
            '    Getopts normally parses the positional parameters, but if arguments\n'
            '    are supplied as ARG values, they are parsed instead.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success if an option is found; fails if the end of options is\n'
            '    encountered or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'hash': (
        (
            'hash: hash [-lr] [-p pathname] [-dt] [name ...]\n'
            '    Remember or display program locations.\n'
            '    \n'
            '    Determine and remember the full pathname of each command NAME.  If\n'
            '    no arguments are given, information about remembered commands is displayed.\n'
            '    \n'
            '    Options:\n'
            '      -d\tforget the remembered location of each NAME\n'
            '      -l\tdisplay in a format that may be reused as input\n'
            '      -p pathname\tuse PATHNAME as the full pathname of NAME\n'
            '      -r\tforget all remembered locations\n'
            '      -t\tprint the remembered location of each NAME, preceding\n'
            '    \t\teach location with the corresponding NAME if multiple\n'
            '    \t\tNAMEs are given\n'
            '    Arguments:\n'
            '      NAME\tEach NAME is searched for in $PATH and added to the list\n'
            '    \t\tof remembered commands.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless NAME is not found or an invalid option is given.\n'
        ),
        (
            ''
        ), 2),
    'help': (
        (
            'help: help [-dms] [pattern ...]\n'
            '    Display information about builtin commands.\n'
            '    \n'
            '    Displays brief summaries of builtin commands.  If PATTERN is\n'
            '    specified, gives detailed help on all commands matching PATTERN,\n'
            '    otherwise the list of help topics is printed.\n'
            '    \n'
            '    Options:\n'
            '      -d\toutput short description for each topic\n'
            '      -m\tdisplay usage in pseudo-manpage format\n'
            '      -s\toutput only a short usage synopsis for each topic matching\n'
            '    \t\tPATTERN\n'
            '    \n'
            '    Arguments:\n'
            '      PATTERN\tPattern specifying a help topic\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless PATTERN is not found or an invalid option is given.\n'
        ),
        (
            ''
        ), 2),
    'history': (
        (
            'history: history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]\n'
            '    Display or manipulate the history list.\n'
            '    \n'
            '    Display the history list with line numbers, prefixing each modified\n'
            "    entry with a `*'.  An argument of N lists only the last N entries.\n"
            '    \n'
            '    Options:\n'
            '      -c\tclear the history list by deleting all of the entries\n'
            '      -d offset\tdelete the history entry at position OFFSET. Negative\n'
            '    \t\toffsets count back from the end of the history list\n'
            '    \n'
            '      -a\tappend history lines from this session to the history file\n'
            '      -n\tread all history lines not already read from the history file\n'
            '    \t\tand append them to the history list\n'
            '      -r\tread the history file and append the contents to the history\n'
            '    \t\tlist\n'
            '      -w\twrite the current history to the history file\n'
            '    \n'
            '      -p\tperform history expansion on each ARG and display the result\n'
            '    \t\twithout storing it in the history list\n'
            '      -s\tappend the ARGs to the history list as a single entry\n'
            '    \n'
            '    If FILENAME is given, it is used as the history file.  Otherwise,\n'
            '    if HISTFILE has a value, that is used, else ~/.bash_history.\n'
            '    \n'
            '    If the HISTTIMEFORMAT variable is set and not null, its value is used\n'
            '    as a format string for strftime(3) to print the time stamp associated\n'
            '    with each displayed history entry.  No time stamps are printed otherwise.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'jobs': (
        (
            'jobs: jobs [-lnprs] [jobspec ...] or jobs -x command [args]\n'
            '    Display status of jobs.\n'
            '    \n'
            '    Lists the active jobs.  JOBSPEC restricts output to that job.\n'
            '    Without options, the status of all active jobs is displayed.\n'
            '    \n'
            '    Options:\n'
            '      -l\tlists process IDs in addition to the normal information\n'
            '      -n\tlists only processes that have changed status since the last\n'
            '    \t\tnotification\n'
            '      -p\tlists process IDs only\n'
            '      -r\trestrict output to running jobs\n'
            '      -s\trestrict output to stopped jobs\n'
            '    \n'
            '    If -x is supplied, COMMAND is run after all job specifications that\n'
            "    appear in ARGS have been replaced with the process ID of that job's\n"
            '    process group leader.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or an error occurs.\n'
            '    If -x is used, returns the exit status of COMMAND.\n'
        ),
        (
            ''
        ), 2),
    'kill': (
        (
            'kill: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n'
            '    Send a signal to a job.\n'
            '    \n'
            '    Send the processes identified by PID or JOBSPEC the signal named by\n'
            '    SIGSPEC or SIGNUM.  If neither SIGSPEC nor SIGNUM is present, then\n'
            '    SIGTERM is assumed.\n'
            '    \n'
            '    Options:\n'
            '      -s sig\tSIG is a signal name\n'
            '      -n sig\tSIG is a signal number\n'
            "      -l\tlist the signal names; if arguments follow `-l' they are\n"
            '    \t\tassumed to be signal numbers for which names should be listed\n'
            '      -L\tsynonym for -l\n'
            '    \n'
            '    Kill is a shell builtin for two reasons: it allows job IDs to be used\n'
            '    instead of process IDs, and allows processes to be killed if the limit\n'
            '    on processes that you can create is reached.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'let': (
        (
            'let: let arg [arg ...]\n'
            '    Evaluate arithmetic expressions.\n'
            '    \n'
            '    Evaluate each ARG as an arithmetic expression.  Evaluation is done in\n'
            '    fixed-width integers with no check for overflow, though division by 0\n'
            '    is trapped and flagged as an error.  The following list of operators is\n'
            '    grouped into levels of equal-precedence operators.  The levels are listed\n'
            '    in order of decreasing precedence.\n'
            '    \n'
            '    \tid++, id--\tvariable post-increment, post-decrement\n'
            '    \t++id, --id\tvariable pre-increment, pre-decrement\n'
            '    \t-, +\t\tunary minus, plus\n'
            '    \t!, ~\t\tlogical and bitwise negation\n'
            '    \t**\t\texponentiation\n'
            '    \t*, /, %\t\tmultiplication, division, remainder\n'
            '    \t+, -\t\taddition, subtraction\n'
            '    \t<<, >>\t\tleft and right bitwise shifts\n'
            '    \t<=, >=, <, >\tcomparison\n'
            '    \t==, !=\t\tequality, inequality\n'
            '    \t&\t\tbitwise AND\n'
            '    \t^\t\tbitwise XOR\n'
            '    \t|\t\tbitwise OR\n'
            '    \t&&\t\tlogical AND\n'
            '    \t||\t\tlogical OR\n'
            '    \texpr ? expr : expr\n'
            '    \t\t\tconditional operator\n'
            '    \t=, *=, /=, %=,\n'
            '    \t+=, -=, <<=, >>=,\n'
            '    \t&=, ^=, |=\tassignment\n'
            '    \n'
            '    Shell variables are allowed as operands.  The name of the variable\n'
            '    is replaced by its value (coerced to a fixed-width integer) within\n'
            '    an expression.  The variable need not have its integer attribute\n'
            '    turned on to be used in an expression.\n'
            '    \n'
            '    Operators are evaluated in order of precedence.  Sub-expressions in\n'
            '    parentheses are evaluated first and may override the precedence\n'
            '    rules above.\n'
            '    \n'
            '    Exit Status:\n'
            '    If the last ARG evaluates to 0, let returns 1; let returns 0 otherwise.\n'
        ),
        (
            ''
        ), 2),
    'local': (
        (
            'local: local [option] name[=value] ...\n'
            '    Define local variables.\n'
            '    \n'
            '    Create a local variable called NAME, and give it VALUE.  OPTION can\n'
            "    be any option accepted by `declare'.\n"
            '    \n'
            '    Local variables can only be used within a function; they are visible\n'
            '    only to the function where they are defined and its children.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is supplied, a variable\n'
            '    assignment error occurs, or the shell is not executing a function.\n'
        ),
        (
            ''
        ), 2),
    'logout': (
        (
            'logout: logout [n]\n'
            '    Exit a login shell.\n'
            '    \n'
            '    Exits a login shell with exit status N.  Returns an error if not executed\n'
            '    in a login shell.\n'
        ),
        (
            ''
        ), 2),
    'mapfile': (
        (
            'mapfile: mapfile [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]\n'
            '    Read lines from the standard input into an indexed array variable.\n'
            '    \n'
            '    Read lines from the standard input into the indexed array variable ARRAY, or\n'
            '    from file descriptor FD if the -u option is supplied.  The variable MAPFILE\n'
            '    is the default ARRAY.\n'
            '    \n'
            '    Options:\n'
            '      -d delim\tUse DELIM to terminate lines, instead of newline\n'
            '      -n count\tCopy at most COUNT lines.  If COUNT is 0, all lines are copied\n'
            '      -O origin\tBegin assigning to ARRAY at index ORIGIN.  The default index is 0\n'
            '      -s count\tDiscard the first COUNT lines read\n'
            '      -t\tRemove a trailing DELIM from each line read (default newline)\n'
            '      -u fd\tRead lines from file descriptor FD instead of the standard input\n'
            '      -C callback\tEvaluate CALLBACK each time QUANTUM lines are read\n'
            '      -c quantum\tSpecify the number of lines read between each call to\n'
            '    \t\t\tCALLBACK\n'
            '    \n'
            '    Arguments:\n'
            '      ARRAY\tArray variable name to use for file data\n'
            '    \n'
            '    If -C is supplied without -c, the default quantum is 5000.  When\n'
            '    CALLBACK is evaluated, it is supplied the index of the next array\n'
            '    element to be assigned and the line to be assigned to that element\n'
            '    as additional arguments.\n'
            '    \n'
            '    If not supplied with an explicit origin, mapfile will clear ARRAY before\n'
            '    assigning to it.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or ARRAY is readonly or\n'
            '    not an indexed array.\n'
        ),
        (
            ''
        ), 2),
    'popd': (
        (
            'popd: popd [-n] [+N | -N]\n'
            '    Remove directories from stack.\n'
            '    \n'
            '    Removes entries from the directory stack.  With no arguments, removes\n'
            '    the top directory from the stack, and changes to the new top directory.\n'
            '    \n'
            '    Options:\n'
            '      -n\tSuppresses the normal change of directory when removing\n'
            '    \t\tdirectories from the stack, so only the stack is manipulated.\n'
            '    \n'
            '    Arguments:\n'
            '      +N\tRemoves the Nth entry counting from the left of the list\n'
            "    \t\tshown by `dirs', starting with zero.  For example: `popd +0'\n"
            "    \t\tremoves the first directory, `popd +1' the second.\n"
            '    \n'
            '      -N\tRemoves the Nth entry counting from the right of the list\n'
            "    \t\tshown by `dirs', starting with zero.  For example: `popd -0'\n"
            "    \t\tremoves the last directory, `popd -1' the next to last.\n"
            '    \n'
            "    The `dirs' builtin displays the directory stack.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid argument is supplied or the directory\n'
            '    change fails.\n'
        ),
        (
            ''
        ), 2),
    'printf': (
        (
            'printf: printf [-v var] format [arguments]\n'
            '    Formats and prints ARGUMENTS under control of the FORMAT.\n'
            '    \n'
            '    Options:\n'
            '      -v var\tassign the output to shell variable VAR rather than\n'
            '    \t\tdisplay it on the standard output\n'
            '    \n'
            '    FORMAT is a character string which contains three types of objects: plain\n'
            '    characters, which are simply copied to standard output; character escape\n'
            '    sequences, which are converted and copied to the standard output; and\n'
            '    format specifications, each of which causes printing of the next successive\n'
            '    argument.\n'
            '    \n'
            '    In addition to the standard format specifications described in printf(1),\n'
            '    printf interprets:\n'
            '    \n'
            '      %b\texpand backslash escape sequences in the corresponding argument\n'
            '      %q\tquote the argument in a way that can be reused as shell input\n'
            '      %Q\tlike %q, but apply any precision to the unquoted argument before\n'
            '    \t\tquoting\n'
            '      %(fmt)T\toutput the date-time string resulting from using FMT as a format\n'
            '    \t        string for strftime(3)\n'
            '    \n'
            '    The format is re-used as necessary to consume all of the arguments.  If\n'
            '    there are fewer arguments than the format requires,  extra format\n'
            '    specifications behave as if a zero value or null string, as appropriate,\n'
            '    had been supplied.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or a write or assignment\n'
            '    error occurs.\n'
        ),
        (
            ''
        ), 2),
    'pushd': (
        (
            'pushd: pushd [-n] [+N | -N | dir]\n'
            '    Add directories to stack.\n'
            '    \n'
            '    Adds a directory to the top of the directory stack, or rotates\n'
            '    the stack, making the new top of the stack the current working\n'
            '    directory.  With no arguments, exchanges the top two directories.\n'
            '    \n'
            '    Options:\n'
            '      -n\tSuppresses the normal change of directory when adding\n'
            '    \t\tdirectories to the stack, so only the stack is manipulated.\n'
            '    \n'
            '    Arguments:\n'
            '      +N\tRotates the stack so that the Nth directory (counting\n'
            "    \t\tfrom the left of the list shown by `dirs', starting with\n"
            '    \t\tzero) is at the top.\n'
            '    \n'
            '      -N\tRotates the stack so that the Nth directory (counting\n'
            "    \t\tfrom the right of the list shown by `dirs', starting with\n"
            '    \t\tzero) is at the top.\n'
            '    \n'
            '      dir\tAdds DIR to the directory stack at the top, making it the\n'
            '    \t\tnew current working directory.\n'
            '    \n'
            "    The `dirs' builtin displays the directory stack.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid argument is supplied or the directory\n'
            '    change fails.\n'
        ),
        (
            ''
        ), 2),
    'pwd': (
        (
            'pwd: pwd [-LP]\n'
            '    Print the name of the current working directory.\n'
            '    \n'
            '    Options:\n'
            '      -L\tprint the value of $PWD if it names the current working\n'
            '    \t\tdirectory\n'
            '      -P\tprint the physical directory, without any symbolic links\n'
            '    \n'
            "    By default, `pwd' behaves as if `-L' were specified.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns 0 unless an invalid option is given or the current directory\n'
            '    cannot be read.\n'
        ),
        (
            ''
        ), 2),
    'read': (
        (
            'read: read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]\n'
            '    Read a line from the standard input and split it into fields.\n'
            '    \n'
            '    Reads a single line from the standard input, or from file descriptor FD\n'
            '    if the -u option is supplied.  The line is split into fields as with word\n'
            '    splitting, and the first word is assigned to the first NAME, the second\n'
            '    word to the second NAME, and so on, with any leftover words assigned to\n'
            '    the last NAME.  Only the characters found in $IFS are recognized as word\n'
            '    delimiters. By default, the backslash character escapes delimiter characters\n'
            '    and newline.\n'
            '    \n'
            '    If no NAMEs are supplied, the line read is stored in the REPLY variable.\n'
            '    \n'
            '    Options:\n'
            '      -a array\tassign the words read to sequential indices of the array\n'
            '    \t\tvariable ARRAY, starting at zero\n'
            '      -d delim\tcontinue until the first character of DELIM is read, rather\n'
            '    \t\tthan newline\n'
            '      -e\tuse Readline to obtain the line\n'
            '      -i text\tuse TEXT as the initial text for Readline\n'
            '      -n nchars\treturn after reading NCHARS characters rather than waiting\n'
            '    \t\tfor a newline, but honor a delimiter if fewer than\n'
            '    \t\tNCHARS characters are read before the delimiter\n'
            '      -N nchars\treturn only after reading exactly NCHARS characters, unless\n'
            '    \t\tEOF is encountered or read times out, ignoring any\n'
            '    \t\tdelimiter\n'
            '      -p prompt\toutput the string PROMPT without a trailing newline before\n'
            '    \t\tattempting to read\n'
            '      -r\tdo not allow backslashes to escape any characters\n'
            '      -s\tdo not echo input coming from a terminal\n'
            '      -t timeout\ttime out and return failure if a complete line of\n'
            '    \t\tinput is not read within TIMEOUT seconds.  The value of the\n'
            '    \t\tTMOUT variable is the default timeout.  TIMEOUT may be a\n'
            '    \t\tfractional number.  If TIMEOUT is 0, read returns\n'
            '    \t\timmediately, without trying to read any data, returning\n'
            '    \t\tsuccess only if input is available on the specified\n'
            '    \t\tfile descriptor.  The exit status is greater than 128\n'
            '    \t\tif the timeout is exceeded\n'
            '      -u fd\tread from file descriptor FD instead of the standard input\n'
            '    \n'
            '    Exit Status:\n'
            '    The return code is zero, unless end-of-file is encountered, read times out\n'
            "    (in which case it's greater than 128), a variable assignment error occurs,\n"
            '    or an invalid file descriptor is supplied as the argument to -u.\n'
        ),
        (
            ''
        ), 2),
    'readarray': (
        (
            'readarray: readarray [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]\n'
            '    Read lines from a file into an array variable.\n'
            '    \n'
            "    A synonym for `mapfile'.\n"
        ),
        (
            ''
        ), 2),
    'readonly': (
        (
            'readonly: readonly [-aAf] [name[=value] ...] or readonly -p\n'
            '    Mark shell variables as unchangeable.\n'
            '    \n'
            '    Mark each NAME as read-only; the values of these NAMEs may not be\n'
            '    changed by subsequent assignment.  If VALUE is supplied, assign VALUE\n'
            '    before marking as read-only.\n'
            '    \n'
            '    Options:\n'
            '      -a\trefer to indexed array variables\n'
            '      -A\trefer to associative array variables\n'
            '      -f\trefer to shell functions\n'
            '      -p\tdisplay a list of all readonly variables or functions,\n'
            '    \t\tdepending on whether or not the -f option is given\n'
            '    \n'
            "    An argument of `--' disables further option processing.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or NAME is invalid.\n'
        ),
        (
            ''
        ), 2),
    'return': (
        (
            'return: return [n]\n'
            '    Return from a shell function.\n'
            '    \n'
            '    Causes a function or sourced script to exit with the return value\n'
            '    specified by N.  If N is omitted, the return status is that of the\n'
            '    last command executed within the function or script.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns N, or failure if the shell is not executing a function or script.\n'
        ),
        (
            ''
        ), 2),
    'set': (
        (
            'set: set [-abefhkmnptuvxBCEHPT] [-o option-name] [--] [-] [arg ...]\n'
            '    Set or unset values of shell options and positional parameters.\n'
            '    \n'
            '    Change the value of shell attributes and positional parameters, or\n'
            '    display the names and values of shell variables.\n'
            '    \n'
            '    Options:\n'
            '      -a  Mark variables which are modified or created for export.\n'
            '      -b  Notify of job termination immediately.\n'
            '      -e  Exit immediately if a command exits with a non-zero status.\n'
            '      -f  Disable file name generation (globbing).\n'
            '      -h  Remember the location of commands as they are looked up.\n'
            '      -k  All assignment arguments are placed in the environment for a\n'
            '          command, not just those that precede the command name.\n'
            '      -m  Job control is enabled.\n'
            '      -n  Read commands but do not execute them.\n'
            '      -o option-name\n'
            '          Set the variable corresponding to option-name:\n'
            '              allexport    same as -a\n'
            '              braceexpand  same as -B\n'
            '              emacs        use an emacs-style line editing interface\n'
            '              errexit      same as -e\n'
            '              errtrace     same as -E\n'
            '              functrace    same as -T\n'
            '              hashall      same as -h\n'
            '              histexpand   same as -H\n'
            '              history      enable command history\n'
            '              ignoreeof    the shell will not exit upon reading EOF\n'
            '              interactive-comments\n'
            '                           allow comments to appear in interactive commands\n'
            '              keyword      same as -k\n'
            '              monitor      same as -m\n'
            '              noclobber    same as -C\n'
            '              noexec       same as -n\n'
            '              noglob       same as -f\n'
            '              nolog        currently accepted but ignored\n'
            '              notify       same as -b\n'
            '              nounset      same as -u\n'
            '              onecmd       same as -t\n'
            '              physical     same as -P\n'
            '              pipefail     the return value of a pipeline is the status of\n'
            '                           the last command to exit with a non-zero status,\n'
            '                           or zero if no command exited with a non-zero status\n'
            '              posix        change the behavior of bash where the default\n'
            '                           operation differs from the Posix standard to\n'
            '                           match the standard\n'
            '              privileged   same as -p\n'
            '              verbose      same as -v\n'
            '              vi           use a vi-style line editing interface\n'
            '              xtrace       same as -x\n'
            '      -p  Turned on whenever the real and effective user ids do not match.\n'
            '          Disables processing of the $ENV file and importing of shell\n'
            '          functions.  Turning this option off causes the effective uid and\n'
            '          gid to be set to the real uid and gid.\n'
            '      -t  Exit after reading and executing one command.\n'
            '      -u  Treat unset variables as an error when substituting.\n'
            '      -v  Print shell input lines as they are read.\n'
            '      -x  Print commands and their arguments as they are executed.\n'
            '      -B  the shell will perform brace expansion\n'
            '      -C  If set, disallow existing regular files to be overwritten\n'
            '          by redirection of output.\n'
            '      -E  If set, the ERR trap is inherited by shell functions.\n'
            '      -H  Enable ! style history substitution.  This flag is on\n'
            '          by default when the shell is interactive.\n'
            '      -P  If set, do not resolve symbolic links when executing commands\n'
            '          such as cd which change the current directory.\n'
            '      -T  If set, the DEBUG and RETURN traps are inherited by shell functions.\n'
            '      --  Assign any remaining arguments to the positional parameters.\n'
            '          If there are no remaining arguments, the positional parameters\n'
            '          are unset.\n'
            '      -   Assign any remaining arguments to the positional parameters.\n'
            '          The -x and -v options are turned off.\n'
            '    \n'
            '    Using + rather than - causes these flags to be turned off.  The\n'
            '    flags can also be used upon invocation of the shell.  The current\n'
            '    set of flags may be found in $-.  The remaining n ARGs are positional\n'
            '    parameters and are assigned, in order, to $1, $2, .. $n.  If no\n'
            '    ARGs are given, all shell variables are printed.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given.\n'
        ),
        (
            ''
        ), 2),
    'shift': (
        (
            'shift: shift [n]\n'
            '    Shift positional parameters.\n'
            '    \n'
            '    Rename the positional parameters $N+1,$N+2 ... to $1,$2 ...  If N is\n'
            '    not given, it is assumed to be 1.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless N is negative or greater than $#.\n'
        ),
        (
            ''
        ), 2),
    'shopt': (
        (
            'shopt: shopt [-pqsu] [-o] [optname ...]\n'
            '    Set and unset shell options.\n'
            '    \n'
            '    Change the setting of each shell option OPTNAME.  Without any option\n'
            '    arguments, list each supplied OPTNAME, or all shell options if no\n'
            '    OPTNAMEs are given, with an indication of whether or not each is set.\n'
            '    \n'
            '    Options:\n'
            "      -o\trestrict OPTNAMEs to those defined for use with `set -o'\n"
            '      -p\tprint each shell option with an indication of its status\n'
            '      -q\tsuppress output\n'
            '      -s\tenable (set) each OPTNAME\n'
            '      -u\tdisable (unset) each OPTNAME\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success if OPTNAME is enabled; fails if an invalid option is\n'
            '    given or OPTNAME is disabled.\n'
        ),
        (
            ''
        ), 2),
    'source': (
        (
            'source: source filename [arguments]\n'
            '    Execute commands from a file in the current shell.\n'
            '    \n'
            '    Read and execute commands from FILENAME in the current shell.  The\n'
            '    entries in $PATH are used to find the directory containing FILENAME.\n'
            '    If any ARGUMENTS are supplied, they become the positional parameters\n'
            '    when FILENAME is executed.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns the status of the last command executed in FILENAME; fails if\n'
            '    FILENAME cannot be read.\n'
        ),
        (
            ''
        ), 2),
    'suspend': (
        (
            'suspend: suspend [-f]\n'
            '    Suspend shell execution.\n'
            '    \n'
            '    Suspend the execution of this shell until it receives a SIGCONT signal.\n'
            '    Unless forced, login shells and shells without job control cannot be\n'
            '    suspended.\n'
            '    \n'
            '    Options:\n'
            '      -f\tforce the suspend, even if the shell is a login shell or job\n'
            '    \t\tcontrol is not enabled.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless job control is not enabled or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'times': (
        (
            'times: times\n'
            '    Display process times.\n'
            '    \n'
            '    Prints the accumulated user and system times for the shell and all of its\n'
            '    child processes.\n'
            '    \n'
            '    Exit Status:\n'
            '    Always succeeds.\n'
        ),
        (
            ''
        ), 2),
    'trap': (
        (
            'trap: trap [-lp] [[arg] signal_spec ...]\n'
            '    Trap signals and other events.\n'
            '    \n'
            '    Defines and activates handlers to be run when the shell receives signals\n'
            '    or other conditions.\n'
            '    \n'
            '    ARG is a command to be read and executed when the shell receives the\n'
            '    signal(s) SIGNAL_SPEC.  If ARG is absent (and a single SIGNAL_SPEC\n'
            "    is supplied) or `-', each specified signal is reset to its original\n"
            '    value.  If ARG is the null string each SIGNAL_SPEC is ignored by the\n'
            '    shell and by the commands it invokes.\n'
            '    \n'
            '    If a SIGNAL_SPEC is EXIT (0) ARG is executed on exit from the shell.  If\n'
            '    a SIGNAL_SPEC is DEBUG, ARG is executed before every simple command.  If\n'
            '    a SIGNAL_SPEC is RETURN, ARG is executed each time a shell function or a\n'
            '    script run by the . or source builtins finishes executing.  A SIGNAL_SPEC\n'
            "    of ERR means to execute ARG each time a command's failure would cause the\n"
            '    shell to exit when the -e option is enabled.\n'
            '    \n'
            '    If no arguments are supplied, trap prints the list of commands associated\n'
            '    with each signal.\n'
            '    \n'
            '    Options:\n'
            '      -l\tprint a list of signal names and their corresponding numbers\n'
            '      -p\tdisplay the trap commands associated with each SIGNAL_SPEC\n'
            '    \n'
            '    Each SIGNAL_SPEC is either a signal name in <signal.h> or a signal number.\n'
            '    Signal names are case insensitive and the SIG prefix is optional.  A\n'
            '    signal may be sent to the shell with "kill -signal $$".\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless a SIGSPEC is invalid or an invalid option is given.\n'
        ),
        (
            ''
        ), 2),
    'type': (
        (
            'type: type [-afptP] name [name ...]\n'
            '    Display information about command type.\n'
            '    \n'
            '    For each NAME, indicate how it would be interpreted if used as a\n'
            '    command name.\n'
            '    \n'
            '    Options:\n'
            '      -a\tdisplay all locations containing an executable named NAME;\n'
            '    \t\tincludes aliases, builtins, and functions, if and only if\n'
            "    \t\tthe `-p' option is not also used\n"
            '      -f\tsuppress shell function lookup\n'
            '      -P\tforce a PATH search for each NAME, even if it is an alias,\n'
            '    \t\tbuiltin, or function, and returns the name of the disk file\n'
            '    \t\tthat would be executed\n'
            '      -p\treturns either the name of the disk file that would be executed,\n'
            "    \t\tor nothing if `type -t NAME' would not return `file'\n"
            "      -t\toutput a single word which is one of `alias', `keyword',\n"
            "    \t\t`function', `builtin', `file' or `', if NAME is an alias,\n"
            '    \t\tshell reserved word, shell function, shell builtin, disk file,\n'
            '    \t\tor not found, respectively\n'
            '    \n'
            '    Arguments:\n'
            '      NAME\tCommand name to be interpreted.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success if all of the NAMEs are found; fails if any are not found.\n'
        ),
        (
            ''
        ), 2),
    'typeset': (
        (
            'typeset: typeset [-aAfFgiIlnrtux] name[=value] ... or typeset -p [-aAfFilnrtux] [name ...]\n'
            '    Set variable values and attributes.\n'
            '    \n'
            "    A synonym for `declare'.  See `help declare'.\n"
        ),
        (
            ''
        ), 2),
    'ulimit': (
        (
            'ulimit: ulimit [-SHabcdefiklmnpqrstuvxPRT] [limit]\n'
            '    Modify shell resource limits.\n'
            '    \n'
            '    Provides control over the resources available to the shell and processes\n'
            '    it creates, on systems that allow such control.\n'
            '    \n'
            '    Options:\n'
            "      -S\tuse the `soft' resource limit\n"
            "      -H\tuse the `hard' resource limit\n"
            '      -a\tall current limits are reported\n'
            '      -b\tthe socket buffer size\n'
            '      -c\tthe maximum size of core files created\n'
            "      -d\tthe maximum size of a process's data segment\n"
            "      -e\tthe maximum scheduling priority (`nice')\n"
            '      -f\tthe maximum size of files written by the shell and its children\n'
            '      -i\tthe maximum number of pending signals\n'
            '      -k\tthe maximum number of kqueues allocated for this process\n'
            '      -l\tthe maximum size a process may lock into memory\n'
            '      -m\tthe maximum resident set size\n'
            '      -n\tthe maximum number of open file descriptors\n'
            '      -p\tthe pipe buffer size\n'
            '      -q\tthe maximum number of bytes in POSIX message queues\n'
            '      -r\tthe maximum real-time scheduling priority\n'
            '      -s\tthe maximum stack size\n'
            '      -t\tthe maximum amount of cpu time in seconds\n'
            '      -u\tthe maximum number of user processes\n'
            '      -v\tthe size of virtual memory\n'
            '      -x\tthe maximum number of file locks\n'
            '      -P\tthe maximum number of pseudoterminals\n'
            '      -R\tthe maximum time a real-time process can run before blocking\n'
            '      -T\tthe maximum number of threads\n'
            '    \n'
            '    Not all options are available on all platforms.\n'
            '    \n'
            '    If LIMIT is given, it is the new value of the specified resource; the\n'
            "    special LIMIT values `soft', `hard', and `unlimited' stand for the\n"
            '    current soft limit, the current hard limit, and no limit, respectively.\n'
            '    Otherwise, the current value of the specified resource is printed.  If\n'
            '    no option is given, then -f is assumed.\n'
            '    \n'
            '    Values are in 1024-byte increments, except for -t, which is in seconds,\n'
            '    -p, which is in increments of 512 bytes, and -u, which is an unscaled\n'
            '    number of processes.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is supplied or an error occurs.\n'
        ),
        (
            ''
        ), 2),
    'umask': (
        (
            'umask: umask [-p] [-S] [mode]\n'
            '    Display or set file mode mask.\n'
            '    \n'
            '    Sets the user file-creation mask to MODE.  If MODE is omitted, prints\n'
            '    the current value of the mask.\n'
            '    \n'
            '    If MODE begins with a digit, it is interpreted as an octal number;\n'
            '    otherwise it is a symbolic mode string like that accepted by chmod(1).\n'
            '    \n'
            '    Options:\n'
            '      -p\tif MODE is omitted, output in a form that may be reused as input\n'
            '      -S\tmakes the output symbolic; otherwise an octal number is output\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless MODE is invalid or an invalid option is given.\n'
        ),
        (
            ''
        ), 2),
    'unalias': (
        (
            'unalias: unalias [-a] name [name ...]\n'
            '    Remove each NAME from the list of defined aliases.\n'
            '    \n'
            '    Options:\n'
            '      -a\tremove all alias definitions\n'
            '    \n'
            '    Return success unless a NAME is not an existing alias.\n'
        ),
        (
            ''
        ), 2),
    'unset': (
        (
            'unset: unset [-f] [-v] [-n] [name ...]\n'
            '    Unset values and attributes of shell variables and functions.\n'
            '    \n'
            '    For each NAME, remove the corresponding variable or function.\n'
            '    \n'
            '    Options:\n'
            '      -f\ttreat each NAME as a shell function\n'
            '      -v\ttreat each NAME as a shell variable\n'
            '      -n\ttreat each NAME as a name reference and unset the variable itself\n'
            '    \t\trather than the variable it references\n'
            '    \n'
            '    Without options, unset first tries to unset a variable, and if that fails,\n'
            '    tries to unset a function.\n'
            '    \n'
            "    Some variables cannot be unset; also see `readonly'.\n"
            '    \n'
            '    Exit Status:\n'
            '    Returns success unless an invalid option is given or a NAME is read-only.\n'
        ),
        (
            ''
        ), 2),
    'wait': (
        (
            'wait: wait [-fn] [-p var] [id ...]\n'
            '    Wait for job completion and return exit status.\n'
            '    \n'
            '    Waits for each process identified by an ID, which may be a process ID or a\n'
            '    job specification, and reports its termination status.  If ID is not\n'
            '    given, waits for all currently active child processes, and the return\n'
            '    status is zero.  If ID is a job specification, waits for all processes\n'
            "    in that job's pipeline.\n"
            '    \n'
            '    If the -n option is supplied, waits for a single job from the list of IDs,\n'
            '    or, if no IDs are supplied, for the next job to complete and returns its\n'
            '    exit status.\n'
            '    \n'
            '    If the -p option is supplied, the process or job identifier of the job\n'
            '    for which the exit status is returned is assigned to the variable VAR\n'
            '    named by the option argument. The variable will be unset initially, before\n'
            '    any assignment. This is useful only when the -n option is supplied.\n'
            '    \n'
            '    If the -f option is supplied, and job control is enabled, waits for the\n'
            '    specified ID to terminate, instead of waiting for it to change status.\n'
            '    \n'
            '    Exit Status:\n'
            '    Returns the status of the last ID; fails if ID is invalid or an invalid\n'
            '    option is given, or if -n is supplied and the shell has no unwaited-for\n'
            '    children.\n'
        ),
        (
            ''
        ), 2),
}


#: The tools an attacker actually types, measured the same way. These were
#: not on the stock-template list, because they answered --help with
#: something -- just not with their help:
#:
#:   journalctl --help   310899 bytes of the JOURNAL, against 5213 of help
#:   tar --help          "tar: unrecognized option" on stderr, rc 2
#:   grep --help         43 bytes on stderr, rc 2, against 4042 on stdout
#:   sed, find, dpkg, dmesg, getent, umount, unxz, egrep, fgrep: the same
#:                       shape -- a short line on the wrong stream, and a
#:                       non-zero status for a request that succeeds
#:   ip --help           ours 331 bytes on stdout rc 0; the real one puts
#:                       982 on stderr and exits 255
#:   systemctl --help    3836 bytes against 12585 -- a partial help
#:
#: egrep and fgrep print grep's help, byte for byte, because that is what
#: they are. socat is deliberately absent: its usage line carries a
#: timestamp and its own pid, so there is nothing stable to store.
HELP.update({
    'apt': (
        (
            'apt 3.0.3 (amd64)\n'
            'Usage: apt [options] command\n'
            '\n'
            'apt is a commandline package manager and provides commands for\n'
            'searching and managing as well as querying information about packages.\n'
            'It provides the same functionality as the specialized APT tools,\n'
            'like apt-get and apt-cache, but enables options more suitable for\n'
            'interactive use by default.\n'
            '\n'
            'Most used commands:\n'
            '  list - list packages based on package names\n'
            '  search - search in package descriptions\n'
            '  show - show package details\n'
            '  install - install packages\n'
            '  reinstall - reinstall packages\n'
            '  remove - remove packages\n'
            '  autoremove - automatically remove all unused packages\n'
            '  update - update list of available packages\n'
            '  upgrade - upgrade the system by installing/upgrading packages\n'
            '  full-upgrade - upgrade the system by removing/installing/upgrading packages\n'
            '  edit-sources - edit the source information file\n'
            '  modernize-sources - modernize .list files to .sources files\n'
            '  satisfy - satisfy dependency strings\n'
            '\n'
            'See apt(8) for more information about the available commands.\n'
            'Configuration options and syntax is detailed in apt.conf(5).\n'
            'Information about how to configure sources can be found in sources.list(5).\n'
            'Package and version choices can be expressed via apt_preferences(5).\n'
            'Security details are available in apt-secure(8).\n'
            '                                        This APT has Super Cow Powers.\n'
        ),
        (
            ''
        ), 0),
    'apt-cache': (
        (
            'apt 3.0.3 (amd64)\n'
            'Usage: apt-cache [options] command\n'
            '       apt-cache [options] show pkg1 [pkg2 ...]\n'
            '\n'
            'apt-cache queries and displays available information about installed\n'
            'and installable packages. It works exclusively on the data acquired\n'
            "into the local cache via the 'update' command of e.g. apt-get. The\n"
            'displayed information may therefore be outdated if the last update was\n'
            'too long ago, but in exchange apt-cache works independently of the\n'
            'availability of the configured sources (e.g. offline).\n'
            '\n'
            'Most used commands:\n'
            '  showsrc - Show source records\n'
            '  search - Search the package list for a regex pattern\n'
            '  depends - Show raw dependency information for a package\n'
            '  rdepends - Show reverse dependency information for a package\n'
            '  show - Show a readable record for the package\n'
            '  pkgnames - List the names of all packages in the system\n'
            '  policy - Show policy settings\n'
            '\n'
            'See apt-cache(8) for more information about the available commands.\n'
            'Configuration options and syntax is detailed in apt.conf(5).\n'
            'Information about how to configure sources can be found in sources.list(5).\n'
            'Package and version choices can be expressed via apt_preferences(5).\n'
            'Security details are available in apt-secure(8).\n'
        ),
        (
            ''
        ), 0),
    'apt-get': (
        (
            'apt 3.0.3 (amd64)\n'
            'Usage: apt-get [options] command\n'
            '       apt-get [options] install|remove pkg1 [pkg2 ...]\n'
            '       apt-get [options] source pkg1 [pkg2 ...]\n'
            '\n'
            'apt-get is a command line interface for retrieval of packages\n'
            'and information about them from authenticated sources and\n'
            'for installation, upgrade and removal of packages together\n'
            'with their dependencies.\n'
            '\n'
            'Most used commands:\n'
            '  update - Retrieve new lists of packages\n'
            '  upgrade - Perform an upgrade\n'
            '  install - Install new packages (pkg is libc6 not libc6.deb)\n'
            '  reinstall - Reinstall packages (pkg is libc6 not libc6.deb)\n'
            '  remove - Remove packages\n'
            '  purge - Remove packages and config files\n'
            '  autoremove - Remove automatically all unused packages\n'
            '  dist-upgrade - Distribution upgrade, see apt-get(8)\n'
            '  dselect-upgrade - Follow dselect selections\n'
            '  build-dep - Configure build-dependencies for source packages\n'
            '  satisfy - Satisfy dependency strings\n'
            '  clean - Erase downloaded archive files\n'
            '  autoclean - Erase old downloaded archive files\n'
            '  check - Verify that there are no broken dependencies\n'
            '  source - Download source archives\n'
            '  download - Download the binary package into the current directory\n'
            '  changelog - Download and display the changelog for the given package\n'
            '\n'
            'See apt-get(8) for more information about the available commands.\n'
            'Configuration options and syntax is detailed in apt.conf(5).\n'
            'Information about how to configure sources can be found in sources.list(5).\n'
            'Package and version choices can be expressed via apt_preferences(5).\n'
            'Security details are available in apt-secure(8).\n'
            '                                        This APT has Super Cow Powers.\n'
        ),
        (
            ''
        ), 0),
    'chattr': (
        (
            ''
        ),
        (
            'Usage: chattr [-RVf] [-+=aAcCdDeijPsStTuFx] [-p project] [-v version] files...\n'
        ), 1),
    'dmesg': (
        (
            '\n'
            'Usage:\n'
            ' dmesg [options]\n'
            '\n'
            'Display or control the kernel ring buffer.\n'
            '\n'
            'Options:\n'
            ' -C, --clear                 clear the kernel ring buffer\n'
            ' -c, --read-clear            read and clear all messages\n'
            ' -D, --console-off           disable printing messages to console\n'
            ' -E, --console-on            enable printing messages to console\n'
            ' -F, --file <file>           use the file instead of the kernel log buffer\n'
            ' -K, --kmsg-file <file>      use the file in kmsg format\n'
            ' -f, --facility <list>       restrict output to defined facilities\n'
            ' -H, --human                 human readable output\n'
            ' -J, --json                  use JSON output format\n'
            ' -k, --kernel                display kernel messages\n'
            ' -L, --color[=<when>]        colorize messages (auto, always or never)\n'
            '                               colors are enabled by default\n'
            ' -l, --level <list>          restrict output to defined levels\n'
            ' -n, --console-level <level> set level of messages printed to console\n'
            ' -P, --nopager               do not pipe output into a pager\n'
            ' -p, --force-prefix          force timestamp output on each line of multi-line messages\n'
            ' -r, --raw                   print the raw message buffer\n'
            "     --noescape              don't escape unprintable character\n"
            ' -S, --syslog                force to use syslog(2) rather than /dev/kmsg\n'
            ' -s, --buffer-size <size>    buffer size to query the kernel ring buffer\n'
            ' -u, --userspace             display userspace messages\n'
            ' -w, --follow                wait for new messages\n'
            ' -W, --follow-new            wait and print only new messages\n'
            ' -x, --decode                decode facility and level to readable string\n'
            ' -d, --show-delta            show time delta between printed messages\n'
            ' -e, --reltime               show local time and time delta in readable format\n'
            ' -T, --ctime                 show human-readable timestamp (may be inaccurate!)\n'
            " -t, --notime                don't show any timestamp with messages\n"
            '     --time-format <format>  show timestamp using the given format:\n'
            '                               [delta|reltime|ctime|notime|iso|raw]\n'
            'Suspending/resume will make ctime and iso timestamps inaccurate.\n'
            '     --since <time>          display the lines since the specified time\n'
            '     --until <time>          display the lines until the specified time\n'
            '\n'
            ' -h, --help                  display this help\n'
            ' -V, --version               display version\n'
            '\n'
            'Supported log facilities:\n'
            '    kern - kernel messages\n'
            '    user - random user-level messages\n'
            '    mail - mail system\n'
            '  daemon - system daemons\n'
            '    auth - security/authorization messages\n'
            '  syslog - messages generated internally by syslogd\n'
            '     lpr - line printer subsystem\n'
            '    news - network news subsystem\n'
            '    uucp - UUCP subsystem\n'
            '    cron - clock daemon\n'
            ' authpriv - security/authorization messages (private)\n'
            '     ftp - FTP daemon\n'
            '    res0 - reserved 0\n'
            '    res1 - reserved 1\n'
            '    res2 - reserved 2\n'
            '    res3 - reserved 3\n'
            '  local0 - local use 0\n'
            '  local1 - local use 1\n'
            '  local2 - local use 2\n'
            '  local3 - local use 3\n'
            '  local4 - local use 4\n'
            '  local5 - local use 5\n'
            '  local6 - local use 6\n'
            '  local7 - local use 7\n'
            '\n'
            'Supported log levels (priorities):\n'
            '   emerg - system is unusable\n'
            '   alert - action must be taken immediately\n'
            '    crit - critical conditions\n'
            '     err - error conditions\n'
            '    warn - warning conditions\n'
            '  notice - normal but significant condition\n'
            '    info - informational\n'
            '   debug - debug-level messages\n'
            '\n'
            'For more details see dmesg(1).\n'
        ),
        (
            ''
        ), 0),
    'dpkg': (
        (
            'Usage: dpkg [<option>...] <command>\n'
            '\n'
            'Commands:\n'
            '  -i|--install       <.deb file name>... | -R|--recursive <directory>...\n'
            '  --unpack           <.deb file name>... | -R|--recursive <directory>...\n'
            '  -A|--record-avail  <.deb file name>... | -R|--recursive <directory>...\n'
            '  --configure        <package>... | -a|--pending\n'
            '  --triggers-only    <package>... | -a|--pending\n'
            '  -r|--remove        <package>... | -a|--pending\n'
            '  -P|--purge         <package>... | -a|--pending\n'
            '  -V|--verify [<package>...]       Verify the integrity of package(s).\n'
            '  --get-selections [<pattern>...]  Get list of selections to stdout.\n'
            '  --set-selections                 Set package selections from stdin.\n'
            '  --clear-selections               Deselect every non-essential package.\n'
            '  --update-avail [<Packages-file>] Replace available packages info.\n'
            '  --merge-avail [<Packages-file>]  Merge with info from file.\n'
            '  --clear-avail                    Erase existing available info.\n'
            '  --forget-old-unavail             Forget uninstalled unavailable pkgs.\n'
            '  -s|--status [<package>...]       Display package status details.\n'
            '  -p|--print-avail [<package>...]  Display available version details.\n'
            "  -L|--listfiles <package>...      List files 'owned' by package(s).\n"
            '  -l|--list [<pattern>...]         List packages concisely.\n'
            '  -S|--search <pattern>...         Find package(s) owning file(s).\n'
            '  -C|--audit [<package>...]        Check for broken package(s).\n'
            '  --yet-to-unpack                  Print packages selected for installation.\n'
            '  --predep-package                 Print pre-dependencies to unpack.\n'
            '  --add-architecture <arch>        Add <arch> to the list of architectures.\n'
            '  --remove-architecture <arch>     Remove <arch> from the list of architectures.\n'
            '  --print-architecture             Print dpkg architecture.\n'
            '  --print-foreign-architectures    Print allowed foreign architectures.\n'
            '  --assert-help                    Show help on assertions.\n'
            '  --assert-<feature>               Assert support for the specified feature.\n'
            "  --validate-<thing> <string>      Validate a <thing>'s <string>.\n"
            '  --compare-versions <a> <op> <b>  Compare version numbers - see below.\n'
            '  --force-help                     Show help on forcing.\n'
            '  -Dh|--debug=help                 Show help on debugging.\n'
            '\n'
            '  -?, --help                       Show this help message.\n'
            '      --version                    Show the version.\n'
            '\n'
            'Validatable things: pkgname, archname, trigname, version.\n'
            '\n'
            'Use dpkg with -b, --build, -c, --contents, -e, --control, -I, --info,\n'
            '  -f, --field, -x, --extract, -X, --vextract, --ctrl-tarfile, --fsys-tarfile\n'
            'on archives (type dpkg-deb --help).\n'
            '\n'
            'Options:\n'
            '  --admindir=<directory>     Use <directory> instead of /var/lib/dpkg.\n'
            '  --root=<directory>         Install on a different root directory.\n'
            '  --instdir=<directory>      Change installation dir without changing admin dir.\n'
            '  --pre-invoke=<command>     Set a pre-invoke hook.\n'
            '  --post-invoke=<command>    Set a post-invoke hook.\n'
            '  --path-exclude=<pattern>   Do not install paths which match a shell pattern.\n'
            '  --path-include=<pattern>   Re-include a pattern after a previous exclusion.\n'
            '  -O|--selected-only         Skip packages not selected for install/upgrade.\n'
            '  -E|--skip-same-version     Skip packages with same installed version/arch.\n'
            '  -G|--refuse-downgrade      Skip packages with earlier version than installed.\n'
            '  -B|--auto-deconfigure      Install even if it would break some other package.\n'
            '  --[no-]triggers            Skip or force consequential trigger processing.\n'
            "  --verify-format=<format>   Verify output format (supported: 'rpm').\n"
            '  --no-pager                 Disables the use of any pager.\n'
            '  --no-debsig                Do not try to verify package signatures.\n'
            '  --no-act|--dry-run|--simulate\n'
            "                             Just say what we would do - don't do it.\n"
            '  -D|--debug=<octal>         Enable debugging (see -Dhelp or --debug=help).\n'
            '  --status-fd <n>            Send status change updates to file descriptor <n>.\n'
            "  --status-logger=<command>  Send status change updates to <command>'s stdin.\n"
            '  --log=<filename>           Log status changes and actions to <filename>.\n'
            '  --ignore-depends=<package>[,...]\n'
            '                             Ignore dependencies involving <package>.\n'
            '  --force-<thing>[,...]      Override problems (see --force-help).\n'
            '  --no-force-<thing>[,...]   Stop when problems encountered.\n'
            '  --refuse-<thing>[,...]     Ditto.\n'
            '  --abort-after <n>          Abort after encountering <n> errors.\n'
            '  --robot                    Use machine-readable output on some commands.\n'
            '\n'
            'Comparison operators for --compare-versions are:\n'
            '  lt le eq ne ge gt       (treat empty version as earlier than any version);\n'
            '  lt-nl le-nl ge-nl gt-nl (treat empty version as later than any version);\n'
            '  < << <= = >= >> >       (only for compatibility with control file syntax).\n'
            '\n'
            "Use 'apt' or 'aptitude' for user-friendly package management.\n"
        ),
        (
            ''
        ), 0),
    'dpkg-query': (
        (
            'Usage: dpkg-query [<option>...] <command>\n'
            '\n'
            'Commands:\n'
            '  -s, --status [<package>...]      Display package status details.\n'
            '  -p, --print-avail [<package>...] Display available version details.\n'
            "  -L, --listfiles <package>...     List files 'owned' by package(s).\n"
            '  -l, --list [<pattern>...]        List packages concisely.\n'
            '  -W, --show [<pattern>...]        Show information on package(s).\n'
            '  -S, --search <pattern>...        Find package(s) owning file(s).\n'
            '      --control-list <package>     Print the package control file list.\n'
            '      --control-show <package> <file>\n'
            '                                   Show the package control file.\n'
            '  -c, --control-path <package> [<file>]\n'
            '                                   Print path for package control file.\n'
            '\n'
            '  -?, --help                       Show this help message.\n'
            '      --version                    Show the version.\n'
            '\n'
            'Options:\n'
            '  --admindir=<directory>           Use <directory> instead of /var/lib/dpkg.\n'
            '  --root=<directory>               Use <directory> instead of /.\n'
            '  --load-avail                     Use available file on --show and --list.\n'
            '  --no-pager                       Disables the use of any pager.\n'
            '  -f|--showformat=<format>         Use alternative format for --show.\n'
            '\n'
            'Format syntax:\n'
            '  A format is a string that will be output for each package. The format\n'
            '  can include the standard escape sequences \\n (newline), \\r (carriage\n'
            '  return) or \\\\ (plain backslash). Package information can be included\n'
            '  by inserting variable references to package fields using the ${var[;width]}\n'
            '  syntax. Fields will be right-aligned unless the width is negative in which\n'
            '  case left alignment will be used.\n'
        ),
        (
            ''
        ), 0),
    'egrep': (
        (
            'Usage: grep [OPTION]... PATTERNS [FILE]...\n'
            'Search for PATTERNS in each FILE.\n'
            "Example: grep -i 'hello world' menu.h main.c\n"
            'PATTERNS can contain multiple patterns separated by newlines.\n'
            '\n'
            'Pattern selection and interpretation:\n'
            '  -E, --extended-regexp     PATTERNS are extended regular expressions\n'
            '  -F, --fixed-strings       PATTERNS are strings\n'
            '  -G, --basic-regexp        PATTERNS are basic regular expressions\n'
            '  -P, --perl-regexp         PATTERNS are Perl regular expressions\n'
            '  -e, --regexp=PATTERNS     use PATTERNS for matching\n'
            '  -f, --file=FILE           take PATTERNS from FILE\n'
            '  -i, --ignore-case         ignore case distinctions in patterns and data\n'
            '      --no-ignore-case      do not ignore case distinctions (default)\n'
            '  -w, --word-regexp         match only whole words\n'
            '  -x, --line-regexp         match only whole lines\n'
            '  -z, --null-data           a data line ends in 0 byte, not newline\n'
            '\n'
            'Miscellaneous:\n'
            '  -s, --no-messages         suppress error messages\n'
            '  -v, --invert-match        select non-matching lines\n'
            '  -V, --version             display version information and exit\n'
            '      --help                display this help text and exit\n'
            '\n'
            'Output control:\n'
            '  -m, --max-count=NUM       stop after NUM selected lines\n'
            '  -b, --byte-offset         print the byte offset with output lines\n'
            '  -n, --line-number         print line number with output lines\n'
            '      --line-buffered       flush output on every line\n'
            '  -H, --with-filename       print file name with output lines\n'
            '  -h, --no-filename         suppress the file name prefix on output\n'
            '      --label=LABEL         use LABEL as the standard input file name prefix\n'
            '  -o, --only-matching       show only nonempty parts of lines that match\n'
            '  -q, --quiet, --silent     suppress all normal output\n'
            '      --binary-files=TYPE   assume that binary files are TYPE;\n'
            "                            TYPE is 'binary', 'text', or 'without-match'\n"
            '  -a, --text                equivalent to --binary-files=text\n'
            '  -I                        equivalent to --binary-files=without-match\n'
            '  -d, --directories=ACTION  how to handle directories;\n'
            "                            ACTION is 'read', 'recurse', or 'skip'\n"
            '  -D, --devices=ACTION      how to handle devices, FIFOs and sockets;\n'
            "                            ACTION is 'read' or 'skip'\n"
            '  -r, --recursive           like --directories=recurse\n'
            '  -R, --dereference-recursive  likewise, but follow all symlinks\n'
            '      --include=GLOB        search only files that match GLOB (a file pattern)\n'
            '      --exclude=GLOB        skip files that match GLOB\n'
            '      --exclude-from=FILE   skip files that match any file pattern from FILE\n'
            '      --exclude-dir=GLOB    skip directories that match GLOB\n'
            '  -L, --files-without-match  print only names of FILEs with no selected lines\n'
            '  -l, --files-with-matches  print only names of FILEs with selected lines\n'
            '  -c, --count               print only a count of selected lines per FILE\n'
            '  -T, --initial-tab         make tabs line up (if needed)\n'
            '  -Z, --null                print 0 byte after FILE name\n'
            '\n'
            'Context control:\n'
            '  -B, --before-context=NUM  print NUM lines of leading context\n'
            '  -A, --after-context=NUM   print NUM lines of trailing context\n'
            '  -C, --context=NUM         print NUM lines of output context\n'
            '  -NUM                      same as --context=NUM\n'
            '      --group-separator=SEP  print SEP on line between matches with context\n'
            '      --no-group-separator  do not print separator for matches with context\n'
            '      --color[=WHEN],\n'
            '      --colour[=WHEN]       use markers to highlight the matching strings;\n'
            "                            WHEN is 'always', 'never', or 'auto'\n"
            '  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)\n'
            '\n'
            "When FILE is '-', read standard input.  With no FILE, read '.' if\n"
            "recursive, '-' otherwise.  With fewer than two FILEs, assume -h.\n"
            'Exit status is 0 if any line is selected, 1 otherwise;\n'
            'if any error occurs and -q is not given, the exit status is 2.\n'
            '\n'
            'Report bugs to: bug-grep@gnu.org\n'
            'GNU grep home page: <https://www.gnu.org/software/grep/>\n'
            'General help using GNU software: <https://www.gnu.org/gethelp/>\n'
        ),
        (
            ''
        ), 0),
    'fgrep': (
        (
            'Usage: grep [OPTION]... PATTERNS [FILE]...\n'
            'Search for PATTERNS in each FILE.\n'
            "Example: grep -i 'hello world' menu.h main.c\n"
            'PATTERNS can contain multiple patterns separated by newlines.\n'
            '\n'
            'Pattern selection and interpretation:\n'
            '  -E, --extended-regexp     PATTERNS are extended regular expressions\n'
            '  -F, --fixed-strings       PATTERNS are strings\n'
            '  -G, --basic-regexp        PATTERNS are basic regular expressions\n'
            '  -P, --perl-regexp         PATTERNS are Perl regular expressions\n'
            '  -e, --regexp=PATTERNS     use PATTERNS for matching\n'
            '  -f, --file=FILE           take PATTERNS from FILE\n'
            '  -i, --ignore-case         ignore case distinctions in patterns and data\n'
            '      --no-ignore-case      do not ignore case distinctions (default)\n'
            '  -w, --word-regexp         match only whole words\n'
            '  -x, --line-regexp         match only whole lines\n'
            '  -z, --null-data           a data line ends in 0 byte, not newline\n'
            '\n'
            'Miscellaneous:\n'
            '  -s, --no-messages         suppress error messages\n'
            '  -v, --invert-match        select non-matching lines\n'
            '  -V, --version             display version information and exit\n'
            '      --help                display this help text and exit\n'
            '\n'
            'Output control:\n'
            '  -m, --max-count=NUM       stop after NUM selected lines\n'
            '  -b, --byte-offset         print the byte offset with output lines\n'
            '  -n, --line-number         print line number with output lines\n'
            '      --line-buffered       flush output on every line\n'
            '  -H, --with-filename       print file name with output lines\n'
            '  -h, --no-filename         suppress the file name prefix on output\n'
            '      --label=LABEL         use LABEL as the standard input file name prefix\n'
            '  -o, --only-matching       show only nonempty parts of lines that match\n'
            '  -q, --quiet, --silent     suppress all normal output\n'
            '      --binary-files=TYPE   assume that binary files are TYPE;\n'
            "                            TYPE is 'binary', 'text', or 'without-match'\n"
            '  -a, --text                equivalent to --binary-files=text\n'
            '  -I                        equivalent to --binary-files=without-match\n'
            '  -d, --directories=ACTION  how to handle directories;\n'
            "                            ACTION is 'read', 'recurse', or 'skip'\n"
            '  -D, --devices=ACTION      how to handle devices, FIFOs and sockets;\n'
            "                            ACTION is 'read' or 'skip'\n"
            '  -r, --recursive           like --directories=recurse\n'
            '  -R, --dereference-recursive  likewise, but follow all symlinks\n'
            '      --include=GLOB        search only files that match GLOB (a file pattern)\n'
            '      --exclude=GLOB        skip files that match GLOB\n'
            '      --exclude-from=FILE   skip files that match any file pattern from FILE\n'
            '      --exclude-dir=GLOB    skip directories that match GLOB\n'
            '  -L, --files-without-match  print only names of FILEs with no selected lines\n'
            '  -l, --files-with-matches  print only names of FILEs with selected lines\n'
            '  -c, --count               print only a count of selected lines per FILE\n'
            '  -T, --initial-tab         make tabs line up (if needed)\n'
            '  -Z, --null                print 0 byte after FILE name\n'
            '\n'
            'Context control:\n'
            '  -B, --before-context=NUM  print NUM lines of leading context\n'
            '  -A, --after-context=NUM   print NUM lines of trailing context\n'
            '  -C, --context=NUM         print NUM lines of output context\n'
            '  -NUM                      same as --context=NUM\n'
            '      --group-separator=SEP  print SEP on line between matches with context\n'
            '      --no-group-separator  do not print separator for matches with context\n'
            '      --color[=WHEN],\n'
            '      --colour[=WHEN]       use markers to highlight the matching strings;\n'
            "                            WHEN is 'always', 'never', or 'auto'\n"
            '  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)\n'
            '\n'
            "When FILE is '-', read standard input.  With no FILE, read '.' if\n"
            "recursive, '-' otherwise.  With fewer than two FILEs, assume -h.\n"
            'Exit status is 0 if any line is selected, 1 otherwise;\n'
            'if any error occurs and -q is not given, the exit status is 2.\n'
            '\n'
            'Report bugs to: bug-grep@gnu.org\n'
            'GNU grep home page: <https://www.gnu.org/software/grep/>\n'
            'General help using GNU software: <https://www.gnu.org/gethelp/>\n'
        ),
        (
            ''
        ), 0),
    'find': (
        (
            'Usage: find [-H] [-L] [-P] [-Olevel] [-D debugopts] [path...] [expression]\n'
            '\n'
            'Default path is the current directory; default expression is -print.\n'
            'Expression may consist of: operators, options, tests, and actions.\n'
            '\n'
            'Operators (decreasing precedence; -and is implicit where no others are given):\n'
            '      ( EXPR )   ! EXPR   -not EXPR   EXPR1 -a EXPR2   EXPR1 -and EXPR2\n'
            '      EXPR1 -o EXPR2   EXPR1 -or EXPR2   EXPR1 , EXPR2\n'
            '\n'
            'Positional options (always true):\n'
            '      -daystart -follow -nowarn -regextype -warn\n'
            '\n'
            'Normal options (always true, specified before other expressions):\n'
            '      -depth -files0-from FILE -maxdepth LEVELS -mindepth LEVELS\n'
            '      -mount -noleaf -xdev -ignore_readdir_race -noignore_readdir_race\n'
            '\n'
            'Tests (N can be +N or -N or N):\n'
            '      -amin N -anewer FILE -atime N -cmin N -cnewer FILE -context CONTEXT\n'
            '      -ctime N -empty -false -fstype TYPE -gid N -group NAME -ilname PATTERN\n'
            '      -iname PATTERN -inum N -iwholename PATTERN -iregex PATTERN\n'
            '      -links N -lname PATTERN -mmin N -mtime N -name PATTERN -newer FILE\n'
            '      -nouser -nogroup -path PATTERN -perm [-/]MODE -regex PATTERN\n'
            '      -readable -writable -executable\n'
            '      -wholename PATTERN -size N[bcwkMG] -true -type [bcdpflsD] -uid N\n'
            '      -used N -user NAME -xtype [bcdpfls]\n'
            '\n'
            'Actions:\n'
            '      -delete -print0 -printf FORMAT -fprintf FILE FORMAT -print \n'
            '      -fprint0 FILE -fprint FILE -ls -fls FILE -prune -quit\n'
            '      -exec COMMAND ; -exec COMMAND {} + -ok COMMAND ;\n'
            '      -execdir COMMAND ; -execdir COMMAND {} + -okdir COMMAND ;\n'
            '\n'
            'Other common options:\n'
            '      --help                   display this help and exit\n'
            '      --version                output version information and exit\n'
            '\n'
            'Valid arguments for -D:\n'
            'exec, opt, rates, search, stat, time, tree, all, help\n'
            "Use '-D help' for a description of the options, or see find(1)\n"
            '\n'
            'Please see also the documentation at https://www.gnu.org/software/findutils/.\n'
            'You can report (and track progress on fixing) bugs in the "find"\n'
            'program via the GNU findutils bug-reporting page at\n'
            'https://savannah.gnu.org/bugs/?group=findutils or, if\n'
            'you have no web access, by sending email to <bug-findutils@gnu.org>.\n'
        ),
        (
            ''
        ), 0),
    'getent': (
        (
            'Usage: getent [OPTION...] database [key ...]\n'
            'Get entries from administrative database.\n'
            '\n'
            '  -A, --no-addrconfig        do not filter out unsupported IPv4/IPv6 addresses\n'
            '                             (with ahosts*)\n'
            '  -i, --no-idn               disable IDN encoding\n'
            '  -s, --service=CONFIG       Service configuration to be used\n'
            '  -?, --help                 Give this help list\n'
            '      --usage                Give a short usage message\n'
            '  -V, --version              Print program version\n'
            '\n'
            'Mandatory or optional arguments to long options are also mandatory or optional\n'
            'for any corresponding short options.\n'
            '\n'
            'Supported databases:\n'
            'ahosts ahostsv4 ahostsv6 aliases ethers group gshadow hosts initgroups\n'
            'netgroup networks passwd protocols rpc services shadow\n'
            '\n'
            'For bug reporting instructions, please see:\n'
            '<http://www.debian.org/Bugs/>.\n'
        ),
        (
            ''
        ), 0),
    'grep': (
        (
            'Usage: grep [OPTION]... PATTERNS [FILE]...\n'
            'Search for PATTERNS in each FILE.\n'
            "Example: grep -i 'hello world' menu.h main.c\n"
            'PATTERNS can contain multiple patterns separated by newlines.\n'
            '\n'
            'Pattern selection and interpretation:\n'
            '  -E, --extended-regexp     PATTERNS are extended regular expressions\n'
            '  -F, --fixed-strings       PATTERNS are strings\n'
            '  -G, --basic-regexp        PATTERNS are basic regular expressions\n'
            '  -P, --perl-regexp         PATTERNS are Perl regular expressions\n'
            '  -e, --regexp=PATTERNS     use PATTERNS for matching\n'
            '  -f, --file=FILE           take PATTERNS from FILE\n'
            '  -i, --ignore-case         ignore case distinctions in patterns and data\n'
            '      --no-ignore-case      do not ignore case distinctions (default)\n'
            '  -w, --word-regexp         match only whole words\n'
            '  -x, --line-regexp         match only whole lines\n'
            '  -z, --null-data           a data line ends in 0 byte, not newline\n'
            '\n'
            'Miscellaneous:\n'
            '  -s, --no-messages         suppress error messages\n'
            '  -v, --invert-match        select non-matching lines\n'
            '  -V, --version             display version information and exit\n'
            '      --help                display this help text and exit\n'
            '\n'
            'Output control:\n'
            '  -m, --max-count=NUM       stop after NUM selected lines\n'
            '  -b, --byte-offset         print the byte offset with output lines\n'
            '  -n, --line-number         print line number with output lines\n'
            '      --line-buffered       flush output on every line\n'
            '  -H, --with-filename       print file name with output lines\n'
            '  -h, --no-filename         suppress the file name prefix on output\n'
            '      --label=LABEL         use LABEL as the standard input file name prefix\n'
            '  -o, --only-matching       show only nonempty parts of lines that match\n'
            '  -q, --quiet, --silent     suppress all normal output\n'
            '      --binary-files=TYPE   assume that binary files are TYPE;\n'
            "                            TYPE is 'binary', 'text', or 'without-match'\n"
            '  -a, --text                equivalent to --binary-files=text\n'
            '  -I                        equivalent to --binary-files=without-match\n'
            '  -d, --directories=ACTION  how to handle directories;\n'
            "                            ACTION is 'read', 'recurse', or 'skip'\n"
            '  -D, --devices=ACTION      how to handle devices, FIFOs and sockets;\n'
            "                            ACTION is 'read' or 'skip'\n"
            '  -r, --recursive           like --directories=recurse\n'
            '  -R, --dereference-recursive  likewise, but follow all symlinks\n'
            '      --include=GLOB        search only files that match GLOB (a file pattern)\n'
            '      --exclude=GLOB        skip files that match GLOB\n'
            '      --exclude-from=FILE   skip files that match any file pattern from FILE\n'
            '      --exclude-dir=GLOB    skip directories that match GLOB\n'
            '  -L, --files-without-match  print only names of FILEs with no selected lines\n'
            '  -l, --files-with-matches  print only names of FILEs with selected lines\n'
            '  -c, --count               print only a count of selected lines per FILE\n'
            '  -T, --initial-tab         make tabs line up (if needed)\n'
            '  -Z, --null                print 0 byte after FILE name\n'
            '\n'
            'Context control:\n'
            '  -B, --before-context=NUM  print NUM lines of leading context\n'
            '  -A, --after-context=NUM   print NUM lines of trailing context\n'
            '  -C, --context=NUM         print NUM lines of output context\n'
            '  -NUM                      same as --context=NUM\n'
            '      --group-separator=SEP  print SEP on line between matches with context\n'
            '      --no-group-separator  do not print separator for matches with context\n'
            '      --color[=WHEN],\n'
            '      --colour[=WHEN]       use markers to highlight the matching strings;\n'
            "                            WHEN is 'always', 'never', or 'auto'\n"
            '  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)\n'
            '\n'
            "When FILE is '-', read standard input.  With no FILE, read '.' if\n"
            "recursive, '-' otherwise.  With fewer than two FILEs, assume -h.\n"
            'Exit status is 0 if any line is selected, 1 otherwise;\n'
            'if any error occurs and -q is not given, the exit status is 2.\n'
            '\n'
            'Report bugs to: bug-grep@gnu.org\n'
            'GNU grep home page: <https://www.gnu.org/software/grep/>\n'
            'General help using GNU software: <https://www.gnu.org/gethelp/>\n'
        ),
        (
            ''
        ), 0),
    'gzip': (
        (
            'Usage: gzip [OPTION]... [FILE]...\n'
            'Compress or uncompress FILEs (by default, compress FILES in-place).\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '\n'
            '  -c, --stdout      write on standard output, keep original files unchanged\n'
            '  -d, --decompress  decompress\n'
            '  -f, --force       force overwrite of output file and compress links\n'
            '  -h, --help        give this help\n'
            "  -k, --keep        keep (don't delete) input files\n"
            '  -l, --list        list compressed file contents\n'
            '  -L, --license     display software license\n'
            '  -n, --no-name     do not save or restore the original name and timestamp\n'
            '  -N, --name        save or restore the original name and timestamp\n'
            '  -q, --quiet       suppress all warnings\n'
            '  -r, --recursive   operate recursively on directories\n'
            '      --rsyncable   make rsync-friendly archive\n'
            '  -S, --suffix=SUF  use suffix SUF on compressed files\n'
            '      --synchronous synchronous output (safer if system crashes, but slower)\n'
            '  -t, --test        test compressed file integrity\n'
            '  -v, --verbose     verbose mode\n'
            '  -V, --version     display version number\n'
            '  -1, --fast        compress faster\n'
            '  -9, --best        compress better\n'
            '\n'
            'With no FILE, or when FILE is -, read standard input.\n'
            '\n'
            'Report bugs to <bug-gzip@gnu.org>.\n'
        ),
        (
            ''
        ), 0),
    'ip': (
        (
            ''
        ),
        (
            'Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n'
            '       ip [ -force ] -batch filename\n'
            'where  OBJECT := { address | addrlabel | fou | help | ila | ioam | l2tp | link |\n'
            '                   macsec | maddress | monitor | mptcp | mroute | mrule |\n'
            '                   neighbor | neighbour | netconf | netns | nexthop | ntable |\n'
            '                   ntbl | route | rule | sr | stats | tap | tcpmetrics |\n'
            '                   token | tunnel | tuntap | vrf | xfrm }\n'
            '       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -r[esolve] |\n'
            '                    -h[uman-readable] | -iec | -j[son] | -p[retty] |\n'
            '                    -f[amily] { inet | inet6 | mpls | bridge | link } |\n'
            '                    -4 | -6 | -M | -B | -0 |\n'
            '                    -l[oops] { maximum-addr-flush-attempts } | -echo | -br[ief] |\n'
            '                    -o[neline] | -t[imestamp] | -ts[hort] | -b[atch] [filename] |\n'
            '                    -rc[vbuf] [size] | -n[etns] name | -N[umeric] | -a[ll] |\n'
            '                    -c[olor]}\n'
        ), 255),
    'journalctl': (
        (
            'journalctl [OPTIONS...] [MATCHES...]\n'
            '\n'
            'Query the journal.\n'
            '\n'
            'Source Options:\n'
            '     --system                Show the system journal\n'
            '     --user                  Show the user journal for the current user\n'
            '  -M --machine=CONTAINER     Operate on local container\n'
            '  -m --merge                 Show entries from all available journals\n'
            '  -D --directory=PATH        Show journal files from directory\n'
            '  -i --file=PATH             Show journal file\n'
            '     --root=PATH             Operate on an alternate filesystem root\n'
            '     --image=PATH            Operate on disk image as filesystem root\n'
            '     --image-policy=POLICY   Specify disk image dissection policy\n'
            '     --namespace=NAMESPACE   Show journal data from specified journal namespace\n'
            '\n'
            'Filtering Options:\n'
            '  -S --since=DATE            Show entries not older than the specified date\n'
            '  -U --until=DATE            Show entries not newer than the specified date\n'
            '  -c --cursor=CURSOR         Show entries starting at the specified cursor\n'
            '     --after-cursor=CURSOR   Show entries after the specified cursor\n'
            '     --cursor-file=FILE      Show entries after cursor in FILE and update FILE\n'
            '  -b --boot[=ID]             Show current boot or the specified boot\n'
            '  -u --unit=UNIT             Show logs from the specified unit\n'
            '     --user-unit=UNIT        Show logs from the specified user unit\n'
            '     --invocation=ID         Show logs from the matching invocation ID\n'
            '  -I                         Show logs from the latest invocation of unit\n'
            '  -t --identifier=STRING     Show entries with the specified syslog identifier\n'
            '  -T --exclude-identifier=STRING\n'
            '                             Hide entries with the specified syslog identifier\n'
            '  -p --priority=RANGE        Show entries within the specified priority range\n'
            '     --facility=FACILITY...  Show entries with the specified facilities\n'
            '  -g --grep=PATTERN          Show entries with MESSAGE matching PATTERN\n'
            '     --case-sensitive[=BOOL] Force case sensitive or insensitive matching\n'
            '  -k --dmesg                 Show kernel message log from the current boot\n'
            '\n'
            'Output Control Options:\n'
            '  -o --output=STRING         Change journal output mode (short, short-precise,\n'
            '                               short-iso, short-iso-precise, short-full,\n'
            '                               short-monotonic, short-unix, verbose, export,\n'
            '                               json, json-pretty, json-sse, json-seq, cat,\n'
            '                               with-unit)\n'
            '     --output-fields=LIST    Select fields to print in verbose/export/json modes\n'
            '  -n --lines[=[+]INTEGER]    Number of journal entries to show\n'
            '  -r --reverse               Show the newest entries first\n'
            '     --show-cursor           Print the cursor after all the entries\n'
            '     --utc                   Express time in Coordinated Universal Time (UTC)\n'
            '  -x --catalog               Add message explanations where available\n'
            '     --no-hostname           Suppress output of hostname field\n'
            '     --no-full               Ellipsize fields\n'
            '  -a --all                   Show all fields, including long and unprintable\n'
            '  -f --follow                Follow the journal\n'
            '     --no-tail               Show all lines, even in follow mode\n'
            '     --truncate-newline      Truncate entries by first newline character\n'
            '  -q --quiet                 Do not show info messages and privilege warning\n'
            '\n'
            'Pager Control Options:\n'
            '     --no-pager              Do not pipe output into a pager\n'
            '  -e --pager-end             Immediately jump to the end in the pager\n'
            '\n'
            'Forward Secure Sealing (FSS) Options:\n'
            '     --interval=TIME         Time interval for changing the FSS sealing key\n'
            '     --verify-key=KEY        Specify FSS verification key\n'
            '     --force                 Override of the FSS key pair with --setup-keys\n'
            '\n'
            'Commands:\n'
            '  -h --help                  Show this help text\n'
            '     --version               Show package version\n'
            '  -N --fields                List all field names currently used\n'
            '  -F --field=FIELD           List all values that a specified field takes\n'
            '     --list-boots            Show terse information about recorded boots\n'
            '     --list-invocations      Show invocation IDs of specified unit\n'
            '     --list-namespaces       Show list of journal namespaces\n'
            '     --disk-usage            Show total disk usage of all journal files\n'
            '     --vacuum-size=BYTES     Reduce disk usage below specified size\n'
            '     --vacuum-files=INT      Leave only the specified number of journal files\n'
            '     --vacuum-time=TIME      Remove journal files older than specified time\n'
            '     --verify                Verify journal file consistency\n'
            '     --sync                  Synchronize unwritten journal messages to disk\n'
            '     --relinquish-var        Stop logging to disk, log to temporary file system\n'
            '     --smart-relinquish-var  Similar, but NOP if log directory is on root mount\n'
            '     --flush                 Flush all journal data from /run into /var\n'
            '     --rotate                Request immediate rotation of the journal files\n'
            '     --header                Show journal header information\n'
            '     --list-catalog          Show all message IDs in the catalog\n'
            '     --dump-catalog          Show entries in the message catalog\n'
            '     --update-catalog        Update the message catalog database\n'
            '     --setup-keys            Generate a new FSS key pair\n'
            '\n'
            'See the journalctl(1) man page for details.\n'
        ),
        (
            ''
        ), 0),
    'killall': (
        (
            ''
        ),
        (
            'Usage: killall [OPTION]... [--] NAME...\n'
            '       killall -l, --list\n'
            '       killall -V, --version\n'
            '\n'
            '  -e,--exact          require exact match for very long names\n'
            '  -I,--ignore-case    case insensitive process name match\n'
            '  -g,--process-group  kill process group instead of process\n'
            '  -y,--younger-than   kill processes younger than TIME\n'
            '  -o,--older-than     kill processes older than TIME\n'
            '  -i,--interactive    ask for confirmation before killing\n'
            '  -l,--list           list all known signal names\n'
            "  -q,--quiet          don't print complaints\n"
            '  -r,--regexp         interpret NAME as an extended regular expression\n'
            '  -s,--signal SIGNAL  send this signal instead of SIGTERM\n'
            '  -u,--user USER      kill only process(es) running as USER\n'
            '  -v,--verbose        report if the signal was successfully sent\n'
            '  -V,--version        display version information\n'
            '  -w,--wait           wait for processes to die\n'
            '  -n,--ns PID         match processes that belong to the same namespaces\n'
            '                      as PID\n'
            '  -Z,--context REGEXP kill only process(es) having context\n'
            '                      (must precede other arguments)\n'
            '\n'
        ), 1),
    'lsattr': (
        (
            ''
        ),
        (
            "lsattr: invalid option -- '-'\n"
            'Usage: lsattr [-RVadlpv] [files...]\n'
        ), 1),
    'mount': (
        (
            '\n'
            'Usage:\n'
            ' mount [-lhV]\n'
            ' mount -a [options]\n'
            ' mount [options] [--source] <source> | [--target] <directory>\n'
            ' mount [options] <source> <directory>\n'
            ' mount <operation> <mountpoint> [<target>]\n'
            '\n'
            'Mount a filesystem.\n'
            '\n'
            'Options:\n'
            ' -a, --all               mount all filesystems mentioned in fstab\n'
            " -c, --no-canonicalize   don't canonicalize paths\n"
            ' -f, --fake              dry run; skip the mount(2) syscall\n'
            ' -F, --fork              fork off for each device (use with -a)\n'
            ' -T, --fstab <path>      alternative file to /etc/fstab\n'
            " -i, --internal-only     don't call the mount.<type> helpers\n"
            ' -l, --show-labels       show also filesystem labels\n'
            '     --map-groups <inner>:<outer>:<count>\n'
            '                         add the specified GID map to an ID-mapped mount\n'
            '     --map-users <inner>:<outer>:<count>\n'
            '                         add the specified UID map to an ID-mapped mount\n'
            '     --map-users /proc/<pid>/ns/user\n'
            '                         specify the user namespace for an ID-mapped mount\n'
            " -m, --mkdir[=<mode>]    alias to '-o X-mount.mkdir[=<mode>]'\n"
            " -n, --no-mtab           don't write to /etc/mtab\n"
            '     --options-mode <mode>\n'
            '                         what to do with options loaded from fstab\n'
            '     --options-source <source>\n'
            '                         mount options source\n'
            '     --options-source-force\n'
            '                         force use of options from fstab/mtab\n'
            '     --onlyonce          check if filesystem is already mounted\n'
            ' -o, --options <list>    comma-separated list of mount options\n'
            ' -O, --test-opts <list>  limit the set of filesystems (use with -a)\n'
            ' -r, --read-only         mount the filesystem read-only (same as -o ro)\n'
            ' -t, --types <list>      limit the set of filesystem types\n'
            '     --source <src>      explicitly specifies source (path, label, uuid)\n'
            '     --target <target>   explicitly specifies mountpoint\n'
            '     --target-prefix <path>\n'
            '                         specifies path used for all mountpoints\n'
            ' -v, --verbose           say what is being done\n'
            ' -w, --rw, --read-write  mount the filesystem read-write (default)\n'
            ' -N, --namespace <ns>    perform mount in another namespace\n'
            '\n'
            ' -h, --help              display this help\n'
            ' -V, --version           display version\n'
            '\n'
            'Source:\n'
            ' -L, --label <label>     synonym for LABEL=<label>\n'
            ' -U, --uuid <uuid>       synonym for UUID=<uuid>\n'
            ' LABEL=<label>           specifies device by filesystem label\n'
            ' UUID=<uuid>             specifies device by filesystem UUID\n'
            ' PARTLABEL=<label>       specifies device by partition label\n'
            ' PARTUUID=<uuid>         specifies device by partition UUID\n'
            ' ID=<id>                 specifies device by udev hardware ID\n'
            ' <device>                specifies device by path\n'
            ' <directory>             mountpoint for bind mounts (see --bind/rbind)\n'
            ' <file>                  regular file for loopdev setup\n'
            '\n'
            'Operations:\n'
            ' -B, --bind              mount a subtree somewhere else (same as -o bind)\n'
            ' -M, --move              move a subtree to some other place\n'
            ' -R, --rbind             mount a subtree and all submounts somewhere else\n'
            ' --make-shared           mark a subtree as shared\n'
            ' --make-slave            mark a subtree as slave\n'
            ' --make-private          mark a subtree as private\n'
            ' --make-unbindable       mark a subtree as unbindable\n'
            ' --make-rshared          recursively mark a whole subtree as shared\n'
            ' --make-rslave           recursively mark a whole subtree as slave\n'
            ' --make-rprivate         recursively mark a whole subtree as private\n'
            ' --make-runbindable      recursively mark a whole subtree as unbindable\n'
            '\n'
            'For more details see mount(8).\n'
        ),
        (
            ''
        ), 0),
    'openssl': (
        (
            ''
        ),
        (
            'help:\n'
            '\n'
            'Standard commands\n'
            'asn1parse         ca                ciphers           cmp               \n'
            'cms               crl               crl2pkcs7         dgst              \n'
            'dhparam           dsa               dsaparam          ec                \n'
            'ecparam           enc               engine            errstr            \n'
            'fipsinstall       gendsa            genpkey           genrsa            \n'
            'help              info              kdf               list              \n'
            'mac               nseq              ocsp              passwd            \n'
            'pkcs12            pkcs7             pkcs8             pkey              \n'
            'pkeyparam         pkeyutl           prime             rand              \n'
            'rehash            req               rsa               rsautl            \n'
            's_client          s_server          s_time            sess_id           \n'
            'skeyutl           smime             speed             spkac             \n'
            'srp               storeutl          ts                verify            \n'
            'version           x509              \n'
            '\n'
            "Message Digest commands (see the `dgst' command for more details)\n"
            'blake2b512        blake2s256        md4               md5               \n'
            'rmd160            sha1              sha224            sha256            \n'
            'sha3-224          sha3-256          sha3-384          sha3-512          \n'
            'sha384            sha512            sha512-224        sha512-256        \n'
            'shake128          shake256          sm3               \n'
            '\n'
            "Cipher commands (see the `enc' command for more details)\n"
            'aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb       \n'
            'aes-256-cbc       aes-256-ecb       aria-128-cbc      aria-128-cfb      \n'
            'aria-128-cfb1     aria-128-cfb8     aria-128-ctr      aria-128-ecb      \n'
            'aria-128-ofb      aria-192-cbc      aria-192-cfb      aria-192-cfb1     \n'
            'aria-192-cfb8     aria-192-ctr      aria-192-ecb      aria-192-ofb      \n'
            'aria-256-cbc      aria-256-cfb      aria-256-cfb1     aria-256-cfb8     \n'
            'aria-256-ctr      aria-256-ecb      aria-256-ofb      base64            \n'
            'bf                bf-cbc            bf-cfb            bf-ecb            \n'
            'bf-ofb            camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  \n'
            'camellia-192-ecb  camellia-256-cbc  camellia-256-ecb  cast              \n'
            'cast-cbc          cast5-cbc         cast5-cfb         cast5-ecb         \n'
            'cast5-ofb         des               des-cbc           des-cfb           \n'
            'des-ecb           des-ede           des-ede-cbc       des-ede-cfb       \n'
            'des-ede-ofb       des-ede3          des-ede3-cbc      des-ede3-cfb      \n'
            'des-ede3-ofb      des-ofb           des3              desx              \n'
            'rc2               rc2-40-cbc        rc2-64-cbc        rc2-cbc           \n'
            'rc2-cfb           rc2-ecb           rc2-ofb           rc4               \n'
            'rc4-40            seed              seed-cbc          seed-cfb          \n'
            'seed-ecb          seed-ofb          sm4-cbc           sm4-cfb           \n'
            'sm4-ctr           sm4-ecb           sm4-ofb           zlib              \n'
            'zstd              \n'
            '\n'
        ), 0),
    'sed': (
        (
            'Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n'
            '\n'
            '  -n, --quiet, --silent\n'
            '                 suppress automatic printing of pattern space\n'
            '      --debug\n'
            '                 annotate program execution\n'
            '  -e script, --expression=script\n'
            '                 add the script to the commands to be executed\n'
            '  -f script-file, --file=script-file\n'
            '                 add the contents of script-file to the commands to be executed\n'
            '  --follow-symlinks\n'
            '                 follow symlinks when processing in place\n'
            '  -i[SUFFIX], --in-place[=SUFFIX]\n'
            '                 edit files in place (makes backup if SUFFIX supplied)\n'
            '  -l N, --line-length=N\n'
            "                 specify the desired line-wrap length for the `l' command\n"
            '  --posix\n'
            '                 disable all GNU extensions.\n'
            '  -E, -r, --regexp-extended\n'
            '                 use extended regular expressions in the script\n'
            '                 (for portability use POSIX -E).\n'
            '  -s, --separate\n'
            '                 consider files as separate rather than as a single,\n'
            '                 continuous long stream.\n'
            '      --sandbox\n'
            '                 operate in sandbox mode (disable e/r/w commands).\n'
            '  -u, --unbuffered\n'
            '                 load minimal amounts of data from the input files and flush\n'
            '                 the output buffers more often\n'
            '  -z, --null-data\n'
            '                 separate lines by NUL characters\n'
            '      --help     display this help and exit\n'
            '      --version  output version information and exit\n'
            '\n'
            'If no -e, --expression, -f, or --file option is given, then the first\n'
            'non-option argument is taken as the sed script to interpret.  All\n'
            'remaining arguments are names of input files; if no input files are\n'
            'specified, then the standard input is read.\n'
            '\n'
            'GNU sed home page: <https://www.gnu.org/software/sed/>.\n'
            'General help using GNU software: <https://www.gnu.org/gethelp/>.\n'
            'E-mail bug reports to: <bug-sed@gnu.org>.\n'
        ),
        (
            ''
        ), 0),
    'ss': (
        (
            'Usage: ss [ OPTIONS ]\n'
            '       ss [ OPTIONS ] [ FILTER ]\n'
            '   -h, --help          this message\n'
            '   -V, --version       output version information\n'
            "   -n, --numeric       don't resolve service names\n"
            '   -r, --resolve       resolve host names\n'
            '   -a, --all           display all sockets\n'
            '   -l, --listening     display listening sockets\n'
            '   -B, --bound-inactive display TCP bound but inactive sockets\n'
            '   -o, --options       show timer information\n'
            '   -e, --extended      show detailed socket information\n'
            '   -m, --memory        show socket memory usage\n'
            '   -p, --processes     show process using socket\n'
            '   -T, --threads       show thread using socket\n'
            '   -i, --info          show internal TCP information\n'
            '       --tipcinfo      show internal tipc socket information\n'
            '   -s, --summary       show socket usage summary\n'
            '       --tos           show tos and priority information\n'
            '       --cgroup        show cgroup information\n'
            '   -b, --bpf           show bpf filter socket information\n'
            '       --bpf-maps      show all BPF socket-local storage maps\n'
            '       --bpf-map-id=MAP-ID    show a BPF socket-local storage map\n'
            '   -E, --events        continually display sockets as they are destroyed\n'
            '   -Z, --context       display task SELinux security contexts\n'
            '   -z, --contexts      display task and socket SELinux security contexts\n'
            '   -N, --net           switch to the specified network namespace name\n'
            '\n'
            '   -4, --ipv4          display only IP version 4 sockets\n'
            '   -6, --ipv6          display only IP version 6 sockets\n'
            '   -0, --packet        display PACKET sockets\n'
            '   -t, --tcp           display only TCP sockets\n'
            '   -M, --mptcp         display only MPTCP sockets\n'
            '   -S, --sctp          display only SCTP sockets\n'
            '   -u, --udp           display only UDP sockets\n'
            '   -d, --dccp          display only DCCP sockets\n'
            '   -w, --raw           display only RAW sockets\n'
            '   -x, --unix          display only Unix domain sockets\n'
            '       --tipc          display only TIPC sockets\n'
            '       --vsock         display only vsock sockets\n'
            '       --xdp           display only XDP sockets\n'
            '   -f, --family=FAMILY display sockets of type FAMILY\n'
            '       FAMILY := {inet|inet6|link|unix|netlink|vsock|tipc|xdp|help}\n'
            '\n'
            '   -K, --kill          forcibly close sockets, display what was closed\n'
            '   -H, --no-header     Suppress header line\n'
            '   -Q, --no-queues     Suppress sending and receiving queue columns\n'
            "   -O, --oneline       socket's data printed on a single line\n"
            '       --inet-sockopt  show various inet socket options\n'
            '\n'
            '   -A, --query=QUERY, --socket=QUERY\n'
            '       QUERY := {all|inet|tcp|mptcp|udp|raw|unix|unix_dgram|unix_stream|unix_seqpacket|packet|packet_raw|packet_dgram|netlink|dccp|sctp|vsock_stream|vsock_dgram|tipc|xdp}[,QUERY]\n'
            '\n'
            '   -D, --diag=FILE     Dump raw information about TCP sockets to FILE\n'
            '   -F, --filter=FILE   read filter information from FILE\n'
            '       FILTER := [ state STATE-FILTER ] [ EXPRESSION ]\n'
            '       STATE-FILTER := {all|connected|synchronized|bucket|big|TCP-STATES}\n'
            '         TCP-STATES := {established|syn-sent|syn-recv|fin-wait-{1,2}|time-wait|closed|close-wait|last-ack|listening|closing}\n'
            '          connected := {established|syn-sent|syn-recv|fin-wait-{1,2}|time-wait|close-wait|last-ack|closing}\n'
            '       synchronized := {established|syn-recv|fin-wait-{1,2}|time-wait|close-wait|last-ack|closing}\n'
            '             bucket := {syn-recv|time-wait}\n'
            '                big := {established|syn-sent|fin-wait-{1,2}|closed|close-wait|last-ack|listening|closing}\n'
        ),
        (
            ''
        ), 0),
    'ssh': (
        (
            ''
        ),
        (
            'unknown option -- -\n'
            'usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address]\n'
            '           [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n'
            '           [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n'
            '           [-J destination] [-L address] [-l login_name] [-m mac_spec]\n'
            '           [-O ctl_cmd] [-o option] [-P tag] [-p port] [-R address]\n'
            '           [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n'
            '           destination [command [argument ...]]\n'
            '       ssh [-Q query_option]\n'
        ), 255),
    'ssh-keygen': (
        (
            ''
        ),
        (
            'unknown option -- -\n'
            'usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n'
            '                  [-m format] [-N new_passphrase] [-O option]\n'
            '                  [-t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa]\n'
            '                  [-w provider] [-Z cipher]\n'
            '       ssh-keygen -p [-a rounds] [-f keyfile] [-m format] [-N new_passphrase]\n'
            '                   [-P old_passphrase] [-Z cipher]\n'
            '       ssh-keygen -i [-f input_keyfile] [-m key_format]\n'
            '       ssh-keygen -e [-f input_keyfile] [-m key_format]\n'
            '       ssh-keygen -y [-f input_keyfile]\n'
            '       ssh-keygen -c [-a rounds] [-C comment] [-f keyfile] [-P passphrase]\n'
            '       ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n'
            '       ssh-keygen -B [-f input_keyfile]\n'
            '       ssh-keygen -D pkcs11\n'
            '       ssh-keygen -F hostname [-lv] [-f known_hosts_file]\n'
            '       ssh-keygen -H [-f known_hosts_file]\n'
            '       ssh-keygen -K [-a rounds] [-w provider]\n'
            '       ssh-keygen -R hostname [-f known_hosts_file]\n'
            '       ssh-keygen -r hostname [-g] [-f input_keyfile]\n'
            '       ssh-keygen -M generate [-O option] output_file\n'
            '       ssh-keygen -M screen [-f input_file] [-O option] output_file\n'
            '       ssh-keygen -I certificate_identity -s ca_key [-hU] [-D pkcs11_provider]\n'
            '                  [-n principals] [-O option] [-V validity_interval]\n'
            '                  [-z serial_number] file ...\n'
            '       ssh-keygen -L [-f input_keyfile]\n'
            '       ssh-keygen -A [-a rounds] [-f prefix_path]\n'
            '       ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number]\n'
            '                  file ...\n'
            '       ssh-keygen -Q [-l] -f krl_file [file ...]\n'
            '       ssh-keygen -Y find-principals -s signature_file -f allowed_signers_file\n'
            '       ssh-keygen -Y match-principals -I signer_identity -f allowed_signers_file\n'
            '       ssh-keygen -Y check-novalidate -n namespace -s signature_file\n'
            '       ssh-keygen -Y sign -f key_file -n namespace file [-O option] ...\n'
            '       ssh-keygen -Y verify -f allowed_signers_file -I signer_identity\n'
            '                  -n namespace -s signature_file [-r krl_file] [-O option]\n'
        ), 1),
    'systemctl': (
        (
            'systemctl [OPTIONS...] COMMAND ...\n'
            '\n'
            'Query or send control commands to the system manager.\n'
            '\n'
            'Unit Commands:\n'
            '  list-units [PATTERN...]             List units currently in memory\n'
            '  list-automounts [PATTERN...]        List automount units currently in memory,\n'
            '                                      ordered by path\n'
            '  list-paths [PATTERN...]             List path units currently in memory,\n'
            '                                      ordered by path\n'
            '  list-sockets [PATTERN...]           List socket units currently in memory,\n'
            '                                      ordered by address\n'
            '  list-timers [PATTERN...]            List timer units currently in memory,\n'
            '                                      ordered by next elapse\n'
            '  is-active PATTERN...                Check whether units are active\n'
            '  is-failed [PATTERN...]              Check whether units are failed or\n'
            '                                      system is in degraded state\n'
            '  status [PATTERN...|PID...]          Show runtime status of one or more units\n'
            '  show [PATTERN...|JOB...]            Show properties of one or more\n'
            '                                      units/jobs or the manager\n'
            '  cat PATTERN...                      Show files and drop-ins of specified units\n'
            '  help PATTERN...|PID...              Show manual for one or more units\n'
            '  list-dependencies [UNIT...]         Recursively show units which are required\n'
            '                                      or wanted by the units or by which those\n'
            '                                      units are required or wanted\n'
            '  start UNIT...                       Start (activate) one or more units\n'
            '  stop UNIT...                        Stop (deactivate) one or more units\n'
            '  reload UNIT...                      Reload one or more units\n'
            '  restart UNIT...                     Start or restart one or more units\n'
            '  try-restart UNIT...                 Restart one or more units if active\n'
            '  reload-or-restart UNIT...           Reload one or more units if possible,\n'
            '                                      otherwise start or restart\n'
            '  try-reload-or-restart UNIT...       If active, reload one or more units,\n'
            '                                      if supported, otherwise restart\n'
            '  isolate UNIT                        Start one unit and stop all others\n'
            '  kill UNIT...                        Send signal to processes of a unit\n'
            '  clean UNIT...                       Clean runtime, cache, state, logs or\n'
            '                                      configuration of unit\n'
            '  freeze PATTERN...                   Freeze execution of unit processes\n'
            '  thaw PATTERN...                     Resume execution of a frozen unit\n'
            '  set-property UNIT PROPERTY=VALUE... Sets one or more properties of a unit\n'
            '  bind UNIT PATH [PATH]               Bind-mount a path from the host into a\n'
            "                                      unit's namespace\n"
            '  mount-image UNIT PATH [PATH [OPTS]] Mount an image from the host into a\n'
            "                                      unit's namespace\n"
            '  service-log-level SERVICE [LEVEL]   Get/set logging threshold for service\n'
            '  service-log-target SERVICE [TARGET] Get/set logging target for service\n'
            '  reset-failed [PATTERN...]           Reset failed state for all, one, or more\n'
            '                                      units\n'
            '  whoami [PID...]                     Return unit caller or specified PIDs are\n'
            '                                      part of\n'
            '\n'
            'Unit File Commands:\n'
            '  list-unit-files [PATTERN...]        List installed unit files\n'
            '  enable [UNIT...|PATH...]            Enable one or more unit files\n'
            '  disable UNIT...                     Disable one or more unit files\n'
            '  reenable UNIT...                    Reenable one or more unit files\n'
            '  preset UNIT...                      Enable/disable one or more unit files\n'
            '                                      based on preset configuration\n'
            '  preset-all                          Enable/disable all unit files based on\n'
            '                                      preset configuration\n'
            '  is-enabled UNIT...                  Check whether unit files are enabled\n'
            '  mask UNIT...                        Mask one or more units\n'
            '  unmask UNIT...                      Unmask one or more units\n'
            '  link PATH...                        Link one or more units files into\n'
            '                                      the search path\n'
            '  revert UNIT...                      Revert one or more unit files to vendor\n'
            '                                      version\n'
            "  add-wants TARGET UNIT...            Add 'Wants' dependency for the target\n"
            '                                      on specified one or more units\n'
            "  add-requires TARGET UNIT...         Add 'Requires' dependency for the target\n"
            '                                      on specified one or more units\n'
            '  edit UNIT...                        Edit one or more unit files\n'
            '  get-default                         Get the name of the default target\n'
            '  set-default TARGET                  Set the default target\n'
            '\n'
            'Machine Commands:\n'
            '  list-machines [PATTERN...]          List local containers and host\n'
            '\n'
            'Job Commands:\n'
            '  list-jobs [PATTERN...]              List jobs\n'
            '  cancel [JOB...]                     Cancel all, one, or more jobs\n'
            '\n'
            'Environment Commands:\n'
            '  show-environment                    Dump environment\n'
            '  set-environment VARIABLE=VALUE...   Set one or more environment variables\n'
            '  unset-environment VARIABLE...       Unset one or more environment variables\n'
            '  import-environment VARIABLE...      Import all or some environment variables\n'
            '\n'
            'Manager State Commands:\n'
            '  daemon-reload                       Reload systemd manager configuration\n'
            '  daemon-reexec                       Reexecute systemd manager\n'
            '  log-level [LEVEL]                   Get/set logging threshold for manager\n'
            '  log-target [TARGET]                 Get/set logging target for manager\n'
            '  service-watchdogs [BOOL]            Get/set service watchdog state\n'
            '\n'
            'System Commands:\n'
            '  is-system-running                   Check whether system is fully running\n'
            '  default                             Enter system default mode\n'
            '  rescue                              Enter system rescue mode\n'
            '  emergency                           Enter system emergency mode\n'
            '  halt                                Shut down and halt the system\n'
            '  poweroff                            Shut down and power-off the system\n'
            '  reboot                              Shut down and reboot the system\n'
            '  kexec                               Shut down and reboot the system with kexec\n'
            '  soft-reboot                         Shut down and reboot userspace\n'
            '  exit [EXIT_CODE]                    Request user instance or container exit\n'
            '  switch-root [ROOT [INIT]]           Change to a different root file system\n'
            '  sleep                               Put the system to sleep (through one of\n'
            '                                      the operations below)\n'
            '  suspend                             Suspend the system\n'
            '  hibernate                           Hibernate the system\n'
            '  hybrid-sleep                        Hibernate and suspend the system\n'
            '  suspend-then-hibernate              Suspend the system, wake after a period of\n'
            '                                      time, and hibernate\n'
            'Options:\n'
            '  -h --help              Show this help\n'
            '     --version           Show package version\n'
            '     --system            Connect to system manager\n'
            '     --user              Connect to user service manager\n'
            '  -C --capsule=NAME      Connect to service manager of specified capsule\n'
            '  -H --host=[USER@]HOST  Operate on remote host\n'
            '  -M --machine=CONTAINER Operate on a local container\n'
            '  -t --type=TYPE         List units of a particular type\n'
            '     --state=STATE       List units with particular LOAD or SUB or ACTIVE state\n'
            '     --failed            Shortcut for --state=failed\n'
            '  -p --property=NAME     Show only properties by this name\n'
            '  -P NAME                Equivalent to --value --property=NAME\n'
            '  -a --all               Show all properties/all units currently in memory,\n'
            '                         including dead/empty ones. To list all units installed\n'
            "                         on the system, use 'list-unit-files' instead.\n"
            "  -l --full              Don't ellipsize unit names on output\n"
            '  -r --recursive         Show unit list of host and local containers\n'
            "     --reverse           Show reverse dependencies with 'list-dependencies'\n"
            "     --before            Show units ordered before with 'list-dependencies'\n"
            "     --after             Show units ordered after with 'list-dependencies'\n"
            "     --with-dependencies Show unit dependencies with 'status', 'cat',\n"
            "                         'list-units', and 'list-unit-files'.\n"
            '     --job-mode=MODE     Specify how to deal with already queued jobs, when\n'
            '                         queueing a new job\n'
            '  -T --show-transaction  When enqueuing a unit job, show full transaction\n'
            '     --show-types        When showing sockets, explicitly show their type\n'
            '     --value             When showing properties, only print the value\n'
            '     --check-inhibitors=MODE\n'
            '                         Whether to check inhibitors before shutting down,\n'
            '                         sleeping, or hibernating\n'
            '  -i                     Shortcut for --check-inhibitors=no\n'
            '     --kill-whom=WHOM    Whom to send signal to\n'
            '     --kill-value=INT    Signal value to enqueue\n'
            '  -s --signal=SIGNAL     Which signal to send\n'
            '     --what=RESOURCES    Which types of resources to remove\n'
            '     --now               Start or stop unit after enabling or disabling it\n'
            '     --dry-run           Only print what would be done\n'
            '                         Currently supported by verbs: halt, poweroff, reboot,\n'
            '                             kexec, soft-reboot, suspend, hibernate, \n'
            '                             suspend-then-hibernate, hybrid-sleep, default,\n'
            '                             rescue, emergency, and exit.\n'
            '  -q --quiet             Suppress output\n'
            '     --no-warn           Suppress several warnings shown by default\n'
            '     --wait              For (re)start, wait until service stopped again\n'
            '                         For is-system-running, wait until startup is completed\n'
            '                         For kill, wait until service stopped\n'
            '     --no-block          Do not wait until operation finished\n'
            "     --no-wall           Don't send wall message before halt/power-off/reboot\n"
            '     --message=MESSAGE   Specify human readable reason for system shutdown\n'
            "     --no-reload         Don't reload daemon after en-/dis-abling unit files\n"
            '     --legend=BOOL       Enable/disable the legend (column headers and hints)\n'
            '     --no-pager          Do not pipe output into a pager\n'
            '     --no-ask-password   Do not ask for system passwords\n'
            '     --global            Edit/enable/disable/mask default user unit files\n'
            '                         globally\n'
            '     --runtime           Edit/enable/disable/mask unit files temporarily until\n'
            '                         next reboot\n'
            '  -f --force             When enabling unit files, override existing symlinks\n'
            '                         When shutting down, execute action immediately\n'
            '     --preset-mode=      Apply only enable, only disable, or all presets\n'
            '     --root=PATH         Edit/enable/disable/mask unit files in the specified\n'
            '                         root directory\n'
            '     --image=PATH        Edit/enable/disable/mask unit files in the specified\n'
            '                         disk image\n'
            '     --image-policy=POLICY\n'
            '                         Specify disk image dissection policy\n'
            '  -n --lines=INTEGER     Number of journal entries to show\n'
            '  -o --output=STRING     Change journal output mode (short, short-precise,\n'
            '                             short-iso, short-iso-precise, short-full,\n'
            '                             short-monotonic, short-unix, short-delta,\n'
            '                             verbose, export, json, json-pretty, json-sse, cat)\n'
            '     --firmware-setup    Tell the firmware to show the setup menu on next boot\n'
            '     --boot-loader-menu=TIME\n'
            '                         Boot into boot loader menu on next boot\n'
            '     --boot-loader-entry=NAME\n'
            '                         Boot into a specific boot loader entry on next boot\n'
            '     --reboot-argument=ARG\n'
            '                         Specify argument string to pass to reboot()\n'
            '     --plain             Print unit dependencies as a list instead of a tree\n'
            '     --timestamp=FORMAT  Change format of printed timestamps (pretty, unix,\n'
            '                             us, utc, us+utc)\n'
            '     --read-only         Create read-only bind mount\n'
            '     --mkdir             Create directory before mounting, if missing\n'
            '     --marked            Restart/reload previously marked units\n'
            '     --drop-in=NAME      Edit unit files using the specified drop-in file name\n'
            '     --when=TIME         Schedule halt/power-off/reboot/kexec action after\n'
            '                         a certain timestamp\n'
            '     --stdin             Read new contents of edited file from stdin\n'
            '\n'
            'See the systemctl(1) man page for details.\n'
        ),
        (
            ''
        ), 0),
    'systemd-analyze': (
        (
            'systemd-analyze [OPTIONS...] COMMAND ...\n'
            '\n'
            'Profile systemd, show unit dependencies, check unit files.\n'
            '\n'
            'Boot Analysis:\n'
            '  [time]                     Print time required to boot the machine\n'
            '  blame                      Print list of running units ordered by\n'
            '                             time to init\n'
            '  critical-chain [UNIT...]   Print a tree of the time critical chain\n'
            '                             of units\n'
            '\n'
            'Dependency Analysis:\n'
            '  plot                       Output SVG graphic showing service\n'
            '                             initialization\n'
            '  dot [UNIT...]              Output dependency graph in dot(1) format\n'
            '  dump [PATTERN...]          Output state serialization of service\n'
            '                             manager\n'
            '\n'
            'Configuration Files and Search Paths:\n'
            '  cat-config NAME|PATH...    Show configuration file and drop-ins\n'
            '  unit-files                 List files and symlinks for units\n'
            '  unit-paths                 List load directories for units\n'
            '\n'
            'Enumerate OS Concepts:\n'
            '  exit-status [STATUS...]    List exit status definitions\n'
            '  capability [CAP...]        List capability definitions\n'
            '  syscall-filter [NAME...]   List syscalls in seccomp filters\n'
            '  filesystems [NAME...]      List known filesystems\n'
            '  architectures [NAME...]    List known architectures\n'
            '  smbios11                   List strings passed via SMBIOS Type #11\n'
            '\n'
            'Expression Evaluation:\n'
            '  condition CONDITION...     Evaluate conditions and asserts\n'
            '  compare-versions VERSION1 [OP] VERSION2\n'
            '                             Compare two version strings\n'
            '  image-policy POLICY...     Analyze image policy string\n'
            '\n'
            'Clock & Time:\n'
            '  calendar SPEC...           Validate repetitive calendar time\n'
            '                             events\n'
            '  timestamp TIMESTAMP...     Validate a timestamp\n'
            '  timespan SPAN...           Validate a time span\n'
            '\n'
            'Unit & Service Analysis:\n'
            '  verify FILE...             Check unit files for correctness\n'
            '  security [UNIT...]         Analyze security of unit\n'
            '  fdstore SERVICE...         Show file descriptor store contents of service\n'
            '  malloc [D-BUS SERVICE...]  Dump malloc stats of a D-Bus service\n'
            '\n'
            'Executable Analysis:\n'
            '  inspect-elf FILE...        Parse and print ELF package metadata\n'
            '\n'
            'TPM Operations:\n'
            '  has-tpm2                   Report whether TPM2 support is available\n'
            '  pcrs [PCR...]              Show TPM2 PCRs and their names\n'
            '  srk [>FILE]                Write TPM2 SRK (to FILE)\n'
            '\n'
            'Options:\n'
            '     --recursive-errors=MODE Control which units are verified\n'
            '     --offline=BOOL          Perform a security review on unit file(s)\n'
            '     --threshold=N           Exit with a non-zero status when overall\n'
            '                             exposure level is over threshold value\n'
            '     --security-policy=PATH  Use custom JSON security policy instead\n'
            '                             of built-in one\n'
            '     --json=pretty|short|off Generate JSON output of the security\n'
            "                             analysis table, or plot's raw time data\n"
            '     --no-pager              Do not pipe output into a pager\n'
            '     --no-legend             Disable column headers and hints in plot\n'
            '                             with either --table or --json=\n'
            '     --system                Operate on system systemd instance\n'
            '     --user                  Operate on user systemd instance\n'
            '     --global                Operate on global user configuration\n'
            '  -H --host=[USER@]HOST      Operate on remote host\n'
            '  -M --machine=CONTAINER     Operate on local container\n'
            '     --order                 Show only order in the graph\n'
            '     --require               Show only requirement in the graph\n'
            '     --from-pattern=GLOB     Show only origins in the graph\n'
            '     --to-pattern=GLOB       Show only destinations in the graph\n'
            '     --fuzz=SECONDS          Also print services which finished SECONDS\n'
            '                             earlier than the latest in the branch\n'
            '     --man[=BOOL]            Do [not] check for existence of man pages\n'
            '     --generators[=BOOL]     Do [not] run unit generators\n'
            '                             (requires privileges)\n'
            '     --instance=NAME         Specify fallback instance name for template units\n'
            '     --iterations=N          Show the specified number of iterations\n'
            '     --base-time=TIMESTAMP   Calculate calendar times relative to\n'
            '                             specified time\n'
            '     --profile=name|PATH     Include the specified profile in the\n'
            '                             security review of the unit(s)\n'
            '     --unit=UNIT             Evaluate conditions and asserts of unit\n'
            "     --table                 Output plot's raw time data as a table\n"
            '     --scale-svg=FACTOR      Stretch x-axis of plot by FACTOR (default: 1.0)\n'
            '     --detailed              Add more details to SVG plot,\n'
            '                             e.g. show activation timestamps\n'
            '  -h --help                  Show this help\n'
            '     --version               Show package version\n'
            '  -q --quiet                 Do not emit hints\n'
            '     --tldr                  Skip comments and empty lines\n'
            '     --root=PATH             Operate on an alternate filesystem root\n'
            '     --image=PATH            Operate on disk image as filesystem root\n'
            '     --image-policy=POLICY   Specify disk image dissection policy\n'
            '  -m --mask                  Parse parameter as numeric capability mask\n'
            '\n'
            'See the systemd-analyze(1) man page for details.\n'
        ),
        (
            ''
        ), 0),
    'tar': (
        (
            'Usage: tar [OPTION...] [FILE]...\n'
            "GNU 'tar' saves many files together into a single tape or disk archive, and can\n"
            'restore individual files from the archive.\n'
            '\n'
            'Examples:\n'
            '  tar -cf archive.tar foo bar  # Create archive.tar from files foo and bar.\n'
            '  tar -tvf archive.tar         # List all files in archive.tar verbosely.\n'
            '  tar -xf archive.tar          # Extract all files from archive.tar.\n'
            '\n'
            ' Main operation mode:\n'
            '  -A, --catenate, --concatenate   append tar files to an archive\n'
            '  -c, --create               create a new archive\n'
            '      --delete               delete from the archive (not on mag tapes!)\n'
            '  -d, --diff, --compare      find differences between archive and file system\n'
            '  -r, --append               append files to the end of an archive\n'
            '      --test-label           test the archive volume label and exit\n'
            '  -t, --list                 list the contents of an archive\n'
            '  -u, --update               only append files newer than copy in archive\n'
            '  -x, --extract, --get       extract files from an archive\n'
            '\n'
            ' Operation modifiers:\n'
            '\n'
            '      --check-device         check device numbers when creating incremental\n'
            '                             archives (default)\n'
            '  -g, --listed-incremental=FILE   handle new GNU-format incremental backup\n'
            '  -G, --incremental          handle old GNU-format incremental backup\n'
            '      --hole-detection=TYPE  technique to detect holes\n'
            '      --ignore-failed-read   do not exit with nonzero on unreadable files\n'
            '      --level=NUMBER         dump level for created listed-incremental archive\n'
            '      --no-check-device      do not check device numbers when creating\n'
            '                             incremental archives\n'
            '      --no-seek              archive is not seekable\n'
            '  -n, --seek                 archive is seekable\n'
            '      --occurrence[=NUMBER]  process only the NUMBERth occurrence of each file\n'
            '                             in the archive; this option is valid only in\n'
            '                             conjunction with one of the subcommands --delete,\n'
            '                             --diff, --extract or --list and when a list of\n'
            '                             files is given either on the command line or via\n'
            '                             the -T option; NUMBER defaults to 1\n'
            '      --sparse-version=MAJOR[.MINOR]\n'
            '                             set version of the sparse format to use (implies\n'
            '                             --sparse)\n'
            '  -S, --sparse               handle sparse files efficiently\n'
            '\n'
            ' Local file name selection:\n'
            '      --add-file=FILE        add given FILE to the archive (useful if its name\n'
            '                             starts with a dash)\n'
            '  -C, --directory=DIR        change to directory DIR\n'
            '      --exclude=PATTERN      exclude files, given as a PATTERN\n'
            '      --exclude-backups      exclude backup and lock files\n'
            '      --exclude-caches       exclude contents of directories containing\n'
            '                             CACHEDIR.TAG, except for the tag file itself\n'
            '      --exclude-caches-all   exclude directories containing CACHEDIR.TAG\n'
            '      --exclude-caches-under exclude everything under directories containing\n'
            '                             CACHEDIR.TAG\n'
            '      --exclude-ignore=FILE  read exclude patterns for each directory from\n'
            '                             FILE, if it exists\n'
            '      --exclude-ignore-recursive=FILE\n'
            '                             read exclude patterns for each directory and its\n'
            '                             subdirectories from FILE, if it exists\n'
            '      --exclude-tag=FILE     exclude contents of directories containing FILE,\n'
            '                             except for FILE itself\n'
            '      --exclude-tag-all=FILE exclude directories containing FILE\n'
            '      --exclude-tag-under=FILE   exclude everything under directories\n'
            '                             containing FILE\n'
            '      --exclude-vcs          exclude version control system directories\n'
            '      --exclude-vcs-ignores  read exclude patterns from the VCS ignore files\n'
            '      --no-null              disable the effect of the previous --null option\n'
            '      --no-recursion         avoid descending automatically in directories\n'
            '      --no-unquote           do not unquote input file or member names\n'
            '      --no-verbatim-files-from   -T treats file names starting with dash as\n'
            '                             options (default)\n'
            '      --null                 -T reads null-terminated names; implies\n'
            '                             --verbatim-files-from\n'
            '      --recursion            recurse into directories (default)\n'
            '  -T, --files-from=FILE      get names to extract or create from FILE\n'
            '      --unquote              unquote input file or member names (default)\n'
            '      --verbatim-files-from  -T reads file names verbatim (no escape or option\n'
            '                             handling)\n'
            '  -X, --exclude-from=FILE    exclude patterns listed in FILE\n'
            '\n'
            ' File name matching options (affect both exclude and include patterns):\n'
            '\n'
            '      --anchored             patterns match file name start\n'
            '      --ignore-case          ignore case\n'
            "      --no-anchored          patterns match after any '/' (default for\n"
            '                             exclusion)\n'
            '      --no-ignore-case       case sensitive matching (default)\n'
            '      --no-wildcards         verbatim string matching\n'
            "      --no-wildcards-match-slash   wildcards do not match '/'\n"
            '      --wildcards            use wildcards (default for exclusion)\n'
            "      --wildcards-match-slash   wildcards match '/' (default for exclusion)\n"
            '\n'
            ' Overwrite control:\n'
            '\n'
            '      --keep-directory-symlink   preserve existing symlinks to directories when\n'
            '                             extracting\n'
            "      --keep-newer-files     don't replace existing files that are newer than\n"
            '                             their archive copies\n'
            "  -k, --keep-old-files       don't replace existing files when extracting,\n"
            '                             treat them as errors\n'
            '      --no-overwrite-dir     preserve metadata of existing directories\n'
            '      --one-top-level[=DIR]  create a subdirectory to avoid having loose files\n'
            '                             extracted\n'
            '      --overwrite            overwrite existing files when extracting\n'
            '      --overwrite-dir        overwrite metadata of existing directories when\n'
            '                             extracting (default)\n'
            '      --recursive-unlink     empty hierarchies prior to extracting directory\n'
            '      --remove-files         remove files after adding them to the archive\n'
            "      --skip-old-files       don't replace existing files when extracting,\n"
            '                             silently skip over them\n'
            '  -U, --unlink-first         remove each file prior to extracting over it\n'
            '  -W, --verify               attempt to verify the archive after writing it\n'
            '\n'
            ' Select output stream:\n'
            '\n'
            '      --ignore-command-error ignore exit codes of children\n'
            '      --no-ignore-command-error   treat non-zero exit codes of children as\n'
            '                             error\n'
            '  -O, --to-stdout            extract files to standard output\n'
            '      --to-command=COMMAND   pipe extracted files to another program\n'
            '\n'
            ' Handling of file attributes:\n'
            '\n'
            '      --atime-preserve[=METHOD]   preserve access times on dumped files, either\n'
            '                             by restoring the times after reading\n'
            "                             (METHOD='replace'; default) or by not setting the\n"
            "                             times in the first place (METHOD='system')\n"
            '      --clamp-mtime          only set time when the file is more recent than\n'
            '                             what was given with --mtime\n'
            '      --delay-directory-restore   delay setting modification times and\n'
            '                             permissions of extracted directories until the end\n'
            '                             of extraction\n'
            '      --group=NAME           force NAME as group for added files\n'
            '      --group-map=FILE       use FILE to map file owner GIDs and names\n'
            '      --mode=CHANGES         force (symbolic) mode CHANGES for added files\n'
            '      --mtime=DATE-OR-FILE   set mtime for added files from DATE-OR-FILE\n'
            "  -m, --touch                don't extract file modified time\n"
            '      --no-delay-directory-restore\n'
            '                             cancel the effect of --delay-directory-restore\n'
            '                             option\n'
            '      --no-same-owner        extract files as yourself (default for ordinary\n'
            '                             users)\n'
            "      --no-same-permissions  apply the user's umask when extracting permissions\n"
            '                             from the archive (default for ordinary users)\n'
            '      --numeric-owner        always use numbers for user/group names\n'
            '      --owner=NAME           force NAME as owner for added files\n'
            '      --owner-map=FILE       use FILE to map file owner UIDs and names\n'
            '  -p, --preserve-permissions, --same-permissions\n'
            '                             extract information about file permissions\n'
            '                             (default for superuser)\n'
            '      --same-owner           try extracting files with the same ownership as\n'
            '                             exists in the archive (default for superuser)\n'
            '      --sort=ORDER           directory sorting order: none (default), name or\n'
            '                             inode\n'
            '  -s, --preserve-order, --same-order\n'
            '                             member arguments are listed in the same order as\n'
            '                             the files in the archive\n'
            '\n'
            ' Handling of extended file attributes:\n'
            '\n'
            '      --acls                 Enable the POSIX ACLs support\n'
            '      --no-acls              Disable the POSIX ACLs support\n'
            '      --no-selinux           Disable the SELinux context support\n'
            '      --no-xattrs            Disable extended attributes support\n'
            '      --selinux              Enable the SELinux context support\n'
            '      --xattrs               Enable extended attributes support\n'
            '      --xattrs-exclude=MASK  specify the exclude pattern for xattr keys\n'
            '      --xattrs-include=MASK  specify the include pattern for xattr keys\n'
            '\n'
            ' Device selection and switching:\n'
            '\n'
            '      --force-local          archive file is local even if it has a colon\n'
            '  -f, --file=ARCHIVE         use archive file or device ARCHIVE\n'
            '  -F, --info-script=NAME, --new-volume-script=NAME\n'
            '                             run script at end of each tape (implies -M)\n'
            '  -L, --tape-length=NUMBER   change tape after writing NUMBER x 1024 bytes\n'
            '  -M, --multi-volume         create/list/extract multi-volume archive\n'
            '      --rmt-command=COMMAND  use given rmt COMMAND instead of rmt\n'
            '      --rsh-command=COMMAND  use remote COMMAND instead of rsh\n'
            '      --volno-file=FILE      use/update the volume number in FILE\n'
            '\n'
            ' Device blocking:\n'
            '\n'
            '  -b, --blocking-factor=BLOCKS   BLOCKS x 512 bytes per record\n'
            '  -B, --read-full-records    reblock as we read (for 4.2BSD pipes)\n'
            '  -i, --ignore-zeros         ignore zeroed blocks in archive (means EOF)\n'
            '      --record-size=NUMBER   NUMBER of bytes per record, multiple of 512\n'
            '\n'
            ' Archive format selection:\n'
            '\n'
            '  -H, --format=FORMAT        create archive of the given format\n'
            '\n'
            ' FORMAT is one of the following:\n'
            '    gnu                      GNU tar 1.13.x format\n'
            '    oldgnu                   GNU format as per tar <= 1.12\n'
            '    pax                      POSIX 1003.1-2001 (pax) format\n'
            '    posix                    same as pax\n'
            '    ustar                    POSIX 1003.1-1988 (ustar) format\n'
            '    v7                       old V7 tar format\n'
            '\n'
            '      --old-archive, --portability\n'
            '                             same as --format=v7\n'
            '      --pax-option=keyword[[:]=value][,keyword[[:]=value]]...\n'
            '                             control pax keywords\n'
            '      --posix                same as --format=posix\n'
            '  -V, --label=TEXT           create archive with volume name TEXT; at\n'
            '                             list/extract time, use TEXT as a globbing pattern\n'
            '                             for volume name\n'
            '\n'
            ' Compression options:\n'
            '\n'
            '  -a, --auto-compress        use archive suffix to determine the compression\n'
            '                             program\n'
            '  -I, --use-compress-program=PROG\n'
            '                             filter through PROG (must accept -d)\n'
            '  -j, --bzip2                filter the archive through bzip2\n'
            '  -J, --xz                   filter the archive through xz\n'
            '      --lzip                 filter the archive through lzip\n'
            '      --lzma                 filter the archive through xz\n'
            '      --lzop                 filter the archive through lzop\n'
            '      --no-auto-compress     do not use archive suffix to determine the\n'
            '                             compression program\n'
            '      --zstd                 filter the archive through zstd\n'
            '  -z, --gzip, --gunzip, --ungzip   filter the archive through gzip\n'
            '  -Z, --compress, --uncompress   filter the archive through compress\n'
            '\n'
            ' Local file selection:\n'
            '\n'
            '      --backup[=CONTROL]     backup before removal, choose version CONTROL\n'
            '      --hard-dereference     follow hard links; archive and dump the files they\n'
            '                             refer to\n'
            '  -h, --dereference          follow symlinks; archive and dump the files they\n'
            '                             point to\n'
            '  -K, --starting-file=MEMBER-NAME\n'
            '                             begin at member MEMBER-NAME when reading the\n'
            '                             archive\n'
            '      --newer-mtime=DATE     compare date and time when data changed only\n'
            '  -N, --newer=DATE-OR-FILE, --after-date=DATE-OR-FILE\n'
            '                             only store files newer than DATE-OR-FILE\n'
            '      --one-file-system      stay in local file system when creating archive\n'
            "  -P, --absolute-names       don't strip leading '/'s from file names\n"
            "      --suffix=STRING        backup before removal, override usual suffix ('~'\n"
            '                             unless overridden by environment variable\n'
            '                             SIMPLE_BACKUP_SUFFIX)\n'
            '\n'
            ' File name transformations:\n'
            '\n'
            '      --strip-components=NUMBER   strip NUMBER leading components from file\n'
            '                             names on extraction\n'
            '      --transform=EXPRESSION, --xform=EXPRESSION\n'
            '                             use sed replace EXPRESSION to transform file\n'
            '                             names\n'
            '\n'
            ' Informative output:\n'
            '\n'
            '      --checkpoint[=NUMBER]  display progress messages every NUMBERth record\n'
            '                             (default 10)\n'
            '      --checkpoint-action=ACTION   execute ACTION on each checkpoint\n'
            '      --full-time            print file time to its full resolution\n'
            '      --index-file=FILE      send verbose output to FILE\n'
            '  -l, --check-links          print a message if not all links are dumped\n'
            '      --no-quote-chars=STRING   disable quoting for characters from STRING\n'
            '      --quote-chars=STRING   additionally quote characters from STRING\n'
            '      --quoting-style=STYLE  set name quoting style; see below for valid STYLE\n'
            '                             values\n'
            '  -R, --block-number         show block number within archive with each message\n'
            '                            \n'
            '      --show-defaults        show tar defaults\n'
            '      --show-omitted-dirs    when listing or extracting, list each directory\n'
            '                             that does not match search criteria\n'
            '      --show-snapshot-field-ranges\n'
            '                             show valid ranges for snapshot-file fields\n'
            '      --show-transformed-names, --show-stored-names\n'
            '                             show file or archive names after transformation\n'
            '      --totals[=SIGNAL]      print total bytes after processing the archive;\n'
            '                             with an argument - print total bytes when this\n'
            '                             SIGNAL is delivered; Allowed signals are: SIGHUP,\n'
            '                             SIGQUIT, SIGINT, SIGUSR1 and SIGUSR2; the names\n'
            '                             without SIG prefix are also accepted\n'
            '      --utc                  print file modification times in UTC\n'
            '  -v, --verbose              verbosely list files processed\n'
            '      --warning=KEYWORD      warning control\n'
            '  -w, --interactive, --confirmation\n'
            '                             ask for confirmation for every action\n'
            '\n'
            ' Compatibility options:\n'
            '\n'
            '  -o                         when creating, same as --old-archive; when\n'
            '                             extracting, same as --no-same-owner\n'
            '\n'
            ' Other options:\n'
            '\n'
            '  -?, --help                 give this help list\n'
            '      --restrict             disable use of some potentially harmful options\n'
            '      --usage                give a short usage message\n'
            '      --version              print program version\n'
            '\n'
            'Mandatory or optional arguments to long options are also mandatory or optional\n'
            'for any corresponding short options.\n'
            '\n'
            "The backup suffix is '~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX.\n"
            'The version control may be set with --backup or VERSION_CONTROL, values are:\n'
            '\n'
            '  none, off       never make backups\n'
            '  t, numbered     make numbered backups\n'
            '  nil, existing   numbered if numbered backups exist, simple otherwise\n'
            '  never, simple   always make simple backups\n'
            '\n'
            'Valid arguments for the --quoting-style option are:\n'
            '\n'
            '  literal\n'
            '  shell\n'
            '  shell-always\n'
            '  shell-escape\n'
            '  shell-escape-always\n'
            '  c\n'
            '  c-maybe\n'
            '  escape\n'
            '  locale\n'
            '  clocale\n'
            '\n'
            '*This* tar defaults to:\n'
            '--format=gnu -f- -b20 --quoting-style=escape --rmt-command=/usr/sbin/rmt\n'
            '--rsh-command=/usr/bin/rsh\n'
        ),
        (
            ''
        ), 0),
    'umount': (
        (
            '\n'
            'Usage:\n'
            ' umount [-hV]\n'
            ' umount -a [options]\n'
            ' umount [options] <source> | <directory>\n'
            '\n'
            'Unmount filesystems.\n'
            '\n'
            'Options:\n'
            ' -a, --all               unmount all filesystems\n'
            ' -A, --all-targets       unmount all mountpoints for the given device in the\n'
            '                           current namespace\n'
            " -c, --no-canonicalize   don't canonicalize paths\n"
            ' -d, --detach-loop       if mounted loop device, also free this loop device\n'
            '     --fake              dry run; skip the umount(2) syscall\n'
            ' -f, --force             force unmount (in case of an unreachable NFS system)\n'
            " -i, --internal-only     don't call the umount.<type> helpers\n"
            " -n, --no-mtab           don't write to /etc/mtab\n"
            ' -l, --lazy              detach the filesystem now, clean up things later\n'
            ' -O, --test-opts <list>  limit the set of filesystems (use with -a)\n'
            ' -R, --recursive         recursively unmount a target with all its children\n'
            ' -r, --read-only         in case unmounting fails, try to remount read-only\n'
            ' -t, --types <list>      limit the set of filesystem types\n'
            ' -v, --verbose           say what is being done\n'
            " -q, --quiet             suppress 'not mounted' error messages\n"
            ' -N, --namespace <ns>    perform umount in another namespace\n'
            '\n'
            ' -h, --help              display this help\n'
            ' -V, --version           display version\n'
            '\n'
            'For more details see umount(8).\n'
        ),
        (
            ''
        ), 0),
    'unxz': (
        (
            'Usage: unxz [OPTION]... [FILE]...\n'
            'Compress or decompress FILEs in the .xz format.\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '\n'
            '  -z, --compress      force compression\n'
            '  -d, --decompress    force decompression\n'
            '  -t, --test          test compressed file integrity\n'
            '  -l, --list          list information about .xz files\n'
            "  -k, --keep          keep (don't delete) input files\n"
            '  -f, --force         force overwrite of output file and (de)compress links\n'
            "  -c, --stdout        write to standard output and don't delete input files\n"
            '  -0 ... -9           compression preset; default is 6; take compressor *and*\n'
            '                      decompressor memory usage into account before using 7-9!\n'
            '  -e, --extreme       try to improve compression ratio by using more CPU time;\n'
            '                      does not affect decompressor memory requirements\n'
            '  -T, --threads=NUM   use at most NUM threads; the default is 0 which uses as\n'
            '                      many threads as there are processor cores\n'
            '  -q, --quiet         suppress warnings; specify twice to suppress errors too\n'
            '  -v, --verbose       be verbose; specify twice for even more verbose\n'
            '  -h, --help          display this short help and exit\n'
            '  -H, --long-help     display the long help (lists also the advanced options)\n'
            '  -V, --version       display the version number and exit\n'
            '\n'
            'With no FILE, or when FILE is -, read standard input.\n'
            '\n'
            'Report bugs to <xz@tukaani.org> (in English or Finnish).\n'
            'XZ Utils home page: <https://tukaani.org/xz/>\n'
        ),
        (
            ''
        ), 0),
    'xz': (
        (
            'Usage: xz [OPTION]... [FILE]...\n'
            'Compress or decompress FILEs in the .xz format.\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '\n'
            '  -z, --compress      force compression\n'
            '  -d, --decompress    force decompression\n'
            '  -t, --test          test compressed file integrity\n'
            '  -l, --list          list information about .xz files\n'
            "  -k, --keep          keep (don't delete) input files\n"
            '  -f, --force         force overwrite of output file and (de)compress links\n'
            "  -c, --stdout        write to standard output and don't delete input files\n"
            '  -0 ... -9           compression preset; default is 6; take compressor *and*\n'
            '                      decompressor memory usage into account before using 7-9!\n'
            '  -e, --extreme       try to improve compression ratio by using more CPU time;\n'
            '                      does not affect decompressor memory requirements\n'
            '  -T, --threads=NUM   use at most NUM threads; the default is 0 which uses as\n'
            '                      many threads as there are processor cores\n'
            '  -q, --quiet         suppress warnings; specify twice to suppress errors too\n'
            '  -v, --verbose       be verbose; specify twice for even more verbose\n'
            '  -h, --help          display this short help and exit\n'
            '  -H, --long-help     display the long help (lists also the advanced options)\n'
            '  -V, --version       display the version number and exit\n'
            '\n'
            'With no FILE, or when FILE is -, read standard input.\n'
            '\n'
            'Report bugs to <xz@tukaani.org> (in English or Finnish).\n'
            'XZ Utils home page: <https://tukaani.org/xz/>\n'
        ),
        (
            ''
        ), 0),
})


#: The rest of the stock-template list -- the commands that answered
#: --help with `<name> <version>` and `Usage: <name> [OPTION]... [FILE]...`,
#: which is coreutils' shape and not theirs. Sixty-nine of them, all
#: present on the guest and measured there.
#:
#: Several answer on stderr and several exit non-zero for a --help that
#: works, which is why the table keeps all three parts: agetty, badblocks,
#: bridge, cfdisk, dbus-daemon and sfdisk print nothing at all on stdout.
#: pager is less and editor is nano -- byte-identical, because that is
#: what those alternatives point at. lesspipe answers with nothing on
#: either stream, so its entry is empty on purpose rather than missing.
#:
#: Screened for anything that would not reproduce -- a timestamp, a pid, a
#: varying path -- before being embedded, which is why socat is not here.
HELP.update({
    'agetty': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘agetty’: No such file or directory\n'
        ), 127),
    'badblocks': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘badblocks’: No such file or directory\n'
        ), 127),
    'bridge': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘bridge’: No such file or directory\n'
        ), 127),
    'busctl': (
        (
            'busctl [OPTIONS...] COMMAND ...\n'
            '\n'
            'Introspect the D-Bus IPC bus.\n'
            '\n'
            'Commands:\n'
            '  list                     List bus names\n'
            '  status [SERVICE]         Show bus service, process or bus owner credentials\n'
            '  monitor [SERVICE...]     Show bus traffic\n'
            '  capture [SERVICE...]     Capture bus traffic as pcap\n'
            '  tree [SERVICE...]        Show object tree of service\n'
            '  introspect SERVICE OBJECT [INTERFACE]\n'
            '  call SERVICE OBJECT INTERFACE METHOD [SIGNATURE [ARGUMENT...]]\n'
            '                           Call a method\n'
            '  emit OBJECT INTERFACE SIGNAL [SIGNATURE [ARGUMENT...]]\n'
            '                           Emit a signal\n'
            '  wait OBJECT INTERFACE SIGNAL\n'
            '                           Wait for a signal\n'
            '  get-property SERVICE OBJECT INTERFACE PROPERTY...\n'
            '                           Get property value\n'
            '  set-property SERVICE OBJECT INTERFACE PROPERTY SIGNATURE ARGUMENT...\n'
            '                           Set property value\n'
            '  help                     Show this help\n'
            '\n'
            'Options:\n'
            '  -h --help                Show this help\n'
            '     --version             Show package version\n'
            '     --no-pager            Do not pipe output into a pager\n'
            '     --no-legend           Do not show the headers and footers\n'
            '  -l --full                Do not ellipsize output\n'
            '     --system              Connect to system bus\n'
            '     --user                Connect to user bus\n'
            '  -H --host=[USER@]HOST    Operate on remote host\n'
            '  -M --machine=CONTAINER   Operate on local container\n'
            '     --address=ADDRESS     Connect to bus specified by address\n'
            '     --show-machine        Show machine ID column in list\n'
            '     --unique              Only show unique names\n'
            '     --acquired            Only show acquired names\n'
            '     --activatable         Only show activatable names\n'
            '     --match=MATCH         Only show matching messages\n'
            '     --size=SIZE           Maximum length of captured packet\n'
            "     --list                Don't show tree, but simple object path list\n"
            "  -q --quiet               Don't show method call reply\n"
            '     --verbose             Show result values in long format\n'
            '     --json=MODE           Output as JSON\n'
            '  -j                       Same as --json=pretty on tty, --json=short otherwise\n'
            '     --xml-interface       Dump the XML description in introspect command\n'
            '     --expect-reply=BOOL   Expect a method call reply\n'
            '     --auto-start=BOOL     Auto-start destination service\n'
            '     --allow-interactive-authorization=BOOL\n'
            '                           Allow interactive authorization for operation\n'
            '     --timeout=SECS        Maximum time to wait for method call completion\n'
            '     --augment-creds=BOOL  Extend credential data with data read from /proc/$PID\n'
            '     --watch-bind=BOOL     Wait for bus AF_UNIX socket to be bound in the file\n'
            '                           system\n'
            '     --destination=SERVICE Destination service of a signal\n'
            '  -N --limit-messages=NUMBER\n'
            '                           Stop monitoring after receiving the specified number\n'
            '                           of messages\n'
            '\n'
            'See the busctl(1) man page for details.\n'
        ),
        (
            ''
        ), 0),
    'catman': (
        (
            'Usage: catman [OPTION...] [SECTION...]\n'
            '\n'
            '  -C, --config-file=FILE     use this user configuration file\n'
            '  -d, --debug                emit debugging messages\n'
            '  -M, --manpath=PATH         set search path for manual pages to PATH\n'
            '  -?, --help                 give this help list\n'
            '      --usage                give a short usage message\n'
            '  -V, --version              print program version\n'
            '\n'
            'Mandatory or optional arguments to long options are also mandatory or optional\n'
            'for any corresponding short options.\n'
            '\n'
            'Report bugs to cjwatson@debian.org.\n'
        ),
        (
            ''
        ), 0),
    'cfdisk': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘cfdisk’: No such file or directory\n'
        ), 127),
    'col': (
        (
            '\n'
            'Usage:\n'
            ' col [options]\n'
            '\n'
            'Filter out reverse line feeds from standard input.\n'
            '\n'
            'Options:\n'
            ' -b, --no-backspaces    do not output backspaces\n'
            ' -f, --fine             permit forward half line feeds\n'
            ' -p, --pass             pass unknown control sequences\n'
            ' -h, --tabs             convert spaces to tabs\n'
            ' -x, --spaces           convert tabs to spaces\n'
            ' -l, --lines NUM        buffer at least NUM lines\n'
            ' -H, --help             display this help\n'
            ' -V, --version          display version\n'
            '\n'
            'For more details see col(1).\n'
        ),
        (
            ''
        ), 0),
    'colcrt': (
        (
            '\n'
            'Usage:\n'
            ' colcrt [options] [<file>...]\n'
            '\n'
            'Filter nroff output for CRT previewing.\n'
            '\n'
            'Options:\n'
            ' -,  --no-underlining    suppress all underlining\n'
            ' -2, --half-lines        print all half-lines\n'
            '\n'
            ' -h, --help              display this help\n'
            ' -V, --version           display version\n'
            '\n'
            'For more details see colcrt(1).\n'
        ),
        (
            ''
        ), 0),
    'colrm': (
        (
            '\n'
            'Usage:\n'
            ' colrm [startcol [endcol]]\n'
            '\n'
            'Filter out the specified columns from standard input.\n'
            '\n'
            'Options:\n'
            ' -h, --help     display this help\n'
            ' -V, --version  display version\n'
            '\n'
            'For more details see colrm(1).\n'
        ),
        (
            ''
        ), 0),
    'column': (
        (
            '\n'
            'Usage:\n'
            ' column [options] [<file>...]\n'
            '\n'
            'Columnate lists.\n'
            '\n'
            'Options:\n'
            ' -t, --table                      create a table\n'
            ' -n, --table-name <name>          table name for JSON output\n'
            ' -O, --table-order <columns>      specify order of output columns\n'
            ' -C, --table-column <properties>  define column\n'
            ' -N, --table-columns <names>      comma separated columns names\n'
            ' -l, --table-columns-limit <num>  maximal number of input columns\n'
            " -E, --table-noextreme <columns>  don't count long text from the columns to column width\n"
            " -d, --table-noheadings           don't print header\n"
            ' -m, --table-maxout               fill all available space\n'
            ' -e, --table-header-repeat        repeat header for each page\n'
            " -H, --table-hide <columns>       don't print the columns\n"
            ' -R, --table-right <columns>      right align text in these columns\n'
            ' -T, --table-truncate <columns>   truncate text in the columns when necessary\n'
            ' -W, --table-wrap <columns>       wrap text in the columns when necessary\n'
            " -L, --keep-empty-lines           don't ignore empty lines\n"
            ' -J, --json                       use JSON output format for table\n'
            '\n'
            ' -r, --tree <column>              column to use tree-like output for the table\n'
            ' -i, --tree-id <column>           line ID to specify child-parent relation\n'
            ' -p, --tree-parent <column>       parent to specify child-parent relation\n'
            '\n'
            ' -c, --output-width <width>       width of output in number of characters\n'
            ' -o, --output-separator <string>  columns separator for table output (default is two spaces)\n'
            ' -s, --separator <string>         possible table delimiters\n'
            ' -x, --fillrows                   fill rows before columns\n'
            ' -S, --use-spaces <number>        minimal whitespaces between columns (no tabs)\n'
            '\n'
            ' -h, --help                       display this help\n'
            ' -V, --version                    display version\n'
            '\n'
            'For more details see column(1).\n'
        ),
        (
            ''
        ), 0),
    'dbus-daemon': (
        (
            ''
        ),
        (
            'dbus-daemon [--version] [--session] [--system] [--config-file=FILE] [--print-address[=DESCRIPTOR]] [--print-pid[=DESCRIPTOR]] [--introspect] [--address=ADDRESS] [--nopidfile] [--nosyslog] [--syslog] [--syslog-only] [--nofork] [--fork] [--systemd-activation]\n'
        ), 1),
    'deb-systemd-helper': (
        (
            '/usr/bin/deb-systemd-helper is a program which should be called by dpkg maintscripts only.\n'
            'Please do not run it interactively, ever. Also see the manpage deb-systemd-helper(1).\n'
        ),
        (
            'Unknown option: help\n'
        ), 0),
    'diff3': (
        (
            'Usage: diff3 [OPTION]... MYFILE OLDFILE YOURFILE\n'
            'Compare three files line by line.\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '  -A, --show-all              output all changes, bracketing conflicts\n'
            '\n'
            '  -e, --ed                    output ed script incorporating changes\n'
            '                                from OLDFILE to YOURFILE into MYFILE\n'
            '  -E, --show-overlap          like -e, but bracket conflicts\n'
            '  -3, --easy-only             like -e, but incorporate only nonoverlapping changes\n'
            '  -x, --overlap-only          like -e, but incorporate only overlapping changes\n'
            '  -X                          like -x, but bracket conflicts\n'
            "  -i                          append 'w' and 'q' commands to ed scripts\n"
            '\n'
            '  -m, --merge                 output actual merged file, according to\n'
            '                                -A if no other options are given\n'
            '\n'
            '  -a, --text                  treat all files as text\n'
            '      --strip-trailing-cr     strip trailing carriage return on input\n'
            '  -T, --initial-tab           make tabs line up by prepending a tab\n'
            '      --diff-program=PROGRAM  use PROGRAM to compare files\n'
            '  -L, --label=LABEL           use LABEL instead of file name\n'
            '                                (can be repeated up to three times)\n'
            '\n'
            '      --help                  display this help and exit\n'
            '  -v, --version               output version information and exit\n'
            '\n'
            'The default output format is a somewhat human-readable representation of\n'
            'the changes.\n'
            '\n'
            'The -e, -E, -x, -X (and corresponding long) options cause an ed script\n'
            'to be output instead of the default.\n'
            '\n'
            'Finally, the -m (--merge) option causes diff3 to do the merge internally\n'
            'and output the actual merged file.  For unusual input, this is more\n'
            'robust than using ed.\n'
            '\n'
            "If a FILE is '-', read standard input.\n"
            'Exit status is 0 if successful, 1 if conflicts, 2 if trouble.\n'
            '\n'
            'Report bugs to: bug-diffutils@gnu.org\n'
            'GNU diffutils home page: <https://www.gnu.org/software/diffutils/>\n'
            'General help using GNU software: <https://www.gnu.org/gethelp/>\n'
        ),
        (
            ''
        ), 0),
    'dpkg-deb': (
        (
            'Usage: dpkg-deb [<option>...] <command>\n'
            '\n'
            'Commands:\n'
            '  -b|--build <directory> [<deb>]   Build an archive.\n'
            '  -c|--contents <deb>              List contents.\n'
            '  -I|--info <deb> [<cfile>...]     Show info to stdout.\n'
            '  -W|--show <deb>                  Show information on package(s)\n'
            '  -f|--field <deb> [<cfield>...]   Show field(s) to stdout.\n'
            '  -e|--control <deb> [<directory>] Extract control info.\n'
            '  -x|--extract <deb> <directory>   Extract files.\n'
            '  -X|--vextract <deb> <directory>  Extract & list files.\n'
            '  -R|--raw-extract <deb> <directory>\n'
            '                                   Extract control info and files.\n'
            '  --ctrl-tarfile <deb>             Output control tarfile.\n'
            '  --fsys-tarfile <deb>             Output filesystem tarfile.\n'
            '\n'
            '  -?, --help                       Show this help message.\n'
            '      --version                    Show the version.\n'
            '\n'
            '<deb> is the filename of a Debian format archive.\n'
            '<cfile> is the name of an administrative file component.\n'
            "<cfield> is the name of a field in the main 'control' file.\n"
            '\n'
            'Options:\n'
            '  -v, --verbose                    Enable verbose output.\n'
            '  -D, --debug                      Enable debugging output.\n'
            '      --showformat=<format>        Use alternative format for --show.\n'
            '      --deb-format=<format>        Select archive format.\n'
            '                                     Allowed values: 0.939000, 2.0 (default).\n'
            '      --no-check                   Suppress all checks (build bad packages).\n'
            '      --nocheck                    Alias for --no-check.\n'
            '      --root-owner-group           Forces the owner and groups to root.\n'
            '      --threads-max=<threads>      Use at most <threads> with compressor.\n'
            '      --[no-]uniform-compression   Use the compression params on all members.\n'
            '  -Z, --compression=<compressor>   Set build compression type.\n'
            '                                     Allowed types: gzip, xz, zstd, none.\n'
            '  -z, --compression-level=<level>  Set build compression level.\n'
            '  -S, --compression-strategy=<name>\n'
            '                                   Set build compression strategy.\n'
            '                                     Allowed values: none; extreme (xz);\n'
            '                                     filtered, huffman, rle, fixed (gzip).\n'
            '\n'
            'Format syntax:\n'
            '  A format is a string that will be output for each package. The format\n'
            '  can include the standard escape sequences \\n (newline), \\r (carriage\n'
            '  return) or \\\\ (plain backslash). Package information can be included\n'
            '  by inserting variable references to package fields using the ${var[;width]}\n'
            '  syntax. Fields will be right-aligned unless the width is negative in which\n'
            '  case left alignment will be used.\n'
            '\n'
            "Use 'dpkg' to install and remove packages from your system, or\n"
            "'apt' or 'aptitude' for user-friendly package management. Packages\n"
            "unpacked using 'dpkg-deb --extract' will be incorrectly installed !\n"
        ),
        (
            ''
        ), 0),
    'dpkg-divert': (
        (
            'Usage: dpkg-divert [<option>...] <command>\n'
            '\n'
            'Commands:\n'
            '  [--add] <file>           add a diversion.\n'
            '  --remove <file>          remove the diversion.\n'
            '  --list [<glob-pattern>]  show file diversions.\n'
            '  --listpackage <file>     show what package diverts the file.\n'
            '  --truename <file>        return the diverted file.\n'
            '\n'
            'Options:\n'
            '  --package <package>      name of the package whose copy of <file> will not\n'
            '                             be diverted.\n'
            "  --local                  all packages' versions are diverted.\n"
            "  --divert <divert-to>     the name used by other packages' versions.\n"
            '  --rename                 actually move the file aside (or back).\n'
            '  --no-rename              do not move the file aside (or back) (default).\n'
            '  --admindir <directory>   set the directory with the diversions file.\n'
            '  --instdir <directory>    set the root directory, but not the admin dir.\n'
            '  --root <directory>       set the directory of the root filesystem.\n'
            "  --test                   don't do anything, just demonstrate.\n"
            '  --quiet                  quiet operation, minimal output.\n'
            '  --help                   show this help message.\n'
            '  --version                show the version.\n'
            '\n'
            'When adding, default is --local and --divert <original>.distrib.\n'
            'When removing, --package or --local and --divert must match if specified.\n'
            'Package preinst/postrm scripts should always specify --package and --divert.\n'
        ),
        (
            ''
        ), 0),
    'dpkg-split': (
        (
            'Usage: dpkg-split [<option> ...] <command>\n'
            '\n'
            'Commands:\n'
            '  -s|--split <file> [<prefix>]     Split an archive.\n'
            '  -j|--join <part> <part> ...      Join parts together.\n'
            '  -I|--info <part> ...             Display info about a part.\n'
            '  -a|--auto -o <complete> <part>   Auto-accumulate parts.\n'
            '  -l|--listq                       List unmatched pieces.\n'
            '  -d|--discard [<filename> ...]    Discard unmatched pieces.\n'
            '\n'
            '  -?, --help                       Show this help message.\n'
            '      --version                    Show the version.\n'
            '\n'
            'Options:\n'
            '      --depotdir <directory>       Use <directory> instead of /var/lib/dpkg/parts.\n'
            '      --admindir <directory>       Use <directory> instead of /var/lib/dpkg.\n'
            '      --root <directory>           Use <directory> instead of /.\n'
            '  -S, --partsize <size>            In KiB, for -s (default is 450).\n'
            '  -o, --output <file>              Filename, for -j (default is\n'
            '                                     <package>_<version>_<arch>.deb).\n'
            '  -Q, --npquiet                    Be quiet when -a is not a part.\n'
            '      --msdos                      Generate 8.3 filenames.\n'
            '\n'
            'Exit status:\n'
            '  0 = ok\n'
            '  1 = with --auto, file is not a part\n'
            '  2 = trouble\n'
        ),
        (
            ''
        ), 0),
    'dpkg-statoverride': (
        (
            'Usage: dpkg-statoverride [<option> ...] <command>\n'
            '\n'
            'Commands:\n'
            '  --add <owner> <group> <mode> <path>\n'
            '                           add a new <path> entry into the database.\n'
            '  --remove <path>          remove <path> from the database.\n'
            '  --list [<glob-pattern>]  list current overrides in the database.\n'
            '\n'
            'Options:\n'
            '  --admindir <directory>   set the directory with the statoverride file.\n'
            '  --instdir <directory>    set the root directory, but not the admin dir.\n'
            '  --root <directory>       set the directory of the root filesystem.\n'
            '  --update                 immediately update <path> permissions.\n'
            '  --force                  deprecated alias for --force-all.\n'
            '  --force-<thing>[,...]    override problems (see --force-help).\n'
            '  --no-force-<thing>[,...] stop when problems encountered.\n'
            '  --refuse-<thing>[,...]   ditto.\n'
            '  --quiet                  quiet operation, minimal output.\n'
            '  --help                   show this help message.\n'
            '  --version                show the version.\n'
            '\n'
        ),
        (
            ''
        ), 0),
    'e2fsck': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘e2fsck’: No such file or directory\n'
        ), 127),
    'editor': (
        (
            'Usage: nano [OPTIONS] [[+LINE[,COLUMN]] FILE]...\n'
            '\n'
            'To place the cursor on a specific line of a file, put the line number with\n'
            "a '+' before the filename.  The column number can be added after a comma.\n"
            "When a filename is '-', nano reads data from standard input.\n"
            '\n'
            ' Option         Long option             Meaning\n'
            ' -A             --smarthome             Enable smart home key\n'
            ' -B             --backup                Save backups of existing files\n'
            ' -C <dir>       --backupdir=<dir>       Directory for saving unique backup files\n'
            ' -D             --boldtext              Use bold instead of reverse video text\n'
            ' -E             --tabstospaces          Convert typed tabs to spaces\n'
            ' -F             --multibuffer           Read a file into a new buffer by default\n'
            ' -G             --locking               Use (vim-style) lock files\n'
            ' -H             --historylog            Save & reload old search/replace strings\n'
            " -I             --ignorercfiles         Don't look at nanorc files\n"
            ' -J <number>    --guidestripe=<number>  Show a guiding bar at this column\n'
            ' -K             --rawsequences          Fix numeric keypad key confusion problem\n'
            " -L             --nonewlines            Don't add an automatic newline\n"
            ' -M             --trimblanks            Trim tail spaces when hard-wrapping\n'
            " -N             --noconvert             Don't convert files from DOS/Mac format\n"
            ' -O             --bookstyle             Leading whitespace means new paragraph\n'
            ' -P             --positionlog           Save & restore position of the cursor\n'
            ' -Q <regex>     --quotestr=<regex>      Regular expression to match quoting\n'
            ' -R             --restricted            Restrict access to the filesystem\n'
            ' -S             --softwrap              Display overlong lines on multiple rows\n'
            ' -T <number>    --tabsize=<number>      Make a tab this number of columns wide\n'
            ' -U             --quickblank            Wipe status bar upon next keystroke\n'
            ' -V             --version               Print version information and exit\n'
            ' -W             --wordbounds            Detect word boundaries more accurately\n'
            ' -X <string>    --wordchars=<string>    Which other characters are word parts\n'
            ' -Y <name>      --syntax=<name>         Syntax definition to use for coloring\n'
            ' -Z             --zap                   Let Bsp and Del erase a marked region\n'
            ' -a             --atblanks              When soft-wrapping, do it at whitespace\n'
            ' -b             --breaklonglines        Automatically hard-wrap overlong lines\n'
            ' -c             --constantshow          Constantly show cursor position\n'
            ' -d             --rebinddelete          Fix Backspace/Delete confusion problem\n'
            ' -e             --emptyline             Keep the line below the title bar empty\n'
            ' -f <file>      --rcfile=<file>         Use only this file for configuring nano\n'
            ' -g             --showcursor            Show cursor in file browser & help text\n'
            ' -h             --help                  Show this help text and exit\n'
            ' -i             --autoindent            Automatically indent new lines\n'
            ' -j             --jumpyscrolling        Scroll per half-screen, not per line\n'
            ' -k             --cutfromcursor         Cut from cursor to end of line\n'
            ' -l             --linenumbers           Show line numbers in front of the text\n'
            ' -m             --mouse                 Enable the use of the mouse\n'
            ' -n             --noread                Do not read the file (only write it)\n'
            ' -o <dir>       --operatingdir=<dir>    Set operating directory\n'
            ' -p             --preserve              Preserve XON (^Q) and XOFF (^S) keys\n'
            ' -q             --indicator             Show a position+portion indicator\n'
            ' -r <number>    --fill=<number>         Set width for hard-wrap and justify\n'
            ' -s <program>   --speller=<program>     Use this alternative spell checker\n'
            " -t             --saveonexit            Save changes on exit, don't prompt\n"
            ' -u             --unix                  Save a file by default in Unix format\n'
            ' -v             --view                  View mode (read-only)\n'
            " -w             --nowrap                Don't hard-wrap long lines [default]\n"
            " -x             --nohelp                Don't show the two help lines\n"
            ' -y             --afterends             Make Ctrl+Right stop at word ends\n'
            ' -z             --listsyntaxes          List the names of available syntaxes\n'
            " -@             --colonparsing          Accept 'filename:linenumber' notation\n"
            ' -%             --stateflags            Show some states on the title bar\n'
            ' -_             --minibar               Show a feedback bar at the bottom\n'
            ' -0             --zero                  Hide all bars, use whole terminal\n'
            ' -/             --modernbindings        Use better-known key bindings\n'
        ),
        (
            ''
        ), 0),
    'faillock': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘faillock’: No such file or directory\n'
        ), 127),
    'fstab-decode': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘fstab-decode’: No such file or directory\n'
        ), 127),
    'gzexe': (
        (
            'Usage: /usr/bin/gzexe [OPTION] FILE...\n'
            'Replace each executable FILE with a compressed version of itself.\n'
            'Make a backup FILE~ of the old version of FILE.\n'
            '\n'
            '  -d             Decompress each FILE instead of compressing it.\n'
            '      --help     display this help and exit\n'
            '      --version  output version information and exit\n'
            '\n'
            'Report bugs to <bug-gzip@gnu.org>.\n'
        ),
        (
            ''
        ), 0),
    'invoke-rc.d': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘invoke-rc.d’: No such file or directory\n'
        ), 127),
    'ip6tables-restore': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘ip6tables-restore’: No such file or directory\n'
        ), 127),
    'iptables-restore': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘iptables-restore’: No such file or directory\n'
        ), 127),
    'ischroot': (
        (
            'Usage: ischroot [OPTION]\n'
            '  -f, --default-false return false if detection fails\n'
            '  -t, --default-true  return true if detection fails\n'
            '  -V, --version       output version information and exit.\n'
            '  -h, --help          display this help and exit.\n'
        ),
        (
            ''
        ), 0),
    'less': (
        (
            '\n'
            '                   S\x08SU\x08UM\x08MM\x08MA\x08AR\x08RY\x08Y O\x08OF\x08F L\x08LE\x08ES\x08SS\x08S C\x08CO\x08OM\x08MM\x08MA\x08AN\x08ND\x08DS\x08S\n'
            '\n'
            '      Commands marked with * may be preceded by a number, _\x08N.\n'
            '      Notes in parentheses indicate the behavior if _\x08N is given.\n'
            '      A key preceded by a caret indicates the Ctrl key; thus ^K is ctrl-K.\n'
            '\n'
            '  h  H                 Display this help.\n'
            '  q  :q  Q  :Q  ZZ     Exit.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                           M\x08MO\x08OV\x08VI\x08IN\x08NG\x08G\n'
            '\n'
            '  e  ^E  j  ^N  CR  *  Forward  one line   (or _\x08N lines).\n'
            '  y  ^Y  k  ^K  ^P  *  Backward one line   (or _\x08N lines).\n'
            '  f  ^F  ^V  SPACE  *  Forward  one window (or _\x08N lines).\n'
            '  b  ^B  ESC-v      *  Backward one window (or _\x08N lines).\n'
            '  z                 *  Forward  one window (and set window to _\x08N).\n'
            '  w                 *  Backward one window (and set window to _\x08N).\n'
            "  ESC-SPACE         *  Forward  one window, but don't stop at end-of-file.\n"
            '  d  ^D             *  Forward  one half-window (and set half-window to _\x08N).\n'
            '  u  ^U             *  Backward one half-window (and set half-window to _\x08N).\n'
            '  ESC-)  RightArrow *  Right one half screen width (or _\x08N positions).\n'
            '  ESC-(  LeftArrow  *  Left  one half screen width (or _\x08N positions).\n'
            '  ESC-}  ^RightArrow   Right to last column displayed.\n'
            '  ESC-{  ^LeftArrow    Left  to first column.\n'
            '  F                    Forward forever; like "tail -f".\n'
            '  ESC-F                Like F but stop when search pattern is found.\n'
            '  r  ^R  ^L            Repaint screen.\n'
            '  R                    Repaint screen, discarding buffered input.\n'
            '        ---------------------------------------------------\n'
            '        Default "window" is the screen height.\n'
            '        Default "half-window" is half of the screen height.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                          S\x08SE\x08EA\x08AR\x08RC\x08CH\x08HI\x08IN\x08NG\x08G\n'
            '\n'
            '  /_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n          *  Search forward for (_\x08N-th) matching line.\n'
            '  ?_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n          *  Search backward for (_\x08N-th) matching line.\n'
            '  n                 *  Repeat previous search (for _\x08N-th occurrence).\n'
            '  N                 *  Repeat previous search in reverse direction.\n'
            '  ESC-n             *  Repeat previous search, spanning files.\n'
            '  ESC-N             *  Repeat previous search, reverse dir. & spanning files.\n'
            '  ^O^N  ^On         *  Search forward for (_\x08N-th) OSC8 hyperlink.\n'
            '  ^O^P  ^Op         *  Search backward for (_\x08N-th) OSC8 hyperlink.\n'
            '  ^O^L  ^Ol            Jump to the currently selected OSC8 hyperlink.\n'
            '  ESC-u                Undo (toggle) search highlighting.\n'
            '  ESC-U                Clear search highlighting.\n'
            '  &_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n          *  Display only matching lines.\n'
            '        ---------------------------------------------------\n'
            '        A search pattern may begin with one or more of:\n'
            '        ^N or !  Search for NON-matching lines.\n'
            '        ^E or *  Search multiple files (pass thru END OF FILE).\n'
            '        ^F or @  Start search at FIRST file (for /) or last file (for ?).\n'
            "        ^K       Highlight matches, but don't move (KEEP position).\n"
            "        ^R       Don't use REGULAR EXPRESSIONS.\n"
            '        ^S _\x08n     Search for match in _\x08n-th parenthesized subpattern.\n'
            '        ^W       WRAP search if no match found.\n'
            '        ^L       Enter next character literally into pattern.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                           J\x08JU\x08UM\x08MP\x08PI\x08IN\x08NG\x08G\n'
            '\n'
            '  g  <  ESC-<       *  Go to first line in file (or line _\x08N).\n'
            '  G  >  ESC->       *  Go to last line in file (or line _\x08N).\n'
            '  p  %              *  Go to beginning of file (or _\x08N percent into file).\n'
            '  t                 *  Go to the (_\x08N-th) next tag.\n'
            '  T                 *  Go to the (_\x08N-th) previous tag.\n'
            '  {  (  [           *  Find close bracket } ) ].\n'
            '  }  )  ]           *  Find open bracket { ( [.\n'
            '  ESC-^F _\x08<_\x08c_\x081_\x08> _\x08<_\x08c_\x082_\x08>  *  Find close bracket _\x08<_\x08c_\x082_\x08>.\n'
            '  ESC-^B _\x08<_\x08c_\x081_\x08> _\x08<_\x08c_\x082_\x08>  *  Find open bracket _\x08<_\x08c_\x081_\x08>.\n'
            '        ---------------------------------------------------\n'
            '        Each "find close bracket" command goes forward to the close bracket \n'
            '          matching the (_\x08N-th) open bracket in the top line.\n'
            '        Each "find open bracket" command goes backward to the open bracket \n'
            '          matching the (_\x08N-th) close bracket in the bottom line.\n'
            '\n'
            '  m_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>            Mark the current top line with <letter>.\n'
            '  M_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>            Mark the current bottom line with <letter>.\n'
            "  '_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>            Go to a previously marked position.\n"
            "  ''                   Go to the previous position.\n"
            "  ^X^X                 Same as '.\n"
            '  ESC-m_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>        Clear a mark.\n'
            '        ---------------------------------------------------\n'
            '        A mark is any upper-case or lower-case letter.\n'
            '        Certain marks are predefined:\n'
            '             ^  means  beginning of the file\n'
            '             $  means  end of the file\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                        C\x08CH\x08HA\x08AN\x08NG\x08GI\x08IN\x08NG\x08G F\x08FI\x08IL\x08LE\x08ES\x08S\n'
            '\n'
            '  :e [_\x08f_\x08i_\x08l_\x08e]            Examine a new file.\n'
            '  ^X^V                 Same as :e.\n'
            '  :n                *  Examine the (_\x08N-th) next file from the command line.\n'
            '  :p                *  Examine the (_\x08N-th) previous file from the command line.\n'
            '  :x                *  Examine the first (or _\x08N-th) file from the command line.\n'
            '  ^O^O                 Open the currently selected OSC8 hyperlink.\n'
            '  :d                   Delete the current file from the command line list.\n'
            '  =  ^G  :f            Print current file name.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                    M\x08MI\x08IS\x08SC\x08CE\x08EL\x08LL\x08LA\x08AN\x08NE\x08EO\x08OU\x08US\x08S C\x08CO\x08OM\x08MM\x08MA\x08AN\x08ND\x08DS\x08S\n'
            '\n'
            '  -_\x08<_\x08f_\x08l_\x08a_\x08g_\x08>              Toggle a command line option [see OPTIONS below].\n'
            '  --_\x08<_\x08n_\x08a_\x08m_\x08e_\x08>             Toggle a command line option, by name.\n'
            '  __\x08<_\x08f_\x08l_\x08a_\x08g_\x08>              Display the setting of a command line option.\n'
            '  ___\x08<_\x08n_\x08a_\x08m_\x08e_\x08>             Display the setting of an option, by name.\n'
            '  +_\x08c_\x08m_\x08d                 Execute the less cmd each time a new file is examined.\n'
            '\n'
            '  !_\x08c_\x08o_\x08m_\x08m_\x08a_\x08n_\x08d             Execute the shell command with $SHELL.\n'
            '  #_\x08c_\x08o_\x08m_\x08m_\x08a_\x08n_\x08d             Execute the shell command, expanded like a prompt.\n'
            '  |X\x08X_\x08c_\x08o_\x08m_\x08m_\x08a_\x08n_\x08d            Pipe file between current pos & mark X\x08X to shell command.\n'
            '  s _\x08f_\x08i_\x08l_\x08e               Save input to a file.\n'
            '  v                    Edit the current file with $VISUAL or $EDITOR.\n'
            '  V                    Print version number of "less".\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                           O\x08OP\x08PT\x08TI\x08IO\x08ON\x08NS\x08S\n'
            '\n'
            '        Most options may be changed either on the command line,\n'
            '        or from within less by using the - or -- command.\n'
            '        Options may be given in one of two forms: either a single\n'
            '        character preceded by a -, or a name preceded by --.\n'
            '\n'
            '  -?  ........  --help\n'
            '                  Display help (from command line).\n'
            '  -a  ........  --search-skip-screen\n'
            '                  Search skips current screen.\n'
            '  -A  ........  --SEARCH-SKIP-SCREEN\n'
            '                  Search starts just after target line.\n'
            '  -b [_\x08N]  ....  --buffers=[_\x08N]\n'
            '                  Number of buffers.\n'
            '  -B  ........  --auto-buffers\n'
            "                  Don't automatically allocate buffers for pipes.\n"
            '  -c  ........  --clear-screen\n'
            '                  Repaint by clearing rather than scrolling.\n'
            '  -d  ........  --dumb\n'
            '                  Dumb terminal.\n'
            '  -D x\x08x_\x08c_\x08o_\x08l_\x08o_\x08r  .  --color=x\x08x_\x08c_\x08o_\x08l_\x08o_\x08r\n'
            '                  Set screen colors.\n'
            '  -e  -E  ....  --quit-at-eof  --QUIT-AT-EOF\n'
            '                  Quit at end of file.\n'
            '  -f  ........  --force\n'
            '                  Force open non-regular files.\n'
            '  -F  ........  --quit-if-one-screen\n'
            '                  Quit if entire file fits on first screen.\n'
            '  -g  ........  --hilite-search\n'
            '                  Highlight only last match for searches.\n'
            '  -G  ........  --HILITE-SEARCH\n'
            "                  Don't highlight any matches for searches.\n"
            '  -h [_\x08N]  ....  --max-back-scroll=[_\x08N]\n'
            '                  Backward scroll limit.\n'
            '  -i  ........  --ignore-case\n'
            '                  Ignore case in searches that do not contain uppercase.\n'
            '  -I  ........  --IGNORE-CASE\n'
            '                  Ignore case in all searches.\n'
            '  -j [_\x08N]  ....  --jump-target=[_\x08N]\n'
            '                  Screen position of target lines.\n'
            '  -J  ........  --status-column\n'
            '                  Display a status column at left edge of screen.\n'
            '  -k _\x08f_\x08i_\x08l_\x08e  ...  --lesskey-file=_\x08f_\x08i_\x08l_\x08e\n'
            '                  Use a compiled lesskey file.\n'
            '  -K  ........  --quit-on-intr\n'
            '                  Exit less in response to ctrl-C.\n'
            '  -L  ........  --no-lessopen\n'
            '                  Ignore the LESSOPEN environment variable.\n'
            '  -m  -M  ....  --long-prompt  --LONG-PROMPT\n'
            '                  Set prompt style.\n'
            '  -n .........  --line-numbers\n'
            '                  Suppress line numbers in prompts and messages.\n'
            '  -N .........  --LINE-NUMBERS\n'
            '                  Display line number at start of each line.\n'
            '  -o [_\x08f_\x08i_\x08l_\x08e] ..  --log-file=[_\x08f_\x08i_\x08l_\x08e]\n'
            '                  Copy to log file (standard input only).\n'
            '  -O [_\x08f_\x08i_\x08l_\x08e] ..  --LOG-FILE=[_\x08f_\x08i_\x08l_\x08e]\n'
            '                  Copy to log file (unconditionally overwrite).\n'
            '  -p _\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n .  --pattern=[_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n]\n'
            '                  Start at pattern (from command line).\n'
            '  -P [_\x08p_\x08r_\x08o_\x08m_\x08p_\x08t]   --prompt=[_\x08p_\x08r_\x08o_\x08m_\x08p_\x08t]\n'
            '                  Define new prompt.\n'
            '  -q  -Q  ....  --quiet  --QUIET  --silent --SILENT\n'
            '                  Quiet the terminal bell.\n'
            '  -r  -R  ....  --raw-control-chars  --RAW-CONTROL-CHARS\n'
            '                  Output "raw" control characters.\n'
            '  -s  ........  --squeeze-blank-lines\n'
            '                  Squeeze multiple blank lines.\n'
            '  -S  ........  --chop-long-lines\n'
            '                  Chop (truncate) long lines rather than wrapping.\n'
            '  -t _\x08t_\x08a_\x08g  ....  --tag=[_\x08t_\x08a_\x08g]\n'
            '                  Find a tag.\n'
            '  -T [_\x08t_\x08a_\x08g_\x08s_\x08f_\x08i_\x08l_\x08e] --tag-file=[_\x08t_\x08a_\x08g_\x08s_\x08f_\x08i_\x08l_\x08e]\n'
            '                  Use an alternate tags file.\n'
            '  -u  -U  ....  --underline-special  --UNDERLINE-SPECIAL\n'
            '                  Change handling of backspaces, tabs and carriage returns.\n'
            '  -V  ........  --version\n'
            '                  Display the version number of "less".\n'
            '  -w  ........  --hilite-unread\n'
            '                  Highlight first new line after forward-screen.\n'
            '  -W  ........  --HILITE-UNREAD\n'
            '                  Highlight first new line after any forward movement.\n'
            '  -x [_\x08N[,...]]  --tabs=[_\x08N[,...]]\n'
            '                  Set tab stops.\n'
            '  -X  ........  --no-init\n'
            "                  Don't use termcap init/deinit strings.\n"
            '  -y [_\x08N]  ....  --max-forw-scroll=[_\x08N]\n'
            '                  Forward scroll limit.\n'
            '  -z [_\x08N]  ....  --window=[_\x08N]\n'
            '                  Set size of window.\n'
            '  -" [_\x08c[_\x08c]]  .  --quotes=[_\x08c[_\x08c]]\n'
            '                  Set shell quote characters.\n'
            '  -~  ........  --tilde\n'
            "                  Don't display tildes after end of file.\n"
            '  -# [_\x08N]  ....  --shift=[_\x08N]\n'
            '                  Set horizontal scroll amount (0 = one half screen width).\n'
            '\n'
            '                --exit-follow-on-close\n'
            '                  Exit F command on a pipe when writer closes pipe.\n'
            '                --file-size\n'
            '                  Automatically determine the size of the input file.\n'
            '                --follow-name\n'
            '                  The F command changes files if the input file is renamed.\n'
            '                --header=[_\x08L[,_\x08C[,_\x08N]]]\n'
            '                  Use _\x08L lines (starting at line _\x08N) and _\x08C columns as headers.\n'
            '                --incsearch\n'
            '                  Search file as each pattern character is typed in.\n'
            '                --intr=[_\x08C]\n'
            '                  Use _\x08C instead of ^X to interrupt a read.\n'
            '                --lesskey-context=_\x08t_\x08e_\x08x_\x08t\n'
            '                  Use lesskey source file contents.\n'
            '                --lesskey-src=_\x08f_\x08i_\x08l_\x08e\n'
            '                  Use a lesskey source file.\n'
            '                --line-num-width=[_\x08N]\n'
            '                  Set the width of the -N line number field to _\x08N characters.\n'
            '                --match-shift=[_\x08N]\n'
            '                  Show at least _\x08N characters to the left of a search match.\n'
            '                --modelines=[_\x08N]\n'
            '                  Read _\x08N lines from the input file and look for vim modelines.\n'
            '                --mouse\n'
            '                  Enable mouse input.\n'
            '                --no-keypad\n'
            "                  Don't send termcap keypad init/deinit strings.\n"
            '                --no-histdups\n'
            '                  Remove duplicates from command history.\n'
            '                --no-number-headers\n'
            "                  Don't give line numbers to header lines.\n"
            '                --no-search-header-lines\n'
            '                  Searches do not include header lines.\n'
            '                --no-search-header-columns\n'
            '                  Searches do not include header columns.\n'
            '                --no-search-headers\n'
            '                  Searches do not include header lines or columns.\n'
            '                --no-vbell\n'
            "                  Disable the terminal's visual bell.\n"
            '                --redraw-on-quit\n'
            '                  Redraw final screen when quitting.\n'
            '                --rscroll=[_\x08C]\n'
            '                  Set the character used to mark truncated lines.\n'
            '                --save-marks\n'
            '                  Retain marks across invocations of less.\n'
            '                --search-options=[EFKNRW-]\n'
            '                  Set default options for every search.\n'
            '                --show-preproc-errors\n'
            '                  Display a message if preprocessor exits with an error status.\n'
            '                --proc-backspace\n'
            '                  Process backspaces for bold/underline.\n'
            '                --PROC-BACKSPACE\n'
            '                  Treat backspaces as control characters.\n'
            '                --proc-return\n'
            '                  Delete carriage returns before newline.\n'
            '                --PROC-RETURN\n'
            '                  Treat carriage returns as control characters.\n'
            '                --proc-tab\n'
            '                  Expand tabs to spaces.\n'
            '                --PROC-TAB\n'
            '                  Treat tabs as control characters.\n'
            '                --status-col-width=[_\x08N]\n'
            '                  Set the width of the -J status column to _\x08N characters.\n'
            '                --status-line\n'
            '                  Highlight or color the entire line containing a mark.\n'
            '                --use-backslash\n'
            '                  Subsequent options use backslash as escape char.\n'
            '                --use-color\n'
            '                  Enables colored text.\n'
            '                --wheel-lines=[_\x08N]\n'
            '                  Each click of the mouse wheel moves _\x08N lines.\n'
            '                --wordwrap\n'
            '                  Wrap lines at spaces.\n'
            '\n'
            '\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                          L\x08LI\x08IN\x08NE\x08E E\x08ED\x08DI\x08IT\x08TI\x08IN\x08NG\x08G\n'
            '\n'
            '        These keys can be used to edit text being entered \n'
            '        on the "command line" at the bottom of the screen.\n'
            '\n'
            ' RightArrow ..................... ESC-l ... Move cursor right one character.\n'
            ' LeftArrow ...................... ESC-h ... Move cursor left one character.\n'
            ' ctrl-RightArrow  ESC-RightArrow  ESC-w ... Move cursor right one word.\n'
            ' ctrl-LeftArrow   ESC-LeftArrow   ESC-b ... Move cursor left one word.\n'
            ' HOME ........................... ESC-0 ... Move cursor to start of line.\n'
            ' END ............................ ESC-$ ... Move cursor to end of line.\n'
            ' BACKSPACE ................................ Delete char to left of cursor.\n'
            ' DELETE ......................... ESC-x ... Delete char under cursor.\n'
            ' ctrl-BACKSPACE   ESC-BACKSPACE ........... Delete word to left of cursor.\n'
            ' ctrl-DELETE .... ESC-DELETE .... ESC-X ... Delete word under cursor.\n'
            ' ctrl-U ......... ESC (MS-DOS only) ....... Delete entire line.\n'
            ' UpArrow ........................ ESC-k ... Retrieve previous command line.\n'
            ' DownArrow ...................... ESC-j ... Retrieve next command line.\n'
            ' TAB ...................................... Complete filename & cycle.\n'
            ' SHIFT-TAB ...................... ESC-TAB   Complete filename & reverse cycle.\n'
            ' ctrl-L ................................... Complete filename, list all.\n'
        ),
        (
            ''
        ), 0),
    'lessecho': (
        (
            ''
        ),
        (
            'usage: lessecho [-ox] [-cx] [-pn] [-dn] [-mx] [-nn] [-ex] [-fn] [-a] file ...\n'
        ), 0),
    'lesskey': (
        (
            ''
        ),
        (
            'usage: lesskey [-o output] [input]\n'
        ), 1),
    'lesspipe': (
        (
            ''
        ),
        (
            ''
        ), 0),
    'lexgrog': (
        (
            'Usage: lexgrog [OPTION...] FILE...\n'
            '\n'
            '  -d, --debug                emit debugging messages\n'
            '  -c, --cat                  parse as cat page\n'
            '  -m, --man                  parse as man page\n'
            '  -f, --filters              show guessed series of preprocessing filters\n'
            '  -w, --whatis               show whatis information\n'
            '  -E, --encoding=ENCODING    use selected output encoding\n'
            '  -?, --help                 give this help list\n'
            '      --usage                give a short usage message\n'
            '  -V, --version              print program version\n'
            '\n'
            'Mandatory or optional arguments to long options are also mandatory or optional\n'
            'for any corresponding short options.\n'
            '\n'
            'The defaults are --man and --whatis.\n'
            '\n'
            'Report bugs to cjwatson@debian.org.\n'
        ),
        (
            ''
        ), 0),
    'localedef': (
        (
            'Usage: localedef [OPTION...] NAME\n'
            '  or:  localedef [OPTION...] [--add-to-archive|--delete-from-archive] FILE...\n'
            '  or:  localedef [OPTION...] --list-archive [FILE]\n'
            'Compile locale specification\n'
            '\n'
            ' Input Files:\n'
            '  -f, --charmap=FILE         Symbolic character names defined in FILE\n'
            '  -i, --inputfile=FILE       Source definitions are found in FILE\n'
            '  -u, --repertoire-map=FILE  FILE contains mapping from symbolic names to UCS4\n'
            '                             values\n'
            '\n'
            ' Output control:\n'
            '  -c, --force                Create output even if warning messages were issued\n'
            '                            \n'
            '      --no-hard-links        Do not create hard links between installed\n'
            '                             locales\n'
            '      --no-warnings=<warnings>   Comma-separated list of warnings to disable;\n'
            '                             supported warnings are: ascii, intcurrsym\n'
            '      --posix                Strictly conform to POSIX\n'
            '      --prefix=PATH          Optional output file prefix\n'
            '      --quiet                Suppress warnings and information messages\n'
            '  -v, --verbose              Print more messages\n'
            '      --warnings=<warnings>  Comma-separated list of warnings to enable;\n'
            '                             supported warnings are: ascii, intcurrsym\n'
            '\n'
            ' Archive control:\n'
            '      --add-to-archive       Add locales named by parameters to archive\n'
            '  -A, --alias-file=FILE      locale.alias file to consult when making archive\n'
            '      --big-endian           Generate big-endian output\n'
            '      --delete-from-archive  Remove locales named by parameters from archive\n'
            '      --list-archive         List content of archive\n'
            '      --little-endian        Generate little-endian output\n'
            "      --no-archive           Don't add new data to archive\n"
            '      --replace              Replace existing archive content\n'
            '\n'
            '  -?, --help                 Give this help list\n'
            '      --usage                Give a short usage message\n'
            '  -V, --version              Print program version\n'
            '\n'
            'Mandatory or optional arguments to long options are also mandatory or optional\n'
            'for any corresponding short options.\n'
            '\n'
            "System's directory for character maps : /usr/share/i18n/charmaps\n"
            '\t\t       repertoire maps: /usr/share/i18n/repertoiremaps\n'
            '\t\t       locale path    : /usr/lib/locale:/usr/share/i18n\n'
            'For bug reporting instructions, please see:\n'
            '<http://www.debian.org/Bugs/>.\n'
        ),
        (
            ''
        ), 0),
    'login': (
        (
            '\n'
            'Usage:\n'
            ' login [-p] [-h <host>] [-H] [[-f] <username>]\n'
            '\n'
            'Begin a session on the system.\n'
            '\n'
            'Options:\n'
            ' -p             do not destroy the environment\n'
            ' -f             skip a login authentication\n'
            ' -h <host>      hostname to be used for utmp logging\n'
            ' -H             suppress hostname in the login prompt\n'
            '     --help     display this help\n'
            ' -V, --version  display version\n'
            '\n'
            'For more details see login(1).\n'
        ),
        (
            ''
        ), 0),
    'look': (
        (
            '\n'
            'Usage:\n'
            ' look [options] <string> [<file>...]\n'
            '\n'
            'Display lines beginning with a specified string.\n'
            '\n'
            'Options:\n'
            ' -a, --alternative        use the alternative dictionary\n'
            ' -d, --alphanum           compare only blanks and alphanumeric characters\n'
            ' -f, --ignore-case        ignore case differences when comparing\n'
            ' -t, --terminate <char>   define the string-termination character\n'
            '\n'
            ' -h, --help               display this help\n'
            ' -V, --version            display version\n'
            '\n'
            'For more details see look(1).\n'
        ),
        (
            ''
        ), 0),
    'man-recode': (
        (
            'Usage: man-recode [OPTION...]\n'
            '            -t CODE {--suffix SUFFIX | --in-place} FILENAME...\n'
            '\n'
            '  -d, --debug                emit debugging messages\n'
            '      --in-place             overwrite input files in place\n'
            '  -q, --quiet                produce fewer warnings\n'
            '      --suffix=SUFFIX        suffix to append to output file name\n'
            '  -t, --to-code=CODE         encoding for output\n'
            '  -?, --help                 give this help list\n'
            '      --usage                give a short usage message\n'
            '  -V, --version              print program version\n'
            '\n'
            'Mandatory or optional arguments to long options are also mandatory or optional\n'
            'for any corresponding short options.\n'
            '\n'
            'Report bugs to cjwatson@debian.org.\n'
        ),
        (
            ''
        ), 0),
    'mandb': (
        (
            'Usage: mandb [OPTION...] [MANPATH]\n'
            '\n'
            '  -c, --create               create dbs from scratch, rather than updating\n'
            '  -C, --config-file=FILE     use this user configuration file\n'
            '  -d, --debug                emit debugging messages\n'
            '  -f, --filename=FILENAME    update just the entry for this filename\n'
            "  -p, --no-purge             don't purge obsolete entries from the dbs\n"
            "  -q, --quiet                work quietly, except for 'bogus' warning\n"
            "  -s, --no-straycats         don't look for or add stray cats to the dbs\n"
            '  -t, --test                 check manual pages for correctness\n'
            '  -u, --user-db              produce user databases only\n'
            '  -?, --help                 give this help list\n'
            '      --usage                give a short usage message\n'
            '  -V, --version              print program version\n'
            '\n'
            'Mandatory or optional arguments to long options are also mandatory or optional\n'
            'for any corresponding short options.\n'
            '\n'
            'Report bugs to cjwatson@debian.org.\n'
        ),
        (
            ''
        ), 0),
    'mke2fs': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘mke2fs’: No such file or directory\n'
        ), 127),
    'mkhomedir_helper': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘mkhomedir_helper’: No such file or directory\n'
        ), 127),
    'nano': (
        (
            'Usage: nano [OPTIONS] [[+LINE[,COLUMN]] FILE]...\n'
            '\n'
            'To place the cursor on a specific line of a file, put the line number with\n'
            "a '+' before the filename.  The column number can be added after a comma.\n"
            "When a filename is '-', nano reads data from standard input.\n"
            '\n'
            ' Option         Long option             Meaning\n'
            ' -A             --smarthome             Enable smart home key\n'
            ' -B             --backup                Save backups of existing files\n'
            ' -C <dir>       --backupdir=<dir>       Directory for saving unique backup files\n'
            ' -D             --boldtext              Use bold instead of reverse video text\n'
            ' -E             --tabstospaces          Convert typed tabs to spaces\n'
            ' -F             --multibuffer           Read a file into a new buffer by default\n'
            ' -G             --locking               Use (vim-style) lock files\n'
            ' -H             --historylog            Save & reload old search/replace strings\n'
            " -I             --ignorercfiles         Don't look at nanorc files\n"
            ' -J <number>    --guidestripe=<number>  Show a guiding bar at this column\n'
            ' -K             --rawsequences          Fix numeric keypad key confusion problem\n'
            " -L             --nonewlines            Don't add an automatic newline\n"
            ' -M             --trimblanks            Trim tail spaces when hard-wrapping\n'
            " -N             --noconvert             Don't convert files from DOS/Mac format\n"
            ' -O             --bookstyle             Leading whitespace means new paragraph\n'
            ' -P             --positionlog           Save & restore position of the cursor\n'
            ' -Q <regex>     --quotestr=<regex>      Regular expression to match quoting\n'
            ' -R             --restricted            Restrict access to the filesystem\n'
            ' -S             --softwrap              Display overlong lines on multiple rows\n'
            ' -T <number>    --tabsize=<number>      Make a tab this number of columns wide\n'
            ' -U             --quickblank            Wipe status bar upon next keystroke\n'
            ' -V             --version               Print version information and exit\n'
            ' -W             --wordbounds            Detect word boundaries more accurately\n'
            ' -X <string>    --wordchars=<string>    Which other characters are word parts\n'
            ' -Y <name>      --syntax=<name>         Syntax definition to use for coloring\n'
            ' -Z             --zap                   Let Bsp and Del erase a marked region\n'
            ' -a             --atblanks              When soft-wrapping, do it at whitespace\n'
            ' -b             --breaklonglines        Automatically hard-wrap overlong lines\n'
            ' -c             --constantshow          Constantly show cursor position\n'
            ' -d             --rebinddelete          Fix Backspace/Delete confusion problem\n'
            ' -e             --emptyline             Keep the line below the title bar empty\n'
            ' -f <file>      --rcfile=<file>         Use only this file for configuring nano\n'
            ' -g             --showcursor            Show cursor in file browser & help text\n'
            ' -h             --help                  Show this help text and exit\n'
            ' -i             --autoindent            Automatically indent new lines\n'
            ' -j             --jumpyscrolling        Scroll per half-screen, not per line\n'
            ' -k             --cutfromcursor         Cut from cursor to end of line\n'
            ' -l             --linenumbers           Show line numbers in front of the text\n'
            ' -m             --mouse                 Enable the use of the mouse\n'
            ' -n             --noread                Do not read the file (only write it)\n'
            ' -o <dir>       --operatingdir=<dir>    Set operating directory\n'
            ' -p             --preserve              Preserve XON (^Q) and XOFF (^S) keys\n'
            ' -q             --indicator             Show a position+portion indicator\n'
            ' -r <number>    --fill=<number>         Set width for hard-wrap and justify\n'
            ' -s <program>   --speller=<program>     Use this alternative spell checker\n'
            " -t             --saveonexit            Save changes on exit, don't prompt\n"
            ' -u             --unix                  Save a file by default in Unix format\n'
            ' -v             --view                  View mode (read-only)\n'
            " -w             --nowrap                Don't hard-wrap long lines [default]\n"
            " -x             --nohelp                Don't show the two help lines\n"
            ' -y             --afterends             Make Ctrl+Right stop at word ends\n'
            ' -z             --listsyntaxes          List the names of available syntaxes\n'
            " -@             --colonparsing          Accept 'filename:linenumber' notation\n"
            ' -%             --stateflags            Show some states on the title bar\n'
            ' -_             --minibar               Show a feedback bar at the bottom\n'
            ' -0             --zero                  Hide all bars, use whole terminal\n'
            ' -/             --modernbindings        Use better-known key bindings\n'
        ),
        (
            ''
        ), 0),
    'networkctl': (
        (
            'networkctl [OPTIONS...] COMMAND\n'
            '\n'
            'Query and control the networking subsystem.\n'
            '\n'
            'Commands:\n'
            '  list [PATTERN...]      List links\n'
            '  status [PATTERN...]    Show link status\n'
            '  lldp [PATTERN...]      Show LLDP neighbors\n'
            '  label                  Show current address label entries in the kernel\n'
            '  delete DEVICES...      Delete virtual netdevs\n'
            '  up DEVICES...          Bring devices up\n'
            '  down DEVICES...        Bring devices down\n'
            '  renew DEVICES...       Renew dynamic configurations\n'
            '  forcerenew DEVICES...  Trigger DHCP reconfiguration of all connected clients\n'
            '  reconfigure DEVICES... Reconfigure interfaces\n'
            '  reload                 Reload .network and .netdev files\n'
            '  edit FILES|DEVICES...  Edit network configuration files\n'
            '  cat [FILES|DEVICES...] Show network configuration files\n'
            '  mask FILES...          Mask network configuration files\n'
            '  unmask FILES...        Unmask network configuration files\n'
            '  persistent-storage BOOL\n'
            '                         Notify systemd-networkd if persistent storage is ready\n'
            '\n'
            'Options:\n'
            '  -h --help              Show this help\n'
            '     --version           Show package version\n'
            '     --no-pager          Do not pipe output into a pager\n'
            '     --no-legend         Do not show the headers and footers\n'
            '     --no-ask-password   Do not prompt for password\n'
            '  -a --all               Show status for all links\n'
            '  -s --stats             Show detailed link statistics\n'
            '  -l --full              Do not ellipsize output\n'
            '  -n --lines=INTEGER     Number of journal entries to show\n'
            '     --json=pretty|short|off\n'
            '                         Generate JSON output\n'
            '     --no-reload         Do not reload systemd-networkd or systemd-udevd\n'
            '                         after editing network config\n'
            '     --drop-in=NAME      Edit specified drop-in instead of main config file\n'
            '     --runtime           Edit runtime config files\n'
            '     --stdin             Read new contents of edited file from stdin\n'
            '\n'
            'See the networkctl(1) man page for details.\n'
        ),
        (
            ''
        ), 0),
    'nstat': (
        (
            ''
        ),
        (
            'Usage: nstat [OPTION] [ PATTERN [ PATTERN ] ]\n'
            '   -h, --help          this message\n'
            '   -a, --ignore        ignore history\n'
            '   -d, --scan=SECS     sample every statistics every SECS\n'
            '   -j, --json          format output in JSON\n'
            '   -n, --nooutput      do history only\n'
            '   -p, --pretty        pretty print\n'
            '   -r, --reset         reset history\n'
            "   -s, --noupdate      don't update history\n"
            '   -t, --interval=SECS report average over the last SECS\n'
            '   -V, --version       output version information\n'
            '   -z, --zeros         show entries with zero activity\n'
        ), 255),
    'pager': (
        (
            '\n'
            '                   S\x08SU\x08UM\x08MM\x08MA\x08AR\x08RY\x08Y O\x08OF\x08F L\x08LE\x08ES\x08SS\x08S C\x08CO\x08OM\x08MM\x08MA\x08AN\x08ND\x08DS\x08S\n'
            '\n'
            '      Commands marked with * may be preceded by a number, _\x08N.\n'
            '      Notes in parentheses indicate the behavior if _\x08N is given.\n'
            '      A key preceded by a caret indicates the Ctrl key; thus ^K is ctrl-K.\n'
            '\n'
            '  h  H                 Display this help.\n'
            '  q  :q  Q  :Q  ZZ     Exit.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                           M\x08MO\x08OV\x08VI\x08IN\x08NG\x08G\n'
            '\n'
            '  e  ^E  j  ^N  CR  *  Forward  one line   (or _\x08N lines).\n'
            '  y  ^Y  k  ^K  ^P  *  Backward one line   (or _\x08N lines).\n'
            '  f  ^F  ^V  SPACE  *  Forward  one window (or _\x08N lines).\n'
            '  b  ^B  ESC-v      *  Backward one window (or _\x08N lines).\n'
            '  z                 *  Forward  one window (and set window to _\x08N).\n'
            '  w                 *  Backward one window (and set window to _\x08N).\n'
            "  ESC-SPACE         *  Forward  one window, but don't stop at end-of-file.\n"
            '  d  ^D             *  Forward  one half-window (and set half-window to _\x08N).\n'
            '  u  ^U             *  Backward one half-window (and set half-window to _\x08N).\n'
            '  ESC-)  RightArrow *  Right one half screen width (or _\x08N positions).\n'
            '  ESC-(  LeftArrow  *  Left  one half screen width (or _\x08N positions).\n'
            '  ESC-}  ^RightArrow   Right to last column displayed.\n'
            '  ESC-{  ^LeftArrow    Left  to first column.\n'
            '  F                    Forward forever; like "tail -f".\n'
            '  ESC-F                Like F but stop when search pattern is found.\n'
            '  r  ^R  ^L            Repaint screen.\n'
            '  R                    Repaint screen, discarding buffered input.\n'
            '        ---------------------------------------------------\n'
            '        Default "window" is the screen height.\n'
            '        Default "half-window" is half of the screen height.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                          S\x08SE\x08EA\x08AR\x08RC\x08CH\x08HI\x08IN\x08NG\x08G\n'
            '\n'
            '  /_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n          *  Search forward for (_\x08N-th) matching line.\n'
            '  ?_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n          *  Search backward for (_\x08N-th) matching line.\n'
            '  n                 *  Repeat previous search (for _\x08N-th occurrence).\n'
            '  N                 *  Repeat previous search in reverse direction.\n'
            '  ESC-n             *  Repeat previous search, spanning files.\n'
            '  ESC-N             *  Repeat previous search, reverse dir. & spanning files.\n'
            '  ^O^N  ^On         *  Search forward for (_\x08N-th) OSC8 hyperlink.\n'
            '  ^O^P  ^Op         *  Search backward for (_\x08N-th) OSC8 hyperlink.\n'
            '  ^O^L  ^Ol            Jump to the currently selected OSC8 hyperlink.\n'
            '  ESC-u                Undo (toggle) search highlighting.\n'
            '  ESC-U                Clear search highlighting.\n'
            '  &_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n          *  Display only matching lines.\n'
            '        ---------------------------------------------------\n'
            '        A search pattern may begin with one or more of:\n'
            '        ^N or !  Search for NON-matching lines.\n'
            '        ^E or *  Search multiple files (pass thru END OF FILE).\n'
            '        ^F or @  Start search at FIRST file (for /) or last file (for ?).\n'
            "        ^K       Highlight matches, but don't move (KEEP position).\n"
            "        ^R       Don't use REGULAR EXPRESSIONS.\n"
            '        ^S _\x08n     Search for match in _\x08n-th parenthesized subpattern.\n'
            '        ^W       WRAP search if no match found.\n'
            '        ^L       Enter next character literally into pattern.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                           J\x08JU\x08UM\x08MP\x08PI\x08IN\x08NG\x08G\n'
            '\n'
            '  g  <  ESC-<       *  Go to first line in file (or line _\x08N).\n'
            '  G  >  ESC->       *  Go to last line in file (or line _\x08N).\n'
            '  p  %              *  Go to beginning of file (or _\x08N percent into file).\n'
            '  t                 *  Go to the (_\x08N-th) next tag.\n'
            '  T                 *  Go to the (_\x08N-th) previous tag.\n'
            '  {  (  [           *  Find close bracket } ) ].\n'
            '  }  )  ]           *  Find open bracket { ( [.\n'
            '  ESC-^F _\x08<_\x08c_\x081_\x08> _\x08<_\x08c_\x082_\x08>  *  Find close bracket _\x08<_\x08c_\x082_\x08>.\n'
            '  ESC-^B _\x08<_\x08c_\x081_\x08> _\x08<_\x08c_\x082_\x08>  *  Find open bracket _\x08<_\x08c_\x081_\x08>.\n'
            '        ---------------------------------------------------\n'
            '        Each "find close bracket" command goes forward to the close bracket \n'
            '          matching the (_\x08N-th) open bracket in the top line.\n'
            '        Each "find open bracket" command goes backward to the open bracket \n'
            '          matching the (_\x08N-th) close bracket in the bottom line.\n'
            '\n'
            '  m_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>            Mark the current top line with <letter>.\n'
            '  M_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>            Mark the current bottom line with <letter>.\n'
            "  '_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>            Go to a previously marked position.\n"
            "  ''                   Go to the previous position.\n"
            "  ^X^X                 Same as '.\n"
            '  ESC-m_\x08<_\x08l_\x08e_\x08t_\x08t_\x08e_\x08r_\x08>        Clear a mark.\n'
            '        ---------------------------------------------------\n'
            '        A mark is any upper-case or lower-case letter.\n'
            '        Certain marks are predefined:\n'
            '             ^  means  beginning of the file\n'
            '             $  means  end of the file\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                        C\x08CH\x08HA\x08AN\x08NG\x08GI\x08IN\x08NG\x08G F\x08FI\x08IL\x08LE\x08ES\x08S\n'
            '\n'
            '  :e [_\x08f_\x08i_\x08l_\x08e]            Examine a new file.\n'
            '  ^X^V                 Same as :e.\n'
            '  :n                *  Examine the (_\x08N-th) next file from the command line.\n'
            '  :p                *  Examine the (_\x08N-th) previous file from the command line.\n'
            '  :x                *  Examine the first (or _\x08N-th) file from the command line.\n'
            '  ^O^O                 Open the currently selected OSC8 hyperlink.\n'
            '  :d                   Delete the current file from the command line list.\n'
            '  =  ^G  :f            Print current file name.\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                    M\x08MI\x08IS\x08SC\x08CE\x08EL\x08LL\x08LA\x08AN\x08NE\x08EO\x08OU\x08US\x08S C\x08CO\x08OM\x08MM\x08MA\x08AN\x08ND\x08DS\x08S\n'
            '\n'
            '  -_\x08<_\x08f_\x08l_\x08a_\x08g_\x08>              Toggle a command line option [see OPTIONS below].\n'
            '  --_\x08<_\x08n_\x08a_\x08m_\x08e_\x08>             Toggle a command line option, by name.\n'
            '  __\x08<_\x08f_\x08l_\x08a_\x08g_\x08>              Display the setting of a command line option.\n'
            '  ___\x08<_\x08n_\x08a_\x08m_\x08e_\x08>             Display the setting of an option, by name.\n'
            '  +_\x08c_\x08m_\x08d                 Execute the less cmd each time a new file is examined.\n'
            '\n'
            '  !_\x08c_\x08o_\x08m_\x08m_\x08a_\x08n_\x08d             Execute the shell command with $SHELL.\n'
            '  #_\x08c_\x08o_\x08m_\x08m_\x08a_\x08n_\x08d             Execute the shell command, expanded like a prompt.\n'
            '  |X\x08X_\x08c_\x08o_\x08m_\x08m_\x08a_\x08n_\x08d            Pipe file between current pos & mark X\x08X to shell command.\n'
            '  s _\x08f_\x08i_\x08l_\x08e               Save input to a file.\n'
            '  v                    Edit the current file with $VISUAL or $EDITOR.\n'
            '  V                    Print version number of "less".\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                           O\x08OP\x08PT\x08TI\x08IO\x08ON\x08NS\x08S\n'
            '\n'
            '        Most options may be changed either on the command line,\n'
            '        or from within less by using the - or -- command.\n'
            '        Options may be given in one of two forms: either a single\n'
            '        character preceded by a -, or a name preceded by --.\n'
            '\n'
            '  -?  ........  --help\n'
            '                  Display help (from command line).\n'
            '  -a  ........  --search-skip-screen\n'
            '                  Search skips current screen.\n'
            '  -A  ........  --SEARCH-SKIP-SCREEN\n'
            '                  Search starts just after target line.\n'
            '  -b [_\x08N]  ....  --buffers=[_\x08N]\n'
            '                  Number of buffers.\n'
            '  -B  ........  --auto-buffers\n'
            "                  Don't automatically allocate buffers for pipes.\n"
            '  -c  ........  --clear-screen\n'
            '                  Repaint by clearing rather than scrolling.\n'
            '  -d  ........  --dumb\n'
            '                  Dumb terminal.\n'
            '  -D x\x08x_\x08c_\x08o_\x08l_\x08o_\x08r  .  --color=x\x08x_\x08c_\x08o_\x08l_\x08o_\x08r\n'
            '                  Set screen colors.\n'
            '  -e  -E  ....  --quit-at-eof  --QUIT-AT-EOF\n'
            '                  Quit at end of file.\n'
            '  -f  ........  --force\n'
            '                  Force open non-regular files.\n'
            '  -F  ........  --quit-if-one-screen\n'
            '                  Quit if entire file fits on first screen.\n'
            '  -g  ........  --hilite-search\n'
            '                  Highlight only last match for searches.\n'
            '  -G  ........  --HILITE-SEARCH\n'
            "                  Don't highlight any matches for searches.\n"
            '  -h [_\x08N]  ....  --max-back-scroll=[_\x08N]\n'
            '                  Backward scroll limit.\n'
            '  -i  ........  --ignore-case\n'
            '                  Ignore case in searches that do not contain uppercase.\n'
            '  -I  ........  --IGNORE-CASE\n'
            '                  Ignore case in all searches.\n'
            '  -j [_\x08N]  ....  --jump-target=[_\x08N]\n'
            '                  Screen position of target lines.\n'
            '  -J  ........  --status-column\n'
            '                  Display a status column at left edge of screen.\n'
            '  -k _\x08f_\x08i_\x08l_\x08e  ...  --lesskey-file=_\x08f_\x08i_\x08l_\x08e\n'
            '                  Use a compiled lesskey file.\n'
            '  -K  ........  --quit-on-intr\n'
            '                  Exit less in response to ctrl-C.\n'
            '  -L  ........  --no-lessopen\n'
            '                  Ignore the LESSOPEN environment variable.\n'
            '  -m  -M  ....  --long-prompt  --LONG-PROMPT\n'
            '                  Set prompt style.\n'
            '  -n .........  --line-numbers\n'
            '                  Suppress line numbers in prompts and messages.\n'
            '  -N .........  --LINE-NUMBERS\n'
            '                  Display line number at start of each line.\n'
            '  -o [_\x08f_\x08i_\x08l_\x08e] ..  --log-file=[_\x08f_\x08i_\x08l_\x08e]\n'
            '                  Copy to log file (standard input only).\n'
            '  -O [_\x08f_\x08i_\x08l_\x08e] ..  --LOG-FILE=[_\x08f_\x08i_\x08l_\x08e]\n'
            '                  Copy to log file (unconditionally overwrite).\n'
            '  -p _\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n .  --pattern=[_\x08p_\x08a_\x08t_\x08t_\x08e_\x08r_\x08n]\n'
            '                  Start at pattern (from command line).\n'
            '  -P [_\x08p_\x08r_\x08o_\x08m_\x08p_\x08t]   --prompt=[_\x08p_\x08r_\x08o_\x08m_\x08p_\x08t]\n'
            '                  Define new prompt.\n'
            '  -q  -Q  ....  --quiet  --QUIET  --silent --SILENT\n'
            '                  Quiet the terminal bell.\n'
            '  -r  -R  ....  --raw-control-chars  --RAW-CONTROL-CHARS\n'
            '                  Output "raw" control characters.\n'
            '  -s  ........  --squeeze-blank-lines\n'
            '                  Squeeze multiple blank lines.\n'
            '  -S  ........  --chop-long-lines\n'
            '                  Chop (truncate) long lines rather than wrapping.\n'
            '  -t _\x08t_\x08a_\x08g  ....  --tag=[_\x08t_\x08a_\x08g]\n'
            '                  Find a tag.\n'
            '  -T [_\x08t_\x08a_\x08g_\x08s_\x08f_\x08i_\x08l_\x08e] --tag-file=[_\x08t_\x08a_\x08g_\x08s_\x08f_\x08i_\x08l_\x08e]\n'
            '                  Use an alternate tags file.\n'
            '  -u  -U  ....  --underline-special  --UNDERLINE-SPECIAL\n'
            '                  Change handling of backspaces, tabs and carriage returns.\n'
            '  -V  ........  --version\n'
            '                  Display the version number of "less".\n'
            '  -w  ........  --hilite-unread\n'
            '                  Highlight first new line after forward-screen.\n'
            '  -W  ........  --HILITE-UNREAD\n'
            '                  Highlight first new line after any forward movement.\n'
            '  -x [_\x08N[,...]]  --tabs=[_\x08N[,...]]\n'
            '                  Set tab stops.\n'
            '  -X  ........  --no-init\n'
            "                  Don't use termcap init/deinit strings.\n"
            '  -y [_\x08N]  ....  --max-forw-scroll=[_\x08N]\n'
            '                  Forward scroll limit.\n'
            '  -z [_\x08N]  ....  --window=[_\x08N]\n'
            '                  Set size of window.\n'
            '  -" [_\x08c[_\x08c]]  .  --quotes=[_\x08c[_\x08c]]\n'
            '                  Set shell quote characters.\n'
            '  -~  ........  --tilde\n'
            "                  Don't display tildes after end of file.\n"
            '  -# [_\x08N]  ....  --shift=[_\x08N]\n'
            '                  Set horizontal scroll amount (0 = one half screen width).\n'
            '\n'
            '                --exit-follow-on-close\n'
            '                  Exit F command on a pipe when writer closes pipe.\n'
            '                --file-size\n'
            '                  Automatically determine the size of the input file.\n'
            '                --follow-name\n'
            '                  The F command changes files if the input file is renamed.\n'
            '                --header=[_\x08L[,_\x08C[,_\x08N]]]\n'
            '                  Use _\x08L lines (starting at line _\x08N) and _\x08C columns as headers.\n'
            '                --incsearch\n'
            '                  Search file as each pattern character is typed in.\n'
            '                --intr=[_\x08C]\n'
            '                  Use _\x08C instead of ^X to interrupt a read.\n'
            '                --lesskey-context=_\x08t_\x08e_\x08x_\x08t\n'
            '                  Use lesskey source file contents.\n'
            '                --lesskey-src=_\x08f_\x08i_\x08l_\x08e\n'
            '                  Use a lesskey source file.\n'
            '                --line-num-width=[_\x08N]\n'
            '                  Set the width of the -N line number field to _\x08N characters.\n'
            '                --match-shift=[_\x08N]\n'
            '                  Show at least _\x08N characters to the left of a search match.\n'
            '                --modelines=[_\x08N]\n'
            '                  Read _\x08N lines from the input file and look for vim modelines.\n'
            '                --mouse\n'
            '                  Enable mouse input.\n'
            '                --no-keypad\n'
            "                  Don't send termcap keypad init/deinit strings.\n"
            '                --no-histdups\n'
            '                  Remove duplicates from command history.\n'
            '                --no-number-headers\n'
            "                  Don't give line numbers to header lines.\n"
            '                --no-search-header-lines\n'
            '                  Searches do not include header lines.\n'
            '                --no-search-header-columns\n'
            '                  Searches do not include header columns.\n'
            '                --no-search-headers\n'
            '                  Searches do not include header lines or columns.\n'
            '                --no-vbell\n'
            "                  Disable the terminal's visual bell.\n"
            '                --redraw-on-quit\n'
            '                  Redraw final screen when quitting.\n'
            '                --rscroll=[_\x08C]\n'
            '                  Set the character used to mark truncated lines.\n'
            '                --save-marks\n'
            '                  Retain marks across invocations of less.\n'
            '                --search-options=[EFKNRW-]\n'
            '                  Set default options for every search.\n'
            '                --show-preproc-errors\n'
            '                  Display a message if preprocessor exits with an error status.\n'
            '                --proc-backspace\n'
            '                  Process backspaces for bold/underline.\n'
            '                --PROC-BACKSPACE\n'
            '                  Treat backspaces as control characters.\n'
            '                --proc-return\n'
            '                  Delete carriage returns before newline.\n'
            '                --PROC-RETURN\n'
            '                  Treat carriage returns as control characters.\n'
            '                --proc-tab\n'
            '                  Expand tabs to spaces.\n'
            '                --PROC-TAB\n'
            '                  Treat tabs as control characters.\n'
            '                --status-col-width=[_\x08N]\n'
            '                  Set the width of the -J status column to _\x08N characters.\n'
            '                --status-line\n'
            '                  Highlight or color the entire line containing a mark.\n'
            '                --use-backslash\n'
            '                  Subsequent options use backslash as escape char.\n'
            '                --use-color\n'
            '                  Enables colored text.\n'
            '                --wheel-lines=[_\x08N]\n'
            '                  Each click of the mouse wheel moves _\x08N lines.\n'
            '                --wordwrap\n'
            '                  Wrap lines at spaces.\n'
            '\n'
            '\n'
            ' ---------------------------------------------------------------------------\n'
            '\n'
            '                          L\x08LI\x08IN\x08NE\x08E E\x08ED\x08DI\x08IT\x08TI\x08IN\x08NG\x08G\n'
            '\n'
            '        These keys can be used to edit text being entered \n'
            '        on the "command line" at the bottom of the screen.\n'
            '\n'
            ' RightArrow ..................... ESC-l ... Move cursor right one character.\n'
            ' LeftArrow ...................... ESC-h ... Move cursor left one character.\n'
            ' ctrl-RightArrow  ESC-RightArrow  ESC-w ... Move cursor right one word.\n'
            ' ctrl-LeftArrow   ESC-LeftArrow   ESC-b ... Move cursor left one word.\n'
            ' HOME ........................... ESC-0 ... Move cursor to start of line.\n'
            ' END ............................ ESC-$ ... Move cursor to end of line.\n'
            ' BACKSPACE ................................ Delete char to left of cursor.\n'
            ' DELETE ......................... ESC-x ... Delete char under cursor.\n'
            ' ctrl-BACKSPACE   ESC-BACKSPACE ........... Delete word to left of cursor.\n'
            ' ctrl-DELETE .... ESC-DELETE .... ESC-X ... Delete word under cursor.\n'
            ' ctrl-U ......... ESC (MS-DOS only) ....... Delete entire line.\n'
            ' UpArrow ........................ ESC-k ... Retrieve previous command line.\n'
            ' DownArrow ...................... ESC-j ... Retrieve next command line.\n'
            ' TAB ...................................... Complete filename & cycle.\n'
            ' SHIFT-TAB ...................... ESC-TAB   Complete filename & reverse cycle.\n'
            ' ctrl-L ................................... Complete filename, list all.\n'
        ),
        (
            ''
        ), 0),
    'pam_namespace_helper': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘pam_namespace_helper’: No such file or directory\n'
        ), 127),
    'pldd': (
        (
            'Usage: pldd [OPTION...] PID\n'
            'List dynamic shared objects loaded into process.\n'
            '\n'
            '  -?, --help                 Give this help list\n'
            '      --usage                Give a short usage message\n'
            '  -V, --version              Print program version\n'
            '\n'
            'For bug reporting instructions, please see:\n'
            '<http://www.debian.org/Bugs/>.\n'
        ),
        (
            ''
        ), 0),
    'pstree.x11': (
        (
            ''
        ),
        (
            "pstree.x11: unrecognized option '--help'\n"
            'Usage: pstree [-acglpsStTuZ] [ -h | -H PID ] [ -n | -N type ]\n'
            '              [ -A | -G | -U ] [ PID | USER ]\n'
            '   or: pstree -V\n'
            '\n'
            'Display a tree of processes.\n'
            '\n'
            '  -a, --arguments     show command line arguments\n'
            '  -A, --ascii         use ASCII line drawing characters\n'
            "  -c, --compact-not   don't compact identical subtrees\n"
            '  -C, --color=TYPE    color process by attribute\n'
            '                      (age)\n'
            '  -g, --show-pgids    show process group ids; implies -c\n'
            '  -G, --vt100         use VT100 line drawing characters\n'
            '  -h, --highlight-all highlight current process and its ancestors\n'
            '  -H PID, --highlight-pid=PID\n'
            '                      highlight this process and its ancestors\n'
            "  -l, --long          don't truncate long lines\n"
            '  -n, --numeric-sort  sort output by PID\n'
            '  -N TYPE, --ns-sort=TYPE\n'
            '                      sort output by this namespace type\n'
            '                              (cgroup, ipc, mnt, net, pid, time, user, uts)\n'
            '  -p, --show-pids     show PIDs; implies -c\n'
            '  -s, --show-parents  show parents of the selected process\n'
            '  -S, --ns-changes    show namespace transitions\n'
            '  -t, --thread-names  show full thread names\n'
            '  -T, --hide-threads  hide threads, show only processes\n'
            '  -u, --uid-changes   show uid transitions\n'
            '  -U, --unicode       use UTF-8 (Unicode) line drawing characters\n'
            '  -V, --version       display version information\n'
            '  -Z, --security-context\n'
            '                      show security attributes\n'
            '\n'
            '  PID    start at this PID; default is 1 (init)\n'
            '  USER   show only trees rooted at processes of this user\n'
            '\n'
        ), 1),
    'resize2fs': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘resize2fs’: No such file or directory\n'
        ), 127),
    'rgrep': (
        (
            'Usage: grep [OPTION]... PATTERNS [FILE]...\n'
            'Search for PATTERNS in each FILE.\n'
            "Example: grep -i 'hello world' menu.h main.c\n"
            'PATTERNS can contain multiple patterns separated by newlines.\n'
            '\n'
            'Pattern selection and interpretation:\n'
            '  -E, --extended-regexp     PATTERNS are extended regular expressions\n'
            '  -F, --fixed-strings       PATTERNS are strings\n'
            '  -G, --basic-regexp        PATTERNS are basic regular expressions\n'
            '  -P, --perl-regexp         PATTERNS are Perl regular expressions\n'
            '  -e, --regexp=PATTERNS     use PATTERNS for matching\n'
            '  -f, --file=FILE           take PATTERNS from FILE\n'
            '  -i, --ignore-case         ignore case distinctions in patterns and data\n'
            '      --no-ignore-case      do not ignore case distinctions (default)\n'
            '  -w, --word-regexp         match only whole words\n'
            '  -x, --line-regexp         match only whole lines\n'
            '  -z, --null-data           a data line ends in 0 byte, not newline\n'
            '\n'
            'Miscellaneous:\n'
            '  -s, --no-messages         suppress error messages\n'
            '  -v, --invert-match        select non-matching lines\n'
            '  -V, --version             display version information and exit\n'
            '      --help                display this help text and exit\n'
            '\n'
            'Output control:\n'
            '  -m, --max-count=NUM       stop after NUM selected lines\n'
            '  -b, --byte-offset         print the byte offset with output lines\n'
            '  -n, --line-number         print line number with output lines\n'
            '      --line-buffered       flush output on every line\n'
            '  -H, --with-filename       print file name with output lines\n'
            '  -h, --no-filename         suppress the file name prefix on output\n'
            '      --label=LABEL         use LABEL as the standard input file name prefix\n'
            '  -o, --only-matching       show only nonempty parts of lines that match\n'
            '  -q, --quiet, --silent     suppress all normal output\n'
            '      --binary-files=TYPE   assume that binary files are TYPE;\n'
            "                            TYPE is 'binary', 'text', or 'without-match'\n"
            '  -a, --text                equivalent to --binary-files=text\n'
            '  -I                        equivalent to --binary-files=without-match\n'
            '  -d, --directories=ACTION  how to handle directories;\n'
            "                            ACTION is 'read', 'recurse', or 'skip'\n"
            '  -D, --devices=ACTION      how to handle devices, FIFOs and sockets;\n'
            "                            ACTION is 'read' or 'skip'\n"
            '  -r, --recursive           like --directories=recurse\n'
            '  -R, --dereference-recursive  likewise, but follow all symlinks\n'
            '      --include=GLOB        search only files that match GLOB (a file pattern)\n'
            '      --exclude=GLOB        skip files that match GLOB\n'
            '      --exclude-from=FILE   skip files that match any file pattern from FILE\n'
            '      --exclude-dir=GLOB    skip directories that match GLOB\n'
            '  -L, --files-without-match  print only names of FILEs with no selected lines\n'
            '  -l, --files-with-matches  print only names of FILEs with selected lines\n'
            '  -c, --count               print only a count of selected lines per FILE\n'
            '  -T, --initial-tab         make tabs line up (if needed)\n'
            '  -Z, --null                print 0 byte after FILE name\n'
            '\n'
            'Context control:\n'
            '  -B, --before-context=NUM  print NUM lines of leading context\n'
            '  -A, --after-context=NUM   print NUM lines of trailing context\n'
            '  -C, --context=NUM         print NUM lines of output context\n'
            '  -NUM                      same as --context=NUM\n'
            '      --group-separator=SEP  print SEP on line between matches with context\n'
            '      --no-group-separator  do not print separator for matches with context\n'
            '      --color[=WHEN],\n'
            '      --colour[=WHEN]       use markers to highlight the matching strings;\n'
            "                            WHEN is 'always', 'never', or 'auto'\n"
            '  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)\n'
            '\n'
            "When FILE is '-', read standard input.  With no FILE, read '.' if\n"
            "recursive, '-' otherwise.  With fewer than two FILEs, assume -h.\n"
            'Exit status is 0 if any line is selected, 1 otherwise;\n'
            'if any error occurs and -q is not given, the exit status is 2.\n'
            '\n'
            'Report bugs to: bug-grep@gnu.org\n'
            'GNU grep home page: <https://www.gnu.org/software/grep/>\n'
            'General help using GNU software: <https://www.gnu.org/gethelp/>\n'
        ),
        (
            ''
        ), 0),
    'run-parts': (
        (
            'Usage: run-parts [OPTION]... DIRECTORY [DIRECTORY ...]\n'
            "      --test          print script names which would run, but don't run them.\n"
            '      --list          print names of all valid files (can not be used with\n'
            '                      --test)\n'
            '  -v, --verbose       print script names before running them.\n'
            '  -d, --debug         print script names while checking them.\n'
            '      --report        print script names if they produce output.\n'
            '      --reverse       reverse execution order of scripts.\n'
            '      --exit-on-error exit as soon as a script returns with a non-zero exit\n'
            '                      code.\n'
            '      --stdin         multiplex stdin to scripts being run, using temporary file\n'
            '      --lsbsysinit    validate filenames based on LSB sysinit specs.\n'
            '      --new-session   run each script in a separate process session\n'
            '      --regex=PATTERN validate filenames based on POSIX ERE pattern PATTERN.\n'
            '  -u, --umask=UMASK   sets umask to UMASK (octal), default is 022.\n'
            '  -a, --arg=ARGUMENT  pass ARGUMENT to scripts, use once for each argument.\n'
            '  -V, --version       output version information and exit.\n'
            '  -h, --help          display this help and exit.\n'
        ),
        (
            ''
        ), 0),
    'savelog': (
        (
            'Usage: savelog [-m mode] [-u user] [-g group] [-t] [-c cycle] [-p]\n'
            '             [-j] [-C] [-d] [-l] [-r rolldir] [-n] [-q] file ...\n'
            '\t-m mode\t   - chmod log files to mode\n'
            '\t-u user\t   - chown log files to user\n'
            '\t-g group   - chgrp log files to group\n'
            '\t-c cycle   - save cycle versions of the logfile (default: 7)\n'
            '\t-r rolldir - use rolldir instead of . to roll files\n'
            '\t-C\t   - force cleanup of cycled logfiles\n'
            '\t-d\t   - use standard date for rolling\n'
            '\t-D\t   - override date format for -d\n'
            '\t-t\t   - touch file\n'
            "\t-l\t   - don't compress any log files (default: compress)\n"
            '\t-p         - preserve mode/user/group of original file\n'
            '\t-j         - use bzip2 instead of gzip\n'
            '\t-J         - use xz instead of gzip\n'
            '\t-1 .. -9   - compression strength or memory usage (default: 9, except for xz)\n'
            '\t-x script  - invoke script with rotated log file in $FILE\n'
            '\t-n         - do not rotate empty files\n'
            '\t-q         - suppress rotation message\n'
            '\tfile \t   - log file names\n'
        ),
        (
            'Illegal option --\n'
        ), 1),
    'scriptlive': (
        (
            '\n'
            'Usage:\n'
            ' scriptlive [options] <timingfile> <typescript>\n'
            '\n'
            'Execute terminal typescript.\n'
            '\n'
            'Options:\n'
            ' -t, --timing <file>     script timing log file\n'
            ' -T, --log-timing <file> alias to -t\n'
            ' -I, --log-in <file>     script stdin log file\n'
            ' -B, --log-io <file>     script stdin and stdout log file\n'
            '\n'
            ' -c, --command <command> run command rather than interactive shell\n'
            ' -d, --divisor <num>     speed up or slow down execution with time divisor\n'
            ' -E, --echo <when>       echo input in session (auto, always or never)\n'
            ' -m, --maxdelay <num>    wait at most this many seconds between updates\n'
            '\n'
            ' -h, --help              display this help\n'
            ' -V, --version           display version\n'
            '\n'
            'For more details see scriptlive(1).\n'
        ),
        (
            ''
        ), 0),
    'scriptreplay': (
        (
            '\n'
            'Usage:\n'
            ' scriptreplay [options] <timingfile> [<typescript> [<divisor>]]\n'
            '\n'
            'Play back terminal typescripts, using timing information.\n'
            '\n'
            'Options:\n'
            ' -t, --timing <file>     script timing log file\n'
            ' -T, --log-timing <file> alias to -t\n'
            ' -I, --log-in <file>     script stdin log file\n'
            ' -O, --log-out <file>    script stdout log file (default)\n'
            ' -B, --log-io <file>     script stdin and stdout log file\n'
            '\n'
            ' -s, --typescript <file> deprecated alias to -O\n'
            '\n'
            '     --summary           display overview about recorded session and exit\n'
            ' -d, --divisor <num>     speed up or slow down execution with time divisor\n'
            ' -m, --maxdelay <num>    wait at most this many seconds between updates\n'
            ' -x, --stream <name>     stream type (out, in, signal or info)\n'
            ' -c, --cr-mode <type>    CR char mode (auto, never, always)\n'
            '\n'
            ' -h, --help              display this help\n'
            ' -V, --version           display version\n'
            '\n'
            'Key bindings:\n'
            ' space        toggles between pause and play\n'
            ' up-arrow     increases playback speed with ten percent\n'
            ' down-arrow   decreases playback speed with ten percent\n'
            '\n'
            'For more details see scriptreplay(1).\n'
        ),
        (
            ''
        ), 0),
    'sdiff': (
        (
            'Usage: sdiff [OPTION]... FILE1 FILE2\n'
            'Side-by-side merge of differences between FILE1 and FILE2.\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '  -o, --output=FILE            operate interactively, sending output to FILE\n'
            '\n'
            '  -i, --ignore-case            consider upper- and lower-case to be the same\n'
            '  -E, --ignore-tab-expansion   ignore changes due to tab expansion\n'
            '  -Z, --ignore-trailing-space  ignore white space at line end\n'
            '  -b, --ignore-space-change    ignore changes in the amount of white space\n'
            '  -W, --ignore-all-space       ignore all white space\n'
            '  -B, --ignore-blank-lines     ignore changes whose lines are all blank\n'
            '  -I, --ignore-matching-lines=RE  ignore changes all whose lines match RE\n'
            '      --strip-trailing-cr      strip trailing carriage return on input\n'
            '  -a, --text                   treat all files as text\n'
            '\n'
            '  -w, --width=NUM              output at most NUM (default 130) print columns\n'
            '  -l, --left-column            output only the left column of common lines\n'
            '  -s, --suppress-common-lines  do not output common lines\n'
            '\n'
            '  -t, --expand-tabs            expand tabs to spaces in output\n'
            '      --tabsize=NUM            tab stops at every NUM (default 8) print columns\n'
            '\n'
            '  -d, --minimal                try hard to find a smaller set of changes\n'
            '  -H, --speed-large-files      assume large files, many scattered small changes\n'
            '      --diff-program=PROGRAM   use PROGRAM to compare files\n'
            '\n'
            '      --help                   display this help and exit\n'
            '  -v, --version                output version information and exit\n'
            '\n'
            "If a FILE is '-', read standard input.\n"
            'Exit status is 0 if inputs are the same, 1 if different, 2 if trouble.\n'
            '\n'
            'Report bugs to: bug-diffutils@gnu.org\n'
            'GNU diffutils home page: <https://www.gnu.org/software/diffutils/>\n'
            'General help using GNU software: <https://www.gnu.org/gethelp/>\n'
        ),
        (
            ''
        ), 0),
    'setpci': (
        (
            ''
        ),
        (
            'Usage: setpci [<options>] (<device>+ <reg>[=<values>]*)*\n'
            '\n'
            'General options:\n'
            "-f\t\tDon't complain if there's nothing to do\n"
            '-v\t\tBe verbose\n'
            "-D\t\tList changes, don't commit them\n"
            '-r\t\tUse raw access without bus scan if possible\n'
            '--dumpregs\tDump all known register names and exit\n'
            '\n'
            'PCI access options:\n'
            "-A <method>\tUse the specified PCI access method (see `-A help' for a list)\n"
            "-O <par>=<val>\tSet PCI access parameter (see `-O help' for a list)\n"
            '-G\t\tEnable PCI access debugging\n'
            '-H <mode>\tUse direct hardware access (<mode> = 1 or 2)\n'
            '\n'
            'Setting commands:\n'
            '<device>:\t-s [[[<domain>]:][<bus>]:][<slot>][.[<func>]]\n'
            '\t\t-d [<vendor>]:[<device>]\n'
            '<reg>:\t\t<base>[+<offset>][.(B|W|L)][@<number>]\n'
            '<base>:\t\t<address>\n'
            '\t\t<named-register>\n'
            '\t\t[E]CAP_<capability-name>\n'
            '\t\t[E]CAP<capability-number>\n'
            '<values>:\t<value>[,<value>...]\n'
            '<value>:\t<hex>\n'
            '\t\t<hex>:<mask>\n'
        ), 0),
    'sfdisk': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘sfdisk’: No such file or directory\n'
        ), 127),
    'ssh-add': (
        (
            ''
        ),
        (
            'Could not open a connection to your authentication agent.\n'
        ), 2),
    'ssh-agent': (
        (
            ''
        ),
        (
            'unknown option -- -\n'
            'usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n'
            '                 [-O option] [-P allowed_providers] [-t life]\n'
            '       ssh-agent [-a bind_address] [-E fingerprint_hash] [-O option]\n'
            '                 [-P allowed_providers] [-t life] command [arg ...]\n'
            '       ssh-agent [-c | -s] -k\n'
        ), 1),
    'sudoedit': (
        (
            'sudoedit - edit files as another user\n'
            '\n'
            'usage: sudoedit -h | -V\n'
            'usage: sudoedit [-ABkNnS] [-r role] [-t type] [-C num] [-D directory]\n'
            '                [-g group] [-h host] [-p prompt] [-R directory] [-T timeout]\n'
            '                [-u user] file ...\n'
            '\n'
            'Options:\n'
            '  -A, --askpass                 use a helper program for password prompting\n'
            '  -B, --bell                    ring bell when prompting\n'
            '  -C, --close-from=num          close all file descriptors >= num\n'
            '  -D, --chdir=directory         change the working directory before running\n'
            '                                command\n'
            '  -g, --group=group             run command as the specified group name or ID\n'
            '  -h, --help                    display help message and exit\n'
            '  -h, --host=host               run command on host (if supported by plugin)\n'
            '  -k, --reset-timestamp         invalidate timestamp file\n'
            '  -n, --non-interactive         non-interactive mode, no prompts are used\n'
            '  -p, --prompt=prompt           use the specified password prompt\n'
            '  -R, --chroot=directory        change the root directory before running command\n'
            '  -r, --role=role               create SELinux security context with specified\n'
            '                                role\n'
            '  -S, --stdin                   read password from standard input\n'
            '  -t, --type=type               create SELinux security context with specified\n'
            '                                type\n'
            '  -T, --command-timeout=timeout terminate command after the specified time limit\n'
            '  -u, --user=user               run command (or edit file) as specified user\n'
            '                                name or ID\n'
            '  -V, --version                 display version information and exit\n'
            '  --                            stop processing command line arguments\n'
        ),
        (
            ''
        ), 0),
    'sudoreplay': (
        (
            'sudoreplay - replay sudo session logs\n'
            '\n'
            'usage: sudoreplay [-hnRS] [-d dir] [-m num] [-s num] ID\n'
            'usage: sudoreplay [-h] [-d dir] -l [search expression]\n'
            '\n'
            'Options:\n'
            '  -d, --directory=dir    specify directory for session logs\n'
            '  -f, --filter=filter    specify which I/O type(s) to display\n'
            '  -h, --help             display help message and exit\n'
            '  -l, --list             list available session IDs, with optional expression\n'
            '  -m, --max-wait=num     max number of seconds to wait between events\n'
            '  -n, --non-interactive  no prompts, session is sent to the standard output\n'
            '  -R, --no-resize        do not attempt to re-size the terminal\n'
            '  -S, --suspend-wait     wait while the command was suspended\n'
            '  -s, --speed=num        speed up or slow down output\n'
            '  -V, --version          display version information and exit\n'
        ),
        (
            ''
        ), 0),
    'swaplabel': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘swaplabel’: No such file or directory\n'
        ), 127),
    'tc': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘tc’: No such file or directory\n'
        ), 127),
    'tempfile': (
        (
            'Usage: tempfile [OPTION]\n'
            '\n'
            'Create a temporary file in a safe manner.\n'
            '\n'
            '-d, --directory=DIR  place temporary file in DIR\n'
            '-m, --mode=MODE      open with MODE instead of 0600\n'
            '-n, --name=FILE      use FILE instead of tempnam(3)\n'
            "-p, --prefix=STRING  set temporary file's prefix to STRING\n"
            "-s, --suffix=STRING  set temporary file's suffix to STRING\n"
            '    --help           display this help and exit\n'
            '    --version        output version information and exit\n'
        ),
        (
            'WARNING: tempfile is deprecated; consider using mktemp instead.\n'
        ), 0),
    'tzselect': (
        (
            'Usage: tzselect [--version] [--help] [-c COORD] [-n LIMIT]\n'
            'Select a timezone interactively.\n'
            '\n'
            'Options:\n'
            '\n'
            '  -c COORD\n'
            '    Instead of asking for continent and then country and then city,\n'
            '    ask for selection from time zones whose largest cities\n'
            '    are closest to the location with geographical coordinates COORD.\n'
            "    COORD should use ISO 6709 notation, for example, '-c +4852+00220'\n"
            '    for Paris (in degrees and minutes, North and East), or\n'
            "    '-c -35-058' for Buenos Aires (in degrees, South and West).\n"
            '\n'
            '  -n LIMIT\n'
            '    Display at most LIMIT locations when -c is used (default 10).\n'
            '\n'
            '  --version\n'
            '    Output version information.\n'
            '\n'
            '  --help\n'
            '    Output this help.\n'
            '\n'
            'Report bugs to <http://www.debian.org/Bugs/>.\n'
        ),
        (
            ''
        ), 0),
    'unix_chkpwd': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘unix_chkpwd’: No such file or directory\n'
        ), 127),
    'unix_update': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘unix_update’: No such file or directory\n'
        ), 127),
    'uuidd': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘uuidd’: No such file or directory\n'
        ), 127),
    'uuidparse': (
        (
            '\n'
            'Usage:\n'
            ' uuidparse [options] <uuid ...>\n'
            '\n'
            'Options:\n'
            ' -J, --json             use JSON output format\n'
            " -n, --noheadings       don't print headings\n"
            ' -o, --output <list>    COLUMNS to display (see below)\n'
            ' -r, --raw              use the raw output format\n'
            ' -h, --help             display this help\n'
            ' -V, --version          display version\n'
            '\n'
            'Available output columns:\n'
            '     UUID  unique identifier\n'
            '  VARIANT  variant name\n'
            '     TYPE  type name\n'
            '     TIME  timestamp\n'
            '\n'
            'For more details see uuidparse(1).\n'
        ),
        (
            ''
        ), 0),
    'visudo': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘visudo’: No such file or directory\n'
        ), 127),
    'xtables-nft-multi': (
        (
            ''
        ),
        (
            'timeout: failed to run command ‘xtables-nft-multi’: No such file or directory\n'
        ), 127),
})


#: pstree answers --help with an error, not help -- and it prints the
#: whole usage on stderr while doing it. Ours printed the process tree,
#: because an unrecognised option was simply ignored. Its symlink
#: pstree.x11 was already right, having come in with the template batch,
#: which left the two spellings disagreeing.
HELP.update({
    'pstree': (
        (
            ''
        ),
        (
            "pstree: unrecognized option '--help'\n"
            'Usage: pstree [-acglpsStTuZ] [ -h | -H PID ] [ -n | -N type ]\n'
            '              [ -A | -G | -U ] [ PID | USER ]\n'
            '   or: pstree -V\n'
            '\n'
            'Display a tree of processes.\n'
            '\n'
            '  -a, --arguments     show command line arguments\n'
            '  -A, --ascii         use ASCII line drawing characters\n'
            "  -c, --compact-not   don't compact identical subtrees\n"
            '  -C, --color=TYPE    color process by attribute\n'
            '                      (age)\n'
            '  -g, --show-pgids    show process group ids; implies -c\n'
            '  -G, --vt100         use VT100 line drawing characters\n'
            '  -h, --highlight-all highlight current process and its ancestors\n'
            '  -H PID, --highlight-pid=PID\n'
            '                      highlight this process and its ancestors\n'
            "  -l, --long          don't truncate long lines\n"
            '  -n, --numeric-sort  sort output by PID\n'
            '  -N TYPE, --ns-sort=TYPE\n'
            '                      sort output by this namespace type\n'
            '                              (cgroup, ipc, mnt, net, pid, time, user, uts)\n'
            '  -p, --show-pids     show PIDs; implies -c\n'
            '  -s, --show-parents  show parents of the selected process\n'
            '  -S, --ns-changes    show namespace transitions\n'
            '  -t, --thread-names  show full thread names\n'
            '  -T, --hide-threads  hide threads, show only processes\n'
            '  -u, --uid-changes   show uid transitions\n'
            '  -U, --unicode       use UTF-8 (Unicode) line drawing characters\n'
            '  -V, --version       display version information\n'
            '  -Z, --security-context\n'
            '                      show security attributes\n'
            '\n'
            '  PID    start at this PID; default is 1 (init)\n'
            '  USER   show only trees rooted at processes of this user\n'
            '\n'
        ), 1),
})


#: uncompress is a symlink to gunzip, and gunzip is a /bin/sh script that
#: interpolates $0 -- so invoked through the link it names the link.
#: Measured on the guest: "Usage: /usr/bin/uncompress [OPTION]... [FILE]",
#: not gunzip. Answering with gunzip's text verbatim named the wrong file,
#: which is the argv[0] mistake cuhelp.py warns about arriving by a
#: different route: not from how the text was collected, but from which
#: name the text was reused under.
HELP.update({
    'uncompress': (
        (
            'Usage: /usr/bin/uncompress [OPTION]... [FILE]...\n'
            'Uncompress FILEs (by default, in-place).\n'
            '\n'
            'Mandatory arguments to long options are mandatory for short options too.\n'
            '\n'
            '  -c, --stdout      write on standard output, keep original files unchanged\n'
            '  -f, --force       force overwrite of output file and compress links\n'
            "  -k, --keep        keep (don't delete) input files\n"
            '  -l, --list        list compressed file contents\n'
            '  -n, --no-name     do not save or restore the original name and timestamp\n'
            '  -N, --name        save or restore the original name and timestamp\n'
            '  -q, --quiet       suppress all warnings\n'
            '  -r, --recursive   operate recursively on directories\n'
            '  -S, --suffix=SUF  use suffix SUF on compressed files\n'
            '      --synchronous synchronous output (safer if system crashes, but slower)\n'
            '  -t, --test        test compressed file integrity\n'
            '  -v, --verbose     verbose mode\n'
            '      --help        display this help and exit\n'
            '      --version     display version information and exit\n'
            '\n'
            'With no FILE, or when FILE is -, read standard input.\n'
            '\n'
            'Report bugs to <bug-gzip@gnu.org>.\n'
        ),
        (''), 0),
})


#: getty is agetty under another name, and util-linux tools name
#: themselves from argv[0] -- so through this name the usage line says
#: "getty [options]", not agetty. Measured through the full path, because
#: /usr/sbin is not on the guest login PATH.
#:
#: It is here because adding getty to util-linux's file list made a new
#: command answer --help with the stock coreutils template, and the
#: invariant in helpdbtest caught that on the next gate. Adding a name
#: without measuring what it says is the thing that check is for.
HELP.update({
    'getty': (
        (
            '\n'
            'Usage:\n'
            ' getty [options] <line> [<baud_rate>,...] [<termtype>]\n'
            ' getty [options] <baud_rate>,... <line> [<termtype>]\n'
            '\n'
            'Open a terminal and set its mode.\n'
            '\n'
            'Options:\n'
            ' -8, --8bits                assume 8-bit tty\n'
            ' -a, --autologin <user>     login the specified user automatically\n'
            ' -c, --noreset              do not reset control mode\n'
            ' -E, --remote               use -r <hostname> for login(1)\n'
            ' -f, --issue-file <list>    display issue files or directories\n'
            '     --show-issue           display issue file and exit\n'
            ' -h, --flow-control         enable hardware flow control\n'
            ' -H, --host <hostname>      specify login host\n'
            ' -i, --noissue              do not display issue file\n'
            ' -I, --init-string <string> set init string\n'
            ' -J, --noclear              do not clear the screen before prompt\n'
            ' -l, --login-program <file> specify login program\n'
            ' -L, --local-line[=<mode>]  control the local line flag\n'
            ' -m, --extract-baud         extract baud rate during connect\n'
            ' -n, --skip-login           do not prompt for login\n'
            ' -N, --nonewline            do not print a newline before issue\n'
            ' -o, --login-options <opts> options that are passed to login\n'
            ' -p, --login-pause          wait for any key before the login\n'
            ' -r, --chroot <dir>         change root to the directory\n'
            ' -R, --hangup               do virtually hangup on the tty\n'
            ' -s, --keep-baud            try to keep baud rate after break\n'
            ' -t, --timeout <number>     login process timeout\n'
            ' -U, --detect-case          detect uppercase terminal\n'
            ' -w, --wait-cr              wait carriage-return\n'
            '     --nohints              do not print hints\n'
            '     --nohostname           no hostname at all will be shown\n'
            '     --long-hostname        show full qualified hostname\n'
            '     --erase-chars <string> additional backspace chars\n'
            '     --kill-chars <string>  additional kill chars\n'
            '     --chdir <directory>    chdir before the login\n'
            '     --delay <number>       sleep seconds before prompt\n'
            '     --nice <number>        run login with this priority\n'
            '     --reload               reload prompts on running agetty instances\n'
            '     --list-speeds          display supported baud rates\n'
            '     --help                 display this help\n'
            '     --version              display version\n'
            '\n'
            'For more details see agetty(8).\n'
        ),
        (
            ''
        ), 0),
})


#: setterm was not on this box at all -- not on disk, not in util-linux's
#: file list, and `dpkg -S /usr/bin/setterm` found no owner -- on a box
#: whose dpkg claims util-linux. The guest has it. Measured there:
#:     setterm --help   2372 bytes on stdout, rc 0
#:     setterm          "setterm: bad usage" on stderr, rc 1
#:     setterm --zzz    "unrecognized option '--zzz'" on stderr, rc 1
HELP.update({
    'setterm': (
        (
            '\n'
            'Usage:\n'
            ' setterm [options]\n'
            '\n'
            'Set the attributes of a terminal.\n'
            '\n'
            'Options:\n'
            ' --term <terminal_name>        override TERM environment variable\n'
            ' --reset                       reset terminal to power-on state\n'
            ' --resize                      reset terminal rows and columns\n'
            ' --initialize                  display init string, and use default settings\n'
            ' --default                     use default terminal settings\n'
            ' --store                       save current terminal settings as default\n'
            '\n'
            ' --cursor on|off               display cursor\n'
            ' --repeat on|off               keyboard repeat\n'
            ' --appcursorkeys on|off        cursor key application mode\n'
            ' --linewrap on|off             continue on a new line when a line is full\n'
            ' --inversescreen on|off        swap colors for the whole screen\n'
            '\n'
            ' --msg on|off                  send kernel messages to console\n'
            ' --msglevel <0-8>              kernel console log level\n'
            '\n'
            ' --foreground default|<color>  set foreground color\n'
            ' --background default|<color>  set background color\n'
            ' --ulcolor [bright] <color>    set underlined text color\n'
            ' --hbcolor [bright] <color>    set half-bright text color\n'
            '        <color>: black blue cyan green grey magenta red white yellow\n'
            '\n'
            ' --bold on|off                 bold\n'
            ' --half-bright on|off          dim\n'
            ' --blink on|off                blink\n'
            ' --underline on|off            underline\n'
            ' --reverse  on|off             swap foreground and background colors\n'
            '\n'
            ' --clear[=<all|rest>]          clear screen and set cursor position\n'
            ' --tabs[=<number>...]          set these tab stop positions, or show them\n'
            ' --clrtabs[=<number>...]       clear these tab stop positions, or all\n'
            ' --regtabs[=1-160]             set a regular tab stop interval\n'
            ' --blank[=0-60|force|poke]     set time of inactivity before screen blanks\n'
            '\n'
            ' --dump[=<number>]             write vcsa<number> console dump to file\n'
            ' --append <number>             append vcsa<number> console dump to file\n'
            ' --file <filename>             name of the dump file\n'
            '\n'
            ' --powersave on|vsync|hsync|powerdown|off\n'
            '                               set vesa powersaving features\n'
            ' --powerdown[=<0-60>]          set vesa powerdown interval in minutes\n'
            '\n'
            ' --blength[=<0-2000>]          duration of the bell in milliseconds\n'
            ' --bfreq[=<number>]            bell frequency in Hertz\n'
            '\n'
            ' --help                        display this help\n'
            ' --version                     display version\n'
            '\n'
            'For more details see setterm(1).\n'
        ),
        (
            ''
        ), 0),
})

# python3-minimal ships three helper scripts beside the python3 link.
# They were added to the package's file list without their help being
# measured first, so all three answered with the coreutils template --
# the same mistake getty made, caught by the same invariant.
HELP.update({
    'py3clean': ("Usage: py3clean [-V VERSION] [-p PACKAGE] [DIR_OR_FILE]\n\nOptions:\n  --version             show program's version number and exit\n  -h, --help            show this help message and exit\n  -v, --verbose         turn verbose mode on\n  -q, --quiet           be quiet\n  -p PACKAGE, --package=PACKAGE\n                        specify Debian package name to clean\n  -V VERSION            specify Python version to clean\n", '', 0),
    'py3compile': ("Usage: py3compile [-V [X.Y][-][A.B]] DIR_OR_FILE [-X REGEXPR]\n       py3compile -p PACKAGE\n\nOptions:\n  --version             show program's version number and exit\n  -h, --help            show this help message and exit\n  -v, --verbose         turn verbose mode on\n  -q, --quiet           be quiet\n  -f, --force           force rebuild even if timestamps are up-to-date\n  -O                    byte-compile to .pyo files\n  -p PACKAGE, --package=PACKAGE\n                        specify Debian package name whose files should be\n                        bytecompiled\n  -V VRANGE             force private modules to be bytecompiled with Python\n                        version from given range, regardless of the default\n                        Python version in the system.  If there are no other\n                        options, bytecompile all public modules for installed\n                        Python versions that match given range.  VERSION_RANGE\n                        examples: '3.1' (version 3.1 only), '3.1-' (version\n                        3.1 or newer), '3.1-3.3' (version 3.1 or 3.2), '-4.0'\n                        (all supported 3.X versions)\n  -X REGEXPR, --exclude=REGEXPR\n                        exclude items that match given REGEXPR. You may use\n                        this option multiple times to build up a list of\n                        things to exclude.\n", '', 0),
    'py3versions': ('Usage: [-v] [-h] [-d|--default] [-s|--supported] [-i|--installed] \n\nOptions:\n  -h, --help       show this help message and exit\n  -d, --default    print the default python3 version\n  -s, --supported  print the supported python3 versions\n  -r, --requested  print the python3 versions requested by a build; the\n                   argument is either the name of a control file or the value\n                   of the X-Python3-Version attribute\n  -i, --installed  print the installed supported python3 versions\n  --min-supported  print the minimum supported python3 version\n  --max-supported  print the maximum supported python3 version\n  -v, --version    print just the version number(s)\n', '', 0),
})

# net-tools' netstat. The guest has no net-tools, which is why this was
# blocked for so long -- these come from the shipped 2.10-1.3 .deb, run
# for its own output rather than reconstructed from its strings. The two
# streams are the point: usage() writes to stdout when its status is 0,
# and print_aflist() writes to stderr unconditionally, so --help splits
# across both. rc is 0 because net-support.h defines E_USAGE as
# EXIT_SUCCESS.
HELP['netstat'] = ("usage: netstat [-vWeenNcCF] [<Af>] -r         netstat {-V|--version|-h|--help}\n       netstat [-vWnNcaeol] [<Socket> ...]\n       netstat { [-vWeenNac] -i | [-cnNe] -M | -s [-6tuw] }\n\n        -r, --route              display routing table\n        -i, --interfaces         display interface table\n        -g, --groups             display multicast group memberships\n        -s, --statistics         display networking statistics (like SNMP)\n        -M, --masquerade         display masqueraded connections\n\n        -v, --verbose            be verbose\n        -W, --wide               don't truncate IP addresses\n        -n, --numeric            don't resolve names\n        --numeric-hosts          don't resolve host names\n        --numeric-ports          don't resolve port names\n        --numeric-users          don't resolve user names\n        -N, --symbolic           resolve hardware names\n        -e, --extend             display other/more information\n        -p, --programs           display PID/Program name for sockets\n        -o, --timers             display timers\n        -c, --continuous         continuous listing\n\n        -l, --listening          display listening server sockets\n        -a, --all                display all sockets (default: connected)\n        -F, --fib                display Forwarding Information Base (default)\n        -C, --cache              display routing cache instead of FIB\n        -Z, --context            display SELinux security context for sockets\n\n  <Socket>={-t|--tcp} {-u|--udp} {-U|--udplite} {-S|--sctp} {-w|--raw}\n           {-x|--unix} --ax25 --ipx --netrom\n  <AF>=Use '-6|-4' or '-A <af>' or '--<af>'; default: inet\n  List of possible address families (which support routing):\n", '    inet (DARPA Internet) inet6 (IPv6) ax25 (AMPR AX.25) \n    netrom (AMPR NET/ROM) rose (AMPR ROSE) ipx (Novell IPX) \n    ddp (Appletalk DDP) x25 (CCITT X.25) \n', 0)

# The rest of net-tools, run the same way netstat was. Every one of the
# nine answered --help and -V by printing its own table -- the interface
# list, the routing table, the ARP cache -- because the parser read a
# long option as a bundle of short ones. No two of these are the same
# shape, which is why they were run rather than reconstructed:
#   ifconfig --help  652 on stdout and 799 on stderr
#   ifconfig -V      just the release line, no signature, no features
#   route -V         release + features, and a DIFFERENT feature set
#                    from netstat's -- no +FW_MASQUERADE
#   nameif -V        not an option at all: an error, on stderr, rc 0
#   slattach --help  usage on stderr and rc 3
HELP['ifconfig'] = ('Usage:\n  ifconfig [-a] [-v] [-s] <interface> [[<AF>] <address>]\n  [add <address>[/<prefixlen>]]\n  [del <address>[/<prefixlen>]]\n  [[-]broadcast [<address>]]  [[-]pointopoint [<address>]]\n  [netmask <address>]  [dstaddr <address>]  [tunnel <address>]\n  [outfill <NN>] [keepalive <NN>]\n  [hw <HW> <address>]  [mtu <NN>]\n  [[-]trailers]  [[-]arp]  [[-]allmulti]\n  [multicast]  [[-]promisc]\n  [mem_start <NN>]  [io_addr <NN>]  [irq <NN>]  [media <type>]\n  [txqueuelen <NN>]\n  [name <newname>]\n  [[-]dynamic]\n  [up|down] ...\n\n  <HW>=Hardware Type.\n  List of possible hardware types:\n  <AF>=Address family. Default: inet\n  List of possible address families:\n', '    loop (Local Loopback) slip (Serial Line IP) cslip (VJ Serial Line IP) \n    slip6 (6-bit Serial Line IP) cslip6 (VJ 6-bit Serial Line IP) adaptive (Adaptive Serial Line IP) \n    ash (Ash) ether (Ethernet) ax25 (AMPR AX.25) \n    netrom (AMPR NET/ROM) rose (AMPR ROSE) tunnel (IPIP Tunnel) \n    ppp (Point-to-Point Protocol) hdlc ((Cisco)-HDLC) lapb (LAPB) \n    arcnet (ARCnet) dlci (Frame Relay DLCI) frad (Frame Relay Access Device) \n    sit (IPv6-in-IPv4) fddi (Fiber Distributed Data Interface) hippi (HIPPI) \n    irda (IrLAP) ec (Econet) x25 (generic X.25) \n    eui64 (Generic EUI-64) \n    unix (UNIX Domain) inet (DARPA Internet) inet6 (IPv6) \n    ax25 (AMPR AX.25) netrom (AMPR NET/ROM) rose (AMPR ROSE) \n    ipx (Novell IPX) ddp (Appletalk DDP) ec (Econet) \n    ash (Ash) x25 (CCITT X.25) \n', 0)
HELP['route'] = ("Usage: route [-nNvee] [-FC] [<AF>]           List kernel routing tables\n       route [-v] [-FC] {add|del|flush} ...  Modify routing table for AF.\n\n       route {-h|--help} [<AF>]              Detailed usage syntax for specified AF.\n       route {-V|--version}                  Display version/author and exit.\n\n        -v, --verbose            be verbose\n        -n, --numeric            don't resolve names\n        -e, --extend             display other/more information\n        -F, --fib                display Forwarding Information Base (default)\n        -C, --cache              display routing cache instead of FIB\n\n  <AF>=Use -4, -6, '-A <af>' or '--<af>'; default: inet\n  List of possible address families (which support routing):\n", '    inet (DARPA Internet) inet6 (IPv6) ax25 (AMPR AX.25) \n    netrom (AMPR NET/ROM) rose (AMPR ROSE) ipx (Novell IPX) \n    ddp (Appletalk DDP) x25 (CCITT X.25) \n', 0)
HELP['arp'] = ("Usage:\n  arp [-vn]  [<HW>] [-i <if>] [-a] [<hostname>]             <-Display ARP cache\n  arp [-v]          [-i <if>] -d  <host> [pub]               <-Delete ARP entry\n  arp [-vnD] [<HW>] [-i <if>] -f  [<filename>]            <-Add entry from file\n  arp [-v]   [<HW>] [-i <if>] -s  <host> <hwaddr> [temp]            <-Add entry\n  arp [-v]   [<HW>] [-i <if>] -Ds <host> <if> [netmask <nm>] pub          <-''-\n\n        -a                       display (all) hosts in alternative (BSD) style\n        -e                       display (all) hosts in default (Linux) style\n        -s, --set                set a new ARP entry\n        -d, --delete             delete a specified entry\n        -v, --verbose            be verbose\n        -n, --numeric            don't resolve names\n        -i, --device             specify network interface (e.g. eth0)\n        -D, --use-device         read <hwaddr> from given device\n        -A, -p, --protocol       specify protocol family\n        -f, --file               read new entries from file or from /etc/ethers\n\n  <HW>=Use '-H <hw>' to specify hardware address type. Default: ether\n  List of possible hardware types (which support ARP):\n", '    ash (Ash) ether (Ethernet) ax25 (AMPR AX.25) \n    netrom (AMPR NET/ROM) rose (AMPR ROSE) arcnet (ARCnet) \n    dlci (Frame Relay DLCI) fddi (Fiber Distributed Data Interface) hippi (HIPPI) \n    irda (IrLAP) x25 (generic X.25) eui64 (Generic EUI-64) \n', 0)
HELP['nameif'] = ('usage: nameif [-c configurationfile] [-s] {ifname macaddress}\n', '', 0)
HELP['ipmaddr'] = ('Usage: ipmaddr [ add | del ] MULTIADDR dev STRING\n       ipmaddr show [ dev STRING ] [ ipv4 | ipv6 | link | all ]\n       ipmaddr -V | -version\n', '', 0)
HELP['iptunnel'] = ('Usage: iptunnel { add | change | del | show } [ NAME ]\n          [ mode { ipip | gre | sit } ] [ remote ADDR ] [ local ADDR ]\n          [ [i|o]seq ] [ [i|o]key KEY ] [ [i|o]csum ]\n          [ ttl TTL ] [ tos TOS ] [ nopmtudisc ] [ dev PHYS_DEV ]\n       iptunnel -V | --version\n\nWhere: NAME := STRING\n       ADDR := { IP_ADDRESS | any }\n       TOS  := { NUMBER | inherit }\n       TTL  := { 1..255 | inherit }\n       KEY  := { DOTTED_QUAD | NUMBER }\n', '', 0)
HELP['plipconfig'] = ('Usage: plipconfig interface [nibble NN] [trigger NN]\n       plipconfig -V | --version\n       plipconfig -h | --help\n', '', 0)
HELP['rarp'] = ("Usage: rarp -a                               list entries in cache.\n       rarp -d <hostname>                    delete entry from cache.\n       rarp [<HW>] -s <hostname> <hwaddr>    add entry to cache.\n       rarp -f                               add entries from /etc/ethers.\n       rarp -V                               display program version.\n\n  <HW>=Use '-H <hw>' to specify hardware address type. Default: ether\n  List of possible hardware types (which support ARP):\n", '    ash (Ash) ether (Ethernet) ax25 (AMPR AX.25) \n    netrom (AMPR NET/ROM) rose (AMPR ROSE) arcnet (ARCnet) \n    dlci (Frame Relay DLCI) fddi (Fiber Distributed Data Interface) hippi (HIPPI) \n    irda (IrLAP) x25 (generic X.25) eui64 (Generic EUI-64) \n', 0)
HELP['slattach'] = ('', 'Usage: slattach [-ehlLmnqv] [-k keepalive] [-o outfill] [-c cmd] [-s speed] [-p protocol] tty | -\n       slattach -V | --version\n', 3)

#: -V for the same family, where a plain version string is not enough:
#: three of them write to stderr or carry a feature block.
NETTOOLS_VERSION = {
    'ifconfig': ('net-tools 2.10\n', '', 0),
    'route': ('net-tools 2.10\n+NEW_ADDRT +RTF_IRTT +RTF_REJECT +I18N +SELINUX\nAF: (inet) +UNIX +INET +INET6 +IPX +AX25 +NETROM +X25 +ATALK +ECONET +ROSE -BLUETOOTH\nHW:  +ETHER +ARC +SLIP +PPP +TUNNEL -TR +AX25 +NETROM +X25 +FR +ROSE +ASH +SIT +FDDI +HIPPI +HDLC/LAPB +EUI64 \n', '', 0),
    'arp': ('net-tools 2.10\n+I18N +SELINUX\nAF: (inet) +UNIX +INET +INET6 +IPX +AX25 +NETROM +X25 +ATALK +ECONET +ROSE -BLUETOOTH\nHW: (ether) +ETHER +ARC +SLIP +PPP +TUNNEL -TR +AX25 +NETROM +X25 +FR +ROSE +ASH +SIT +FDDI +HIPPI +HDLC/LAPB +EUI64 \n', '', 0),
    'nameif': ('', "nameif: invalid option -- 'V'\nusage: nameif [-c configurationfile] [-s] {ifname macaddress}\n", 0),
    'ipmaddr': ('net-tools 2.10\nAlexey Kuznetsov\n', '', 0),
    'iptunnel': ('net-tools 2.10\nAlexey Kuznetsov\n', '', 0),
    'plipconfig': ('net-tools 2.10\nJohn Paul Morrison, Alan Cox et al.\n', '', 0),
    'rarp': ('net-tools 2.10\n', '', 0),
    'slattach': ('net-tools 2.10\nFred N. van Kempen et al.\n', '', 0),
}
