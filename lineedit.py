"""Readline-style line editing for the interactive shell.

bash on a pty runs readline, and an attacker's fingers expect it. The ssh
loop used to handle Enter, backspace and ctrl-c and nothing else, so every
arrow key was appended to the command line as literal bytes: pressing Up
printed ^[[A and then tried to run it. That is visible within seconds of
landing on a box.

Kept apart from the ssh layer on purpose. Inline in the socket loop it could
only be exercised by connecting to it; here a suite can push keystrokes in
and read the bytes that would go out, so every key can be checked without a
socket -- including the ones that only happen when a sequence is split
across two packets.

The history is not this object's own. It is handed the shell's list, so
what Up recalls and what `history` prints cannot drift apart.
"""

ESC = "\x1b"
FINALS = "ABCDEFHPQRSabcdfhpqrs~"


class LineEditor(object):
    """One line being typed. feed() returns bytes to send and any line."""

    def __init__(self, history=None, max_len=4096):
        self.buf = ""
        self.pos = 0
        self.history = history if history is not None else []
        self.hist_idx = None
        self.saved = ""
        self.pending = ""
        self.max_len = max_len
        self.done = False          # ctrl-d on an empty line

    # -- helpers ---------------------------------------------------------
    def _redraw(self, old_len, prompt):
        """Repaint in place and leave the cursor at self.pos."""
        out = "\r" + prompt + self.buf
        pad = old_len - len(self.buf)
        if pad > 0:
            out += " " * pad
        back = len(self.buf) - self.pos + (pad if pad > 0 else 0)
        if back > 0:
            out += "\b" * back
        return out

    def _hist_up(self, prompt):
        if not self.history:
            return ""
        old = len(self.buf)
        if self.hist_idx is None:
            self.saved = self.buf
            self.hist_idx = len(self.history)
        if self.hist_idx <= 0:
            return ""
        self.hist_idx -= 1
        self.buf = self.history[self.hist_idx]
        self.pos = len(self.buf)
        return self._redraw(old, prompt)

    def _hist_down(self, prompt):
        if self.hist_idx is None:
            return ""
        old = len(self.buf)
        self.hist_idx += 1
        if self.hist_idx >= len(self.history):
            self.hist_idx = None
            self.buf = self.saved
        else:
            self.buf = self.history[self.hist_idx]
        self.pos = len(self.buf)
        return self._redraw(old, prompt)

    def _word_start(self):
        j = self.pos
        while j > 0 and self.buf[j - 1].isspace():
            j -= 1
        while j > 0 and not self.buf[j - 1].isspace():
            j -= 1
        return j

    def _word_end(self):
        j = self.pos
        n = len(self.buf)
        while j < n and self.buf[j].isspace():
            j += 1
        while j < n and not self.buf[j].isspace():
            j += 1
        return j

    # -- the escape sequences -------------------------------------------
    def _escape(self, rest, prompt):
        """(bytes out, consumed, incomplete). rest starts after the ESC."""
        if not rest:
            return "", 0, True
        if rest[0] == "b":                      # alt-b, word left
            self.pos = self._word_start()
            return self._redraw(len(self.buf), prompt), 1, False
        if rest[0] == "f":                      # alt-f, word right
            self.pos = self._word_end()
            return self._redraw(len(self.buf), prompt), 1, False
        if rest[0] not in ("[", "O"):
            return "", 1, False                 # lone ESC: bash ignores it
        i = 1
        params = ""
        while i < len(rest) and rest[i] not in FINALS:
            params += rest[i]
            i += 1
        if i >= len(rest):
            return "", 0, True                  # split across packets
        final = rest[i]
        consumed = i + 1
        old = len(self.buf)
        if final == "A":
            return self._hist_up(prompt), consumed, False
        if final == "B":
            return self._hist_down(prompt), consumed, False
        if final == "C":
            if self.pos < len(self.buf):
                self.pos += 1
                return "\x1b[C", consumed, False
            return "", consumed, False
        if final == "D":
            if self.pos > 0:
                self.pos -= 1
                return "\b", consumed, False
            return "", consumed, False
        if final in ("H",) or params == "1":
            self.pos = 0
            return self._redraw(old, prompt), consumed, False
        if final in ("F",) or params == "4":
            self.pos = len(self.buf)
            return self._redraw(old, prompt), consumed, False
        if final == "~" and params == "3":      # delete
            if self.pos < len(self.buf):
                self.buf = self.buf[:self.pos] + self.buf[self.pos + 1:]
                return self._redraw(old, prompt), consumed, False
            return "", consumed, False
        if final == "~" and params in ("200", "201"):
            return "", consumed, False          # bracketed paste markers
        return "", consumed, False

    # -- the main entry point -------------------------------------------
    def feed(self, text, prompt):
        """Consume keystrokes.

        Returns (out, lines): bytes to write to the channel, and any command
        lines the user completed with Enter.
        """
        out = []
        lines = []
        text = self.pending + text
        self.pending = ""
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == ESC:
                piece, consumed, incomplete = self._escape(text[i + 1:],
                                                           prompt)
                if incomplete:
                    self.pending = text[i:]
                    return "".join(out), lines
                out.append(piece)
                i += 1 + consumed
                continue
            i += 1
            if ch in ("\r", "\n"):
                out.append("\r\n")
                lines.append(self.buf)
                self.buf = ""
                self.pos = 0
                self.hist_idx = None
                self.saved = ""
            elif ch == "\x7f" or ch == "\b":
                if self.pos:
                    old = len(self.buf)
                    self.buf = self.buf[:self.pos - 1] + self.buf[self.pos:]
                    self.pos -= 1
                    out.append(self._redraw(old, prompt))
            elif ch == "\x03":                  # ctrl-c
                out.append("^C\r\n")
                self.buf = ""
                self.pos = 0
                self.hist_idx = None
                lines.append(None)              # caller reprints the prompt
            elif ch == "\x04":                  # ctrl-d
                if not self.buf:
                    self.done = True
                    # Whatever followed the ^D in this chunk has not been
                    # read yet, and returning here used to drop it on the
                    # floor. That was invisible while ^D always meant an
                    # immediate logout; once a command can consume the ^D
                    # as its end of input, the commands typed after it are
                    # real input and have to survive. Same slot the
                    # incomplete-escape case uses. Note the index: the
                    # loop advances i *before* dispatching on the
                    # character, so i is already past the ^D and slicing
                    # from i + 1 would eat the first byte after it.
                    self.pending = text[i:]
                    return "".join(out), lines
            elif ch == "\x01":                  # ctrl-a
                self.pos = 0
                out.append(self._redraw(len(self.buf), prompt))
            elif ch == "\x05":                  # ctrl-e
                self.pos = len(self.buf)
                out.append(self._redraw(len(self.buf), prompt))
            elif ch == "\x02":                  # ctrl-b
                if self.pos > 0:
                    self.pos -= 1
                    out.append("\b")
            elif ch == "\x06":                  # ctrl-f
                if self.pos < len(self.buf):
                    self.pos += 1
                    out.append("\x1b[C")
            elif ch == "\x15":                  # ctrl-u
                old = len(self.buf)
                self.buf = self.buf[self.pos:]
                self.pos = 0
                out.append(self._redraw(old, prompt))
            elif ch == "\x0b":                  # ctrl-k
                old = len(self.buf)
                self.buf = self.buf[:self.pos]
                out.append(self._redraw(old, prompt))
            elif ch == "\x17":                  # ctrl-w
                old = len(self.buf)
                j = self._word_start()
                self.buf = self.buf[:j] + self.buf[self.pos:]
                self.pos = j
                out.append(self._redraw(old, prompt))
            elif ch == "\x0c":                  # ctrl-l
                out.append("\x1b[H\x1b[2J" + prompt + self.buf)
                if self.pos < len(self.buf):
                    out.append("\b" * (len(self.buf) - self.pos))
            elif ch == "\x14":                  # ctrl-t: transpose
                if self.pos >= 2:
                    old = len(self.buf)
                    a, b = self.buf[self.pos - 2], self.buf[self.pos - 1]
                    self.buf = (self.buf[:self.pos - 2] + b + a
                                + self.buf[self.pos:])
                    out.append(self._redraw(old, prompt))
            elif ch == "\t":
                pass                            # no completion table to offer
            elif ch >= " " and len(self.buf) < self.max_len:
                old = len(self.buf)
                self.buf = self.buf[:self.pos] + ch + self.buf[self.pos:]
                self.pos += 1
                if self.pos == len(self.buf):
                    out.append(ch)              # append: no repaint needed
                else:
                    out.append(self._redraw(old, prompt))
        return "".join(out), lines
