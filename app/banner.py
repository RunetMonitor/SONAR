"""SONAR splash for the terminal (BIOS-style, 3-color).

Navy in the source logo is treated as transparent so the terminal theme
shows through. Letters are mid-gray (readable on light and dark
backgrounds). Sage green is unchanged. No image files at runtime.
"""

import os
import shutil
import sys

# Index 0 is transparent (logo navy). Letters are slate gray, not white,
# so they stay visible on a light terminal. Green matches logo2.jpeg.
_TRANSPARENT = 0
_LETTER = (107, 114, 128)
_GREEN = (88, 144, 112)
_PALETTE = ((0, 0, 0), _LETTER, _GREEN)

# 256-color: unused / gray-243 / sage-72
_C256 = (0, 243, 72)
# 16-color fg/bg: unused / bright-black (gray) / green
_FG16 = (30, 90, 32)
_BG16 = (40, 100, 42)

_ASCII = {0: " ", 1: "#", 2: "+"}
_UPPER = "\u2580"  # ▀
_LOWER = "\u2584"  # ▄
_FULL = "\u2588"  # █
_RESET = "\033[0m"

# '.' transparent  '#' letter  '+' sage  — even height for half-blocks
_BITMAP = """\
........................................................
..######.....#####......##.....#.......##.......######..
.##.........##...##.....##.....#.......##.......#....##.
.#.........##.....##....#.#....#......#..#......#.....#.
..#........#.......#....#..#...#......#..#......#.....#.
...###.....#.......#....#..##..#.....#....#.....#....##.
......#....#.......#....#...#..#.....#....#.....######..
.......#...##.....##....#....#.#....##....##....#...#...
......##....##...##.....#.....##....#......#....#....#..
.######......#####......#.....##....#......#....#.....#.
........................................................
........................................................
........................................................
........................................................
.++++++++++++++++++++++++++++++++++++++++++++++++++++++.
......................++++++++++++......................
.......................++++++++++.......................
........................++++++++........................
.................++......++++++......++.................
.................++..................++.................
..................++................++..................
...........++.....+++..............+++.....++...........
...........++......+++............+++......++...........
...........+++......+++..........+++......+++...........
............++.......+++++....+++++.......++............
............+++........++++++++++........+++............
......++.....++...........++++...........++.....++......
......++.....+++........................+++.....++......
......++......+++......................+++......++......
.......++......+++....................+++......++.......
.......++.......+++..................+++.......++.......
........++.......++++..............++++.......++........
........+++........++++..........++++........+++........
.........+++........++++++++++++++++........+++.........
..........++...........++++++++++...........++..........
...........++..............................++...........
............+++..........................+++............
.............+++........................+++.............
..............++++....................++++..............
...............+++++................+++++...............
.................+++++............+++++.................
...................++++++++++++++++++...................
......................++++++++++++......................
........................................................
"""

_ROWS = tuple(_BITMAP.splitlines())
WIDTH = len(_ROWS[0]) if _ROWS else 0
HEIGHT = len(_ROWS)


def _vt_windows():
    """Turn on ANSI/VT processing and UTF-8 output on Windows consoles."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if not handle or handle == -1:
            return False
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
            return False
        try:
            kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
        try:
            reconf = getattr(sys.stdout, "reconfigure", None)
            if reconf is not None:
                reconf(encoding="utf-8", errors="replace")
        except Exception:
            pass
        return True
    except Exception:
        return False


def _isatty():
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _term_cols():
    try:
        return int(shutil.get_terminal_size().columns)
    except Exception:
        return 80


def _force_flag():
    return (os.environ.get("FORCE_COLOR") or "").strip()


def _color_bits():
    """0 = no color, 16 / 256 / 24 = ANSI palettes."""
    if os.environ.get("NO_COLOR"):
        return 0
    force = _force_flag()
    if force in ("0", "false", "False", "no"):
        return 0
    forced = bool(force)
    if not forced and not _isatty():
        return 0
    term = os.environ.get("TERM") or ""
    if not forced and term == "dumb":
        return 0
    if force == "1":
        return 16
    if force == "2":
        return 256
    if force == "3":
        return 24
    colorterm = (os.environ.get("COLORTERM") or "").lower()
    program = os.environ.get("TERM_PROGRAM") or ""
    if program == "Apple_Terminal":
        return 256
    if "truecolor" in colorterm or "24bit" in colorterm:
        return 24
    if program in ("iTerm.app", "vscode", "WezTerm", "ghostty", "Terminus"):
        return 24
    if os.environ.get("WT_SESSION"):
        return 24
    # Truecolor keeps navy/sage; Win10+ / modern Unix accept 38;2.
    # Apple Terminal is handled above (256-color).
    if sys.platform in ("win32", "darwin") or sys.platform.startswith("linux"):
        return 24
    if "256" in term:
        return 256
    return 16


def _use_half_block():
    enc = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    if enc in ("utf8", "cp65001"):
        return True
    if sys.platform in ("win32", "darwin") or sys.platform.startswith("linux"):
        return True
    return False


def _fg(idx, bits):
    r, g, b = _PALETTE[idx]
    if bits >= 256:
        return "\033[38;5;{}m".format(_C256[idx])
    if bits >= 24:
        return "\033[38;2;{};{};{}m".format(r, g, b)
    return "\033[{}m".format(_FG16[idx])


def _bg(idx, bits):
    r, g, b = _PALETTE[idx]
    if bits >= 256:
        return "\033[48;5;{}m".format(_C256[idx])
    if bits >= 24:
        return "\033[48;2;{};{};{}m".format(r, g, b)
    return "\033[{}m".format(_BG16[idx])


def _pix(row, col):
    if row < 0 or row >= HEIGHT or col < 0 or col >= WIDTH:
        return 0
    ch = _ROWS[row][col]
    if ch == "#":
        return 1
    if ch == "+":
        return 2
    return 0


def _cell(top, bot, bits, half):
    if bits <= 0:
        ink = top if top else bot
        return _ASCII[ink]
    if not half:
        ink = top if top else bot
        if ink == _TRANSPARENT:
            return " "
        return _fg(ink, bits) + _ASCII[ink] + _RESET
    if top == _TRANSPARENT and bot == _TRANSPARENT:
        return " "
    if top == _TRANSPARENT:
        return _fg(bot, bits) + _LOWER + _RESET
    if bot == _TRANSPARENT:
        return _fg(top, bits) + _UPPER + _RESET
    if top == bot:
        return _fg(top, bits) + _FULL + _RESET
    return _fg(top, bits) + _bg(bot, bits) + _UPPER + _RESET


def render_banner(bits=None, half=None, min_width=None):
    """Return the splash as a list of lines (no trailing newline)."""
    if bits is None:
        bits = _color_bits()
    if half is None:
        half = _use_half_block()
    step = 2 if half else 1
    lines = []
    for y in range(0, HEIGHT, step):
        parts = []
        for x in range(WIDTH):
            top = _pix(y, x)
            bot = _pix(y + 1, x) if step == 2 else top
            parts.append(_cell(top, bot, bits, half))
        line = "".join(parts)
        if bits:
            line += _RESET
        lines.append(line)
    cols = _term_cols() if min_width is None else min_width
    pad = 0
    # Keep a spare column so 80-wide consoles do not wrap the art.
    if cols > WIDTH + 1:
        pad = (cols - WIDTH) // 2
    if pad:
        prefix = " " * pad
        lines = [prefix + ln for ln in lines]
    return lines


def print_banner():
    """Print the SONAR splash. No-op when stdout is not a terminal.

    FORCE_COLOR=1/2/3 still prints (16 / 256 / 24-bit) even to a pipe.
    """
    force = _force_flag()
    if force in ("0", "false", "False", "no"):
        return
    if not force and not _isatty():
        return
    if os.environ.get("NO_COLOR") and not force:
        bits, half = 0, True
    elif sys.platform == "win32" and not _vt_windows():
        bits, half = 0, True
    else:
        bits = _color_bits()
        half = _use_half_block()
    cols = _term_cols()
    # Avoid wrapping, which shreds the art on narrow consoles.
    if cols and cols <= WIDTH:
        _print_compact(bits)
        return
    try:
        sys.stdout.write("\n")
        for line in render_banner(bits=bits, half=half, min_width=cols):
            sys.stdout.write(line + "\n")
        sys.stdout.write(_RESET + "\n" if bits else "\n")
        sys.stdout.flush()
    except UnicodeEncodeError:
        try:
            sys.stdout.write(_RESET)
            for line in render_banner(bits=bits, half=False, min_width=cols):
                sys.stdout.write(line + "\n")
            sys.stdout.write(_RESET + "\n" if bits else "\n")
            sys.stdout.flush()
        except Exception:
            pass
    except Exception:
        try:
            sys.stdout.write(_RESET + "\n")
        except Exception:
            pass


def _print_compact(bits):
    """One-line fallback when the console is narrower than the bitmap."""
    if bits:
        text = (
            _fg(1, bits)
            + "  SONAR  "
            + _fg(2, bits)
            + " ))) "
            + _RESET
        )
    else:
        text = "  SONAR"
    try:
        sys.stdout.write("\n" + text + "\n\n")
        sys.stdout.flush()
    except Exception:
        pass
