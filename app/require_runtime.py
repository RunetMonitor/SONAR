"""Fail fast if this Python cannot run SONAR.

Must stay parseable on Python 3.6: no postponed annotations, no 3.7-only syntax.
run.py imports this *before* config.py / upload_token.py, which 3.6 cannot parse.
"""

import sys

MIN_PY = (3, 7)

_STDLIB = (
    "concurrent.futures",
    "csv",
    "hashlib",
    "json",
    "ssl",
    "struct",
    "urllib.request",
    "zipfile",
    "zlib",
)


def _pause_if_windows():
    if sys.platform == "win32":
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass


def _fail(message):
    sys.stdout.write("ERROR: {}\n".format(message))
    sys.stdout.flush()
    _pause_if_windows()
    sys.exit(2)


def require_python():
    if sys.version_info[:2] >= MIN_PY:
        return
    have = "{}.{}.{}".format(*sys.version_info[:3])
    need = "{}.{}".format(*MIN_PY)
    _fail("Python {} or newer is required (you have {}).".format(need, have))


def require_stdlib():
    missing = []
    for name in _STDLIB:
        try:
            __import__(name)
        except ImportError:
            missing.append(name)
    if missing:
        _fail(
            "Python is missing required modules: {}.".format(", ".join(missing))
        )


def require_runtime():
    require_python()
    require_stdlib()
