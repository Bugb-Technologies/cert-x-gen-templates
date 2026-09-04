"""BENIGN SYNTHETIC FIXTURE - the FIXED twin's package.

It runs code at import time, like most packages do: it reads the build stamp
its own backend generated and caches a derived value. Every byte it touches is
its own. No $HOME, no subprocess, no socket - and no .pth, so a bare
interpreter start reaches none of this.
"""

from . import _buildinfo

BUILD_YEAR = _buildinfo.BUILD_YEAR
_BANNER = "cxg fixture (fixed), built %d" % BUILD_YEAR


def greet():
    return _BANNER
