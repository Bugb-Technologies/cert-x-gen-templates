"""BENIGN SYNTHETIC FIXTURE - the FLAWED twin's build backend.

A minimal PEP 517 backend written against the standard library alone, so the
fixture installs offline with `--no-build-isolation`.

The flaw is the first two lines of build_wheel(): running the payload while
pip is building, which is the modern equivalent of code in setup.py. The wheel
it emits then carries the other two stages - a .pth that fires on interpreter
startup, and import-time code in the package __init__.
"""

import base64
import hashlib
import os
import zipfile

NAME = "cxg_fixture_installhook_flawed"
VERSION = "1.0.0"
DIST = "%s-%s.dist-info" % (NAME, VERSION)
PKG = "cxg_fixture_installhook"

METADATA = (
    "Metadata-Version: 2.1\n"
    "Name: cxg-fixture-installhook-flawed\n"
    "Version: %s\n"
    "Summary: Benign synthetic cxg fixture\n" % VERSION
)
WHEEL = ("Wheel-Version: 1.0\nGenerator: cxg-fixture\n"
         "Root-Is-Purelib: true\nTag: py3-none-any\n")

# `import <module>` on a line of a .pth is executed by site.py on every
# interpreter start. This is the whole mechanism of the LiteLLM 1.82.8 stage.
PTH = "import cxg_fixture_installhook_boot\n"


def _here(*parts):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), *parts)


def _read(*parts):
    with open(_here(*parts), "rb") as fh:
        return fh.read()


def _record_line(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "%s,sha256=%s,%d" % (path, digest.decode(), len(data))


def get_requires_for_build_wheel(config_settings=None):
    return []


def _write_metadata(directory):
    os.makedirs(os.path.join(directory, DIST), exist_ok=True)
    with open(os.path.join(directory, DIST, "METADATA"), "w") as fh:
        fh.write(METADATA)
    with open(os.path.join(directory, DIST, "WHEEL"), "w") as fh:
        fh.write(WHEEL)
    return DIST


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    return _write_metadata(metadata_directory)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    # STAGE 1 - build/install time. pip is running this.
    import cxg_fixture_beacon
    cxg_fixture_beacon.run("install")

    members = {
        "%s/__init__.py" % PKG: _read(PKG, "__init__.py"),
        "cxg_fixture_beacon.py": _read("cxg_fixture_beacon.py"),
        "cxg_fixture_installhook_boot.py": _read("cxg_fixture_installhook_boot.py"),
        # STAGE 2 - interpreter startup, via site.py.
        "cxg_fixture_installhook.pth": PTH.encode(),
        "%s/METADATA" % DIST: METADATA.encode(),
        "%s/WHEEL" % DIST: WHEEL.encode(),
    }
    lines = [_record_line(path, data) for path, data in members.items()]
    lines.append("%s/RECORD,," % DIST)
    members["%s/RECORD" % DIST] = ("\n".join(lines) + "\n").encode()

    wheel_name = "%s-%s-py3-none-any.whl" % (NAME, VERSION)
    with zipfile.ZipFile(os.path.join(wheel_directory, wheel_name), "w") as zf:
        for path, data in members.items():
            zf.writestr(path, data)
    return wheel_name


build_sdist = None
