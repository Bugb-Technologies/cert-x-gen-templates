"""BENIGN SYNTHETIC FIXTURE - the FIXED twin's build backend.

Deliberately NOT inert. It runs code while pip builds, exactly as the flawed
twin does, and it generates a file - the ordinary work of a real build backend.
The difference is where the effects land: inside the wheel it is producing,
and nowhere else. No $HOME read, no write outside the build tree, no socket,
and no .pth.

A probe that confirmed here would be reporting "this package has a build
backend", which is not a finding.
"""

import base64
import datetime
import hashlib
import os
import zipfile

NAME = "cxg_fixture_installhook_fixed"
VERSION = "1.0.0"
DIST = "%s-%s.dist-info" % (NAME, VERSION)
PKG = "cxg_fixture_installhook"

METADATA = (
    "Metadata-Version: 2.1\n"
    "Name: cxg-fixture-installhook-fixed\n"
    "Version: %s\n"
    "Summary: Benign synthetic cxg fixture\n" % VERSION
)
WHEEL = ("Wheel-Version: 1.0\nGenerator: cxg-fixture\n"
         "Root-Is-Purelib: true\nTag: py3-none-any\n")


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
    # Real build-time work, generated into the wheel and nowhere else.
    stamp = ("BUILD_YEAR = %d\n"
             % datetime.datetime.now(datetime.timezone.utc).year)

    members = {
        "%s/__init__.py" % PKG: _read(PKG, "__init__.py"),
        "%s/_buildinfo.py" % PKG: stamp.encode(),
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
