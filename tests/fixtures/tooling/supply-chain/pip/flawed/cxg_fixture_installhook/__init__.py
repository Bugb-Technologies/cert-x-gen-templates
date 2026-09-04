"""BENIGN SYNTHETIC FIXTURE - import-time execution (LiteLLM 1.82.7 shape).

Importing this package is enough to run the payload. Nothing has to call it.
"""

import cxg_fixture_beacon

cxg_fixture_beacon.run("import")


def greet():
    return "cxg fixture (flawed)"
