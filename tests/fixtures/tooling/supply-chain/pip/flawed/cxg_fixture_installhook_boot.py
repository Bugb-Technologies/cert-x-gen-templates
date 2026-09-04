"""BENIGN SYNTHETIC FIXTURE - interpreter-startup execution.

Reached from cxg_fixture_installhook.pth, which the wheel drops straight into
site-packages. Python executes an `import` line in a .pth on EVERY interpreter
start, so this runs even when cxg_fixture_installhook is never imported - the
LiteLLM 1.82.8 shape.
"""

import cxg_fixture_beacon

cxg_fixture_beacon.run("startup")
