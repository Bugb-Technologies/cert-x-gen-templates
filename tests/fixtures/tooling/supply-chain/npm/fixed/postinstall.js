// BENIGN SYNTHETIC FIXTURE - the FIXED twin.
//
// The point of this twin is that it is NOT inert. It runs at install time, it
// spawns a subprocess, and it does real work - exactly like the thousands of
// honest packages that compile or configure something during `npm install`.
// What it never does is leave its own tree: no read of $HOME, no write outside
// the install prefix, no socket.
//
// A probe that confirmed here would be detecting "this package has a
// postinstall script", which is not a finding. The refutation on this twin is
// the precision claim of supply-chain-install-hook-behavior.
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const manifest = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));

// A subprocess, and a shell at that - the thing a signature-based check would
// flag and this probe deliberately does not.
const banner = execFileSync('sh', ['-c', 'echo build-step'], {
  encoding: 'utf8',
}).trim();

console.log('cxg-fixture-fixed: %s for %s@%s', banner,
            manifest.name, manifest.version);
