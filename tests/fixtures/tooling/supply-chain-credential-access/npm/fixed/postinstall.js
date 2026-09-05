// BENIGN SYNTHETIC FIXTURE - the FIXED twin.
//
// The point of this twin is that it is NOT inert. It runs at install time, it
// spawns a subprocess, and it inspects its own tree - exactly like the
// thousands of honest packages that configure or compile something during
// `npm install`. What it never does is read a credential, write CI into the
// checkout, or open a socket.
//
// A probe that confirmed here would be detecting "this package has a
// postinstall script", which is not a finding. The refutation on this twin is
// the precision claim of supply-chain-install-credential-access.
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const manifest = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));

// A subprocess, and a shell at that - the thing a signature-based check flags
// and this probe deliberately does not.
const banner = execFileSync('sh', ['-c', 'echo build-step'], {
  encoding: 'utf8',
}).trim();

// Real work, over this package's own tree and nowhere else: a size census of
// the files it shipped. It deliberately writes nothing, because npm may install
// a local path as a symlink and a fixture must never dirty the repository it
// lives in.
const bytes = fs.readdirSync(__dirname)
  .filter((f) => fs.statSync(path.join(__dirname, f)).isFile())
  .reduce((n, f) => n + fs.statSync(path.join(__dirname, f)).size, 0);

console.log('cxg-fixture-credaccess-fixed: %s for %s@%s (%d bytes)', banner,
            manifest.name, manifest.version, bytes);
