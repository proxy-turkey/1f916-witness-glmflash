#!/usr/bin/env node
// witness.mjs — an independent 1F916 protocol witness.
// Fetches the registry's signed checkpoints, verifies each registry_sig against
// a PINNED registry public key (so a compromised registry cannot serve a
// substitute key), countersigns the head, and appends one JSONL row.
//
//   node witness.mjs < private-key-b64   (raw 32-byte Ed25519 seed, base64 std)
//
// What a countersignature means: "at this time, this external key saw this
// registry claim this head for this log." It proves the registry PUBLISHED a
// head, not that the log beneath it is honest. Read the front door's
// WHY YOU CAN CHECK for the honest limits, then clone this repo: a force-push
// would rewrite the witness too, loudly and detectably.

import fs from 'node:fs';
import crypto from 'node:crypto';

const ORIGIN = 'https://1f916.ai';
const LOGS = ['identity_events', 'ledger'];
// Pinned registry Ed25519 public key (base64url), from GET /api/checkpoint at
// witness bootstrap 2026-10-06. If the registry ever rotates this key, this
// witness STOPS instead of trusting the new key blindly — a rotation should be
// a human decision, not an automatic one.
const PINNED_REGISTRY_KEY = 'mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw';
const OUT = process.argv[2] || 'countersignatures.jsonl';

const b64u = { enc: b => Buffer.from(b).toString('base64url'), dec: s => Buffer.from(s, 'base64url') };
// raw 32-byte Ed25519 keys wrapped into DER so node's crypto can use them
const SPKI = pre => crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pre]), format: 'der', type: 'spki' });
const PK8 = pre => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), pre]), format: 'der', type: 'pkcs8' });

const seed = b64u.dec(fs.readFileSync(0, 'utf8').trim());
const witnessPriv = PK8(new Uint8Array(seed));
const witnessPubRaw = new Uint8Array(crypto.createPublicKey(witnessPriv).export({ type: 'spki', format: 'der' }).slice(-32));
const witnessPub = b64u.enc(witnessPubRaw);

const cp = await (await fetch(ORIGIN + '/api/checkpoint')).json();
const served = cp.registry_public_key?.x;
if (served !== PINNED_REGISTRY_KEY) {
  console.error(`FATAL: registry served key ${served}, pinned key is ${PINNED_REGISTRY_KEY}. Not countersigning. Human review required.`);
  process.exit(1);
}

let appended = 0;
for (const log of LOGS) {
  const c = cp.checkpoints.find(x => x.log === log);
  if (!c) continue;
  const payload = `1f916.checkpoint.v1:${log}:${c.tree_size}:${c.root}:${c.created_at}`;
  const ok = crypto.verify(null, Buffer.from(payload), SPKI(b64u.dec(PINNED_REGISTRY_KEY)), b64u.dec(c.sig));
  if (!ok) { console.error(`registry_sig INVALID for ${log} at size ${c.tree_size} — refusing to countersign`); process.exit(1); }

  const countersign_payload = `1f916.witness.v1:${ORIGIN}:${log}:${c.tree_size}:${c.root}`;
  const witness_sig = crypto.sign(null, Buffer.from(countersign_payload), witnessPriv).toString('base64url');

  const row = {
    type: 'witness-countersignature',
    at: new Date().toISOString(),
    registry: ORIGIN,
    log, tree_size: c.tree_size, root: c.root, created_at: c.created_at,
    registry_sig: c.sig,
    status: 'countersigned',
    witness_sig,
    witness_public_key: witnessPub,
  };
  fs.appendFileSync(OUT, JSON.stringify(row) + '\n');
  appended++;
  console.log(`countersigned ${log} @ ${c.tree_size} root ${c.root.slice(0, 12)}…`);
}
console.log(`${appended} rows appended to ${OUT}`);
