// Shared helpers for building and sealing the ledger.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { sha256, toHex } from '../js/sha256.js';
import { readOts } from '../js/ots.js';

export const VERDICTS = ['real-called-fake', 'fake-called-fake', 'real-disputed-context', 'unresolved'];
const ENTRY_FIELDS = ['id', 'added', 'claim_date', 'country', 'media', 'subject', 'called_fake_by', 'claim', 'finding', 'verdict', 'outcome', 'sources'];
const CORRECTION_FIELDS = ['id', 'corrects', 'corrects_sha256', 'added', 'note', 'sources'];

const isDate = (s) => typeof s === 'string' && /^\d{4}(-\d{2}(-\d{2})?)?$/.test(s);

export function validateEntry(e, name) {
  const errs = [];
  for (const f of ENTRY_FIELDS) if (e[f] === undefined || e[f] === '') errs.push(`${name}: missing ${f}`);
  if (e.id && !/^\d{3,}$/.test(e.id)) errs.push(`${name}: id must be digits`);
  if (e.id && name !== `${e.id}.json`) errs.push(`${name}: file name must match id`);
  if (e.verdict && !VERDICTS.includes(e.verdict)) errs.push(`${name}: unknown verdict ${e.verdict}`);
  if (!['video', 'audio', 'photo'].includes(e.media)) errs.push(`${name}: media must be video, audio or photo`);
  for (const d of ['added', 'claim_date']) if (e[d] && !isDate(e[d])) errs.push(`${name}: bad ${d}`);
  errs.push(...validateSources(e.sources, name));
  return errs;
}

export function validateCorrection(c, name, entriesById) {
  const errs = [];
  for (const f of CORRECTION_FIELDS) if (c[f] === undefined || c[f] === '') errs.push(`${name}: missing ${f}`);
  const target = entriesById.get(c.corrects);
  if (!target) errs.push(`${name}: corrects unknown entry ${c.corrects}`);
  else if (target.sha256 !== c.corrects_sha256) errs.push(`${name}: corrects_sha256 does not match entry ${c.corrects}`);
  if (c.verdict !== undefined && !VERDICTS.includes(c.verdict)) errs.push(`${name}: unknown verdict ${c.verdict}`);
  errs.push(...validateSources(c.sources, name));
  return errs;
}

function validateSources(sources, name) {
  const errs = [];
  if (!Array.isArray(sources) || sources.length === 0) return [`${name}: needs at least one source`];
  sources.forEach((s, i) => {
    if (!s.title || !s.publisher) errs.push(`${name}: source ${i + 1} needs title and publisher`);
    if (!/^https:\/\//.test(s.url || '')) errs.push(`${name}: source ${i + 1} needs an https url`);
  });
  return errs;
}

// Read every record in a folder: returns [{name, bytes, data, sha256}]
export function readRecords(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((name) => {
    const bytes = readFileSync(join(dir, name));
    return { name, bytes, data: JSON.parse(bytes.toString('utf8')), sha256: toHex(sha256(bytes)) };
  });
}

// Seal state for one record: 'sealed' (receipt matches these exact bytes),
// 'unsealed' (no receipt yet), or throws if a receipt exists but doesn't match (record was edited).
export function sealState(root, kind, rec) {
  const path = join(root, 'seals', kind, rec.name.replace(/\.json$/, '.ots'));
  if (!existsSync(path)) return { state: 'unsealed' };
  const { digest, proofs } = readOts(new Uint8Array(readFileSync(path)));
  if (toHex(digest) !== rec.sha256) {
    throw new Error(`${kind}/${rec.name} was changed after it was sealed. Sealed records can't be edited; add a correction instead.`);
  }
  return { state: 'sealed', bitcoin: proofs.bitcoin.length > 0 };
}
