import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, cpSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from '../tools/build.mjs';
import { buildOts, parseTimestamp } from '../js/ots.js';
import { sha256, fromHex } from '../js/sha256.js';
import { fakeCalendarResponse } from './helpers.js';

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-'));
  cpSync('entries', join(dir, 'entries'), { recursive: true });
  mkdirSync(join(dir, 'corrections'));
  return dir;
}
const fakeSeal = (hex) => buildOts(fromHex(hex), new Uint8Array(16), [parseTimestamp(fakeCalendarResponse('https://cal.example'))]);
const seal = (dir, kind, id, hex) => { mkdirSync(join(dir, 'seals', kind), { recursive: true }); writeFileSync(join(dir, 'seals', kind, id + '.ots'), fakeSeal(hex)); };

test('the real ledger builds and every entry is valid', () => {
  const l = build('.');
  assert.ok(l.entries.length >= 11);
});

test('seal matching the exact bytes shows as sealed', () => {
  const dir = fixture();
  const first = build(dir).entries[0];
  seal(dir, 'entries', first.id, first.sha256);
  assert.equal(build(dir).entries[0].state, 'sealed');
});

test('editing a sealed entry breaks the build', () => {
  const dir = fixture();
  const first = build(dir).entries[0];
  seal(dir, 'entries', first.id, first.sha256);
  const p = join(dir, first.file);
  writeFileSync(p, readFileSync(p, 'utf8').replace('"claim":', '"claim": "x",\n  "claim2":'));
  assert.throws(() => build(dir), /changed after it was sealed/);
});

test('corrections must point at the exact sealed version', () => {
  const dir = fixture();
  const first = build(dir).entries[0];
  const c = { id: '001-1', corrects: first.id, corrects_sha256: 'ab'.repeat(32), added: '2026-12-01', note: 'x', sources: [{ title: 't', publisher: 'p', url: 'https://x.example' }] };
  writeFileSync(join(dir, 'corrections', '001-1.json'), JSON.stringify(c));
  assert.throws(() => build(dir), /corrects_sha256 does not match/);
  c.corrects_sha256 = first.sha256;
  writeFileSync(join(dir, 'corrections', '001-1.json'), JSON.stringify(c));
  assert.equal(build(dir).corrections.length, 1);
});

test('bad entries are rejected', () => {
  const dir = fixture();
  const p = join(dir, 'entries', '001.json');
  const e = JSON.parse(readFileSync(p, 'utf8'));
  writeFileSync(p, JSON.stringify({ ...e, verdict: 'probably-fake', sources: [{ title: 't', publisher: 'p', url: 'http://insecure' }] }));
  assert.throws(() => build(dir), /unknown verdict[\s\S]*https url/);
});

test('every source link is https and every entry is paraphrased (no long quotes)', () => {
  for (const x of build('.').entries) {
    const e = JSON.parse(readFileSync(x.file, 'utf8'));
    for (const f of ['claim', 'finding', 'outcome']) {
      for (const q of e[f].match(/"[^"]+"/g) || []) assert.ok(q.split(/\s+/).length < 15, `${x.file} ${f} has a long quote`);
    }
  }
});
