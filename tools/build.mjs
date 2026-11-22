// Validate every record and write ledger.json, the index the site reads.
// Refuses to build if any sealed record was edited.
import { writeFileSync } from 'node:fs';
import { readRecords, validateEntry, validateCorrection, sealState } from './lib.mjs';

export function build(root = '.') {
  const entries = readRecords(`${root}/entries`);
  const corrections = readRecords(`${root}/corrections`);
  const errs = [];
  for (const r of entries) errs.push(...validateEntry(r.data, r.name));
  const byId = new Map(entries.map((r) => [r.data.id, r]));
  for (const r of corrections) errs.push(...validateCorrection(r.data, r.name, byId));
  if (errs.length) throw new Error('Ledger has problems:\n- ' + errs.join('\n- '));

  const item = (kind) => (r) => ({ id: r.data.id, file: `${kind}/${r.name}`, sha256: r.sha256, seal: `seals/${kind}/${r.name.replace(/\.json$/, '.ots')}`, ...sealState(root, kind, r) });
  return {
    name: 'The Denial Ledger',
    entries: entries.map(item('entries')),
    corrections: corrections.map(item('corrections')),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const ledger = build('.');
  writeFileSync('ledger.json', JSON.stringify(ledger, null, 2) + '\n');
  const unsealed = [...ledger.entries, ...ledger.corrections].filter((x) => x.state === 'unsealed').length;
  console.log(`ledger.json: ${ledger.entries.length} entries, ${ledger.corrections.length} corrections, ${unsealed} not yet sealed`);
}
