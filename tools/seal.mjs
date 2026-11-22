// Seal every record that doesn't have a receipt yet, using public OpenTimestamps calendars.
// Needs internet access to the calendars. Run: node tools/seal.mjs && node tools/build.mjs
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { readRecords } from './lib.mjs';
import { submitToCalendars } from '../js/ots.js';
import { fromHex } from '../js/sha256.js';

for (const kind of ['entries', 'corrections']) {
  mkdirSync(`seals/${kind}`, { recursive: true });
  for (const r of readRecords(kind)) {
    const out = `seals/${kind}/${r.name.replace(/\.json$/, '.ots')}`;
    if (existsSync(out)) continue;
    const { ots, calendars } = await submitToCalendars(fromHex(r.sha256));
    writeFileSync(out, ots);
    console.log(`sealed ${kind}/${r.name} (${calendars.length} calendars)`);
  }
}
