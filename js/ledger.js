import { sha256, toHex } from './sha256.js';
import { readOts } from './ots.js';

// The scale runs from "the footage was real" (the denial was wrong) to "the footage was fake" (the denial was right).
const VERDICTS = {
  'confirmed-real': { label: 'Confirmed real', short: 'Confirmed real', color: '#9e2a20' },
  'likely-real': { label: 'Likely real', short: 'Likely real', color: '#d4685d' },
  'real-disputed-context': { label: 'Real footage, framing disputed', short: 'Real, framing disputed', color: '#c98b2b' },
  'unresolved': { label: 'Unresolved', short: 'Unresolved', color: '#8a867d' },
  'likely-fake': { label: 'Likely fake', short: 'Likely fake', color: '#5fa77a' },
  'confirmed-fake': { label: 'Confirmed fake', short: 'Confirmed fake', color: '#24683f' },
};
const MEDIA = { video: 'Video', audio: 'Audio', photo: 'Photo' };

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = (u) => (/^https:\/\//.test(u) ? u : '#');

async function fetchBytes(path) {
  const r = await fetch(path, { cache: 'no-cache' });
  if (!r.ok) throw new Error(path + ': HTTP ' + r.status);
  return new Uint8Array(await r.arrayBuffer());
}

// Check a record's bytes against its seal, right here in the browser.
async function checkSeal(bytes, sealPath) {
  const hash = toHex(sha256(bytes));
  let sealBytes;
  try { sealBytes = await fetchBytes(sealPath); } catch { return { hash, state: 'unsealed' }; }
  try {
    const { digest, proofs } = readOts(sealBytes);
    if (toHex(digest) !== hash) return { hash, state: 'broken' };
    return { hash, state: proofs.bitcoin.length ? 'bitcoin' : 'pending' };
  } catch {
    return { hash, state: 'broken' };
  }
}

function sealHtml(file, sealPath, s) {
  const status = {
    bitcoin: '<span class="ok">Sealed in Bitcoin. Unchanged.</span>',
    pending: '<span class="ok">Sealed. Unchanged.</span> <span class="wait">Bitcoin confirmation pending.</span>',
    unsealed: '<span class="wait">Not sealed yet.</span>',
    broken: '<span class="bad">Seal broken: this file was changed after sealing.</span>',
  }[s.state];
  const links = s.state === 'unsealed'
    ? `<a href="${file}" download>entry file</a>`
    : `<a href="${file}" download>entry file</a> <a href="${sealPath}" download>seal (.ots)</a>`;
  return `<div class="seal">${status}<span title="${s.hash}">sha256 ${s.hash.slice(0, 16)}…</span>${links}</div>`;
}

function entryHtml(e, seal, file, sealPath, corrections) {
  const v = VERDICTS[e.verdict];
  const sources = e.sources.map((s) => `<li><a href="${esc(safeUrl(s.url))}" target="_blank" rel="noopener">${esc(s.title)}</a>, ${esc(s.publisher)}${s.date ? ', ' + esc(s.date) : ''}</li>`).join('');
  const corr = corrections.map((c) => `
    <div class="correction"><b>Correction, ${esc(c.data.added)}</b>
      <p style="margin:6px 0">${esc(c.data.note)}</p>
      ${c.data.verdict ? `<p style="margin:6px 0">Verdict changed to: <strong>${esc(VERDICTS[c.data.verdict]?.label || c.data.verdict)}</strong></p>` : ''}
      ${sealHtml(c.file, c.sealPath, c.seal)}
    </div>`).join('');
  return `
  <article class="entry" data-verdict="${e.verdict}" style="--c:${v.color}">
    <div class="meta"><span>#${esc(e.id)}</span><span>${esc(e.claim_date)}</span><span>${esc(e.country)}</span><span>${MEDIA[e.media] || esc(e.media)}</span></div>
    <h2>${esc(e.subject)}</h2>
    <p class="by">Called fake by: ${esc(e.called_fake_by)}</p>
    <span class="verdict">Footage: ${v.label}</span>
    <dl>
      <dt>The claim</dt><dd>${esc(e.claim)}</dd>
      <dt>What came out</dt><dd>${esc(e.finding)}</dd>
      <dt>What happened</dt><dd>${esc(e.outcome)}</dd>
    </dl>
    <ul class="sources">${sources}</ul>
    ${sealHtml(file, sealPath, seal)}
    ${corr}
  </article>`;
}

let filter = null;

function renderScore(entries) {
  const counts = Object.fromEntries(Object.keys(VERDICTS).map((k) => [k, 0]));
  for (const e of entries) counts[e.verdict]++;
  $('score').innerHTML = Object.entries(VERDICTS).map(([k, v]) =>
    `<button class="tile${filter === k ? ' on' : ''}" data-k="${k}" style="--c:${v.color}"><b>${counts[k]}</b><span>${v.short}</span></button>`).join('');
  $('bar').innerHTML = Object.entries(VERDICTS).filter(([k]) => counts[k])
    .map(([k, v]) => `<i style="flex:${counts[k]};background:${v.color}"></i>`).join('');
  $('barnote').textContent = filter ? 'Showing one kind. Tap it again to show all.' : `${entries.length} entries. Tap a box to filter.`;
  document.querySelectorAll('.tile').forEach((t) => t.addEventListener('click', () => {
    filter = filter === t.dataset.k ? null : t.dataset.k;
    renderScore(entries);
    document.querySelectorAll('.entry').forEach((a) => { a.hidden = filter && a.dataset.verdict !== filter; });
  }));
}

async function main() {
  const ledger = JSON.parse(new TextDecoder().decode(await fetchBytes('ledger.json')));
  const load = async (x) => {
    const bytes = await fetchBytes(x.file);
    return { data: JSON.parse(new TextDecoder().decode(bytes)), file: x.file, sealPath: x.seal, seal: await checkSeal(bytes, x.seal) };
  };
  const [entries, corrections] = await Promise.all([
    Promise.all(ledger.entries.map(load)),
    Promise.all(ledger.corrections.map(load)),
  ]);
  // A correction can change the verdict shown in the scoreboard; the original entry stays as sealed.
  const effective = entries.map((e) => {
    const latest = corrections.filter((c) => c.data.corrects === e.data.id && c.data.verdict).pop();
    return { ...e.data, verdict: latest ? latest.data.verdict : e.data.verdict };
  });
  renderScore(effective);
  const newestFirst = entries.map((e, i) => ({ e, v: effective[i] })).sort((a, b) => b.v.claim_date.localeCompare(a.v.claim_date));
  $('list').innerHTML = newestFirst.map(({ e, v }) =>
    entryHtml(v, e.seal, e.file, e.sealPath, corrections.filter((c) => c.data.corrects === e.data.id))).join('');
}

main().catch((err) => { $('list').innerHTML = `<p class="empty">Couldn't load the ledger: ${esc(err.message)}</p>`; });
