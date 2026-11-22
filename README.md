# The Denial Ledger

A sealed public record of public figures calling footage fake, and whether they were right.

When anything can be generated, anyone caught on camera can say "that's fake." Researchers call
this the liar's dividend. This ledger tracks it case by case: who called what fake, what came out,
and what happened to them afterward.

**Live:** https://selfradiance.github.io/denial-ledger/

## What gets in

- A public figure, campaign, company or government office says a specific video, audio clip or photo is fake or AI-made.
- The claim and the outcome are documented by at least one credible news organization or fact-checker, linked on the entry.
- **Both directions.** Fakes correctly called fake are logged alongside real footage called fake.
- No private individuals. Claims are paraphrased, not quoted at length.
- It's a sample, not a complete list.

Each entry rates the footage itself on a six-step scale, from "the denial was wrong" to "the denial was right":
`confirmed-real`, `likely-real`, `real-disputed-context` (genuine footage, dispute over editing or framing), `unresolved`, `likely-fake`, `confirmed-fake`.
"Likely" means credible analysis points one way but it isn't settled.

## Sealed, append-only

Each entry is one JSON file in `entries/`. Its exact bytes are hashed (SHA-256) and timestamped in
Bitcoin through [OpenTimestamps](https://opentimestamps.org); the receipt lives in `seals/`.

- The site re-hashes every entry in your browser and checks it against its seal. An edited entry shows as broken.
- `npm run build` refuses to build if a sealed entry was changed.
- Mistakes get a correction in `corrections/`, which names the exact sealed version it corrects (`corrects_sha256`) and is sealed too. The original stays.

To check a seal independently: download the entry file and its `.ots` and drop both into opentimestamps.org.

## Working on it

```
npm test            # validation and tamper tests
npm run build       # validate everything, write ledger.json
npm run seal        # seal anything unsealed (needs internet access to the OpenTimestamps calendars), then build
python3 -m http.server   # view at http://localhost:8000
```

Adding a case: create `entries/NNN.json` (copy an existing one for the fields), cite sources, run
`npm run build`, get it fact-checked, then `npm run seal`. Once sealed, never edit it.

The receipt code (`js/sha256.js`, `js/ots.js`) is shared with [Witness Stamp](https://github.com/selfradiance/witness-stamp).

## Found an error or a missing case?

Open an issue with a link to a credible source.

MIT licensed.
