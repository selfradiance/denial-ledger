import { varuint } from '../js/ots.js';

const PENDING_TAG = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN_TAG = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

// A realistic fake calendar response: prepend(bytes) -> sha256 -> pending attestation.
export function fakeCalendarResponse(uri, seed = 1) {
  const uriBytes = [...new TextEncoder().encode(uri)];
  const payload = [...varuint(uriBytes.length), ...uriBytes];
  return Uint8Array.from([
    0xf1, 4, seed & 0xff, 2, 3, 4,   // prepend 4 bytes
    0x08,                            // sha256
    0x00, ...PENDING_TAG, ...varuint(payload.length), ...payload,
  ]);
}

// A response that ends in a Bitcoin block attestation.
export function fakeBitcoinResponse(height) {
  const payload = varuint(height);
  return Uint8Array.from([
    0xf0, 2, 9, 9, 0x08,
    0x00, ...BITCOIN_TAG, ...varuint(payload.length), ...payload,
  ]);
}
