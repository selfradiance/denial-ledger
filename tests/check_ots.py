"""Parse a .ots receipt with the official OpenTimestamps library (test helper)."""
import json
import sys

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile

with open(sys.argv[1], 'rb') as f:
    dtf = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))

atts = [a for _, a in dtf.timestamp.all_attestations()]
pending = [a.uri for a in atts if isinstance(a, PendingAttestation)]
bitcoin = [a.height for a in atts if isinstance(a, BitcoinBlockHeaderAttestation)]
messages = []


def walk(ts):
    messages.append(ts.msg.hex())
    for sub in ts.ops.values():
        walk(sub)


walk(dtf.timestamp)
print(json.dumps({'digest': dtf.file_digest.hex(), 'pending': pending, 'bitcoin': bitcoin, 'messages': messages}))
