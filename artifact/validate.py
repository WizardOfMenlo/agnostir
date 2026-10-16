#!/usr/bin/env python3
"""Verify packaged checksums or accepted regenerated proofs and known hashes."""
import csv
import hashlib
import json
import sys
from pathlib import Path

def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

mode, directory = sys.argv[1:]
root = Path(directory).resolve()
if mode == 'manifest':
    with (root/'SHA256SUMS').open('w') as stream:
        for p in sorted(root.rglob('*')):
            if p.is_file() and p.name != 'SHA256SUMS':
                stream.write(f'{sha(p)}  {p.relative_to(root)}\n')
elif mode == 'evidence':
    count = 0
    for line in (root/'SHA256SUMS').read_text().splitlines():
        expected, name = line.split('  ', 1)
        path = (root/name).resolve()
        assert path.is_relative_to(root), name
        assert sha(path) == expected, name
        count += 1
    print(json.dumps(dict(verified_files=count, manifest='SHA256SUMS')))
elif mode == 'run':
    references = json.loads((Path(__file__).parent/'expected-proofs.json').read_text())
    checked = []
    for path in sorted(root.rglob('*.csv')):
        with path.open() as stream:
            reader = csv.DictReader(stream)
            if not {'accepted', 'proof_bytes', 'commit_ms'}.issubset(reader.fieldnames or []):
                continue
            rows = list(reader)
        assert rows and all(r['accepted'] == 'true' for r in rows), path
        for row in rows:
            protocol = row.get('code', row['protocol'])
            if 'code' in row:
                proof = path.parent/'proof.bin'
                if not proof.exists(): proof = path.parent/f'{protocol}.proof'
            else:
                proof = path.parent/'proofs'/f'{protocol}.proof'
            assert proof.stat().st_size == int(row['proof_bytes']), proof
            digest = sha(proof)
            key = f"{protocol}:n{row['message_log']}:eta{row['eta']}"
            expected = references.get(key)
            if expected: assert digest == expected, (key, digest, expected)
            checked.append(dict(case=key, proof=str(proof.relative_to(root)),
                                bytes=proof.stat().st_size, sha256=digest,
                                matched_reference=expected is not None))
    assert checked, 'No measured proofs'
    (root/'proof-validation.json').write_text(json.dumps(checked, indent=2)+'\n')
    print(json.dumps(dict(verified_rows=len(checked), known_hash_matches=sum(x['matched_reference'] for x in checked))))
else:
    raise SystemExit('Expected manifest, evidence, or run')
