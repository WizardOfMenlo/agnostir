import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIB = 1 << 30
mode = sys.argv[1]
plan = json.loads((ROOT/'artifact_results/2026-10-15-aws-r7a4x-n28/plan.json').read_text())

if mode == 'identity':
    records = []
    for name in ['era-corrected.proof', 'basefold-local.proof']:
        actual = ROOT/'results/default-identity/proofs'/name
        reference = ROOT/'artifact_results/2026-10-15-iopp-optimized/before/proofs'/name
        assert actual.read_bytes() == reference.read_bytes(), name
        records.append(dict(proof=name, bytes=actual.stat().st_size,
                            sha256=hashlib.file_digest(actual.open('rb'), 'sha256').hexdigest(),
                            byte_identical_to_mac_reference=True))
    (ROOT/'identity-validation.json').write_text(json.dumps(records, indent=2)+'\n')
elif mode == 'full':
    size = 28
    directory = ROOT/f'results/{mode}-n{size}'
    environment = json.loads((directory/'environment.json').read_text())
    assert environment['threads'] == 16 and environment['warmups'] == environment['samples'] == 1
    assert environment['instance_type'] == 'r7a.4xlarge'
    results = json.loads((directory/'summary.json').read_text())
    assert len(results) == 6 and len({r['protocol'] for r in results}) == 6
    checked = []
    for result in results:
        protocol = result['protocol']
        assert result['exit_code'] == 0 and result['peak_rss_bytes'] > 0
        group = 'interleaved' if protocol.startswith('interleaved-') else 'codeswitching'
        case = plan['results'][str(size)][group]['protocols'][protocol]['best']
        run = directory/f'{protocol}-n{size}-eta{case["eta"]}'
        rows = list(csv.DictReader((run/'timings.csv').open()))
        assert len(rows) == 1 and rows[0]['accepted'] == 'true'
        assert int(rows[0]['proof_bytes']) == result['proof_bytes']
        record = dict(protocol=protocol, message_log=size, eta=case['eta'],
                      proof_bytes=result['proof_bytes'], peak_rss_gib=result['peak_rss_bytes']/GIB,
                      setup_seconds=float(rows[0]['setup_ms'])/1000,
                      commit_seconds=float(rows[0]['commit_ms'])/1000,
                      evaluation_prover_seconds=float(rows[0]['prove_ms'])/1000,
                      total_prover_seconds=(float(rows[0]['commit_ms'])+float(rows[0]['prove_ms']))/1000,
                      verifier_seconds=float(rows[0]['verify_ms'])/1000,
                      estimated_proof_relative_error=result['estimate_relative_error'])
        checked.append(record)
    (ROOT/f'{mode}-validation.json').write_text(json.dumps(checked, indent=2)+'\n')
    print(json.dumps(checked, indent=2))
else:
    raise ValueError(mode)
