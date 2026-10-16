#!/usr/bin/env python3
"""Joint wire-size search using the checked sparse-base grid, without rerunning it.

Select the fastest multiplication-count base for each row size and rounded
inner block length, then vary interleaving, output length/rate and termination.
All sizes are expectations for the current wire format, not measured proofs.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

import plan_large_iopp as P


def search(path, budget):
    source = json.loads(path.read_text())
    groups = {}
    for candidate in source['candidates']:
        c = candidate['case']
        key = (c['row_log'], c['distance_details']['inner_n'])
        rank = (candidate['encoding_multiplications_per_input'], c['code_storage_bytes'])
        if key not in groups or rank < groups[key][0]:
            groups[key] = (rank, candidate)
    results = []
    fields = ['block_length', 'distance', 'numerical_distance', 'code_storage_bytes',
              'distance_details', 'base_parameters']
    for (_, candidate) in groups.values():
        c = candidate['case']
        p = {key: c[key] for key in fields}
        for out in range(13, c['row_log']):
            for rate_log in range(1, 6):
                # For fixed output/code dimensions, terminal size affects only
                # the BaseFold suffix. Choose its exact expected-byte minimum.
                qb = P.query_count(P.output_distance(out, rate_log), 104)
                term = min(range(6, min(out, 16)), key=lambda t:
                           P.basefold_proof_bytes(out, rate_log, t, qb, [1]))
                case = P.codeswitch_candidate_from_parameters(
                    source['message_log'], c['row_log'], source['threads'], p,
                    output_log=out, output_log_rate=rate_log, terminal_log=term,
                    consume_commitment=True)
                case['estimated_peak_with_margin_bytes'] = math.ceil(case['estimated_live_bytes']*1.15)
                results.append(dict(case=case,
                                    encoding_multiplications_per_input=candidate['encoding_multiplications_per_input'],
                                    terminal_dimensions=candidate['terminal_dimensions'],
                                    recursive_bound=candidate['recursive_bound'],
                                    fits=case['estimated_peak_with_margin_bytes'] <= budget*P.GIB))
    fits = sorted((r for r in results if r['fits']), key=lambda r:r['case']['estimated_proof_bytes'])
    return dict(message_log=source['message_log'], threads=source['threads'], memory_budget_gib=budget,
                base_grid_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                scope=__doc__, output_log_min=13, output_rate_logs=list(range(1,6)),
                terminal_logs='6 through min(output_log-1,15)',
                candidates_checked=len(results), base_groups=len(groups),
                chosen=fits[0] if fits else None,
                best_by_row=[min((r for r in results if r['case']['row_log']==row and r['fits']),
                                 key=lambda r:r['case']['estimated_proof_bytes'], default=None)
                             for row in sorted({c[0] for c in groups})],
                best_unconstrained=min(results,key=lambda r:r['case']['estimated_proof_bytes']),
                best_fitting=fits[:20], candidates=results)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_grid',type=Path)
    parser.add_argument('output',type=Path)
    parser.add_argument('--memory-budget-gib',type=float,default=112)
    args=parser.parse_args()
    result=search(args.base_grid,args.memory_budget_gib)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    for item in result['best_by_row']+[result['best_unconstrained']]:
        if item:
            c=item['case']
            print({k:c[k] for k in ['eta','row_log','output_log','output_log_rate','terminal_log','queries','terminal_queries','estimated_proof_bytes']},
                  'GiB',c['estimated_peak_with_margin_bytes']/P.GIB,'fits',item['fits'],flush=True)
