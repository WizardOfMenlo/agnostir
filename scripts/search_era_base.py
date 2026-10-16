#!/usr/bin/env python3
"""Search sparse Brakedown tensor bases with no RS and numerical ERA distance > 0.2.

Uses Habock's per-support finite-size union bounds at every recursive level.
The terminal code is x -> (x,0), with exact absolute distance ONE. ERA uses the
existing numerical CalcDist solver, not a new all-roots or FS certificate.
"""
import argparse
import json
import math
from pathlib import Path
import plan_large_iopp as P


def encoding_cost(k, alpha, inverse_rate, cn, dn):
    n, child = int(k*inverse_rate), math.ceil(alpha*k)
    child_n = int(child*inverse_rate)
    parity = n-k-child_n
    if parity < 0:
        raise ValueError('negative rounded parity dimension')
    if k <= 32 or child < cn or parity < dn:
        return 0, [k,n]
    cost, leaf = encoding_cost(child, alpha, inverse_rate, cn, dn)
    return k*cn+child_n*dn+cost, leaf


def minimum_degree(n, m, first, last, output_weight, bits):
    if m < 1:
        return None
    def passes(d):
        return P.BD.matrix_check(n,m,d,first,last,output_weight,P.BD.SECP256K1_SCALAR,bits)['passes']
    if not passes(m):
        return None
    lo, hi = 1,m
    while lo < hi:
        mid=(lo+hi)//2
        if passes(mid): hi=mid
        else: lo=mid+1
    return lo


def reverse_distance(length, target):
    # First bracket the field-size and gamma < base-distance constraints.
    lo, hi = 1e-9, .05
    for _ in range(24):
        mid=(lo+hi)/2
        c=P.ERA.compute_c_from_q_bound(4,P.SETUP_BITS,mid,math.log2(length),P.FIELD_LOG)
        feasible=c is not None and P.ERA.compute_gamma_from_n_bound(4,c,P.SETUP_BITS,math.log2(length)) < mid
        if feasible: hi=mid
        else: lo=mid
    # Leave a 5% margin on the INNER distance and round UP; check the resulting
    # ERA distance explicitly, so no monotonicity of CalcDist is assumed here.
    inner=math.ceil(math.sqrt(hi)*1.05*1e5)/1e5
    delta, details=P.era_distance(length,inner*inner)
    if delta <= target:
        raise ValueError('this feasibility-derived candidate misses target ERA distance')
    return inner, delta, dict(tensor_feasibility_threshold=hi, **details)


def search(log, threads, budget):
    if log < 16 or threads < 1 or budget <= 0:
        raise ValueError('require message_log >= 16, positive threads and memory budget')
    candidates=[]
    row_logs=[r for r in [16,18,20,22,24] if r <= log]
    rates=[1.025,1.03,1.035,1.04,1.045,1.05,1.06,1.075,1.09,1.1,1.125,1.15,1.175,1.2,1.25,1.3,1.4,1.5]
    for row_log in row_logs:
        k=1 << (row_log//2)
        for rate in rates:
            n=int(k*rate); length=4*n*n
            inner,delta,details=reverse_distance(length,.2)
            for ai in range(4,121):
                alpha=ai/1000
                if not inner<alpha<1-1/rate:
                    continue
                child=math.ceil(alpha*k); child_n=int(child*rate); parity=n-k-child_n
                bits=P.SETUP_BITS+math.ceil(math.log2(4*P.BD.recursion_bound(k,alpha)))
                cn=minimum_degree(k,child,1,math.floor(inner*n),0,bits)
                dn=minimum_degree(child_n,parity,math.floor(inner*child_n)+1,math.floor(inner*n),inner*(n-child_n),bits)
                if cn is None or dn is None:
                    continue
                try:
                    cost,leaf=encoding_cost(k,alpha,rate,cn,dn)
                    check=P.BD.check_recursive(k,alpha,rate,inner,cn,dn,security=P.SETUP_BITS,base_case='zero-pad')
                except ValueError:
                    continue
                if not check['bound_passes'] or check['events']==0:
                    continue
                base=dict(alpha=alpha,inverse_rate=rate,cn=cn,dn=dn,base_case='zero-pad')
                p=dict(block_length=length,distance=math.floor(delta*1e6)/1e6,numerical_distance=delta,
                       code_storage_bytes=P.brakedown_storage(k,alpha,rate,cn,dn,'zero-pad')+80*length,
                       distance_details=dict(inner_k=k,inner_n=n,inner_distance=inner,**details),
                       base_parameters=base)
                case=P.codeswitch_candidate_from_parameters(log,row_log,threads,p)
                case['estimated_peak_with_margin_bytes']=math.ceil(case['estimated_live_bytes']*1.15)
                candidates.append(dict(case=case,inner_multiplications=cost,terminal_dimensions=leaf,
                                       encoding_multiplications_per_input=(cost*(k+n)+2*length)/(k*k),
                                       recursive_bound=check, fits=case['estimated_peak_with_margin_bytes'] <= budget*(1<<30)))
        print(f'row_log={row_log}: {len(candidates)} passing candidates so far',flush=True)
    # Optimize encoding operation count within each row size, then choose eta
    # by estimated proof size among those fast bases that fit the machine.
    fastest=[]
    for row_log in row_logs:
        options=[c for c in candidates if c['case']['row_log']==row_log and c['fits']]
        if options:
            fastest.append(min(options,key=lambda c:(c['encoding_multiplications_per_input'],c['case']['estimated_proof_bytes'])))
    if not fastest:
        raise ValueError('no passing candidate fits the specified memory budget')
    chosen=min(fastest,key=lambda c:c['case']['estimated_proof_bytes'])
    return dict(message_log=log,threads=threads,memory_budget_gib=budget,target_era_distance_strictly_above=.2,
                scope='Numerical sufficient ideal-ensemble bounds; ERA CalcDist is not an all-roots certificate. '
                      'Finite parameter grid, minimum root degrees, then full recursion checks. '
                      'Fastest multiplication-count base per row size, then minimum expected proof size.',
                rates=rates,alpha_grid=[.004,.120,.001],candidates_checked_and_passing=len(candidates),
                fastest_by_row=fastest,chosen=chosen,candidates=candidates)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('output',type=Path)
    p.add_argument('--message-log',type=int,default=28)
    p.add_argument('--threads',type=int,default=16)
    p.add_argument('--memory-budget-gib',type=float,default=112)
    args=p.parse_args()
    result=search(args.message_log,args.threads,args.memory_budget_gib)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    print(json.dumps(result['chosen'],indent=2))

if __name__=='__main__':
    main()
