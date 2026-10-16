import json,math,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import plan_large_iopp as P


def expected(log,row_log,out_log,inner_k,inner_n,q,qb,rate_log=3,term_log=12):
    k=1<<row_log;n=1<<log;h=1<<(log-row_log);width=1<<out_log
    base=inner_n**2;length=4*base;generator=inner_n*inner_k;rate=1<<rate_log
    g,m,b,ell=[P.ceildiv(x,width) for x in [generator,k,base,length]]
    index,online=g+4*ell,m+b+2*ell;rows=index+online
    claims=2*m+online+2*b+2*g+6*ell;d=(length-1).bit_length()
    fields=(3*log+m+online+1+b+4*row_log+3+2*g+m+8+16*d+2*d*(d-1)+6+b+6*ell+4*out_log+rows)
    initial_fields=32*h*P.distinct(length,q)
    initial_hashes=32*P.authentication_hashes(length,q)
    source_fields=64*P.distinct(rate*width//2,qb)*rows
    source_hashes=64*P.authentication_hashes(rate*width//2,qb)
    terminal=P.basefold_proof_bytes(out_log,rate_log,term_log,qb,[index,online])
    total=72+32*fields+initial_fields+initial_hashes+terminal
    # Same conservative memory formula as the saved planner; sparse storage
    # below is for our current eta=8 base and only used for that comparison.
    storage=P.brakedown_storage(inner_k,.058,1.09,7,16,'zero-pad')+80*length
    setup=storage+32*index*width*(rate+1)+64*rate*width+64*P.power_ceiling(rate*width)
    resident=32*(n+h*length)+64*P.power_ceiling(length)+setup
    scratch=min(h,16)*32*(2*length+k)
    online_live=32*(online*width*(rate+1)+rows*width+k+base+3*length)
    gkr=32*(16*P.power_ceiling(length)+17*P.power_ceiling(length)//2+claims*width)
    reduction=32*((3*claims+rows)*width+3*rate*width)
    memory=(resident+max(64*n,scratch,online_live+max(gkr,reduction)))*1.15
    return dict(log=log,row_log=row_log,output_log=out_log,eta=log-row_log,queries=q,terminal_queries=qb,
                index_rows=index,online_rows=online,initial_fields=initial_fields,initial_hashes=initial_hashes,
                source_fields=source_fields,source_hashes=source_hashes,
                other_terminal=terminal-source_fields-source_hashes,other_messages=72+32*fields,
                total_bytes=total,estimated_peak_with_margin_gib=memory/2**30)

plan_path = Path(__file__).with_name('sparse-base-plan.json')
if not plan_path.exists():
    plan_path = ROOT/'artifact_results/2026-10-15-era-sparse-base/plan.json'
p=json.loads(plan_path.read_text())['results']['28']['codeswitching']['protocols']['era-codeswitch']['best']
current=expected(28,20,15,1024,1116,887,147)
assert abs(current['total_bytes']-p['estimated_proof_bytes'])<1e-6
variants=[]
for out_log in range(15,20):
    delta=math.floor(P.BF.distance_for_setup_bits(P.FIELD_LOG,8,out_log,102)*1e6)/1e6
    variants.append(dict(terminal_distance=delta,**expected(28,20,out_log,1024,1116,887,P.query_count(delta,104))))
paper_runtime=expected(32,26,25,8192,9011,830,154)
paper_runtime.pop('estimated_peak_with_margin_gib') # storage above uses different base parameters
report=dict(current=current,output_length_variants=variants,paper_dimensions_current_protocol_paper_queries=paper_runtime)
print(json.dumps(report,indent=2))
