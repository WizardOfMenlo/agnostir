#!/usr/bin/env python3
"""Assemble an immutable submission tree without touching the Git index."""
import hashlib,json,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
def copy(source,target=None):
    source=Path(source);target=OUT/(target or source.relative_to(ROOT))
    target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
for name in ['Cargo.toml','Cargo.lock','LICENSE','AI_DISCLOSURE.md','Dockerfile','.dockerignore','requirements-analysis.txt','proof-size-estimate.py','precomputed_distances.txt']:
    copy(ROOT/name)
for directory in ['src','benches','artifact','distance-analysis']:
    for path in sorted((ROOT/directory).rglob('*')):
        if path.is_file() and path.suffix not in ['.pyc'] and path.name not in ['.DS_Store','package.py','paper.pdf'] and '__pycache__' not in path.parts:
            copy(path)
for name in ['calibrate_interleaved.py','audit_distances.py','calibrate_custom.py','plan_large_iopp.py','run_large_iopp_plan.py','test_large_iopp_plan.py','check_era_sparse_base.py','search_era_base.py','search_era_joint.py','summarize_iopp_profile.py']:
    copy(ROOT/'scripts'/name)
readme=(ROOT/'artifact/README.md').read_text()
for name in ['paper-map.md','results.md','changes.md','submission.json','parameters.md','validation.md','THIRD_PARTY.md']:
    readme=readme.replace(f']({name})',f'](artifact/{name})')
readme=readme.replace('see THIRD_PARTY.md','see artifact/THIRD_PARTY.md')
readme=readme.replace('](../AI_DISCLOSURE.md)','](AI_DISCLOSURE.md)')
readme=readme.replace('](../LICENSE)','](LICENSE)')
(OUT/'README.md').write_text(readme)
copy(ROOT/'artifact/paper.pdf',Path('paper/paper.pdf'))
# Retain compact raw measurements; full random proof payloads live in a separate archive.
for path in (ROOT/'artifact_results/2026-10-14-prime-four').iterdir():
    if path.is_file() and path.suffix in ['.csv','.json','.txt','.log'] and path.name not in ['clippy.log']:
        copy(path,Path('evidence/paper22')/path.name)
for rootname,label in [('2026-10-15-aws-r7a4x-n28','interleaved28'),('2026-10-16-era-compact','codeswitch28'),('2026-10-16-submission-validation','container-validation')]:
    base=ROOT/'artifact_results'/rootname
    for path in sorted(base.rglob('*')):
        rel=path.relative_to(base)
        if not path.is_file() or path.suffix not in ['.csv','.json','.txt','.log'] or 'local-validation' in rel.parts:continue
        if label=='interleaved28' and any(x.startswith(('era-codeswitch-','basefold-local-')) for x in rel.parts):continue
        if label=='interleaved28' and path.name=='results.json':
            target=OUT/'evidence'/label/rel;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text(json.dumps([r for r in json.loads(path.read_text()) if r['protocol'].startswith('interleaved-')],indent=2)+'\n');continue
        copy(path,Path('evidence')/label/rel)
for path in (ROOT/'artifact_results/2026-10-15-proof-size-audit').rglob('*'):
    if path.is_file() and path.suffix in ['.json','.csv','.md','.py']:copy(path,Path('evidence/proof-size-audit')/path.relative_to(ROOT/'artifact_results/2026-10-15-proof-size-audit'))
version={'version':json.loads((ROOT/'artifact/submission.json').read_text())['version'],'git_base':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'git_status':subprocess.check_output(['git','status','--short'],cwd=ROOT,text=True),'note':'Includes uncommitted source. Git base alone is not this release; SHA256SUMS identifies the exact files.','rust_source_sha256':{str(p.relative_to(OUT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((OUT/'src').rglob('*.rs'))}}
(OUT/'SOURCE_VERSION.json').write_text(json.dumps(version,indent=2)+'\n')
subprocess.run([sys.executable,'-B',str(OUT/'artifact/validate.py'),'manifest',str(OUT)],check=True)
subprocess.run([sys.executable,'-B',str(OUT/'artifact/validate.py'),'evidence',str(OUT)],check=True)
print(OUT)
