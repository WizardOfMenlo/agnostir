#!/usr/bin/env python3
"""Execute a proof-size-optimized plan sequentially and record peak process RSS.

Build both release binaries first. Query counts come from the saved plan;
custom-size executions do not inherit a claim of certified soundness.
"""
import argparse
import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIB = 1 << 30
PROTOCOLS = ['interleaved-era', 'interleaved-basefold', 'interleaved-brakedown',
             'interleaved-ea', 'era-codeswitch', 'basefold-local']


def command(case, out, args, profiled):
    common = ['--threads', str(args.threads), '--samples', str(args.samples),
              '--warmups', str(args.warmups), '--message-log', str(case['message_log']),
              '--eta', str(case['eta'])]
    protocol = case['protocol']
    if protocol.startswith('interleaved-'):
        return [str(ROOT/'target/release/interleaved_iopp'), *common, '--csv',
                '--code', protocol.removeprefix('interleaved-'),
                '--distance', str(case['distance']), '--queries', str(case['queries']),
                '--proof-out', str(out/'proof.bin')]
    # --eta controls ERA. BaseFold has an independent --basefold-eta argument.
    if protocol == 'basefold-local':
        common[-2:] = ['--basefold-eta', str(case['eta'])]
    cmd = [str(ROOT/'target/release/compare_iopps'), *common, '--custom-parameters',
           '--protocol', 'era' if protocol == 'era-codeswitch' else protocol,
           '--terminal-log', str(case['terminal_log']), '--proof-dir', str(out/'proofs')]
    if protocol == 'era-codeswitch':
        if case.get('consume_commitment', False):
            cmd += ['--consume-era-commitment']
        cmd += ['--output-log', str(case['output_log']), '--era-queries', str(case['queries']),
                '--output-log-rate', str(case.get('output_log_rate', 3)),
                '--terminal-queries', str(case['terminal_queries'])]
        if 'base_parameters' in case:
            base = case['base_parameters']
            for name in ['alpha', 'inverse_rate', 'cn', 'dn', 'base_case']:
                option = 'case' if name == 'base_case' else name.replace('_', '-')
                cmd += ['--era-base-' + option, str(base[name])]
    else:
        cmd += ['--basefold-queries', str(case['queries'])]
    if profiled:
        cmd += ['--profile-out', str(out/'stages.csv')]
        if protocol == 'era-codeswitch':
            cmd += ['--verify-profile-out', str(out/'verifier-stages.csv')]
    return cmd


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('plan', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--logs', nargs='+', type=int, help='default: each experiment\'s maximum fitting log')
    p.add_argument('--experiment', choices=['both','interleaved','codeswitching'], default='both')
    p.add_argument('--protocols', nargs='+', choices=PROTOCOLS,
                   help='run only these protocols, preserving their planned parameters')
    p.add_argument('--dry-run', action='store_true', help='print selected commands without running or writing files')
    p.add_argument('--threads', type=int, default=16)
    p.add_argument('--samples', type=int, default=1)
    p.add_argument('--warmups', type=int, default=1)
    p.add_argument('--memory-budget-gib', type=float, default=112)
    p.add_argument('--profile', action='store_true', help='also retain codeswitch/BaseFold stage profiles')
    p.add_argument('--instance-type', default='unspecified')
    args = p.parse_args()
    assert args.threads > 0 and args.samples > 0 and args.warmups >= 0
    plan = json.loads(args.plan.read_text())
    assert args.threads == plan['threads'], 'regenerate the memory plan for this worker count'
    selected = []
    groups = ['interleaved', 'codeswitching'] if args.experiment == 'both' else [args.experiment]
    for group in groups:
        for log in args.logs or [plan['maximum_fitting_log'][group]]:
            assert log is not None, f'no fitting size for {group}'
            for case in plan['results'][str(log)][group]['protocols'].values():
                case = case['best']
                assert case is not None
                if args.protocols and case['protocol'] not in args.protocols:
                    continue
                assert case['estimated_peak_with_margin_bytes'] <= args.memory_budget_gib*GIB, (
                    f"{case['protocol']} at 2^{log} exceeds the declared memory budget")
                selected.append(case)
    if not selected:
        p.error('no protocols selected')
    if args.protocols and set(args.protocols) != {c['protocol'] for c in selected}:
        p.error('requested protocols do not all belong to the selected experiment')
    if args.dry_run:
        print(json.dumps([dict(protocol=c['protocol'], message_log=c['message_log'], eta=c['eta'],
                               command=command(c, args.output.resolve()/f"{c['protocol']}-n{c['message_log']}-eta{c['eta']}", args, args.profile))
                          for c in selected], indent=2))
        return
    if sys.platform == 'linux':
        mem = {line.split(':')[0]: int(line.split()[1])*1024
               for line in Path('/proc/meminfo').read_text().splitlines()}
        needed = max(c['estimated_peak_with_margin_bytes'] for c in selected)
        assert needed < mem['MemAvailable'], 'insufficient available RAM for the selected cases'
    elif args.memory_budget_gib > 8:
        raise SystemExit('On this local host pass --memory-budget-gib 8; large runs require the Linux target.')
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output.resolve()
    (out/'plan.json').write_text(json.dumps(plan, indent=2)+'\n')
    environment = dict(platform=platform.platform(), python=sys.version,
                       instance_type=args.instance_type,
                       threads=args.threads, samples=args.samples, warmups=args.warmups,
                       memory_budget_gib=args.memory_budget_gib,
                       rustflags=os.environ.get('RUSTFLAGS',''), profile=args.profile)
    for label, cmd in [('rustc', ['rustc','-Vv']), ('git_head',['git','rev-parse','HEAD']),
                       ('git_status',['git','status','--short'])]:
        result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
        if label == 'rustc':
            result.check_returncode()
        environment[label] = result.stdout.strip() if result.returncode == 0 else None
    provenance = ROOT/'source-provenance.json'
    if provenance.exists():
        environment['source_provenance'] = json.loads(provenance.read_text())
    if sys.platform == 'linux':
        environment['lscpu'] = subprocess.check_output(['lscpu'], text=True)
        environment['meminfo'] = Path('/proc/meminfo').read_text()
    (out/'environment.json').write_text(json.dumps(environment, indent=2)+'\n')
    with tarfile.open(out/'source.tar.gz', 'w:gz') as archive:
        for name in ['Cargo.toml','Cargo.lock','AGENTS.md','README.md','requirements-analysis.txt',
                     'source-provenance.json','source.patch','SOURCE_VERSION.json','LICENSE','AI_DISCLOSURE.md','Dockerfile','artifact',
                     'src','benches','scripts','distance-analysis','docs']:
            path = ROOT/name
            for f in sorted(path.rglob('*')) if path.is_dir() else [path]:
                if f.is_file() and '__pycache__' not in f.parts and f.suffix != '.pyc':
                    archive.add(f, arcname=f.relative_to(ROOT), recursive=False)
    summaries = []
    for case in selected:
        label = f"{case['protocol']}-n{case['message_log']}-eta{case['eta']}"
        directory = out/label
        directory.mkdir()
        cmd = command(case, directory, args, args.profile)
        (directory/'command.json').write_text(json.dumps(cmd, indent=2)+'\n')
        print(f'Running {label}', file=sys.stderr, flush=True)
        with (directory/'timings.csv').open('w') as stdout, (directory/'run.log').open('w') as stderr:
            process = subprocess.Popen(cmd, cwd=ROOT, stdout=stdout, stderr=stderr)
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
        rss = usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024)
        memory = dict(peak_rss_bytes=rss, exit_code=process.returncode,
                      user_seconds=usage.ru_utime, system_seconds=usage.ru_stime)
        (directory/'memory.json').write_text(json.dumps(memory, indent=2)+'\n')
        assert process.returncode == 0, f'{label} failed; inspect its log'
        with (directory/'timings.csv').open() as file:
            rows = list(csv.DictReader(file))
        assert len(rows) == args.samples and all(r['accepted'] == 'true' for r in rows)
        lengths = {int(r['proof_bytes']) for r in rows}
        assert len(lengths) == 1
        proof_bytes = lengths.pop()
        for filename, root_name in [('stages.csv', 'prove'), ('verifier-stages.csv', 'verify')]:
            if not (directory/filename).exists():
                continue
            with (directory/filename).open() as file:
                stages = list(csv.DictReader(file))
            for r in rows:
                sample = [s for s in stages if s['sample'] == r['sample']]
                root, = [s for s in sample if s['path'] == root_name]
                assert sum(int(s['exclusive_bytes']) for s in sample) == proof_bytes
                assert int(root['inclusive_bytes']) == proof_bytes
                assert abs(sum(float(s['exclusive_ms']) for s in sample)
                           - float(root['inclusive_ms'])) < .01
        saved = [directory/'proof.bin'] if case['protocol'].startswith('interleaved-') else list((directory/'proofs').glob('*.proof'))
        assert len(saved) == 1 and saved[0].stat().st_size == proof_bytes
        summary = dict(protocol=case['protocol'], message_log=case['message_log'], eta=case['eta'],
                       estimated_proof_bytes=case['estimated_proof_bytes'], proof_bytes=proof_bytes,
                       estimate_relative_error=(case['estimated_proof_bytes']/proof_bytes-1), **memory)
        summaries.append(summary)
        (out/'summary.json').write_text(json.dumps(summaries, indent=2)+'\n')
    with (out/'SHA256SUMS').open('w') as sums:
        for f in sorted(out.rglob('*')):
            if f.is_file() and f.name != 'SHA256SUMS':
                with f.open('rb') as file:
                    digest = hashlib.file_digest(file, 'sha256').hexdigest()
                sums.write(f'{digest}  {f.relative_to(out)}\n')
    print(json.dumps(summaries, indent=2))


if __name__ == '__main__':
    main()
