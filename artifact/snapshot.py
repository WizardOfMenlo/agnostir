#!/usr/bin/env python3
"""Capture the exact source used by a local small benchmark, including dirty files."""
import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
output = Path(sys.argv[1]).resolve()
files = []
for name in ['Cargo.toml', 'Cargo.lock', 'LICENSE', 'AI_DISCLOSURE.md', 'README.md',
             'Dockerfile', 'requirements-analysis.txt', 'SOURCE_VERSION.json',
             'src', 'benches', 'scripts', 'distance-analysis', 'artifact']:
    path = root / name
    for item in sorted(path.rglob('*')) if path.is_dir() else [path]:
        if (item.is_file() and not item.is_symlink()
                and '__pycache__' not in item.parts and item.suffix not in ['.pyc', '.pdf']):
            files.append(item)
manifest = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in files}
with tarfile.open(output / 'source.tar.gz', 'x:gz') as archive:
    for path in files:
        archive.add(path, arcname=path.relative_to(root), recursive=False)
metadata = {'files_sha256': manifest, 'note': 'This snapshot includes uncommitted source.'}
for key, command in [('git_base', ['git', 'rev-parse', 'HEAD']),
                     ('git_status', ['git', 'status', '--short'])]:
    try:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
        metadata[key] = result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        metadata[key] = None
(output / 'source-provenance.json').write_text(json.dumps(metadata, indent=2) + '\n')
