import sys
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
files = list(root.glob('*'))
for name in ['results', 'control']:
    files.extend((root/name).rglob('*'))
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as archive:
    for file in sorted(files):
        if file.is_file() and file.suffix not in ['.proof', '.bin', '.gz', '.pyc']:
            archive.add(file, arcname=file.relative_to(root), recursive=False)
