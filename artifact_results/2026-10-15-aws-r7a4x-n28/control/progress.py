import datetime
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
def read(name):
    path = root/name
    return path.read_text().strip() if path.exists() else None

report = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
              phase=read('phase.txt'), started_at=read('started-at.txt'),
              exit_code=read('campaign.exit'), ended_at=read('ended-at.txt'))
report['meminfo'] = {line.split(':')[0]: line.split(':')[1].strip()
                     for line in Path('/proc/meminfo').read_text().splitlines()
                     if line.split(':')[0] in ['MemTotal','MemAvailable','SwapTotal','SwapFree']}
report['processes'] = []
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        args = path.read_bytes().decode().rstrip('\0').split('\0')
        if not args or Path(args[0]).name not in ['interleaved_iopp','compare_iopps','cargo','rustc']:
            continue
        status = (path.parent/'status').read_text().splitlines()
        memory = {s.split(':')[0]: s.split(':')[1].strip()
                  for s in status if s.startswith(('VmRSS:','VmHWM:','Threads:'))}
        report['processes'].append(dict(pid=int(path.parent.name), arguments=args if Path(args[0]).name in ['interleaved_iopp','compare_iopps'] else args[:2], **memory))
    except (OSError, UnicodeDecodeError):
        pass
for stage in ['full']:
    log = read(stage+'-run.log')
    report[stage+'_latest'] = log.splitlines()[-1] if log else None
    summary = root/'results'/'full-n28'/'summary.json'
    report[stage+'_completed'] = json.loads(summary.read_text()) if summary.exists() else []
print(json.dumps(report, indent=2))
