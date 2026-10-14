#!/usr/bin/python3
"""Apply root-owned tmpufw cleanup settings during installation."""
import importlib.util
from pathlib import Path
import subprocess

root = Path(__file__).parent
spec = importlib.util.spec_from_file_location('tmpufw', root / 'tmpufw.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
cleanup = m.settings().get('cleanup', {})
schedule = cleanup.get('schedule', '*-*-* *:*:00')
accuracy = cleanup.get('accuracy_seconds', 1)
if not isinstance(schedule, str) or not schedule or '\n' in schedule or '\r' in schedule:
    raise SystemExit('Invalid cleanup schedule')
if isinstance(accuracy, bool) or not isinstance(accuracy, int) or accuracy < 1:
    raise SystemExit('cleanup accuracy_seconds must be a positive integer')
subprocess.run(['/usr/bin/systemd-analyze', 'calendar', schedule], check=True, capture_output=True)
text = (root / 'systemd/tmpufw-clean.timer').read_text()
text = text.replace('OnCalendar=*-*-* *:*:00', 'OnCalendar=' + schedule)
text = text.replace('AccuracySec=1s', 'AccuracySec=' + str(accuracy) + 's')
path = Path('/etc/systemd/system/tmpufw-clean.timer')
path.write_text(text)
path.chmod(0o644)
