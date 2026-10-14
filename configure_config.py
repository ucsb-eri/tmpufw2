#!/usr/bin/python3
"""Create unified config or migrate prior email settings without overwriting it."""
import json
import os
from pathlib import Path

target = Path('/etc/tmpufw/config.json')
if target.exists():
    raise SystemExit(0)
config = json.loads(Path(__file__).with_name('config.example.json').read_text())
previous = Path('/etc/tmpufw/notifications.json')
legacy = Path('/etc/tmpufw.json')
if previous.exists():
    config['notifications'] = json.loads(previous.read_text())
elif legacy.exists():
    old = json.loads(legacy.read_text())
    config['notifications']['channels']['email'].update(
        enabled=bool(old.get('email_to')), to=old.get('email_to', []),
        **{'from': old.get('email_from', 'tmpufw@localhost')})
try:
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    raise SystemExit(0)
with os.fdopen(fd, 'w') as stream:
    json.dump(config, stream, indent=2)
    stream.write('\n')
print('Created /etc/tmpufw/config.json; previous configuration files preserved.')
