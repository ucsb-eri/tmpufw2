#!/usr/bin/python3
"""Temporary UFW rules with persistent expiration."""
import argparse
import contextlib
import datetime as dt
import fcntl
from email.message import EmailMessage
from email.utils import formatdate
import socket
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import uuid

STATE = Path('/var/lib/tmpufw')
UFW = '/usr/sbin/ufw'
UTC = dt.timezone.utc

CONFIG = Path('/etc/tmpufw/config.json')


def settings():
    config = json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    if not isinstance(config, dict) or (config and config.get('version') != 1):
        raise ValueError('Unsupported tmpufw config version')
    defaults = config.get('defaults', {})
    if not isinstance(defaults, dict):
        raise ValueError('defaults must be an object')
    for key in ('position', 'legacy_position'):
        value = defaults.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
            raise ValueError(key + ' must be null or a positive integer')
    if defaults.get('protocol', 'any') not in ('any', 'tcp', 'udp'):
        raise ValueError('Invalid default protocol')
    if defaults.get('direction', 'in') not in ('in', 'out'):
        raise ValueError('Invalid default direction')
    return config


def expiry(ttl=None, until=None):
    now = dt.datetime.now(UTC)
    if ttl is None and until is None:
        ttl = settings().get('defaults', {}).get('ttl', '30d')
        if not isinstance(ttl, str) or not ttl:
            raise ValueError('Default TTL must be a nonempty string')
    if ttl:
        match = re.fullmatch(r'([1-9][0-9]*)(s|m|h|d|w)', ttl)
        if match:
            seconds = int(match[1]) * dict(s=1, m=60, h=3600, d=86400, w=604800)[match[2]]
            end = now + dt.timedelta(seconds=seconds)
        else:
            words = re.fullmatch(r'(?:in )?([1-9][0-9]*) (seconds?|minutes?|hours?|days?|weeks?)', ttl)
            if words:
                end = now + dt.timedelta(**{words[2].rstrip('s') + 's': int(words[1])})
            else:
                try:
                    from parsedatetime import Calendar
                except ImportError:
                    raise ValueError('For expressions such as tomorrow, install python3-parsedatetime')
                local, status = Calendar().parseDT(ttl, sourceTime=now.astimezone().replace(tzinfo=None))
                if not status:
                    raise ValueError('Unrecognized expiration expression')
                end = local.astimezone(UTC)
    else:
        end = dt.datetime.fromisoformat(until.replace('Z', '+00:00'))
        if end.tzinfo is None:
            raise ValueError('Expiration requires a timezone, e.g. 2026-10-14T18:00:00-07:00')
    if end <= now:
        raise ValueError('Expiration must be in the future')
    return end.astimezone(UTC).isoformat()

def run(*args):
    result = subprocess.run([UFW, *args], text=True, capture_output=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout

def tuple_records(text):
    records = []
    for line in text.splitlines():
        if not line.startswith('### tuple ### '):
            continue
        fields = line[len('### tuple ### '):].split()
        comment = ''
        if fields and fields[-1].startswith('comment='):
            comment = fields.pop()[8:]
        if len(fields) not in (7, 9):
            raise RuntimeError('Unrecognized UFW tuple format; refusing mutation')
        # App-expanded tuples have two extra profile names before interfaces.
        key = fields[:6] + [fields[-1]]
        for index in (3, 5):
            key[index] = str(ipaddress.ip_network(key[index], strict=False))
        for index in (2, 4):
            if key[index] != 'any':
                key[index] = ','.join(sorted(key[index].split(','), key=lambda x: int(x.split(':')[0])))
        records.append((key, comment))
    return records


def saved_records():
    rows = []
    for name in ('user.rules', 'user6.rules'):
        path = Path('/etc/ufw') / name
        if path.exists():
            rows.extend(tuple_records(path.read_text()))
    return rows


def tuples():
    return [key for key, comment in saved_records()]


def marked_records(records):
    marked = {}
    for key, comment in records:
        try:
            text = bytes.fromhex(comment).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            continue
        if re.fullmatch(r'tmpufw:[0-9a-f]{32}', text):
            marked.setdefault(text[7:], []).append(key)
    return marked


def reconciliation(data):
    records = saved_records()
    marked = marked_records(records)
    output = run('status', 'numbered')
    active = output.startswith('Status: active')
    live = {}
    for line in output.splitlines():
        match = re.match(r'^\[\s*(\d+)\]', line)
        comment = line.partition('#')[2].strip()
        if match and re.fullmatch(r'tmpufw:[0-9a-f]{32}', comment):
            live.setdefault(comment[7:], []).append(int(match[1]))
    result = {'ufw_active': active, 'rules': {}, 'orphans': {}}
    now = dt.datetime.now(UTC)
    for identifier, item in data.items():
        expected = item.get('expected_keys')
        present = marked.get(identifier, [])
        problems = []
        if not present:
            problems.append('missing')
        if expected is not None and sorted(expected) != sorted(present):
            if present:
                problems.append('changed_or_partial')
            marker = ('tmpufw:' + identifier).encode().hex()
            if any(key in expected and comment != marker for key, comment in records):
                problems.append('changed_comment_or_equivalent_rule')
        if not active:
            problems.append('ufw_inactive')
        elif len(live.get(identifier, [])) != len(present):
            problems.append('saved_live_count_mismatch')
        remaining = int((dt.datetime.fromisoformat(item['expires']) - now).total_seconds())
        if remaining <= 0:
            problems.append('overdue')
        if item['status'] != 'active':
            problems.append(item['status'])
        result['rules'][identifier] = dict(item, remaining_seconds=max(0, remaining),
            saved_entries=len(present), live_numbers=live.get(identifier, []),
            health=problems or ['ok'], verification='full' if expected is not None else 'legacy_presence_only')
    for identifier in set(marked) | set(live):
        if identifier not in data:
            result['orphans'][identifier] = {'saved_entries': len(marked.get(identifier, [])),
                                             'live_numbers': live.get(identifier, [])}
    return result


def install_rule(data, identifier, command):
    try:
        output = run(*command, 'comment', 'tmpufw:' + identifier)
        actual = marked_records(saved_records()).get(identifier, [])
        if 'Skipping' in output or sorted(actual) != sorted(data[identifier]['expected_keys']) or not owned_numbers(identifier):
            raise RuntimeError('Installed rules do not match the complete ownership preview')
        data[identifier]['status'] = 'active'
        save(data)
    except (RuntimeError, OSError) as original:
        # Roll back only this attempt's marked entries. Never delete matching
        # unmarked rules, even if a concurrent administrator changed ownership.
        failed_item = dict(data[identifier], status='rollback_failed')
        data[identifier] = failed_item
        data[identifier]['expires'] = dt.datetime.now(UTC).isoformat()
        try:
            save(data)
            remove(identifier)
            if marked_records(saved_records()).get(identifier):
                raise RuntimeError('Owned entries remain after rollback')
            del data[identifier]
            save(data)
        except (RuntimeError, OSError) as rollback:
            data[identifier] = failed_item
            raise RuntimeError(f'Addition failed: {original}; rollback incomplete: {rollback}; ID {identifier} retained for immediate cleanup retry') from original
        raise RuntimeError(f'Addition failed and its marked entries were rolled back: {original}') from original


def preview_keys(output, identifier):
    marker = ('tmpufw:' + identifier).encode().hex()
    keys = [key for key, comment in tuple_records(output) if comment.lower() == marker]
    if not keys:
        raise RuntimeError('UFW preview lacks ownership tuples; rule may already exist or UFW format is unsupported')
    return keys


def positioned(args, position):
    if not position:
        return args
    if args[0] == 'route':
        return ['route', 'insert', str(position), *args[1:]]
    return ['insert', str(position), *args]


def normalize_address(value, version):
    return str(ipaddress.ip_network(value, strict=False)) if value != 'any' else (
        '0.0.0.0/0' if version == 4 else '::/0')

def port_spec(value):
    value = str(value)
    if value == 'any':
        return value
    for part in value.split(','):
        bounds = part.split(':')
        if len(bounds) > 2 or any(not x.isdigit() or not 1 <= int(x) <= 65535 for x in bounds):
            raise ValueError('Invalid port or port range')
        if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
            raise ValueError('Reversed port range')
    return value


def raw_rule(value):
    tokens = shlex.split(value)
    action_index = 1 if tokens and tokens[0] == 'route' else 0
    if len(tokens) <= action_index or tokens[action_index] not in ('allow', 'deny', 'reject', 'limit'):
        raise ValueError('Rule must start with allow, deny, reject, limit or route ACTION')
    if any(x.startswith('--') or x in ('comment', 'insert', 'prepend', 'delete') for x in tokens):
        raise ValueError('Rule cannot contain command controls or comments; use --position/--note')
    # UFW itself parses the complete rule during the required dry run.
    return tokens, []


def rule_spec(a):
    defaults = settings().get('defaults', {})
    a.proto = a.proto or ('any' if getattr(a, 'app', None) else defaults.get('protocol', 'any'))
    a.direction = a.direction or defaults.get('direction', 'in')
    for value in (a.source, a.destination):
        if value != 'any':
            ipaddress.ip_network(value, strict=False)
    versions = {ipaddress.ip_network(x, strict=False).version
                for x in (a.source, a.destination) if x != 'any'}
    if len(versions) > 1:
        raise ValueError('Source and destination address families differ')
    a.port = port_spec(a.port)
    source_port = port_spec(getattr(a, 'source_port', 'any'))
    keys = []
    for version in versions or {4, 6}:
        keys.append([a.action, a.proto, str(a.port), normalize_address(a.destination, version),
                     source_port, normalize_address(a.source, version), a.direction])
    app = getattr(a, 'app', None)
    incoming = getattr(a, 'in_interface', None)
    outgoing = getattr(a, 'out_interface', None)
    route = getattr(a, 'route', False)
    interface = getattr(a, 'interface', None)
    if interface:
        if incoming or outgoing:
            raise ValueError('Use --interface or --in-interface/--out-interface, not both')
        incoming, outgoing = (interface, None) if a.direction == 'in' else (None, interface)
    if not route and incoming and outgoing:
        raise ValueError('Both interfaces require --route')
    if not route and ((incoming and a.direction != 'in') or (outgoing and a.direction != 'out')):
        raise ValueError('Interface conflicts with direction')
    if app and (a.port != 'any' or source_port != 'any' or a.proto != 'any'):
        raise ValueError('Application profiles cannot be combined with ports or explicit protocol')
    args = (['route'] if route else []) + [a.action]
    if incoming:
        args += ['in', 'on', incoming]
    if outgoing:
        args += ['out', 'on', outgoing]
    if not incoming and not outgoing and not route:
        args += [a.direction]
    if a.proto != 'any':
        args += ['proto', a.proto]
    args += ['from', a.source]
    if source_port != 'any':
        args += ['port', source_port]
    args += ['to', a.destination]
    if app:
        args += ['app', app]
    elif a.port != 'any':
        args += ['port', a.port]
    return args, keys

def owned_numbers(identifier):
    marker = 'tmpufw:' + identifier
    numbers = []
    for line in run('status', 'numbered').splitlines():
        match = re.match(r'^\[\s*(\d+)\]', line)
        if match and line.partition('#')[2].strip() == marker:
            numbers.append(int(match[1]))
    return numbers

def remove(identifier):
    # Re-query after every deletion because UFW renumbers rules, including IPv6.
    while True:
        numbers = owned_numbers(identifier)
        if not numbers:
            return
        run('--dry-run', '--force', 'delete', str(max(numbers)))
        run('--force', 'delete', str(max(numbers)))

def save(data, filename='rules.json'):
    fd, name = tempfile.mkstemp(dir=STATE, prefix='.state-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, STATE / filename)
        directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)

@contextlib.contextmanager
def locked():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = STATE / 'rules.json'
        yield json.loads(path.read_text()) if path.exists() else {}

NOTIFICATION_CONFIG = Path('/etc/tmpufw/notifications.json')
LEGACY_CONFIG = Path('/etc/tmpufw.json')


def email_settings():
    if CONFIG.exists() or NOTIFICATION_CONFIG.exists():
        config = settings().get('notifications', {'version': 1, 'channels': {}}) if CONFIG.exists() else json.loads(NOTIFICATION_CONFIG.read_text())
        if not isinstance(config, dict) or config.get('version') != 1:
            raise ValueError('Unsupported notification config version')
        channels = config.get('channels', {})
        if not isinstance(channels, dict):
            raise ValueError('channels must be an object')
        for name, channel in channels.items():
            if not isinstance(channel, dict):
                raise ValueError('Each notification channel must be an object')
            if name != 'email' and channel.get('enabled', False):
                raise ValueError('Notification channel is not implemented: ' + name)
        email = channels.get('email', {})
        if not isinstance(email, dict) or not isinstance(email.get('enabled', False), bool):
            raise ValueError('email channel must contain a boolean enabled setting')
        if email.get('transport', 'sendmail') != 'sendmail':
            raise ValueError('Only sendmail email transport is currently implemented')
        targets = email.get('to', []) if email.get('enabled', False) else []
        return {'email_to': targets, 'email_from': email.get('from', 'tmpufw@localhost'),
                'sendmail_path': email.get('sendmail_path', '/usr/sbin/sendmail'),
                'timeout_seconds': email.get('timeout_seconds', 15)}
    return json.loads(LEGACY_CONFIG.read_text()) if LEGACY_CONFIG.exists() else {}


def notification_policy(a):
    return 'disabled' if a.no_email else ('explicit' if a.email else 'configured')


def expiration_recipients(item):
    policy = item.get('notification_policy', 'explicit')
    if policy == 'disabled':
        return []
    if policy == 'configured':
        return recipients(argparse.Namespace(email=None, no_email=False))
    return item.get('email_to', [])


def email_address(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", value):
        raise ValueError('Use a plain email address without display names or whitespace')
    return value


def recipients(a):
    config = email_settings()
    defaults = config.get('email_to', [])
    if not isinstance(defaults, list):
        raise ValueError('email_to must be an array')
    email_address(config.get('email_from', 'tmpufw@localhost'))
    return [] if a.no_email else list(dict.fromkeys(email_address(x) for x in (a.email or defaults)))


def outbox():
    path = STATE / 'notifications.json'
    return json.loads(path.read_text()) if path.exists() else {}


def queue_expiration(identifier, item):
    if not item.get('email_to'):
        return
    # Deterministic event ID makes queue insertion idempotent across crash retries.
    pending = outbox()
    pending.setdefault(identifier, dict(item, id=identifier, host=socket.getfqdn(), attempts=0))
    save(pending, 'notifications.json')


def deliver_notifications():
    pending = outbox()
    for identifier, item in list(pending.items()):
        try:
            config = email_settings()
            sender = email_address(config.get('email_from', 'tmpufw@localhost'))
            targets = [email_address(x) for x in item['email_to']]
            message = EmailMessage()
            message['From'] = sender
            message['To'] = ', '.join(targets)
            message['Subject'] = '[tmpufw] Expiration processed on ' + item['host']
            message['Date'] = formatdate(localtime=False)
            message['Message-ID'] = '<tmpufw-' + identifier + '@localhost>'
            message.set_content('Temporary UFW rule expiration cleanup completed.\n\n'
                + 'Host: ' + item['host'] + '\nRule ID: ' + identifier
                + '\nRule: ' + shlex.join(item['rule']) + '\nScheduled expiration: ' + item['expires']
                + '\nCleanup completed: ' + item['removed_at']
                + '\nOwned entries removed: ' + str(item.get('removed_entries', 0))
                + '\nNote: ' + item.get('note', '') + '\n')
            executable = config.get('sendmail_path', '/usr/sbin/sendmail')
            timeout = config.get('timeout_seconds', 15)
            if not isinstance(executable, str) or not Path(executable).is_absolute():
                raise ValueError('sendmail_path must be absolute')
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
                raise ValueError('timeout_seconds must be positive')
            result = subprocess.run([executable, '-i', '-f', sender, '--', *targets],
                input=message.as_bytes(), capture_output=True, timeout=timeout,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors='replace').strip() or 'sendmail failed')
            del pending[identifier]
            save(pending, 'notifications.json')
            print('notification queued to mail system', identifier)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            item['attempts'] += 1
            item['last_error'] = str(error)
            save(pending, 'notifications.json')
            print('email retry pending', identifier, error, file=sys.stderr)


def parser():
    p = argparse.ArgumentParser(description=__doc__, epilog='UFW-style: tmpufw allow 22/tcp --ttl 2h; tmpufw insert 1 deny from ADDRESS; tmpufw status; tmpufw delete ID')
    p.add_argument('--version', action='version', version='tmpufw-modern 0.8.0')
    sub = p.add_subparsers(dest='command', required=True)
    add = sub.add_parser('add')
    add.add_argument('action', nargs='?', choices=['allow', 'deny', 'reject', 'limit'])
    add.add_argument('--from', dest='source', default='any')
    add.add_argument('--to', dest='destination', default='any')
    add.add_argument('-r', '--rule')
    add.add_argument('--port')
    add.add_argument('--source-port', default='any')
    add.add_argument('--proto', choices=['any', 'tcp', 'udp'], default=None)
    add.add_argument('--direction', choices=['in', 'out'], default=None)
    add.add_argument('-p', '--position', type=int)
    add.add_argument('--note', default=None)
    add.add_argument('--email', action='append', help='Expiration recipient; repeat for multiple addresses')
    add.add_argument('--no-email', action='store_true')
    add.add_argument('--dry-run', action='store_true')
    add.add_argument('--app')
    add.add_argument('--interface')
    add.add_argument('--in-interface')
    add.add_argument('--out-interface')
    add.add_argument('--route', action='store_true')
    extend = sub.add_parser('extend')
    extend.add_argument('id')
    for command in (add, extend):
        group = command.add_mutually_exclusive_group(required=command is extend)
        group.add_argument('-t', '--ttl')
        group.add_argument('--until')
    delete = sub.add_parser('remove')
    delete.add_argument('id')
    listing = sub.add_parser('list')
    listing.add_argument('--json', action='store_true')
    listing.add_argument('--numbered', action='store_true')
    sub.add_parser('clean')
    notify = sub.add_parser('notify')
    notify.add_argument('id')
    notify.add_argument('--email', action='append')
    notify.add_argument('--no-email', action='store_true')
    sub.add_parser('notifications')
    reconcile = sub.add_parser('reconcile')
    reconcile.add_argument('--json', action='store_true')
    delete_rule = sub.add_parser('delete-rule', help='Delete a managed rule by specification; normally use delete')
    delete_rule.add_argument('rule')
    return p

def ufw_style(argv):
    if not argv:
        return argv
    if argv[0] == 'status':
        tail = argv[1:]
        if tail in (['numbered'], ['verbose']):
            tail = ['--numbered'] if tail == ['numbered'] else []
        return ['list', *tail]
    if argv[0] == 'delete':
        if len(argv) == 2:
            return ['remove', argv[1]]
        return ['delete-rule', shlex.join(argv[1:])]
    tokens = []
    options = []
    valued = {'--ttl', '-t', '--until', '--email', '--note'}
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in valued:
            if index + 1 == len(argv):
                raise ValueError('Missing value for ' + token)
            options += argv[index:index + 2]
            index += 2
        elif any(token.startswith(name + '=') for name in valued):
            options.append(token)
            index += 1
        elif token in ('--no-email', '--dry-run'):
            options.append(token)
            index += 1
        else:
            tokens.append(token)
            index += 1
    if not tokens:
        return argv
    route = tokens[0] == 'route'
    head = 1 if route else 0
    if len(tokens) <= head:
        return argv
    placement = None
    if tokens[head] in ('insert', 'prepend'):
        mode = tokens.pop(head)
        if mode == 'insert':
            if len(tokens) <= head:
                raise ValueError('insert requires a position')
            placement = int(tokens.pop(head))
        else:
            placement = 1
    if len(tokens) <= head or tokens[head] not in ('allow', 'deny', 'reject', 'limit'):
        return argv
    # UFW comments become human notes; ownership comments remain tool-controlled.
    if 'comment' in tokens:
        i = tokens.index('comment')
        if i != len(tokens) - 2:
            raise ValueError('comment requires one final argument; quote multi-word notes')
        options += ['--note', tokens[i + 1]]
        tokens = tokens[:i]
    translated = ['add', '--rule', shlex.join(tokens), *options]
    if placement is not None:
        translated += ['--position', str(placement)]
    return translated


def parse_args(argv=None):
    argv = ufw_style(list(sys.argv[1:] if argv is None else argv))
    if argv and argv[0] not in ('add', 'extend', 'remove', 'list', 'clean', 'reconcile', 'notify', 'notifications', 'delete-rule', '--version', '-h', '--help'):
        if argv == ['--status'] or argv == ['-s']:
            argv = ['list']
        elif argv == ['--clean'] or argv == ['-c']:
            argv = ['clean']
        elif any(x in ('-r', '--rule') or x.startswith('--rule=') for x in argv):
            argv = ['add', *argv]
            if not any(x in ('-p', '--position') or x.startswith('--position=') for x in argv):
                legacy_position = settings().get('defaults', {}).get('legacy_position', 1)
                if legacy_position is not None:
                    argv += ['--position', str(legacy_position)]
    parsed = parser().parse_args(argv)
    if parsed.command == 'add' and parsed.position is None:
        parsed.position = settings().get('defaults', {}).get('position')
    return parsed


def main():
    a = parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo')
    with locked() as data:
        if a.command == 'delete-rule':
            args, _ = raw_rule(a.rule)
            preview_id = uuid.uuid4().hex
            keys = preview_keys(run('--dry-run', *args, 'comment', 'tmpufw:' + preview_id), preview_id)
            matches = [identifier for identifier, item in data.items()
                       if sorted(item.get('expected_keys', [])) == sorted(keys)]
            if len(matches) != 1:
                raise ValueError('Rule must match exactly one managed temporary rule; use its full ID')
            a.command, a.id = 'remove', matches[0]
        if a.command == 'remove' and a.id.isdigit():
            number = int(a.id)
            matches = [identifier for identifier in data if number in owned_numbers(identifier)]
            if len(matches) != 1:
                raise ValueError('UFW number does not belong to a managed temporary rule')
            a.id = matches[0]
        if a.command == 'notifications':
            print(json.dumps(outbox(), indent=2))
        elif a.command == 'notify':
            if a.id not in data:
                raise ValueError('Unknown rule ID')
            data[a.id]['email_to'] = recipients(a)
            data[a.id]['notification_policy'] = notification_policy(a)
            save(data)
            print(a.id, 'expiration recipients:', ','.join(data[a.id]['email_to']) or 'disabled')
        elif a.command in ('list', 'reconcile'):
            report = reconciliation(data)
            if getattr(a, 'numbered', False):
                print(run('status', 'numbered'))
            if a.json:
                print(json.dumps(report, indent=2))
            else:
                print('UFW:', 'active' if report['ufw_active'] else 'inactive')
                for identifier, item in report['rules'].items():
                    print(identifier, item['expires'], 'remaining=' + str(item['remaining_seconds']) + 's',
                          ','.join(item['health']), 'entries=' + str(item['saved_entries']),
                          shlex.join(item['rule']), item['note'])
                for identifier, item in report['orphans'].items():
                    print('ORPHAN', identifier, 'entries=' + str(item['saved_entries']),
                          'live=' + str(item['live_numbers']))
            if a.command == 'reconcile' and (report['orphans'] or
                    any(item['health'] != ['ok'] for item in report['rules'].values())):
                raise RuntimeError('Reconciliation found anomalies; no rules or state were changed')
        elif a.command == 'add':
            defaults = settings().get('defaults', {})
            a.note = a.note if a.note is not None else defaults.get('note', '')
            end = expiry(a.ttl, a.until)
            targets = recipients(a)
            if a.rule:
                if a.action is not None or a.port is not None or a.source != 'any' or a.destination != 'any' or a.source_port != 'any' or a.proto is not None or a.direction is not None or a.app or a.interface or a.in_interface or a.out_interface or a.route:
                    raise ValueError('Do not mix --rule with structured rule arguments')
                args, keys = raw_rule(a.rule)
            else:
                if a.action is None:
                    raise ValueError('Specify an action or --rule')
                a.proto = a.proto or ('any' if a.app else defaults.get('protocol', 'any'))
                a.direction = a.direction or defaults.get('direction', 'in')
                a.port = a.port or 'any'
                args, keys = rule_spec(a)
            if a.position is not None and a.position < 1:
                raise ValueError('Position must be positive')
            timer = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet',
                                    'tmpufw-clean.timer'], check=False)
            if timer.returncode and not a.dry_run:
                raise RuntimeError('tmpufw-clean.timer must be active before adding rules')
            if not run('status').startswith('Status: active'):
                raise RuntimeError('UFW must already be active; tmpufw never enables it')
            existing = tuples()
            identifier = uuid.uuid4().hex
            command = positioned(args, a.position)
            try:
                preview = run('--dry-run', *command, 'comment', 'tmpufw:' + identifier)
            except RuntimeError as error:
                if a.position == 1 and "Invalid position '1'" in str(error):
                    command = args
                    preview = run('--dry-run', *command, 'comment', 'tmpufw:' + identifier)
                else:
                    raise
            keys = preview_keys(preview, identifier)
            if any(key in existing for key in keys):
                raise RuntimeError('Equivalent UFW rule exists; refusing to take ownership')
            if a.dry_run:
                print(json.dumps({'rule': command, 'expires': end, 'email_to': targets, 'entries': len(keys)}, indent=2))
                return
            data[identifier] = dict(rule=args, expires=end, status='pending', note=a.note, expected_keys=keys, email_to=targets, notification_policy=notification_policy(a))
            save(data)  # Journal before firewall mutation; pending entries are also cleaned.
            install_rule(data, identifier, command)
            print(identifier, end)
        elif a.command == 'extend':
            if a.id not in data:
                raise ValueError('Unknown rule ID')
            if not owned_numbers(a.id):
                raise ValueError('Rule no longer exists with its ownership marker')
            data[a.id]['expires'] = expiry(a.ttl, a.until)
            save(data)
            print(a.id, data[a.id]['expires'])
        else:
            if a.command == 'remove':
                if a.id not in data:
                    raise ValueError('Unknown rule ID')
                selected = [a.id]
            else:
                selected = [key for key, item in data.items()
                            if dt.datetime.fromisoformat(item['expires']) <= dt.datetime.now(UTC)]
            failed = False
            for identifier in selected:
                try:
                    if not run('status').startswith('Status: active'):
                        raise RuntimeError('UFW inactive: cleanup deferred until it is active')
                    item = data[identifier]
                    if item['status'] == 'expired_config_pending':
                        item['email_to'] = expiration_recipients(item)
                        item['status'] = 'expired_email_pending'
                        save(data)
                    if item['status'] != 'expired_email_pending':
                        count = len(owned_numbers(identifier))
                        remove(identifier)
                        if marked_records(saved_records()).get(identifier):
                            raise RuntimeError('Owned entries remain; cleanup incomplete')
                        if a.command == 'clean' and item['status'] != 'rollback_failed':
                            try:
                                item['email_to'] = expiration_recipients(item)
                            except (ValueError, OSError) as error:
                                item.update(status='expired_config_pending', removed_at=dt.datetime.now(UTC).isoformat(), removed_entries=count)
                                save(data)
                                raise RuntimeError('Firewall cleanup completed; notification configuration needs repair: ' + str(error))
                        if a.command == 'clean' and item['status'] != 'rollback_failed' and item.get('email_to'):
                            item.update(status='expired_email_pending', removed_at=dt.datetime.now(UTC).isoformat(),
                                        removed_entries=count)
                            save(data)
                    if item['status'] == 'expired_email_pending':
                        queue_expiration(identifier, item)
                    del data[identifier]
                    save(data)
                    print('removed', identifier)
                except (RuntimeError, OSError) as error:
                    print(identifier, error, file=sys.stderr)
                    failed = True
            if a.command == 'clean':
                deliver_notifications()
            if failed:
                raise RuntimeError('Cleanup incomplete; retained entries will be retried')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, OverflowError) as error:
        print('tmpufw:', error, file=sys.stderr)
        sys.exit(1)
