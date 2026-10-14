# tmpufw-modern 0.8.0

Temporary UFW rules with expiration, persistent cleanup, reconciliation, and
optional email notifications. Uses familiar UFW syntax with `--ttl` or `--until`.
Requires Ubuntu/Debian, Python 3.10+, UFW, and systemd.

## Install or upgrade

```bash
cd tmpufw-modern
sudo ./install.sh
```

The installer starts the cleanup timer and preserves existing config and rule
state. It does not enable UFW. UFW must already be active to add rules.
For expressions such as `tomorrow`, optionally install:

```bash
sudo apt install python3-parsedatetime
```

## Quick start: UFW-style commands

```bash
# TCP port for two hours
sudo tmpufw allow 22/tcp --ttl 2h

# Specific source IP
sudo tmpufw allow from 192.0.2.10 to any port 22 proto tcp --ttl 2h

# Block an IP before existing allow rules
sudo tmpufw insert 1 deny from 192.0.2.10 --ttl 1d

# Same placement shortcut
sudo tmpufw prepend deny from 192.0.2.10 --ttl 1d

# Explicit date and timezone
sudo tmpufw allow 18443/tcp --until '2026-12-01T18:00:00-08:00'

# Human note, using UFW's comment syntax
sudo tmpufw allow 18444/tcp comment 'temporary research access' --ttl 2h

# Use the configured default expiration
sudo tmpufw allow 18445/tcp

# Preview without adding a rule
sudo tmpufw --dry-run allow 18446/tcp --ttl 2h
```

Each successful addition prints a full rule ID and its UTC expiration. Compact
TTL suffixes are `s`, `m`, `h`, `d`, and `w`. Word durations such as `2 hours`,
`in 2 hours`, and `30 days` need no extra dependency. Other natural-language times
use parsedatetime and the host's local timezone. Absolute `--until` dates require
an explicit UTC offset or `Z`. Past or invalid expirations are rejected.

## Profiles, interfaces, and route rules

```bash
# Existing UFW application profile; quote names with spaces
sudo tmpufw allow 'Nginx Full' --ttl 2h

# Port range
sudo tmpufw allow 6000:6010/tcp --ttl 1h

# Interface-specific rule
sudo tmpufw allow in on eth0 from 192.0.2.0/24 to any port 22 proto tcp --ttl 2h

# Outgoing rule
sudo tmpufw allow out to 198.51.100.10 port 443 proto tcp --ttl 1h

# Forwarded traffic between interfaces
sudo tmpufw route allow in on eth0 out on eth1 from 192.0.2.0/24 to 198.51.100.0/24 --ttl 1h

# Insert a route rule
sudo tmpufw route insert 1 allow from 192.0.2.0/24 to 198.51.100.0/24 --ttl 1h
```

Supported actions include `allow`, `deny`, `reject`, and `limit`. UFW validates
native rule syntax during dry run. Profile expansion remains under UFW control;
all generated IPv4/IPv6/profile entries share one expiration ID. The tool does
not enable IP forwarding or change routed policy. `prepend` uses position-1
insertion semantics. Native rule syntax uses UFW's protocol/direction semantics;
structured-wrapper defaults apply to the compatibility `add` form.

## Status, extension, and deletion

```bash
sudo tmpufw status
sudo tmpufw status numbered
sudo tmpufw status --json
sudo tmpufw reconcile
sudo tmpufw reconcile --json

sudo tmpufw extend RULE_ID --ttl 1d
sudo tmpufw delete RULE_ID
sudo tmpufw delete allow 18443/tcp
sudo tmpufw delete 30
```

Replace `RULE_ID` with the full ID printed when creating the rule. `extend --ttl`
measures from now. `status` shows managed rules, remaining seconds, entry counts,
and health. `status numbered` also prints the full UFW numbered ruleset.
`status verbose` is accepted as the managed status view, not stock UFW's complete
verbose output. JSON has `ufw_active`, `rules`, and `orphans` top-level fields.

**Deletion only affects managed temporary rules.** A numbered delete is accepted
only when that current UFW number belongs to a tracked temporary rule. It removes
that entire managed rule, including its IPv4/IPv6/profile entries. Specification
deletion must match exactly one tracked rule with saved expected entries; use
its ID when a rule has changed or comes from an older state format.

Reconciliation is read-only and exits nonzero for anomalies: missing, changed,
partial, overdue or orphaned rules; changed comments or equivalent replacement
rules; inactive UFW; and saved/live count mismatches. It never adopts or deletes
orphans. Older state without expected entries gets presence-only verification.
This view checks UFW saved rules and numbered status, not kernel packet counters.

## Configure defaults in /etc

Edit `/etc/tmpufw/config.json`. The full template is `config.example.json`.

```json
{
  "version": 1,
  "defaults": {
    "ttl": "30 days",
    "position": null,
    "legacy_position": 1,
    "protocol": "any",
    "direction": "in",
    "note": ""
  },
  "cleanup": {
    "schedule": "*-*-* *:*:00",
    "accuracy_seconds": 1
  },
  "notifications": {
    "version": 1,
    "channels": {
      "email": {
        "enabled": false,
        "transport": "sendmail",
        "from": "tmpufw@localhost",
        "to": [],
        "sendmail_path": "/usr/sbin/sendmail",
        "timeout_seconds": 15
      }
    }
  }
}
```

`position: null` means append. `legacy_position` controls old `-r` commands.
CLI options override defaults. Changes to the default TTL affect new additions,
not existing expirations. Other runtime settings are read on each invocation.
Cleanup calendar/accuracy changes require rerunning `sudo ./install.sh` to
validate and regenerate the timer. A longer cleanup interval increases delay.

The installer creates the config root-owned with mode 0600, or migrates prior
email settings when no unified config exists. Existing unified config is never
overwritten. Prior `/etc/tmpufw/notifications.json` and `/etc/tmpufw.json` are
preserved; the unified config takes precedence.

## Expiration notifications

Enable the email channel in the config and set its sender and recipient list.
Requires a configured sendmail-compatible mail transport; tmpufw does not set up
SMTP or store relay credentials. Future transports fit under `channels`; only
email/sendmail is currently implemented. Enabling another channel is rejected.

```bash
# Override central recipient defaults for this rule
sudo tmpufw allow 18443/tcp --ttl 2m --email admin@example.org

# Multiple recipients
sudo tmpufw allow 18444/tcp --ttl 1d --email first@example.org --email second@example.org

# Disable notification for this rule
sudo tmpufw allow 18445/tcp --ttl 1h --no-email

# Change an existing rule's recipient policy
sudo tmpufw notify RULE_ID --email admin@example.org
sudo tmpufw notify RULE_ID --no-email
sudo tmpufw notify RULE_ID

# Inspect queued/retrying emails
sudo tmpufw notifications
```

New rules without overrides use current central recipients at expiration.
`notify ID` without an override switches an existing rule to central defaults.
Older v0.5.0 records preserve their saved recipients. Queued emails retain their
recipient snapshot; sender/transport settings are read at submission.
`email.enabled: false` disables central defaults; explicit `--email` remains an
override. Plain email addresses only; display names and header injection are
rejected. Keep configuration root-owned, particularly if selecting a transport
executable; its path must be absolute and never runs through a shell.

Email is queued after expiration cleanup and includes host, rule ID, rule, note,
scheduled expiration, completion time, and removed-entry count. Manual deletion
and rollback retries do not generate expiration messages. Already-missing rules
report zero removed entries. Notification failures never restore expired rules.
The persistent outbox retries on each cleanup tick, even when no rules remain.
Successful sendmail submission is not confirmation of inbox delivery. A crash
between submission and queue removal can cause duplicate delivery with the same
Message-ID. A config error after deletion retains bookkeeping for retry.

## Cleanup and troubleshooting

```bash
systemctl list-timers tmpufw-clean.timer
sudo journalctl -u tmpufw-clean.service --since '10 minutes ago'
sudo tmpufw clean
sudo ufw status numbered
```

The default persistent timer checks every minute with approximately one-second
accuracy. Expiration can be delayed until the next tick. Overdue rules are
processed after boot. If UFW is inactive or deletion fails, cleanup retries later.
Re-enabling UFW can briefly restore an overdue rule before cleanup. Existing
connections can survive a firewall change; test new connections.

Every managed entry carries an exact `tmpufw:ID` ownership comment. Changing that
comment prevents automatic deletion. Equivalent existing rules are rejected;
matching numeric criteria from different application profiles are conservatively
treated as duplicates. Normal UFW first-match ordering still applies.

State is locked, atomically replaced and fsynced under `/var/lib/tmpufw`. An add
intent is saved before firewall mutation. Failed/partial additions trigger
immediate rollback of that attempt's marked entries. Failed rollback remains
tracked and becomes due for immediate cleanup retry. Abrupt process termination
still relies on the pending record and its expiration.

Avoid concurrent manual UFW changes during tmpufw operations: UFW numbered
inspection/deletion is not a transaction with other administrators' edits.
`--dry-run` requires readable config and active UFW, but not an active timer.
It creates no rule or rule record. Unsupported global commands such as UFW
`enable`, `disable`, `reset` and `default` are not passed through.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

35 unit tests passed for v0.8.0; five optional actual-UFW preview tests were skipped
in the latest environment. Earlier UFW 0.36.2 parser/rendering tests passed, and
on-host addition, duplicate refusal, expiration, extension and removal were
verified. Email delivery is mocked; validate your host's mail transport.

Optional actual-UFW dry-run tests use an extracted package and isolated config:

```bash
dpkg-deb -x ufw_VERSION_all.deb /tmp/ufw-test-root
UFW_TEST_ROOT=/tmp/ufw-test-root python3 -m unittest discover -s tests -v
```

Live tests must run on a fresh **disposable VM from its console**, after installing
this package, UFW and iproute2. They alter firewall policy and are not production
checks. The live runner leaves UFW disabled and its incoming default set to deny.

```bash
sudo python3 tests/live_vm.py --disposable-vm
sudo python3 tests/reboot_vm.py --disposable-vm --stage prepare
# Power off immediately, leave off at least 60 seconds, then boot.
sudo python3 tests/reboot_vm.py --disposable-vm --stage verify
```

The runners check traffic, IPv6, real timer expiration, profiles and reboot catchup.
They are syntax-checked but could not execute in the build environment because
network namespace creation is prohibited.

## Compatibility and uninstall

Previous syntax remains supported:

```bash
sudo tmpufw add allow --port 22 --proto tcp --ttl 2h
sudo tmpufw -r 'deny from 192.0.2.10' -t '30 days' -p 1
sudo tmpufw --status
sudo tmpufw --clean
sudo tmpufw list
sudo tmpufw remove RULE_ID
```

Legacy rule state from the original project is not automatically imported because
those rules lack ownership markers. State from earlier modern releases remains
compatible. Before uninstalling, delete all managed rules and inspect pending
notifications. Disabling the timer with temporary rules present leaves persistent
UFW entries without expiration cleanup.

## Origin and license

An independent implementation inspired by Joshua Sherman's MIT-licensed tmpufw.
It is not an upstream patch. License: MIT; see `LICENSE`.
