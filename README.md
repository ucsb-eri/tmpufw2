# tmpufw-modern 0.8.0

A clean Python 3 successor to Josh Sherman's tmpufw concept. The original
source could not be retrieved; this is an independent implementation, not
an upstream patch. Legacy CLI flags are supported; legacy state is not imported.
Requires Ubuntu/Debian, Python 3.10+, UFW, and systemd. No mandatory pip dependencies. Optional `sudo apt install python3-parsedatetime` enables general natural-language times.

## Install

```sh
sudo ./install.sh
```

Installation starts the expiration timer; it does not enable UFW or change rules.
UFW must already be active. The CLI refuses additions if the timer is inactive.

## Use

```sh
sudo tmpufw add allow --from 192.0.2.10 --port 22 --ttl 2h
sudo tmpufw add deny --from 192.0.2.10 --port 22 --position 1 \
  --until '2026-10-14T18:00:00-07:00' --note 'temporary SSH block'
sudo tmpufw list
sudo tmpufw list --json
sudo tmpufw extend RULE_ID --ttl 1d
sudo tmpufw remove RULE_ID
sudo tmpufw clean
systemctl list-timers tmpufw-clean.timer
sudo journalctl -u tmpufw-clean.service
```

Replace RULE_ID with the full ID printed by `add`. Duration suffixes: s/m/h/d/w.
Absolute dates require ISO 8601 with an explicit UTC offset or Z; state stores UTC.
`extend --ttl` measures from now. `--direction out`, `--to`, and `--proto udp`
are supported. Source/destination accept IP addresses, CIDRs, or `any`.
Single ports, comma-separated ports, port ranges, source ports, `limit`, and
whole-address rules are supported. Application profiles, interfaces and route rules are also supported. Rule strings
are parsed by UFW itself during the required dry run; shell execution is excluded.

## Expiration and ownership

The persistent timer checks every minute, with approximately one second timer
accuracy. Expiration is not exact to the second. Overdue rules are processed after
boot. If UFW is inactive or deletion fails, state is retained and retried on the
next tick. Re-enabling UFW can briefly restore an overdue rule before cleanup.
The timer is required to remain enabled; no local scheduler works while the host
is off. Existing SSH connections may remain established after a rule changes.

Each managed rule carries `comment tmpufw:ID`. Cleanup only removes entries still
bearing that exact marker; it never deletes a saved rule specification blindly.
Equivalent existing UFW tuples are rejected before addition. Rules with different
actions, broader networks, or different matching criteria are distinct; normal
UFW first-match ordering still applies. Use `--position 1` deliberately for a
temporary block that must precede an existing allow.

State is atomically written, fsynced, and locked across tmpufw processes. An intent
record is saved before adding a firewall rule, so an interrupted add remains
scheduled for expiration. Do not manually edit its rule comments or copy markers.
If a marker is removed, cleanup leaves that rule untouched. `list` reconciles saved intent with UFW saved entries and numbered live status.
It does not inspect kernel iptables counters or prove packet behavior.

UFW commands run as argv, never through a shell. A fixed executable path and clean
command environment are used. UFW CLI changes by other tools/admins do not acquire
tmpufw's lock: avoid concurrent manual UFW edits during add/cleanup, especially
because UFW numbered deletion is not transactional with inspection.

## Validation and rollout

```sh
python3 -m unittest discover -s tests -v
```

Tests cover expiration parsing, address families, ownership markers, renumbering,
duplicate refusal, state persistence, and retry after cleanup failure using mocks.
Actual UFW 0.36.2 parsing and dry-run rendering have been tested against isolated
configuration trees. Installation checks and the iptables version probe were
substituted in those tests; no live kernel packet-filtering test has been run.
Before fleet deployment, test on a disposable Ubuntu 24.04 VM: add an unused port
with `--ttl 1m`, confirm IPv4/IPv6 removal, test duplicate refusal and reboot catchup.
Retain console access while testing SSH-related rules.

## Uninstall

First remove every managed rule using `tmpufw list` and `tmpufw remove ID`.
Then disable the timer and remove the executable/unit files. Do not disable cleanup
while temporary rules remain: those rules are persistent UFW rules until deleted.

License: MIT. Independent implementation copyright 2026.

## 0.2.0 parity additions

```sh
sudo tmpufw --rule="deny from 192.0.2.10" --ttl="30 days"
sudo tmpufw -r "allow 6000:6010/tcp" -t "2 hours" -p 1
sudo tmpufw --status
sudo tmpufw --clean
sudo tmpufw add --rule "allow proto udp from 192.0.2.0/24 port 53 to any port 1024:65535" --ttl 1h
sudo tmpufw add allow --port 22 --ttl tomorrow
```

The last expression requires python3-parsedatetime. Compact and word durations
(`2h`, `2 hours`, `in 2 hours`, `30 days`) require no additional dependency.
Omitted expiration defaults to 30 days when adding. `extend` still requires
an explicit expiration. General natural-language dates use the host's local
timezone and are stored as UTC; explicit `--until` requires a timezone.
Parsing failure and past expirations are rejected.

Legacy `--rule`, `--ttl`, `--position`, `--status` and `--clean` flags are accepted.
Legacy additions default to position 1, including the empty-ruleset fallback;
modern `add` appends unless given `--position`. Rule strings are tokenized without
a shell, validated by UFW during dry run, and passed as argv.
Every addition and numbered deletion is dry-run validated before execution.
Legacy state files are not imported automatically: their rules lack ownership
markers. Existing v0.1.0 JSON state remains compatible. Re-run install.sh to upgrade.

## 0.3.0 profiles, interfaces and route rules

```sh
sudo tmpufw add allow --app 'Nginx Full' --ttl 2h
sudo tmpufw add allow --interface eth0 --from 192.0.2.0/24 --port 22 --proto tcp --ttl 2h
sudo tmpufw add allow --route --in-interface eth0 --out-interface eth1 \
  --from 192.0.2.0/24 --to 198.51.100.0/24 --port 443 --proto tcp --ttl 1d
sudo tmpufw -r "allow in on eth0 from any to any app 'Nginx Full'" -t '2 hours'
sudo tmpufw add --rule 'route allow in on eth0 out on eth1 from 192.0.2.0/24 to 198.51.100.0/24 port 443 proto tcp' --ttl 1h
```

Use an application profile already installed on the host (`sudo ufw app list`).
Profile expansion stays under UFW control, and all expanded IPv4/IPv6 entries
share one ownership ID. Removing or expiring that ID deletes all marked entries.
`--interface` uses `--direction`; route rules may use both `--in-interface` and
`--out-interface`. Route insertion uses UFW's `route insert POSITION` syntax.
The tool does not enable IP forwarding or change the default routed policy.

Duplicate detection now uses the ownership-marked canonical tuples emitted by
UFW's dry run and compares them against the current saved rule files. This covers
expanded profiles, normalized ports/addresses, interface pairs and route scope.
If any proposed entry duplicates an existing rule, the whole addition is refused.
Different profile names with identical matching ports are conservatively treated
as duplicates. A preview without recognizable ownership tuples is refused.

The default structured protocol changed from tcp to any, matching UFW's native
unspecified-protocol behavior and allowing profiles. Specify `--proto tcp` for TCP
only. Older persisted rules retain their saved protocol and expiration.

Optional native-UFW tests:

```sh
# Download a trusted UFW .deb and extract it; no package installation needed.
dpkg-deb -x ufw_VERSION_all.deb /tmp/ufw-test-root
UFW_TEST_ROOT=/tmp/ufw-test-root python3 -m unittest discover -s tests -v
```

The test runner always forces dry-run mode. Test configuration is copied into a
private temporary directory; it checks that previews do not change config files.

## 0.4.0 reconciliation and failed-add rollback

```sh
sudo tmpufw list
sudo tmpufw list --json
sudo tmpufw reconcile
sudo tmpufw reconcile --json
```

Lists now show time remaining, owned entry counts, live rule numbers, and health.
Reconciliation flags missing/changed/partial rules, changed comments or equivalent
unmarked entries, overdue expirations, inactive UFW, count mismatches, and orphaned
ownership markers. `reconcile` is read-only and exits nonzero when anomalies exist;
it never adopts, removes or recreates orphaned rules. A changed comment cannot be
uniquely distinguished from a replacement rule with equivalent matching criteria.

JSON output now has `ufw_active`, `rules` and `orphans` top-level fields; this changes
the v0.3.0 JSON output shape. Newly added records retain their preview's expected
entries, enabling complete comparison. Older records remain compatible and report
`legacy_presence_only` verification rather than assuming their intended expansion.

Failed additions and incomplete ownership verification trigger immediate rollback
of the attempt's marked entries. If rollback fails, the journal entry remains with
`rollback_failed` status and an immediate expiration for timer retries. Abrupt process
termination still relies on the prewritten pending record and eventual expiration.
Unmarked equivalent rules are never selected for rollback.

Validation: 25 automated tests pass, including five actual-UFW dry-run tests.
Live tests could not execute in the build environment: network namespace creation
is prohibited. The following runners are provided for a fresh **disposable VM**,
run from its console after installing tmpufw and `ufw`, `iproute2`, and Python 3.
They alter the VM's firewall and are not production-host checks.

```sh
sudo python3 tests/live_vm.py --disposable-vm
sudo python3 tests/reboot_vm.py --disposable-vm --stage prepare
# Power off immediately, wait at least 60 seconds, then boot the VM.
sudo python3 tests/reboot_vm.py --disposable-vm --stage verify
```

The live runner tests IPv4 traffic, real systemd expiration, IPv6 traffic/removal,
profile expansion/removal, and reconciliation. The reboot runner checks catchup of
an overdue rule after a new boot. The live runner leaves UFW disabled and its incoming
default set to deny; use only a disposable VM. Existing rules/state are rejected.
Both live runners have been syntax-checked, but have not been executed here.

## 0.5.0 expiration emails

Requires a configured sendmail-compatible mail transport at `/usr/sbin/sendmail`
(Postfix, Exim, or a suitable relay wrapper). tmpufw does not configure SMTP or
store mail credentials. Mail is disabled unless recipients are specified.

```sh
sudo tmpufw add allow --port 18443 --proto tcp --ttl 2m --email admin@example.org
sudo tmpufw add allow --port 18444 --ttl 1d --email first@example.org --email second@example.org
sudo tmpufw notify RULE_ID --email admin@example.org
sudo tmpufw notify RULE_ID --no-email
sudo tmpufw notifications
```

Optional host defaults in `/etc/tmpufw.json`:

```json
{
  "email_to": ["admin@example.org"],
  "email_from": "tmpufw@example.org"
}
```

Recipients are copied into each rule at creation, so changing host defaults does
not change existing rules. `notify ID` applies the current defaults to an existing
record; `--email` overrides defaults and `--no-email` disables them. Plain email
addresses only; display names and newline/header injection are rejected.
Sender configuration is read when sending. Choose a sender your relay accepts.
Protect the config with root ownership; the installer never overwrites it.

Emails are generated after successful expiration cleanup and include host, ID,
rule, note, scheduled expiration, cleanup time, and owned entries removed. Manual
removal and rollback retries do not generate expiration emails. If the rule was
already missing, the message reports zero removed entries rather than claiming
it was deleted. Defaults do not enable notifications retroactively.

A persistent outbox in `/var/lib/tmpufw/notifications.json` is retried by the cleanup
timer, including when no firewall rules remain. Mail submission failure does not
restore an expired rule. `notifications` shows queued messages, attempt counts and
last errors; service journal output records submission or retry. A successful
sendmail exit means the local mail transport accepted the message, not that the
recipient's inbox received it. Delivery is at least once: a crash between mail
acceptance and queue removal may resend a message with the same Message-ID.
Each mail submission has a 15-second timeout. Failed queue entries remain until
accepted; disable cleanup only after considering pending rules and emails.

31 automated tests pass, including email validation, recipient overrides, outbox
persistence, failure retries and mocked sendmail submission. No actual email was
sent during development; validate your host's mail relay with a two-minute rule.

## 0.6.0 central notification configuration

Notification setup now lives in `/etc/tmpufw/notifications.json`:

```json
{
  "version": 1,
  "channels": {
    "email": {
      "enabled": true,
      "transport": "sendmail",
      "from": "tmpufw@example.org",
      "to": ["admin@example.org"]
    }
  }
}
```

The installer creates a disabled example on a fresh install, mode 0600, and never
replaces an existing configuration. If `/etc/tmpufw.json` exists, the installer
leaves it in service; the new file takes precedence when explicitly created.
Copy `notifications.example.json` to the new path and edit it to migrate.
No SMTP credentials belong in rule arguments or rule records.

New rules use the current central recipients at expiration unless `--email`
explicitly overrides them or `--no-email` disables notification for that rule.
Existing v0.5.0 rule records preserve their saved recipients. Run `tmpufw notify ID`
without overrides to switch an existing rule to central defaults. Sender settings
are read from the central file at submission. No daemon restart is required.
Previously queued emails retain their recipient snapshot for retries.

The `channels` structure reserves room for future webhook or other transports.
Email/sendmail is implemented now; enabling an unimplemented channel is rejected
rather than silently pretending to send. Email `enabled: false` disables central
defaults; explicit per-rule `--email` remains an override. Configuration parsing
failure after firewall removal retains notification bookkeeping for retry; it does
not restore the expired firewall rule.

Validation for this release: 28 local unit tests pass, five optional native-UFW
preview tests skipped because their extracted package is no longer present.
Prior actual-UFW dry-run validation and the user's successful on-host rule lifecycle
checks remain applicable; no new email was sent during this change.

## 0.7.0 unified configuration

All exposed host defaults now live in `/etc/tmpufw/config.json`; see
`config.example.json` for the complete schema. Configure default TTL, modern and
legacy placement, protocol, direction and note under `defaults`; calendar cleanup
schedule and timer accuracy under `cleanup`; and transports under `notifications`.
The installer creates or migrates this file without overwriting an existing one.
Old `/etc/tmpufw/notifications.json` and `/etc/tmpufw.json` are preserved, but the
unified config takes precedence. Permissions are root-owned 0600 on creation.

Example default changes:

```json
"defaults": {
  "ttl": "2 hours",
  "position": null,
  "legacy_position": 1,
  "protocol": "tcp",
  "direction": "in",
  "note": ""
}
```

TTL and placement defaults apply when adding a rule; existing expirations stay
unchanged. CLI options override defaults. Profiles use unspecified protocol unless
explicitly provided; explicit protocol with an app remains invalid UFW syntax.
Raw `--rule` syntax retains native UFW protocol/direction interpretation.
`position: null` means append. `legacy_position` controls legacy -r placement.

`cleanup.schedule` accepts a systemd calendar expression, default `*-*-* *:*:00`.
`accuracy_seconds` defaults to 1. After changing cleanup settings, rerun install.sh;
it validates the calendar, regenerates the timer, reloads systemd and restarts the
timer. A longer interval increases expiration delay. Other defaults/configured
notification settings are read on each invocation without service restart.

Email `sendmail_path` and `timeout_seconds` are configurable in the central channel
object. No shell command strings are accepted; the executable path must be absolute.
State and ownership internals stay at fixed implementation paths.

Validation: 29 local unit tests pass; five optional native-UFW tests skipped.

## 0.8.0 UFW-style interface

```sh
sudo tmpufw allow 22/tcp --ttl 2h
sudo tmpufw deny from 192.0.2.10 --ttl 1d
sudo tmpufw insert 1 deny from 192.0.2.10 --until '2026-12-01T18:00:00-08:00'
sudo tmpufw prepend deny from 192.0.2.10 --ttl 1d
sudo tmpufw allow 'Nginx Full' comment 'temporary web access' --ttl 2h
sudo tmpufw route allow in on eth0 out on eth1 from 192.0.2.0/24 to 198.51.100.0/24 --ttl 1h
sudo tmpufw route insert 1 allow from 192.0.2.0/24 to 198.51.100.0/24 --ttl 1h
sudo tmpufw status
sudo tmpufw status numbered
sudo tmpufw delete RULE_ID
sudo tmpufw delete allow 22/tcp
sudo tmpufw --dry-run allow 22/tcp --ttl 2h
```

UFW syntax is passed to its own parser. Expiration/email/note options are extracted
without a shell. Quote application names and multi-word comments normally; a UFW
comment becomes the note while tmpufw retains the ownership comment internally.
When TTL is omitted, the /etc config default applies. Stock-style commands use the
modern configured position; legacy -r commands retain legacy placement defaults.
`prepend` currently means insert at position 1 and therefore uses UFW's insertion
semantics (not a new independent rule-order algorithm).

`status` lists managed temporary rules with expiration information. `status numbered`
also prints the full UFW numbered ruleset. `status verbose` is accepted as the managed
status view; it does not reproduce all stock UFW verbose fields.

`delete` accepts a full temporary ID, a current UFW number belonging to a managed
rule, or a rule specification matching exactly one managed record. Numbered deletion
removes the whole managed rule across IPv4/IPv6/profile entries, not just one UFW row.
Permanent rules are never eligible. Specification deletion requires saved expected
keys (v0.3.0+); use the ID for older records or incomplete/changed rules.
`extend RULE_ID --ttl ...` remains available. Legacy add/remove/list and -r/-t syntax
remain supported. UFW enable/disable/reset/default commands are not passed through.

User-facing --dry-run previews the parsed rule, expiration, recipients and expansion
count without creating a rule or saving a rule record. The config and UFW ruleset
must still be readable and UFW active; the cleanup timer need not be active. The
preview's synthetic ownership marker is discarded. Native UFW rule protocol/direction
syntax takes precedence over structured-wrapper defaults.

Validation: 35 unit tests pass; five optional native-UFW preview tests skipped.
