# tmpufw-modern 0.4.0

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
