# Feeding outside logs to the detector (`kig.ingest`)

The detection rules run on PRISM's own audit log. `kig.ingest` runs the same rules on log lines from other services
(JSON lines or CSV), so an access log, an identity-provider log and a VPN log can be checked together. Every field name
and event name is configurable, because we do not know the format in advance.

```
python -m kig.ingest logs.jsonl                        # JSON lines, default field names
python -m kig.ingest web.csv vpn.csv --config map.json # CSV, names changed in map.json; files share one detector
python -m kig.ingest - < logs.jsonl                    # stdin
python -m kig.ingest logs.jsonl --sort                 # sort by timestamp first (reads everything into memory)
```

Output: one alert per line on stdout (JSON, the same fields as PRISM's own alerts), then one summary line on stderr:
lines read, lines fed, lines skipped with the reason for each kind of skip, and how many lines mapped to each kind.
A bad line is skipped and counted, never fatal. A bad config exits with status 2.

## What a line needs

| Canonical field | Required | Default names looked for (first present wins) |
| --- | --- | --- |
| `ts` | yes | `timestamp`, `ts`, `time`, `@timestamp`, `datetime` |
| `identity` | yes | `identity`, `user`, `username`, `principal`, `subject`, `account` |
| `service` | no (`default_service`, "external") | `service`, `app`, `application`, `host`, `target` |
| `event` | no (then the line is kind `other`) | `event`, `action`, `event_type`, `type`, `method` |
| `source` | no | `source`, `ip`, `src_ip`, `client_ip`, `remote_addr` |
| `resource` | no | `resource`, `path`, `url`, `file`, `object` |
| `outcome` | no | `outcome`, `status`, `result`, `status_code` |
| `device` | no (the identity) | `device`, `device_id`, `credential`, `key_id` |
| `by` | no | `by`, `actor`, `admin` |

Timestamps (`ts_format`): `auto` reads epoch seconds, epoch milliseconds (any number above 1e11) or ISO 8601;
`epoch`, `epoch_ms`, `iso`, or a `strptime` pattern such as `"%d/%b/%Y:%H:%M:%S %z"`. A timestamp with no time zone is
taken as UTC.

## Event kinds

The `event` value (case ignored) is mapped to one kind. Anything not in the map is `other`: it is still used for the
ordering check, but no rule fires on it.

| Kind | Rules it feeds | Default event values |
| --- | --- | --- |
| `access` | R6-LATERAL-SERVICE, R6-LATERAL-MOVEMENT, R7-BULK-READ | login, access, read, get, post, put, delete, request, download, query |
| `auth_failure` | R3-AUTH-FAILURE-BURST, R8-SLOW-GUESSING | login_failed, failed_login, auth_failure, auth_failed, login_failure, bad_password |
| `revoked_use` | R1-REVOKED-DEVICE-USE (critical) | revoked_use, revoked_token_use, disabled_login |
| `replay` | R2-REPLAY | replay |
| `revoked` | (context for R1) | revoke, revoked, key_revoked |
| `enrolled` | R4 (critical when it is a new admin's first credential) | enroll, enrolled, device_enrolled, key_issued |
| `admin_created` | R4-PRIVILEGE-ESCALATION | create_admin, admin_created |
| `role_admin` | R4-PRIVILEGE-ESCALATION | grant_admin, promote_admin, role_admin |

An `outcome` listed in `failure_outcomes` (default: fail, failed, failure, denied, deny, unauthorized, forbidden, 401,
403, false) turns an `access` or `other` line into `auth_failure`. That is how a plain web access log with status codes
works without an event map.

## Config file

Only the keys you give change; `fields` and `events` are merged into the defaults.

```json
{
  "format": "csv",
  "fields": {"ts": "when", "identity": "who", "service": "app", "event": "verb", "source": "client"},
  "ts_format": "%d/%m/%Y %H:%M:%S",
  "events": {"logon_bad": "auth_failure", "vpn_connect": "access", "mfa_reset": "other"},
  "failure_outcomes": ["fail", "401", "403"],
  "default_service": "webapp",
  "sort": false
}
```

## What the alerts say

Each alert names `identity` (the user or credential from the log), `services` (every service named by the evidence plus
"ingest"), `event`, `evidence` (record numbers: data rows, counted across all files given), and `path` for R6-LATERAL-SERVICE.
`identity_verified` is false for failed-login rules, because the log only says who the sender claimed to be.

`ordering` is `uncertain` when the evidence holds events of the same identity from different services less than 30 s
apart. With the +/-30 s clock skew this system assumes, their order is not known. An event that arrives more than 30 s
older than one already seen for that identity raises R10-OUT-OF-ORDER (low). Lines are never reordered unless you pass
`--sort`.

## Limits

* The thresholds (`kig/detect.py`) were chosen by us and tuned on traces we wrote (`python -m kig.bench_detect`). They are
  not fitted to the organizers' data. On our synthetic 8-hour, 40-identity, 6-service log they give 0 false alerts in 2,470
  events. Across five random seeds of the same generator, one false alert appeared in about 12,200 events. A real log
  with more services per person will give more R6-LATERAL-SERVICE alerts.
* An identity is still learning its usual services for its first hour in the log. During that hour only a fast chain
  (three services inside five minutes) raises R6-LATERAL-SERVICE.
* Detector memory is bounded (4,096 tracked identities per table, oldest dropped first).
* The adapter reads files; it does not tail a live stream.

## Memory

`run()` reads every line of the file into memory before it feeds the detector, with or without `--sort`. A very large file needs
that much memory; split it, or feed it in pieces (one detector can be shared across calls with `seq0`).
