# Running PRISM: backups, checks, monitoring, rollback

What is here, what is not, and how to use it. Nothing in this file is a managed service: there is no hosted monitoring and no
automatic rollback.

## Scheduled backups

Backups are signed and sealed to an offline backup public key (`python -m kig.cli` has `backup-key` for splitting the private
key; `kig.backup.keygen` makes the pair). The service writes them itself, so the data directory stays under one process:

```bash
export KIG_BACKUP_PUB=/etc/prism/backup.pub       # public key only; the private key stays offline
export KIG_BACKUP_DIR=/var/backups/prism          # must be outside the data directory
# start the API as usual, then schedule this with cron or a systemd timer, for example every night at 02:15:
15 2 * * *  curl -fsS -X POST -H "X-KIG-Operator-Token: $(cat /var/lib/prism/operator.token)" http://127.0.0.1:8443/v1/backup
```

Each call writes `prism-<counter>-<UTC time>.bak` (owner-only) and returns the counter, blob count and audit head. Record the
counter outside the data directory: without it nothing can tell a stale backup from a fresh one (`docs/CORE.md`, "Backup and
restore"). The endpoint answers 409 until both variables are set. Each backup writes a `backup.created` audit entry. Limits: one backup per 60 s (`KIG_BACKUP_MIN_INTERVAL`, answers 429) and at most 500 files in the directory (`KIG_BACKUP_MAX_FILES`, answers 409). Each file is a full copy, so a leaked operator token can still fill the disk up to that cap (500 times the data size); keep the token secret and size the volume for it. It does not delete old backups; keep or prune them with your
own policy (for example `find /var/backups/prism -name '*.bak' -mtime +30 -delete`). Check a file without the private key with
`python verifier/prism_verify.py backup --file x.bak --pub data/server_sign.pub`. Test a restore before you rely on one:
`tests/test_restore_drill.py` is the drill we run.

## Smoke test of a running deployment

```bash
python scripts/smoke.py https://your-host --operator-token "$T" --session-token "$S"
```

It checks `/healthz`, the security headers, that a protected path refuses a request with no token and with a wrong token, and
that the tokens you pass work. Exit code 0 means every check passed. Run it after each deploy. `scripts/readme_smoke.sh` is the
other smoke test: it follows the README from a fresh copy and runs in CI.

## Failed-token limits

The service port does not slow down a client that keeps sending wrong tokens beyond the built-in rate limit, and the
rate limit counts per source address. Put the service behind a reverse proxy that limits failed authentications (for example
by returning 429 after repeated 401 replies) before it faces anything but a trusted network. Detection rules R3 and R8 are
keyed by source address, so one attacker spread over many addresses is not caught by them. See `THREAT_MODEL.md`, "Known limits".

## Health and monitoring

* `GET /healthz`: the service answers 200. The hosted demo's `/healthz` answers 200 only when both of its backends answer
  and 503 otherwise, so a platform health check restarts it.
* `GET /v1/metrics?format=prometheus` (operator token): users, files, files needing rotation, audit entries, devices by status
  and audit events by type, for a Prometheus scrape.
* Alerts are in `GET /v1/alerts` and in the audit log. Nothing is sent anywhere by itself: there is no e-mail, pager or error
  tracker. Connect your own, for example by polling `/v1/alerts`.

## Rollback

* A bad deploy: redeploy the previous code revision. The data directory is plain files and `tests/test_frozen_format.py` checks
  that no PRISM-1 field was removed or renamed. It generates its data at test time, so it does not open bytes from an older build. Going back to older code on data written
  by newer code is not tested.
* Bad data (for example a rolled-back or damaged directory): restore a verified backup. The restore refuses an older backup
  than the live counter unless you say so, and it records the waiver in the audit log.
* Rollback of the data directory by an attacker is what `KIG_PIN_FILE` guards (README, "Setup").

## Size of the audit log

The audit log is read into memory at start and kept there. Measured on this repository's code (2,000 entries, Python 3.12):
about 5.1 KB of memory and 4.7 KB of disk per entry, most of it the 3.3 KB ML-DSA-65 signature, and about 1.6 ms to append one
entry (signing and fsync). Start-up verification took 29 ms for 2,000 entries. At that rate 100,000 entries need about 510 MB
of memory and 470 MB of disk, and 1,000,000 entries about 5 GB. There is no rotation or archive yet, so plan the memory of the
host from the expected number of entries, and take a backup then start a fresh data directory before the log gets that large.
This is a known limit, not a feature.
