# Three-node revocation: what is enforced, what is tested, what is not

One primary (`node-a`) takes writes. Two read replicas (`node-b`, `node-c`) serve reads. Each node has its own data
directory, keys and audit log. The cluster exists in two forms. The first is an in-process simulation (`kig/cluster.py`),
where all three nodes share one process and a message bus that can delay, drop and partition; it is the fast-test path
and its timings are not network timings. The second is three real OS processes over TCP on localhost, described in the
real-process section below. Neither is a multi-host deployment.

## How revocation reaches a node

1. The primary writes the revocation to `revoked.log` first (union-only, fsynced), then to state and the audit log.
2. It signs a certificate (`kind: revoke`, device, audit seq) and pushes it to each replica. A replica verifies the
   signature, adds the device to its own `revoked.log`, and rejects the device from then on.
3. A replica also pulls on every request while it can reach the primary: a signed snapshot plus all certificates.
4. The lease lives in the replica (`GuardService.handle`, `lease_s`), not in the test harness. If a replica has not
   confirmed it is current within `LEASE_S` (5 s), it refuses every request with `node_stale`. It fails closed. A
   fresh or restarted replica has no sync time, so it also refuses everyone until its first successful sync.
   `LEASE_S` is a choice between availability during a short outage and the worst-case exposure; lowering it
   shortens the exposure and makes more outages visible to users.
   The latency claim, precisely: a revocation reaches every reachable replica within the network delay we inject (5 to 50 ms, simulated, one
   process); the delay dominates the printed times, our processing is small. Real networks will differ. A replica cut off from the primary can still serve a revoked device for up to `LEASE_S`.
5. Cost: a pull sends a snapshot only if the primary is ahead of the node, and only certificates after the node's last
   applied sequence. Each certificate is signed once, when first needed, and cached by audit sequence. Replica reads
   no longer re-sign history, so their cost does not grow with the number of rotations. Replicas do not add read
   throughput in this single-process simulation. Each node keeps its own audit log (a replica writes its own
   `access.granted` entries).
6. A running replica never removes a device from its revoked set: installing a snapshot or replaying a certificate
   only adds. Restoring an old copy of a replica directory does make that node forget, but it then has no sync time,
   so it fails closed (lease) until it pulls, and the pull restores the revocation.

## Attacks and the result

| Attack | Result | Test |
|---|---|---|
| Use the lost device on any node after revocation | Denied `revoked` on all three nodes, timed | `test_revocation_enforced_on_every_node_and_timed` |
| Send a request signed before the revocation, after it | Denied on all three nodes | `test_revoked_device_rejected_everywhere_including_captured_request` |
| Replay a request captured at one node on another | Denied (audience is signed) | `test_request_cannot_be_replayed_on_another_node` |
| Partition a replica, revoke, heal | Exposure only inside the partition and lease window, then enforced; never un-revoked | `test_partitioned_node_enforces_after_pull_and_never_unrevokes` |
| Keep a replica cut off past the lease | `node_stale` for everyone, not open | `test_lagging_replica_after_lease_fails_closed_not_open`, `test_partitioned_replica_fails_closed_after_lease` |
| Restart a replica | Revocations kept, fails closed until synced | `test_replica_restart_keeps_revocation_and_fails_closed_until_synced` |
| Restore an old copy of a replica directory | The node forgets, but fails closed until it pulls, and the pull restores the revocation | `test_rollback_of_a_replica_directory_is_healed_by_the_next_pull` |
| Replay a genuine older signed snapshot | Cannot un-revoke | `test_replaying_an_old_valid_snapshot_cannot_unrevoke` |
| Forge or edit a certificate or snapshot | Rejected (signature) | `test_forged_certificate_rejected`, `test_certificate_replay_is_idempotent_and_tamper_is_rejected`, `test_snapshot_from_another_primary_is_rejected` |
| Re-enrol the lost device's id | Refused: ids are never reused | `test_revoked_id_cannot_be_reenrolled_on_any_node` |
| Disable a user | All their devices revoked on every node | `test_disabling_a_user_revokes_all_their_devices_on_every_node` |
| Restart the primary | Revocations kept, replicas consistent | `test_primary_restart_keeps_revocations_and_replicas_stay_consistent` |
| Random mix of partitions, restarts, replays | No node ever forgets a revocation; after a sync all nodes reject every revoked device (12 seeds) | `test_random_partitions_restarts_and_replays_never_unrevoke` |
| Kill the process at any point of a write | State stays consistent and revocations survive | `tests/test_chaos.py`, `tests/test_crash_and_cutoff.py` |

## Real processes over TCP (`kig/node.py`, `kig/netcluster.py`)

The same logic also runs as three separate OS processes. `python -m kig.demo --net` (or `python -m kig.netcluster`)
starts `node-a` (primary), `node-b` and `node-c` (replicas) on localhost, each with its own data directory, signing key
and audit log, and measures the time from the primary's acknowledgement of a revocation until each replica refuses the
device. Clients talk to each node over HTTP. Node to node traffic goes through TCP relays owned by the harness, so a
link can be cut or slowed without changing node code.

* The primary pushes each new certificate to every replica as soon as the command commits, and retries a replica that
  does not answer. Replicas also pull every 0.25 s.
* Every pull reply carries a proof signed by the primary over the replica's random nonce, the primary's position
  (restore generation and audit length), the highest audit sequence covered and a hash of the certificate list. A
  replayed old reply, one with certificates stripped out, or one with an edited position fails the check and does not
  refresh the lease (`test_certificate_reply_must_be_fresh_complete_and_signed_for_this_request`).
* A lease is refreshed only after the replica has applied every certificate and installed a snapshot at or beyond the
  signed position. Someone on the path who blocks only the snapshot step therefore cannot keep a lease fresh while the
  replica falls behind (`test_n2_a_lease_is_not_refreshed_unless_the_node_reached_the_signed_position`). The lease clock
  starts when the last certificate request was sent, not when the reply arrived (`test_the_lease_starts_when_the_request_was_sent`).
* A primary whose log is shorter than what the replica already applied, with no new restore generation, is refused and
  does not refresh the lease (`test_a_primary_with_a_shorter_log_does_not_refresh_a_lease`).
* Certificates travel in pages of at most 200 audit entries, and snapshots as signed state plus blobs in pages of about
  2 MB, each blob checked against its hash and against the signed state. A long history or a large upload during a
  partition no longer needs one huge reply (`test_a_replica_with_a_long_history_catches_up_page_by_page`,
  `test_n1_catch_up_larger_than_one_reply_is_paged`, `test_blob_pages_are_capped_and_only_serve_blobs_of_the_current_state`).
* `/sync/*` and `/node/status` need a shared cluster token. The token only keeps strangers from reading metadata. Nothing
  is trusted because it carries the token (`test_sync_endpoints_need_the_cluster_token`,
  `test_replica_ignores_a_certificate_signed_by_another_key`).
* Node to node requests ignore `http_proxy` settings in the environment, and the token file must be a regular file that
  only its owner can read (`test_http_proxy_environment_is_ignored_for_node_traffic`,
  `test_token_file_must_be_private_and_a_replica_cannot_bootstrap`). A replica refuses `--bootstrap`.
* Replica restart, primary stop and restart, a replica that was down during a revocation, and a cut link are covered by
  `tests/test_netcluster.py`: a revoked device stays revoked everywhere and a node that cannot confirm it is current
  refuses everyone.

Honest limits of this version:

* All processes share one host, one clock and the loopback interface, so the measured milliseconds are not WAN numbers
  (the relay can add a delay, reported as `injected_delay_ms`). Quote the figure only from the output of
  `python -m kig.netcluster`, with that caveat.
* Node to node traffic is plain HTTP. Across hosts it must run over TLS or an authenticated tunnel: the cluster token
  alone protects nothing against someone on the path. Such a party can read sync traffic (state metadata and ciphertext)
  and can delay or block a replica, which then fails closed after the lease. It cannot make a replica accept an unsigned
  certificate or snapshot, or keep a lease fresh while the replica is behind.
* The cluster token is shared by all nodes. A holder can make the primary build full-state snapshots again and again
  (CPU and memory cost) and can read the sync data.
* A primary restored from an older backup under the same restore generation leaves replicas ahead of it; they refuse to
  refresh their lease until the operator restores with a new generation or rebuilds the replicas.
* After each snapshot a replica deletes ciphertext that its new state no longer refers to, so deleted files and
  superseded versions do not stay on its disk (`test_o1_replicas_delete_ciphertext_of_deleted_files_and_old_versions`).
  If files change while a replica is copying blobs, the primary reports the blobs that left its state and the replica starts
  again from a newer snapshot, keeping the blobs it already has, for about one lease (then `churn`) (`test_o2_blob_that_left_the_state_is_reported_as_gone_and_the_pull_recovers`).
* Under very heavy write churn (several writers rewriting multi-megabyte files) a lagging replica can fail to catch up
  within that time, answers `node_stale`, and recovers when the writes slow down. It fails closed; it never serves stale data.
* A replica that cannot sync reports the reason in `/node/status` and prints a JSON line on stderr (`sync_failing`);
  there is no alerting beyond that. Client requests are not relayed, so a partition test cuts only the sync links.

## Limits, stated plainly

* Exposure window: a replica that is partitioned from the primary but not yet past `LEASE_S` (5 s) can still serve a
  device that was revoked during the partition. This is the price of serving reads during a short outage.
* A malicious or compromised replica can ignore revocations for clients that talk only to it. Server-side enforcement
  cannot fix that. A client that needs protection from it must also ask a second node.
* The lease uses a monotonic clock inside the node, so a wall-clock step does not extend or shorten it.
* A demoted admin stays proven in a client's pins, because admin proofs carry no freshness or revocation. Abusing that
  needs a colluding former admin and a malicious service.
* A device that was revoked has already decrypted what it read. Rotation protects the next version, not the past.
* A lost-device notice written by the primary is trusted. A compromised primary signing key breaks the whole scheme.
* The nodes share one process and one clock source in the simulation (`Cluster.skew` shifts a node's wall clock in tests). Clock skew between real hosts is bounded by the
  30 s request window and is not simulated.
* A request signed in the same millisecond a node boots can be refused as older than its boot instant. That is a
  deliberate rule against replays across restarts and costs one retry.
