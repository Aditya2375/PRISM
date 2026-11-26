# Three-node revocation: what is enforced, what is tested, what is not

One primary (`node-a`) takes writes. Two read replicas (`node-b`, `node-c`) serve reads. All three run in one
process with their own data directories, keys and audit logs, and a message bus that can delay, drop and partition.
This is a simulation of the replication logic. It is not a deployment, and the timings are not network timings.

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
   The latency claim, precisely: a revocation reaches every reachable replica in tens of milliseconds (simulated, one
   process). A replica cut off from the primary can still serve a revoked device for up to `LEASE_S`.
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
* The nodes share one process and one clock source in the simulation. Clock skew between real hosts is bounded by the
  30 s request window and is not simulated.
* A request signed in the same millisecond a node boots can be refused as older than its boot instant. That is a
  deliberate rule against replays across restarts and costs one retry.
