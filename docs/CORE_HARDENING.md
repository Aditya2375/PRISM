# Core hardening: device classes, removal rules, deleted ids, and the limits that remain

Self-contained notes on how the core (`kig`) treats powerful devices and deleted data, written to be linked from the
README or merged into the threat model. Every claim names the test that proves it. `kig X` means `python -m kig.cli X`.

## 1. Two device classes

* A **full device** carries its user's role. For an admin user it can create users, enrol devices, disable users and
  remove devices.
* A **limited device** (`kig enroll --limited`, or `"limited": true` in the web API) always acts as a plain member,
  even when its user is an admin. It is meant for phones. A lost limited phone cannot be used to take over the
  service, and a sole admin can remove it from the laptop (`test_y1_*`).
* The `limited` field is a strict boolean on the web API. The device list a user sees (`/my_devices`) shows it.
* The client refuses a signed proof that was made by a limited device where an admin proof is required.
* The last-admin guards count full devices only, so removing the last full admin device is refused.

## 2. Who can remove a powerful device

* An admin-capable device is removed by another admin user, or offline by the host with `kig revoke-device`.
* The removing admin's device must be at least **15 minutes old** (`COOLING_OFF_S = 900`). The same cooling-off covers
  removing limited devices of an admin, disabling an admin and changing an admin's role. A device minted by an
  attacker therefore cannot immediately lock the owner out (`test_i1_*`, `test_k1_*`).
* The cooling-off uses the service clock. A host whose clock is wrong changes it.
* Removing a limited device of an admin raises the high alert **R5-ADMIN-LIMITED-DEVICE-REMOVED** for any remover.
  Expected when you reported a lost phone. If it was not you, the acting device may be stolen.

## 3. Deleted ids (tombstones)

* Deleted file ids are a journalled section with one small record per id, so a create and delete loop does not grow
  every journal line (`test_j1_deleted_ids_do_not_bloat_every_journal_line`).
* The list is capped per owner by `KIG_MAX_DELETED_IDS` (default 2000) (`test_j1_tombstones_are_capped_per_owner`).
* A deleted id can be created again only by its owner or an admin, at the next epoch (`test_j2_*`, `test_i3_*`).
* A crash after the delete was logged but before state was saved still deletes on restart: recovery replays
  `file.deleted` and removes the blobs (`test_j4_*`).
* State written before this section existed is migrated on load (`test_k3_*`).

## 4. Trust roots

* The root of trust is the first admin device (trust on first use). A device can pin the root fingerprint out of
  band. Explicit pins are used alone, so a hostile pin does not mix with the real one (`test_j3_*`).
* `kig pin-root` adds a pin, `kig unpin-root` removes one. `/me` returns the device fingerprint and the pinned roots,
  and the enrol screen shows the fingerprint so it can be read out over a channel the server does not control.

## 5. Alerts and logs

* High and critical alerts also print one line on stderr. The line is JSON-escaped, so user text and ids cannot forge
  a second line (`test_k2_*`). That line and the audit log are the only places an operator sees an alert.

## 6. Limits that remain (not hidden)

* A revoked or lost device keeps everything it already decrypted. Revocation stops later access only.
* A stolen full admin device is an admin until the host removes it with `kig revoke-device` and recovers with
  `kig recover-admin`. A device minted by it can act after 15 minutes if nobody disabled that user.
* The root of trust is trust on first use unless a fingerprint is pinned out of band.
* Python cannot wipe memory, so key bytes may stay in process memory after use.
* The three-node cluster is an in-process simulation. Revocation exposure on a partitioned node is bounded by the
  5 second lease (`docs/REVOCATION.md`).
* The audit log has no independent completeness guarantee without an external head or `KIG_PIN_FILE`.
* A user who loses every device cannot recover their files unless an admin enrols a new one.
