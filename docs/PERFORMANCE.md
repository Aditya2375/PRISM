# Measured numbers

Every figure here comes from a command in this repository, run on one machine: Linux x86_64, **1 vCPU**, Python 3.12.16,
loopback only, no network between nodes. Wall times depend on the machine. They are not a claim about a real deployment,
a WAN or load from many clients.

## Revocation time

`python -m kig.demo --net` starts three real node processes over TCP on one host, revokes a device on the primary 20 times,
and measures the time until the last node refuses it. One run on the machine above:

| Measure | Result |
| --- | --- |
| Revocation to the last node (20 runs) | median 24.8 ms, min 19.6 ms, max 53.3 ms |
| Per node, median | 23.2 ms and 23.1 ms |
| Injected network delay | 0 ms (loopback, one clock) |
| Node cut off from the others | served inside its 2 s lease, `node_stale` after the lease, `revoked` after healing |

An earlier run on the machine we used for the demo video gave about 35 ms; we quote "about 35 ms" when a single figure is needed. Runs differ by machine and load.
The primary refuses the device at once, with no delay. The only waiting is for the replicas to receive the signed
revocation. The 5 to 50 ms figure in the in-process simulation is a delay we inject on purpose, not a measurement.

## Throughput and cost

`python -m kig.bench --sizes 100` (100 files, in process: no HTTP, one thread, one core):

| Operation | Time per call | About per second |
| --- | --- | --- |
| put (encrypt, wrap for each device, sign, audit) | 5.8 ms | 170 |
| fetch (verify, unwrap, decrypt) | 2.5 ms | 400 |
| rotate (re-encrypt and re-wrap) | 10.7 ms | 90 |
| backup of 100 files | 62 ms, 11.6 MB peak memory | |
| restore | 113 ms, 12.8 MB peak memory | |
| start-up replay of the audit log | 35 ms | |

Over HTTP the service handles one command at a time (a lock around the state keeps the audit log a single chain), so
writes do not run in parallel. Commands run off the event loop, so `/healthz` and operator reads keep answering while a
large upload is processed (`tests/test_api_responsive.py`). We have not measured HTTP throughput under many clients.

## Detection

`python -m kig.bench_detect`: precision, recall and time to alert for the rules, on traces we wrote ourselves. See the README
section "Detection, measured".

## Clock skew

A signed request is accepted only when its timestamp is within **+/-30 seconds** of the node's clock (`SKEW_S` in
`kig/service.py`). Outside that window it is refused as `stale` and logged. Three or more such refusals from one device in a
minute raise the low-severity alert R9-CLOCK-SKEW, which states the offsets it saw. Audit entries are ordered by their sequence number and carry the wall clock of the node that wrote them, so timestamps
from two nodes agree only as well as those hosts' clocks do. Cluster leases use each node's monotonic clock, so a wall-clock
step on a node does not change how long its lease lasts.
