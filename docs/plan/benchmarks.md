# Benchmarks

Measured results against the budgets in [requirements.md](../product/requirements.md)
(NFR-1 latency, NFR-2 throughput, NFR-3 memory). Method: `test/k6/run.sh`.

> **Read this first.** Every number below is from a developer machine, not the
> fixed 2 vCPU CI runner the budgets are calibrated on. They show *shape and
> scaling*; they must be re-measured on the runner before any budget is
> confirmed or revised.

## Environment (2026-10-28)

| | |
| --- | --- |
| CPU | Intel Core i9-14900HX (5.6 GHz max), shared with unrelated containers (load average about 1.5 on 32 logical CPUs) |
| "2 vCPU" | Sherlock pinned with `taskset` to logical CPUs 0 and 1, which are the two hyperthreads of **one physical core**: what a cloud 2 vCPU is |
| Origin | `test/k6/upstream`, 1 KB fixed body, pinned to other cores |
| Load | k6 (`grafana/k6:latest`) in Docker on separate cores |
| Sherlock | release-style build (no test hooks), block mode, PL1, CRS 4.25.0, event stdout/file sinks off |
| Request | `GET /products?category=shoes&page=2&sort=price` with browser-like headers, 1 KB response |

## NFR-1 latency: met

200 requests/s for 2 minutes, once straight to the origin and once through
Sherlock. Added latency is the difference.

| | direct (ms) | via Sherlock (ms) | added (ms) | budget |
| --- | --- | --- | --- | --- |
| p50 | 0.365 | 2.300 | 1.935 | |
| p95 | 0.564 | 2.929 | **2.365** | ≤ 5 |
| p99 | 0.646 | 6.173 | **5.527** | ≤ 15 |
| max | 3.862 | 11.529 | 7.667 | |

## NFR-2 throughput: **not met** on 2 logical CPUs

Constant-arrival-rate steps of 20 s; a step passes if p99 ≤ 50 ms and no
requests are dropped.

| Rate (rps) | 2 logical CPUs (1 core): p99 ms / dropped | 4 logical CPUs (2 cores): p99 ms / dropped |
| --- | --- | --- |
| 500 | 4.90 / 0 | 4.22 / 0 |
| 1,000 | 6.41 / 0 | 3.29 / 0 |
| 1,500 | 11.39 / 0 | 3.62 / 0 |
| 2,000 | **42.52 / 24** | 4.11 / 0 |
| 3,000 | not run | 10.14 / 0 |
| 4,000 | not run | **800 / 8,117** |
| **Highest passing step** | **1,500** | **3,000** |

Throughput scales linearly with cores: about **1,500 rps per physical core** at
5.6 GHz. The budget is at least 2,000 rps on 2 vCPU (one core with SMT). A cloud
vCPU runs at a fraction of this CPU's clock, so the budget will not be met on
the CI runner either unless the cost per request falls.

### Where the CPU goes

From the Go benchmarks (`make bench`), one benign request costs about:

| Stage | Cost |
| --- | --- |
| `sherlock_waf` inspection, PL1 | ~0.43 ms (about 2,700 allocations) |
| `sherlock_waf` inspection, PL4 | ~0.89 ms |
| JSON POST inspection, PL1 | ~0.86 ms |
| `sherlock_core` (IP, decision, metrics) | ~0.001 ms |
| event build + publish (only when there are findings) | ~0.006 ms |

Coraza evaluating the CRS dominates; Sherlock's own code is noise next to it.
The allocation count points at per-transaction setup in Coraza, not at the
Sherlock adapter.

## NFR-3 memory

Not measured yet (needs a sustained-load RSS reading on the runner). Idle RSS
was not recorded in this run.

## Decision needed

See [ADR-0014](../architecture/adr/0014-throughput-budget.md) (Proposed).

## Re-running

```sh
test/k6/run.sh all                        # needs Docker for k6; pins Sherlock to CPUs 0,1
K6_SHERLOCK_CPUS=0-3 K6_ORIGIN_CPUS=10,11 test/k6/run.sh throughput
```
