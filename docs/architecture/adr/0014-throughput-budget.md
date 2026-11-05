# ADR-0014: Throughput budget (NFR-2)

- Status: **Proposed** (needs the owner's decision; do not treat as accepted)
- Date: 2026-10-29

## Context

NFR-2 requires at least 2,000 requests/s per 2 vCPU node at PL1 with a 1 KB GET
mix, "calibrated in M2; the budget may be revised once, by ADR". The Phase 1
gate requires NFR-1/2 to be confirmed or revised by ADR.

The first measurements ([benchmarks.md](../../plan/benchmarks.md)), taken on a
developer machine and not on the fixed CI runner, show:

- NFR-1 (latency) is met with margin: +2.4 ms p95, +5.5 ms p99 against 5 ms and 15 ms.
- NFR-2 is **not** met: one physical core (2 hyperthreads) sustains about
  **1,500 rps** at 5.6 GHz, and throughput scales linearly with cores (3,000 rps
  on two cores). A slower cloud vCPU will sustain less.
- The cost is dominated by Coraza evaluating CRS: about 0.43 ms per benign GET at
  PL1 (about 2,700 allocations) and 0.89 ms at PL4. Sherlock's own code is
  negligible.

## Options

| Option | Effect |
| --- | --- |
| A. Keep 2,000 rps / 2 vCPU and optimise | Needs the per-request WAF cost to fall by roughly a third or more on slower hardware. Candidates: reduce Coraza allocations (pooling, upstream changes), skip rule groups that cannot apply to a request (for example body rules for bodyless GET), cache per-request work across rules. Uncertain effort and payoff; some of it is upstream. |
| B. Revise to a per-vCPU figure | State the budget as, for example, **500 rps per vCPU** (1,000 rps for the 2 vCPU reference node) and document scaling to ~1,500 rps/core on fast hardware. Honest and testable; weaker marketing number. |
| C. Revise by paranoia level | Keep 2,000 rps only for a reduced rule set; not recommended, since PL1 is already the lightest supported configuration. |

## Recommendation

Do not change the requirement until the numbers exist on the fixed 2 vCPU runner.
Then, if it confirms the shortfall, take **B now** (so the gate is honest) and
schedule **A** as the performance work already listed in M12, with the benchmark
harness as the acceptance test. Whichever is chosen, the one permitted revision
of NFR-2 should be made with the runner's numbers, not these.

## Consequences

- Until decided, `test/k6/run.sh` fails the throughput check by design.
- Capacity guidance in the documentation must say "about 1,500 rps per fast
  physical core" and not promise the 2,000 rps figure.
