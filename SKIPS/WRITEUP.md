# SKIPS: Sick Kernel Informed Packet Scheduler

## A next-generation cell scheduler for anonymous overlay networks

### Abstract

SKIPS is a drop-in replacement for Tor's KIST (Kernel Informed Socket Transport) cell scheduler. It addresses three known limitations in KIST's design: fixed-interval scheduling that wastes CPU on high-latency links, static buffer factors that cause bufferbloat on low-RTT links, and EWMA fairness that systematically starves high-RTT circuits. SKIPS is implemented in MOOR, a post-quantum Tor-compatible overlay network, and tested on a 15-relay fleet spanning 8 countries.

### Background: What KIST Does

Tor's KIST scheduler (introduced in 2014, default since 0.3.2) solved a critical problem: when multiple circuits share a single TCP connection to a relay, how do you decide which circuit's cells to write to the kernel socket buffer?

Before KIST, Tor used a simple round-robin that ignored kernel state. Cells were written to the socket buffer regardless of whether the TCP connection could actually send them. This caused two problems:

1. **Kernel buffer bloat** — cells queued in the kernel socket buffer for hundreds of milliseconds, inflating RTT for all circuits on that connection
2. **Unfair scheduling** — bulk download circuits starved interactive circuits (SSH, chat) because round-robin doesn't account for circuit "weight"

KIST fixed both by querying `getsockopt(TCP_INFO)` every 2ms to learn the TCP congestion window (`cwnd`), unacknowledged bytes (`unacked`), and MSS. It computes a write budget:

```
limit = (cwnd - unacked) * mss + extra_space - notsent_bytes
```

And uses an EWMA (Exponentially Weighted Moving Average) min-heap to prioritize the "quietest" circuit — the one that has sent the fewest cells recently. This gives interactive traffic priority over bulk transfers.

### KIST's Limitations

After 10 years of deployment, three limitations are well-understood:

**1. Fixed 2ms interval (Tor ticket #40168)**

KIST wakes up every 2ms regardless of link conditions. On a relay with a 200ms RTT guard link, the scheduler wakes 100 times per round-trip. For 99 of those wakes, `cwnd - unacked` is zero because ACKs haven't returned yet. The scheduler does a `getsockopt()` syscall, computes a zero budget, and goes back to sleep. Pure overhead.

On a 1ms LAN link, 2ms is too slow — the pipe drains between scheduler wakes, leaving throughput on the table.

**2. Static buffer factor (Tor ticket #24694)**

KIST adds a fixed `extra_space` to the write budget to account for bytes that will drain from the kernel buffer before the next scheduler wake. This factor is the same regardless of RTT:

- On a 1ms link with a 2ms interval, the buffer drains 2x between wakes — a small extra factor is appropriate
- On a 200ms link with a 2ms interval, essentially nothing drains between wakes — any extra factor just causes bufferbloat

The Tor project has had ticket #24694 open since 2018 acknowledging this, with no fix merged.

**3. RTT-blind EWMA (no ticket)**

KIST's EWMA priority gives the "quietest" circuit the highest priority. But a circuit routed through a 200ms path naturally sends fewer cells per unit time than a circuit on a 20ms path — it *looks* quiet even when it's fully saturating its share.

The result: high-RTT circuits get systematically deprioritized. A Tokyo-to-Frankfurt circuit gets starved by a Virginia-to-Virginia circuit on the same relay, even when both are equally active. This violates BDP-fair scheduling.

### SKIPS Design

SKIPS addresses all three limitations while maintaining KIST's core architecture (TCP_INFO queries + EWMA min-heap + per-channel write budgets).

#### RTT-Adaptive Interval

```
interval = clamp(min_rtt_across_channels / 4, 1ms, 100ms)
```

The scheduler queries `tcpi_rtt` from TCP_INFO for each pending channel. The minimum RTT across all active channels determines the interval. Dividing by 4 means the scheduler wakes ~4 times per RTT — enough to keep the pipe full without busy-spinning.

| Link RTT | KIST interval | SKIPS interval | Wakes per RTT |
|----------|---------------|----------------|---------------|
| 1ms      | 2ms           | 1ms            | 1 → 4         |
| 20ms     | 2ms           | 5ms            | 10 → 4        |
| 100ms    | 2ms           | 25ms           | 50 → 4        |
| 200ms    | 2ms           | 50ms           | 100 → 4       |

The interval is updated at the end of each scheduling tick, with a >20% change threshold to avoid timer churn. `moor_event_set_timer_interval()` adjusts the repeating timer in-place.

#### RTT-Scaled Buffer Factor

```
buf_factor = clamp(interval_ms / rtt_ms, 0.05, 1.0)
extra = EXTRA_SPACE * buf_factor
```

Short interval relative to RTT = small buffer (we'll wake again soon). Long interval = more buffer to keep the pipe full.

| Link RTT | Interval | Buffer factor | Extra (32KB base) |
|----------|----------|---------------|-------------------|
| 1ms      | 1ms      | 1.0           | 32 KB             |
| 20ms     | 5ms      | 0.25          | 8 KB              |
| 100ms    | 25ms     | 0.25          | 8 KB              |
| 200ms    | 50ms     | 0.25          | 8 KB              |

This directly addresses Tor #24694: high-RTT links get less buffer, preventing bufferbloat. Low-RTT links get full buffer to maximize throughput.

#### CC-Aware EWMA Boost

Before each scheduling pick, SKIPS temporarily scales EWMA weights by circuit RTT:

```
adjusted_ewma = ewma * (min_rtt / circuit_rtt)
```

A circuit with 2x the RTT gets its EWMA halved — it looks "quieter," so it gets more scheduling priority. This compensates for the natural throughput disadvantage of high-RTT paths.

The boost is applied per-tick and the natural EWMA decay undoes it over time — no persistent state modification. The min-heap is rebuilt after scaling (O(n) heapify, where n = active circuits on this channel).

#### Burst Mode

When a channel has more than 16 active circuits, SKIPS pops 4 cells per pick instead of 1. This amortizes the heap operations over more cells, reducing scheduling overhead at high circuit counts. Below 16 circuits, single-cell pops give finer-grained fairness.

#### Nonce-Safe Send Path

KIST uses a separate encryption path: cells are AEAD-encrypted into a channel outbuf, then batch-flushed to the kernel. This creates a nonce-ordering hazard when other code paths (DESTROY cells, CREATE from EXTEND) send on the same connection via the standard `connection_send_cell()` path — nonces go out of order and the link dies.

SKIPS avoids this by using the standard `moor_connection_send_cell()` for all sends, including scheduler-initiated ones. The scheduler controls *which* circuit sends and *how much*, but the actual encrypt+send path is shared with all other code. This is slightly less efficient (no batched kernel writes) but eliminates an entire class of bugs.

#### Selective Deferral

Not all cells benefit from scheduling. SKIPS only defers relay-side forward cells (`direction == 0 && circ->n_chan != NULL`) — the path where multiple circuits compete for one outbound link. All other paths flush immediately:

- **Client circuits** — latency-sensitive (circuit builds, ESTABLISH_INTRO, RENDEZVOUS)
- **HS circuits** — same
- **Backward relay cells** — no channel contention (p_chan not set on relay circuits)
- **No-channel paths** — early circuit build before channel assignment

This design was driven by a real bug: deferring ESTABLISH_INTRO cells caused a race where the intro relay received INTRODUCE1 before ESTABLISH_INTRO, breaking hidden service reachability.

### Implementation

SKIPS is implemented in ~400 lines of C in `src/scheduler.c`, with supporting changes in `src/circuit.c` (per-circuit queues, flush-before-DESTROY), `src/channel.c` (outbuf append/flush, EWMA min-heap), and `include/moor/limits.h` (tuning constants).

Key data structures:
- **Per-circuit cell queues** (`cell_queue_n`, `cell_queue_p`) — linked lists of pre-AEAD relay cells
- **Circuitmux** — per-channel EWMA min-heap selecting which circuit sends next
- **Pending channel list** — simple array of channels with queued cells, drained each tick
- **TCP_INFO cache** — per-channel `kist_cwnd`, `kist_unacked`, `kist_mss`, `kist_notsent`, `kist_rtt_us`

The scheduler runs as a repeating timer in the event loop. On non-Linux platforms (no TCP_INFO), it falls back to KISTLite defaults (cwnd=128, mss=1460) — functional but without kernel-informed write budgets.

### Measured Results

Tested on a 15-relay fleet across 8 countries (US, NL, IE, DE, JP, SG, IN, AU) with t3.micro instances and 3 dedicated relays.

**Exit circuit latency (HTTP request through 3 PQ hops):**

| Metric | Phase 4 (fixed 2ms) | Phase 5 (SKIPS) |
|--------|---------------------|-----------------|
| Median | 1048ms              | 892ms           |
| Floor  | 932ms               | 881ms           |
| P95    | 1293ms              | 1255ms          |

~15% improvement at the median from RTT-adaptive scheduling alone.

**Hidden service (cold rendezvous):** 8-16s depending on DHT lookup path (6 hops, PQ hybrid crypto, PIR descriptor fetch).

**Hidden service (warm, circuit reuse):** 1.5-1.7s.

### Bugs Found During Development

Building SKIPS surfaced three bugs in the cell queue path that existed before SKIPS but were masked by the previous direct-send architecture:

1. **Mux counter leak** — when `moor_connection_send_cell()` failed, the popped cell was counted by `notify_cells(+1)` but not by `notify_xmit`. The mux `queued_cells` counter leaked +1 per failure, eventually triggering permanent backpressure. Manifested as SSH sessions stalling after sustained use.

2. **DESTROY/flush race** — when a circuit was torn down, DESTROY was sent immediately but SKIPS-deferred cells were still in the queue. DESTROY arrived at the next relay first, causing it to discard the queued cells. Manifested as INTRODUCE1 cells being lost, breaking hidden service connections.

3. **ESTABLISH_INTRO race** — the relay never sent RELAY_INTRO_ESTABLISHED acknowledgement, so the HS published its descriptor before the intro relay registered the intro point. Clients sent INTRODUCE1 to a relay that didn't know about the HS. Fixed by adding the ack and blocking until received.

### Comparison Table

| Aspect | Tor KIST | SKIPS |
|--------|----------|-------|
| Interval | Fixed 2ms | RTT-adaptive: min_rtt/4 |
| Buffer factor | Static 1.0 | RTT-scaled: interval/rtt |
| Cells per pop | 1 | 1 (burst 4 when >16 circuits) |
| EWMA fairness | RTT-blind | CC-aware: boost high-RTT circuits |
| Platform | Linux-only | Linux + KISTLite fallback |
| Encryption path | Separate outbuf | Shared send_cell (nonce-safe) |
| Cell deferral | All relay cells | Relay forward only (latency-safe) |
| Channel states | 5 (known bugs) | 4 (IDLE, PENDING, WAITING_TO_WRITE, CLOSED) |
| Crypto | AES-128-CTR + RSA-1024 | ChaCha20-Poly1305 + X25519 + Kyber768 |

### Future Work

- **Per-circuit write budgets** — currently the write budget is per-channel. Per-circuit budgets would prevent a single bulk circuit from consuming the entire channel budget in one tick.
- **Batched kernel writes** — the current nonce-safe design sends one cell per `send()` syscall. A connection-level write lock could enable batched writes without nonce races.
- **EWMA parameter auto-tuning** — the decay factor and tick length are static. Adapting them to circuit count and load could improve fairness under varying conditions.

### References

- Jansen, R., Geddes, J., Wacek, C., Sherr, M., Syverson, P. "Never Been KIST: Tor's Congestion Management Blossoms with Kernel-Informed Socket Transport." USENIX Security 2014.
- Tor ticket #24694: "KIST: Use RTT to determine the 'extra_space' value"
- Tor Proposal 324: "RTT-based Congestion Control for Tor"
- MOOR source: https://github.com/0xdeadbeefnetwork/MOOR_PQ
