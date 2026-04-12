# SKIPS — Sick Kernel Informed Packet Scheduler

## Implementation Plan for MOOR

### Prerequisites (sloppy code fixes needed first)

#### Phase 1 — Crash Prevention (30 min)
- `src/relay.c:163` — `g_extend_pq_inflight` bare `++/--` from threads → use `__sync_fetch_and_add/sub`
- `src/circuit.c:266` — `realloc(g_circuits, ...)` doesn't check NULL return → add check, keep old pointer on failure
- `src/relay.c:2588` — hardcoded `4` for PQ inflight cap → `#define MOOR_MAX_PQ_EXTEND_INFLIGHT 4` in limits.h

#### Phase 2 — Unify RELAY_DATA handling (1-2 hours)
Three files implement the same protocol operation differently:
- `src/relay.c:2013` — exit relay handler (has short-write, XOFF/XON, SENDME)
- `src/main.c:2021` — HS handler (has short-write, SENDME, but different)
- `src/socks5.c:987` — client handler (different again)

Extract into shared `moor_stream_forward_to_target()` called by all three.

#### Phase 2.5 — SKIPS Prerequisites (the big one)
These changes are required before SKIPS can work:

**a) Refactor send_cell to always queue (not inline send)**
- Current: `moor_connection_send_cell()` at `src/connection.c:1185` tries `send()` inline, only queues on EAGAIN
- Needed: ALL cells go to per-circuit queues. The scheduler decides when to flush to kernel.
- The per-circuit queue structs already exist at `src/scheduler.c:157-176` (`moor_circ_queue_init/clear`) but are never populated

**b) Wire up circuitmux as single EWMA authority**
- Current: `src/channel.c:514` has `moor_circuitmux_pick()` (full min-heap, decay, priority) but it's NEVER CALLED
- Current: `src/circuit.c:1761` has a SEPARATE `circ->ewma_cell_count` that diverges from the mux's count
- Fix: remove `circ->ewma_cell_count`, use only `mux->entries[].ewma_cell_count`
- Call `moor_circuitmux_notify_xmit()` after each cell send to update EWMA

**c) Fix backpressure to check circuit queues**
- Current: `src/socks5.c:1790` pauses clients when `conn->outq > 384`
- Current: `src/relay.c:1168` resumes when `conn->outq < 256`
- If cells move to per-circuit queues, `conn->outq` is always near-empty
- Fix: check total queued cells across all circuits on this connection, OR check global queue pressure

**d) Remove dead fields**
- `circuit.h:123` — `last_real_cell_time` (written, never read)
- `circuit.h:110` — `ewma_cell_count` (duplicate of mux's EWMA, remove after wiring mux)

#### Phase 3 — Magic Numbers (20 min)
- `src/socks5.c:525` — hardcoded `498` → use `MOOR_RELAY_DATA`
- `src/relay.c:2588` — hardcoded `4` → constant
- `src/relay.c:30` — hardcoded `30` timeout → constant
- Various IPv4 mask constants in `relay.c:37+` → named defines

---

### SKIPS Implementation (~400 lines in scheduler.c)

#### What Tor's KIST does (baseline)
1. Every 2ms, wake up
2. For each connection with pending cells: `getsockopt(SOL_TCP, TCP_INFO)` to get cwnd, unacked, mss
3. Compute write budget: `limit = (cwnd - unacked) * mss + extra_space - notsent`
4. Pop channels from EWMA priority queue, flush 1 cell at a time, re-insert
5. Stop writing when `written >= limit`
6. Batch flush outbufs to kernel at end

#### What SKIPS improves

| Aspect | Tor KIST | SKIPS |
|--------|----------|-------|
| Interval | Fixed 2ms | RTT-adaptive: `min(2ms, tcpi_rtt/4)` |
| Buffer factor | Static 1.0 | RTT-scaled: `min(interval_ms / tcpi_rtt, 1.0)` (fixes Tor ticket #24694) |
| Cells per pop | 1 (expensive for high circuit counts) | Burst 4 when > 16 active circuits |
| Platform | Linux-only | Graceful KISTLite fallback on non-Linux |
| CC interaction | None | CC-aware: boost EWMA priority for high-RTT circuits |
| Channel states | 5 states with known bugs | 3 states: IDLE, HAS_CELLS, WRITING |

#### Data flow after SKIPS

```
Application data
  → moor_socks5_forward_to_circuit()
    → e2e encrypt (if HS)
    → moor_circuit_send_data()
      → moor_circuit_encrypt_forward()
      → ENQUEUE to circ->cell_queue (NOT conn->outq)
      → moor_circuitmux_notify_cells(chan, circ, 1)
      → moor_skips_channel_has_cells(chan)  // mark channel pending

SKIPS timer fires (every 2ms or RTT/4):
  → for each pending channel:
      getsockopt(fd, SOL_TCP, TCP_INFO) → fill kist_cwnd/unacked/mss/notsent
      compute limit = (cwnd - unacked) * mss + extra - notsent
  → while pending channels exist:
      chan = pop min-EWMA channel
      circ = moor_circuitmux_pick(chan)  // EWMA selects circuit
      cell = circ->cell_queue.pop()
      append to chan->outbuf
      chan->kist_written += cell_wire_size
      moor_circuitmux_notify_xmit(chan, circ, 1)  // update EWMA
      if kist_written >= kist_limit: remove from pending
      else: re-insert channel
  → flush all outbufs to kernel via write()
  → re-add channels that still have cells but hit limit
```

#### Files to modify

| File | Change |
|------|--------|
| `src/scheduler.c` | Replace stubs with full SKIPS: init, timer, scheduling loop, TCP_INFO query |
| `src/connection.c` | `send_cell` queues to circuit instead of inline send |
| `src/channel.c` | Wire `circuitmux_pick` into scheduling, remove orphaned code paths |
| `src/circuit.c` | Remove duplicate `ewma_cell_count`, use mux's exclusively |
| `src/socks5.c` | Backpressure checks circuit queue depth instead of conn->outq |
| `src/relay.c` | Same backpressure fix, flush path uses scheduler |
| `src/main.c` | Same backpressure fix |
| `include/moor/scheduler.h` | Replace KIST stubs with SKIPS API: `moor_skips_init`, `moor_skips_channel_has_cells`, `moor_skips_run` |
| `include/moor/limits.h` | Add SKIPS constants: interval, burst size, buffer factor |
| `include/moor/circuit.h` | Remove `ewma_cell_count`, `last_real_cell_time` |

#### Existing infrastructure that slots in

| Component | File:Line | Status |
|-----------|-----------|--------|
| EWMA circuitmux (min-heap, decay, pick) | `channel.c:340-567` | Complete, never called |
| Channel KIST fields (cwnd, unacked, mss, notsent, limit, written) | `channel.h:104-110` | Allocated, zeroed |
| Per-circuit queue structs | `scheduler.c:157-176` | Exist, never populated |
| KIST stub call sites | `relay.c:1142`, `socks5.c:1164`, `main.c:557`, `channel.c:284` | Wired, no-op |
| Backpressure pause/resume | `socks5.c:1790`, `relay.c:1168` | Works, needs threshold change |
| Event timer system | `event.c:156-176` | Works, used for other timers |

#### TCP_INFO syscall (Linux)

```c
#include <linux/tcp.h>
#include <sys/ioctl.h>

struct tcp_info ti;
socklen_t ti_len = sizeof(ti);
getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len);

uint32_t cwnd    = ti.tcpi_snd_cwnd;
uint32_t unacked = ti.tcpi_unacked;
uint32_t mss     = ti.tcpi_snd_mss;

// Not-sent bytes in kernel buffer
int notsent = 0;
ioctl(fd, SIOCOUTQNSD, &notsent);  // requires Linux >= 2.6.39
```

#### Constants to add to limits.h

```c
#define MOOR_SKIPS_INTERVAL_DEFAULT  2      /* ms between scheduler runs */
#define MOOR_SKIPS_INTERVAL_MIN      1
#define MOOR_SKIPS_INTERVAL_MAX      100
#define MOOR_SKIPS_BURST_THRESHOLD   16     /* circuits before burst mode */
#define MOOR_SKIPS_BURST_SIZE        4      /* cells per pop in burst mode */
#define MOOR_SKIPS_OUTBUF_FLUSH      8      /* cells before kernel flush */
#define MOOR_SKIPS_BUF_FACTOR        1.0    /* sock buffer factor (RTT-adjusted) */
```

#### Order of implementation

1. Phase 1 — crash fixes (atomics, NULL check)
2. Phase 2 — unify RELAY_DATA
3. Phase 2.5a — refactor send_cell to queue-only (biggest change)
4. Phase 2.5b — wire circuitmux, remove duplicate EWMA
5. Phase 2.5c — fix backpressure for circuit queues
6. Phase 2.5d — remove dead fields
7. Phase 3 — magic numbers
8. Phase 4 — implement SKIPS scheduling loop in scheduler.c
9. Phase 5 — RTT-adaptive interval + CC-aware EWMA boost
10. Test on 3-relay fleet, measure latency improvement

### References

- Tor KIST paper: https://www.robgjansen.com/publications/kist-tops2018.pdf
- Tor source: https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/core/or/scheduler_kist.c
- Tor ticket #24694 (RTT-aware factor): https://gitlab.torproject.org/tpo/core/tor/-/issues/24694
- Tor Prop 324 (Vegas CC): https://spec.torproject.org/proposals/324-rtt-congestion-control.html
