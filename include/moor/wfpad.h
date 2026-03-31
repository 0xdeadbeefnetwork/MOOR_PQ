/*
 * MOOR -- WTF-PAD adaptive padding state machine
 *
 * Each padding "machine" is a small Markov chain where transitions
 * and inter-arrival times are sampled from configurable distributions
 * that mimic real traffic patterns.
 */
#ifndef MOOR_WFPAD_H
#define MOOR_WFPAD_H

#include <stdint.h>

#define WFPAD_MAX_STATES    4
#define WFPAD_IAT_BINS      8    /* Log-scale histogram bins */

/* IAT histogram: bins[i] covers delay range [lo_ms, hi_ms) */
typedef struct {
    double   prob[WFPAD_IAT_BINS];     /* probability weight per bin */
    uint32_t lo_ms[WFPAD_IAT_BINS];    /* bin lower bound (ms) */
    uint32_t hi_ms[WFPAD_IAT_BINS];    /* bin upper bound (ms) */
} wfpad_iat_t;

typedef struct {
    wfpad_iat_t iat;
    double transition_on_real[WFPAD_MAX_STATES]; /* P(next_state | real cell) */
    double transition_on_pad[WFPAD_MAX_STATES];  /* P(next_state | pad cell) */
    int    send_padding;     /* whether this state generates padding */
    int    max_pads;         /* max padding cells in this state (0=unlimited) */
} wfpad_state_t;

typedef struct {
    const char *name;
    int num_states;
    wfpad_state_t states[WFPAD_MAX_STATES];
} wfpad_machine_t;

/* Per-circuit runtime state */
typedef struct {
    const wfpad_machine_t *machine;
    int      current_state;
    int      pads_sent;             /* pads sent in current state */
    uint64_t next_pad_time_ms;      /* when next padding cell is due */
    /* Per-circuit randomized machine (machine ptr points here after init) */
    wfpad_machine_t own_machine;
    /* Constant-rate floor: minimum cell rate regardless of state machine */
    uint32_t constant_floor_ms;     /* min ms between any cells, 0=disabled */
    uint64_t last_any_cell_ms;      /* timestamp of last cell (real or pad) */
    /* FRONT: randomized front padding (Gong & Wang 2020) */
    uint16_t front_target;          /* N cells to inject at start of data */
    uint16_t front_sent;            /* cells injected so far */
    int      front_active;          /* 1 during front phase */
    uint64_t front_start_ms;        /* when front phase began */
    /* Volume padding: pad total cells to next power of 2 */
    uint32_t real_cells_sent;       /* real data cells sent on this circuit */
} wfpad_circuit_state_t;

/* Built-in preset machines */
extern const wfpad_machine_t wfpad_machine_web;
extern const wfpad_machine_t wfpad_machine_stream;
extern const wfpad_machine_t wfpad_machine_generic;

/* Find a machine by name. Returns NULL if not found. */
const wfpad_machine_t *moor_wfpad_find_machine(const char *name);

/* Initialize per-circuit state with the given machine */
void moor_wfpad_init_circuit(wfpad_circuit_state_t *state,
                              const wfpad_machine_t *machine);

/*
 * Initialize per-circuit state with a RANDOMIZED copy of the machine.
 * Each circuit gets unique IAT distributions and transition probabilities,
 * making the state machine unlearnable by observing individual circuits.
 */
void moor_wfpad_init_circuit_randomized(wfpad_circuit_state_t *state,
                                         const wfpad_machine_t *base);

/*
 * Notify the state machine that a real cell was sent/received.
 * May trigger a state transition. Activates FRONT phase on first call.
 */
void moor_wfpad_on_real_cell(wfpad_circuit_state_t *state, uint64_t now_ms);

/*
 * Notify that any cell (real or padding) was sent.
 * Updates the constant-rate floor timestamp.
 */
void moor_wfpad_on_any_cell(wfpad_circuit_state_t *state, uint64_t now_ms);

/*
 * Check if padding should be sent now (called from timer).
 * Returns 1 if a padding cell should be injected, 0 if not.
 * Checks (in priority order): FRONT phase, constant-rate floor, WTF-PAD machine.
 */
int moor_wfpad_tick(wfpad_circuit_state_t *state, uint64_t now_ms);

/*
 * Compute how many padding cells needed to round up to next power of 2.
 * Returns 0 if already at a power of 2.
 */
uint32_t moor_wfpad_volume_pad_count(uint32_t real_cells);

#endif /* MOOR_WFPAD_H */
