/*
 * MOOR -- WTF-PAD adaptive padding state machine
 *
 * Three built-in machines: web, stream, generic.
 * Each is a Markov chain with configurable IAT distributions
 * and state transitions on real/pad events.
 *
 * Enhanced with:
 *   - Per-circuit randomized parameters (unlearnable machines)
 *   - Constant-rate base layer (Tamaraw/Interspace-inspired floor)
 *   - FRONT randomized front padding (Gong & Wang 2020)
 *   - Volume padding support (pad to power-of-2)
 */
#include "moor/moor.h"
#include "moor/wfpad.h"
#include <sodium.h>
#include <string.h>
#include <math.h>

/* ================================================================
 * Built-in machines
 * ================================================================ */

/*
 * Web: HTTP burst/gap pattern
 *   State 0: IDLE    - low-rate keepalive (~500ms)
 *   State 1: BURST   - active, fast padding
 *   State 2: GAP     - fills gaps at ~50ms
 */
const wfpad_machine_t wfpad_machine_web = {
    .name = "web",
    .num_states = 3,
    .states = {
        [0] = { /* IDLE */
            .iat = {
                .prob  = {1.0, 0, 0, 0, 0, 0, 0, 0},
                .lo_ms = {400, 0, 0, 0, 0, 0, 0, 0},
                .hi_ms = {600, 0, 0, 0, 0, 0, 0, 0},
            },
            .transition_on_real = {0.0, 1.0, 0.0, 0.0},  /* IDLE -> BURST on real */
            .transition_on_pad  = {1.0, 0.0, 0.0, 0.0},  /* Stay IDLE on pad */
            .send_padding = 1,
            .max_pads = 0,
        },
        [1] = { /* BURST */
            .iat = {
                .prob  = {0.7, 0.3, 0, 0, 0, 0, 0, 0},
                .lo_ms = {5,  15, 0, 0, 0, 0, 0, 0},
                .hi_ms = {15, 30, 0, 0, 0, 0, 0, 0},
            },
            .transition_on_real = {0.0, 0.8, 0.2, 0.0},  /* BURST: 80% stay, 20% -> GAP */
            .transition_on_pad  = {0.0, 0.9, 0.1, 0.0},
            .send_padding = 1,
            .max_pads = 20,
        },
        [2] = { /* GAP */
            .iat = {
                .prob  = {1.0, 0, 0, 0, 0, 0, 0, 0},
                .lo_ms = {40, 0, 0, 0, 0, 0, 0, 0},
                .hi_ms = {60, 0, 0, 0, 0, 0, 0, 0},
            },
            .transition_on_real = {0.0, 1.0, 0.0, 0.0},  /* GAP -> BURST on real */
            .transition_on_pad  = {1.0, 0.0, 0.0, 0.0},  /* GAP -> IDLE after pads */
            .send_padding = 1,
            .max_pads = 5,
        },
    },
};

/*
 * Stream: Steady-rate pattern (video/audio)
 *   State 0: ACTIVE - constant padding at ~20ms
 *   State 1: PAUSE  - brief pause, resume on real cell
 */
const wfpad_machine_t wfpad_machine_stream = {
    .name = "stream",
    .num_states = 2,
    .states = {
        [0] = { /* ACTIVE */
            .iat = {
                .prob  = {1.0, 0, 0, 0, 0, 0, 0, 0},
                .lo_ms = {15, 0, 0, 0, 0, 0, 0, 0},
                .hi_ms = {25, 0, 0, 0, 0, 0, 0, 0},
            },
            .transition_on_real = {0.95, 0.05, 0.0, 0.0},
            .transition_on_pad  = {0.98, 0.02, 0.0, 0.0},
            .send_padding = 1,
            .max_pads = 0,
        },
        [1] = { /* PAUSE */
            .iat = {
                .prob  = {1.0, 0, 0, 0, 0, 0, 0, 0},
                .lo_ms = {15, 0, 0, 0, 0, 0, 0, 0},
                .hi_ms = {25, 0, 0, 0, 0, 0, 0, 0},
            },
            .transition_on_real = {1.0, 0.0, 0.0, 0.0},  /* Resume on real */
            .transition_on_pad  = {0.0, 1.0, 0.0, 0.0},  /* Stay paused */
            .send_padding = 1,
            .max_pads = 0,
        },
    },
};

/*
 * Generic: Balanced defense (default)
 *   State 0: ON  - moderate padding at ~10ms
 *   State 1: OFF - slow padding at ~100ms
 */
const wfpad_machine_t wfpad_machine_generic = {
    .name = "generic",
    .num_states = 2,
    .states = {
        [0] = { /* ON */
            .iat = {
                .prob  = {0.6, 0.4, 0, 0, 0, 0, 0, 0},
                .lo_ms = {5,  12, 0, 0, 0, 0, 0, 0},
                .hi_ms = {12, 20, 0, 0, 0, 0, 0, 0},
            },
            .transition_on_real = {0.9, 0.1, 0.0, 0.0},
            .transition_on_pad  = {0.85, 0.15, 0.0, 0.0},
            .send_padding = 1,
            .max_pads = 0,
        },
        [1] = { /* OFF */
            .iat = {
                .prob  = {1.0, 0, 0, 0, 0, 0, 0, 0},
                .lo_ms = {80, 0, 0, 0, 0, 0, 0, 0},
                .hi_ms = {120, 0, 0, 0, 0, 0, 0, 0},
            },
            .transition_on_real = {1.0, 0.0, 0.0, 0.0},  /* Resume on real */
            .transition_on_pad  = {0.0, 1.0, 0.0, 0.0},  /* Stay off */
            .send_padding = 1,
            .max_pads = 0,
        },
    },
};

/* ================================================================
 * Internal helpers
 * ================================================================ */

/* Sample a uniform random double in [0,1] */
static double rand_double(void) {
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    return (double)r / (double)UINT32_MAX;
}

/* Sample from Rayleigh distribution: sigma * sqrt(-2 * ln(U))
 * Used for FRONT padding cell count. */
static uint16_t sample_rayleigh(uint32_t sigma, uint16_t max_val) {
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    double u = ((double)(r | 1)) / (double)UINT32_MAX; /* (0,1] */
    double val = (double)sigma * sqrt(-2.0 * log(u));
    if (val < 0) val = 0;
    if (val > (double)max_val) val = (double)max_val;
    return (uint16_t)val;
}

/* Sample a delay from the IAT histogram of the current state */
static uint64_t sample_iat(const wfpad_state_t *ws) {
    /* Weighted random bin selection */
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    double u = (double)r / (double)UINT32_MAX;

    double cumul = 0.0;
    int bin = 0;
    for (int i = 0; i < WFPAD_IAT_BINS; i++) {
        cumul += ws->iat.prob[i];
        if (u < cumul) { bin = i; break; }
        if (i == WFPAD_IAT_BINS - 1) bin = i; /* fallback to last bin */
    }

    /* Uniform within bin [lo_ms, hi_ms) — rejection sampling to avoid
     * modulo bias (fix #174: padding timing must be unbiased) */
    uint32_t lo = ws->iat.lo_ms[bin];
    uint32_t hi = ws->iat.hi_ms[bin];
    if (hi <= lo) return lo;

    uint32_t range = hi - lo;
    uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    uint32_t r2;
    do {
        randombytes_buf(&r2, sizeof(r2));
    } while (r2 >= limit);
    return lo + (r2 % range);
}

/* Transition based on probability vector */
static int transition(const double *probs, int num_states) {
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    double u = (double)r / (double)UINT32_MAX;

    double cumul = 0.0;
    for (int i = 0; i < num_states; i++) {
        cumul += probs[i];
        if (u <= cumul) return i;
    }
    return 0; /* fallback */
}

/* ================================================================
 * Machine lookup
 * ================================================================ */

const wfpad_machine_t *moor_wfpad_find_machine(const char *name) {
    if (!name || name[0] == '\0') return NULL;
    if (strcmp(name, "web") == 0)     return &wfpad_machine_web;
    if (strcmp(name, "stream") == 0)  return &wfpad_machine_stream;
    if (strcmp(name, "generic") == 0) return &wfpad_machine_generic;
    if (strcmp(name, "none") == 0)    return NULL;
    return NULL;
}

/* ================================================================
 * Initialization
 * ================================================================ */

void moor_wfpad_init_circuit(wfpad_circuit_state_t *state,
                              const wfpad_machine_t *machine) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->machine = machine;
    state->current_state = 0;
    state->pads_sent = 0;
    state->next_pad_time_ms = 0;
}

void moor_wfpad_init_circuit_randomized(wfpad_circuit_state_t *state,
                                         const wfpad_machine_t *base) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    if (!base) return;

    /* Copy base machine into per-circuit storage */
    memcpy(&state->own_machine, base, sizeof(wfpad_machine_t));

    /* Randomize each state's parameters so every circuit has a unique
     * fingerprint.  An observer cannot learn "the" machine from one
     * circuit and apply it to another. */
    for (int s = 0; s < state->own_machine.num_states; s++) {
        wfpad_state_t *ws = &state->own_machine.states[s];

        /* Perturb IAT bin boundaries by ±30% */
        for (int b = 0; b < WFPAD_IAT_BINS; b++) {
            if (ws->iat.prob[b] <= 0.0) continue;
            double factor = 0.7 + rand_double() * 0.6; /* [0.7, 1.3] */
            ws->iat.lo_ms[b] = (uint32_t)((double)ws->iat.lo_ms[b] * factor);
            ws->iat.hi_ms[b] = (uint32_t)((double)ws->iat.hi_ms[b] * factor);
            if (ws->iat.hi_ms[b] <= ws->iat.lo_ms[b])
                ws->iat.hi_ms[b] = ws->iat.lo_ms[b] + 1;
        }

        /* Perturb IAT bin probabilities by ±25%, then renormalize */
        double prob_sum = 0.0;
        for (int b = 0; b < WFPAD_IAT_BINS; b++) {
            if (ws->iat.prob[b] > 0.0) {
                ws->iat.prob[b] *= (0.75 + rand_double() * 0.5);
                if (ws->iat.prob[b] < 0.01) ws->iat.prob[b] = 0.01;
            }
            prob_sum += ws->iat.prob[b];
        }
        if (prob_sum > 0.0) {
            for (int b = 0; b < WFPAD_IAT_BINS; b++)
                ws->iat.prob[b] /= prob_sum;
        }

        /* Perturb transition probabilities by ±20%, then renormalize */
        for (int pass = 0; pass < 2; pass++) {
            double *probs = (pass == 0) ? ws->transition_on_real
                                        : ws->transition_on_pad;
            double sum = 0.0;
            for (int i = 0; i < WFPAD_MAX_STATES; i++) {
                if (probs[i] > 0.0) {
                    probs[i] *= (0.8 + rand_double() * 0.4); /* [0.8, 1.2] */
                    if (probs[i] < 0.001) probs[i] = 0.001;
                }
                sum += probs[i];
            }
            if (sum > 0.0) {
                for (int i = 0; i < WFPAD_MAX_STATES; i++)
                    probs[i] /= sum;
            }
        }

        /* Perturb max_pads by ±50% */
        if (ws->max_pads > 0) {
            double f = 0.5 + rand_double() * 1.0; /* [0.5, 1.5] */
            ws->max_pads = (int)((double)ws->max_pads * f);
            if (ws->max_pads < 1) ws->max_pads = 1;
        }
    }

    /* Point machine at our randomized copy */
    state->machine = &state->own_machine;
    state->current_state = 0;
    state->pads_sent = 0;
    state->next_pad_time_ms = 0;

    /* Enable constant-rate floor: minimum 50 cells/sec */
    state->constant_floor_ms = MOOR_TA_CONSTANT_RATE_MS;
    state->last_any_cell_ms = 0;

    /* FRONT padding: will be activated on first real cell */
    state->front_target = 0;
    state->front_sent = 0;
    state->front_active = 0;
    state->front_start_ms = 0;
    state->real_cells_sent = 0;
}

/* ================================================================
 * Events
 * ================================================================ */

void moor_wfpad_on_real_cell(wfpad_circuit_state_t *state, uint64_t now_ms) {
    if (!state || !state->machine) return;

    const wfpad_machine_t *m = state->machine;
    int cur = state->current_state;
    if (cur < 0 || cur >= m->num_states) return;

    /* Track real cell count for volume padding */
    state->real_cells_sent++;

    /* Activate FRONT phase on first real cell */
    if (!state->front_active && state->front_start_ms == 0) {
        state->front_start_ms = now_ms;
        state->front_target = sample_rayleigh(MOOR_TA_FRONT_SIGMA,
                                               MOOR_TA_FRONT_MAX);
        state->front_sent = 0;
        state->front_active = (state->front_target > 0) ? 1 : 0;
    }

    /* Update constant-rate floor timestamp */
    state->last_any_cell_ms = now_ms;

    /* Transition on real cell */
    int next = transition(m->states[cur].transition_on_real, m->num_states);
    if (next != cur) {
        state->current_state = next;
        state->pads_sent = 0;
    }

    /* Schedule next padding from the (possibly new) state */
    if (m->states[state->current_state].send_padding) {
        state->next_pad_time_ms = now_ms + sample_iat(&m->states[state->current_state]);
    }
}

void moor_wfpad_on_any_cell(wfpad_circuit_state_t *state, uint64_t now_ms) {
    if (!state) return;
    state->last_any_cell_ms = now_ms;
}

/* ================================================================
 * Tick (called from timer, ~5ms interval)
 * ================================================================ */

int moor_wfpad_tick(wfpad_circuit_state_t *state, uint64_t now_ms) {
    if (!state || !state->machine) return 0;

    /* --- Priority 1: FRONT padding phase ---
     * Inject N random cells over the first few seconds of data transfer.
     * Disrupts website fingerprinting that relies on the initial burst. */
    if (state->front_active && state->front_sent < state->front_target) {
        uint64_t window_end = state->front_start_ms + MOOR_TA_FRONT_WINDOW_MS;
        if (now_ms < window_end) {
            /* Probabilistic injection: spread cells evenly over remaining window.
             * Each 5ms tick: P(send) = remaining_cells * 5 / remaining_ms */
            uint64_t remaining_ms = window_end - now_ms;
            uint16_t remaining_cells = state->front_target - state->front_sent;
            if (remaining_ms > 0 && remaining_cells > 0) {
                double p = (double)remaining_cells * 5.0 / (double)remaining_ms;
                if (p > 1.0) p = 1.0;
                if (rand_double() < p) {
                    state->front_sent++;
                    state->last_any_cell_ms = now_ms;
                    return 1; /* send padding cell */
                }
            }
        } else {
            /* Window expired: end FRONT phase */
            state->front_active = 0;
        }
    } else if (state->front_active) {
        /* All FRONT cells sent */
        state->front_active = 0;
    }

    /* --- Priority 2: Constant-rate floor ---
     * Guarantees minimum cell rate even when WTF-PAD state machine is
     * in a slow/OFF state.  Prevents silence-based timing inference. */
    if (state->constant_floor_ms > 0 && state->last_any_cell_ms > 0) {
        if (now_ms >= state->last_any_cell_ms + state->constant_floor_ms) {
            state->last_any_cell_ms = now_ms;
            /* Also update WTF-PAD schedule to prevent double-firing */
            if (state->next_pad_time_ms > 0 &&
                state->next_pad_time_ms <= now_ms + state->constant_floor_ms) {
                const wfpad_state_t *ws = &state->machine->states[state->current_state];
                state->next_pad_time_ms = now_ms + sample_iat(ws);
            }
            return 1; /* send padding cell */
        }
    }

    /* --- Priority 3: Normal WTF-PAD state machine --- */
    const wfpad_machine_t *m = state->machine;
    int cur = state->current_state;
    if (cur < 0 || cur >= m->num_states) return 0;

    const wfpad_state_t *ws = &m->states[cur];

    /* Not time yet */
    if (state->next_pad_time_ms == 0 || now_ms < state->next_pad_time_ms)
        return 0;

    /* Check if this state generates padding */
    if (!ws->send_padding) {
        state->next_pad_time_ms = now_ms + sample_iat(ws);
        return 0;
    }

    /* Check max_pads */
    if (ws->max_pads > 0 && state->pads_sent >= ws->max_pads) {
        /* Transition on pad event (max reached) */
        int next = transition(ws->transition_on_pad, m->num_states);
        state->current_state = next;
        state->pads_sent = 0;
        state->next_pad_time_ms = now_ms + sample_iat(&m->states[next]);
        return 0;
    }

    /* Send padding */
    state->pads_sent++;
    state->last_any_cell_ms = now_ms;

    /* Transition on pad event */
    int next = transition(ws->transition_on_pad, m->num_states);
    if (next != cur) {
        state->current_state = next;
        state->pads_sent = 0;
    }

    /* Schedule next */
    state->next_pad_time_ms = now_ms + sample_iat(&m->states[state->current_state]);
    return 1;
}

/* ================================================================
 * Volume padding utility
 * ================================================================ */

uint32_t moor_wfpad_volume_pad_count(uint32_t real_cells) {
    if (real_cells == 0) return 0;

    /* Find next power of 2 >= real_cells */
    uint32_t target = 1;
    while (target < real_cells && target < 0x80000000u)
        target <<= 1;

    return (target > real_cells) ? (target - real_cells) : 0;
}
