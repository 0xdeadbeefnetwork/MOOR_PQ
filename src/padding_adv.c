/*
 * MOOR -- Advanced traffic analysis resistance (three-layer padding)
 */
#include "moor/moor.h"
#include <string.h>

/* Constant-rate interval: pad every 50ms */
#define CONSTANT_RATE_MS    50

/* Adaptive: burst gap threshold */
#define BURST_GAP_MS        200
/* Cover cells to inject after gap */
#define BURST_COVER_COUNT   5
/* Cover cell interval */
#define BURST_COVER_MS      30

/* Jitter range: 0-10ms */
#define JITTER_MAX_MS       10

void moor_padding_adv_init(moor_padding_adv_state_t *state, int mode) {
    memset(state, 0, sizeof(*state));
    state->mode = mode;
}

int moor_padding_adv_should_pad(moor_padding_adv_state_t *state,
                                 uint64_t current_ms) {
    if (!(state->mode & MOOR_PADDING_CONSTANT))
        return 0;

    if (state->last_pad_cell_ms == 0) {
        state->last_pad_cell_ms = current_ms;
        return 0;
    }

    if (current_ms >= state->last_pad_cell_ms &&
        current_ms - state->last_pad_cell_ms >= CONSTANT_RATE_MS) {
        state->last_pad_cell_ms = current_ms;
        return 1;
    }

    return 0;
}

int moor_padding_adv_on_real_cell(moor_padding_adv_state_t *state,
                                   uint64_t current_ms) {
    if (!(state->mode & MOOR_PADDING_ADAPTIVE)) {
        state->last_real_cell_ms = current_ms;
        return 0;
    }

    int cover_cells = 0;

    /* Detect burst gap */
    if (state->last_real_cell_ms > 0 &&
        current_ms >= state->last_real_cell_ms &&
        current_ms - state->last_real_cell_ms > BURST_GAP_MS) {
        /* Gap detected -- inject cover cells */
        state->burst_active = 1;
        state->burst_cover_remaining = BURST_COVER_COUNT;
        cover_cells = BURST_COVER_COUNT;
    }

    state->last_real_cell_ms = current_ms;
    /* Also update pad timestamp for constant-rate sync */
    state->last_pad_cell_ms = current_ms;
    return cover_cells;
}

int moor_padding_adv_burst_cover(moor_padding_adv_state_t *state,
                                  uint64_t current_ms) {
    if (!state->burst_active || state->burst_cover_remaining <= 0) {
        state->burst_active = 0;
        return 0;
    }

    /* Send cover cells at BURST_COVER_MS intervals */
    if (state->last_pad_cell_ms > 0 &&
        current_ms >= state->last_pad_cell_ms &&
        current_ms - state->last_pad_cell_ms < BURST_COVER_MS) {
        return 0; /* Too soon */
    }

    state->burst_cover_remaining--;
    state->last_pad_cell_ms = current_ms;

    if (state->burst_cover_remaining <= 0)
        state->burst_active = 0;

    return 1;
}

uint64_t moor_padding_adv_jitter(moor_padding_adv_state_t *state) {
    if (!(state->mode & MOOR_PADDING_JITTER))
        return 0;

    uint32_t r;
    moor_crypto_random((uint8_t *)&r, sizeof(r));
    state->jitter_delay_ms = r % (JITTER_MAX_MS + 1);
    return state->jitter_delay_ms;
}
