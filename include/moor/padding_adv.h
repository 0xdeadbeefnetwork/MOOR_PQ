/*
 * MOOR -- Advanced traffic analysis resistance (three-layer padding)
 */
#ifndef MOOR_PADDING_ADV_H
#define MOOR_PADDING_ADV_H

#include <stdint.h>

/* Padding state per circuit */
typedef struct {
    int      mode;                  /* Bitmask: MOOR_PADDING_CONSTANT|ADAPTIVE|JITTER */
    uint64_t last_real_cell_ms;     /* Timestamp of last real cell (ms) */
    uint64_t last_pad_cell_ms;      /* Timestamp of last padding cell (ms) */
    int      burst_active;          /* In a burst gap? */
    int      burst_cover_remaining; /* Cover cells left to inject */
    uint64_t jitter_delay_ms;       /* Current jitter delay */
} moor_padding_adv_state_t;

/* Initialize padding state */
void moor_padding_adv_init(moor_padding_adv_state_t *state, int mode);

/*
 * Check if a padding cell should be sent now (constant-rate layer).
 * Returns 1 if a padding cell should be sent, 0 otherwise.
 * current_ms: current time in milliseconds.
 */
int moor_padding_adv_should_pad(moor_padding_adv_state_t *state,
                                 uint64_t current_ms);

/*
 * Notify of a real cell being sent/received (adaptive layer).
 * Returns number of burst cover cells to inject (0 if none).
 */
int moor_padding_adv_on_real_cell(moor_padding_adv_state_t *state,
                                   uint64_t current_ms);

/*
 * Get jitter delay before forwarding a cell (jitter layer).
 * Returns delay in ms (0-10ms range).
 */
uint64_t moor_padding_adv_jitter(moor_padding_adv_state_t *state);

/*
 * Get the next adaptive cover cell to send after burst gap.
 * Returns 1 if a cover cell should be sent now, 0 if done.
 */
int moor_padding_adv_burst_cover(moor_padding_adv_state_t *state,
                                  uint64_t current_ms);

#endif /* MOOR_PADDING_ADV_H */
