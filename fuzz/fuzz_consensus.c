/* F-15 · fuzz the consensus text parser.
 *
 * moor_consensus_deserialize() is the first thing a client runs on bytes a
 * directory authority sent it, and the F-27 stack overflow lived one call
 * later in this same path. The caller pattern is init(capacity) → deserialize
 * → cleanup; capacity is deliberately small so a relay count the parser fails
 * to bound shows up as an ASan write past relays[] on the first try. The
 * parsed consensus then goes through moor_consensus_verify_hybrid() against
 * two all-zero trusted keys: no signature can pass, but the signature-count
 * and slot bounds F-20/F-21/F-27 fixed are exercised on every input. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "moor/moor.h"
#include "fuzz_stubs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    moor_consensus_t cons;
    if (moor_consensus_init(&cons, 8) != 0) return 0;
    if (moor_consensus_deserialize(&cons, data, size) == 0) {
        moor_trusted_da_key_t keys[2];
        memset(keys, 0, sizeof(keys));
        moor_consensus_verify_hybrid(&cons, keys, 2);
    }
    moor_consensus_cleanup(&cons);
    return 0;
}
