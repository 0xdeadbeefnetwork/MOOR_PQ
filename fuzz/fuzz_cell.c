/* F-15 · fuzz the fixed-size cell and relay-payload parsers.
 *
 * A cell is exactly 514 bytes on the wire and nothing hands the parser less,
 * so inputs shorter than that are not a case. moor_cell_unpack() splits the
 * header; moor_relay_unpack() then reads the 509-byte payload as a relay
 * cell, which is what every hop does to bytes from the hop before it. */
#include <stddef.h>
#include <stdint.h>
#include "moor/moor.h"
#include "fuzz_stubs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < MOOR_CELL_SIZE) return 0;
    moor_cell_t cell;
    moor_cell_unpack(&cell, data);
    moor_relay_payload_t relay;
    moor_relay_unpack(&relay, cell.payload);
    return 0;
}
