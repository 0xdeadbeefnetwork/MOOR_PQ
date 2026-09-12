/* F-15 · fuzz the node-descriptor wire parser.
 *
 * moor_node_descriptor_deserialize() runs on every relay entry a client takes
 * from a consensus it fetched, so a byte pattern that breaks it here breaks
 * every client on the network. libFuzzer supplies the bytes; the library is
 * built with ASan+UBSan so an overread past data_len is a finding, not noise.
 * Nothing here is set up beyond what a real caller has: a zeroed struct. */
#include <stddef.h>
#include <stdint.h>
#include "moor/moor.h"
#include "fuzz_stubs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    moor_node_descriptor_t desc;
    moor_node_descriptor_deserialize(&desc, data, size);
    return 0;
}
