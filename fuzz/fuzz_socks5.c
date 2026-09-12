/* F-15 · fuzz the three SOCKS5 parsers a local application talks to.
 *
 * The first input byte picks the negotiation stage; the rest is what the
 * application sent. The client struct is what the listener has for a fresh
 * connection — zeroed, with no socket: replies go to send() on fd -1 and
 * fail with EBADF, which is the only side effect the parsers have before a
 * request reaches circuit code, and with no circuits built that code returns
 * NULL. Anything else this harness reaches is the parser's own doing.
 *
 * One exclusion: a CONNECT whose destination is a `.moor` name is not parsing,
 * it is the hidden-service path -- socks5.c:2252 spawns a worker thread per
 * request, which under fuzzing cost a thread create per execution (275/s
 * against thousands for the other stages) and needs a network to mean
 * anything. The request layout is fixed (ver, cmd, rsv, atyp, then for
 * atyp 3 a length-prefixed domain), so the harness reads the domain off the
 * wire and skips only that case; every other malformed request goes in. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "moor/moor.h"
#include "fuzz_stubs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    moor_socks5_client_t client;
    memset(&client, 0, sizeof(client));
    client.client_fd = -1;
    client.udp_fd = -1;
    const uint8_t *msg = data + 1;
    size_t len = size - 1;
    switch (data[0] % 3) {
    case 0:  client.state = SOCKS5_STATE_GREETING; moor_socks5_handle_greeting(&client, msg, len); break;
    case 1:  client.state = SOCKS5_STATE_AUTH;     moor_socks5_handle_auth(&client, msg, len);     break;
    default:
        if (len >= 5 && msg[3] == 3) {                 /* atyp 3: domain name */
            size_t dlen = msg[4];
            /* The parser trims a trailing dot and reads the copied name with
             * strlen, so an embedded NUL can end the name early: a suffix
             * check here can be fooled. Any ".moor" sequence anywhere in the
             * domain bytes is excluded instead -- conservative, and the only
             * inputs it drops are ones bound for the thread path anyway. */
            const uint8_t *d = msg + 5;
            size_t avail = len - 5 < dlen ? len - 5 : dlen;
            for (size_t i = 0; i + 5 <= avail; i++) {
                if (d[i] == '.' && (d[i+1] | 0x20) == 'm' && (d[i+2] | 0x20) == 'o' &&
                    (d[i+3] | 0x20) == 'o' && (d[i+4] | 0x20) == 'r')
                    return 0;
            }
        }
        client.state = SOCKS5_STATE_REQUEST;  moor_socks5_handle_request(&client, msg, len);  break;
    }
    return 0;
}
