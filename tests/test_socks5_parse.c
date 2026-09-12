/* The SOCKS5 request parser, on its own.
 *
 * moor_socks5_parse_request() was split out of moor_socks5_handle_request()
 * on 2026-09-12 so the byte layout and address normalisation can be tested and
 * fuzzed without the routing behind them. These cases pin what the handler
 * did before the split: accepted shapes, rejected shapes, and the three
 * normalisations on a domain name (lowercase, trailing dot, bare v3 base32). */
#include "moor/moor.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* The library objects call back into main.c for these. Stubbed so the
 * test links against the real built objects without dragging in main(). */
void moor_hs_event_invalidate_circuit(moor_circuit_t *circ) { (void)circ; }
void moor_hs_event_nullify_conn(moor_connection_t *conn)    { (void)conn; }
void moor_handle_sighup(void)     { }
void moor_graceful_shutdown(void) { }
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;
int g_use_bridges = 0;
void moor_request_consensus_refresh(void) { }

static int checks = 0, failures = 0;
#define OK(cond, msg) do { checks++; if (cond) printf("  ok    %s\n", msg); \
    else { failures++; printf("  FAIL  %s\n", msg); } } while (0)

static int parse(const uint8_t *req, size_t len, moor_socks5_client_t *c, uint8_t *cmd) {
    memset(c, 0, sizeof(*c));
    c->client_fd = -1;          /* replies go to send() and fail; nothing is listening */
    *cmd = 0;
    return moor_socks5_parse_request(c, req, len, cmd);
}

int main(void) {
    moor_log_set_level(MOOR_LOG_FATAL);
    moor_socks5_client_t c; uint8_t cmd;

    printf("== accepted shapes ==\n");
    const uint8_t v4[] = {5,1,0,1, 10,0,0,1, 0x1f,0x90};
    OK(parse(v4, sizeof v4, &c, &cmd) == 0 && cmd == 1 &&
       strcmp(c.target_addr, "10.0.0.1") == 0 && c.target_port == 8080,
       "IPv4 CONNECT: address text and port");
    const uint8_t dom[] = {5,1,0,3, 11, 'E','x','a','m','p','l','e','.','C','o','M', 0,80};
    OK(parse(dom, sizeof dom, &c, &cmd) == 0 && strcmp(c.target_addr, "example.com") == 0 && c.target_port == 80,
       "domain CONNECT: lowercased");
    const uint8_t fqdn[] = {5,1,0,3, 12, 'e','x','a','m','p','l','e','.','c','o','m','.', 0,80};
    OK(parse(fqdn, sizeof fqdn, &c, &cmd) == 0 && strcmp(c.target_addr, "example.com") == 0,
       "domain CONNECT: trailing FQDN dot stripped");
    uint8_t b32[5 + 77 + 2] = {5,1,0,3, 77};
    memset(b32 + 5, 'a', 77); b32[5+77] = 0; b32[5+77+1] = 80;
    OK(parse(b32, sizeof b32, &c, &cmd) == 0 && strlen(c.target_addr) == 82 &&
       strcmp(c.target_addr + 77, ".moor") == 0,
       "bare 77-char base32 gets .moor appended");
    uint8_t v6[4 + 16 + 2] = {5,1,0,4}; v6[4+15] = 1; v6[4+16] = 0x01; v6[4+17] = 0xbb;  /* ::1, port 443 */
    OK(parse(v6, sizeof v6, &c, &cmd) == 0 && strcmp(c.target_addr, "::1") == 0 && c.target_port == 443,
       "IPv6 CONNECT: inet_ntop text and port");
    const uint8_t res[] = {5,0xF0,0,3, 3,'a','b','c', 0,0};
    OK(parse(res, sizeof res, &c, &cmd) == 0 && cmd == 0xF0 && strcmp(c.target_addr, "abc") == 0,
       "RESOLVE (0xF0) is a command the parser accepts");

    printf("== rejected shapes ==\n");
    OK(parse(v4, 6, &c, &cmd) == -1, "shorter than 7 bytes");
    const uint8_t bind[] = {5,2,0,1, 10,0,0,1, 0,80};
    OK(parse(bind, sizeof bind, &c, &cmd) == -1, "BIND (0x02) is unsupported");
    const uint8_t v4short[] = {5,1,0,1, 10,0,0, 0,80};
    OK(parse(v4short, sizeof v4short, &c, &cmd) == -1, "IPv4 with a byte missing");
    const uint8_t dom0[] = {5,1,0,3, 0, 0,80};
    OK(parse(dom0, sizeof dom0, &c, &cmd) == -1, "domain length 0");
    const uint8_t domcut[] = {5,1,0,3, 11, 'e','x','a','m','p','l','e','.','c','o'};
    OK(parse(domcut, sizeof domcut, &c, &cmd) == -1, "domain truncated before its port");
    const uint8_t atyp[] = {5,1,0,9, 10,0,0,1, 0,80};
    OK(parse(atyp, sizeof atyp, &c, &cmd) == -1, "unknown address type");
    const uint8_t onion[] = {5,1,0,3, 9, 'a','b','c','.','o','n','i','o','n', 0,80};
    OK(parse(onion, sizeof onion, &c, &cmd) == -1, "Tor .onion rejected at ingress");
    const uint8_t v6short[4 + 15 + 2] = {5,1,0,4};
    OK(parse(v6short, sizeof v6short, &c, &cmd) == -1, "IPv6 with a byte missing");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
