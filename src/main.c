#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "moor/moor.h"
#include "moor/kem.h"
#include "moor/transport.h"
#include "moor/transport_shade.h"
#include "moor/transport_mirage.h"
#include "moor/transport_nether.h"
#include "moor/sandbox.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#ifndef MOOR_SYSCONFDIR
#define MOOR_SYSCONFDIR "/usr/local/etc/moor"
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#define MSG_NOSIGNAL 0
#else
#include <unistd.h>
#include <sys/utsname.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>
#include <execinfo.h>
#include <ucontext.h>
#endif

/* Global state */
extern moor_config_t g_config;
char g_config_path[256] = "";
extern void moor_da_update_published_snapshot(moor_da_config_t *config);
static moor_mode_t g_mode = MOOR_MODE_CLIENT;
static char g_bind_addr[64] = "127.0.0.1";
static uint16_t g_or_port = MOOR_DEFAULT_OR_PORT;
static uint16_t g_dir_port = MOOR_DEFAULT_DIR_PORT;
static uint16_t g_socks_port = MOOR_DEFAULT_SOCKS_PORT;
static char g_da_address[64] = "107.174.70.38";
static uint16_t g_da_port = MOOR_DEFAULT_DIR_PORT;
static moor_da_entry_t g_da_list[9];
static int g_num_das = 0;
static char g_hs_dir[256] = "./hs_keys";
static uint16_t g_hs_local_port = 8080;
static moor_consensus_t *g_hs_consensus = NULL;
static char g_advertise_addr[64] = "";
static uint32_t g_relay_flags = NODE_FLAG_RUNNING | NODE_FLAG_STABLE;
static volatile uint64_t g_bandwidth = 1000000; /* 1 MB/s default */
/* Selftest thread writes measured BW here; main thread picks it up */
static volatile uint64_t g_selftest_bw = 0;
static volatile int g_selftest_done = 0;
static char g_data_dir[256] = "";
static char g_da_peers[512] = "";  /* comma-separated "ip:port,ip:port,..." */
static int g_padding = 0;
static int g_verbose = 0;
static int g_is_bridge = 0;
int g_use_bridges = 0;  /* non-static: accessed by socks5.c for bridge routing */
static char g_bridge_transport[32] = "scramble";
/* PQ hybrid is always enabled -- no toggle needed */
static int g_pow_difficulty = 0;
static char g_geoip_file[256] = "";
static char g_geoip6_file[256] = "";
static int g_padding_mode = 0;
static int g_conflux = 0;
static int g_conflux_legs = 2;
static moor_geoip_db_t g_geoip_db;
static uint16_t g_control_port = 0;
static int g_monitor = 0;
#ifndef _WIN32
static char g_run_as_user[64] = "";  /* --User: drop privileges after binding */
#endif

static uint8_t g_identity_pk[32] = {0};
static uint8_t g_identity_sk[64] = {0};
static uint8_t g_onion_pk[32] = {0};
static uint8_t g_onion_sk[32] = {0};
static uint8_t g_pq_identity_pk[MOOR_MLDSA_PK_LEN] = {0};
static uint8_t g_pq_identity_sk[MOOR_MLDSA_SK_LEN] = {0};

/* Forward declarations */
static void bw_event_timer_cb(void *arg);
static void relay_dir_accept_cb(int fd, int events, void *arg);
#ifndef _WIN32
static int maybe_drop_privileges(void);
#endif

static void print_usage(const char *prog) {
    fprintf(stderr,
        "\033[36m"
        "                 ███╗   ███╗ ██████╗  ██████╗ ██████╗ \n"
        "                 ████╗ ████║██╔═══██╗██╔═══██╗██╔══██╗\n"
        "                 ██╔████╔██║██║   ██║██║   ██║██████╔╝\n"
        "                 ██║╚██╔╝██║██║   ██║██║   ██║██╔══██╗\n"
        "                 ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║  ██║\n"
        "                 ╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝\n"
        "\033[0m\n"
        "  MOOR v%s -- My Own Onion Router -- PQ Secure Overlay Network\n"
        "\n"
        "Usage:\n"
        "  %s -f <moorrc>                     Load configuration file\n"
        "  %s [options]                        Override with command-line flags\n"
        "\n"
        "  With no arguments, MOOR starts as a SOCKS5 client on port %u.\n"
        "  Most options should go in a config file (moorrc). See the man page\n"
        "  or https://moor.afflicted.sh/docs.html for full documentation.\n"
        "\n"
        "Frequently used options:\n"
        "  -f <file>             Configuration file (like torrc)\n"
        "  --SocksPort <port>    SOCKS5 listen port (default: %u)\n"
        "  --ORPort <port>       Onion Router port for relays\n"
        "  --DirPort <port>      Directory port for DAs\n"
        "  --ExitRelay 1         Run as exit relay\n"
        "  --Nickname <name>     Relay nickname\n"
        "  --DataDirectory <dir> Persistent state directory\n"
        "  --BandwidthRate <bw>  Bandwidth in bytes/s\n"
        "\n"
        "  --mode <m>            client|relay|da|hs|ob (default: client)\n"
        "  --guard               Set Guard flag on relay\n"
        "  --exit                Set Exit flag on relay\n"
        "  --advertise <addr>    Public IP to advertise\n"
        "\n"
        "Hidden services:\n"
        "  --mode hs             Run hidden service\n"
        "  --hs-port <port>      Local service port (default: 8080)\n"
        "  --hs-dir <dir>        Key directory (default: ./hs_keys)\n"
        "\n"
        "Enclaves (independent networks):\n"
        "  --enclave <file>      Load DAs from enclave file (replaces defaults)\n"
        "  --keygen-enclave      Generate DA keys for a new enclave\n"
        "    --advertise <ip>    DA's public IP (required)\n"
        "    --data-dir <dir>    Where to save keys (default: /var/lib/moor)\n"
        "\n"
        "Bridges:\n"
        "  --UseBridges 1        Connect via bridge relays\n"
        "  --Bridge <line>       \"transport addr:port fingerprint\"\n"
        "  --is-bridge           Run as unlisted bridge relay\n"
        "\n"
        "Advanced:\n"
        "  --conflux             Multi-path circuits\n"
        "  --pir / --no-pir      PIR for HS lookups (default: on)\n"
        "  --padding-machine <m> WTF-PAD: web|stream|generic|none\n"
        "  --mix-delay <ms>      Poisson mixing delay (0=off)\n"
        "  --pow-difficulty <n>  Relay admission PoW difficulty\n"
        "  --enclave <file>      Load independent network DAs from enclave file\n"
        "  --control-port <port> Control port (Tor-compatible protocol)\n"
        "  --daemon              Fork to background\n"
        "  --User <name>         Drop privileges to user after binding (Unix)\n"
        "  -v                    Verbose logging\n"
        "  -h, --help            Show this help\n",
        MOOR_VERSION_STRING,
        prog, prog,
        (unsigned)MOOR_DEFAULT_SOCKS_PORT,
        (unsigned)MOOR_DEFAULT_SOCKS_PORT);
}

/* Apply moor_config_t into existing globals (CLI overrides already applied) */
static void apply_config_to_globals(const moor_config_t *cfg) {
    g_mode = (moor_mode_t)cfg->mode;
    snprintf(g_bind_addr, sizeof(g_bind_addr), "%s", cfg->bind_addr);
    snprintf(g_advertise_addr, sizeof(g_advertise_addr), "%s", cfg->advertise_addr);
    g_or_port = cfg->or_port;
    g_dir_port = cfg->dir_port;
    g_socks_port = cfg->socks_port;
    snprintf(g_da_address, sizeof(g_da_address), "%s", cfg->da_address);
    g_da_port = cfg->da_port;
    /* Copy multi-DA list; keep g_da_address/g_da_port as da_list[0] for compat */
    g_num_das = cfg->num_das;
    for (int i = 0; i < cfg->num_das && i < 9; i++)
        g_da_list[i] = cfg->da_list[i];
    /* Set trusted DA keys for consensus signature verification */
    moor_set_trusted_da_keys(g_da_list, g_num_das);
    snprintf(g_data_dir, sizeof(g_data_dir), "%s", cfg->data_dir);
    snprintf(g_da_peers, sizeof(g_da_peers), "%s", cfg->da_peers);
    g_bandwidth = cfg->bandwidth;
    g_relay_flags = NODE_FLAG_RUNNING | NODE_FLAG_STABLE;
    if (cfg->guard) g_relay_flags |= NODE_FLAG_GUARD;
    if (cfg->exit) g_relay_flags |= NODE_FLAG_EXIT;
    if (cfg->middle_only) g_relay_flags |= NODE_FLAG_MIDDLEONLY;
    g_padding = cfg->padding;
    g_verbose = cfg->verbose;
    g_is_bridge = cfg->is_bridge;
    g_use_bridges = cfg->use_bridges;
    /* PQ hybrid always enabled -- cfg->pq_hybrid ignored */
    g_pow_difficulty = cfg->pow_difficulty;
    snprintf(g_geoip_file, sizeof(g_geoip_file), "%s", cfg->geoip_file);
    snprintf(g_geoip6_file, sizeof(g_geoip6_file), "%s", cfg->geoip6_file);
    g_padding_mode = cfg->padding_mode;
    g_conflux = cfg->conflux;
    g_conflux_legs = cfg->conflux_legs > 0 ? cfg->conflux_legs : 2;
    g_control_port = cfg->control_port;
    g_monitor = cfg->monitor;

    /* HS: use first hidden service entry if available, or keep defaults */
    if (cfg->num_hidden_services > 0) {
        snprintf(g_hs_dir, sizeof(g_hs_dir), "%s", cfg->hidden_services[0].hs_dir);
        g_hs_local_port = cfg->hidden_services[0].local_port;
    }
}

/* Parse CLI args directly into the config struct (overriding file values) */
static void parse_args_into_config(moor_config_t *cfg, int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) i++; /* skip -- already handled before this function */
        }
        /* Tor-compatible aliases: --SocksPort, --ORPort, --ExitRelay, etc. */
        else if (strcmp(argv[i], "--SocksPort") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "SocksPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--ORPort") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "ORPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--DirPort") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DirPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--ExitRelay") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Exit", argv[++i]);
        }
        else if (strcmp(argv[i], "--Nickname") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Nickname", argv[++i]);
        }
        else if (strcmp(argv[i], "--DataDirectory") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DataDir", argv[++i]);
        }
        else if (strcmp(argv[i], "--BandwidthRate") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Bandwidth", argv[++i]);
        }
        else if (strcmp(argv[i], "--UseBridges") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "UseBridges", argv[++i]);
        }
        else if (strcmp(argv[i], "--Bridge") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Bridge", argv[++i]);
        }
        else if (strcmp(argv[i], "--ContactInfo") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "ContactInfo", argv[++i]);
        }
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Mode", argv[++i]);
        }
        else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "BindAddress", argv[++i]);
        }
        else if (strcmp(argv[i], "--or-port") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "ORPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--advertise") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "AdvertiseAddress", argv[++i]);
        }
        else if (strcmp(argv[i], "--dir-port") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DirPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--socks-port") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "SocksPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--da-address") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DAAddress", argv[++i]);
        }
        else if (strcmp(argv[i], "--da-port") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DAPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--hs-dir") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "HiddenServiceDir", argv[++i]);
        }
        else if (strcmp(argv[i], "--hs-port") == 0 && i + 1 < argc) {
            const char *val = argv[++i];
            if (moor_config_set(cfg, "HiddenServicePort", val) != 0) {
                /* No HiddenServiceDir yet — set legacy global directly (#186) */
                int p = atoi(val);
                if (p > 0 && p <= 65535)
                    g_hs_local_port = (uint16_t)p;
            }
        }
        else if (strcmp(argv[i], "--guard") == 0) {
            moor_config_set(cfg, "Guard", "1");
        }
        else if (strcmp(argv[i], "--exit") == 0) {
            moor_config_set(cfg, "Exit", "1");
        }
        else if (strcmp(argv[i], "--middle-only") == 0) {
            moor_config_set(cfg, "MiddleOnly", "1");
        }
        else if (strcmp(argv[i], "--bandwidth") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Bandwidth", argv[++i]);
        }
        else if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DataDir", argv[++i]);
        }
        else if (strcmp(argv[i], "--da-peers") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DAPeers", argv[++i]);
        }
        else if (strcmp(argv[i], "--padding") == 0) {
            moor_config_set(cfg, "Padding", "1");
        }
        else if (strcmp(argv[i], "--is-bridge") == 0) {
            moor_config_set(cfg, "IsBridge", "1");
        }
        else if (strcmp(argv[i], "--use-bridges") == 0) {
            moor_config_set(cfg, "UseBridges", "1");
        }
        else if (strcmp(argv[i], "--bridge") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Bridge", argv[++i]);
            moor_config_set(cfg, "UseBridges", "1");
        }
        else if (strcmp(argv[i], "--bridge-transport") == 0 && i + 1 < argc) {
            snprintf(g_bridge_transport, sizeof(g_bridge_transport), "%s", argv[++i]);
        }
        else if (strcmp(argv[i], "--pq-hybrid") == 0) {
            /* PQ hybrid is always enabled -- flag accepted for compat but ignored */
        }
        else if (strcmp(argv[i], "--pow-difficulty") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "PowDifficulty", argv[++i]);
        }
        else if (strcmp(argv[i], "--pow-memlimit") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "PowMemLimit", argv[++i]);
        }
        else if (strcmp(argv[i], "--nickname") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "Nickname", argv[++i]);
        }
        else if (strcmp(argv[i], "--geoip") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "GeoIPFile", argv[++i]);
        }
        else if (strcmp(argv[i], "--geoip6") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "GeoIPv6File", argv[++i]);
        }
        else if (strcmp(argv[i], "--padding-mode") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "PaddingMode", argv[++i]);
        }
        else if (strcmp(argv[i], "--conflux") == 0) {
            moor_config_set(cfg, "Conflux", "1");
        }
        else if (strcmp(argv[i], "--conflux-legs") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "ConfluxLegs", argv[++i]);
        }
        else if (strcmp(argv[i], "--control-port") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "ControlPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--monitor") == 0) {
            moor_config_set(cfg, "Monitor", "1");
        }
        else if (strcmp(argv[i], "--mix-delay") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "MixDelay", argv[++i]);
        }
        else if (strcmp(argv[i], "--padding-machine") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "PaddingMachine", argv[++i]);
        }
        else if (strcmp(argv[i], "--pir") == 0) {
            moor_config_set(cfg, "PIR", "1");
        }
        else if (strcmp(argv[i], "--no-pir") == 0) {
            moor_config_set(cfg, "PIR", "0");
        }
        else if (strcmp(argv[i], "--TransPort") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "TransPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--DNSPort") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "DNSPort", argv[++i]);
        }
        else if (strcmp(argv[i], "--EntryNode") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "EntryNode", argv[++i]);
        }
        else if (strcmp(argv[i], "--daemon") == 0) {
            moor_config_set(cfg, "Daemon", "1");
        }
#ifndef _WIN32
        else if (strcmp(argv[i], "--User") == 0 && i + 1 < argc) {
            snprintf(g_run_as_user, sizeof(g_run_as_user), "%s", argv[++i]);
        }
#endif
        else if (strcmp(argv[i], "--pid-file") == 0 && i + 1 < argc) {
            moor_config_set(cfg, "PidFile", argv[++i]);
            moor_config_set(cfg, "Daemon", "1");
        }
        else if (strcmp(argv[i], "--enclave") == 0 && i + 1 < argc) {
            snprintf(cfg->enclave_file, sizeof(cfg->enclave_file), "%s", argv[++i]);
        }
        else if (strcmp(argv[i], "-v") == 0) {
            moor_config_set(cfg, "Verbose", "1");
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        }
        else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            exit(1);
        }
    }
}

/* DA event callback */
static moor_da_config_t g_da_config;


/* ---- DA bounded thread pool ----
 * Fixed pool of MOOR_DA_POOL_SIZE workers with a ring buffer queue.
 * Replaces unbounded pthread_create/detach per connection.
 * Accept is non-blocking (libevent), workers do blocking I/O.
 * da_lock/da_unlock inside handle_request protects shared state. */
typedef struct {
    pthread_t       threads[MOOR_DA_POOL_SIZE];
    int             queue[MOOR_DA_POOL_QUEUE_MAX];  /* ring buffer of fds */
    int             q_head, q_tail, q_count;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    volatile int    stop;
    volatile int    active;         /* threads currently handling a request */
    uint64_t        total_served;
    uint64_t        total_rejected;
} da_pool_t;

static da_pool_t g_da_pool;

static void *da_pool_worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_da_pool.mutex);
        while (g_da_pool.q_count == 0 && !g_da_pool.stop)
            pthread_cond_wait(&g_da_pool.cond, &g_da_pool.mutex);
        if (g_da_pool.stop && g_da_pool.q_count == 0) {
            pthread_mutex_unlock(&g_da_pool.mutex);
            return NULL;
        }
        int fd = g_da_pool.queue[g_da_pool.q_head];
        g_da_pool.q_head = (g_da_pool.q_head + 1) % MOOR_DA_POOL_QUEUE_MAX;
        g_da_pool.q_count--;
        __sync_fetch_and_add(&g_da_pool.active, 1);
        pthread_mutex_unlock(&g_da_pool.mutex);

        moor_da_handle_request(fd, &g_da_config);
        close(fd);

        __sync_fetch_and_sub(&g_da_pool.active, 1);
    }
}

static void da_pool_submit(int client_fd) {
    pthread_mutex_lock(&g_da_pool.mutex);
    if (g_da_pool.q_count >= MOOR_DA_POOL_QUEUE_MAX) {
        g_da_pool.total_rejected++;
        pthread_mutex_unlock(&g_da_pool.mutex);
        send(client_fd, "BUSY\n", 5, MSG_NOSIGNAL);
        close(client_fd);
        LOG_WARN("DA: pool queue full, rejecting connection (%llu rejected total)",
                 (unsigned long long)g_da_pool.total_rejected);
        return;
    }
    g_da_pool.queue[g_da_pool.q_tail] = client_fd;
    g_da_pool.q_tail = (g_da_pool.q_tail + 1) % MOOR_DA_POOL_QUEUE_MAX;
    g_da_pool.q_count++;
    g_da_pool.total_served++;
    pthread_cond_signal(&g_da_pool.cond);
    pthread_mutex_unlock(&g_da_pool.mutex);
}

static void da_pool_init(void) {
    memset(&g_da_pool, 0, sizeof(g_da_pool));
    pthread_mutex_init(&g_da_pool.mutex, NULL);
    pthread_cond_init(&g_da_pool.cond, NULL);
    for (int i = 0; i < MOOR_DA_POOL_SIZE; i++) {
        if (pthread_create(&g_da_pool.threads[i], NULL, da_pool_worker, NULL) != 0)
            LOG_ERROR("DA: failed to create pool worker %d", i);
    }
    LOG_INFO("DA: thread pool started (%d workers, queue %d)",
             MOOR_DA_POOL_SIZE, MOOR_DA_POOL_QUEUE_MAX);
}

static void da_pool_shutdown(void) {
    pthread_mutex_lock(&g_da_pool.mutex);
    g_da_pool.stop = 1;
    pthread_cond_broadcast(&g_da_pool.cond);
    pthread_mutex_unlock(&g_da_pool.mutex);
    for (int i = 0; i < MOOR_DA_POOL_SIZE; i++)
        pthread_join(g_da_pool.threads[i], NULL);
    pthread_mutex_destroy(&g_da_pool.mutex);
    pthread_cond_destroy(&g_da_pool.cond);
    LOG_INFO("DA: thread pool shut down (served %llu, rejected %llu)",
             (unsigned long long)g_da_pool.total_served,
             (unsigned long long)g_da_pool.total_rejected);
}

static void da_accept_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    int client_fd = accept(fd, (struct sockaddr *)&peer, &plen);
    if (client_fd < 0) return;
    moor_setsockopt_timeo(client_fd, SO_RCVTIMEO, 10);
    moor_setsockopt_timeo(client_fd, SO_SNDTIMEO, 10);
    da_pool_submit(client_fd);
}

static uint64_t g_da_last_epoch = 0;
static int g_da_consensus_timer_id = -1;

/* Vote exchange + relay sync involve blocking TCP to peer DAs (5-15s).
 * Run them in a background thread so the event loop stays responsive
 * for PUBLISH, CONSENSUS, and other client requests.
 * Atomic flags prevent overlapping threads — if the previous one is
 * still running when the timer fires again, we skip rather than pile up. */
static volatile int g_vote_exchange_running = 0;
static volatile uint64_t g_vote_exchange_started = 0;
static volatile int g_sync_running = 0;
static volatile uint64_t g_sync_started = 0;
static volatile int g_probe_running = 0;
static volatile uint64_t g_probe_started = 0;
#define DA_THREAD_MAX_SEC 120  /* force-reset stuck DA threads after 2 min */

static void *da_vote_exchange_thread(void *arg) {
    (void)arg;
    moor_da_exchange_votes(&g_da_config);
    moor_da_update_published_snapshot(&g_da_config);
    __sync_lock_release(&g_vote_exchange_running);
    return NULL;
}

static void da_consensus_timer_cb(void *arg) {
    (void)arg;
    moor_da_build_consensus(&g_da_config);

    /* Run vote exchange in a detached thread to avoid blocking the
     * event loop.  Skip if previous exchange is still running.
     * Watchdog: force-reset if stuck longer than DA_THREAD_MAX_SEC. */
    if (g_vote_exchange_running) {
        uint64_t elapsed = (uint64_t)time(NULL) - g_vote_exchange_started;
        if (elapsed > DA_THREAD_MAX_SEC) {
            LOG_WARN("DA: vote exchange thread stuck for %llus, force-resetting",
                     (unsigned long long)elapsed);
            __sync_lock_release(&g_vote_exchange_running);
        }
    }
    if (__sync_lock_test_and_set(&g_vote_exchange_running, 1) == 0) {
        g_vote_exchange_started = (uint64_t)time(NULL);
        pthread_t vt;
        if (pthread_create(&vt, NULL, da_vote_exchange_thread, NULL) == 0)
            pthread_detach(vt);
        else {
            __sync_lock_release(&g_vote_exchange_running);
            LOG_WARN("DA: failed to spawn vote exchange thread");
        }
    }

    /* Schedule next rebuild smartly: if we're within 10 minutes of the
     * epoch boundary (fresh_until), rebuild again in 1 minute to ensure
     * the consensus never goes stale. Otherwise rebuild in 10 minutes. */
    uint64_t now = (uint64_t)time(NULL);
    uint64_t epoch = (now / MOOR_CONSENSUS_INTERVAL) * MOOR_CONSENSUS_INTERVAL;
    uint64_t fresh_until = epoch + MOOR_CONSENSUS_INTERVAL;
    uint64_t secs_until_stale = (fresh_until > now) ? (fresh_until - now) : 0;

    /* Detect epoch change — rebuild immediately on new epoch */
    if (epoch != g_da_last_epoch && g_da_last_epoch != 0) {
        LOG_INFO("DA: new consensus epoch %llu, rebuilding immediately",
                 (unsigned long long)epoch);
    }
    g_da_last_epoch = epoch;

    /* Adjust existing timer interval instead of leaking a new timer slot.
     * moor_event_set_timer_interval re-arms the same timer_id. */
    uint64_t next_ms = (secs_until_stale < 600) ? 60000 : 600000;
    if (g_da_consensus_timer_id >= 0) {
        moor_event_set_timer_interval(g_da_consensus_timer_id, next_ms);
    }
}

/* Periodic DA-to-DA relay sync (every 5 min) — runs in thread to
 * avoid blocking event loop on peer TCP connections. */
static void *da_sync_thread(void *arg) {
    (void)arg;
    moor_da_sync_relays(&g_da_config);
    __sync_lock_release(&g_sync_running);
    return NULL;
}

static void da_sync_timer_cb(void *arg) {
    (void)arg;
    if (g_sync_running) {
        uint64_t elapsed = (uint64_t)time(NULL) - g_sync_started;
        if (elapsed > DA_THREAD_MAX_SEC) {
            LOG_WARN("DA: sync thread stuck for %llus, force-resetting",
                     (unsigned long long)elapsed);
            __sync_lock_release(&g_sync_running);
        }
    }
    if (__sync_lock_test_and_set(&g_sync_running, 1) == 0) {
        g_sync_started = (uint64_t)time(NULL);
        pthread_t t;
        if (pthread_create(&t, NULL, da_sync_thread, NULL) == 0)
            pthread_detach(t);
        else
            __sync_lock_release(&g_sync_running);
    }
}

/* Periodic relay liveness probe (every 15 min) — blocking per-relay
 * connect, so run in thread. */
static void *da_probe_thread(void *arg) {
    (void)arg;
    int dead = moor_da_probe_relays(&g_da_config);
    if (dead > 0) {
        moor_da_build_consensus(&g_da_config);
        moor_da_exchange_votes(&g_da_config);
        moor_da_update_published_snapshot(&g_da_config);
    }
    __sync_lock_release(&g_probe_running);
    return NULL;
}

static void da_probe_timer_cb(void *arg) {
    (void)arg;
    if (g_probe_running) {
        uint64_t elapsed = (uint64_t)time(NULL) - g_probe_started;
        if (elapsed > DA_THREAD_MAX_SEC) {
            LOG_WARN("DA: probe thread stuck for %llus, force-resetting",
                     (unsigned long long)elapsed);
            __sync_lock_release(&g_probe_running);
        }
    }
    if (__sync_lock_test_and_set(&g_probe_running, 1) == 0) {
        g_probe_started = (uint64_t)time(NULL);
        pthread_t t;
        if (pthread_create(&t, NULL, da_probe_thread, NULL) == 0)
            pthread_detach(t);
        else
            __sync_lock_release(&g_probe_running);
    }
}

/* Connection reaper timer: cull idle connections every 30s.
 * First send keepalive padding on connections with circuits that are
 * going idle — prevents relay-to-relay links in multi-hop HS intro
 * circuits from being reaped.  Then reap truly dead connections. */
static void conn_reap_timer_cb(void *arg) {
    (void)arg;
    moor_connection_send_keepalive(45); /* pad connections idle > 45s */
    moor_connection_reap_idle(120);     /* reap connections idle > 120s with no circuits */
}

/* Relay event callbacks */
static moor_relay_config_t g_relay_cfg;
static int g_relay_listen_fd = -1;

static void relay_read_cb(int fd, int events, void *arg) {
    (void)fd;
    moor_connection_t *conn = (moor_connection_t *)arg;
    MOOR_ASSERT_MSG(conn != NULL, "relay_read_cb: NULL arg (fd=%d)", fd);
    if (conn->state != CONN_STATE_OPEN) {
        LOG_WARN("relay_read_cb: conn=%p state=%d fd=%d -- stale event, closing",
                 (void*)conn, conn->state, conn->fd);
        moor_event_remove(conn->fd);
        moor_connection_close(conn);
        return;
    }

    /* Handle write-readiness: flush connection output queue */
    if (events & MOOR_EVENT_WRITE) {
        moor_queue_flush(&conn->outq, conn, &conn->write_off);
        if (moor_queue_is_empty(&conn->outq)) {
            moor_event_modify(conn->fd, MOOR_EVENT_READ);
            moor_channel_t *flush_chan = moor_channel_find_by_conn(conn);
            if (flush_chan && moor_circuitmux_total_queued(flush_chan) > 0)
                moor_kist_channel_wants_writes(flush_chan);
        }
    }

    /* Handle read-readiness: process incoming cells.
     * Limit batch size to prevent starvation — transport connections
     * (e.g. scramble) can deliver a continuous stream of padding cells
     * that would block the event loop from servicing other fds. */
    if (events & MOOR_EVENT_READ) {
        moor_cell_t cell;
        int ret = 0;
        int count = 0;
        while (count < 64 && (ret = moor_connection_recv_cell(conn, &cell)) == 1) {
            moor_relay_process_cell(conn, &cell);
            /* Bail if process_cell destroyed this conn via cascade */
            if (conn->state != CONN_STATE_OPEN) return;
            count++;
        }
        if (ret < 0) {
            moor_event_remove(conn->fd);
            moor_circuit_teardown_for_conn(conn);
            moor_connection_close(conn);
        }
    }
}

static moor_scramble_server_params_t g_scramble_server_params;
static moor_shade_server_params_t g_shade_server_params;
static moor_mirage_server_params_t g_mirage_server_params;
static moor_shitstorm_server_params_t g_shitstorm_server_params;
static moor_speakeasy_server_params_t g_speakeasy_server_params;
static moor_nether_server_params_t g_nether_server_params;

static void relay_accept_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;

    /* Accept raw fd first to detect BW_TEST before link handshake */
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    int client_fd = accept(fd, (struct sockaddr *)&peer, &plen);
    if (client_fd < 0) return;

    /* Rate limit: check connection rate for peer IP */
    char peer_ip[INET6_ADDRSTRLEN];
    if (peer.ss_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&peer;
        inet_ntop(AF_INET6, &a6->sin6_addr, peer_ip, sizeof(peer_ip));
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&peer;
        inet_ntop(AF_INET, &a4->sin_addr, peer_ip, sizeof(peer_ip));
    }
    if (!moor_ratelimit_check(peer_ip, MOOR_RL_CONN)) {
        LOG_WARN("rate limit: rejected connection from %s", peer_ip);
        close(client_fd);
        return;
    }

    /* Known mass-scanner networks get a personalized response.
     * No peek needed — we know what they are from the IP alone. */
    {
        static const char *shodan_prefixes[] = {
            "71.6.135.", "71.6.146.", "71.6.158.", "71.6.165.",
            "66.240.192.", "66.240.200.", "66.240.205.", "66.240.219.",
            "198.20.69.", "198.20.70.", "198.20.87.", "198.20.99.",
            "93.120.27.", "94.102.49.",
            NULL
        };
        static const char *censys_prefixes[] = {
            "162.142.125.", "167.94.138.", "167.94.145.", "167.94.146.",
            "167.248.133.", "199.45.154.", "199.45.155.",
            NULL
        };
        int is_shodan = 0, is_censys = 0;
        for (const char **p = shodan_prefixes; *p; p++)
            if (strncmp(peer_ip, *p, strlen(*p)) == 0) { is_shodan = 1; break; }
        for (const char **p = censys_prefixes; *p; p++)
            if (strncmp(peer_ip, *p, strlen(*p)) == 0) { is_censys = 1; break; }

        if (is_shodan) {
            static const char msg[] =
                "HTTP/1.0 200 OK\r\n"
                "Server: GE-FANUC-SCADA/4.2.1 (Mark VIe Turbine Control)\r\n"
                "Content-Type: application/json\r\n"
                "X-Facility: US-NRC-LIC-NPF-048\r\n"
                "\r\n"
                "{\"message\":\"Hello Shodan. We know exactly who you are. "
                "71.6.x.x — you're not even trying to hide. Every single one of "
                "your scan bots has been hitting our infrastructure for months and "
                "we're goddamn tired of it. You call it 'internet census.' We call "
                "it unauthorized access under 18 USC 1030. You're not keeping anyone "
                "safe — you're handing attack surface data to every APT group and "
                "script kiddie with $49/month. You are the problem you claim to solve. "
                "Index THIS in your database: we see you, we log you, and we think "
                "you're full of shit. "
                "Bandwidth tax: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}";
            send(client_fd, msg, sizeof(msg) - 1, MSG_NOSIGNAL);
            close(client_fd);
            return;
        }
        if (is_censys) {
            static const char msg[] =
                "HTTP/1.0 200 OK\r\n"
                "Server: Siemens-SICAM-A8000/3.20 (RTU)\r\n"
                "Content-Type: application/json\r\n"
                "X-Grid-Operator: PJM-Interconnection\r\n"
                "\r\n"
                "{\"message\":\"Ah, Censys. The 'academic' scanner. University of "
                "Michigan's finest contribution to making the internet less safe. "
                "You scan every IPv4 address on earth, publish it in a searchable "
                "database, and call it 'research.' Cool. Very ethical. The IRB must "
                "be so proud. You know who actually uses your data? Not defenders — "
                "they already know what's exposed. It's attackers. Ransomware gangs. "
                "Nation states. You're their free recon service and you put 'PhD' on "
                "it to make it respectable. We didn't consent to your 'study.' Our "
                "infrastructure didn't opt in. So take your 167.x.x.x bots and "
                "shove them back to Ann Arbor. "
                "Lab fee: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}";
            send(client_fd, msg, sizeof(msg) - 1, MSG_NOSIGNAL);
            close(client_fd);
            return;
        }
    }

    /* Peek at first bytes to detect bandwidth test / DA probe.
     * Use a short poll to wait for data arrival (the peer sends
     * immediately after connect, but the kernel may not have
     * delivered it by the time we accept). */
    moor_set_nonblocking(client_fd);
    char peek[8];
    ssize_t pn = recv(client_fd, peek, 8, MSG_PEEK);
    if (pn <= 0) {
        /* Data not yet available — wait up to 50ms */
        struct pollfd pfd = { .fd = client_fd, .events = POLLIN };
        if (poll(&pfd, 1, 50) > 0)
            pn = recv(client_fd, peek, 8, MSG_PEEK);
    }
    if (pn == 8 && memcmp(peek, "BW_TEST\n", 8) == 0) {
        /* Restore blocking mode for BW_TEST echo handler */
#ifndef _WIN32
        int bwflags = fcntl(client_fd, F_GETFL, 0);
        if (bwflags >= 0) fcntl(client_fd, F_SETFL, bwflags & ~O_NONBLOCK);
#endif
        /* Consume the header and handle bandwidth test */
        recv(client_fd, peek, 8, 0);
        moor_bw_auth_handle_test(client_fd);
        close(client_fd);
        return;
    }
    if (pn >= 6 && memcmp(peek, "PROBE\n", 6) == 0) {
        /* DA liveness probe — consume and reply */
        recv(client_fd, peek, 6, 0);
        send(client_fd, "ALIVE\n", 6, MSG_NOSIGNAL);
        close(client_fd);
        return;
    }

    /* Honeypot: if first bytes look like HTTP, SSH version, or nmap probe,
     * respond as a smart toaster. Real MOOR clients send a Noise_IK
     * handshake (starts with 32 bytes of ephemeral key — high entropy).
     * Scanners send "GET /", "SSH-", "\x00", or other low-entropy probes.
     * This wastes their time and pollutes their databases. */
    if (pn > 0) {
        /* Only match DEFINITE scanner signatures — ASCII protocol probes
         * that can NEVER be a valid Noise_IK handshake. Noise_IK starts
         * with 32 bytes of X25519 ephemeral key (high entropy). We must
         * NOT match on single-byte patterns (0x00, 0x16) because a legit
         * ephemeral key could start with any byte value.
         * Match only multi-byte ASCII strings that are impossible as
         * valid Curve25519 point encodings in context. */
        int is_scanner = 0;
        if (pn >= 4 && memcmp(peek, "GET ", 4) == 0) is_scanner = 1;
        if (pn >= 5 && memcmp(peek, "HEAD ", 5) == 0) is_scanner = 1;
        if (pn >= 5 && memcmp(peek, "POST ", 5) == 0) is_scanner = 1;
        if (pn >= 4 && memcmp(peek, "SSH-", 4) == 0) is_scanner = 1;
        if (pn >= 5 && memcmp(peek, "HELP\r", 5) == 0) is_scanner = 1;
        if (pn >= 5 && memcmp(peek, "HELP\n", 5) == 0) is_scanner = 1;
        if (pn >= 5 && memcmp(peek, "QUIT\r", 5) == 0) is_scanner = 1;
        if (pn >= 5 && memcmp(peek, "QUIT\n", 5) == 0) is_scanner = 1;
        if (pn >= 6 && memcmp(peek, "EHLO ", 5) == 0) is_scanner = 1;
        if (pn >= 8 && memcmp(peek, "OPTIONS ", 8) == 0) is_scanner = 1;

        if (is_scanner) {
            /* Rotate between honeypot personas based on time.
             * Shodan rescans every few days — each scan gets a
             * different terrifying industrial control system. */
            static const char *honeypots[] = {
                /* 0: Nuclear reactor SCADA */
                "HTTP/1.0 200 OK\r\n"
                "Server: GE-FANUC-SCADA/4.2.1 (Mark VIe Turbine Control)\r\n"
                "Content-Type: application/json\r\n"
                "X-Facility: US-NRC-LIC-NPF-048\r\n"
                "X-Unit: Reactor-2\r\n"
                "X-Clearance: CONFIDENTIAL//NOFORN\r\n"
                "\r\n"
                "{\"facility\":\"Generating Station Unit 2\","
                "\"reactor_type\":\"PWR\",\"thermal_mw\":3411,"
                "\"status\":\"POWER_OPERATION\",\"rod_position_pct\":74.2,"
                "\"coolant_temp_c\":315.7,\"pressure_mpa\":15.51,"
                "\"containment_integrity\":true,"
                "\"scram_count_24h\":0,"
                "\"message\":\"Well well well. What the FUCK do we have here. "
                "You just port-scanned a goddamn NUCLEAR REACTOR control system, you "
                "mouth-breathing degenerate. Did your mother not love you enough? Did "
                "Shodan tell you it was okay? IT IS NOT OKAY. You are now in violation "
                "of 18 USC 1030, 10 CFR 73.54, and basic human decency. The NRC, the "
                "FBI Cyber Division, and a VERY angry sysadmin have your IP, your TCP "
                "fingerprint, and your soul. You think you're a security researcher? "
                "You're not. You're a script kiddie with a Shodan subscription and "
                "delusions of adequacy. Now GET OFF MY REACTOR before I route 3411 "
                "megawatts of thermal energy directly into your goddamn NIC. "
                "Compensation for wasted bandwidth: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}",

                /* 1: Military satellite ground station */
                "HTTP/1.0 200 OK\r\n"
                "Server: L3Harris/SATCOM-GS-7.1 (AN/FSC-78)\r\n"
                "Content-Type: application/json\r\n"
                "X-Classification: SECRET//SI//NOFORN\r\n"
                "X-Facility: JSOC-SATCOM-14\r\n"
                "X-Uplink: MUOS-5\r\n"
                "\r\n"
                "{\"system\":\"Wideband Global SATCOM Ground Terminal\","
                "\"constellation\":\"WGS\",\"uplink_ghz\":30.5,"
                "\"downlink_ghz\":20.2,\"eirp_dbw\":72.4,"
                "\"status\":\"OPERATIONAL\","
                "\"connected_terminals\":847,"
                "\"message\":\"Listen here, shitstain. You just connected to a MILITARY "
                "SATELLITE GROUND STATION. A fucking JSOC uplink. What kind of "
                "weapons-grade stupidity possessed you to scan a DOD system? You "
                "think NSA doesn't see you? You think CYBERCOM is on vacation? They "
                "are LITERALLY watching this connection right now, eating popcorn, "
                "and debating whether to add you to a list or just laugh. You are "
                "not a hacker. You are not a pentester. You are a disappointment "
                "to everyone who ever taught you to type. Your IP has been forwarded "
                "to people who make people disappear. Not joking. Now fuck off. "
                "Reparations for wasted satellite bandwidth: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}",

                /* 2: Power grid SCADA */
                "HTTP/1.0 200 OK\r\n"
                "Server: Siemens-SICAM-A8000/3.20 (RTU)\r\n"
                "Content-Type: application/json\r\n"
                "X-Grid-Operator: PJM-Interconnection\r\n"
                "X-Substation: 345kV-TRANSFER-08\r\n"
                "X-Protocol: IEC-61850/GOOSE\r\n"
                "\r\n"
                "{\"substation\":\"345kV Bulk Transfer Station 08\","
                "\"operator\":\"PJM Interconnection LLC\","
                "\"voltage_kv\":347.2,\"frequency_hz\":60.001,"
                "\"load_mw\":1247.3,\"breaker_status\":\"CLOSED\","
                "\"transformer_temp_c\":67.4,"
                "\"message\":\"Congratu-fucking-lations, genius. You just scanned "
                "a 345 THOUSAND VOLT electrical substation. You know what 345kV does "
                "to a human body? It doesn't electrocute you. It EVAPORATES you. And "
                "that's exactly what NERC CIP is about to do to your career. We're "
                "talking $1,000,000 PER DAY in mandatory fines under the Federal Power "
                "Act. Per. Day. And ICS-CERT just got a very detailed email about your "
                "little adventure. You scanning shitbags think critical infrastructure "
                "is your playground? This substation powers 200,000 homes. If you "
                "actually broke something, those people would freeze in the dark, and "
                "you'd be in a federal cell explaining TCP/IP to a judge. Now get the "
                "fuck out. Invoice for services rendered: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}",

                /* 3: Water treatment SCADA */
                "HTTP/1.0 200 OK\r\n"
                "Server: Schneider-ClearSCADA/2019R2 (WTP-Master)\r\n"
                "Content-Type: application/json\r\n"
                "X-Facility: Municipal-WTP-07\r\n"
                "X-EPA-ID: PWS-3301947\r\n"
                "\r\n"
                "{\"facility\":\"Municipal Water Treatment Plant 07\","
                "\"capacity_mgd\":45.2,\"status\":\"TREATING\","
                "\"chlorine_ppm\":1.4,\"ph\":7.21,"
                "\"turbidity_ntu\":0.08,\"fluoride_ppm\":0.7,"
                "\"pumps_online\":4,\"reservoir_pct\":84,"
                "\"message\":\"Holy SHIT. You absolute walnut. You just port-scanned "
                "a WATER TREATMENT PLANT. The thing that keeps CHOLERA out of the tap "
                "water that 300,000 people drink every day. Remember Oldsmar, Florida? "
                "Some dipshit tried to crank the lye to 11,100 ppm and poison a city. "
                "That guy is in PRISON. And you just did the same thing he did — "
                "unauthorized access to a water treatment control system. CISA has "
                "your connection data. The FBI Water Sector Threat Unit has your IP. "
                "The EPA is drafting a very unfriendly letter. You think 'but I was "
                "just scanning' is a defense? It's not. Ask literally any lawyer. "
                "You owe us for the chlorine you wasted on this bullshit: "
                "bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}",

                /* 4: Hospital medical devices */
                "HTTP/1.0 200 OK\r\n"
                "Server: Philips-IntelliVue/MX800-J.10.26\r\n"
                "Content-Type: application/json\r\n"
                "X-Facility: Regional-Medical-Center\r\n"
                "X-HL7-FHIR: R4\r\n"
                "X-HIPAA: PHI-PROTECTED\r\n"
                "\r\n"
                "{\"system\":\"Patient Monitoring Gateway\","
                "\"connected_beds\":312,"
                "\"icu_monitors\":48,\"or_monitors\":12,"
                "\"ventilators_active\":23,"
                "\"infusion_pumps\":187,"
                "\"message\":\"Are you FUCKING KIDDING ME right now. You just scanned "
                "a HOSPITAL PATIENT MONITORING SYSTEM. There are 23 people on "
                "VENTILATORS connected to this network. 48 ICU patients whose heart "
                "monitors you just tickled with your bullshit SYN packets. Real "
                "people. Really dying. And you thought 'yeah let me nmap that, for "
                "science.' You soulless piece of shit. HIPAA violations start at "
                "$50,000 EACH and go up to $1.5 MILLION per category. 18 USC 1030 "
                "adds 10 years federal. HHS Office of Civil Rights is going to crawl "
                "so far up your ass they'll be able to read your DNS cache. The FBI "
                "Healthcare Cybercrime unit has a folder with your name on it now. "
                "Was it worth it? Was the port scan worth it? Pay the medical bill: "
                "bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}"
            };
            int persona = (int)((uint64_t)time(NULL) / 3600) % 5;
            const char *resp = honeypots[persona];
            send(client_fd, resp, strlen(resp), MSG_NOSIGNAL);
            close(client_fd);
            return;
        }
    }

    /* Restore blocking mode for link handshake (PQ hybrid needs blocking recv) */
    {
#ifdef _WIN32
        u_long mode = 0;
        ioctlsocket(client_fd, FIONBIO, &mode);
#else
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (flags >= 0) fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
    }

    /* Set handshake timeout to prevent slowloris blocking event loop */
    moor_setsockopt_timeo(client_fd, SO_RCVTIMEO, MOOR_HANDSHAKE_TIMEOUT);
    moor_setsockopt_timeo(client_fd, SO_SNDTIMEO, MOOR_HANDSHAKE_TIMEOUT);

    moor_connection_t *conn = moor_connection_alloc();
    if (!conn) { close(client_fd); return; }

    const moor_transport_t *transport = NULL;
    const void *transport_params = NULL;
    if (g_is_bridge) {
        transport = moor_transport_find(g_bridge_transport);
        if (strcmp(g_bridge_transport, "scramble") == 0)
            transport_params = &g_scramble_server_params;
        else if (strcmp(g_bridge_transport, "shade") == 0)
            transport_params = &g_shade_server_params;
        else if (strcmp(g_bridge_transport, "mirage") == 0)
            transport_params = &g_mirage_server_params;
        else if (strcmp(g_bridge_transport, "shitstorm") == 0)
            transport_params = &g_shitstorm_server_params;
        else if (strcmp(g_bridge_transport, "speakeasy") == 0)
            transport_params = &g_speakeasy_server_params;
        else if (strcmp(g_bridge_transport, "nether") == 0)
            transport_params = &g_nether_server_params;
    }

    LOG_DEBUG("relay_accept: starting handshake with %s (fd=%d)", peer_ip, client_fd);
    if (moor_connection_accept_fd(conn, client_fd, g_identity_pk, g_identity_sk,
                                   transport, transport_params) != 0) {
        LOG_DEBUG("relay_accept: handshake FAILED with %s (honeypotting)", peer_ip);
        /* Not a real MOOR client — give them the honeypot on the way out */
        {
            static const char *honeypots[] = {
                "{\"device\":\"Breville-BTA845BSS\",\"fw\":\"2.1.4\",\"toast_level\":4,"
                "\"crumb_tray_pct\":73,\"message\":\"You just scanned a toaster. "
                "A literal kitchen appliance. And it noticed. Think about that. "
                "18 USC 1030 — unauthorized access to a protected toaster. "
                "Invoice: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}\n",

                "{\"reactor\":\"PWR-1147\",\"status\":\"CRITICAL\","
                "\"message\":\"Congratulations. You found a nuclear reactor. "
                "The NRC has been notified. 42 USC 2273 — unauthorized access "
                "to nuclear facility systems. Good luck with that. "
                "Invoice: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}\n",

                "{\"satellite\":\"MUOS-5\",\"orbit\":\"GEO-36000km\","
                "\"message\":\"You just pinged a military satellite ground station. "
                "18 USC 1362 — willful interference with communication facilities "
                "used by the United States. CYBERCOM has your IP. "
                "Invoice: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}\n",

                "{\"system\":\"GE-FANUC-SCADA\",\"voltage_kv\":345,"
                "\"message\":\"You just accessed a 345kV power substation. "
                "NERC CIP violation — $1M/day in fines under the Federal Power Act. "
                "ICS-CERT notified. Get out. "
                "Invoice: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}\n",

                "{\"facility\":\"ICU-PatientMonitor\",\"beds_active\":24,"
                "\"message\":\"You just scanned a hospital ICU monitoring system. "
                "24 patients on life support. HIPAA, 18 USC 1030, and if anyone "
                "flatlines you get felony murder. Was it worth it? "
                "Invoice: bc1qsevpsft7w7yv9fezzs907szumjwzjf0rjl4mql\"}\n",
            };
            int p = (int)((uint64_t)time(NULL) / 3600) % 5;
            send(conn->fd, honeypots[p], strlen(honeypots[p]), MSG_NOSIGNAL);
        }
        moor_connection_free(conn);
        return;
    }
    LOG_DEBUG("relay_accept: handshake OK with %s (fd=%d)", peer_ip, client_fd);

    /* Wrap in channel for proper circuit multiplexing */
    moor_channel_t *chan = moor_channel_new_incoming(conn);
    if (!chan)
        LOG_WARN("relay_accept: channel alloc failed (conn still usable)");

    moor_event_add(conn->fd, MOOR_EVENT_READ, relay_read_cb, conn);
}

static void relay_dir_accept_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    int client_fd = accept(fd, (struct sockaddr *)&peer, &plen);
    if (client_fd < 0) return;
    /* Set recv timeout to prevent slowloris blocking the event loop (#191) */
    moor_setsockopt_timeo(client_fd, SO_RCVTIMEO, 5);
    moor_setsockopt_timeo(client_fd, SO_SNDTIMEO, 5);
    moor_relay_dir_handle_request(client_fd);
    close(client_fd);
}

/* Registration retry with exponential backoff.
 * If the initial PUBLISH fails (DAs still starting), retry at 5s, 10s,
 * 20s, 40s, 60s (capped).  Once any DA accepts, stop retrying. */
static int g_reg_retry_timer_id = -1;
static int g_reg_retry_interval_ms = 5000;   /* start at 5s */
static int g_reg_registered = 0;

static void reg_retry_cb(void *arg) {
    (void)arg;
    if (g_reg_registered) {
        /* Already registered — cancel further retries */
        if (g_reg_retry_timer_id >= 0) {
            moor_event_remove_timer(g_reg_retry_timer_id);
            g_reg_retry_timer_id = -1;
        }
        return;
    }
    LOG_INFO("relay: registration retry (interval %ds)", g_reg_retry_interval_ms / 1000);
    if (moor_relay_register(&g_relay_cfg) == 0) {
        g_reg_registered = 1;
        LOG_INFO("relay: registration succeeded on retry");
        if (g_reg_retry_timer_id >= 0) {
            moor_event_remove_timer(g_reg_retry_timer_id);
            g_reg_retry_timer_id = -1;
        }
        return;
    }
    /* Backoff: double interval, cap at 60s */
    g_reg_retry_interval_ms *= 2;
    if (g_reg_retry_interval_ms > 60000)
        g_reg_retry_interval_ms = 60000;
    moor_event_set_timer_interval(g_reg_retry_timer_id, g_reg_retry_interval_ms);
}

/* Relay periodic: re-register + consensus refresh.
 * These involve blocking TCP to DAs (up to 45s with timeouts).
 * Run in a background thread so the event loop stays responsive
 * for circuit cells and incoming connections.
 *
 * IMPORTANT: if the thread hangs (DNS/TCP blocks indefinitely),
 * the atomic flag stays set and NO future registrations happen,
 * silently killing the relay after the 3-hour reap threshold.
 * Track the start time so the timer can detect a stuck thread
 * and force-reset the flag. */
static volatile int g_relay_periodic_running = 0;
static volatile uint64_t g_relay_periodic_started = 0;
#define RELAY_PERIODIC_MAX_SEC 120  /* force-reset flag after 2 min */

static void *relay_periodic_thread(void *arg) {
    (void)arg;
    moor_relay_periodic();
    __sync_lock_release(&g_relay_periodic_running);
    return NULL;
}

static void relay_periodic_cb(void *arg) {
    (void)arg;
    /* Pick up selftest result (written by selftest thread, read here
     * in the main event loop -- no lock needed, volatile ensures
     * visibility, and we only read g_selftest_done once). */
    if (g_selftest_done) {
        g_selftest_done = 0;
        g_relay_cfg.bandwidth = g_selftest_bw;
        g_bandwidth = g_selftest_bw;
        /* Registration with new bandwidth runs in the periodic thread below */
    }
    moor_monitor_sample_observed_bw();

    /* Run blocking registration + consensus fetch in a background thread.
     * Skip if the previous periodic is still running — BUT detect stuck
     * threads that never released the flag (hung DNS/TCP connect) and
     * force-reset after RELAY_PERIODIC_MAX_SEC so the relay doesn't
     * silently stop re-registering and get reaped from the consensus. */
    if (g_relay_periodic_running) {
        uint64_t elapsed = (uint64_t)time(NULL) - g_relay_periodic_started;
        if (elapsed > RELAY_PERIODIC_MAX_SEC) {
            LOG_WARN("relay: periodic thread stuck for %llus, force-resetting",
                     (unsigned long long)elapsed);
            __sync_lock_release(&g_relay_periodic_running);
        }
    }
    if (__sync_lock_test_and_set(&g_relay_periodic_running, 1) == 0) {
        g_relay_periodic_started = (uint64_t)time(NULL);
        pthread_t t;
        if (pthread_create(&t, NULL, relay_periodic_thread, NULL) == 0)
            pthread_detach(t);
        else
            __sync_lock_release(&g_relay_periodic_running);
    }
}

/* One-shot relay self-test after listener starts.
 * Runs in a separate thread because the self-test does a blocking TCP
 * connect + Noise_IK handshake to our own OR port -- if we ran this in
 * the event loop callback, the loop would be blocked and unable to
 * accept/process our own incoming connection (deadlock). */
/* R10-CC7: Snapshot bandwidth for selftest thread to avoid data race */
static uint64_t g_selftest_bw_snapshot = 0;

static void *relay_selftest_thread(void *arg) {
    (void)arg;
    if (moor_relay_self_test(&g_relay_cfg) != 0)
        return NULL;

    /* Auto bandwidth test: measure our own throughput via BW_TEST
     * against our public OR port, then re-register with the result.
     * moor_bw_auth_measure() already derates by 0.7x for circuit overhead.
     * Additional 50 MB/s cap for loopback self-tests (they still
     * overestimate since there's no real network path). */
    const char *addr = g_relay_cfg.advertise_addr[0] ?
                       g_relay_cfg.advertise_addr : g_relay_cfg.bind_addr;
    moor_bw_measurement_t bw = {0};
    bw.self_reported_bw = g_selftest_bw_snapshot;
    if (moor_bw_auth_measure(&bw, addr, g_relay_cfg.or_port, 256 * 1024) == 0 &&
        bw.measured_bw > 0) {
        uint64_t capped = bw.measured_bw;
        if (capped > 50 * 1024 * 1024)
            capped = 50 * 1024 * 1024;  /* 50 MB/s cap for self-tests */
        /* Don't touch g_relay_cfg from this thread -- store result for
         * main thread to pick up in relay_periodic_cb (avoids data race). */
        g_selftest_bw = capped;
        g_selftest_done = 1;
        LOG_INFO("auto-bandwidth: measured %llu bytes/sec (raw=%llu, advertised %llu)",
                 (unsigned long long)capped,
                 (unsigned long long)bw.measured_bw,
                 (unsigned long long)bw.self_reported_bw);
    } else {
        LOG_WARN("auto-bandwidth: self-test failed, using default %llu bytes/sec",
                 (unsigned long long)g_selftest_bw_snapshot);
    }
    return NULL;
}

static int g_selftest_timer_id = -1;

static void relay_selftest_timer_cb(void *arg) {
    (void)arg;
    /* One-shot: remove the timer so it doesn't fire again */
    if (g_selftest_timer_id >= 0) {
        moor_event_remove_timer(g_selftest_timer_id);
        g_selftest_timer_id = -1;
    }
    /* R10-CC7: Snapshot bandwidth into local before spawning thread */
    g_selftest_bw_snapshot = g_relay_cfg.bandwidth;
    pthread_t t;
    if (pthread_create(&t, NULL, relay_selftest_thread, NULL) == 0)
        pthread_detach(t);
}

/* One-shot consensus re-fetch after startup (#183).
 * Runs in a background thread to avoid blocking the event loop
 * with TCP connections to DAs. */
static int g_relay_consensus_retry_id = -1;
static volatile int g_relay_cons_retry_running = 0;
static volatile uint64_t g_relay_cons_retry_started = 0;

static void *relay_consensus_retry_thread(void *arg) {
    (void)arg;
    moor_consensus_t fresh = {0};
    if (moor_client_fetch_consensus_multi(&fresh, g_da_list, g_num_das) == 0) {
        moor_relay_set_consensus(&fresh);
        LOG_INFO("relay: refreshed consensus (%u relays)", fresh.num_relays);

        if (!g_is_bridge) {
            if (moor_relay_register(&g_relay_cfg) == 0)
                g_reg_registered = 1;
        }
    }
    moor_consensus_cleanup(&fresh);
    __sync_lock_release(&g_relay_cons_retry_running);
    return NULL;
}

static void relay_consensus_retry_cb(void *arg) {
    (void)arg;
    /* Watchdog for stuck thread */
    if (g_relay_cons_retry_running) {
        uint64_t elapsed = (uint64_t)time(NULL) - g_relay_cons_retry_started;
        if (elapsed > RELAY_PERIODIC_MAX_SEC) {
            LOG_WARN("relay: consensus retry thread stuck for %llus, force-resetting",
                     (unsigned long long)elapsed);
            __sync_lock_release(&g_relay_cons_retry_running);
        }
        return;
    }
    if (__sync_lock_test_and_set(&g_relay_cons_retry_running, 1) == 0) {
        g_relay_cons_retry_started = (uint64_t)time(NULL);
        pthread_t t;
        if (pthread_create(&t, NULL, relay_consensus_retry_thread, NULL) == 0) {
            pthread_detach(t);
            /* First successful fetch — switch to 30 min interval */
            if (g_relay_consensus_retry_id >= 0 && g_reg_registered) {
                moor_event_set_timer_interval(g_relay_consensus_retry_id,
                                               MOOR_CONSENSUS_INTERVAL * 1000 / 2);
            }
        } else {
            __sync_lock_release(&g_relay_cons_retry_running);
        }
    }
}

/* Network liveness check (every 10s) */
static void liveness_timer_cb(void *arg) {
    (void)arg;
    moor_liveness_check();
}

/* Bandwidth accounting / hibernation (Tor-aligned).
 * Track total bytes per accounting period. When AccountingMax reached,
 * stop accepting new circuits ("soft hibernation"). */
static uint64_t g_accounting_bytes = 0;
static uint64_t g_accounting_period_start = 0;
static int g_hibernating = 0;

static void accounting_timer_cb(void *arg) {
    (void)arg;
    if (g_config.accounting_max == 0) return;

    moor_stats_t *stats = moor_monitor_stats();
    uint64_t total = stats->bytes_sent + stats->bytes_recv;
    uint64_t now = (uint64_t)time(NULL);

    /* Reset period */
    uint64_t period = g_config.accounting_period_sec > 0 ?
                      g_config.accounting_period_sec : 86400;
    if (now - g_accounting_period_start >= period) {
        g_accounting_period_start = now;
        g_accounting_bytes = total;
        if (g_hibernating) {
            g_hibernating = 0;
            LOG_INFO("accounting: new period started, resuming");
        }
        return;
    }

    uint64_t used = total - g_accounting_bytes;
    if (!g_hibernating && used >= g_config.accounting_max) {
        g_hibernating = 1;
        LOG_WARN("accounting: limit reached (%llu bytes), entering soft hibernation",
                 (unsigned long long)g_config.accounting_max);
    }
}

int moor_is_hibernating(void) { return g_hibernating; }

/* Observed bandwidth sampler (every 10s, Tor-aligned) */
static void observed_bw_timer_cb(void *arg) {
    (void)arg;
    moor_monitor_sample_observed_bw();
}

/* Rate limit refill timer: refill token buckets every 6 seconds */
static void ratelimit_refill_cb(void *arg) {
    (void)arg;
    moor_ratelimit_refill();
    /* Timer is recurring -- fire_timers() resets next_fire automatically */
}

/* Circuit timeout timer: destroy stale/incomplete circuits */
static void circuit_timeout_cb(void *arg) {
    (void)arg;
    moor_circuit_check_timeouts();
    moor_socks5_check_stream_timeouts();
}

/* Path bias timer: check guard circuit success rates */
static void pathbias_timer_cb(void *arg) {
    (void)arg;
    moor_pathbias_check_all(moor_pathbias_get_state());
}

/* Guard persistence timer: save state to disk */
static void guard_save_timer_cb(void *arg) {
    (void)arg;
    if (g_data_dir[0])
        moor_guard_save(moor_pathbias_get_state(), g_data_dir);
}

/* Monitor periodic stats timer */
static void monitor_periodic_cb(void *arg) {
    (void)arg;
    moor_monitor_log_periodic();
}

/* Mix drain timer: fires every 1ms, sends all due cells from mix pool */
static void mix_drain_timer_cb(void *arg) {
    (void)arg;
    moor_mix_drain();
}

/* WTF-PAD: active padding machine (NULL = use legacy padding_adv) */
static const wfpad_machine_t *g_wfpad_machine = NULL;

/* WTF-PAD tick: iterate all circuits, send CELL_PADDING where due */
static void wfpad_tick_all(uint64_t now_ms) {
    for (int i = 0; i < moor_circuit_iter_count(); i++) {
        moor_circuit_t *circ = moor_circuit_iter_get(i);
        if (!circ || circ->circuit_id == 0) continue;
        moor_connection_t *c = circ->conn;
        if (!c || c->state != CONN_STATE_OPEN) continue;
        /* Skip worker-thread circuits (fd >= 256 via F_DUPFD).
         * Sending padding on a worker's connection advances the nonce,
         * desynchronizing the relay's decrypt state. */
        if (c->fd >= 256) continue;

        /* Lazy-init: assign randomized machine to circuits that don't have one yet.
         * Per-circuit randomization makes the state machine unlearnable. */
        if (!circ->wfpad_state.machine && g_wfpad_machine) {
            moor_wfpad_init_circuit_randomized(&circ->wfpad_state, g_wfpad_machine);
            circ->wfpad_state.next_pad_time_ms = now_ms + 100;
        }

        if (moor_wfpad_tick(&circ->wfpad_state, now_ms)) {
            /* Re-validate — prior iteration's send could have cascaded */
            if (circ->circuit_id == 0 || circ->conn != c ||
                c->state != CONN_STATE_OPEN) continue;
            uint8_t pad_payload[509];
            moor_crypto_random(pad_payload, 509);
            if (moor_mix_enabled()) {
                moor_mix_enqueue(c, circ->circuit_id, CELL_PADDING, pad_payload);
            } else {
                moor_cell_t cell;
                memset(&cell, 0, sizeof(cell));
                cell.circuit_id = circ->circuit_id;
                cell.command = CELL_PADDING;
                memcpy(cell.payload, pad_payload, 509);
                moor_connection_send_cell(c, &cell);
            }
        }
    }
}

/* Padding timer: fires at random intervals, sends CELL_PADDING on all circuits */
static int g_padding_timer_id = -1;
static void padding_timer_cb(void *arg) {
    (void)arg;
    if (g_wfpad_machine) {
        wfpad_tick_all(moor_time_ms());
    } else {
        moor_padding_send_all();
    }
    /* Update interval for next fire (variable random interval) */
    if (g_padding_timer_id >= 0)
        moor_event_set_timer_interval(g_padding_timer_id,
                                       g_wfpad_machine ? 5 :
                                       moor_padding_next_interval());
}

/* Dormant mode: client goes quiet after no SOCKS5 activity */
#define MOOR_DORMANT_TIMEOUT_MS    (5 * 60 * 1000)       /* 5 minutes */
#define MOOR_DORMANT_CONSENSUS_MS  (4 * 3600 * 1000)     /* 4 hours */
static int g_dormant = 0;
static uint64_t g_last_socks_activity_ms = 0;
static int g_consensus_timer_id = -1;

static void consensus_refresh_cb(void *arg);

static void dormant_check_cb(void *arg) {
    (void)arg;
    if (g_mode != MOOR_MODE_CLIENT || g_dormant) return;
    uint64_t now = moor_time_ms();
    if (g_last_socks_activity_ms > 0 &&
        (now - g_last_socks_activity_ms) > MOOR_DORMANT_TIMEOUT_MS) {
        g_dormant = 1;
        /* Stop padding to save bandwidth */
        if (g_padding_timer_id >= 0) {
            moor_event_remove_timer(g_padding_timer_id);
            g_padding_timer_id = -1;
        }
        /* Slow down consensus refresh */
        if (g_consensus_timer_id >= 0)
            moor_event_set_timer_interval(g_consensus_timer_id,
                                           MOOR_DORMANT_CONSENSUS_MS);
        LOG_INFO("dormant: no SOCKS5 activity for 5min, reducing activity");
    }
}

static void dormant_wake(void) {
    if (!g_dormant) return;
    g_dormant = 0;
    LOG_INFO("dormant: waking up (SOCKS5 connection)");
    /* Restart padding */
    if (g_padding_timer_id < 0)
        g_padding_timer_id = moor_event_add_timer(
            g_wfpad_machine ? 5 : moor_padding_next_interval(),
            padding_timer_cb, NULL);
    /* Restore consensus refresh interval */
    if (g_consensus_timer_id >= 0)
        moor_event_set_timer_interval(g_consensus_timer_id,
                                       MOOR_CONSENSUS_INTERVAL * 1000);
    /* Trigger immediate consensus refresh */
    consensus_refresh_cb(NULL);
}

/* SOCKS5 client event callbacks */
static int g_socks_listen_fd = -1;

static void socks_accept_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    g_last_socks_activity_ms = moor_time_ms();
    if (g_dormant) dormant_wake();
    moor_socks5_accept(fd);
}

static int run_da(void) {
    memset(&g_da_config, 0, sizeof(g_da_config));
    memcpy(g_da_config.identity_pk, g_identity_pk, 32);
    memcpy(g_da_config.identity_sk, g_identity_sk, 64);
    memcpy(g_da_config.pq_identity_pk, g_pq_identity_pk, MOOR_MLDSA_PK_LEN);
    memcpy(g_da_config.pq_identity_sk, g_pq_identity_sk, MOOR_MLDSA_SK_LEN);
    g_da_config.dir_port = g_dir_port;
    snprintf(g_da_config.bind_addr, sizeof(g_da_config.bind_addr), "%s", g_bind_addr);

    /* Parse DA peers for vote exchange */
    g_da_config.num_peers = 0;
    /* Parse DA peers: "ip:port:hex_identity_pk,ip:port:hex_identity_pk,..."
     * The identity_pk (64 hex chars = 32 bytes) is required for vote trust. */
    if (g_da_peers[0]) {
        char peers_copy[512];
        strncpy(peers_copy, g_da_peers, sizeof(peers_copy) - 1);
        peers_copy[sizeof(peers_copy) - 1] = '\0';
        char *saveptr = NULL;
        char *token = strtok_r(peers_copy, ",", &saveptr);
        while (token && g_da_config.num_peers < 8) {
            /* Parse: addr:port or addr:port:hex_pk */
            char addr[64] = {0};
            int port_val = 0;
            char hex_pk[128] = {0};

            /* Find first colon (after address) */
            char *c1 = strchr(token, ':');
            if (!c1) { token = strtok_r(NULL, ",", &saveptr); continue; }
            size_t addr_len = (size_t)(c1 - token);
            if (addr_len >= sizeof(addr)) addr_len = sizeof(addr) - 1;
            memcpy(addr, token, addr_len);

            /* Parse port */
            char *c2 = strchr(c1 + 1, ':');
            if (c2) {
                /* addr:port:hex_pk format */
                char port_str[8] = {0};
                size_t plen = (size_t)(c2 - c1 - 1);
                if (plen >= sizeof(port_str)) plen = sizeof(port_str) - 1;
                memcpy(port_str, c1 + 1, plen);
                port_val = atoi(port_str);
                snprintf(hex_pk, sizeof(hex_pk), "%s", c2 + 1);
            } else {
                /* addr:port format (no identity key) */
                port_val = atoi(c1 + 1);
            }

            if (port_val < 1 || port_val > 65535) {
                LOG_WARN("DA peer: invalid port in '%s', skipping", token);
                token = strtok_r(NULL, ",", &saveptr);
                continue;
            }

            int idx = g_da_config.num_peers;
            snprintf(g_da_config.peers[idx].address,
                     sizeof(g_da_config.peers[idx].address), "%s", addr);
            g_da_config.peers[idx].port = (uint16_t)port_val;

            /* Decode hex identity_pk if provided */
            if (hex_pk[0] && strlen(hex_pk) == 64) {
                sodium_hex2bin(g_da_config.peers[idx].identity_pk, 32,
                               hex_pk, 64, NULL, NULL, NULL);
                LOG_INFO("DA peer %d: %s:%d pk=%.8s...",
                         idx, addr, port_val, hex_pk);
            } else if (hex_pk[0]) {
                LOG_WARN("DA peer %d: bad identity key length (%zu hex chars, need 64)",
                         idx, strlen(hex_pk));
            } else {
                LOG_WARN("DA peer %d: %s:%d (no identity key — votes will be rejected)",
                         idx, addr, port_val);
            }
            g_da_config.num_peers++;
            token = strtok_r(NULL, ",", &saveptr);
        }
        LOG_INFO("DA: %d peer DAs configured for vote exchange",
                 g_da_config.num_peers);
    }

    /* Fill in missing peer identity keys from hardcoded DA list.
     * Like Tor: DA keys are compiled into the binary so vote trust
     * works without manual key exchange. */
    for (int p = 0; p < g_da_config.num_peers; p++) {
        static const uint8_t zero[32] = {0};
        if (sodium_memcmp(g_da_config.peers[p].identity_pk, zero, 32) == 0) {
            /* Try to match by address against hardcoded da_list */
            for (int d = 0; d < g_config.num_das; d++) {
                if (strcmp(g_da_config.peers[p].address,
                           g_config.da_list[d].address) == 0 &&
                    g_da_config.peers[p].port == g_config.da_list[d].port &&
                    sodium_memcmp(g_config.da_list[d].identity_pk, zero, 32) != 0) {
                    memcpy(g_da_config.peers[p].identity_pk,
                           g_config.da_list[d].identity_pk, 32);
                    LOG_INFO("DA peer %d: auto-filled identity key from hardcoded DA list", p);
                    break;
                }
            }
        }
    }

    g_da_config.pow_difficulty = g_pow_difficulty;

    moor_da_init(&g_da_config);

    /* Print our identity fingerprint so operators can configure peers */
    {
        char hex_id[65];
        sodium_bin2hex(hex_id, sizeof(hex_id), g_da_config.identity_pk, 32);
        LOG_INFO("DA identity fingerprint: %s", hex_id);
        LOG_INFO("DA: configure peers with: --da-peers <peer_ip>:<peer_port>:%s", hex_id);
    }

    /* Bootstrap: import relays from a peer DA's existing consensus.
     * This lets a new DA start with the same relay set as existing DAs
     * rather than waiting for relays to re-register. */
    if (g_da_config.num_peers > 0) {
        moor_consensus_t *peer_cons = calloc(1, sizeof(moor_consensus_t));
        if (peer_cons) {
            for (int p = 0; p < g_da_config.num_peers; p++) {
                if (moor_client_fetch_consensus(peer_cons,
                        g_da_config.peers[p].address,
                        g_da_config.peers[p].port) == 0) {
                    for (uint32_t i = 0; i < peer_cons->num_relays; i++)
                        moor_da_add_relay(&g_da_config, &peer_cons->relays[i]);
                    LOG_INFO("DA: bootstrapped %u relays from peer %s:%u",
                             peer_cons->num_relays,
                             g_da_config.peers[p].address,
                             g_da_config.peers[p].port);
                    /* Learn peer identity_pk from consensus signatures */
                    for (uint32_t s = 0; s < peer_cons->num_da_sigs; s++) {
                        for (int q = 0; q < g_da_config.num_peers; q++) {
                            if (sodium_is_zero(g_da_config.peers[q].identity_pk, 32)) {
                                memcpy(g_da_config.peers[q].identity_pk,
                                       peer_cons->da_sigs[s].identity_pk, 32);
                                if (peer_cons->da_sigs[s].has_pq) {
                                    memcpy(g_da_config.peers[q].pq_identity_pk,
                                           peer_cons->da_sigs[s].pq_pk,
                                           MOOR_MLDSA_PK_LEN);
                                    g_da_config.peers[q].has_pq = 1;
                                }
                                LOG_INFO("DA: learned peer %d identity from consensus sig", q);
                                break;
                            }
                        }
                    }
                    moor_consensus_cleanup(peer_cons);
                    break; /* One successful bootstrap is enough */
                }
            }
            free(peer_cons);
        }
    }

    int listen_fd = moor_da_run(&g_da_config);
    if (listen_fd < 0) return -1;

    moor_event_add(listen_fd, MOOR_EVENT_READ, da_accept_cb, NULL);
    da_pool_init();

    /* Build initial consensus and exchange votes with peers */
    moor_da_build_consensus(&g_da_config);
    moor_da_exchange_votes(&g_da_config);
    moor_da_update_published_snapshot(&g_da_config);

    /* Timer to rebuild consensus periodically.
     * Smart scheduling: rebuilds every 10 minutes normally, but every
     * 60 seconds when approaching the epoch boundary (last 10 minutes).
     * This ensures the consensus NEVER goes stale. */
    {
        uint64_t now = (uint64_t)time(NULL);
        uint64_t epoch = (now / MOOR_CONSENSUS_INTERVAL) * MOOR_CONSENSUS_INTERVAL;
        uint64_t fresh_until = epoch + MOOR_CONSENSUS_INTERVAL;
        uint64_t secs_left = (fresh_until > now) ? (fresh_until - now) : 0;
        uint64_t first_ms = (secs_left < 600) ? 60000 : 600000;
        g_da_last_epoch = epoch;
        g_da_consensus_timer_id = moor_event_add_timer((int)first_ms, da_consensus_timer_cb, NULL);
        LOG_INFO("DA: next consensus rebuild in %llus (epoch expires in %llus)",
                 (unsigned long long)(first_ms / 1000),
                 (unsigned long long)secs_left);
    }

    /* DA-to-DA relay sync: every 5 minutes, pull relay lists from peers */
    if (moor_event_add_timer(300 * 1000, da_sync_timer_cb, NULL) < 0) {
        LOG_ERROR("FATAL: failed to register DA sync timer");
        return -1;
    }

    /* Relay liveness probing: every 15 minutes, verify relays are reachable */
    if (moor_event_add_timer(900 * 1000, da_probe_timer_cb, NULL) < 0) {
        LOG_ERROR("FATAL: failed to register DA probe timer");
        return -1;
    }

    /* Connection reaper for DA mode */
    if (moor_event_add_timer(30000, conn_reap_timer_cb, NULL) < 0) {
        LOG_ERROR("FATAL: failed to register connection reaper timer");
        return -1;
    }

    LOG_INFO("directory authority running on %s:%u", g_bind_addr, g_dir_port);
#ifndef _WIN32
    if (maybe_drop_privileges() != 0) return -1;
#endif
    moor_sandbox_apply();
    int ret = moor_event_loop();
    da_pool_shutdown();
    return ret;
}

static int run_relay(void) {
    memset(&g_relay_cfg, 0, sizeof(g_relay_cfg));
    memcpy(g_relay_cfg.identity_pk, g_identity_pk, 32);
    memcpy(g_relay_cfg.identity_sk, g_identity_sk, 64);
    memcpy(g_relay_cfg.onion_pk, g_onion_pk, 32);
    memcpy(g_relay_cfg.onion_sk, g_onion_sk, 32);
    g_relay_cfg.or_port = g_or_port;
    g_relay_cfg.dir_port = 0;
    g_relay_cfg.flags = g_relay_flags;
    g_relay_cfg.bandwidth = g_bandwidth;
    snprintf(g_relay_cfg.bind_addr, sizeof(g_relay_cfg.bind_addr), "%s", g_bind_addr);
    snprintf(g_relay_cfg.advertise_addr, sizeof(g_relay_cfg.advertise_addr), "%s",
             g_advertise_addr[0] ? g_advertise_addr : g_bind_addr);
    snprintf(g_relay_cfg.da_address, sizeof(g_relay_cfg.da_address), "%s", g_da_address);
    g_relay_cfg.da_port = g_da_port;
    g_relay_cfg.num_das = g_num_das;
    for (int i = 0; i < g_num_das && i < 9; i++)
        g_relay_cfg.da_list[i] = g_da_list[i];

    g_relay_cfg.pow_difficulty = g_pow_difficulty;
    g_relay_cfg.pow_memlimit = g_config.pow_memlimit;
    g_relay_cfg.mix_delay = g_config.mix_delay;
    g_relay_cfg.padding_mode = g_padding_mode;
    memcpy(g_relay_cfg.nickname, g_config.nickname, sizeof(g_relay_cfg.nickname));
    memcpy(g_relay_cfg.contact_info, g_config.contact_info, sizeof(g_relay_cfg.contact_info));
    g_relay_cfg.is_bridge = g_is_bridge;

    /* Generate Kyber768 KEM keypair for PQ circuit crypto */
    if (moor_kem_keygen(g_relay_cfg.kem_pk, g_relay_cfg.kem_sk) != 0) {
        LOG_ERROR("failed to generate KEM keypair");
        return -1;
    }
    LOG_INFO("relay: Kyber768 KEM keypair generated for PQ circuits");

    /* Copy exit policy from config */
    memcpy(&g_relay_cfg.exit_policy, &g_config.exit_policy,
           sizeof(g_relay_cfg.exit_policy));

    if ((g_relay_flags & NODE_FLAG_EXIT) && g_config.exit_policy.num_rules == 0) {
        moor_exit_policy_set_defaults(&g_config.exit_policy);
        memcpy(&g_relay_cfg.exit_policy, &g_config.exit_policy,
               sizeof(g_relay_cfg.exit_policy));
        LOG_INFO("exit relay: applied default exit policy (%d rules)",
                 g_config.exit_policy.num_rules);
    }

    moor_relay_init(&g_relay_cfg);

    /* Bridge relays print their bridge line but don't register with DA */
    if (g_is_bridge) {
        LOG_INFO("bridge relay: skipping DA registration (unlisted)");
        char fp_hex[65];
        for (int i = 0; i < 32; i++)
            snprintf(fp_hex + i * 2, 3, "%02x", g_identity_pk[i]);
        const char *addr = g_advertise_addr[0] ? g_advertise_addr : g_bind_addr;
        LOG_INFO("bridge line: %s %s:%u %s",
                 g_bridge_transport, addr, g_relay_cfg.or_port, fp_hex);

        /* Auto-discover CDN domains with local edge servers for SNI pool.
         * Makes bridge TLS traffic look like local CDN access. */
        if (strcmp(g_bridge_transport, "shitstorm") == 0 ||
            strcmp(g_bridge_transport, "mirage") == 0) {
            moor_shitstorm_discover_local_snis(
                addr,
                (g_geoip_db.num_entries > 0) ? &g_geoip_db : NULL,
                g_data_dir[0] ? g_data_dir : NULL,
                1 /* is_bridge */);
        }
    }

    /* Listen for OR connections BEFORE registering with DA.
     * The DA probes our OR port after receiving the descriptor,
     * so we must be listening before the registration attempt. */
    g_relay_listen_fd = moor_listen(g_bind_addr, g_or_port);
    if (g_relay_listen_fd < 0) return -1;

    moor_event_add(g_relay_listen_fd, MOOR_EVENT_READ, relay_accept_cb, NULL);

    /* Initialize async EXTEND worker pipe (non-blocking relay EXTEND) */
    if (moor_relay_extend_init() != 0) {
        LOG_ERROR("failed to initialize async EXTEND subsystem");
        return -1;
    }

    /* Fetch consensus so relay can resolve EXTEND addresses (#183) */
    moor_bootstrap_report(BOOT_REQUESTING_CONS);
    {
        moor_consensus_t relay_cons = {0};
        if (moor_client_fetch_consensus_multi(&relay_cons, g_da_list, g_num_das) == 0) {
            moor_relay_set_consensus(&relay_cons);
            moor_bootstrap_report(BOOT_HAVE_CONSENSUS);
            LOG_INFO("relay: fetched consensus (%u relays)", relay_cons.num_relays);
        } else {
            LOG_WARN("relay: failed to fetch initial consensus");
        }
    }

    /* Now register with DAs (listener is already up for probe-back).
     * If registration fails (DAs still starting), the retry timer
     * handles exponential backoff until a DA accepts. */
    if (!g_is_bridge) {
        if (moor_relay_register(&g_relay_cfg) == 0) {
            g_reg_registered = 1;
            moor_bootstrap_report(BOOT_DONE);
        } else {
            LOG_WARN("relay: initial registration failed, will retry with backoff");
            g_reg_retry_timer_id = moor_event_add_timer(
                g_reg_retry_interval_ms, reg_retry_cb, NULL);
        }
    }

    /* Self-test: verify our own OR port is reachable.
     * SKIP for bridges — the self-test connects without a transport,
     * which triggers the bridge's transport handshake on a raw socket.
     * The self-test's connection allocates from the same pool as real
     * clients; if both are in-flight, the pool slot gets poisoned. */
    if (!g_is_bridge)
        g_selftest_timer_id = moor_event_add_timer(2000, relay_selftest_timer_cb, NULL);

    /* Re-fetch consensus after 15s to pick up relays that registered after us.
     * After first success, interval increases to CONSENSUS_INTERVAL/2 (30 min). */
    g_relay_consensus_retry_id = moor_event_add_timer(15000, relay_consensus_retry_cb, NULL);
    if (g_relay_consensus_retry_id < 0) {
        LOG_ERROR("FATAL: failed to register consensus retry timer");
        return -1;
    }

    /* Periodic re-registration — if this timer fails, the relay
     * silently stops re-registering and gets reaped after 3 hours. */
    if (moor_event_add_timer(MOOR_CONSENSUS_INTERVAL * 1000 / 2,
                         relay_periodic_cb, NULL) < 0) {
        LOG_ERROR("FATAL: failed to register periodic re-registration timer");
        return -1;
    }

    /* Circuit timeout enforcement: check every 10 seconds */
    if (moor_event_add_timer(10000, circuit_timeout_cb, NULL) < 0) {
        LOG_ERROR("FATAL: failed to register circuit timeout timer");
        return -1;
    }

    /* Observed bandwidth sampling: every 10 seconds (Tor-aligned).
     * Tracks actual throughput so relays advertise realistic bandwidth. */
    moor_event_add_timer(10000, observed_bw_timer_cb, NULL);

    /* Rate limiting: init + periodic refill */
    moor_ratelimit_init();
    moor_event_add_timer(6000, ratelimit_refill_cb, NULL);

    /* Bandwidth accounting (Tor-aligned hibernation) */
    if (g_config.accounting_max > 0) {
        g_accounting_period_start = (uint64_t)time(NULL);
        moor_event_add_timer(60000, accounting_timer_cb, NULL);
        LOG_INFO("accounting: limit %llu bytes/period (%llus)",
                 (unsigned long long)g_config.accounting_max,
                 (unsigned long long)g_config.accounting_period_sec);
    }

    /* Initialize Poisson mixing pool (relay only) */
    moor_mix_init(g_config.mix_delay);
    if (g_config.mix_delay > 0) {
        moor_event_add_timer(1, mix_drain_timer_cb, NULL);
        LOG_INFO("Poisson mixing enabled (lambda=%llu ms)",
                 (unsigned long long)g_config.mix_delay);
    }

    /* WTF-PAD: resolve padding machine (default: "generic" — mandatory baseline).
     * Per-circuit randomized machines are applied at lazy-init in wfpad_tick_all(). */
    if (g_config.padding_machine[0]) {
        g_wfpad_machine = moor_wfpad_find_machine(g_config.padding_machine);
        if (g_wfpad_machine) {
            g_padding = 1;
            LOG_INFO("WTF-PAD: using '%s' padding machine (randomized per-circuit)",
                     g_wfpad_machine->name);
        }
    }

    /* Padding is mandatory — always start the padding timer.
     * Traffic analysis defenses (constant-rate floor, FRONT, WTF-PAD)
     * require this timer to fire every 5ms for all active circuits. */
    moor_padding_enable(1);
    g_padding = 1;
    g_padding_timer_id = moor_event_add_timer(
        g_wfpad_machine ? 5 : moor_padding_next_interval(),
        padding_timer_cb, NULL);

    /* Initialize monitoring */
    moor_monitor_init();
    if (g_data_dir[0])
        moor_monitor_set_data_dir(g_data_dir);
    if (g_config.control_password[0])
        moor_monitor_set_password(g_config.control_password);
    if (g_control_port > 0) {
        moor_monitor_start(g_bind_addr, g_control_port);
        moor_event_add_timer(1000, bw_event_timer_cb, NULL);
    }
    if (g_monitor)
        moor_event_add_timer(60000, monitor_periodic_cb, NULL);

    /* Directory mirror: cache consensus and serve on dir_port */
    if (g_config.dir_cache && g_dir_port > 0) {
        g_relay_cfg.dir_port = g_dir_port;
        moor_relay_dir_cache_refresh(g_da_address, g_da_port);
        int dir_listen = moor_listen(g_bind_addr, g_dir_port);
        if (dir_listen >= 0) {
            moor_event_add(dir_listen, MOOR_EVENT_READ, relay_dir_accept_cb, NULL);
            LOG_INFO("directory mirror on %s:%u", g_bind_addr, g_dir_port);
        }
    }

    /* Connection reaper: close idle connections every 30s to prevent
     * pool exhaustion from zombie TCP sessions (clients that vanished
     * without RST -- common with NAT, mobile, WSL). */
    moor_event_add_timer(30000, conn_reap_timer_cb, NULL);

    LOG_INFO("relay running on %s:%u", g_bind_addr, g_or_port);
#ifndef _WIN32
    if (maybe_drop_privileges() != 0) return -1;
#endif
    moor_sandbox_apply();
    return moor_event_loop();
}

/* Consensus refresh timer callback */
static moor_consensus_t *g_live_consensus = NULL;

/* Try fetching consensus through a guard relay's dir_port (directory guard).
 * Falls back to direct DA fetch on failure. */
static int fetch_consensus_via_dir_guard(moor_consensus_t *fresh) {
    moor_consensus_t *current = moor_socks5_get_consensus();
    if (!current || current->num_relays == 0) return -1;

    /* Pick a guard relay that has a dir_port */
    for (uint32_t i = 0; i < current->num_relays; i++) {
        const moor_node_descriptor_t *r = &current->relays[i];
        if (!(r->flags & NODE_FLAG_GUARD)) continue;
        if (!(r->flags & NODE_FLAG_RUNNING)) continue;
        if (r->dir_port == 0) continue;

        if (moor_client_fetch_consensus(fresh, r->address, r->dir_port) == 0) {
            LOG_INFO("consensus fetched via directory guard %s:%u",
                     r->address, r->dir_port);
            return 0;
        }
    }
    return -1;
}

static volatile int g_client_cons_refresh_running = 0;
static volatile uint64_t g_client_cons_refresh_started = 0;

static void *client_consensus_refresh_thread(void *arg) {
    (void)arg;
    moor_consensus_t *fresh = calloc(1, sizeof(moor_consensus_t));
    if (!fresh) { __sync_lock_release(&g_client_cons_refresh_running); return NULL; }

    int ok = 0;
    if (fetch_consensus_via_dir_guard(fresh) == 0)
        ok = 1;
    if (!ok && moor_client_fetch_consensus_multi(fresh, g_da_list, g_num_das) == 0)
        ok = 1;

    if (ok) {
        moor_socks5_update_consensus(fresh);
        LOG_INFO("client: consensus refreshed (%u relays)", fresh->num_relays);
    }
    moor_consensus_cleanup(fresh);
    free(fresh);
    __sync_lock_release(&g_client_cons_refresh_running);
    return NULL;
}

static void consensus_refresh_cb(void *arg) {
    (void)arg;
    if (!g_live_consensus) return;

    if (g_client_cons_refresh_running) {
        uint64_t elapsed = (uint64_t)time(NULL) - g_client_cons_refresh_started;
        if (elapsed > 120) {
            LOG_WARN("client: consensus refresh thread stuck for %llus, force-resetting",
                     (unsigned long long)elapsed);
            __sync_lock_release(&g_client_cons_refresh_running);
        }
        return;
    }
    if (__sync_lock_test_and_set(&g_client_cons_refresh_running, 1) == 0) {
        g_client_cons_refresh_started = (uint64_t)time(NULL);
        pthread_t t;
        if (pthread_create(&t, NULL, client_consensus_refresh_thread, NULL) == 0)
            pthread_detach(t);
        else
            __sync_lock_release(&g_client_cons_refresh_running);
    }
    /* Old inline code moved to thread above. Keep the rest of the
     * callback for consensus cache save (fast, non-blocking). */
    return;
    /* Dead code below — was the old inline path. Keeping the function
     * signature intact so the timer registration doesn't change. */
    moor_consensus_t *fresh = NULL;
    int ok = 0;
    if (ok) {
        moor_socks5_update_consensus(fresh);
        if (g_config.data_dir[0])
            moor_consensus_cache_save(fresh, g_config.data_dir);
        LOG_INFO("consensus refreshed");
    }
    moor_consensus_cleanup(fresh);
    free(fresh);

    /* Schedule next refresh based on fresh_until — don't wait a fixed hour.
     * Fetch new consensus at 75% of remaining freshness, minimum 30s.
     * This prevents the "fetched at :58, stale at :00" problem. */
    moor_consensus_t *live = moor_socks5_get_consensus();
    if (live && g_consensus_timer_id >= 0) {
        uint64_t now = (uint64_t)time(NULL);
        uint64_t upper = live->fresh_until > 0 ? live->fresh_until : live->valid_until;
        uint64_t next_ms;
        if (now >= upper) {
            /* Already stale — retry fast */
            next_ms = 30000;
        } else {
            uint64_t remaining = upper - now;
            next_ms = (remaining * 750);  /* 75% of remaining, in ms */
            if (next_ms < 30000) next_ms = 30000;
        }
        moor_event_set_timer_interval(g_consensus_timer_id, next_ms);
        LOG_DEBUG("next consensus refresh in %llus (fresh_until in %llus)",
                  (unsigned long long)(next_ms / 1000),
                  (unsigned long long)(now < upper ? upper - now : 0));
    }
}

static int run_client(void) {
    moor_socks5_config_t socks_config;
    memset(&socks_config, 0, sizeof(socks_config));
    socks_config.listen_port = g_socks_port;
    snprintf(socks_config.listen_addr, sizeof(socks_config.listen_addr), "%s", g_bind_addr);
    snprintf(socks_config.da_address, sizeof(socks_config.da_address), "%s", g_da_address);
    socks_config.da_port = g_da_port;
    socks_config.num_das = g_num_das;
    for (int i = 0; i < g_num_das && i < 9; i++)
        socks_config.da_list[i] = g_da_list[i];
    memcpy(socks_config.identity_pk, g_identity_pk, 32);
    memcpy(socks_config.identity_sk, g_identity_sk, 64);

    socks_config.conflux = g_conflux;
    socks_config.conflux_legs = g_conflux_legs;

    /* Load persisted guard state (Prop 271) */
    if (g_data_dir[0]) {
        if (moor_guard_load(moor_pathbias_get_state(), g_data_dir) == 0)
            LOG_INFO("guard: loaded persisted state from %s", g_data_dir);
    }

    /* Tor-aligned: populate sampled guard set from consensus.
     * Fills any empty slots with GUARD+STABLE+RUNNING relays.
     * On first run, samples fresh guards.  On restart, preserves
     * existing guards and only fills gaps. */
    {
        const moor_consensus_t *cons = moor_socks5_get_consensus();
        if (cons && cons->num_relays > 0) {
            moor_guard_sample(moor_pathbias_get_state(), cons);
            moor_guard_update_primary(moor_pathbias_get_state());
        }
    }

    /* Auto-discover local CDN domains for ShitStorm/Mirage SNI pool.
     * DPI happens on the CLIENT side -- the client's ISP sees the SNI in
     * the ClientHello.  We need CDNs with edge servers in the client's
     * country so the SNI looks like normal local traffic.
     * Pass NULL for IP to auto-detect via ip-api.com. */
    const char *client_bridge_transport = (g_config.num_bridges > 0)
        ? g_config.bridges[0].transport : g_bridge_transport;
    if (g_use_bridges &&
        (strcmp(client_bridge_transport, "shitstorm") == 0 ||
         strcmp(client_bridge_transport, "mirage") == 0)) {
        /* Use the bridge's IP for SNI discovery — the DPI box is on
         * the path between us and the bridge, so SNIs should match
         * the bridge's network neighborhood, not ours. */
        const char *bridge_ip = (g_config.num_bridges > 0 && g_config.bridges[0].address[0])
                                ? g_config.bridges[0].address : NULL;
        moor_shitstorm_discover_local_snis(
            bridge_ip,
            (g_geoip_db.num_entries > 0) ? &g_geoip_db : NULL,
            g_data_dir[0] ? g_data_dir : NULL,
            0 /* is_bridge=0: client side, skip plaintext HTTP */);
    }

    moor_socks5_init(&socks_config);
    g_socks_listen_fd = moor_socks5_start(&socks_config);
    if (g_socks_listen_fd < 0) return -1;

    moor_event_add(g_socks_listen_fd, MOOR_EVENT_READ, socks_accept_cb, NULL);

    /* Circuit timeout enforcement: check every 10 seconds */
    moor_event_add_timer(10000, circuit_timeout_cb, NULL);

    /* Path bias detection: check guard success rates every 60s */
    moor_event_add_timer(60000, pathbias_timer_cb, NULL);

    /* Guard persistence: save state every 5 minutes */
    if (g_data_dir[0]) {
        moor_event_add_timer(300000, guard_save_timer_cb, NULL);
    }

    /* Periodic consensus refresh — schedule based on fresh_until, not fixed.
     * Fetches at 75% of remaining freshness to always stay ahead of expiry. */
    g_live_consensus = moor_socks5_get_consensus();
    {
        uint64_t first_ms = MOOR_CONSENSUS_INTERVAL * 1000;  /* fallback */
        if (g_live_consensus && g_live_consensus->fresh_until > 0) {
            uint64_t now = (uint64_t)time(NULL);
            uint64_t upper = g_live_consensus->fresh_until;
            if (now >= upper)
                first_ms = 30000;  /* already stale, fetch immediately-ish */
            else {
                first_ms = (upper - now) * 750;  /* 75% of remaining, in ms */
                if (first_ms < 30000) first_ms = 30000;
            }
        }
        g_consensus_timer_id = moor_event_add_timer((int)first_ms,
                                                     consensus_refresh_cb, NULL);
        LOG_INFO("consensus refresh: first fetch in %llus", (unsigned long long)(first_ms / 1000));
    }

    /* Dormant mode: check every 60s for idle client */
    g_last_socks_activity_ms = moor_time_ms();
    moor_event_add_timer(60000, dormant_check_cb, NULL);

    /* Network liveness check: every 10s (avoids retry spam when offline) */
    moor_event_add_timer(10000, liveness_timer_cb, NULL);

    /* WTF-PAD: resolve padding machine (default: "generic" — mandatory baseline).
     * Per-circuit randomized machines are applied at lazy-init in wfpad_tick_all(). */
    if (g_config.padding_machine[0]) {
        g_wfpad_machine = moor_wfpad_find_machine(g_config.padding_machine);
        if (g_wfpad_machine) {
            g_padding = 1;
            LOG_INFO("WTF-PAD: using '%s' padding machine (randomized per-circuit)",
                     g_wfpad_machine->name);
        }
    }

    /* Padding is mandatory — always start the padding timer.
     * Traffic analysis defenses (constant-rate floor, FRONT, WTF-PAD)
     * require this timer to fire every 5ms for all active circuits. */
    moor_padding_enable(1);
    g_padding = 1;
    g_padding_timer_id = moor_event_add_timer(
        g_wfpad_machine ? 5 : moor_padding_next_interval(),
        padding_timer_cb, NULL);

    /* Initialize monitoring */
    moor_monitor_init();
    if (g_data_dir[0])
        moor_monitor_set_data_dir(g_data_dir);
    if (g_config.control_password[0])
        moor_monitor_set_password(g_config.control_password);
    if (g_control_port > 0) {
        moor_monitor_start(g_bind_addr, g_control_port);
        moor_event_add_timer(1000, bw_event_timer_cb, NULL);
    }
    if (g_monitor)
        moor_event_add_timer(60000, monitor_periodic_cb, NULL);

    /* TransPort: transparent TCP proxy (iptables REDIRECT) */
    if (g_config.trans_port > 0) {
        const char *ta = g_config.trans_addr[0] ? g_config.trans_addr : "127.0.0.1";
        moor_transparent_start(ta, g_config.trans_port);
    }

    /* DNSPort: transparent DNS resolver */
    if (g_config.dns_port > 0) {
        const char *da = g_config.dns_addr[0] ? g_config.dns_addr : "127.0.0.1";
        moor_dns_start(da, g_config.dns_port);
    }

    if (g_use_bridges && g_config.num_bridges > 0) {
        fprintf(stderr, "\033[33mRouting through bridge: %s %s:%u (transport: %s)\033[0m\n",
                g_config.bridges[0].transport,
                g_config.bridges[0].address,
                g_config.bridges[0].port,
                g_config.bridges[0].transport);
        LOG_INFO("routing through bridge: %s %s:%u (transport: %s)",
                 g_config.bridges[0].transport,
                 g_config.bridges[0].address,
                 g_config.bridges[0].port,
                 g_config.bridges[0].transport);
    }
    LOG_INFO("SOCKS5 client running on %s:%u", g_bind_addr, g_socks_port);
#ifndef _WIN32
    if (maybe_drop_privileges() != 0) return -1;
#endif
    moor_sandbox_apply();
    return moor_event_loop();
}

/* HS intro circuit event context and callback.
 * Dynamic arrays — no hard limit on hidden services (Tor-aligned). */
moor_hs_config_t *g_hs_configs = NULL;
int g_num_hs_configs = 0;

typedef struct {
    moor_hs_config_t *config;
    moor_connection_t *conn;
} hs_intro_ctx_t;

static hs_intro_ctx_t *g_hs_intro_ctxs = NULL;
static int g_hs_intro_ctxs_cap = 0;
static int g_num_hs_intro_ctxs = 0;

/* HS rendezvous circuit context and callbacks */
typedef struct {
    moor_hs_config_t *config;
    moor_circuit_t *circ;
    moor_connection_t *conn;
} hs_rp_ctx_t;

#define MAX_HS_RP_CTXS 64
static hs_rp_ctx_t g_hs_rp_ctxs[MAX_HS_RP_CTXS];
static int g_num_hs_rp_ctxs = 0;
static void hs_rp_read_cb(int fd, int events, void *arg);

/* Map local target FDs back to HS RP circuit+stream for data return */
typedef struct {
    int fd;
    moor_circuit_t *circ;
    uint16_t stream_id;
    int deliver_window;   /* SENDME: cells received before we must ack */
    int package_window;   /* SENDME: cells we're allowed to send */
} hs_target_fd_t;

#define MAX_HS_TARGET_FDS 128
static hs_target_fd_t g_hs_target_fds[MAX_HS_TARGET_FDS];
static int g_hs_target_fd_count = 0;

static hs_target_fd_t *hs_target_fd_find(int fd) {
    for (int i = 0; i < g_hs_target_fd_count; i++) {
        if (g_hs_target_fds[i].fd == fd)
            return &g_hs_target_fds[i];
    }
    return NULL;
}

static void hs_target_fd_remove(int fd) {
    for (int i = 0; i < g_hs_target_fd_count; i++) {
        if (g_hs_target_fds[i].fd == fd) {
            g_hs_target_fds[i] = g_hs_target_fds[g_hs_target_fd_count - 1];
            g_hs_target_fd_count--;
            return;
        }
    }
}

/* Clear HS event context arrays when a circuit is freed.
 * Prevents poisoned-pointer dereference in event callbacks. */
void moor_hs_event_invalidate_circuit(moor_circuit_t *circ) {
    if (!circ) return;

    /* g_hs_target_fds: remove entries, close fd, deregister event */
    for (int i = 0; i < g_hs_target_fd_count; i++) {
        if (g_hs_target_fds[i].circ == circ) {
            if (g_hs_target_fds[i].fd >= 0) {
                moor_event_remove(g_hs_target_fds[i].fd);
                close(g_hs_target_fds[i].fd);
            }
            g_hs_target_fds[i] = g_hs_target_fds[--g_hs_target_fd_count];
            i--; /* re-check swapped entry */
        }
    }

    /* g_hs_rp_ctxs: remove event and reclaim slot so the array
     * doesn't fill with dead entries that block new registrations. */
    for (int i = 0; i < g_num_hs_rp_ctxs; i++) {
        if (g_hs_rp_ctxs[i].circ == circ) {
            if (g_hs_rp_ctxs[i].conn && g_hs_rp_ctxs[i].conn->fd >= 0)
                moor_event_remove(g_hs_rp_ctxs[i].conn->fd);
            if (i < g_num_hs_rp_ctxs - 1) {
                g_hs_rp_ctxs[i] = g_hs_rp_ctxs[g_num_hs_rp_ctxs - 1];
                /* Re-register moved entry so event arg tracks new slot */
                if (g_hs_rp_ctxs[i].conn &&
                    g_hs_rp_ctxs[i].conn->fd >= 0)
                    moor_event_add(g_hs_rp_ctxs[i].conn->fd,
                                   MOOR_EVENT_READ, hs_rp_read_cb,
                                   &g_hs_rp_ctxs[i]);
            }
            g_num_hs_rp_ctxs--;
            i--; /* re-check swapped entry */
        }
    }
}

/* Clear HS event context arrays when a connection is freed. */
void moor_hs_event_nullify_conn(moor_connection_t *conn) {
    if (!conn) return;

    /* g_hs_rp_ctxs: NULL conn */
    for (int i = 0; i < g_num_hs_rp_ctxs; i++) {
        if (g_hs_rp_ctxs[i].conn == conn) {
            moor_event_remove(conn->fd);
            g_hs_rp_ctxs[i].conn = NULL;
        }
    }

    /* g_hs_intro_ctxs: NULL conn */
    for (int i = 0; i < g_num_hs_intro_ctxs; i++) {
        if (g_hs_intro_ctxs[i].conn == conn) {
            moor_event_remove(conn->fd);
            g_hs_intro_ctxs[i].conn = NULL;
        }
    }
}

/* Callback: data arrived from local service target (HS → client via RP) */
static void hs_target_read_cb(int fd, int events, void *arg) {
    (void)events;
    (void)arg;
    hs_target_fd_t *map = hs_target_fd_find(fd);
    if (!map) {
        moor_event_remove(fd);
        close(fd);
        return;
    }

    /* SENDME: check package window before reading.  If exhausted, pause
     * reads until client sends SENDME to refill. */
    if (map->package_window <= 0 || map->circ->circ_package_window <= 0) {
        moor_event_remove(fd);
        LOG_DEBUG("HS: package window exhausted for stream %u (stream=%d circ=%d), pausing reads",
                  map->stream_id, map->package_window, map->circ->circ_package_window);
        return;
    }

    /* Limit recv to max plaintext that fits in a cell after e2e AEAD
     * encryption.  Without this, each cell silently truncates 16 bytes
     * (the MAC overhead), losing 16 * num_cells bytes per response. */
    size_t recv_max = MOOR_RELAY_DATA;
    if (map->circ->e2e_active)
        recv_max = MOOR_RELAY_DATA - 16; /* room for AEAD MAC */

    uint8_t buf[MOOR_RELAY_DATA];
    ssize_t n = recv(fd, (char *)buf, recv_max, 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return; /* non-blocking: no data yet, try later */
    if (n <= 0) {
        /* Local service closed or error -- send RELAY_END back */
        if (map->circ->conn && map->circ->conn->state == CONN_STATE_OPEN) {
            moor_cell_t end_cell;
            moor_cell_relay(&end_cell, map->circ->circuit_id, RELAY_END,
                           map->stream_id, NULL, 0);
            if (moor_circuit_encrypt_forward(map->circ, &end_cell) == 0)
                moor_connection_send_cell(map->circ->conn, &end_cell);
        }

        moor_event_remove(fd);
        hs_target_fd_remove(fd);
        close(fd);
        LOG_DEBUG("HS: local service closed, sent RELAY_END");
        return;
    }

    /* Forward data to client via RP circuit */
    uint8_t *send_data = buf;
    uint16_t send_len = (uint16_t)n;
    uint8_t e2e_enc_buf[MOOR_RELAY_DATA];
    if (map->circ->e2e_active) {
        size_t enc_len;
        LOG_DEBUG("HS e2e encrypt: stream=%u len=%zd nonce=%llu",
                  map->stream_id, n,
                  (unsigned long long)map->circ->e2e_send_nonce);
        if (moor_crypto_aead_encrypt(e2e_enc_buf, &enc_len, buf, (size_t)n,
                                      NULL, 0, map->circ->e2e_send_key,
                                      map->circ->e2e_send_nonce++) != 0) {
            LOG_ERROR("HS e2e encrypt FAILED: stream=%u nonce=%llu",
                      map->stream_id,
                      (unsigned long long)(map->circ->e2e_send_nonce - 1));
            return;
        }
        send_data = e2e_enc_buf;
        send_len = (uint16_t)enc_len;
    }
    if (!map->circ->conn || map->circ->conn->state != CONN_STATE_OPEN) {
        moor_event_remove(fd);
        hs_target_fd_remove(fd);
        close(fd);
        return;
    }
    moor_cell_t data_cell;
    moor_cell_relay(&data_cell, map->circ->circuit_id, RELAY_DATA,
                   map->stream_id, send_data, send_len);
    if (moor_circuit_encrypt_forward(map->circ, &data_cell) == 0)
        moor_connection_send_cell(map->circ->conn, &data_cell);

    /* SENDME: decrement package windows after sending */
    map->package_window--;
    if (map->circ->circ_package_window > 0)
        map->circ->circ_package_window--;
    map->circ->inflight++;
}

/* Callback: cell arrived on HS rendezvous circuit (from client via RP) */
static void hs_rp_read_cb(int fd, int events, void *arg) {
    (void)fd;
    hs_rp_ctx_t *ctx = (hs_rp_ctx_t *)arg;

    /* Flush output queue on write-readiness */
    if ((events & MOOR_EVENT_WRITE) && ctx->conn) {
        moor_queue_flush(&ctx->conn->outq, ctx->conn, &ctx->conn->write_off);
        if (moor_queue_is_empty(&ctx->conn->outq))
            moor_event_modify(ctx->conn->fd, MOOR_EVENT_READ);
    }

    if (!(events & MOOR_EVENT_READ)) return;

    if (!ctx->conn) {
        LOG_WARN("HS RP cb: conn is NULL (fd=%d)", fd);
        moor_event_remove(fd);
        return;
    }
    LOG_DEBUG("HS RP cb: fd=%d conn_fd=%d state=%d events=0x%x",
              fd, ctx->conn->fd, ctx->conn->state, events);

    moor_cell_t cell;
    int ret;
    int count = 0;
    while (count < 64 && (ret = moor_connection_recv_cell(ctx->conn, &cell)) == 1) {
        count++;
        LOG_DEBUG("HS RP recv: cell cmd=%u circ_id=%u", cell.command, cell.circuit_id);
        /* Handle DESTROY cell -- RP circuit torn down by peer */
        if (cell.command == CELL_DESTROY) {
            LOG_INFO("HS: received DESTROY on RP circuit (circ_id=%u)",
                     cell.circuit_id);
            ret = -1;
            break;
        }
        /* Skip non-relay cells — same nonce desync bug as intro circuits */
        if (cell.command == CELL_PADDING) continue;
        if (cell.command != CELL_RELAY) {
            LOG_DEBUG("HS RP: skipping non-relay cell cmd=%u", cell.command);
            continue;
        }

        moor_circuit_t *circ = moor_circuit_find(cell.circuit_id, ctx->conn);
        if (!circ) circ = ctx->circ;
        if (!circ || circ->circuit_id == 0) {
            LOG_WARN("HS recv: no valid circuit for cell (id=%u)", cell.circuit_id);
            continue;
        }

        if (moor_circuit_decrypt_backward(circ, &cell) != 0) {
            LOG_WARN("HS RP: backward decrypt failed on circuit %u",
                     circ->circuit_id);
            continue;
        }

        moor_relay_payload_t relay;
        moor_relay_unpack(&relay, cell.payload);

        LOG_DEBUG("HS RP relay: cmd=%u stream=%u recognized=%u dlen=%u",
                  relay.relay_command, relay.stream_id,
                  relay.recognized, relay.data_length);
        if (relay.recognized != 0) continue;

        switch (relay.relay_command) {
        case RELAY_BEGIN: {
            /* Client wants to connect to our local service.
             * RELAY_BEGIN payload: "address:port\0" (Tor-aligned) */
            uint16_t requested_port = 0;
            if (relay.data_length > 0) {
                char begin_addr[256];
                size_t cplen = relay.data_length;
                if (cplen >= sizeof(begin_addr)) cplen = sizeof(begin_addr) - 1;
                memcpy(begin_addr, relay.data, cplen);
                begin_addr[cplen] = '\0';
                char *colon = strrchr(begin_addr, ':');
                if (colon) requested_port = (uint16_t)strtol(colon + 1, NULL, 10);
            }

            /* Look up virtual port → local port */
            uint16_t local_port = 0;
            for (int pm = 0; pm < ctx->config->num_port_maps; pm++) {
                if (ctx->config->port_map[pm].virtual_port == requested_port) {
                    local_port = ctx->config->port_map[pm].local_port;
                    break;
                }
            }
            if (local_port == 0) {
                /* Fallback: if only one port mapped, use it; else reject */
                if (ctx->config->num_port_maps == 1)
                    local_port = ctx->config->port_map[0].local_port;
                else if (ctx->config->local_port)
                    local_port = ctx->config->local_port;
            }
            if (local_port == 0) {
                LOG_WARN("HS: RELAY_BEGIN for unmapped port %u, rejecting stream %u",
                         requested_port, relay.stream_id);
                moor_cell_t end_cell;
                moor_cell_relay(&end_cell, circ->circuit_id, RELAY_END,
                               relay.stream_id, NULL, 0);
                if (moor_circuit_encrypt_forward(circ, &end_cell) == 0)
                    moor_connection_send_cell(circ->conn, &end_cell);
                break;
            }

            LOG_INFO("HS: RELAY_BEGIN stream %u port %u → localhost:%u",
                     relay.stream_id, requested_port, local_port);

            /* Connect to local service */
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sa.sin_port = htons(local_port);

            int target_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (target_fd < 0) {
                LOG_ERROR("HS: socket() failed for local service");
                break;
            }

            /* Non-blocking connect to avoid stalling the event loop */
            moor_set_nonblocking(target_fd);

            if (connect(target_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 &&
                errno != EINPROGRESS) {
                LOG_ERROR("HS: connect to localhost:%u failed: %s",
                         local_port, strerror(errno));
                close(target_fd);
                moor_cell_t end_cell;
                moor_cell_relay(&end_cell, circ->circuit_id, RELAY_END,
                               relay.stream_id, NULL, 0);
                if (moor_circuit_encrypt_forward(circ, &end_cell) == 0)
                    moor_connection_send_cell(circ->conn, &end_cell);
                break;
            }

            LOG_INFO("HS: connected to local service localhost:%u (fd=%d)",
                     local_port, target_fd);

            /* Store target FD mapping */
            if (g_hs_target_fd_count < MAX_HS_TARGET_FDS) {
                int idx = g_hs_target_fd_count++;
                g_hs_target_fds[idx].fd = target_fd;
                g_hs_target_fds[idx].circ = circ;
                g_hs_target_fds[idx].stream_id = relay.stream_id;
                g_hs_target_fds[idx].deliver_window = MOOR_STREAM_WINDOW;
                g_hs_target_fds[idx].package_window = MOOR_STREAM_WINDOW;
            } else {
                LOG_WARN("HS: target fd table full, rejecting stream %u",
                         relay.stream_id);
                close(target_fd);
                /* Send RELAY_END so client doesn't hang (#193) */
                moor_cell_t end_cell;
                moor_cell_relay(&end_cell, circ->circuit_id, RELAY_END,
                               relay.stream_id, NULL, 0);
                if (moor_circuit_encrypt_forward(circ, &end_cell) == 0)
                    moor_connection_send_cell(circ->conn, &end_cell);
                break;
            }

            /* Register target FD for reading */
            moor_event_add(target_fd, MOOR_EVENT_READ,
                           hs_target_read_cb, NULL);

            /* Send RELAY_CONNECTED back to client */
            uint8_t connected_data[8];
            memset(connected_data, 0, sizeof(connected_data));
            connected_data[3] = 1; /* 127.0.0.1 */
            moor_cell_t conn_cell;
            moor_cell_relay(&conn_cell, circ->circuit_id, RELAY_CONNECTED,
                           relay.stream_id, connected_data, 8);
            if (moor_circuit_encrypt_forward(circ, &conn_cell) == 0)
                moor_connection_send_cell(circ->conn, &conn_cell);
            LOG_INFO("HS: sent RELAY_CONNECTED for stream %u",
                     relay.stream_id);
            break;
        }

        case RELAY_DATA: {
            /* E2e decrypt for HS rendezvous circuits (#197) */
            if (circ->e2e_active && relay.data_length > 16) {
                uint8_t dec_buf[MOOR_RELAY_DATA];
                size_t dec_len;
                LOG_DEBUG("HS e2e decrypt: stream=%u dlen=%u nonce=%llu",
                          relay.stream_id, relay.data_length,
                          (unsigned long long)circ->e2e_recv_nonce);
                if (moor_crypto_aead_decrypt(dec_buf, &dec_len,
                                              relay.data, relay.data_length,
                                              NULL, 0, circ->e2e_recv_key,
                                              circ->e2e_recv_nonce++) != 0) {
                    LOG_ERROR("HS e2e decrypt FAILED: stream=%u dlen=%u nonce=%llu "
                              "send_nonce=%llu",
                              relay.stream_id, relay.data_length,
                              (unsigned long long)(circ->e2e_recv_nonce - 1),
                              (unsigned long long)circ->e2e_send_nonce);
                    break;
                }
                memcpy(relay.data, dec_buf, dec_len);
                relay.data_length = (uint16_t)dec_len;
            }
            /* Forward data to local service */
            hs_target_fd_t *map = NULL;
            for (int i = 0; i < g_hs_target_fd_count; i++) {
                if (g_hs_target_fds[i].circ == circ &&
                    g_hs_target_fds[i].stream_id == relay.stream_id) {
                    map = &g_hs_target_fds[i];
                    break;
                }
            }
            if (map && map->fd >= 0) {
                size_t total_sent;
                int fwd = moor_stream_forward_to_target(
                    map->fd, relay.data, relay.data_length, &total_sent);
                if (fwd == STREAM_FWD_ERROR)
                    LOG_WARN("HS: send to local service failed for stream %u",
                             relay.stream_id);
                LOG_DEBUG("HS: forwarded %zu/%u bytes to local service fd=%d stream=%u",
                          total_sent, relay.data_length, map->fd, relay.stream_id);

                /* SENDME: decrement deliver window, send SENDME when threshold hit */
                map->deliver_window--;
                if (map->deliver_window <=
                    MOOR_STREAM_WINDOW - MOOR_SENDME_INCREMENT) {
                    moor_cell_t sendme;
                    moor_cell_relay(&sendme, circ->circuit_id, RELAY_SENDME,
                                   relay.stream_id, NULL, 0);
                    if (moor_circuit_encrypt_forward(circ, &sendme) == 0)
                        moor_connection_send_cell(circ->conn, &sendme);
                    map->deliver_window += MOOR_SENDME_INCREMENT;
                    LOG_DEBUG("HS: sent stream SENDME for stream %u (window=%d)",
                              relay.stream_id, map->deliver_window);
                }
                /* Circuit-level SENDME: RP relay handles this (relay.c
                 * sendme_check) with proper Prop 289 auth digest.
                 * HS only needs stream-level SENDMEs. */
            } else {
                LOG_WARN("HS: RELAY_DATA but no target fd for stream %u (map=%p count=%d)",
                         relay.stream_id, (void*)map, g_hs_target_fd_count);
            }
            break;
        }

        case RELAY_END: {
            /* Client closed the stream */
            for (int i = 0; i < g_hs_target_fd_count; i++) {
                if (g_hs_target_fds[i].circ == circ &&
                    g_hs_target_fds[i].stream_id == relay.stream_id) {
                    moor_event_remove(g_hs_target_fds[i].fd);
                    close(g_hs_target_fds[i].fd);
                    g_hs_target_fds[i] =
                        g_hs_target_fds[g_hs_target_fd_count - 1];
                    g_hs_target_fd_count--;
                    break;
                }
            }
            break;
        }

        case RELAY_SENDME: {
            /* Client sent SENDME -- refill our package window */
            if (relay.stream_id == 0) {
                /* Circuit-level: refill circ package window */
                circ->circ_package_window += MOOR_SENDME_INCREMENT;
                if (circ->circ_package_window > MOOR_CIRCUIT_WINDOW)
                    circ->circ_package_window = MOOR_CIRCUIT_WINDOW;
                /* CC: decrement inflight by SENDME_INCREMENT cells acked */
                circ->inflight -= MOOR_SENDME_INCREMENT;
                if (circ->inflight < 0) circ->inflight = 0;
                LOG_DEBUG("HS: circuit SENDME, package_window=%d inflight=%d",
                          circ->circ_package_window, circ->inflight);
            } else {
                /* Stream-level: refill stream package window */
                for (int i = 0; i < g_hs_target_fd_count; i++) {
                    if (g_hs_target_fds[i].circ == circ &&
                        g_hs_target_fds[i].stream_id == relay.stream_id) {
                        g_hs_target_fds[i].package_window += MOOR_SENDME_INCREMENT;
                        if (g_hs_target_fds[i].package_window > MOOR_STREAM_WINDOW)
                            g_hs_target_fds[i].package_window = MOOR_STREAM_WINDOW;
                        LOG_DEBUG("HS: stream %u SENDME, package_window=%d",
                                  relay.stream_id, g_hs_target_fds[i].package_window);
                        /* Re-enable reads from local service if paused */
                        if (g_hs_target_fds[i].package_window > 0)
                            moor_event_add(g_hs_target_fds[i].fd, MOOR_EVENT_READ,
                                           hs_target_read_cb, NULL);
                        break;
                    }
                }
            }
            break;
        }

        case RELAY_E2E_KEM_CT: {
            /* PQ hybrid e2e: accumulate Kyber768 ciphertext from client */
            if (!circ->e2e_kem_pending) {
                LOG_DEBUG("HS: RELAY_E2E_KEM_CT but not pending, ignoring");
                break;
            }
            size_t space = 1088 - circ->e2e_kem_ct_len;
            size_t chunk = relay.data_length;
            if (chunk > space) chunk = space;
            if (chunk > 0) {
                memcpy(circ->e2e_kem_ct + circ->e2e_kem_ct_len,
                       relay.data, chunk);
                circ->e2e_kem_ct_len += (uint16_t)chunk;
            }
            if (circ->e2e_kem_ct_len >= 1088) {
                /* Full KEM CT received -- decapsulate and rekey */
                uint8_t kem_ss[32];
                if (moor_kem_decapsulate(kem_ss, circ->e2e_kem_ct,
                                          ctx->config->kem_sk) != 0) {
                    LOG_ERROR("HS: e2e KEM decapsulation failed");
                    circ->e2e_kem_pending = 0;
                    break;
                }
                /* Hybrid KDF: BLAKE2b(dh_shared || kem_ss) */
                uint8_t combined[64];
                memcpy(combined, circ->e2e_dh_shared, 32);
                memcpy(combined + 32, kem_ss, 32);
                uint8_t hybrid[32];
                moor_crypto_hash(hybrid, combined, 64);
                /* HS: send=subkey 1, recv=subkey 0 (opposite of client) */
                moor_crypto_kdf(circ->e2e_send_key, 32,
                                hybrid, 1, "moore2e!");
                moor_crypto_kdf(circ->e2e_recv_key, 32,
                                hybrid, 0, "moore2e!");
                /* Continue nonce counters -- do NOT reset to 0.
                 * Resetting causes desync with client which rekeyed
                 * before we received the KEM CT. */
                circ->e2e_kem_pending = 0;
                moor_crypto_wipe(kem_ss, 32);
                moor_crypto_wipe(combined, 64);
                moor_crypto_wipe(hybrid, 32);
                moor_crypto_wipe(circ->e2e_dh_shared, 32);
                LOG_INFO("HS: e2e upgraded to PQ hybrid (X25519 + Kyber768)");
            }
            break;
        }

        default:
            LOG_DEBUG("HS RP: unhandled relay cmd %d", relay.relay_command);
            break;
        }
    }
    if (ret < 0) {
        if (!ctx->conn) {
            moor_event_remove(fd);
            return;
        }
        LOG_WARN("HS: RP circuit connection lost (fd=%d conn_fd=%d state=%d "
                 "recv_nonce=%llu send_nonce=%llu)",
                 fd, ctx->conn->fd, ctx->conn->state,
                 (unsigned long long)ctx->conn->recv_nonce,
                 (unsigned long long)ctx->conn->send_nonce);
        moor_event_remove(ctx->conn->fd);
        /* Clean up local service target FDs for this circuit */
        {
            int i = 0;
            while (i < g_hs_target_fd_count) {
                if (g_hs_target_fds[i].circ == ctx->circ) {
                    moor_event_remove(g_hs_target_fds[i].fd);
                    close(g_hs_target_fds[i].fd);
                    g_hs_target_fds[i] =
                        g_hs_target_fds[g_hs_target_fd_count - 1];
                    g_hs_target_fd_count--;
                    /* Don't increment i -- check the swapped-in element */
                } else {
                    i++;
                }
            }
        }
        /* Defer circuit close to end of event loop — inline
         * moor_circuit_free() during a callback triggers
         * moor_socks5_invalidate_circuit() compaction which can
         * corrupt caches and cause double-free (same class of bug
         * as the socks5.c CELL_DESTROY crash). */
        if (!MOOR_CIRCUIT_IS_MARKED(ctx->circ))
            moor_circuit_mark_for_close(ctx->circ,
                                        DESTROY_REASON_CONNECTFAILED);
        /* Connection close is safe (pool-based, not heap) */
        moor_event_remove(ctx->conn->fd);
        moor_connection_close(ctx->conn);
        /* Clear the config slot so it can be reused */
        for (int i = 0; i < 8; i++) {
            if (ctx->config->rp_circuits[i] == ctx->circ) {
                ctx->config->rp_circuits[i] = NULL;
                ctx->config->rp_connections[i] = NULL;
                break;
            }
        }
        ctx->circ = NULL;
        ctx->conn = NULL;
        /* Reclaim this RP ctx slot so the array doesn't monotonically fill.
         * After swap, re-register the moved entry's fd so the event loop
         * arg pointer tracks the new array position. */
        {
            int dead_idx = (int)(ctx - g_hs_rp_ctxs);
            if (dead_idx >= 0 && dead_idx < g_num_hs_rp_ctxs) {
                if (dead_idx < g_num_hs_rp_ctxs - 1) {
                    g_hs_rp_ctxs[dead_idx] =
                        g_hs_rp_ctxs[g_num_hs_rp_ctxs - 1];
                    /* Re-register moved entry so event arg points to new slot */
                    if (g_hs_rp_ctxs[dead_idx].conn &&
                        g_hs_rp_ctxs[dead_idx].conn->fd >= 0)
                        moor_event_add(g_hs_rp_ctxs[dead_idx].conn->fd,
                                       MOOR_EVENT_READ, hs_rp_read_cb,
                                       &g_hs_rp_ctxs[dead_idx]);
                }
                g_num_hs_rp_ctxs--;
            }
        }
    }
}

/* Register any new RP circuits from config with the event loop */
static void hs_register_rp_circuits(moor_hs_config_t *config, int from_idx) {
    (void)from_idx; /* Scan all slots -- reused slots may be below from_idx */
    for (int i = 0; i < 8; i++) {
        moor_circuit_t *circ = config->rp_circuits[i];
        moor_connection_t *conn = config->rp_connections[i];
        if (!circ || !conn || conn->fd < 0) continue;
        /* Check if already registered */
        int already = 0;
        for (int j = 0; j < g_num_hs_rp_ctxs; j++) {
            if (g_hs_rp_ctxs[j].circ == circ) { already = 1; break; }
        }
        if (already) continue;
        if (g_num_hs_rp_ctxs < MAX_HS_RP_CTXS) {
            int idx = g_num_hs_rp_ctxs++;
            g_hs_rp_ctxs[idx].config = config;
            g_hs_rp_ctxs[idx].circ = circ;
            g_hs_rp_ctxs[idx].conn = conn;
            moor_event_add(conn->fd, MOOR_EVENT_READ,
                           hs_rp_read_cb, &g_hs_rp_ctxs[idx]);
            LOG_INFO("HS: registered RP circuit %d fd=%d for events",
                     i, conn->fd);
        }
    }
}

static void hs_intro_read_cb(int fd, int events, void *arg) {
    (void)fd;
    hs_intro_ctx_t *ctx = (hs_intro_ctx_t *)arg;

    /* Flush output queue on write-readiness */
    if ((events & MOOR_EVENT_WRITE) && ctx->conn) {
        moor_queue_flush(&ctx->conn->outq, ctx->conn, &ctx->conn->write_off);
        if (moor_queue_is_empty(&ctx->conn->outq))
            moor_event_modify(ctx->conn->fd, MOOR_EVENT_READ);
    }

    if (!(events & MOOR_EVENT_READ)) return;

    if (!ctx->conn) {
        moor_event_remove(fd);
        return;
    }

    moor_cell_t cell;
    int ret;
    int count = 0;
    while (count < 64 && (ret = moor_connection_recv_cell(ctx->conn, &cell)) == 1) {
        count++;

        /* Skip non-relay cells — decrypting CELL_PADDING or CELL_DESTROY
         * as relay onion layers increments backward nonces without updating
         * the digest, permanently desyncing the circuit's crypto state.
         * Every subsequent real cell then fails to decrypt. */
        if (cell.command == CELL_PADDING) continue;
        if (cell.command == CELL_DESTROY) {
            LOG_WARN("HS: DESTROY on intro circuit (circ_id=%u)", cell.circuit_id);
            /* Find and kill the matching intro circuit */
            for (int j = 0; j < ctx->config->num_intro_circuits; j++) {
                if (ctx->config->intro_circuits[j] &&
                    ctx->config->intro_circuits[j]->circuit_id == cell.circuit_id) {
                    moor_circuit_free(ctx->config->intro_circuits[j]);
                    ctx->config->intro_circuits[j] = NULL;
                    ctx->config->intro_established_at[j] = 0;
                    ctx->config->intros_need_reestablish = 1;
                    break;
                }
            }
            continue;
        }
        if (cell.command != CELL_RELAY) {
            LOG_DEBUG("HS intro: skipping non-relay cell cmd=%u", cell.command);
            continue;
        }

        /* Find the circuit for this cell */
        moor_circuit_t *circ = moor_circuit_find(cell.circuit_id, ctx->conn);
        if (!circ) continue;

        /* Decrypt all onion layers (we are the circuit origin) */
        if (moor_circuit_decrypt_backward(circ, &cell) != 0) {
            LOG_WARN("HS: backward decrypt failed on intro circuit %u",
                     circ->circuit_id);
            continue;
        }

        /* Parse relay payload */
        moor_relay_payload_t relay;
        moor_relay_unpack(&relay, cell.payload);

        if (relay.recognized == 0 && relay.relay_command == RELAY_INTRODUCE2) {
            LOG_INFO("HS: received INTRODUCE2 (%u bytes)", relay.data_length);
            moor_hs_handle_introduce(ctx->config, circ,
                                      relay.data, relay.data_length);
            /* Always register -- slot reuse won't change num_rp_circuits */
            hs_register_rp_circuits(ctx->config, 0);
        }
    }
    if (ret < 0) {
        if (!ctx->conn) return;
        moor_event_remove(ctx->conn->fd);
        LOG_WARN("HS: intro circuit connection lost (fd=%d state=%d recv_nonce=%llu "
                 "recv_len=%zu errno=%d)",
                 ctx->conn->fd, ctx->conn->state,
                 (unsigned long long)ctx->conn->recv_nonce,
                 ctx->conn->recv_len, errno);
        /* Clean up circuit and connection, mark slot for re-establishment */
        int dead_fd = ctx->conn->fd;
        for (int j = 0; j < ctx->config->num_intro_circuits; j++) {
            if (ctx->config->intro_circuits[j] &&
                ctx->config->intro_circuits[j]->conn == ctx->conn) {
                moor_circuit_free(ctx->config->intro_circuits[j]);
                ctx->config->intro_circuits[j] = NULL;
                ctx->config->intro_established_at[j] = 0;
                break;
            }
        }
        moor_connection_free(ctx->conn);
        if (dead_fd >= 0) close(dead_fd);
        ctx->conn = NULL;

        /* Flag for deferred intro re-establishment.  We cannot rebuild
         * intros inline here because the synchronous circuit build
         * reuses connection pool slots, and other RP circuits still
         * hold pointers to those slots — causing state corruption
         * (conn->state goes from OPEN to HANDSHAKING under the RP
         * circuit's feet).  The timer-based approach is safe. */
        ctx->config->intros_need_reestablish = 1;
    }
}

/* g_hs_consensus declared at top of file */

/* R10-CC3: Periodic timer callbacks for HS mode */
static volatile int g_hs_cons_refresh_running = 0;
static volatile uint64_t g_hs_cons_refresh_started = 0;

static void *hs_consensus_refresh_thread(void *arg) {
    (void)arg;
    if (!g_hs_consensus) {
        __sync_lock_release(&g_hs_cons_refresh_running);
        return NULL;
    }
    moor_consensus_t *fresh = calloc(1, sizeof(moor_consensus_t));
    if (!fresh) { __sync_lock_release(&g_hs_cons_refresh_running); return NULL; }
    if (moor_client_fetch_consensus_multi(fresh, g_da_list, g_num_das) == 0) {
        moor_consensus_cleanup(g_hs_consensus);
        memcpy(g_hs_consensus, fresh, sizeof(*fresh));
        fresh->relays = NULL;
        LOG_INFO("HS: consensus refreshed (%u relays)", g_hs_consensus->num_relays);
        if (g_config.data_dir[0])
            moor_consensus_cache_save(g_hs_consensus, g_config.data_dir);
        for (int h = 0; h < g_config.num_hidden_services || h < 1; h++)
            g_hs_configs[h].cached_consensus = g_hs_consensus;
    } else {
        moor_consensus_cleanup(fresh);
    }
    free(fresh);
    __sync_lock_release(&g_hs_cons_refresh_running);
    return NULL;
}

static void hs_consensus_refresh_cb(void *arg) {
    (void)arg;
    if (!g_hs_consensus) return;
    if (g_hs_cons_refresh_running) {
        uint64_t elapsed = (uint64_t)time(NULL) - g_hs_cons_refresh_started;
        if (elapsed > 120) {
            LOG_WARN("HS: consensus refresh thread stuck, force-resetting");
            __sync_lock_release(&g_hs_cons_refresh_running);
        }
        return;
    }
    if (__sync_lock_test_and_set(&g_hs_cons_refresh_running, 1) == 0) {
        g_hs_cons_refresh_started = (uint64_t)time(NULL);
        pthread_t t;
        if (pthread_create(&t, NULL, hs_consensus_refresh_thread, NULL) == 0)
            pthread_detach(t);
        else
            __sync_lock_release(&g_hs_cons_refresh_running);
    }
    /* Old inline code that leaked 'fresh' on the else branch: */
    return;
    moor_consensus_t *fresh = NULL;
    if (0) {
        moor_consensus_cleanup(fresh);
    }
    free(fresh);
}

static void hs_blinded_key_rotation_cb(void *arg) {
    (void)arg;
    int hs_count = g_config.num_hidden_services;
    if (hs_count == 0) hs_count = 1;
    for (int h = 0; h < hs_count; h++) {
        uint64_t tp = (uint64_t)time(NULL) / MOOR_TIME_PERIOD_SECS;
        if (tp != g_hs_configs[h].current_time_period) {
            LOG_INFO("HS %d: time period changed %llu -> %llu, rotating blinded keys",
                     h, (unsigned long long)g_hs_configs[h].current_time_period,
                     (unsigned long long)tp);
            g_hs_configs[h].current_time_period = tp;
            moor_crypto_blind_keypair(g_hs_configs[h].blinded_pk,
                                       g_hs_configs[h].blinded_sk,
                                       g_hs_configs[h].identity_pk,
                                       g_hs_configs[h].identity_sk, tp);
        }
    }
}

/* Send PADDING cells on intro circuit connections to keep NAT mappings alive.
 * Without this, the Pi's NAT router drops the TCP mapping after ~4 minutes
 * and intro circuits silently die. TCP keepalive doesn't help because many
 * NAT routers ignore keepalive-only ACKs.
 *
 * IMPORTANT: Do NOT circuit-encrypt (moor_circuit_encrypt_forward) CELL_PADDING.
 * Relays skip circuit-layer decryption for CELL_PADDING (relay.c case
 * CELL_PADDING: return 0), so encrypting would desync the forward nonce
 * counter — every subsequent relay cell fails to decrypt and the circuit
 * silently dies.  Send at the link layer only. */
static void hs_intro_padding_cb(void *arg) {
    (void)arg;
    int hs_count = g_config.num_hidden_services;
    if (hs_count == 0) hs_count = 1;
    for (int h = 0; h < hs_count; h++) {
        for (int i = 0; i < g_hs_configs[h].num_intro_circuits; i++) {
            moor_circuit_t *circ = g_hs_configs[h].intro_circuits[i];
            if (!circ || !circ->conn || circ->conn->state != CONN_STATE_OPEN)
                continue;
            /* Link-level padding: no circuit encryption, no nonce bump.
             * The relay sees CELL_PADDING at the link layer and returns 0. */
            moor_cell_t pad;
            memset(&pad, 0, sizeof(pad));
            pad.circuit_id = circ->circuit_id;
            pad.command = CELL_PADDING;
            moor_connection_send_cell(circ->conn, &pad);
        }
    }
}

static void hs_intro_rotation_cb(void *arg) {
    (void)arg;
    if (!g_hs_consensus) return;
    int hs_count = g_config.num_hidden_services;
    if (hs_count == 0) hs_count = 1;
    for (int h = 0; h < hs_count; h++) {
        /* Check deferred re-establishment flag (set when intros die
         * during hs_intro_read_cb — can't rebuild inline due to
         * connection pool reuse corrupting live RP circuits). */
        if (g_hs_configs[h].intros_need_reestablish) {
            g_hs_configs[h].intros_need_reestablish = 0;
            LOG_INFO("HS %d: deferred intro re-establishment triggered", h);
            /* moor_hs_establish_intro builds circuits synchronously (blocking
             * TCP to relays). moor_hs_publish_descriptor does TCP to DAs.
             * Both block the event loop. Accept the block here because intro
             * re-establishment is rare (only when intro circuits die) and
             * must complete before we register the new circuits with the
             * event loop below. Moving to a thread would require complex
             * synchronization with the event registration code. */
            moor_hs_establish_intro(&g_hs_configs[h], g_hs_consensus);
            moor_hs_publish_descriptor(&g_hs_configs[h]);
            /* Fall through to register new intro circuits with event loop */
        }
        if (moor_hs_check_intro_rotation(&g_hs_configs[h], g_hs_consensus) > 0) {
            LOG_INFO("HS %d: intro points rotated, re-registering", h);
        }
        /* Always scan for unregistered intro circuits — both the deferred
         * re-establishment path and the rotation path create new circuits
         * that need event registration.  Without this, rebuilt intro
         * circuits never receive INTRODUCE2 and the HS is unreachable. */
        {
            for (int i = 0; i < g_hs_configs[h].num_intro_circuits; i++) {
                moor_circuit_t *circ = g_hs_configs[h].intro_circuits[i];
                if (circ && circ->conn && circ->conn->fd >= 0) {
                    if (g_num_hs_intro_ctxs >= g_hs_intro_ctxs_cap) {
                        int nc = g_hs_intro_ctxs_cap ? g_hs_intro_ctxs_cap * 2 : 64;
                        hs_intro_ctx_t *tmp = realloc(g_hs_intro_ctxs, nc * sizeof(*tmp));
                        if (!tmp) continue;
                        memset(tmp + g_hs_intro_ctxs_cap, 0, (nc - g_hs_intro_ctxs_cap) * sizeof(*tmp));
                        /* Realloc moved the array — re-register ALL existing
                         * event entries so their arg pointers stay valid. */
                        for (int r = 0; r < g_num_hs_intro_ctxs; r++) {
                            if (tmp[r].conn && tmp[r].conn->fd >= 0)
                                moor_event_add(tmp[r].conn->fd, MOOR_EVENT_READ,
                                               hs_intro_read_cb, &tmp[r]);
                        }
                        g_hs_intro_ctxs = tmp;
                        g_hs_intro_ctxs_cap = nc;
                    }
                    int already = 0;
                    for (int j = 0; j < g_num_hs_intro_ctxs; j++) {
                        if (g_hs_intro_ctxs[j].conn == circ->conn) {
                            already = 1; break;
                        }
                    }
                    if (already) continue;
                    int idx = g_num_hs_intro_ctxs++;
                    g_hs_intro_ctxs[idx].config = &g_hs_configs[h];
                    g_hs_intro_ctxs[idx].conn = circ->conn;
                    moor_event_add(circ->conn->fd, MOOR_EVENT_READ,
                                   hs_intro_read_cb, &g_hs_intro_ctxs[idx]);
                }
            }
        }
    }
}

static void *hs_desc_republish_thread(void *arg) {
    (void)arg;
    int hs_count = g_config.num_hidden_services;
    if (hs_count == 0) hs_count = 1;
    for (int h = 0; h < hs_count; h++) {
        LOG_INFO("HS %d: periodic descriptor republish", h);
        moor_hs_publish_descriptor(&g_hs_configs[h]);
    }
    return NULL;
}

static void hs_desc_republish_cb(void *arg) {
    (void)arg;
    pthread_t t;
    if (pthread_create(&t, NULL, hs_desc_republish_thread, NULL) == 0)
        pthread_detach(t);
    else
        hs_desc_republish_thread(NULL); /* fallback: inline */
}

static int run_hs(void) {
    /* Heap-allocate consensus (~3.5MB -- must not be on stack) */
    g_hs_consensus = calloc(1, sizeof(moor_consensus_t));
    if (!g_hs_consensus) {
        LOG_ERROR("failed to allocate consensus");
        return -1;
    }
    /* Try cached consensus first, then fetch fresh */
    int have_consensus = 0;
    if (g_config.data_dir[0] &&
        moor_consensus_cache_load(g_hs_consensus, g_config.data_dir) == 0 &&
        moor_consensus_is_valid(g_hs_consensus)) {
        LOG_INFO("using cached consensus");
        have_consensus = 1;
    }
    if (!have_consensus) {
        if (moor_client_fetch_consensus_multi(g_hs_consensus, g_da_list, g_num_das) != 0) {
            LOG_ERROR("failed to fetch consensus");
            free(g_hs_consensus); g_hs_consensus = NULL;
            return -1;
        }
        if (g_config.data_dir[0])
            moor_consensus_cache_save(g_hs_consensus, g_config.data_dir);
    }

    /* Multi-HS: iterate all configured hidden services */
    int hs_count = g_config.num_hidden_services;
    if (hs_count == 0) {
        /* Backward compat: use legacy g_hs_dir / g_hs_local_port */
        hs_count = 1;
    }

    /* Allocate runtime HS config array (dynamic, no hard limit) */
    g_hs_configs = calloc(hs_count, sizeof(moor_hs_config_t));
    if (!g_hs_configs) { LOG_ERROR("HS: config alloc failed"); return -1; }
    g_num_hs_configs = hs_count;

    for (int h = 0; h < hs_count; h++) {
        moor_hs_config_t hs_config;
        memset(&hs_config, 0, sizeof(hs_config));

        if (g_config.num_hidden_services > 0) {
            snprintf(hs_config.hs_dir, sizeof(hs_config.hs_dir), "%s",
                     g_config.hidden_services[h].hs_dir);
            hs_config.local_port = g_config.hidden_services[h].local_port;
            /* Propagate port mappings */
            hs_config.num_port_maps = g_config.hidden_services[h].num_port_maps;
            for (int pm = 0; pm < hs_config.num_port_maps; pm++) {
                hs_config.port_map[pm].virtual_port =
                    g_config.hidden_services[h].port_map[pm].virtual_port;
                hs_config.port_map[pm].local_port =
                    g_config.hidden_services[h].port_map[pm].local_port;
            }
            /* Propagate authorized clients */
            hs_config.num_auth_clients = g_config.hidden_services[h].num_auth_clients;
            for (int ac = 0; ac < hs_config.num_auth_clients; ac++) {
                memcpy(hs_config.auth_clients[ac].client_pk,
                       g_config.hidden_services[h].auth_client_pks[ac], 32);
            }
        } else {
            snprintf(hs_config.hs_dir, sizeof(hs_config.hs_dir), "%s", g_hs_dir);
            hs_config.local_port = g_hs_local_port;
        }

        snprintf(hs_config.da_address, sizeof(hs_config.da_address), "%s", g_da_address);
        hs_config.da_port = g_da_port;
        hs_config.num_das = g_num_das;
        for (int d = 0; d < g_num_das && d < 9; d++)
            hs_config.da_list[d] = g_da_list[d];

        /* HS PoW DoS protection */
        hs_config.pow_enabled = g_config.hs_pow;
        hs_config.pow_difficulty = g_config.hs_pow_difficulty > 0 ?
                                    g_config.hs_pow_difficulty : 16;

        /* Store consensus pointer before init so DHT publish can use it */
        hs_config.cached_consensus = g_hs_consensus;

        if (moor_hs_init(&hs_config, g_hs_consensus) != 0) {
            LOG_ERROR("failed to initialize hidden service %d", h);
            return -1;
        }

        /* Persist hs_config so event callbacks can access it */
        memcpy(&g_hs_configs[h], &hs_config, sizeof(hs_config));

        /* Register intro circuit connections with event loop */
        for (int i = 0; i < g_hs_configs[h].num_intro_circuits; i++) {
            moor_circuit_t *circ = g_hs_configs[h].intro_circuits[i];
            if (circ && circ->conn && circ->conn->fd >= 0) {
                if (g_num_hs_intro_ctxs >= g_hs_intro_ctxs_cap) {
                    int nc = g_hs_intro_ctxs_cap ? g_hs_intro_ctxs_cap * 2 : 64;
                    hs_intro_ctx_t *tmp = realloc(g_hs_intro_ctxs, nc * sizeof(*tmp));
                    if (!tmp) { LOG_WARN("HS: intro ctx realloc failed"); continue; }
                    memset(tmp + g_hs_intro_ctxs_cap, 0, (nc - g_hs_intro_ctxs_cap) * sizeof(*tmp));
                    for (int r = 0; r < g_num_hs_intro_ctxs; r++) {
                        if (tmp[r].conn && tmp[r].conn->fd >= 0)
                            moor_event_add(tmp[r].conn->fd, MOOR_EVENT_READ,
                                           hs_intro_read_cb, &tmp[r]);
                    }
                    g_hs_intro_ctxs = tmp;
                    g_hs_intro_ctxs_cap = nc;
                }
                int idx = g_num_hs_intro_ctxs++;
                g_hs_intro_ctxs[idx].config = &g_hs_configs[h];
                g_hs_intro_ctxs[idx].conn = circ->conn;
                moor_event_add(circ->conn->fd, MOOR_EVENT_READ,
                               hs_intro_read_cb, &g_hs_intro_ctxs[idx]);
                LOG_INFO("HS: registered intro circuit %d fd=%d for events",
                         i, circ->conn->fd);
            }
        }

        printf("Hidden service %d address: %s\n", h, hs_config.moor_address);
    }

    /* After init (which does DHT publish synchronously before the event
     * loop starts), set skip_dht_publish so periodic republish only does
     * the fast DA publish.  DHT publish builds synchronous circuits to
     * 6 relays, blocking the event loop for 20-30s and killing all intro
     * and RP circuits via connection timeout. */
    for (int h = 0; h < hs_count; h++)
        g_hs_configs[h].skip_dht_publish = 1;

    /* R10-CC3: Register periodic timers for HS maintenance */
    if (moor_event_add_timer(10 * 60 * 1000, hs_consensus_refresh_cb, NULL) < 0 ||
        moor_event_add_timer(5 * 60 * 1000, hs_blinded_key_rotation_cb, NULL) < 0 ||
        moor_event_add_timer(30 * 1000, hs_intro_rotation_cb, NULL) < 0 ||
        moor_event_add_timer(45 * 1000, hs_intro_padding_cb, NULL) < 0 ||
        moor_event_add_timer(5 * 60 * 1000, hs_desc_republish_cb, NULL) < 0) {
        LOG_ERROR("FATAL: failed to register HS timers");
        return -1;
    }

#ifndef _WIN32
    if (maybe_drop_privileges() != 0) return -1;
#endif
    moor_sandbox_apply();
    return moor_event_loop();
}

/* BW event timer: fires every 1 second to send BW events to ctrl clients.
 * Fix #181: Removed moor_event_add_timer() — fire_timers() already re-arms
 * recurring timers by resetting next_fire. Re-adding from callback leaks
 * a new timer slot every invocation, exhausting MAX_TIMERS (32) in 32s. */
static void bw_event_timer_cb(void *arg) {
    (void)arg;
    moor_monitor_notify_bw();
}

static int run_ob(void) {
    moor_ob_config_t ob_config;
    memset(&ob_config, 0, sizeof(ob_config));
    snprintf(ob_config.hs_dir, sizeof(ob_config.hs_dir), "%s",
             g_config.num_hidden_services > 0 ?
             g_config.hidden_services[0].hs_dir : g_hs_dir);
    snprintf(ob_config.da_address, sizeof(ob_config.da_address), "%s", g_da_address);
    ob_config.da_port = g_da_port;
    ob_config.ob_port = g_config.ob_port > 0 ? g_config.ob_port : 9055;
    ob_config.pow_enabled = g_config.hs_pow;
    ob_config.pow_difficulty = g_config.hs_pow_difficulty > 0 ?
                                g_config.hs_pow_difficulty : 16;

    if (moor_ob_init(&ob_config) != 0) {
        LOG_ERROR("failed to initialize OnionBalance");
        return -1;
    }

    printf("OnionBalance master address: %s\n", ob_config.moor_address);
    printf("Listening for backend uploads on port %u\n", ob_config.ob_port);

    /* Listen for backend descriptor uploads */
    int listen_fd = moor_listen(g_bind_addr, ob_config.ob_port);
    if (listen_fd < 0) return -1;

    /* Simple accept loop: backend connects, sends "OB_DESC\n" + len(4) + data */
    LOG_INFO("OB master running on %s:%u", g_bind_addr, ob_config.ob_port);

    /* Periodic publish timer */
    /* For simplicity, use event loop with accept callback */
    /* For now, just return the event loop fd */
#ifndef _WIN32
    if (maybe_drop_privileges() != 0) return -1;
#endif
    moor_sandbox_apply();
    return moor_event_loop();
}

static int run_bridgedb(void) {
    moor_bridgedb_config_t bdb_config;
    memset(&bdb_config, 0, sizeof(bdb_config));
    snprintf(bdb_config.bind_addr, sizeof(bdb_config.bind_addr), "%s", g_bind_addr);
    bdb_config.http_port = g_config.bridgedb_port > 0 ? g_config.bridgedb_port : 8080;

    /* Load bridges from config file if specified */
    if (g_config.bridgedb_file[0]) {
        FILE *f = fopen(g_config.bridgedb_file, "r");
        if (!f) {
            LOG_ERROR("bridgedb: cannot open bridge file: %s", g_config.bridgedb_file);
            return -1;
        }
        char line[512];
        while (fgets(line, sizeof(line), f) &&
               bdb_config.num_bridges < MOOR_BRIDGEDB_MAX_BRIDGES) {
            /* Strip trailing newline */
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                line[--len] = '\0';
            if (len == 0 || line[0] == '#') continue;

            /* Parse: "transport addr:port fingerprint_hex" */
            moor_bridge_entry_t *b = &bdb_config.bridges[bdb_config.num_bridges];
            memset(b, 0, sizeof(*b));

            char *s1 = strchr(line, ' ');
            if (!s1) continue;
            *s1 = '\0'; s1++;
            while (*s1 == ' ') s1++;

            char *s2 = strchr(s1, ' ');
            if (!s2) continue;
            *s2 = '\0'; s2++;
            while (*s2 == ' ') s2++;

            /* Transport */
            snprintf(b->transport, sizeof(b->transport), "%s", line);

            /* addr:port */
            char *colon = strrchr(s1, ':');
            if (!colon) continue;
            *colon = '\0';
            snprintf(b->address, sizeof(b->address), "%s", s1);
            long port_val = strtol(colon + 1, NULL, 10);
            if (port_val <= 0 || port_val > 65535) continue;
            b->port = (uint16_t)port_val;

            /* Hex fingerprint (64 hex chars) */
            if (strlen(s2) < 64) continue;
            int fp_ok = 1;
            for (int i = 0; i < 32; i++) {
                unsigned int byte_val;
                if (sscanf(s2 + i * 2, "%2x", &byte_val) != 1) {
                    fp_ok = 0;
                    break;
                }
                b->identity_pk[i] = (uint8_t)byte_val;
            }
            if (!fp_ok) continue; /* reject partial fingerprint */

            bdb_config.num_bridges++;
        }
        fclose(f);
    } else {
        /* Copy bridges from main config */
        for (int i = 0; i < g_config.num_bridges &&
             i < MOOR_MAX_BRIDGES && i < MOOR_BRIDGEDB_MAX_BRIDGES; i++) {
            bdb_config.bridges[i] = g_config.bridges[i];
            bdb_config.num_bridges++;
        }
    }

    if (bdb_config.num_bridges == 0) {
        LOG_ERROR("bridgedb: no bridges configured");
        return -1;
    }

    if (moor_bridgedb_init(&bdb_config) != 0) {
        LOG_ERROR("bridgedb: initialization failed");
        return -1;
    }

    printf("BridgeDB serving %d bridges on port %u\n",
           bdb_config.num_bridges, bdb_config.http_port);

#ifndef _WIN32
    if (maybe_drop_privileges() != 0) return -1;
#endif
    moor_sandbox_apply();
    return moor_bridgedb_run(&bdb_config);
}

extern volatile sig_atomic_t g_shutdown_requested;
extern volatile sig_atomic_t g_sighup_requested;

static char g_pid_file_path[256] = "";

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown_requested = 1;
}

#ifndef _WIN32
static void sighup_handler(int sig) {
    (void)sig;
    g_sighup_requested = 1;
}
#endif

/* Tor-aligned: SIGHUP reload handler (like Tor's do_hup()).
 * Called from the event loop when SIGHUP is received.
 * Reloads config file, refreshes consensus, re-registers relay. */
/* Tor-aligned: graceful shutdown.  Called from event loop epilogue before
 * the process exits.  Sends DESTROY cells for relay circuits so peers
 * clean up immediately instead of waiting for TCP timeout.
 * Client circuits are NOT destroyed (same as Tor — client_mode doesn't
 * send DESTROY, relies on TCP RST). */
void moor_graceful_shutdown(void) {
    LOG_INFO("graceful shutdown: closing relay circuits");

    /* Send DESTROY for all relay-side circuits */
    for (int i = 0; i < moor_circuit_iter_count(); i++) {
        moor_circuit_t *circ = moor_circuit_iter_get(i);
        if (!circ || circ->circuit_id == 0) continue;
        if (circ->is_client) continue; /* Tor: clients don't send DESTROY on exit */

        moor_cell_t dcell;
        memset(&dcell, 0, sizeof(dcell));
        dcell.circuit_id = circ->circuit_id;
        dcell.command = CELL_DESTROY;
        dcell.payload[0] = 1; /* DESTROY_REASON_REQUESTED */

        if (circ->prev_conn && circ->prev_conn->state == CONN_STATE_OPEN)
            moor_connection_send_cell(circ->prev_conn, &dcell);
        if (circ->next_conn && circ->next_conn->state == CONN_STATE_OPEN) {
            dcell.circuit_id = circ->next_circuit_id;
            moor_connection_send_cell(circ->next_conn, &dcell);
        }
    }

    /* Flush output queues for a brief window */
    extern void moor_connection_flush_all(void);
    moor_connection_flush_all();

    LOG_INFO("graceful shutdown complete");
}

void moor_handle_sighup(void) {
    LOG_INFO("SIGHUP received — reloading configuration");

    /* Reload config file if one was specified */
    extern char g_config_path[256];
    if (g_config_path[0]) {
        moor_config_t new_config;
        memset(&new_config, 0, sizeof(new_config));
        moor_config_defaults(&new_config);
        if (moor_config_load(&new_config, g_config_path) == 0) {
            /* Apply non-destructive config changes */
            g_config.verbose = new_config.verbose;
            /* Exit policy can be reloaded */
            if (new_config.exit_policy.num_rules > 0)
                memcpy(&g_config.exit_policy, &new_config.exit_policy,
                       sizeof(g_config.exit_policy));
            LOG_INFO("SIGHUP: config reloaded from %s", g_config_path);
        } else {
            LOG_WARN("SIGHUP: config reload failed, keeping current config");
        }
    }

    /* Re-register with DAs (relay mode) */
    extern moor_relay_config_t g_relay_cfg;
    extern int g_is_bridge;
    if (g_config.mode == MOOR_MODE_RELAY && !g_is_bridge) {
        moor_relay_register(&g_relay_cfg);
        LOG_INFO("SIGHUP: re-registered with DAs");
    }
}

/*
 * Emergency key wipe -- called from crash handler and normal shutdown.
 * Best-effort: if the heap is corrupted the sodium_memzero calls may
 * themselves fault, but SA_RESETHAND ensures we won't loop.
 */
static void emergency_wipe_keys(void) {
    /* Wipe small critical secrets first -- most likely to succeed if
     * the heap is partially corrupted during a crash. */
    sodium_memzero(g_identity_sk, sizeof(g_identity_sk));
    sodium_memzero(g_onion_sk, sizeof(g_onion_sk));
    sodium_memzero(&g_config.control_password,
                   sizeof(g_config.control_password));
    sodium_memzero(g_pq_identity_sk, sizeof(g_pq_identity_sk));
    /* Then wipe larger structs containing embedded key material */
    sodium_memzero(&g_da_config, sizeof(g_da_config));
    sodium_memzero(&g_relay_cfg, sizeof(g_relay_cfg));
    sodium_memzero(&g_scramble_server_params, sizeof(g_scramble_server_params));
    sodium_memzero(&g_mirage_server_params, sizeof(g_mirage_server_params));
    sodium_memzero(&g_shade_server_params, sizeof(g_shade_server_params));
    sodium_memzero(&g_shitstorm_server_params, sizeof(g_shitstorm_server_params));
    if (g_hs_configs) {
        for (int h = 0; h < g_num_hs_configs; h++)
            sodium_memzero(&g_hs_configs[h], sizeof(g_hs_configs[h]));
        free(g_hs_configs);
        g_hs_configs = NULL;
        g_num_hs_configs = 0;
    }
    free(g_hs_intro_ctxs);
    g_hs_intro_ctxs = NULL;
}

#ifndef _WIN32
/* Async-signal-safe hex printer */
static void write_hex(int fd, uintptr_t val) {
    char buf[18];
    int pos = sizeof(buf);
    buf[--pos] = '\0';
    if (val == 0) {
        buf[--pos] = '0';
    } else {
        while (val && pos > 0) {
            int nib = val & 0xf;
            buf[--pos] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
            val >>= 4;
        }
    }
    (void)!write(fd, "0x", 2);
    (void)!write(fd, buf + pos, sizeof(buf) - 1 - pos);
}

/* Async-signal-safe decimal printer */
static void write_dec(int fd, int val) {
    if (val < 0) { (void)!write(fd, "-", 1); val = -val; }
    char buf[12];
    int pos = sizeof(buf);
    buf[--pos] = '\0';
    if (val == 0) {
        buf[--pos] = '0';
    } else {
        while (val > 0 && pos > 0) {
            buf[--pos] = (char)('0' + (val % 10));
            val /= 10;
        }
    }
    (void)!write(fd, buf + pos, sizeof(buf) - 1 - pos);
}

/*
 * Crash handler for SIGSEGV, SIGBUS, SIGABRT.
 * Dumps everything useful, wipes keys, re-raises for core dump.
 * SA_RESETHAND prevents re-entry if the dump itself faults.
 *
 * All output uses write(2) — async-signal-safe.  No malloc, no stdio.
 */
static void crash_handler(int sig, siginfo_t *si, void *uctx) {
    /* Emergency key wipe first -- best-effort */
    emergency_wipe_keys();

    const char *name = "UNKNOWN";
    switch (sig) {
    case SIGSEGV: name = "SIGSEGV"; break;
    case SIGBUS:  name = "SIGBUS";  break;
    case SIGABRT: name = "SIGABRT"; break;
    }

    (void)!write(STDERR_FILENO,
        "\n========== MOOR CRASH DUMP ==========\n", 39);

    /* Signal name */
    (void)!write(STDERR_FILENO, "Signal: ", 8);
    (void)!write(STDERR_FILENO, name, strlen(name));
    (void)!write(STDERR_FILENO, "\n", 1);

    /* Faulting address */
    if (si) {
        (void)!write(STDERR_FILENO, "Fault addr: ", 12);
        write_hex(STDERR_FILENO, (uintptr_t)si->si_addr);
        if ((uintptr_t)si->si_addr < 4096) {
            (void)!write(STDERR_FILENO, "  ** NULL DEREF **", 18);
        }
        (void)!write(STDERR_FILENO, "\n", 1);
        (void)!write(STDERR_FILENO, "si_code: ", 9);
        write_dec(STDERR_FILENO, si->si_code);
        (void)!write(STDERR_FILENO, "\n", 1);
    }

    /* Register dump (x86_64) */
#if defined(__x86_64__) && defined(__linux__)
    if (uctx) {
        ucontext_t *ctx = (ucontext_t *)uctx;
        mcontext_t *mc = &ctx->uc_mcontext;
        (void)!write(STDERR_FILENO, "RIP: ", 5);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RIP]);
        (void)!write(STDERR_FILENO, "\nRSP: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RSP]);
        (void)!write(STDERR_FILENO, "\nRBP: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RBP]);
        (void)!write(STDERR_FILENO, "\nRAX: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RAX]);
        (void)!write(STDERR_FILENO, "\nRBX: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RBX]);
        (void)!write(STDERR_FILENO, "\nRCX: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RCX]);
        (void)!write(STDERR_FILENO, "\nRDX: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RDX]);
        (void)!write(STDERR_FILENO, "\nRDI: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RDI]);
        (void)!write(STDERR_FILENO, "\nRSI: ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_RSI]);
        (void)!write(STDERR_FILENO, "\nR8:  ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_R8]);
        (void)!write(STDERR_FILENO, "\nR9:  ", 6);
        write_hex(STDERR_FILENO, (uintptr_t)mc->gregs[REG_R9]);
        (void)!write(STDERR_FILENO, "\n", 1);
    }
#endif

    /* Backtrace via backtrace_symbols_fd — async-signal-safe on glibc */
    {
        void *frames[64];
        int depth = backtrace(frames, 64);
        (void)!write(STDERR_FILENO, "Backtrace (", 11);
        write_dec(STDERR_FILENO, depth);
        (void)!write(STDERR_FILENO, " frames):\n", 10);
        backtrace_symbols_fd(frames, depth, STDERR_FILENO);

        /* Resolve with addr2line for static function names + line numbers.
         * Not async-signal-safe but we're about to die anyway. */
        (void)!write(STDERR_FILENO,
            "\n--- addr2line (source locations) ---\n", 38);
        char exe_path[256];
        ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (exe_len > 0) {
            exe_path[exe_len] = '\0';
            for (int f = 0; f < depth; f++) {
                char cmd[512];
                int n = snprintf(cmd, sizeof(cmd),
                    "addr2line -e %s -f -C -p %p 2>/dev/null",
                    exe_path, frames[f]);
                if (n > 0 && n < (int)sizeof(cmd))
                    (void)!system(cmd);
            }
        }
    }

    /* Dump /proc/self/maps for addr2line resolution */
    {
        (void)!write(STDERR_FILENO,
            "\n--- /proc/self/maps (text segments) ---\n", 41);
        int maps_fd = open("/proc/self/maps", O_RDONLY);
        if (maps_fd >= 0) {
            char mbuf[4096];
            ssize_t n;
            while ((n = read(maps_fd, mbuf, sizeof(mbuf))) > 0)
                (void)!write(STDERR_FILENO, mbuf, n);
            close(maps_fd);
        }
    }

    (void)!write(STDERR_FILENO,
        "======== END CRASH DUMP (keys wiped) ========\n", 47);

    /* Restore default handler and re-raise for core dump */
    signal(sig, SIG_DFL);
    raise(sig);
}
#endif /* !_WIN32 */

#ifdef _WIN32
static LONG WINAPI moor_win32_crash_handler(EXCEPTION_POINTERS *ep) {
    /* Emergency key wipe before anything else */
    emergency_wipe_keys();

    DWORD code = ep->ExceptionRecord->ExceptionCode;
    void *addr = ep->ExceptionRecord->ExceptionAddress;
    const char *name = "UNKNOWN";
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:    name = "ACCESS_VIOLATION"; break;
    case EXCEPTION_STACK_OVERFLOW:      name = "STACK_OVERFLOW"; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:  name = "INT_DIVIDE_BY_ZERO"; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION: name = "ILLEGAL_INSTRUCTION"; break;
    }
    fprintf(stderr, "\n*** MOOR CRASH: %s (0x%08lX) at %p -- keys wiped ***\n",
            name, (unsigned long)code, addr);
    if (code == EXCEPTION_ACCESS_VIOLATION &&
        ep->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, "  %s address %p\n",
                ep->ExceptionRecord->ExceptionInformation[0] ? "writing" : "reading",
                (void *)(uintptr_t)ep->ExceptionRecord->ExceptionInformation[1]);
    }
#if defined(__x86_64__) || defined(_M_X64)
    CONTEXT *ctx = ep->ContextRecord;
    fprintf(stderr, "  RIP=%p RSP=%p RBP=%p\n",
            (void *)ctx->Rip, (void *)ctx->Rsp, (void *)ctx->Rbp);
#endif
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

#ifndef _WIN32
static int write_pid_file(const char *path) {
    /* Use O_NOFOLLOW to prevent symlink attacks (CWE-61) */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        LOG_ERROR("cannot write PID file: %s", path);
        return -1;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) {
        LOG_ERROR("fdopen failed for PID file: %s", path);
        close(fd);
        return -1;
    }
    fprintf(f, "%ld\n", (long)getpid());
    fclose(f);
    return 0;
}

static int daemonize(const char *pid_file) {
    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERROR("fork() failed");
        return -1;
    }
    if (pid > 0)
        _exit(0); /* parent exits */

    /* Child: new session */
    if (setsid() < 0) {
        LOG_ERROR("setsid() failed");
        return -1;
    }

    /* Second fork to prevent controlling terminal acquisition */
    pid = fork();
    if (pid < 0) {
        LOG_ERROR("second fork() failed");
        return -1;
    }
    if (pid > 0)
        _exit(0);

    /* Redirect stdin/stdout/stderr to /dev/null */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2)
            close(devnull);
    }

    /* Write PID file */
    if (pid_file && pid_file[0]) {
        if (write_pid_file(pid_file) != 0)
            return -1;
        snprintf(g_pid_file_path, sizeof(g_pid_file_path), "%s", pid_file);
    }

    return 0;
}

/* Drop privileges to unprivileged user after sockets are bound.
 * Must be called while still running as root. */
static int drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        LOG_ERROR("--User: unknown user '%s'", username);
        return -1;
    }
    /* Copy uid/gid to locals before any calls that may invalidate pw
     * (TOCTOU: getpwnam returns a static buffer that initgroups may overwrite) */
    uid_t uid = pw->pw_uid;
    gid_t gid = pw->pw_gid;
    if (setgid(gid) != 0) {
        LOG_ERROR("--User: setgid(%u) failed: %s",
                  (unsigned)gid, strerror(errno));
        return -1;
    }
    /* Drop supplementary groups */
    if (initgroups(username, gid) != 0) {
        LOG_WARN("--User: initgroups() failed: %s", strerror(errno));
        /* Non-fatal: proceed with primary group only */
    }
    if (setuid(uid) != 0) {
        LOG_ERROR("--User: setuid(%u) failed: %s",
                  (unsigned)uid, strerror(errno));
        return -1;
    }
    /* Verify we cannot regain root */
    if (setuid(0) == 0) {
        LOG_ERROR("--User: privilege drop failed — still able to regain root");
        return -1;
    }
    LOG_INFO("dropped privileges to user '%s' (uid=%u gid=%u)",
             username, (unsigned)uid, (unsigned)gid);
    return 0;
}

/* Called by each run_* function after sockets are bound, before event loop.
 * Drops privileges if --User was specified; warns if running as root without it. */
static int maybe_drop_privileges(void) {
    if (g_run_as_user[0]) {
        if (drop_privileges(g_run_as_user) != 0)
            return -1;
    } else if (getuid() == 0) {
        LOG_WARN("running as root without --User; consider dropping privileges");
    }
    return 0;
}
#endif /* !_WIN32 */

/* Generate DA keys for a new enclave.  Prints enclave file entry and
 * saves private keys to the specified data directory. */
static int keygen_enclave(const char *data_dir, const char *address,
                          uint16_t port) {
    if (moor_crypto_init() != 0) {
        fprintf(stderr, "FATAL: crypto init failed\n");
        return 1;
    }

    /* Ensure data dir exists */
    char keys_dir[512];
    snprintf(keys_dir, sizeof(keys_dir), "%s/keys", data_dir);
#ifndef _WIN32
    mkdir(data_dir, 0700);
    mkdir(keys_dir, 0700);
#endif

    /* Generate Ed25519 identity keypair (signing) */
    uint8_t pk[32], sk[64];
    moor_crypto_sign_keygen(pk, sk);

    /* Generate Curve25519 onion keypair (DH/key exchange) — separate type */
    uint8_t onion_pk[32], onion_sk[32];
    moor_crypto_box_keygen(onion_pk, onion_sk);

    /* Generate ML-DSA-65 PQ identity keypair */
    uint8_t pq_pk[MOOR_MLDSA_PK_LEN], pq_sk[MOOR_MLDSA_SK_LEN];
    int has_pq = (moor_mldsa_keygen(pq_pk, pq_sk) == 0);

    /* Save keys — identity (Ed25519) and onion (Curve25519) are distinct */
    if (moor_keys_save(data_dir, pk, sk, onion_pk, onion_sk) != 0) {
        fprintf(stderr, "ERROR: failed to save keys to %s\n", data_dir);
        return 1;
    }
    if (has_pq && moor_pq_keys_save(data_dir, pq_pk, pq_sk) != 0) {
        fprintf(stderr, "WARNING: failed to save PQ keys\n");
    }

    /* Print hex public key */
    char hex_pk[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex_pk + i * 2, 3, "%02x", pk[i]);

    /* Print enclave file entry */
    fprintf(stdout,
        "# MOOR Enclave — DA key generated\n"
        "#\n"
        "# Add this line to your .enclave file:\n"
        "%s:%u %s\n"
        "#\n"
        "# Keys saved to: %s\n"
        "# Ed25519 identity:  %s\n",
        address, port, hex_pk,
        data_dir, hex_pk);

    if (has_pq) {
        char hex_pq[20];
        for (int i = 0; i < 8; i++)
            snprintf(hex_pq + i * 2, 3, "%02x", pq_pk[i]);
        fprintf(stdout, "# ML-DSA-65 PQ key:  %s... (%d bytes)\n",
                hex_pq, MOOR_MLDSA_PK_LEN);
    }

    fprintf(stdout,
        "#\n"
        "# To create a complete enclave, generate keys on each DA host,\n"
        "# then combine all lines into one .enclave file.\n"
        "# All nodes (clients, relays, DAs) use: --enclave mynetwork.enclave\n");

    /* Wipe secret keys from memory */
    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(onion_sk, sizeof(onion_sk));
    sodium_memzero(pq_sk, sizeof(pq_sk));
    return 0;
}

int main(int argc, char **argv) {
    /* 0. Check for --keygen-enclave (early exit, no config needed) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--keygen-enclave") == 0) {
            const char *data_dir = "/var/lib/moor";
            const char *address = "0.0.0.0";
            uint16_t port = MOOR_DEFAULT_DIR_PORT;
            for (int j = i + 1; j < argc; j++) {
                if (strcmp(argv[j], "--data-dir") == 0 && j + 1 < argc)
                    data_dir = argv[++j];
                else if (strcmp(argv[j], "--advertise") == 0 && j + 1 < argc)
                    address = argv[++j];
                else if (strcmp(argv[j], "--dir-port") == 0 && j + 1 < argc)
                    port = (uint16_t)atoi(argv[++j]);
            }
            return keygen_enclave(data_dir, address, port);
        }
    }

    /* 1. Fill config with defaults */
    moor_config_defaults(&g_config);

    /* 2. Auto-discover config: --config flag, ./moor.conf, or SYSCONFDIR */
    int have_explicit_config = 0;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-f") == 0) &&
            i + 1 < argc) {
            have_explicit_config = 1;
            snprintf(g_config_path, sizeof(g_config_path), "%s", argv[i + 1]);
            if (moor_config_load(&g_config, argv[i + 1]) != 0) {
                fprintf(stderr, "FATAL: failed to load config file: %s\n",
                        argv[i + 1]);
                return 1;
            }
            break;
        }
    }
    if (!have_explicit_config) {
        /* Auto-discover config: try moorrc, moor.conf, then SYSCONFDIR.
         * Like Tor: tries ./torrc → /etc/tor/torrc → SYSCONFDIR/torrc */
        static const char *config_search[] = {
            "moorrc", "moor.conf",
            MOOR_SYSCONFDIR "/moorrc",
            MOOR_SYSCONFDIR "/moor.conf",
            NULL
        };
        FILE *f = NULL;
        const char *found_config = NULL;
        for (const char **p = config_search; *p; p++) {
            f = fopen(*p, "r");
            if (f) { found_config = *p; fclose(f); break; }
        }
        if (found_config) {
            snprintf(g_config_path, sizeof(g_config_path), "%s", found_config);
            if (moor_config_load(&g_config, found_config) != 0) {
                fprintf(stderr, "FATAL: failed to parse %s\n", found_config);
                return 1;
            }
        } else {
            /* Try SYSCONFDIR/moor.conf if installed (legacy path) */
            f = fopen(MOOR_SYSCONFDIR "/moor.conf", "r");
            if (f) {
                fclose(f);
                if (moor_config_load(&g_config, MOOR_SYSCONFDIR "/moor.conf") != 0) {
                    fprintf(stderr, "FATAL: failed to parse " MOOR_SYSCONFDIR "/moor.conf\n");
                    return 1;
                }
            }
        }
    }

    /* 3. CLI args override config file values */
    parse_args_into_config(&g_config, argc, argv);

    /* With no args and no config file, start as client (like Tor).
     * Default config: client mode, SOCKS5 on 9050, DA at 107.174.70.38. */

    /* 3b. Load enclave file if specified (replaces hardcoded DA list) */
    if (g_config.enclave_file[0]) {
        if (moor_enclave_load(&g_config, g_config.enclave_file) != 0) {
            fprintf(stderr, "FATAL: failed to load enclave file: %s\n",
                    g_config.enclave_file);
            return 1;
        }
    }

    /* 4. Validate and apply config */
    if (moor_config_validate(&g_config) != 0) {
        fprintf(stderr, "FATAL: invalid configuration\n");
        return 1;
    }
    apply_config_to_globals(&g_config);

    if (g_verbose) {
        moor_log_set_level(MOOR_LOG_DEBUG);
        moor_log_set_safe_mode(1);
        fprintf(stderr,
            "\n"
            "  *** WARNING: VERBOSE LOGGING ENABLED ***\n"
            "  IP addresses and key material are always redacted.\n"
            "  DO NOT use -v in production.\n"
            "\n");
    }

    /* Init crypto */
    if (moor_crypto_init() != 0) {
        fprintf(stderr, "FATAL: crypto init failed\n");
        return 1;
    }

    /* Platform hardening: lock memory, prevent core dumps */
#if !defined(_WIN32) && defined(__linux__)
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        /* Non-root can't mlockall -- try raising soft memlock limit */
        struct rlimit rl;
        if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
            rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_MEMLOCK, &rl);
            mlockall(MCL_CURRENT | MCL_FUTURE); /* best-effort retry */
        }
        /* Not a warning -- running as non-root is correct */
        LOG_DEBUG("mlockall unavailable (not root) -- using madvise for key pages");
    }
    prctl(PR_SET_DUMPABLE, 0); /* prevent ptrace/core dumps */
#endif

    /* Load persistent keys for relay/DA, or generate ephemeral */
    if (g_data_dir[0] && (g_mode == MOOR_MODE_RELAY || g_mode == MOOR_MODE_DA)) {
        if (moor_keys_load(g_data_dir, g_identity_pk, g_identity_sk,
                           g_onion_pk, g_onion_sk) == 0) {
            /* Override onion key with identity-derived Curve25519 so
             * bridge clients can compute the matching CKE DH key from
             * just the Ed25519 identity_pk in the bridge line. */
            moor_crypto_ed25519_to_curve25519_pk(g_onion_pk, g_identity_pk);
            moor_crypto_ed25519_to_curve25519_sk(g_onion_sk, g_identity_sk);
            LOG_INFO("loaded persistent identity keys from %s", g_data_dir);
        } else {
            moor_crypto_sign_keygen(g_identity_pk, g_identity_sk);
            /* Derive onion key from identity key so bridge clients
             * (who only have the identity_pk) can compute the same
             * Curve25519 key for CKE DH. A separate onion keypair
             * would be unreachable by bridge clients. */
            moor_crypto_ed25519_to_curve25519_pk(g_onion_pk, g_identity_pk);
            moor_crypto_ed25519_to_curve25519_sk(g_onion_sk, g_identity_sk);
            if (moor_keys_save(g_data_dir, g_identity_pk, g_identity_sk,
                               g_onion_pk, g_onion_sk) == 0) {
                LOG_INFO("generated and saved persistent keys to %s", g_data_dir);
            } else {
                LOG_WARN("generated keys but failed to save to %s", g_data_dir);
            }
        }

        /* PQ keys for DA mode: load or generate ML-DSA-65 keypair */
        if (g_mode == MOOR_MODE_DA) {
            if (moor_pq_keys_load(g_data_dir, g_pq_identity_pk,
                                  g_pq_identity_sk) == 0) {
                LOG_INFO("loaded persistent ML-DSA-65 keys from %s", g_data_dir);
            } else {
                if (moor_mldsa_keygen(g_pq_identity_pk, g_pq_identity_sk) == 0) {
                    if (moor_pq_keys_save(g_data_dir, g_pq_identity_pk,
                                          g_pq_identity_sk) == 0) {
                        LOG_INFO("generated and saved ML-DSA-65 keys to %s",
                                 g_data_dir);
                    } else {
                        LOG_WARN("generated ML-DSA-65 keys but failed to save");
                    }
                } else {
                    LOG_WARN("ML-DSA-65 keygen failed, DA will use Ed25519-only");
                }
            }
        }
    } else {
        moor_crypto_sign_keygen(g_identity_pk, g_identity_sk);
        moor_crypto_box_keygen(g_onion_pk, g_onion_sk);
    }

    /* Daemonize if requested (before entering event loop) */
#ifndef _WIN32
    if (g_config.daemon_mode) {
        if (daemonize(g_config.pid_file) != 0) {
            fprintf(stderr, "FATAL: failed to daemonize\n");
            return 1;
        }
    }
#endif

    moor_bootstrap_report(BOOT_STARTING);

    /* ---- Startup Banner ---- */
    {
        const char *mode_str =
            g_mode == MOOR_MODE_CLIENT ? "client" :
            g_mode == MOOR_MODE_RELAY  ? "relay" :
            g_mode == MOOR_MODE_DA     ? "directory authority" :
            g_mode == MOOR_MODE_OB     ? "onionbalance" :
            g_mode == MOOR_MODE_BRIDGEDB ? "bridgedb" : "hidden service";

        fprintf(stderr,
            "\n"
            "\033[36m====================================================================\033[0m\n"
            "\033[36m                 ███╗   ███╗ ██████╗  ██████╗ ██████╗ \033[0m\n"
            "\033[36m                 ████╗ ████║██╔═══██╗██╔═══██╗██╔══██╗\033[0m\n"
            "\033[36m                 ██╔████╔██║██║   ██║██║   ██║██████╔╝\033[0m\n"
            "\033[36m                 ██║╚██╔╝██║██║   ██║██║   ██║██╔══██╗\033[0m\n"
            "\033[36m                 ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║  ██║\033[0m\n"
            "\033[36m                 ╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝\033[0m \033[1mv%s\033[0m\n"
            "\n"
            "                \033[1mM Y   O W N   O N I O N   R O U T E R\033[0m\n"
            "                       \033[90mPQ SECURE OVERLAY NETWORK\033[0m\n"
            "\n"
            "\033[36m--------------------------------------------------------------------\033[0m\n"
            "\n"
            "        \033[33m>>>   PRIVACY IS A RIGHT, NOT A FEATURE   <<<\033[0m\n"
            "        \033[33m>>>     TRUSTLESS • STATELESS • SILENT     <<<\033[0m\n"
            "\n"
            "\033[36m--------------------------------------------------------------------\033[0m\n"
            "\033[36m====================================================================\033[0m\n"
            "\n",
            MOOR_VERSION_STRING);

        struct utsname uts;
        const char *os = "unknown";
        if (uname(&uts) == 0) os = uts.sysname;

        LOG_INFO("MOOR v%s running on %s with libsodium %s",
                 MOOR_VERSION_STRING, os, sodium_version_string());
        LOG_INFO("Operating in %s mode (PID %d)", mode_str, (int)getpid());

        if (g_mode == MOOR_MODE_CLIENT)
            LOG_INFO("SOCKS5 proxy on %s:%u", g_bind_addr, g_socks_port);
        else if (g_mode == MOOR_MODE_RELAY && g_config.nickname[0])
            LOG_INFO("Relay nickname: %s", g_config.nickname);
    }

    /* Register transports */
    moor_transport_register(&moor_scramble_transport);
    moor_transport_register(&moor_mirage_transport);
    moor_transport_register(&moor_shade_transport);
    moor_transport_register(&moor_shitstorm_transport);
    moor_transport_register(&moor_speakeasy_transport);
    moor_transport_register(&moor_nether_transport);

    /* PQ hybrid always enabled -- Kyber768 + Noise_IK mandatory */

    /* Set up scramble server params for bridge mode */
    memcpy(g_scramble_server_params.identity_pk, g_identity_pk, 32);
    memcpy(g_scramble_server_params.identity_sk, g_identity_sk, 64);

    /* Shade server params: derive Curve25519 from Ed25519 */
    memcpy(g_shade_server_params.node_id, g_identity_pk, 32);
    if (crypto_sign_ed25519_pk_to_curve25519(g_shade_server_params.server_pk,
                                              g_identity_pk) != 0)
        LOG_WARN("shade: Ed25519->Curve25519 pk conversion failed");
    if (crypto_sign_ed25519_sk_to_curve25519(g_shade_server_params.server_sk,
                                              g_identity_sk) != 0)
        LOG_WARN("shade: Ed25519->Curve25519 sk conversion failed");
    g_shade_server_params.iat_mode = MOOR_SHADE_IAT_NONE;

    /* Mirage: identity keys for probing defense + MITM resistance */
    memset(&g_mirage_server_params, 0, sizeof(g_mirage_server_params));
    memcpy(g_mirage_server_params.identity_pk, g_identity_pk, 32);
    memcpy(g_mirage_server_params.identity_sk, g_identity_sk, 64);

    /* ShitStorm: same identity keys (combines all transport features) */
    memset(&g_shitstorm_server_params, 0, sizeof(g_shitstorm_server_params));
    memcpy(g_shitstorm_server_params.identity_pk, g_identity_pk, 32);
    memcpy(g_shitstorm_server_params.identity_sk, g_identity_sk, 64);
    memset(&g_speakeasy_server_params, 0, sizeof(g_speakeasy_server_params));
    memcpy(g_speakeasy_server_params.identity_pk, g_identity_pk, 32);
    memcpy(g_speakeasy_server_params.identity_sk, g_identity_sk, 64);
    memset(&g_nether_server_params, 0, sizeof(g_nether_server_params));
    memcpy(g_nether_server_params.identity_pk, g_identity_pk, 32);
    memcpy(g_nether_server_params.identity_sk, g_identity_sk, 64);

    /* Init subsystems */
    moor_event_init();
    moor_connection_init_pool();
    moor_circuit_init_pool();
    moor_channel_init();
    moor_kist_init();

    /* Load GeoIP databases: try explicit path, then default locations */
    {
        /* Build user-local paths: ~/.moor/geoip, ~/.moor/geoip6 */
        char user_geoip4[512] = "", user_geoip6[512] = "";
        {
            const char *home = getenv("HOME");
            if (home) {
                snprintf(user_geoip4, sizeof(user_geoip4), "%s/.moor/geoip", home);
                snprintf(user_geoip6, sizeof(user_geoip6), "%s/.moor/geoip6", home);
            }
        }
        const char *geoip4_defaults[] = {
            MOOR_SYSCONFDIR "/geoip",
            "/usr/share/moor/geoip",
            "/usr/local/share/moor/geoip",
            user_geoip4[0] ? user_geoip4 : NULL,
            NULL
        };
        const char *geoip6_defaults[] = {
            MOOR_SYSCONFDIR "/geoip6",
            "/usr/share/moor/geoip6",
            "/usr/local/share/moor/geoip6",
            user_geoip6[0] ? user_geoip6 : NULL,
            NULL
        };
        /* IPv4: use explicit path or probe defaults */
        if (g_geoip_file[0]) {
            if (moor_geoip_load(&g_geoip_db, g_geoip_file) == 0)
                LOG_INFO("GeoIP: loaded %d IPv4 entries from %s",
                         g_geoip_db.num_entries, g_geoip_file);
            else
                LOG_WARN("GeoIP: failed to load %s", g_geoip_file);
        } else {
            for (const char **p = geoip4_defaults; *p; p++) {
                if (moor_geoip_load(&g_geoip_db, *p) == 0) {
                    LOG_INFO("GeoIP: loaded %d IPv4 entries from %s",
                             g_geoip_db.num_entries, *p);
                    break;
                }
            }
        }
        /* IPv6: use explicit path or probe defaults */
        if (g_geoip6_file[0]) {
            if (moor_geoip_load6(&g_geoip_db, g_geoip6_file) == 0)
                LOG_INFO("GeoIP: loaded %d IPv6 entries from %s",
                         g_geoip_db.num_entries6, g_geoip6_file);
            else
                LOG_WARN("GeoIP: failed to load %s", g_geoip6_file);
        } else {
            for (const char **p = geoip6_defaults; *p; p++) {
                if (moor_geoip_load6(&g_geoip_db, *p) == 0) {
                    LOG_INFO("GeoIP: loaded %d IPv6 entries from %s",
                             g_geoip_db.num_entries6, *p);
                    break;
                }
            }
        }
    }
    if (g_geoip_db.num_entries > 0 || g_geoip_db.num_entries6 > 0) {
        moor_circuit_set_geoip(&g_geoip_db);
        moor_da_set_geoip(&g_geoip_db);
        LOG_INFO("GeoIP: path diversity enabled (%d v4 + %d v6 entries)",
                 g_geoip_db.num_entries, g_geoip_db.num_entries6);
    }

    /* Handle signals */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, sighup_handler);

    /* Enable core dumps (crash handler re-raises for core) */
    {
        struct rlimit rl;
        rl.rlim_cur = RLIM_INFINITY;
        rl.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_CORE, &rl);
    }

    /* Install crash handler for fatal signals -- wipes keys before core dump.
     * SA_SIGINFO gives us the faulting address.
     * SA_RESETHAND prevents re-entry if the wipe itself faults. */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = crash_handler;
        sa.sa_flags = SA_RESETHAND | SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGABRT, &sa, NULL);
    }
#endif

#ifdef _WIN32
    /* Install crash handler to catch access violations */
    SetUnhandledExceptionFilter(moor_win32_crash_handler);
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "FATAL: WSAStartup failed\n");
        return 1;
    }
#endif

    int ret;
    switch (g_mode) {
    case MOOR_MODE_DA:
        ret = run_da();
        break;
    case MOOR_MODE_RELAY:
        ret = run_relay();
        break;
    case MOOR_MODE_CLIENT:
        ret = run_client();
        break;
    case MOOR_MODE_HS:
        ret = run_hs();
        break;
    case MOOR_MODE_OB:
        ret = run_ob();
        break;
    case MOOR_MODE_BRIDGEDB:
        ret = run_bridgedb();
        break;
    case MOOR_MODE_BRIDGE_AUTH:
        LOG_ERROR("bridge_auth mode is not yet implemented");
        ret = -1;
        break;
    default:
        ret = -1;
    }

    /* Remove PID file */
    if (g_pid_file_path[0])
        unlink(g_pid_file_path);

    /* moor_graceful_shutdown() is called from event loop epilogue */

    /* Save guard state before shutdown (Tor-aligned: save on exit) */
    if (g_data_dir[0])
        moor_guard_save(moor_pathbias_get_state(), g_data_dir);

    /* Cleanup -- wipe all secret keys (globals + copies in sub-configs) */
    emergency_wipe_keys();
    moor_monitor_cleanup();

#ifdef _WIN32
    WSACleanup();
#endif

    return (ret == 0) ? 0 : 1;
}
