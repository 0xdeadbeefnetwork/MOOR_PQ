# Include config.mk from ./configure (if it exists)
-include config.mk

# Fallback defaults (backward compat when building without ./configure)
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
SYSCONFDIR ?= $(PREFIX)/etc
CC ?= gcc
SODIUM_CFLAGS ?= $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS ?= $(shell pkg-config --libs libsodium 2>/dev/null || echo -lsodium)
LIBEVENT_CFLAGS ?= $(shell pkg-config --cflags libevent 2>/dev/null)
LIBEVENT_LIBS ?= $(shell pkg-config --libs libevent 2>/dev/null || echo -levent)
ZLIB_CFLAGS ?=
ZLIB_LIBS ?= -lz
EXTRA_CFLAGS ?=
EXTRA_LDFLAGS ?=

CFLAGS = -Wall -Wextra -O2 -g3 -fno-strict-aliasing -fstack-protector-strong \
         -fno-omit-frame-pointer \
         -D_FORTIFY_SOURCE=2 -Iinclude -Isrc/kyber -Isrc/dilithium \
         -fPIE -Wformat -Wformat-security \
         -DMOOR_SYSCONFDIR='"$(SYSCONFDIR)/moor"' \
         $(SODIUM_CFLAGS) $(LIBEVENT_CFLAGS) $(ZLIB_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS = -pie -Wl,-z,relro,-z,now -rdynamic \
          $(SODIUM_LIBS) $(LIBEVENT_LIBS) -lm -lpthread $(ZLIB_LIBS) $(EXTRA_LDFLAGS)

# Windows/MSYS2 needs winsock
UNAME := $(shell uname -s)
ifneq (,$(findstring MSYS,$(UNAME)))
    LDFLAGS += -lws2_32
endif
ifneq (,$(findstring MINGW,$(UNAME)))
    LDFLAGS += -lws2_32
endif

SRCDIR = src
OBJDIR = obj
BUILDDIR = .

SOURCES = $(SRCDIR)/log.c \
          $(SRCDIR)/build_id.c \
          $(SRCDIR)/crypto.c \
          $(SRCDIR)/cell.c \
          $(SRCDIR)/event.c \
          $(SRCDIR)/connection.c \
          $(SRCDIR)/channel.c \
          $(SRCDIR)/node.c \
          $(SRCDIR)/circuit.c \
          $(SRCDIR)/relay.c \
          $(SRCDIR)/directory.c \
          $(SRCDIR)/socks5.c \
          $(SRCDIR)/hidden_service.c \
          $(SRCDIR)/config.c \
          $(SRCDIR)/transport.c \
          $(SRCDIR)/transport_scramble.c \
          $(SRCDIR)/kem.c \
          $(SRCDIR)/fragment.c \
          $(SRCDIR)/pow.c \
          $(SRCDIR)/geoip.c \
          $(SRCDIR)/bw_auth.c \
          $(SRCDIR)/conflux.c \
          $(SRCDIR)/ratelimit.c \
          $(SRCDIR)/scheduler.c \
          $(SRCDIR)/monitor.c \
          $(SRCDIR)/onionbalance.c \
          $(SRCDIR)/bridgedb.c \
          $(SRCDIR)/dns_cache.c \
          $(SRCDIR)/bootstrap.c \
          $(SRCDIR)/transparent.c \
          $(SRCDIR)/addressmap.c \
          $(SRCDIR)/transport_shade.c \
          $(SRCDIR)/bridge_auth.c \
          $(SRCDIR)/exit_sla.c \
          $(SRCDIR)/transport_mirage.c \
          $(SRCDIR)/transport_shitstorm.c \
          $(SRCDIR)/transport_speakeasy.c \
          $(SRCDIR)/transport_nether.c \
          $(SRCDIR)/dht.c \
          $(SRCDIR)/sig.c \
          $(SRCDIR)/mix.c \
          $(SRCDIR)/wfpad.c \
          $(SRCDIR)/sandbox.c \
          $(SRCDIR)/elligator2.c \
          $(SRCDIR)/dns_server.c \
          $(SRCDIR)/exit_notice.c

KYBER_SOURCES = $(wildcard $(SRCDIR)/kyber/*.c)
DILITHIUM_SOURCES = $(wildcard $(SRCDIR)/dilithium/*.c)

MAIN_SRC = $(SRCDIR)/main.c
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
KYBER_OBJECTS = $(patsubst $(SRCDIR)/kyber/%.c,$(OBJDIR)/kyber/%.o,$(KYBER_SOURCES))
DILITHIUM_OBJECTS = $(patsubst $(SRCDIR)/dilithium/%.c,$(OBJDIR)/dilithium/%.o,$(DILITHIUM_SOURCES))
MAIN_OBJ = $(OBJDIR)/main.o

ALL_OBJECTS = $(OBJECTS) $(KYBER_OBJECTS) $(DILITHIUM_OBJECTS)

TARGET = $(BUILDDIR)/moor

# Tools
KEYGEN_SRC = tools/moor_keygen.c
KEYGEN_TARGET = $(BUILDDIR)/moor_keygen
MOOR_TOP_SRC = tools/moor-top.c
MOOR_TOP_TARGET = $(BUILDDIR)/moor-top
NCURSES_CFLAGS = $(shell pkg-config --cflags ncurses 2>/dev/null)
NCURSES_LIBS = $(shell pkg-config --libs ncurses 2>/dev/null || echo -lncurses)

# Tests
TEST_CRYPTO_SRC = tests/test_crypto.c
TEST_CELL_SRC = tests/test_cell.c
TEST_CIRCUIT_SRC = tests/test_circuit.c
TEST_CONFIG_SRC = tests/test_config.c
TEST_TRANSPORT_SRC = tests/test_transport.c
TEST_KEM_SRC = tests/test_kem.c
TEST_FRAGMENT_SRC = tests/test_fragment.c
TEST_PQ_CIRCUIT_SRC = tests/test_pq_circuit.c
TEST_POW_SRC = tests/test_pow.c
TEST_GEOIP_SRC = tests/test_geoip.c
TEST_BW_AUTH_SRC = tests/test_bw_auth.c
TEST_CONFLUX_SRC = tests/test_conflux.c
TEST_RATELIMIT_SRC = tests/test_ratelimit.c
TEST_CONSENSUS_CACHE_SRC = tests/test_consensus_cache.c
TEST_SCHEDULER_SRC = tests/test_scheduler.c
TEST_MONITOR_SRC = tests/test_monitor.c
TEST_CKE_SRC = tests/test_cke.c
TEST_NOISE_SRC = tests/test_noise.c
TEST_OB_SRC = tests/test_onionbalance.c
TEST_BRIDGEDB_SRC = tests/test_bridgedb.c
TEST_SOCKS_SRC = tests/test_socks.c
TEST_DNS_CACHE_SRC = tests/test_dns_cache.c
TEST_SHADE_SRC = tests/test_shade.c
TEST_BRIDGE_AUTH_SRC = tests/test_bridge_auth.c
TEST_EXIT_SLA_SRC = tests/test_exit_sla.c
TEST_CC_SRC = tests/test_cc.c
TEST_FEATURES2_SRC = tests/test_features2.c
TEST_INFRA_SRC = tests/test_infra.c
TEST_DHT_SRC = tests/test_dht.c
TEST_MLDSA_SRC = tests/test_mldsa.c
TEST_PATHBIAS_SRC = tests/test_pathbias.c
TEST_KYBER_KAT_SRC = tests/test_kyber_kat.c
TEST_MLDSA_KAT_SRC = tests/test_mldsa_kat.c
TEST_CRYPTO_TARGET = $(BUILDDIR)/test_crypto
TEST_CELL_TARGET = $(BUILDDIR)/test_cell
TEST_CIRCUIT_TARGET = $(BUILDDIR)/test_circuit
TEST_CONFIG_TARGET = $(BUILDDIR)/test_config
TEST_TRANSPORT_TARGET = $(BUILDDIR)/test_transport
TEST_KEM_TARGET = $(BUILDDIR)/test_kem
TEST_FRAGMENT_TARGET = $(BUILDDIR)/test_fragment
TEST_PQ_CIRCUIT_TARGET = $(BUILDDIR)/test_pq_circuit
TEST_POW_TARGET = $(BUILDDIR)/test_pow
TEST_GEOIP_TARGET = $(BUILDDIR)/test_geoip
TEST_BW_AUTH_TARGET = $(BUILDDIR)/test_bw_auth
TEST_CONFLUX_TARGET = $(BUILDDIR)/test_conflux
TEST_RATELIMIT_TARGET = $(BUILDDIR)/test_ratelimit
TEST_CONSENSUS_CACHE_TARGET = $(BUILDDIR)/test_consensus_cache
TEST_SCHEDULER_TARGET = $(BUILDDIR)/test_scheduler
TEST_MONITOR_TARGET = $(BUILDDIR)/test_monitor
TEST_CKE_TARGET = $(BUILDDIR)/test_cke
TEST_NOISE_TARGET = $(BUILDDIR)/test_noise
TEST_OB_TARGET = $(BUILDDIR)/test_onionbalance
TEST_BRIDGEDB_TARGET = $(BUILDDIR)/test_bridgedb
TEST_SOCKS_TARGET = $(BUILDDIR)/test_socks
TEST_DNS_CACHE_TARGET = $(BUILDDIR)/test_dns_cache
TEST_SHADE_TARGET = $(BUILDDIR)/test_shade
TEST_BRIDGE_AUTH_TARGET = $(BUILDDIR)/test_bridge_auth
TEST_EXIT_SLA_TARGET = $(BUILDDIR)/test_exit_sla
TEST_CC_TARGET = $(BUILDDIR)/test_cc
TEST_FEATURES2_TARGET = $(BUILDDIR)/test_features2
TEST_INFRA_TARGET = $(BUILDDIR)/test_infra
TEST_DHT_TARGET = $(BUILDDIR)/test_dht
TEST_MLDSA_TARGET = $(BUILDDIR)/test_mldsa
TEST_PATHBIAS_TARGET = $(BUILDDIR)/test_pathbias
TEST_KYBER_KAT_TARGET = $(BUILDDIR)/test_kyber_kat
TEST_MLDSA_KAT_TARGET = $(BUILDDIR)/test_mldsa_kat

.PHONY: all clean tests tools test check install uninstall distclean static-analysis asan-test tsan-test fuzz-build fuzz fuzz-clean coverage infer kat dudect cbmc build-moor-top

all: $(OBJDIR) $(OBJDIR)/kyber $(OBJDIR)/dilithium $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/kyber:
	mkdir -p $(OBJDIR)/kyber

$(OBJDIR)/dilithium:
	mkdir -p $(OBJDIR)/dilithium

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# build_id.o is always rebuilt so the baked-in git hash matches current HEAD.
# MOOR_BUILD_ID can be overridden from the command line (e.g. by deploy scripts
# that build on machines without a git repo). Falls back to git, then "unknown".
MOOR_BUILD_ID ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || cat BUILD_ID 2>/dev/null || echo unknown)
.PHONY: $(OBJDIR)/build_id.o
$(OBJDIR)/build_id.o: $(SRCDIR)/build_id.c | $(OBJDIR)
	$(CC) $(CFLAGS) -DMOOR_BUILD_ID="\"$(MOOR_BUILD_ID)\"" -c $< -o $@

$(OBJDIR)/kyber/%.o: $(SRCDIR)/kyber/%.c | $(OBJDIR)/kyber
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/dilithium/%.o: $(SRCDIR)/dilithium/%.c | $(OBJDIR)/dilithium
	$(CC) $(CFLAGS) -c $< -o $@

$(MAIN_OBJ): $(MAIN_SRC) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(ALL_OBJECTS) $(MAIN_OBJ)
	$(CC) $(ALL_OBJECTS) $(MAIN_OBJ) -o $@ $(LDFLAGS)
	@echo "Built: $(TARGET)"

# Tools
tools: $(KEYGEN_TARGET) $(MOOR_TOP_TARGET)

$(KEYGEN_TARGET): $(KEYGEN_SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	@echo "Built: $(KEYGEN_TARGET)"

$(MOOR_TOP_TARGET): $(MOOR_TOP_SRC)
	$(CC) -Wall -Wextra -O2 -g $(NCURSES_CFLAGS) $< -o $@ $(NCURSES_LIBS)
	@echo "Built: $(MOOR_TOP_TARGET)"

build-moor-top: $(MOOR_TOP_TARGET)

# Tests
tests: $(TEST_CRYPTO_TARGET) $(TEST_CELL_TARGET) $(TEST_CIRCUIT_TARGET) $(TEST_CONFIG_TARGET) $(TEST_TRANSPORT_TARGET) $(TEST_KEM_TARGET) $(TEST_FRAGMENT_TARGET) $(TEST_PQ_CIRCUIT_TARGET) $(TEST_POW_TARGET) $(TEST_GEOIP_TARGET) $(TEST_PADDING_ADV_TARGET) $(TEST_BW_AUTH_TARGET) $(TEST_CONFLUX_TARGET) $(TEST_RATELIMIT_TARGET) $(TEST_CONSENSUS_CACHE_TARGET) $(TEST_SCHEDULER_TARGET) $(TEST_MONITOR_TARGET) $(TEST_CKE_TARGET) $(TEST_NOISE_TARGET) $(TEST_SOCKS_TARGET) $(TEST_OB_TARGET) $(TEST_BRIDGEDB_TARGET) $(TEST_DNS_CACHE_TARGET) $(TEST_SHADE_TARGET) $(TEST_BRIDGE_AUTH_TARGET) $(TEST_EXIT_SLA_TARGET) $(TEST_CC_TARGET) $(TEST_FEATURES2_TARGET) $(TEST_INFRA_TARGET) $(TEST_DHT_TARGET) $(TEST_MLDSA_TARGET) $(TEST_PATHBIAS_TARGET)

$(TEST_CRYPTO_TARGET): $(TEST_CRYPTO_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_CELL_TARGET): $(TEST_CELL_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_CIRCUIT_TARGET): $(TEST_CIRCUIT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_CONFIG_TARGET): $(TEST_CONFIG_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_TRANSPORT_TARGET): $(TEST_TRANSPORT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_KEM_TARGET): $(TEST_KEM_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_FRAGMENT_TARGET): $(TEST_FRAGMENT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_PQ_CIRCUIT_TARGET): $(TEST_PQ_CIRCUIT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_POW_TARGET): $(TEST_POW_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_GEOIP_TARGET): $(TEST_GEOIP_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_PADDING_ADV_TARGET): $(TEST_PADDING_ADV_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_BW_AUTH_TARGET): $(TEST_BW_AUTH_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_CONFLUX_TARGET): $(TEST_CONFLUX_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_RATELIMIT_TARGET): $(TEST_RATELIMIT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_CONSENSUS_CACHE_TARGET): $(TEST_CONSENSUS_CACHE_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_SCHEDULER_TARGET): $(TEST_SCHEDULER_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_MONITOR_TARGET): $(TEST_MONITOR_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_CKE_TARGET): $(TEST_CKE_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_NOISE_TARGET): $(TEST_NOISE_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_OB_TARGET): $(TEST_OB_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_BRIDGEDB_TARGET): $(TEST_BRIDGEDB_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_SOCKS_TARGET): $(TEST_SOCKS_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_DNS_CACHE_TARGET): $(TEST_DNS_CACHE_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_SHADE_TARGET): $(TEST_SHADE_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_BRIDGE_AUTH_TARGET): $(TEST_BRIDGE_AUTH_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_EXIT_SLA_TARGET): $(TEST_EXIT_SLA_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_CC_TARGET): $(TEST_CC_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_FEATURES2_TARGET): $(TEST_FEATURES2_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_INFRA_TARGET): $(TEST_INFRA_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_DHT_TARGET): $(TEST_DHT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_MLDSA_TARGET): $(TEST_MLDSA_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_PATHBIAS_TARGET): $(TEST_PATHBIAS_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_KYBER_KAT_TARGET): $(TEST_KYBER_KAT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

$(TEST_MLDSA_KAT_TARGET): $(TEST_MLDSA_KAT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

test: tests
	@echo "=== Running tests ==="
	./$(TEST_CRYPTO_TARGET)
	./$(TEST_CELL_TARGET)
	./$(TEST_CIRCUIT_TARGET)
	./$(TEST_CONFIG_TARGET)
	./$(TEST_TRANSPORT_TARGET)
	./$(TEST_KEM_TARGET)
	./$(TEST_FRAGMENT_TARGET)
	./$(TEST_PQ_CIRCUIT_TARGET)
	./$(TEST_POW_TARGET)
	./$(TEST_GEOIP_TARGET)
	./$(TEST_PADDING_ADV_TARGET)
	./$(TEST_BW_AUTH_TARGET)
	./$(TEST_CONFLUX_TARGET)
	./$(TEST_RATELIMIT_TARGET)
	./$(TEST_CONSENSUS_CACHE_TARGET)
	./$(TEST_SCHEDULER_TARGET)
	./$(TEST_MONITOR_TARGET)
	./$(TEST_CKE_TARGET)
	./$(TEST_NOISE_TARGET)
	./$(TEST_SOCKS_TARGET)
	./$(TEST_OB_TARGET)
	./$(TEST_BRIDGEDB_TARGET)
	./$(TEST_DNS_CACHE_TARGET)
	./$(TEST_SHADE_TARGET)
	./$(TEST_BRIDGE_AUTH_TARGET)
	./$(TEST_EXIT_SLA_TARGET)
	./$(TEST_CC_TARGET)
	./$(TEST_FEATURES2_TARGET)
	./$(TEST_INFRA_TARGET)
	./$(TEST_DHT_TARGET)
	./$(TEST_MLDSA_TARGET)
	./$(TEST_PATHBIAS_TARGET)
	@echo "=== All tests passed ==="

clean:
	rm -rf $(OBJDIR) $(TARGET) $(KEYGEN_TARGET) $(MOOR_TOP_TARGET)
	rm -f $(TEST_CRYPTO_TARGET) $(TEST_CELL_TARGET) $(TEST_CIRCUIT_TARGET) $(TEST_CONFIG_TARGET)
	rm -f $(TEST_TRANSPORT_TARGET) $(TEST_KEM_TARGET)
	rm -f $(TEST_FRAGMENT_TARGET) $(TEST_PQ_CIRCUIT_TARGET) $(TEST_POW_TARGET) $(TEST_GEOIP_TARGET)
	rm -f $(TEST_PADDING_ADV_TARGET) $(TEST_BW_AUTH_TARGET) $(TEST_CONFLUX_TARGET)
	rm -f $(TEST_RATELIMIT_TARGET) $(TEST_CONSENSUS_CACHE_TARGET)
	rm -f $(TEST_SCHEDULER_TARGET) $(TEST_MONITOR_TARGET)
	rm -f $(TEST_CKE_TARGET) $(TEST_NOISE_TARGET) $(TEST_SOCKS_TARGET) $(TEST_OB_TARGET) $(TEST_BRIDGEDB_TARGET) $(TEST_DNS_CACHE_TARGET) $(TEST_SHADE_TARGET) $(TEST_BRIDGE_AUTH_TARGET) $(TEST_EXIT_SLA_TARGET) $(TEST_CC_TARGET) $(TEST_FEATURES2_TARGET) $(TEST_INFRA_TARGET) $(TEST_DHT_TARGET) $(TEST_MLDSA_TARGET) $(TEST_PATHBIAS_TARGET)
	rm -f $(TEST_KYBER_KAT_TARGET) $(TEST_MLDSA_KAT_TARGET) $(BUILDDIR)/dudect_crypto
	rm -rf obj_cov coverage_report
	rm -f *.exe

check: test

# Static analysis
cppcheck:
	cppcheck --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction \
		-I include -I src/kyber -I src/dilithium \
		--std=c11 --force --quiet \
		src/*.c 2>&1 | tee cppcheck_report.txt
	@echo "Report: cppcheck_report.txt"

distclean: clean
	rm -f config.mk
	rm -rf $(ASAN_OBJDIR) $(TSAN_OBJDIR) $(FUZZ_OBJDIR) $(COV_OBJDIR)
	rm -f $(ASAN_TEST_TARGETS) $(TSAN_TEST_TARGETS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/moor
	@if [ -f $(MOOR_TOP_TARGET) ]; then \
		install -m 755 $(MOOR_TOP_TARGET) $(DESTDIR)$(BINDIR)/moor-top; \
		echo "Installed moor-top to $(DESTDIR)$(BINDIR)/moor-top"; \
	fi
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 moor.1 $(DESTDIR)$(MANDIR)/man1/moor.1
	install -d $(DESTDIR)$(SYSCONFDIR)/moor
	@echo "Installed moor to $(DESTDIR)$(BINDIR)/moor"
	@echo "Installed manpage to $(DESTDIR)$(MANDIR)/man1/moor.1"
	@echo "Copy $(DESTDIR)$(SYSCONFDIR)/moor/example.conf to moor.conf and edit"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/moor
	rm -f $(DESTDIR)$(BINDIR)/moor-top
	rm -f $(DESTDIR)$(MANDIR)/man1/moor.1
	rm -f $(DESTDIR)$(SYSCONFDIR)/moor/example.conf
	rmdir $(DESTDIR)$(SYSCONFDIR)/moor 2>/dev/null || true

# =============================================================================
# Static Analysis
# =============================================================================
static-analysis:
	@mkdir -p audit
	@echo "=== Running cppcheck ==="
	cppcheck --enable=all --inconclusive --std=c11 \
		-Iinclude -Isrc/kyber -Isrc/dilithium \
		--suppress=missingIncludeSystem \
		--suppress=unusedFunction \
		--force --quiet \
		src/ 2>audit/cppcheck_report.txt || true
	@echo "cppcheck report: audit/cppcheck_report.txt ($$(wc -l < audit/cppcheck_report.txt) lines)"
	@echo "=== Running flawfinder ==="
	flawfinder --columns --context --minlevel=1 \
		src/ include/ > audit/flawfinder_report.txt 2>&1 || true
	@echo "flawfinder report: audit/flawfinder_report.txt"
	@echo "=== Static analysis complete ==="

# =============================================================================
# Sanitizer Test Builds
# =============================================================================

# ASan + UBSan: rebuild everything with clang sanitizers, run all tests
ASAN_CC = clang
ASAN_CFLAGS = -Wall -Wextra -O1 -g -fno-strict-aliasing \
              -fsanitize=address,undefined -fno-omit-frame-pointer \
              -Iinclude -Isrc/kyber -Isrc/dilithium \
              $(shell pkg-config --cflags libsodium)
ASAN_LDFLAGS = -fsanitize=address,undefined \
               $(shell pkg-config --libs libsodium) -lm -lpthread -lz

ASAN_OBJDIR = obj_asan
ASAN_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(ASAN_OBJDIR)/%.o,$(SOURCES))
ASAN_KYBER_OBJECTS = $(patsubst $(SRCDIR)/kyber/%.c,$(ASAN_OBJDIR)/kyber/%.o,$(KYBER_SOURCES))
ASAN_DILITHIUM_OBJECTS = $(patsubst $(SRCDIR)/dilithium/%.c,$(ASAN_OBJDIR)/dilithium/%.o,$(DILITHIUM_SOURCES))
ASAN_ALL_OBJECTS = $(ASAN_OBJECTS) $(ASAN_KYBER_OBJECTS) $(ASAN_DILITHIUM_OBJECTS)

$(ASAN_OBJDIR):
	mkdir -p $(ASAN_OBJDIR)

$(ASAN_OBJDIR)/kyber:
	mkdir -p $(ASAN_OBJDIR)/kyber

$(ASAN_OBJDIR)/dilithium:
	mkdir -p $(ASAN_OBJDIR)/dilithium

$(ASAN_OBJDIR)/%.o: $(SRCDIR)/%.c | $(ASAN_OBJDIR)
	$(ASAN_CC) $(ASAN_CFLAGS) -c $< -o $@

$(ASAN_OBJDIR)/kyber/%.o: $(SRCDIR)/kyber/%.c | $(ASAN_OBJDIR)/kyber
	$(ASAN_CC) $(ASAN_CFLAGS) -c $< -o $@

$(ASAN_OBJDIR)/dilithium/%.o: $(SRCDIR)/dilithium/%.c | $(ASAN_OBJDIR)/dilithium
	$(ASAN_CC) $(ASAN_CFLAGS) -c $< -o $@

# Test source list (all 30)
TEST_SOURCES = $(TEST_CRYPTO_SRC) $(TEST_CELL_SRC) $(TEST_CIRCUIT_SRC) \
               $(TEST_CONFIG_SRC) $(TEST_TRANSPORT_SRC) $(TEST_KEM_SRC) \
               $(TEST_FRAGMENT_SRC) $(TEST_PQ_CIRCUIT_SRC) $(TEST_POW_SRC) \
               $(TEST_GEOIP_SRC) $(TEST_PADDING_ADV_SRC) $(TEST_BW_AUTH_SRC) \
               $(TEST_CONFLUX_SRC) $(TEST_RATELIMIT_SRC) $(TEST_CONSENSUS_CACHE_SRC) \
               $(TEST_SCHEDULER_SRC) $(TEST_MONITOR_SRC) $(TEST_CKE_SRC) \
               $(TEST_NOISE_SRC) $(TEST_SOCKS_SRC) $(TEST_OB_SRC) \
               $(TEST_BRIDGEDB_SRC) $(TEST_DNS_CACHE_SRC) $(TEST_SHADE_SRC) \
               $(TEST_BRIDGE_AUTH_SRC) $(TEST_EXIT_SLA_SRC) $(TEST_CC_SRC) \
               $(TEST_FEATURES2_SRC) $(TEST_INFRA_SRC) $(TEST_DHT_SRC) \
               $(TEST_MLDSA_SRC) $(TEST_PATHBIAS_SRC)

ASAN_TEST_TARGETS = $(patsubst tests/%.c,asan_%,$(TEST_SOURCES))

asan_%: tests/%.c $(ASAN_ALL_OBJECTS) | $(ASAN_OBJDIR) $(ASAN_OBJDIR)/kyber $(ASAN_OBJDIR)/dilithium
	$(ASAN_CC) $(ASAN_CFLAGS) $< $(ASAN_ALL_OBJECTS) -o $@ $(ASAN_LDFLAGS)

asan-test: $(ASAN_OBJDIR) $(ASAN_OBJDIR)/kyber $(ASAN_OBJDIR)/dilithium $(ASAN_ALL_OBJECTS) $(ASAN_TEST_TARGETS)
	@echo "=== Running tests under ASan+UBSan ==="
	@FAILED=0; \
	for t in $(ASAN_TEST_TARGETS); do \
		echo "  Running $$t..."; \
		ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./$$t || FAILED=$$((FAILED+1)); \
	done; \
	if [ $$FAILED -eq 0 ]; then \
		echo "=== All ASan+UBSan tests passed ==="; \
	else \
		echo "=== $$FAILED test(s) failed under ASan+UBSan ==="; \
		exit 1; \
	fi

# TSan: rebuild with ThreadSanitizer
TSAN_CC = clang
TSAN_CFLAGS = -Wall -Wextra -O1 -g -fno-strict-aliasing \
              -fsanitize=thread -fno-omit-frame-pointer \
              -Iinclude -Isrc/kyber -Isrc/dilithium \
              $(shell pkg-config --cflags libsodium)
TSAN_LDFLAGS = -fsanitize=thread \
               $(shell pkg-config --libs libsodium) -lm -lpthread -lz

TSAN_OBJDIR = obj_tsan
TSAN_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(TSAN_OBJDIR)/%.o,$(SOURCES))
TSAN_KYBER_OBJECTS = $(patsubst $(SRCDIR)/kyber/%.c,$(TSAN_OBJDIR)/kyber/%.o,$(KYBER_SOURCES))
TSAN_DILITHIUM_OBJECTS = $(patsubst $(SRCDIR)/dilithium/%.c,$(TSAN_OBJDIR)/dilithium/%.o,$(DILITHIUM_SOURCES))
TSAN_ALL_OBJECTS = $(TSAN_OBJECTS) $(TSAN_KYBER_OBJECTS) $(TSAN_DILITHIUM_OBJECTS)

$(TSAN_OBJDIR):
	mkdir -p $(TSAN_OBJDIR)

$(TSAN_OBJDIR)/kyber:
	mkdir -p $(TSAN_OBJDIR)/kyber

$(TSAN_OBJDIR)/dilithium:
	mkdir -p $(TSAN_OBJDIR)/dilithium

$(TSAN_OBJDIR)/%.o: $(SRCDIR)/%.c | $(TSAN_OBJDIR)
	$(TSAN_CC) $(TSAN_CFLAGS) -c $< -o $@

$(TSAN_OBJDIR)/kyber/%.o: $(SRCDIR)/kyber/%.c | $(TSAN_OBJDIR)/kyber
	$(TSAN_CC) $(TSAN_CFLAGS) -c $< -o $@

$(TSAN_OBJDIR)/dilithium/%.o: $(SRCDIR)/dilithium/%.c | $(TSAN_OBJDIR)/dilithium
	$(TSAN_CC) $(TSAN_CFLAGS) -c $< -o $@

TSAN_TEST_TARGETS = $(patsubst tests/%.c,tsan_%,$(TEST_SOURCES))

tsan_%: tests/%.c $(TSAN_ALL_OBJECTS) | $(TSAN_OBJDIR) $(TSAN_OBJDIR)/kyber $(TSAN_OBJDIR)/dilithium
	$(TSAN_CC) $(TSAN_CFLAGS) $< $(TSAN_ALL_OBJECTS) -o $@ $(TSAN_LDFLAGS)

tsan-test: $(TSAN_OBJDIR) $(TSAN_OBJDIR)/kyber $(TSAN_OBJDIR)/dilithium $(TSAN_ALL_OBJECTS) $(TSAN_TEST_TARGETS)
	@echo "=== Running tests under TSan ==="
	@FAILED=0; \
	for t in $(TSAN_TEST_TARGETS); do \
		echo "  Running $$t..."; \
		TSAN_OPTIONS=halt_on_error=1 ./$$t || FAILED=$$((FAILED+1)); \
	done; \
	if [ $$FAILED -eq 0 ]; then \
		echo "=== All TSan tests passed ==="; \
	else \
		echo "=== $$FAILED test(s) failed under TSan ==="; \
		exit 1; \
	fi

# =============================================================================
# Debug build: full ASAN+UBSan main binary for crash diagnosis
# =============================================================================
# Builds ./moor_debug — run it exactly like ./moor but with full sanitizer
# coverage, zero optimization, and maximum debug info.
#
# Usage:
#   make debug
#   ASAN_OPTIONS=detect_leaks=0:print_stacktrace=1:abort_on_error=1 ./moor_debug [args...]
#
# On crash: ASAN prints the exact line + full backtrace, no core dump needed.

DEBUG_CC = clang
DEBUG_CFLAGS = -Wall -Wextra -O0 -g3 -ggdb -fno-strict-aliasing \
               -fno-omit-frame-pointer -fno-optimize-sibling-calls \
               -fsanitize=address,undefined \
               -fsanitize-recover=undefined \
               -fno-sanitize=vptr \
               -DMOOR_DEBUG=1 \
               -Iinclude -Isrc/kyber -Isrc/dilithium \
               -fPIE -DMOOR_SYSCONFDIR='"$(SYSCONFDIR)/moor"' \
               $(shell pkg-config --cflags libsodium 2>/dev/null)
DEBUG_LDFLAGS = -fsanitize=address,undefined \
                -rdynamic \
                $(shell pkg-config --libs libsodium 2>/dev/null || echo -lsodium) \
                -lm -lpthread -lz

DEBUG_OBJDIR = obj_debug
DEBUG_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(DEBUG_OBJDIR)/%.o,$(SOURCES))
DEBUG_KYBER_OBJECTS = $(patsubst $(SRCDIR)/kyber/%.c,$(DEBUG_OBJDIR)/kyber/%.o,$(KYBER_SOURCES))
DEBUG_DILITHIUM_OBJECTS = $(patsubst $(SRCDIR)/dilithium/%.c,$(DEBUG_OBJDIR)/dilithium/%.o,$(DILITHIUM_SOURCES))
DEBUG_MAIN_OBJ = $(DEBUG_OBJDIR)/main.o
DEBUG_ALL_OBJECTS = $(DEBUG_OBJECTS) $(DEBUG_KYBER_OBJECTS) $(DEBUG_DILITHIUM_OBJECTS)

$(DEBUG_OBJDIR):
	mkdir -p $(DEBUG_OBJDIR)

$(DEBUG_OBJDIR)/kyber:
	mkdir -p $(DEBUG_OBJDIR)/kyber

$(DEBUG_OBJDIR)/dilithium:
	mkdir -p $(DEBUG_OBJDIR)/dilithium

$(DEBUG_OBJDIR)/%.o: $(SRCDIR)/%.c | $(DEBUG_OBJDIR)
	$(DEBUG_CC) $(DEBUG_CFLAGS) -c $< -o $@

$(DEBUG_OBJDIR)/kyber/%.o: $(SRCDIR)/kyber/%.c | $(DEBUG_OBJDIR)/kyber
	$(DEBUG_CC) $(DEBUG_CFLAGS) -c $< -o $@

$(DEBUG_OBJDIR)/dilithium/%.o: $(SRCDIR)/dilithium/%.c | $(DEBUG_OBJDIR)/dilithium
	$(DEBUG_CC) $(DEBUG_CFLAGS) -c $< -o $@

$(DEBUG_MAIN_OBJ): $(MAIN_SRC) | $(DEBUG_OBJDIR)
	$(DEBUG_CC) $(DEBUG_CFLAGS) -c $< -o $@

moor_debug: $(DEBUG_OBJDIR) $(DEBUG_OBJDIR)/kyber $(DEBUG_OBJDIR)/dilithium $(DEBUG_ALL_OBJECTS) $(DEBUG_MAIN_OBJ)
	$(DEBUG_CC) $(DEBUG_ALL_OBJECTS) $(DEBUG_MAIN_OBJ) -o $@ $(DEBUG_LDFLAGS)
	@echo ""
	@echo "=== Built: ./moor_debug (ASAN+UBSan, -O0, -g3) ==="
	@echo "Run with:"
	@echo "  ASAN_OPTIONS=detect_leaks=0:print_stacktrace=1:abort_on_error=1 ./moor_debug [args...]"
	@echo ""

debug: moor_debug

.PHONY: debug

# =============================================================================
# LibFuzzer Harnesses
# =============================================================================

FUZZ_CC = clang
# Library objects: ASan+UBSan but NO -fsanitize=fuzzer (that's only for harness main)
FUZZ_LIB_CFLAGS = -Wall -Wextra -O1 -g -fno-strict-aliasing \
                  -fsanitize=address,undefined -fno-omit-frame-pointer \
                  -Iinclude -Isrc/kyber -Isrc/dilithium \
                  $(shell pkg-config --cflags libsodium)
# Harness files: add -fsanitize=fuzzer for LLVMFuzzerTestOneInput linkage
FUZZ_HARNESS_CFLAGS = $(FUZZ_LIB_CFLAGS) -fsanitize=fuzzer
FUZZ_LDFLAGS = -fsanitize=fuzzer,address,undefined \
               $(shell pkg-config --libs libsodium) -lm -lpthread -lz

FUZZ_OBJDIR = obj_fuzz
FUZZ_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(FUZZ_OBJDIR)/%.o,$(SOURCES))
FUZZ_KYBER_OBJECTS = $(patsubst $(SRCDIR)/kyber/%.c,$(FUZZ_OBJDIR)/kyber/%.o,$(KYBER_SOURCES))
FUZZ_DILITHIUM_OBJECTS = $(patsubst $(SRCDIR)/dilithium/%.c,$(FUZZ_OBJDIR)/dilithium/%.o,$(DILITHIUM_SOURCES))
FUZZ_ALL_OBJECTS = $(FUZZ_OBJECTS) $(FUZZ_KYBER_OBJECTS) $(FUZZ_DILITHIUM_OBJECTS)

FUZZ_HARNESSES = fuzz/fuzz_cell fuzz/fuzz_socks5 fuzz/fuzz_cke \
                 fuzz/fuzz_config fuzz/fuzz_hs_addr fuzz/fuzz_consensus \
                 fuzz/fuzz_noise fuzz/fuzz_kyber fuzz/fuzz_mldsa \
                 fuzz/fuzz_lspec fuzz/fuzz_transport fuzz/fuzz_microdesc \
                 fuzz/fuzz_wfpad fuzz/fuzz_pow fuzz/fuzz_padding \
                 fuzz/fuzz_conflux fuzz/fuzz_ratelimit \
                 fuzz/fuzz_descriptor fuzz/fuzz_geoip \
                 fuzz/fuzz_relay_cell fuzz/fuzz_base32 fuzz/fuzz_dpf

$(FUZZ_OBJDIR):
	mkdir -p $(FUZZ_OBJDIR)

$(FUZZ_OBJDIR)/kyber:
	mkdir -p $(FUZZ_OBJDIR)/kyber

$(FUZZ_OBJDIR)/dilithium:
	mkdir -p $(FUZZ_OBJDIR)/dilithium

$(FUZZ_OBJDIR)/%.o: $(SRCDIR)/%.c | $(FUZZ_OBJDIR)
	$(FUZZ_CC) $(FUZZ_LIB_CFLAGS) -c $< -o $@

$(FUZZ_OBJDIR)/kyber/%.o: $(SRCDIR)/kyber/%.c | $(FUZZ_OBJDIR)/kyber
	$(FUZZ_CC) $(FUZZ_LIB_CFLAGS) -c $< -o $@

$(FUZZ_OBJDIR)/dilithium/%.o: $(SRCDIR)/dilithium/%.c | $(FUZZ_OBJDIR)/dilithium
	$(FUZZ_CC) $(FUZZ_LIB_CFLAGS) -c $< -o $@

fuzz/fuzz_%: fuzz/fuzz_%.c $(FUZZ_ALL_OBJECTS) | $(FUZZ_OBJDIR) $(FUZZ_OBJDIR)/kyber $(FUZZ_OBJDIR)/dilithium
	$(FUZZ_CC) $(FUZZ_HARNESS_CFLAGS) $< $(FUZZ_ALL_OBJECTS) -o $@ $(FUZZ_LDFLAGS)

fuzz-build: $(FUZZ_OBJDIR) $(FUZZ_OBJDIR)/kyber $(FUZZ_OBJDIR)/dilithium $(FUZZ_ALL_OBJECTS) $(FUZZ_HARNESSES)
	@echo "=== Built $(words $(FUZZ_HARNESSES)) fuzz harnesses ==="

# Run all harnesses for 60s each (quick smoke test)
FUZZ_DURATION ?= 60

fuzz: fuzz-build
	@echo "=== Running fuzz campaign ($(FUZZ_DURATION)s per harness) ==="
	@mkdir -p fuzz/crashes
	@for h in $(FUZZ_HARNESSES); do \
		name=$$(basename $$h); \
		seed_dir="fuzz/seeds/$${name#fuzz_}"; \
		corpus_dir="fuzz/corpus_$${name#fuzz_}"; \
		crash_dir="fuzz/crashes/$${name#fuzz_}"; \
		mkdir -p "$$corpus_dir" "$$crash_dir"; \
		if [ -d "$$seed_dir" ]; then cp "$$seed_dir"/* "$$corpus_dir"/ 2>/dev/null || true; fi; \
		echo "  Fuzzing $$name..."; \
		./$$h "$$corpus_dir" \
			-artifact_prefix="$$crash_dir/" \
			-max_total_time=$(FUZZ_DURATION) \
			-max_len=4096 \
			-print_final_stats=1 2>&1 | tail -5 || true; \
	done
	@echo "=== Fuzz campaign complete. Crashes in fuzz/crashes/ ==="

# AFL++ build targets (uses afl-clang-fast for instrumentation)
AFL_CC = afl-clang-fast
AFL_OBJDIR = obj_afl
AFL_LIB_CFLAGS = -Wall -Wextra -O1 -g -fno-strict-aliasing \
                 -fsanitize=address,undefined -fno-omit-frame-pointer \
                 -Iinclude -Isrc/kyber -Isrc/dilithium \
                 $(shell pkg-config --cflags libsodium)
AFL_LDFLAGS = -fsanitize=address,undefined \
              $(shell pkg-config --libs libsodium) -lm -lpthread -lz
AFL_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(AFL_OBJDIR)/%.o,$(SOURCES))
AFL_KYBER_OBJECTS = $(patsubst $(SRCDIR)/kyber/%.c,$(AFL_OBJDIR)/kyber/%.o,$(KYBER_SOURCES))
AFL_DILITHIUM_OBJECTS = $(patsubst $(SRCDIR)/dilithium/%.c,$(AFL_OBJDIR)/dilithium/%.o,$(DILITHIUM_SOURCES))
AFL_ALL_OBJECTS = $(AFL_OBJECTS) $(AFL_KYBER_OBJECTS) $(AFL_DILITHIUM_OBJECTS)
AFL_HARNESS_BINS = $(patsubst fuzz/%,fuzz/afl_%,$(FUZZ_HARNESSES))

$(AFL_OBJDIR):
	mkdir -p $(AFL_OBJDIR)

$(AFL_OBJDIR)/kyber:
	mkdir -p $(AFL_OBJDIR)/kyber

$(AFL_OBJDIR)/dilithium:
	mkdir -p $(AFL_OBJDIR)/dilithium

$(AFL_OBJDIR)/%.o: $(SRCDIR)/%.c | $(AFL_OBJDIR)
	$(AFL_CC) $(AFL_LIB_CFLAGS) -c $< -o $@

$(AFL_OBJDIR)/kyber/%.o: $(SRCDIR)/kyber/%.c | $(AFL_OBJDIR)/kyber
	$(AFL_CC) $(AFL_LIB_CFLAGS) -c $< -o $@

$(AFL_OBJDIR)/dilithium/%.o: $(SRCDIR)/dilithium/%.c | $(AFL_OBJDIR)/dilithium
	$(AFL_CC) $(AFL_LIB_CFLAGS) -c $< -o $@

# AFL harness: strip -fsanitize=fuzzer, add standalone main()
fuzz/afl_fuzz_%: fuzz/fuzz_%.c $(AFL_ALL_OBJECTS) | $(AFL_OBJDIR) $(AFL_OBJDIR)/kyber $(AFL_OBJDIR)/dilithium
	$(AFL_CC) $(AFL_LIB_CFLAGS) -DAFL_STANDALONE $< $(AFL_ALL_OBJECTS) -o $@ $(AFL_LDFLAGS)

afl-build: $(AFL_OBJDIR) $(AFL_OBJDIR)/kyber $(AFL_OBJDIR)/dilithium $(AFL_ALL_OBJECTS) $(AFL_HARNESS_BINS)
	@echo "=== Built $(words $(AFL_HARNESS_BINS)) AFL++ harnesses ==="

fuzz-clean:
	rm -rf $(FUZZ_OBJDIR) $(AFL_OBJDIR) $(FUZZ_HARNESSES) fuzz/afl_fuzz_*
	rm -rf fuzz/corpus_* fuzz/crashes fuzz/seeds
	rm -rf $(ASAN_OBJDIR) $(TSAN_OBJDIR)
	rm -f asan_test_* tsan_test_*

# =============================================================================
# gcov/lcov — Code Coverage Report
# =============================================================================

COV_OBJDIR = obj_cov
COV_CC = gcc
COV_CFLAGS = -Wall -Wextra -O0 -g --coverage -fno-strict-aliasing \
             -Iinclude -Isrc/kyber -Isrc/dilithium \
             $(SODIUM_CFLAGS) $(ZLIB_CFLAGS)
COV_LDFLAGS = --coverage $(SODIUM_LIBS) -lm -lpthread $(ZLIB_LIBS)

COV_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(COV_OBJDIR)/%.o,$(SOURCES))
COV_KYBER_OBJECTS = $(patsubst $(SRCDIR)/kyber/%.c,$(COV_OBJDIR)/kyber/%.o,$(KYBER_SOURCES))
COV_DILITHIUM_OBJECTS = $(patsubst $(SRCDIR)/dilithium/%.c,$(COV_OBJDIR)/dilithium/%.o,$(DILITHIUM_SOURCES))
COV_ALL_OBJECTS = $(COV_OBJECTS) $(COV_KYBER_OBJECTS) $(COV_DILITHIUM_OBJECTS)

COV_TEST_TARGETS = $(patsubst tests/%.c,cov_%,$(TEST_SOURCES)) \
                   cov_test_kyber_kat cov_test_mldsa_kat

$(COV_OBJDIR):
	mkdir -p $(COV_OBJDIR)

$(COV_OBJDIR)/kyber:
	mkdir -p $(COV_OBJDIR)/kyber

$(COV_OBJDIR)/dilithium:
	mkdir -p $(COV_OBJDIR)/dilithium

$(COV_OBJDIR)/%.o: $(SRCDIR)/%.c | $(COV_OBJDIR)
	$(COV_CC) $(COV_CFLAGS) -c $< -o $@

$(COV_OBJDIR)/kyber/%.o: $(SRCDIR)/kyber/%.c | $(COV_OBJDIR)/kyber
	$(COV_CC) $(COV_CFLAGS) -c $< -o $@

$(COV_OBJDIR)/dilithium/%.o: $(SRCDIR)/dilithium/%.c | $(COV_OBJDIR)/dilithium
	$(COV_CC) $(COV_CFLAGS) -c $< -o $@

cov_%: tests/%.c $(COV_ALL_OBJECTS) | $(COV_OBJDIR) $(COV_OBJDIR)/kyber $(COV_OBJDIR)/dilithium
	$(COV_CC) $(COV_CFLAGS) $< $(COV_ALL_OBJECTS) -o $@ $(COV_LDFLAGS)

# Build standalone wrappers for fuzz harnesses (call LLVMFuzzerTestOneInput once)
cov_fuzz_%: fuzz/fuzz_%.c $(COV_ALL_OBJECTS) | $(COV_OBJDIR) $(COV_OBJDIR)/kyber $(COV_OBJDIR)/dilithium
	@echo '#include <stdint.h>' > /tmp/cov_fuzz_main_$*.c
	@echo '#include <stddef.h>' >> /tmp/cov_fuzz_main_$*.c
	@echo 'extern int LLVMFuzzerTestOneInput(const uint8_t *, size_t);' >> /tmp/cov_fuzz_main_$*.c
	@echo 'int main(void) {' >> /tmp/cov_fuzz_main_$*.c
	@echo '    uint8_t buf[256] = {0};' >> /tmp/cov_fuzz_main_$*.c
	@echo '    LLVMFuzzerTestOneInput(buf, sizeof(buf));' >> /tmp/cov_fuzz_main_$*.c
	@echo '    return 0;' >> /tmp/cov_fuzz_main_$*.c
	@echo '}' >> /tmp/cov_fuzz_main_$*.c
	$(COV_CC) $(COV_CFLAGS) $< /tmp/cov_fuzz_main_$*.c $(COV_ALL_OBJECTS) -o $@ $(COV_LDFLAGS)
	@rm -f /tmp/cov_fuzz_main_$*.c

COV_FUZZ_TARGETS = $(patsubst fuzz/fuzz_%.c,cov_fuzz_%,$(wildcard fuzz/fuzz_*.c))

coverage: $(COV_OBJDIR) $(COV_OBJDIR)/kyber $(COV_OBJDIR)/dilithium $(COV_ALL_OBJECTS) $(COV_TEST_TARGETS) $(COV_FUZZ_TARGETS)
	@echo "=== Running all tests with coverage ==="
	@for t in $(COV_TEST_TARGETS) $(COV_FUZZ_TARGETS); do \
		echo "  Running $$t..."; \
		./$$t 2>/dev/null || true; \
	done
	@echo "=== Collecting coverage ==="
	@lcov --capture -d $(COV_OBJDIR) -o coverage.info -q \
		--rc branch_coverage=1 --ignore-errors deprecated,inconsistent
	@lcov --remove coverage.info '/usr/*' -o coverage.info -q \
		--rc branch_coverage=1 --ignore-errors deprecated,unused,inconsistent
	@mkdir -p coverage_report
	@genhtml coverage.info -o coverage_report -q \
		--rc branch_coverage=1 --ignore-errors deprecated,inconsistent
	@echo "=== Coverage report: coverage_report/index.html ==="
	@lcov --summary coverage.info --rc branch_coverage=1 \
		--ignore-errors deprecated,inconsistent 2>&1 | tail -4
	@rm -f coverage.info
	@rm -f $(COV_TEST_TARGETS) $(COV_FUZZ_TARGETS)

# =============================================================================
# Meta Infer — Static Analysis
# =============================================================================

infer:
	infer run --keep-going -- make -j$$(nproc) clean all CC=gcc
	@mkdir -p audit && cp infer-out/report.txt audit/infer_report.txt 2>/dev/null || true
	@echo "=== Infer report: audit/infer_report.txt ==="
	@echo "  $$(wc -l < audit/infer_report.txt 2>/dev/null || echo 0) lines"

# =============================================================================
# NIST KAT Vectors — Crypto Correctness
# =============================================================================

kat: $(TEST_KYBER_KAT_TARGET) $(TEST_MLDSA_KAT_TARGET)
	@echo "=== Running KAT tests ==="
	./$(TEST_KYBER_KAT_TARGET)
	./$(TEST_MLDSA_KAT_TARGET)
	@echo "=== All KAT tests passed ==="

# =============================================================================
# dudect — Constant-Time Verification
# =============================================================================

DUDECT_SRC = tests/dudect_crypto.c
DUDECT_TARGET = $(BUILDDIR)/dudect_crypto

$(DUDECT_TARGET): $(DUDECT_SRC) $(ALL_OBJECTS)
	$(CC) $(CFLAGS) $< $(ALL_OBJECTS) -o $@ $(LDFLAGS)

dudect: $(DUDECT_TARGET)
	@echo "=== Running constant-time tests ==="
	./$(DUDECT_TARGET)

# =============================================================================
# CBMC — Bounded Model Checking
# =============================================================================

CBMC_HARNESSES = cbmc/cbmc_dh_loworder.c cbmc/cbmc_cell_roundtrip.c \
                 cbmc/cbmc_wipe.c cbmc/cbmc_kem_null.c
CBMC_UNWIND = 520

cbmc:
	@echo "=== Running CBMC formal verification ==="
	@FAILED=0; \
	for h in $(CBMC_HARNESSES); do \
		name=$$(basename $$h .c); \
		echo "  Verifying $$name..."; \
		RESULT=$$(cbmc $$h --unwind $(CBMC_UNWIND) --bounds-check --pointer-check \
			--unwinding-assertions 2>&1); \
		RET=$$?; \
		echo "$$RESULT" | tail -1; \
		if [ $$RET -ne 0 ]; then FAILED=$$((FAILED+1)); fi; \
	done; \
	if [ $$FAILED -eq 0 ]; then \
		echo "=== All CBMC proofs verified ==="; \
	else \
		echo "=== $$FAILED CBMC proof(s) failed ==="; \
		exit 1; \
	fi
