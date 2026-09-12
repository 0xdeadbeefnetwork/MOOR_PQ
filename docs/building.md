# Building

## Quick start

```
make
```

This produces the `./moor` binary. It dynamically links against libsodium, zlib,
and libevent.

## Configure (optional, but what `setup.sh` uses)

`make` alone works: the Makefile falls back to `pkg-config` for each library.
`./configure` instead probes once and writes `config.mk`, which the Makefile
includes ahead of those fallbacks, so the build then needs no environment and no
flags on the command line:

```
sh ./configure          # ./configure is not marked executable in some checkouts
make -j"$(nproc)"
```

It probes libsodium, zlib and libevent — all three are required, and libevent is
linked unconditionally, so a configure that succeeds means the build will get that
far. An rpath is added only when a library sits outside the default search path,
which is what makes a build against a non-system prefix runnable without
`LD_LIBRARY_PATH`; a distro libdir, multiarch included, gets none.

`CFLAGS=` and `LDFLAGS=` may be passed as arguments (`sh ./configure
CFLAGS=-O3`); they land in `EXTRA_CFLAGS` / `EXTRA_LDFLAGS`.

### Building against libraries in a local prefix

With no root, the distro packages can be unpacked into a prefix and used from
there. `pkg-config` needs both variables — extracted `.pc` files declare
`prefix=/usr`, so `PKG_CONFIG_PATH` on its own yields link flags with no include
path and the build then compiles against system headers that are not installed:

```
P=$HOME/.cache/moor-deps/local
PKG_CONFIG_SYSROOT_DIR=$P PKG_CONFIG_PATH=$P/usr/lib/x86_64-linux-gnu/pkgconfig \
  sh ./configure
make -j"$(nproc)"
```

A binary built that way carries an rpath into that prefix. That is fine for
development and wrong for deployment: install the distro `-dev` packages and
rebuild, so the binary resolves libraries from system paths and carries no rpath.

### Build identifier

The build id compiled into the binary comes from the git checkout, so **`make`
refuses to build a dirty tree** — otherwise the id would name a commit that is not
what was compiled. Commit, stash, or set the id explicitly and take responsibility
for it:

```
make MOOR_BUILD_ID=local-wip
```

## Dependencies

| Library | Minimum version | Debian/Ubuntu package | Fedora package |
|---------|----------------|-----------------------|----------------|
| libsodium | >= 1.0.18 | `libsodium-dev` | `libsodium-devel` |
| zlib | any | `zlib1g-dev` | `zlib-devel` |
| libevent | >= 2.0 | `libevent-dev` | `libevent-devel` |
| pthreads | -- | included with glibc | included with glibc |

You also need a C compiler (gcc or clang) and `pkg-config` (recommended but optional).

No OpenSSL. No GnuTLS. No liboqs. The post-quantum primitives (ML-KEM-768,
ML-DSA-65, Falcon-512) are vendored from the PQClean reference implementations
in `src/pqclean/` and built in-tree.

On Debian/Ubuntu:

```
sudo apt install build-essential libsodium-dev zlib1g-dev libevent-dev pkg-config
```

On Fedora:

```
sudo dnf install gcc make libsodium-devel zlib-devel libevent-devel pkg-config
```

On Arch:

```
sudo pacman -S base-devel libsodium zlib libevent
```

On Alpine:

```
apk add build-base libsodium-dev zlib-dev libevent-dev pkgconfig
```

## Build targets

| Command | What it does |
|---------|-------------|
| `make` | Build the `moor` binary |
| `make tools` | Build `moor_keygen` (key generation) and `moor-top` (ncurses monitor) |
| `make tests` | Compile the test sources that are present |
| `make test` | Compile and run the tests that are present |
| `make release` | `make`, then split debug info into `moor.debug` and strip the binary |
| `make install` | Install binary, manpage, and config directory to PREFIX |
| `make uninstall` | Remove installed files |
| `make clean` | Remove build artifacts |
| `make distclean` | `clean` plus remove sanitizer build dirs |

`make install` puts the binary in `BINDIR` (default `/usr/local/bin`), the
manpage in `PREFIX/share/man/man1`, and creates the config directory at
`SYSCONFDIR/moor`. Use `DESTDIR` for staged installs (e.g. packaging):

```
make install DESTDIR=/tmp/moor-pkg
```

## Makefile variables

These can be passed on the command line:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CC` | auto-detected (gcc, clang, cc) | C compiler |
| `CFLAGS` | (hardened, see below) | Compiler flags |
| `LDFLAGS` | (hardened, see below) | Linker flags |
| `SODIUM_CFLAGS` | from pkg-config | libsodium include path |
| `SODIUM_LIBS` | from pkg-config | libsodium link flags |
| `LIBEVENT_CFLAGS` | from pkg-config | libevent include path |
| `LIBEVENT_LIBS` | from pkg-config | libevent link flags |
| `ZLIB_CFLAGS` | empty | zlib include path |
| `ZLIB_LIBS` | `-lz` | zlib link flags |
| `MOOR_BUILD_ID` | `git describe` of HEAD | Build identifier compiled into the binary |
| `EXTRA_CFLAGS` | empty | Appended to CFLAGS |
| `EXTRA_LDFLAGS` | empty | Appended to LDFLAGS |
| `PREFIX` | `/usr/local` | Install prefix |
| `BINDIR` | `PREFIX/bin` | Binary install directory |
| `SYSCONFDIR` | `PREFIX/etc` | Config file directory |

Example with a custom libsodium path:

```
make SODIUM_CFLAGS="-I/opt/libsodium/include" SODIUM_LIBS="-L/opt/libsodium/lib -lsodium"
```

## Hardening

The default build enables these hardening flags automatically -- you do not
need to set them yourself:

- `-fstack-protector-strong` -- stack buffer overflow detection
- `-D_FORTIFY_SOURCE=2` -- runtime buffer overflow checks
- `-fPIE` + `-pie` -- position-independent executable (ASLR)
- `-Wl,-z,relro,-z,now` -- full RELRO (GOT hardening)
- `-Wformat -Wformat-security` -- format string warnings

## Build ID fleet gate

Every `make` run stamps the current git commit hash into the binary as a 16-byte
build ID. Directory authorities reject relay descriptors whose build ID differs
from their own, so the whole fleet must upgrade in lockstep when the build ID
changes. For tarball builds where `.git` is not available, write a `BUILD_ID`
file next to the Makefile containing the full git hash and the build picks it up.

## Easy relay setup

For deploying a relay on a fresh server, `setup.sh` handles everything in one
command: installs dependencies, builds from source, creates a system user,
writes a config file, and starts a systemd service.

```
git clone https://github.com/0xdeadbeefnetwork/MOOR_PQ && cd MOOR_PQ
# read setup.sh first -- it runs as root
sudo ./setup.sh
```

Or non-interactively:

```
sudo ./setup.sh --role exit --nickname MYRELAY --ip 1.2.3.4
```

The script builds the checkout it is run from, so what you read is what gets
installed. Piping it from a URL is no longer supported. If there is no checkout
on the box, `sudo ./setup.sh --fetch <full 40-hex commit id>` clones and
refuses to build anything but that exact commit. The GeoIP database comes from
the distro's `tor-geoipdb` package (verified by apt, extracted without
installing tor), not from a download.

The script supports Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman), and
Alpine (apk). If the system's libsodium is older than 1.0.18, it automatically
builds libsodium 1.0.20 from source before compiling moor.

## Building on Windows (MSYS2 / MinGW)

MOOR can be built on Windows using MSYS2 with the MinGW toolchain. The Makefile
detects MSYS2 and MinGW environments automatically and adds `-lws2_32` (Winsock)
to the link flags.

1. Install [MSYS2](https://www.msys2.org/)
2. Open an MSYS2 MinGW 64-bit shell
3. Install dependencies:

```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-libsodium mingw-w64-x86_64-zlib mingw-w64-x86_64-libevent make pkg-config
```

4. Build:

```
make
```

This produces `moor.exe`.

For cross-compiling from Linux with `x86_64-w64-mingw32-gcc`, you will need
MinGW-built libsodium, zlib, and libevent, and should pass the compiler and
library paths explicitly:

```
make CC=x86_64-w64-mingw32-gcc \
     SODIUM_CFLAGS="-I/path/to/mingw-sodium/include" \
     SODIUM_LIBS="-L/path/to/mingw-sodium/lib -lsodium" \
     EXTRA_LDFLAGS="-lws2_32"
```

## Older systems (Debian Buster, GLIBC 2.28)

Binaries built on newer systems may not run on older ones due to GLIBC version
requirements. The simplest fix is to build directly on the target machine:

```
scp moor-src.tar.gz user@host:~/
ssh user@host 'tar xzf moor-src.tar.gz && cd moor && make'
```

If libsodium is installed but not in the default search path:

```
make SODIUM_LIBS="-lsodium -Wl,-rpath,/usr/lib/x86_64-linux-gnu"
```

## Advanced: sanitizer and analysis targets

These are useful during development but not needed for normal builds.

| Command | What it does |
|---------|-------------|
| `make asan-test` | Rebuild and run tests under AddressSanitizer + UBSan (requires clang) |
| `make tsan-test` | Rebuild and run tests under ThreadSanitizer (requires clang) |
| `make coverage` | Build with gcov instrumentation and generate coverage report |
| `make static-analysis` | Run cppcheck and flawfinder, write reports to `audit/` |
| `make fuzz-build` | Build the libFuzzer harnesses in `fuzz/` (requires clang) |
| `make fuzz` | Build them, then run each for `FUZZ_DURATION` seconds (default 60) |
| `make kat` | Build and run Known Answer Tests for ML-KEM-768 and ML-DSA-65 |
| `make dudect` | Build constant-time validation test |
| `make cbmc` | Run CBMC bounded model checker on crypto functions |
| `make infer` | Run Facebook Infer static analysis |

## Fuzzing

`fuzz/` holds one harness per `fuzz/fuzz_*.c`, and the build follows the directory:
adding a file is all it takes for `make fuzz-build` to pick it up. Four exist, each
wrapping one parser that reads untrusted bytes — `fuzz_descriptor`, `fuzz_consensus`,
`fuzz_cell` and `fuzz_socks5`. Harnesses stub the handful of `main.c` callbacks the
library objects refer to; `fuzz/fuzz_stubs.h` holds them, so a new harness includes
that header and writes only `LLVMFuzzerTestOneInput`.

Two properties of the build matter, and both are easy to get wrong in a way that
produces a campaign that runs but finds nothing:

- The library objects are compiled with `-fsanitize=fuzzer-no-link` as well as
  ASan and UBSan. Without it libFuzzer sees coverage only inside the harness and
  mutates blindly — the symptom is a coverage counter stuck in single digits after
  millions of executions.
- `fuzz_stubs.h` sets the log level to fatal in `LLVMFuzzerInitialize`. The parsers
  log a warning per rejected input, which at fuzzing rates is gigabytes of log per
  worker per hour and leaves the process waiting on writes instead of fuzzing.

A parser with no input-dependent branching (`moor_cell_unpack` and
`moor_relay_unpack` are byte shuffling) saturates within seconds and stays there.
Read a clean run of one of those as "this parser is trivial", not "this parser was
tested hard".

## Tools

`make tools` builds two helper programs:

- **moor_keygen** -- generates relay identity keys. Built from `tools/moor_keygen.c`.
- **moor-top** -- ncurses-based live relay monitor (like `htop` for your relay). Built from `tools/moor-top.c`. Requires ncurses (`libncurses-dev` on Debian).

Both are installed to `BINDIR` by `make install` (moor-top only if it was built).
