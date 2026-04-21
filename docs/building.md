# Building

## Quick start

```
make
```

This produces the `./moor` binary. It dynamically links against libsodium, zlib,
and libevent.

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
| `make tests` | Compile the test suite |
| `make test` | Compile and run all tests |
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
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

Or non-interactively:

```
curl -sL .../setup.sh | sudo bash -s -- --role exit --nickname MYRELAY --ip 1.2.3.4
```

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
| `make fuzz` | Build and run libFuzzer harnesses (requires clang) |
| `make kat` | Build and run Known Answer Tests for ML-KEM-768 and ML-DSA-65 |
| `make dudect` | Build constant-time validation test |
| `make cbmc` | Run CBMC bounded model checker on crypto functions |
| `make infer` | Run Facebook Infer static analysis |

## Tools

`make tools` builds two helper programs:

- **moor_keygen** -- generates relay identity keys. Built from `tools/moor_keygen.c`.
- **moor-top** -- ncurses-based live relay monitor (like `htop` for your relay). Built from `tools/moor-top.c`. Requires ncurses (`libncurses-dev` on Debian).

Both are installed to `BINDIR` by `make install` (moor-top only if it was built).
