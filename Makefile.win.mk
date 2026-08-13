# Makefile.win.mk — Windows (MinGW-w64) build settings for MOOR.
#
# Usage: add this line to the existing Makefile, immediately after the
# `-include config.mk` line at the top:
#
#     -include Makefile.win.mk
# On non-Windows hosts every variable below stays untouched, so the POSIX
# build is bit-identical to before.

# ---- host/target detection -------------------------------------------------
# Detect a Windows *target* from the compiler, not from `uname`: that makes
# native MinGW, MSYS2 and Linux->Windows cross-compiles all take this path.
CC_MACHINE := $(shell $(CC) -dumpmachine 2>/dev/null)
IS_WINDOWS := $(findstring mingw,$(CC_MACHINE))

ifneq ($(IS_WINDOWS),)

EXEEXT = .exe

# ---- compile flags ---------------------------------------------------------
# -include moor/compat_win.h : force the portability layer into every TU so no
#     source file needs an #include added.  compat_win.c is excluded below.
# -Icompat/win               : POSIX header shims (sys/socket.h, poll.h, ...)
#     so sources that include them unconditionally still compile.
# __USE_MINGW_ANSI_STDIO     : link MinGW's C99 printf.  msvcrt's printf has
#     no %zu and MOOR uses it in ~35 places.  Pairs with the gnu_printf
#     archetype on moor_log_impl in include/moor/log.h.
# _WIN32_WINNT=0x0601        : Windows 7 baseline — WSAPoll, inet_ntop/pton.
WIN_CFLAGS = -Icompat/win -include moor/compat_win.h \
             -D__USE_MINGW_ANSI_STDIO=1 -D_WIN32_WINNT=0x0601 \
             -DWIN32_LEAN_AND_MEAN

EXTRA_CFLAGS += $(WIN_CFLAGS)

# ---- linker ----------------------------------------------------------------
# -pie/-z relro/-rdynamic are ELF-only; the PE equivalents are below.
#   --dynamicbase  : ASLR
#   --nxcompat     : DEP
#   --high-entropy-va : 64-bit ASLR
# ws2_32  : Winsock.  bcrypt : BCryptGenRandom (compat_win.c socketpair cookie).
# advapi32: registry read in the uname() shim.
WIN_LDFLAGS = -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va \
              -lws2_32 -lbcrypt -ladvapi32 -liphlpapi

# Strip the ELF-only hardening flags the base Makefile sets.
LDFLAGS := $(filter-out -pie -rdynamic -Wl$(comma)-z$(comma)relro$(comma)-z$(comma)now,$(LDFLAGS))
LDFLAGS += $(WIN_LDFLAGS)

# ---- sources ---------------------------------------------------------------
SOURCES += $(SRCDIR)/compat_win.c

# compat_win.c defines the wrappers the macros point at, so it must NOT be
# built with the redirect macros active or each wrapper recurses into itself.
$(OBJDIR)/compat_win.o: $(SRCDIR)/compat_win.c
	@mkdir -p $(OBJDIR)
	$(CC) $(filter-out -include moor/compat_win.h,$(CFLAGS)) -c $< -o $@

# ---- things that do not exist on Windows -----------------------------------
# sandbox.c already guards on __linux__ and transparent.c on _WIN32, so both
# compile to no-ops.  zlib is stubbed in node.c under _WIN32; drop -lz.
ZLIB_LIBS =

endif  # IS_WINDOWS

comma := ,
