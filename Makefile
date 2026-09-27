SUITE := ghoti.io
PROJECT := archive

BUILD ?= release
# The version of this library. MINOR_VERSION carries the minor and the patch as
# one dotted string; the two are split out below for the places that need three
# separate integers. See CONVENTIONS.md section 4.
MAJOR_VERSION := 0
MINOR_VERSION := 0.0
VERSION_MINOR_ONLY := $(word 1,$(subst ., ,$(MINOR_VERSION)))
VERSION_PATCH_ONLY := $(or $(word 2,$(subst ., ,$(MINOR_VERSION))),0)
# Substituted into the .pc file; an empty Version: field makes every
# pkg-config version constraint fail.
VERSION := $(MAJOR_VERSION).$(MINOR_VERSION)

# Names this build everywhere: the .pc file, the install directory, the soname
# and the symbol token. It defaults to the major version, so an ordinary build
# of 1.x is "-1" and two majors cannot be loaded into one process by mistake.
# Override it for a build that wants its own identity:  make BRANCH=-dev
BRANCH ?= -$(MAJOR_VERSION)

# What the library reports as its version. The branch is appended only when it
# is not the default, so an ordinary build says "1.2.3" and an overridden one
# says "1.2.3-dev". Computed before BUILD=debug rewrites BRANCH below.
ifeq ($(BRANCH),-$(MAJOR_VERSION))
VERSION_STRING := $(VERSION)
else
VERSION_STRING := $(VERSION)$(BRANCH)
endif

# If BUILD is debug, append -debug.
#
# "override" because BRANCH may have come from the command line, and a
# command-line variable otherwise wins over a plain assignment here: without it
# `make BRANCH=-dev BUILD=debug` produced a debug build carrying the release
# token, whose symbols collide with the release build's.
ifeq ($(BUILD),debug)
    override BRANCH := $(BRANCH)-debug
    override VERSION_STRING := $(VERSION_STRING)-debug
endif

# The optimisation level, decided here rather than written into CFLAGS.
#
# Two reasons this block is *here*, above the platform rewrite below, rather
# than next to CFLAGS where it is used. `BUILD := linux/$(BUILD)` further down
# is a plain assignment, so a command-line `BUILD=debug` overrides it and BUILD
# stays "debug", while an environment `BUILD=debug` does not and it becomes
# "linux/debug". Testing BUILD up here, before anything rewrites it, is true in
# both cases.
#
# The levels are named rather than inherited, because the suite spent a while
# with the opposite: every library compiled release at -O0 and debug at -O0 as
# well, since the debug block above renames the artifact and changes nothing
# about how anything is compiled. `make BUILD=debug` therefore produced a
# differently-named copy of the release build, and no release build was ever
# optimised. Nobody had decided that - the -O0 predated the repositories and
# was copied in from a project whose production build doubled as its debugger's.
ifeq ($(BUILD),debug)
OPT_CFLAGS := -O0
else
OPT_CFLAGS := -O2
endif

BASE_NAME := lib$(SUITE)-$(PROJECT)$(BRANCH).so
# The symbol namespace token, from BRANCH, so that the token inside every
# exported symbol is the same one that names the .pc file, the install directory
# and the shared library. See CONVENTIONS.md section 4.
LIBVER_SYMBOL := $(shell echo "ghotiio_$(PROJECT)$(BRANCH)" | sed 's/[.-]/_/g')

BASE_NAME_PREFIX := lib$(SUITE)-$(PROJECT)$(BRANCH)
SO_NAME := $(BASE_NAME).$(MAJOR_VERSION)
STATIC_TARGET := $(BASE_NAME_PREFIX).a
ENV_VARS :=

# PC_INSTALL_PATH names where this project's own .pc file is installed.
# PKG_CONFIG_PATH is the environment's and is never assigned here: make exports
# an inherited variable with whatever value the makefile last gave it, so
# overwriting it handed every sub-make a different PKG_CONFIG_PATH from the
# parent's. The sub-make then derived different flags, found the flag stamp
# changed, and rebuilt everything - which check-rebuild reports as a settled
# tree that will not settle. It showed first under MSYS2, whose login shell
# exports PKG_CONFIG_PATH, and happens on Linux whenever the exported value is
# not exactly the install location. cutil made the same change.
PKG_CONFIG_PATH_ENV := $(PKG_CONFIG_PATH)

# `override` on each of those: BUILD may arrive on the command line, and a
# command-line variable beats a plain makefile assignment, so without it
# `make BUILD=debug` skips the rewrite and builds into ./build/debug --
# outside the platform tree, and a different tree from the one plain `make`
# uses. The platform segment exists to keep linux/mac/win builds apart.

# Detect OS
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
	OS_NAME := Linux
	LIB_EXTENSION := so
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG := -Wl,-soname,$(SO_NAME)
	TARGET := $(SO_NAME).$(MINOR_VERSION)
	EXE_EXTENSION :=
	# Additional Linux-specific variables
	PC_INSTALL_PATH := /usr/local/share/pkgconfig
	INCLUDE_INSTALL_PATH := /usr/local/include
	LIB_INSTALL_PATH := /usr/local/lib
	PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
	override BUILD := linux/$(BUILD)

else ifeq ($(UNAME_S), Darwin)
	OS_NAME := Mac
	LIB_EXTENSION := dylib
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG := -Wl,-install_name,$(BASE_NAME_PREFIX).dylib
	TARGET := $(BASE_NAME_PREFIX).dylib
	EXE_EXTENSION :=
	# Additional macOS-specific variables
	PC_INSTALL_PATH := /usr/local/share/pkgconfig
	INCLUDE_INSTALL_PATH := /usr/local/include
	LIB_INSTALL_PATH := /usr/local/lib
	PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
	override BUILD := mac/$(BUILD)

else ifeq ($(findstring MINGW32_NT,$(UNAME_S)),MINGW32_NT)  # 32-bit Windows
	OS_NAME := Windows
	LIB_EXTENSION := dll
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG = -Wl,--out-implib,$(APP_DIR)/$(BASE_NAME_PREFIX).dll.a
	TARGET := $(BASE_NAME_PREFIX).dll
	EXE_EXTENSION := .exe
	# Additional Windows-specific variables
	# This is the path to the pkg-config files on MSYS2
	PC_INSTALL_PATH := /mingw32/lib/pkgconfig
	INCLUDE_INSTALL_PATH := /mingw32/include
	LIB_INSTALL_PATH := /mingw32/lib
	BIN_INSTALL_PATH := /mingw32/bin
	# Windows paths for .pc so gcc invoked by mingw can resolve -I/-L (cygpath for MSYS2)
	PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
	PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
	override BUILD := win32/$(BUILD)

# TODO(windows): the Windows branches in this file were adapted from image's
# and have never been run, nor has GARC_API's dllexport/dllimport switching.
else ifeq ($(findstring MINGW64_NT,$(UNAME_S)),MINGW64_NT)  # 64-bit Windows
	OS_NAME := Windows
	LIB_EXTENSION := dll
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG = -Wl,--out-implib,$(APP_DIR)/$(BASE_NAME_PREFIX).dll.a
	TARGET := $(BASE_NAME_PREFIX).dll
	EXE_EXTENSION := .exe
	# Additional Windows-specific variables
	# This is the path to the pkg-config files on MSYS2
	PC_INSTALL_PATH := /mingw64/lib/pkgconfig
	INCLUDE_INSTALL_PATH := /mingw64/include
	LIB_INSTALL_PATH := /mingw64/lib
	BIN_INSTALL_PATH := /mingw64/bin
	# Windows paths for .pc so gcc invoked by mingw can resolve -I/-L (cygpath for MSYS2)
	PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
	PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
	override BUILD := win64/$(BUILD)

else
    $(error Unsupported OS: $(UNAME_S))

endif

# ---------------------------------------------------------------------------
# Installation prefix
#
# Defaults to the system location chosen above. Override it to install
# somewhere else - the suite's bootstrap installs every library into a local
# prefix so that each build resolves its dependencies through pkg-config,
# exactly as a consumer would, rather than through a second code path that
# only in-tree builds exercise. See CONVENTIONS.md section 1.
#
#     make install PREFIX=/path/to/prefix
# ---------------------------------------------------------------------------
ifdef PREFIX
INCLUDE_INSTALL_PATH := $(PREFIX)/include
LIB_INSTALL_PATH := $(PREFIX)/lib
BIN_INSTALL_PATH := $(PREFIX)/bin
PC_INSTALL_PATH := $(PREFIX)/share/pkgconfig
ifeq ($(OS_NAME), Windows)
PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
else
PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
endif
# A non-system prefix has no /etc/ld.so.conf.d, and writing to it would need
# root anyway. Everything built here carries an rpath to the prefix instead.
LDCONF_INSTALL_PATH :=
endif

# Dependencies are looked up along the inherited PKG_CONFIG_PATH as well as the
# install location chosen above, so that exporting PKG_CONFIG_PATH works as the
# errors below say it does. The inherited value comes first: it is an explicit
# request for this build, where the install location may be only a default.
PKG_CONFIG_LOOKUP_PATH := $(if $(PKG_CONFIG_PATH_ENV),$(PKG_CONFIG_PATH_ENV):)$(PC_INSTALL_PATH)


CXX := g++
CXXFLAGS := -pedantic-errors -Wall -Wextra -Werror -Wno-error=unused-function -Wfatal-errors -std=c++20 -O1 -g $(EXTRA_CXXFLAGS)
CC := cc
# Two flags beyond the suite's shared set, both carried because the suite
# measured what they catch and neither is a nicety.
#
# -Wfloat-conversion is not in -Wall or -Wextra, and catches an *implicit*
# float-to-integer conversion - a double handed to an integer parameter, where
# no cast appears in the source and a grep for "(int32_t)" finds nothing.
# Ghoti.io Tang had one: a float literal passed into a pool keyed by an
# unsigned integer, so 1.5 and 1.0 shared a key. The two instruments do not
# overlap - an explicit cast silences this and is caught at runtime by
# float-cast-overflow instead, and an implicit conversion of an in-range value
# is a wrong answer no sanitizer reports.
#
# -Wstrict-aliasing=1 with -fstrict-aliasing is the suite's only instrument for
# the aliasing class. **No sanitizer reports a strict-aliasing violation at any
# -O**, measured on a minimal pair in model where gcc miscompiles and both
# ASan and UBSan print nothing and exit 0. So this compile-time check is not a
# second opinion on the runtime gates; it is the only opinion.
#
# Three things about the spelling, each of which has bitten somebody:
#
# - **-Wall sets the level to 3 on its own, and 3 is silent** on the plain
#   type-punned dereference that level 1 rejects. So a library at -O2 with
#   `-Wall -Werror` and no level named has the aliasing *optimisation* armed
#   and no warning behind it, which reads from the flag list exactly like a
#   library that is covered. An explicit level beats -Wall's implicit 3 from
#   either side, so the ordering on this line is not load-bearing; a *later*
#   explicit level does beat it, and $(EXTRA_CFLAGS) is last.
# - **-fstrict-aliasing is named because the warning is silent without it**,
#   and gcc enables it only from -O2. Unnamed, the check would be live in the
#   release tree and silently inert in every other tree CFLAGS reaches - the
#   coverage tree, which appends its own -O0, and BUILD=debug.
# - Naming it turns the aliasing *assumption* on where gcc had it off, which is
#   a real change and not only a warning. Whether that changes any codegen is a
#   per-library measurement, not something to inherit: model's 9 objects are
#   instruction-identical with and without it at -O0 and -O1 and differ at -O2.
#   `make check-codegen-aliasing` is not a target here; the way to ask is to
#   compare `objdump -d` output, never whole-object md5, because debug info
#   records the command line and so every object differs whether or not any
#   code does.
#
# The fuzz tree does not read CFLAGS - it builds with clang, at -O1 and with
# -w - and clang implements nothing for -Wstrict-aliasing in any case, so the
# fuzz tree is not a warning gate and under clang this library has no aliasing
# instrument at all. FUZZ_SAN names -fstrict-aliasing separately so its codegen
# assumption is stated rather than inherited.
#
# Building the debug tree needs one flag, because BRANCH becomes `-debug` and
# CUTIL_PC is derived from it, so pkg-config is asked for a ghoti.io-cutil-debug
# that only a whole-suite debug bootstrap installs. Override the name and a
# debug build runs against the ordinary release prefix:
#
#   make BUILD=debug CUTIL_PC=ghoti.io-cutil-$(MAJOR_VERSION) test
CFLAGS := -pedantic-errors -Wall -Wextra -Werror -Wfloat-conversion -fstrict-aliasing -Wstrict-aliasing=1 -Wno-error=unused-function -Wfatal-errors -std=c17 $(OPT_CFLAGS) -g $(EXTRA_CFLAGS)
# Library-specific compile flags (export symbols on Windows, PIC on Linux)
# GARC_BUILD enables DLL export on Windows (checked by GARC_API macro)
# GARC_TEST_BUILD enables export of internal functions for testing (checked by GARC_INTERNAL_API macro)
# No -DGARC_TEST_BUILD: the shipped library exports its public API and nothing
# else. Tests reach the internals by linking the static archive, which a static
# link can do even for hidden symbols.
ifeq ($(OS_NAME), Windows)
# Everything built here but the library itself links the static archive, so
# the headers must not say dllimport to it: an archive has no __imp_ thunks.
# The library's own objects also get GARC_BUILD, which the header tests first.
# See GARC_API in macros.h.
CFLAGS += -DGARC_STATIC
CXXFLAGS += -DGARC_STATIC
endif
LIB_CFLAGS := $(CFLAGS) -fvisibility=hidden -DGARC_BUILD $(EXTRA_CFLAGS)
LDFLAGS := -L /usr/lib -lstdc++ -lm $(EXTRA_LDFLAGS)
ifdef PREFIX
# So that a library, a test or an example finds its Ghoti.io dependencies in the
# prefix at run time without LD_LIBRARY_PATH.
LDFLAGS += -Wl,-rpath,$(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Windows)
# Windows has no rpath: a program finds its DLLs through PATH. Putting the
# prefix's bin/ on it for everything make runs is the equivalent, so that a
# test or an example finds its dependencies without the caller arranging it.
# Without this they die before main() with 0xC0000135 and make reports 127.
export PATH := $(BIN_INSTALL_PATH):$(PATH)
endif
endif

BUILD_DIR := ./build/$(BUILD)
OBJ_DIR := $(BUILD_DIR)/objects
FLAGS_STAMP := $(OBJ_DIR)/.flags
GEN_DIR := $(BUILD_DIR)/generated
APP_DIR := $(BUILD_DIR)/apps


# Add OS-specific flags
ifeq ($(UNAME_S), Linux)
	LIB_CFLAGS += -fPIC

else ifeq ($(UNAME_S), Darwin)

else ifeq ($(findstring MINGW32_NT,$(UNAME_S)),MINGW32_NT)  # 32-bit Windows

else ifeq ($(findstring MINGW64_NT,$(UNAME_S)),MINGW64_NT)  # 64-bit Windows

else
	$(error Unsupported OS: $(UNAME_S))

endif

# The standard include directories for the project.
#
# `-I src/` so that a cross-module internal header is included by the same path
# its include guard is named after - `#include "reader/reader_internal.h"`
# against GHOTI_IO_GARC_SRC_READER_READER_INTERNAL_H. The siblings use relative
# paths (`"../core/number_internal.h"`), which say the same thing in a spelling
# that changes when a file moves and cannot be grepped for.
INCLUDE := -I include/ -I src/ -I $(GEN_DIR)/

# Goals that compile and link nothing.  A missing sibling library must not stop
# them: `make docs` needs doxygen and the tracked sources, not cutil, and it
# was failing at parse time - before doxygen was ever reached - on any machine
# where the suite is not installed.  Every other goal still gets the hard
# error below, which is the point of having no fallback.
# The oracle and corpus goals are here too: they compile and link nothing, and a
# machine that can regenerate the corpus is not necessarily one with the suite
# installed. `make check-corpus` failing at parse time on a missing cutil - before
# it reached a container - was the reason this list grew.
DEPLESS_GOALS := docs docs-pdf clean fuzz-clean cloc help \
	corpus check-corpus check-corpus-hashes check-oracle \
	oracle-build oracle-version
ifeq ($(filter-out $(DEPLESS_GOALS),$(or $(MAKECMDGOALS),all)),)
SKIP_DEP_CHECK := 1
endif

# ghoti.io-cutil, for the allocator vtable. The name must carry $(BRANCH):
# cutil installs its .pc as ghoti.io-cutil-0.pc, so asking for
# "ghoti.io-cutil" never matches. There is no sibling-checkout fallback here or
# anywhere - see the error below.
CUTIL_PC ?= ghoti.io-cutil$(BRANCH)
CUTIL_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --cflags $(CUTIL_PC) 2>/dev/null)
CUTIL_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs $(CUTIL_PC) 2>/dev/null)
# An empty answer means pkg-config could not find it. There is no second
# resolution path to fall back to, so this is a hard error naming the fix.
ifeq ($(strip $(CUTIL_CFLAGS)),)
ifndef SKIP_DEP_CHECK
$(error ghoti.io-cutil was not found by pkg-config. Run ./bootstrap.sh at the root of the workspace - two levels up, the directory holding libs/ - to build and install the suite into a local prefix, then pass the same PREFIX here - or point PKG_CONFIG_PATH at the directory holding its .pc file. There is deliberately no sibling-checkout fallback: a second resolution path that only in-tree builds exercise is one that silently rots.)
endif
endif
INCLUDE += $(CUTIL_CFLAGS)

# Automatically collect all .c source files under the src directory.
SOURCES := $(shell find src -type f -name '*.c')

# Convert each source file path to an object file path.
LIBOBJECTS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

TESTFLAGS := `PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs --cflags gtest`

# The checks `make test` runs besides the tests themselves. Named in a
# variable so that a build which cannot satisfy them can clear it: the
# coverage target does, because --coverage links the gcov runtime, whose
# mangle_path check-symbols is right to reject in a shipping library and
# wrong to reject in an instrumented one. Spelled as text's TEST_GATES is.
TEST_GATES ?= check-symbols check-aliasing check-corpus-hashes check-fixtures

# Valgrind flags (exclude "still reachable" as it's not a leak)
#
# No --suppressions. Nothing here calls into a system facility that leaks on
# its own account - the library allocates through cutil and touches no locale,
# no filesystem and no dynamic loader - so an empty suppression file would be a
# file nobody could tell was doing nothing. Add one when a suppression is
# earned, with the evidence that its frames are narrow enough not to hide a
# leak of our own; see model's tests/valgrind.supp for the shape.
VALGRIND_FLAGS := --leak-check=full --show-leak-kinds=definite,indirect,possible --track-origins=yes --error-exitcode=1

####################################################################
# Test discovery
####################################################################

# Optional shared test helper (if present).
TEST_HELPER_SRC := $(wildcard tests/test_helpers.cpp)
TEST_HELPER_OBJ := $(patsubst tests/%.cpp,$(OBJ_DIR)/tests/%.o,$(TEST_HELPER_SRC))

# The static archive, not -l: a static link resolves hidden symbols, so the
# tests can exercise internals the shared library does not export.
# --whole-archive because anything registering itself from a constructor is
# otherwise dropped - a plain archive link only pulls in object files that
# something references by name.
ARCHIVELIBRARY := -Wl,--whole-archive $(APP_DIR)/$(STATIC_TARGET) -Wl,--no-whole-archive $(CUTIL_LIBS)

# Nothing is wrapped at link time yet. model wraps fprintf here so that its
# FailingSink can fail a write on Windows, which has no fopencookie; this
# library has no _dump to fail a write on until a member exists to dump.
TEST_LDFLAGS :=

# Discover test sources and compute an executable name for each, as
# "path|name" pairs. test_foo.cpp -> testFoo.
TEST_PAIRS := $(shell find tests -type f -name 'test_*.cpp' 2>/dev/null | sort | grep -v test_helpers | while read f; do \
	echo "$$f|$$(basename "$$f" .cpp | sed 's/test_/test/; s/^test\([a-z]\)/test\U\1/')"; done)
TEST_SOURCES := $(foreach pair,$(TEST_PAIRS),$(word 1,$(subst |, ,$(pair))))
TEST_NAMES := $(foreach pair,$(TEST_PAIRS),$(word 2,$(subst |, ,$(pair))))
TEST_EXECUTABLES := $(addprefix $(APP_DIR)/,$(addsuffix $(EXE_EXTENSION),$(TEST_NAMES)))

# Automatically collect all example .c files.
EXAMPLE_SOURCES := $(shell find examples -type f -name '*.c' 2>/dev/null)
EXAMPLES := $(patsubst examples/%.c,$(APP_DIR)/examples/%$(EXE_EXTENSION),$(EXAMPLE_SOURCES))

# Where the test fixtures live. Tests run from build/.../apps, so the path is
# baked in at compile time.
TEST_DATA := $(CURDIR)/tests/data

all: $(APP_DIR)/$(TARGET) $(APP_DIR)/$(STATIC_TARGET) ## Build shared + static libraries

####################################################################
# Dependency Inclusion
####################################################################

TEST_DEPFILES := $(foreach pair,$(TEST_PAIRS),$(OBJ_DIR)/tests/$(basename $(notdir $(word 1,$(subst |, ,$(pair))))).d)
# The ASan tree needs header dependencies as much as the release tree does.
# model shipped without them, and a header change left its objects stale:
# adding a field to GMDL_Limits and running `make test-asan` reported
# "AddressSanitizer: unknown-crash ... in gmdl_limits_default" - a struct
# written by new code into a buffer sized by old code, and a clean rebuild
# passed. That failure mode is worse than a stale result, because the report
# names a source line and accuses working code.
DEPFILES := $(LIBOBJECTS:.o=.d) $(TEST_HELPER_OBJ:.o=.d) $(TEST_DEPFILES)
-include $(DEPFILES)

####################################################################
# Object Files
####################################################################

####################################################################
# Generated version header
####################################################################

LIBVER_GEN := $(GEN_DIR)/ghoti.io/$(PROJECT)/libver_gen.h

# libver_gen.h is regenerated on every build and rewritten only when its content
# changes, so a variable given on the command line - make MAJOR_VERSION=2, or
# make BRANCH=-dev - takes effect. Keying the rule on the Makefile's timestamp
# alone left the previous token and version baked into the build, and nothing
# said so.
.PHONY: force-libver
force-libver:

$(LIBVER_GEN): force-libver
	@if [ -z "$(LIBVER_SYMBOL)" ]; then \
		printf "### LIBVER_SYMBOL is empty ###\n" >&2; \
		printf "Every exported symbol would lose its version namespace.\n" >&2; \
		exit 1; \
	fi
	@mkdir -p $(@D)
	@printf '%s\n' \
		'// Generated by the Makefile. Do not edit; see CONVENTIONS.md section 4.' \
		'#ifndef GHOTI_IO_GARC_LIBVER_GEN_H' \
		'#define GHOTI_IO_GARC_LIBVER_GEN_H' \
		'' \
		'/** The symbol namespace for this build, from the Makefile'"'"'s BRANCH. */' \
		'#define GHOTIIO_ARCHIVE_NAME $(LIBVER_SYMBOL)' \
		'' \
		'/** Human-readable version of this build. */' \
		'#define GHOTIIO_ARCHIVE_VERSION "$(VERSION_STRING)"' \
		'' \
		'/** The same version as three integers. */' \
		'#define GHOTIIO_ARCHIVE_VERSION_MAJOR $(MAJOR_VERSION)' \
		'#define GHOTIIO_ARCHIVE_VERSION_MINOR $(VERSION_MINOR_ONLY)' \
		'#define GHOTIIO_ARCHIVE_VERSION_PATCH $(VERSION_PATCH_ONLY)' \
		'' \
		'#endif // GHOTI_IO_GARC_LIBVER_GEN_H' > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi

$(OBJ_DIR)/%.o: src/%.c $(FLAGS_STAMP) | $(LIBVER_GEN)
	@printf "\n### Compiling $@ ###\n"
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

####################################################################
# Shared Library
####################################################################

$(APP_DIR)/$(TARGET): $(LIBOBJECTS)
	@printf "\n### Compiling Archive Library ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -shared -o $@ $^ $(LDFLAGS) $(CUTIL_LIBS) $(OS_SPECIFIC_LIBRARY_NAME_FLAG)

ifeq ($(OS_NAME), Linux)
	@ln -f -s $(TARGET) $(APP_DIR)/$(SO_NAME)
	@ln -f -s $(SO_NAME) $(APP_DIR)/$(BASE_NAME)
endif

####################################################################
# Static Library
####################################################################

$(APP_DIR)/$(STATIC_TARGET): $(LIBOBJECTS)
	@printf "\n### Archiving Static Archive Library ###\n"
	@mkdir -p $(@D)
	@rm -f $@
	ar rcs $@ $^

####################################################################
# Unit Tests
####################################################################

ifneq ($(TEST_HELPER_SRC),)
$(TEST_HELPER_OBJ): $(TEST_HELPER_SRC) $(FLAGS_STAMP)
	@printf "\n### Compiling Test Helper ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@
endif

# Test sources live in tests/ and tests/unit/; the object name comes from the
# basename either way, so the executable name matches.
$(OBJ_DIR)/tests/%.o: tests/%.cpp $(FLAGS_STAMP)
	@printf "\n### Compiling Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -Itests -DGARC_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(OBJ_DIR)/tests/%.o: tests/unit/%.cpp $(FLAGS_STAMP)
	@printf "\n### Compiling Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -Itests -DGARC_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

# Build rule for one test executable. $1 = source path, $2 = executable name.
# Tests compile to .o first and link separately, so a library change relinks
# without recompiling every test.
#
# The archive is a normal prerequisite because that is what the link line
# uses, and a change to the library therefore relinks the tests. Naming only
# the shared library here - which is what this rule used to do - left nothing
# in the chain that builds the archive, so `make test` failed outright on a
# clean tree and raced under -j. The .so is order-only: it is not linked, but
# check-symbols and the test run both want it built.
define test-executable-rule
TEST_OBJ_$1 := $(OBJ_DIR)/tests/$(basename $(notdir $1)).o

$(APP_DIR)/$2$(EXE_EXTENSION): $$(TEST_OBJ_$1) $(TEST_HELPER_OBJ) \
		$(APP_DIR)/$(STATIC_TARGET) | $(APP_DIR)/$(TARGET)
	@printf "\n### Linking Test: $2 ###\n"
	@mkdir -p $$(@D)
	$(CXX) $(CXXFLAGS) -o $$@ $$(TEST_OBJ_$1) $(TEST_HELPER_OBJ) $(LDFLAGS) $(TEST_LDFLAGS) $(ARCHIVELIBRARY) $(CUTIL_LIBS) $(TESTFLAGS)
endef

$(foreach pair,$(TEST_PAIRS),\
	$(eval $(call test-executable-rule,$(word 1,$(subst |, ,$(pair))),$(word 2,$(subst |, ,$(pair))))))

####################################################################
# Examples
####################################################################

# Links the archive, so it depends on the archive; see test-executable-rule.
$(APP_DIR)/examples/%$(EXE_EXTENSION): examples/%.c $(APP_DIR)/$(STATIC_TARGET) \
		$(FLAGS_STAMP) | $(APP_DIR)/$(TARGET)
	@printf "\n### Compiling Example: $* ###\n"
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS) $(ARCHIVELIBRARY) $(CUTIL_LIBS)

####################################################################
# Commands
####################################################################

# General commands
.PHONY: clean cloc docs docs-pdf examples coverage check-symbols check-aliasing
.PHONY: check-corpus-hashes check-corpus corpus oracle-build oracle-version
.PHONY: check-oracle
# Release build commands
.PHONY: all install test test-quiet test-asan test-valgrind test-valgrind-quiet test-watch uninstall watch
# Debug build commands
.PHONY: all-debug install-debug test-debug test-valgrind-debug test-watch-debug uninstall-debug watch-debug
# Fuzz commands
.PHONY: fuzz fuzz-clean

watch: ## Watch the file directory for changes and compile the target
	@while true; do \
		make --no-print-directory all; \
		printf "\033[0;32m\n"; \
		printf "#########################\n"; \
		printf "# Waiting for changes.. #\n"; \
		printf "#########################\n"; \
		printf "\033[0m\n"; \
		inotifywait -qr -e modify -e create -e delete -e move src include tests Makefile --exclude '/\.'; \
		done

test-watch: ## Watch the file directory for changes and run the unit tests
	@while true; do \
		make --no-print-directory all; \
		make --no-print-directory test; \
		printf "\033[0;32m\n"; \
		printf "#########################\n"; \
		printf "# Waiting for changes.. #\n"; \
		printf "#########################\n"; \
		printf "\033[0m\n"; \
		inotifywait -qr -e modify -e create -e delete -e move src include tests Makefile --exclude '/\.'; \
		done

examples: ## Build all examples
examples: $(APP_DIR)/$(TARGET) $(EXAMPLES)
	@printf "\033[0;32m\n"
	@printf "############################\n"
	@printf "### Examples built       ###\n"
	@printf "############################\n"
	@printf "\033[0m\n"
	@printf "Examples are available in: $(APP_DIR)/examples/\n"
	@printf "\n"
	@printf "\033[0;33mTo run examples:\033[0m\n"
ifeq ($(OS_NAME), Linux)
	@printf "  Linux: Set LD_LIBRARY_PATH to include the library directory:\n"
	@printf "    export LD_LIBRARY_PATH=\"$(TEST_LD_PATH)\"\n"
	@printf "    $(APP_DIR)/examples/<example>\n"
else ifeq ($(OS_NAME), Mac)
	@printf "  macOS: Set DYLD_LIBRARY_PATH to include the library directory:\n"
	@printf "    export DYLD_LIBRARY_PATH=\"$(TEST_LD_PATH)\"\n"
	@printf "    $(APP_DIR)/examples/<example>\n"
else ifeq ($(OS_NAME), Windows)
	@printf "  Windows (MSYS2): The DLL must be in the same directory or in PATH.\n"
	@printf "    cd $(APP_DIR) && ./examples/<example>$(EXE_EXTENSION)\n"
endif
	@printf "\n"

# So the tests can load the archive library and its dependency on cutil. cutil's
# build tree has no release/debug component, so only the leading OS component
# of BUILD applies to it.
TEST_LD_PATH := $(APP_DIR):$(LIB_INSTALL_PATH)/$(SUITE)

####################################################################
# Symbol namespace check
####################################################################

check-aliasing: ## Fail if the strict-aliasing warning is not actually armed
# CFLAGS names -fstrict-aliasing and -Wstrict-aliasing=1, and neither spelling
# tells you the level that results. -Wall sets the level to 3 on its own, an
# explicit level beats it from either side, and a later explicit level beats
# that - so the resolved level depends on the whole command line, and
# $(EXTRA_CFLAGS) sits at the end of it. `make EXTRA_CFLAGS=-Wstrict-aliasing=3`
# builds this library with the aliasing optimisation armed and the warning
# silent, every flag still present and every comment about them still true.
#
# So ask the compiler instead of the flag list: compile a violation with the
# real $(CFLAGS) and require the diagnostic. That reads the level the command
# line resolves to, which no review of the spelling can do. The design is the
# chron session's, and the measurements below are the chron, model and image
# sessions' - reproduced here by this gate passing, not re-derived.
#
# ---- Do not simplify the probe. Its shape is what makes it discriminating.
#
# The probe pins the level at exactly 1: level 1 reports this shape, and 0, 2
# and 3 are all silent on it. Diagnostics at -O2, counted across five violation
# shapes:
#
#                                                      L0  L1  L2  L3
#   cast of a pointer PARAMETER      <- this probe       0   1   0   0
#   struct-to-struct cast of a parameter                 0   1   0   0
#   a void * stored through a typed lvalue               0   1   1   0
#   *(int *)&local, *(long *)&s->member                  0   2   2   2
#   laundered through a `void * v = p` variable          0   0   0   0
#
# Written the obvious way, `*(int *)&local`, this gate would pass with the
# warning at level 3 and certify nothing - row four is reported at every level
# from 1 up. A later tidy-up that "simplifies" the probe therefore silently
# removes the only thing it measures. Measured in model rather than argued:
# with the probe rewritten that way, `make EXTRA_CFLAGS=-Wstrict-aliasing=3
# check-aliasing` exits 0 - the one case the gate exists to catch, passing
# green.
#
# Two axes decide those rows, and they matter if this library ever moves off
# level 1. Taking the address of an object the compiler can see is what level 2
# needs; routing the cast through a separate pointer variable is what defeats
# level 3. So this probe certifies level 1 and **would be vacuous at level 2**:
# green, asserting nothing. A gate meant to certify "1 or 2, but not 3" needs a
# known object reached through a variable instead.
#
# Two limits bound what a green run may be said to mean. Level 3 is not blind
# in general - it catches row four - so a sibling library sitting at 3 is not
# uninstrumented, it is blind to rows one to three. And **nothing catches row
# five at any level**, including 1: a clean run here is not evidence about
# punning laundered through a void * variable, which is the spelling real code
# reaches for most readily.
#
# So a silent probe has three different causes and they want opposite fixes,
# which is why the failure branch *measures* the cause rather than naming the
# likeliest one. A gate whose diagnosis is one step off sends the next reader
# after something that is not wrong, and they will trust it because the gate was
# right to fire:
#
#   $(CC) reports no level at all   a compiler that accepts the option and
#                                   implements nothing. clang does this, so
#                                   under clang there is no instrument here -
#                                   and no sanitizer covers the class either.
#   $(CC) reports 0, 2 or 3         the level is wrong; the flags are present.
#                                   3 is also what -Wall implies, so it is an
#                                   override or a removal and this cannot say
#                                   which - it says so rather than guessing.
#   $(CC) reports 1                 the level is right and it still did not
#                                   fire, which nothing here explains. Suspect
#                                   the probe or the compiler, not CFLAGS.
#
# Reading the level needs its own guard: an empty answer is not a level. clang
# exits 1 and prints nothing, and a flag string gcc rejects produces the same
# empty output - so the exit status and a non-empty level are both checked
# before the number is believed.
#
# The clean file is the control and it does two jobs. It must compile *and* be
# silent: if both files failed for an unrelated reason - a bad -I, a missing
# header - the probe's grep would find nothing, and a gate that only asked "no
# diagnostic on the clean one" would pass while measuring nothing.
	@mkdir -p $(BUILD_DIR)
	@printf 'int garc_alias_probe(float * f);\nint garc_alias_probe(float * f) { int * i = (int *)f; *i = 7; return *i; }\n' > $(BUILD_DIR)/alias_probe.c
	@printf 'int garc_alias_clean(int * i);\nint garc_alias_clean(int * i) { *i = 7; return *i; }\n' > $(BUILD_DIR)/alias_clean.c
	@probe=$$($(CC) $(CFLAGS) -Wno-error -c $(BUILD_DIR)/alias_probe.c -o $(BUILD_DIR)/alias_probe.o 2>&1); \
	ctl=$$($(CC) $(CFLAGS) -Wno-error -c $(BUILD_DIR)/alias_clean.c -o $(BUILD_DIR)/alias_clean.o 2>&1); ctlrc=$$?; \
	if [ $$ctlrc -ne 0 ]; then \
		printf '\033[0;31mcheck-aliasing: the control file did not compile, so this gate is measuring nothing:\033[0m\n%s\n' "$$ctl" >&2; \
		exit 1; \
	fi; \
	if printf '%s' "$$ctl" | grep -q 'strict-aliasing'; then \
		printf '\033[0;31mcheck-aliasing: the control file drew a strict-aliasing diagnostic, so the probe proves nothing:\033[0m\n%s\n' "$$ctl" >&2; \
		exit 1; \
	fi; \
	if printf '%s' "$$probe" | grep -q 'strict-aliasing'; then \
		printf 'check-aliasing: the planted violation is reported; the warning is armed at the level CFLAGS resolves to\n'; \
		exit 0; \
	fi; \
	qout=$$($(CC) -Q --help=warnings $(CFLAGS) 2>/dev/null); qrc=$$?; \
	level=$$(printf '%s' "$$qout" | awk '/-Wstrict-aliasing=</{print $$2}'); \
	if [ $$qrc -ne 0 ] || [ -z "$$level" ]; then \
		printf '\033[0;31mcheck-aliasing: the planted violation drew no diagnostic, and $(CC) reports no -Wstrict-aliasing level at all. That is a compiler which accepts the option and implements nothing - clang does exactly this - so the flags are intact and there is no aliasing instrument behind them. No sanitizer covers this class at any -O, so under this compiler the library has none.\033[0m\n' >&2; \
	elif [ "$$level" = 1 ]; then \
		printf '\033[0;31mcheck-aliasing: $(CC) reports -Wstrict-aliasing=1 and the planted violation still drew no diagnostic. The level is right and the warning did not fire, which neither the flags nor the level explains - suspect the probe or the compiler version before touching CFLAGS.\033[0m\n' >&2; \
	else \
		printf '\033[0;31mcheck-aliasing: CFLAGS resolves to -Wstrict-aliasing=%s, and only level 1 reports the planted store - 0, 2 and 3 are all silent on it. The level is wrong; the flags are not missing. Note that 3 is also what -Wall implies, so it means either an explicit override later on the command line or ALIASING flags that stopped being passed, and this cannot tell which.\033[0m\n' "$$level" >&2; \
	fi; \
	exit 1
check-symbols: ## Fail if any exported symbol lacks the version namespace
check-symbols: $(APP_DIR)/$(TARGET)
ifeq ($(OS_NAME), Linux)
	@leaked=$$(nm -D --defined-only $(APP_DIR)/$(TARGET) \
		| awk '$$2 ~ /^[TDBR]$$/ {print $$3}' \
		| grep -v '^$(LIBVER_SYMBOL)_' | grep -v '^_' || true); \
	if [ -n "$$leaked" ]; then \
		printf "\033[0;31m\n### Exported symbols missing the $(LIBVER_SYMBOL)_ namespace ###\033[0m\n" >&2; \
		printf "%s\n" "$$leaked" >&2; \
		printf "\nEach needs a '#define <name> GHOTIIO_ARCHIVE(<name>)' line in namespace.h.\n" >&2; \
		printf "See CONVENTIONS.md section 4.\n" >&2; \
		exit 1; \
	fi
	@unexported=$$(find include -name '*.h' -exec awk '/^#if DOXYGEN/{d=1} d==0 && /^[a-z_][A-Za-z0-9_ ]*\**[[:space:]]*garc_[a-z0-9_]+[[:space:]]*\(/{print FILENAME": "$$0} /^#endif/{d=0}' {} + \
		| grep -vE 'typedef|static inline' || true); \
	if [ -n "$$unexported" ]; then \
		printf "\033[0;31m\n### Public declarations without GARC_API ###\033[0m\n" >&2; \
		printf "%s\n" "$$unexported" >&2; \
		printf "\nThese are hidden in the shared library. The tests link the archive and\n" >&2; \
		printf "would not notice; a consumer gets an undefined reference.\n" >&2; \
		exit 1; \
	fi
	@split=$$(nm -D --undefined-only $(APP_DIR)/$(TARGET) \
		| awk '{print $$2}' | grep '^$(LIBVER_SYMBOL)_' || true); \
	if [ -n "$$split" ]; then \
		printf "\033[0;31m\n### Renamed but undefined - a split symbol ###\033[0m\n" >&2; \
		printf "%s\n" "$$split" >&2; \
		printf "\nA translation unit referenced the namespaced name while the one that\n" >&2; \
		printf "defines it did not see the rename - usually an internal header that\n" >&2; \
		printf "declares or defines something without including macros.h first.\n" >&2; \
		exit 1; \
	fi
	@nomacros=$$(find include src -name '*.h' \
		! -name 'libver.h' ! -name 'libver_gen.h' ! -name 'namespace.h' ! -name 'macros.h' \
		-exec grep -L '#include <ghoti.io/archive/macros.h>' {} + || true); \
	if [ -n "$$nomacros" ]; then \
		printf "\033[0;31m\n### Headers that do not include macros.h ###\033[0m\n" >&2; \
		printf "%s\n" "$$nomacros" >&2; \
		printf "\nEvery header must include <ghoti.io/archive/macros.h> before it declares\n" >&2; \
		printf "anything, so that the renames in namespace.h are already in effect. A\n" >&2; \
		printf "header that skips it can name a type before that type has been renamed,\n" >&2; \
		printf "producing two different types under one spelling.\n" >&2; \
		printf "See CONVENTIONS.md section 4.\n" >&2; \
		exit 1; \
	fi
	@badguards=$$(find include src -name '*.h' -exec awk 'FNR==1{d=0} !d && /^#ifndef/{print $$2; d=1}' {} + \
		| awk '$$1 !~ /^GHOTI_IO_GARC_/ {print $$1}' || true); \
	if [ -n "$$badguards" ]; then \
		printf "\033[0;31m\n### Include guards with the wrong prefix ###\033[0m\n" >&2; \
		printf "%s\n" "$$badguards" >&2; \
		printf "\nGuards mirror the path: GHOTI_IO_GARC_<PATH>_H. A guard without the\n" >&2; \
		printf "library token is one rename away from colliding with another library's.\n" >&2; \
		exit 1; \
	fi
	@dupguards=$$(find include src -name '*.h' -exec awk 'FNR==1{d=0} !d && /^#ifndef/{print $$2; d=1}' {} + \
		| sort | uniq -d || true); \
	if [ -n "$$dupguards" ]; then \
		printf "\033[0;31m\n### Headers sharing an include guard ###\033[0m\n" >&2; \
		printf "%s\n" "$$dupguards" >&2; \
		printf "\nTwo headers with one guard means whichever is included second is\n" >&2; \
		printf "silently empty. Guards mirror the path: GHOTI_IO_GARC_<PATH>_H.\n" >&2; \
		exit 1; \
	fi
	@printf "\033[0;32mEvery exported symbol carries the $(LIBVER_SYMBOL)_ namespace.\033[0m\n"
	@printf "\033[0;32mEvery public declaration carries GARC_API.\033[0m\n"
	@printf "\033[0;32mEvery header includes macros.h.\033[0m\n"
	@printf "\033[0;32mEvery include guard is unique and correctly prefixed.\033[0m\n"
else
	@printf "check-symbols: skipped (Linux only)\n"
endif

test: ## Make and run the unit tests
test: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES) $(TEST_GATES)
# `|| exit 1` is what makes this a gate at all. Without it the loop ran every
# binary and discarded every exit status, so `make test` returned 0 whatever
# happened - a failing assertion, a segfault, a sanitizer abort. The failure
# was visible only as "[  FAILED  ]" text in the log, which meant anything
# scoring this target had to read the log, and a crash prints no such line at
# all. Measured in the siblings this loop was copied from: a deliberate
# EXPECT_EQ(1, 2) gave exit 0, and so did a null dereference.
	@for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		printf "\033[0;30;43m\n"; \
		printf "############################\n"; \
		printf "### Running %s tests ###\n" "$$test_name"; \
		printf "############################"; \
		printf "\033[0m\n\n"; \
		LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$test_exe --gtest_brief=1 || exit 1; \
	done

test-quiet: ## Run tests with minimal output (one line per test suite)
test-quiet: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES)
	@total_tests=0; total_passed=0; total_failed=0; total_time=0; failed_suites=""; \
	printf "\n\033[1;36m%-30s %8s %10s %s\033[0m\n" "Test Suite" "Tests" "Time" "Status"; \
	printf "\033[1;36m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		output=$$(LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$test_exe --gtest_brief=1 2>&1); \
		exit_code=$$?; \
		num_tests=$$(echo "$$output" | grep -oP '\[\s*=+\s*\]\s*\K\d+(?=\s+tests?)' | head -1); \
		time_ms=$$(echo "$$output" | grep -oP '\(\K\d+(?=\s*ms\s*total\))' | head -1); \
		[ -z "$$num_tests" ] && num_tests=0; \
		[ -z "$$time_ms" ] && time_ms=0; \
		total_tests=$$((total_tests + num_tests)); \
		total_time=$$((total_time + time_ms)); \
		if [ $$exit_code -eq 0 ]; then \
			total_passed=$$((total_passed + num_tests)); \
			printf "%-30s %8d %8dms \033[0;32mPASS\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms"; \
		else \
			failures=$$(echo "$$output" | grep -oP '\[\s*FAILED\s*\]\s*\K\d+' | head -1); \
			[ -z "$$failures" ] && failures=$$num_tests; \
			total_failed=$$((total_failed + failures)); \
			total_passed=$$((total_passed + num_tests - failures)); \
			printf "%-30s %8d %8dms \033[0;31mFAIL\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms"; \
			failed_suites="$$failed_suites\n\033[0;31m=== $$test_name FAILURES ===\033[0m\n$$output\n"; \
		fi; \
	done; \
	printf "\033[1;36m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	if [ $$total_failed -eq 0 ]; then \
		printf "\033[0;32m%-30s %8d %6dms PASS\033[0m\n\n" "TOTAL" "$$total_tests" "$$total_time"; \
	else \
		printf "\033[0;31m%-30s %8d %6dms FAIL (%d failed)\033[0m\n" "TOTAL" "$$total_tests" "$$total_time" "$$total_failed"; \
		printf "$$failed_suites\n"; \
		exit 1; \
	fi

test-valgrind: ## Run all tests under valgrind (Linux only)
test-valgrind: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES)
# VALGRIND_FLAGS carries --error-exitcode=1, so valgrind reports a leak or an
# invalid access in its status - and the loop used to discard it, along with
# the test binary's own. See the note on `test`.
ifeq ($(OS_NAME), Linux)
	@for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		printf "\033[0;30;43m\n"; \
		printf "############################\n"; \
		printf "### Running %s tests under Valgrind ###\n" "$$test_name"; \
		printf "############################"; \
		printf "\033[0m\n\n"; \
		LD_LIBRARY_PATH="$(TEST_LD_PATH)" valgrind $(VALGRIND_FLAGS) $$test_exe --gtest_brief=1 || exit 1; \
	done
else
	@printf "\033[0;31m\nValgrind is only available on Linux\n\033[0m\n"
	@exit 1
endif

# test-valgrind-quiet passes only when both the tests pass and Valgrind is
# clean, so a FAIL here can mean an assertion failure even with no leaks.
test-valgrind-quiet: ## Run tests under valgrind with minimal output (Linux only)
test-valgrind-quiet: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES)
ifeq ($(OS_NAME), Linux)
	@total_tests=0; total_failed=0; total_time=0; failed_suites=""; \
	printf "\n\033[1;35m%-30s %8s %10s %s\033[0m\n" "Test Suite (Valgrind)" "Tests" "Time" "Status"; \
	printf "\033[1;35m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		output=$$(LD_LIBRARY_PATH="$(TEST_LD_PATH)" valgrind $(VALGRIND_FLAGS) $$test_exe --gtest_brief=1 2>&1); \
		exit_code=$$?; \
		num_tests=$$(echo "$$output" | grep -oP '\[\s*=+\s*\]\s*\K\d+(?=\s+tests?)' | head -1); \
		time_ms=$$(echo "$$output" | grep -oP '\(\K\d+(?=\s*ms\s*total\))' | head -1); \
		[ -z "$$num_tests" ] && num_tests=0; \
		[ -z "$$time_ms" ] && time_ms=0; \
		total_tests=$$((total_tests + num_tests)); \
		total_time=$$((total_time + time_ms)); \
		has_leak=$$(echo "$$output" | grep -c "are definitely lost\|are indirectly lost\|are possibly lost" || true); \
		if [ $$exit_code -eq 0 ] && [ $$has_leak -eq 0 ]; then \
			printf "%-30s %8d %8dms \033[0;32mPASS\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms"; \
		else \
			if [ $$has_leak -gt 0 ]; then status_msg="LEAK"; else status_msg="FAIL"; fi; \
			total_failed=$$((total_failed + 1)); \
			printf "%-30s %8d %8dms \033[0;31m%s\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms" "$$status_msg"; \
			failed_suites="$$failed_suites\n\033[0;31m=== $$test_name FAILURES ===\033[0m\n$$output\n"; \
		fi; \
	done; \
	printf "\033[1;35m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	if [ $$total_failed -eq 0 ]; then \
		printf "\033[0;32m%-30s %8d %6dms PASS\033[0m\n\n" "TOTAL" "$$total_tests" "$$total_time"; \
	else \
		printf "\033[0;31m%-30s %8d %6dms FAIL (%d suites)\033[0m\n" "TOTAL" "$$total_tests" "$$total_time" "$$total_failed"; \
		printf "$$failed_suites\n"; \
		exit 1; \
	fi
else
	@printf "\033[0;31m\nValgrind is only available on Linux\n\033[0m\n"
	@exit 1
endif

####################################################################
# Sanitizer build (ASan + UBSan): separate build dir, run the test suite
####################################################################
# -fno-sanitize-recover: without it UBSan PRINTS a diagnostic and carries on,
# so the process still exits 0 and the suite reports clean over undefined
# behaviour it just described. A gate that cannot fail is not a gate.
#
# float-cast-overflow is named separately because GCC does NOT put it in the
# `undefined` group - and so `-fno-sanitize-recover=undefined` does not reach
# it either. Measured: a cast of 1e30 to int under `-fsanitize=undefined
# -fno-sanitize-recover=undefined` printed nothing and exited 0, and with this
# flag it reports. Converting a float that does not fit is undefined
# behaviour. Nothing here converts a float today - every field of every
# container this library will read is an integer - so the flag is carried
# because it costs nothing and fails the build the day that stops being true,
# rather than because it is watching something. The same reasoning does not
# extend to float-divide-by-zero, which IEEE defines.
UBSAN_CHECKS := undefined,float-cast-overflow
# The gate's own -O, pinned rather than inherited. ASAN_CFLAGS starts from
# $(CFLAGS), so without this the sanitizer tree silently tracks the release
# level - it is -O2 today because the release build is, and it would become
# -O3 the day that did, with nobody deciding it.
#
# The argument for inheriting is that strict-aliasing and signed-overflow
# assumptions are inert at -O0 and live at -O2, so a UB gate should run at the
# level that ships. That is true about the *optimiser* and says nothing about
# what the *sanitizer sees*, and the two weld into one sentence very easily.
# The text session made that argument, measured it, and withdrew it; model
# re-measured on its own ASAN_CFLAGS rather than copying the table, one defect
# per program so that halting at the first finding cannot hide a later one:
#
#                          -O1         -O2
#   heap-use-after-free    caught      caught
#   heap-buffer-overflow   caught      caught
#   stack-buffer-overflow  caught      caught
#   use-after-scope        caught      caught
#   signed overflow        caught      caught
#   float-cast overflow    caught      caught
#   strict aliasing        NOT caught  NOT caught
#
# Nothing the sanitizer can see depends on the level, so inheriting never
# bought the coverage the argument implied. The last row is the one that
# decides it: aliasing is the hazard the argument names, and no sanitizer in
# this toolchain reports it at any level - check-aliasing exists because of
# that, and it is where that class has to be caught.
#
# use-after-scope was in that table because the optimiser can dissolve the
# scope it depends on; it did not differ either.
#
# What pinning buys here. FUZZ_SAN is -O1, so the gate and the fuzzers share
# one codegen and a fuzz artifact reproduces under test-asan without a level
# change in between. And the gate stops moving silently when the release level
# moves.
#
# For a trace that needs reading, `make test-asan BUILD=debug
# CUTIL_PC=ghoti.io-cutil-0` gives -O0. Trace quality is NOT the argument
# here: text measured the reports identical frame for frame and did not claim
# it, and neither does this.
ASAN_UBSAN_FLAGS := -fsanitize=address,$(UBSAN_CHECKS) -fno-sanitize-recover=$(UBSAN_CHECKS) -fno-omit-frame-pointer -g -O1
# The instrumented-coverage tree, kept apart from the release objects for the
# same reason the sanitizer ones are: a plain `make` must never be able to
# find an object built with flags it did not ask for.
COV_BUILD_DIR := ./build/$(BUILD)-cov

ASAN_BUILD_DIR := ./build/$(BUILD)-asan
ASAN_OBJ_DIR := $(ASAN_BUILD_DIR)/objects
ASAN_FLAGS_STAMP := $(ASAN_OBJ_DIR)/.flags
ASAN_APP_DIR := $(ASAN_BUILD_DIR)/apps

ASAN_LIBOBJECTS := $(patsubst src/%.c,$(ASAN_OBJ_DIR)/%.o,$(SOURCES))

# The ASan tree needs header dependencies as much as the release tree does.
# See the release DEPFILES comment above for the failure model had without
# them: a stale object reported as "unknown-crash" inside working code.
#
# This sits HERE, after ASAN_LIBOBJECTS, and not with the release DEPFILES
# near the top. `:=` expands immediately, so up there ASAN_LIBOBJECTS is
# still empty and the list came out blank - which looks exactly like a
# working fix, since a no-op build is 0 either way. What tells them apart is
# editing a header and counting: 0 before, and every dependent object after.
ASAN_DEPFILES := $(ASAN_LIBOBJECTS:.o=.d) \
    $(foreach pair,$(TEST_PAIRS),$(ASAN_OBJ_DIR)/tests/$(basename $(notdir $(word 1,$(subst |, ,$(pair))))).d)
-include $(ASAN_DEPFILES)
ASAN_TARGET := $(BASE_NAME_PREFIX)-asan.$(LIB_EXTENSION)
ASAN_ARCHIVELIBRARY := -L $(ASAN_APP_DIR) -l$(SUITE)-$(PROJECT)$(BRANCH)-asan

ASAN_CFLAGS := $(CFLAGS) $(ASAN_UBSAN_FLAGS) -DGARC_BUILD -DGARC_TEST_BUILD
ASAN_CXXFLAGS := $(CXXFLAGS) $(ASAN_UBSAN_FLAGS)
ASAN_LDFLAGS := $(LDFLAGS) $(ASAN_UBSAN_FLAGS)
ifeq ($(UNAME_S), Linux)
	ASAN_CFLAGS += -fPIC
endif

$(ASAN_OBJ_DIR)/%.o: src/%.c $(ASAN_FLAGS_STAMP)
	@printf "\n### Compiling (ASan+UBSan): $< ###\n"
	@mkdir -p $(@D)
	$(CC) $(ASAN_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(ASAN_APP_DIR)/$(ASAN_TARGET): $(ASAN_LIBOBJECTS)
	@printf "\n### Linking ASan+UBSan Archive Library ###\n"
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) -shared -o $@ $^ $(ASAN_LDFLAGS) $(CUTIL_LIBS)

$(ASAN_OBJ_DIR)/tests/%.o: tests/%.cpp $(ASAN_FLAGS_STAMP)
	@printf "\n### Compiling ASan Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) $(INCLUDE) -Itests -DGARC_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(ASAN_OBJ_DIR)/tests/%.o: tests/unit/%.cpp $(ASAN_FLAGS_STAMP)
	@printf "\n### Compiling ASan Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) $(INCLUDE) -Itests -DGARC_TEST_DATA=\"$(TEST_DATA)\" -c $< -MMD -MP -MF $(@:.o=.d) -o $@

define asan-test-executable-rule
ASAN_TEST_OBJ_$1 := $(ASAN_OBJ_DIR)/tests/$(basename $(notdir $1)).o

$(ASAN_APP_DIR)/$2$(EXE_EXTENSION): $$(ASAN_TEST_OBJ_$1) $(ASAN_APP_DIR)/$(ASAN_TARGET)
	@printf "\n### Linking ASan Test: $2 ###\n"
	@mkdir -p $$(@D)
	$(CXX) $(ASAN_CXXFLAGS) -o $$@ $$(ASAN_TEST_OBJ_$1) $(ASAN_LDFLAGS) $(ASAN_ARCHIVELIBRARY) $(CUTIL_LIBS) $(TESTFLAGS)
endef

$(foreach pair,$(TEST_PAIRS),\
	$(eval $(call asan-test-executable-rule,$(word 1,$(subst |, ,$(pair))),$(word 2,$(subst |, ,$(pair))))))

ASAN_TEST_EXECUTABLES := $(addprefix $(ASAN_APP_DIR)/,$(addsuffix $(EXE_EXTENSION),$(TEST_NAMES)))

# ASan insists on being the first library loaded. A desktop session that sets
# LD_PRELOAD for its own reasons (libgtk3-nocsd, for instance) puts something
# ahead of it and every sanitized binary refuses to start, so put the runtime
# back in front rather than discarding whatever the user had set.
ASAN_RUNTIME := $(shell $(CC) -print-file-name=libasan.so 2>/dev/null)

test-asan: ## Build with ASan+UBSan and run the test suite
test-asan: $(ASAN_TEST_EXECUTABLES)
	@for test_exe in $(ASAN_TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		printf "\033[0;30;43m\n### Running %s (ASan+UBSan) ###\033[0m\n\n" "$$test_name"; \
		LD_PRELOAD="$(ASAN_RUNTIME)$${LD_PRELOAD:+:$$LD_PRELOAD}" \
		LD_LIBRARY_PATH="$(ASAN_APP_DIR):$(LIB_INSTALL_PATH)/$(SUITE)" \
			$$test_exe --gtest_brief=1 || exit 1; \
	done
	@printf "\033[0;32m\nASan+UBSan suite clean.\033[0m\n"

####################################################################
# Fuzzing (libFuzzer)
####################################################################
#
# The library is rebuilt with -fsanitize=fuzzer-no-link rather than linking the
# ordinary shared library. That matters: libFuzzer steers its mutations by the
# coverage it observes, and a harness linked against an uninstrumented library
# sees none of the parser's branches, which leaves it generating random input
# rather than exploring the format.
FUZZ_CC ?= clang
FUZZ_CXX ?= clang++
FUZZ_CC_OK := $(shell which $(FUZZ_CC) 2>/dev/null)
# -fstrict-aliasing is named here for the same reason it is named in CFLAGS.
# This line does not read CFLAGS, so without it the fuzz tree's aliasing
# assumption would be whatever the fuzzing compiler happens to default to - and
# that default is not gcc's. Measured in model on clang 19.1.7: the assumption
# is already on at -O1 and -O2 and off at -O0, where gcc has it off until -O2,
# so naming it changed none of its objects.
#
# It stays because the alternative is a tree whose codegen assumption is
# inherited from a compiler default, differs between the two compilers this
# Makefile can use, and is invisible on the command line. The warning half is
# deliberately absent: this line carries -w, so the fuzz tree reports nothing
# and is not a warning gate. Matching the assumption is the point; matching
# the diagnostics is not.
FUZZ_SAN := -fsanitize=address,$(UBSAN_CHECKS) -fno-omit-frame-pointer -g -O1 -fstrict-aliasing
FUZZ_LIB_FLAGS := $(FUZZ_SAN) -fsanitize=fuzzer-no-link
FUZZ_BIN_FLAGS := $(FUZZ_SAN) -fsanitize=fuzzer
FUZZ_DIR := $(BUILD_DIR)/fuzz
FUZZ_OBJ_DIR := $(FUZZ_DIR)/objects
FUZZ_FLAGS_STAMP := $(FUZZ_OBJ_DIR)/.flags
FUZZ_APP_DIR := $(FUZZ_DIR)/apps
FUZZ_OBJECTS := $(patsubst src/%.c,$(FUZZ_OBJ_DIR)/%.o,$(SOURCES))
FUZZ_CORPUS := tests/fuzz/corpus

# A smoke-test length by default; for a real campaign: make fuzz FUZZ_TIME=3600
FUZZ_TIME ?= 60

# The fuzz tree needs header dependencies as much as the release and ASan trees
# do, and it went without them until a run found out. The failure is worse here
# than a stale answer: a fuzz object built against one revision of a struct,
# linked with one built against the next, is a **binary with two layouts for the
# same object**. What that produced was an ASan heap-buffer-overflow eight bytes
# past the archive, in code that was correct - reader.c's object still had the
# struct from before a field was added, so it allocated the old size, and the
# writer of the new field ran off the end of it.
#
# That is the most expensive shape a gate can have: a finding that is real, is
# reported against a line that is not wrong, and cannot be reproduced from a
# clean tree. `make clean` does not touch this directory either (fuzz-clean
# does), so the staleness survives the check that would otherwise have shown it.
#
# As in the ASan tree, FUZZ_DEPFILES sits after FUZZ_OBJECTS: `:=` expands
# immediately, so above that line the list is empty and the -include is a no-op
# that looks exactly like a working fix. The way to tell them apart is to touch
# a header and count what rebuilds.
$(FUZZ_OBJ_DIR)/%.o: src/%.c $(FUZZ_FLAGS_STAMP)
	@mkdir -p $(@D)
	@$(FUZZ_CC) $(FUZZ_LIB_FLAGS) -std=c17 -w $(INCLUDE) -c $< \
		-MMD -MP -MF $(@:.o=.d) -o $@

FUZZ_DEPFILES := $(FUZZ_OBJECTS:.o=.d)
-include $(FUZZ_DEPFILES)

# $1 = harness basename (fuzz_stream), $2 = target suffix (stream)
define fuzz-rule
fuzz-$2: ## Build the $2 fuzz harness (requires clang)
fuzz-$2: $$(FUZZ_APP_DIR)/$1

$$(FUZZ_APP_DIR)/$1: tests/fuzz/$1.cpp $$(FUZZ_OBJECTS) $$(FUZZ_FLAGS_STAMP)
	@if [ -z "$$(FUZZ_CC_OK)" ]; then \
		echo "fuzzing requires $$(FUZZ_CXX); install clang or set FUZZ_CC/FUZZ_CXX"; \
		exit 1; \
	fi
	@mkdir -p $$(@D) $$(FUZZ_CORPUS)/$2
	@printf "\n### Building fuzz harness: $1 ###\n"
	$$(FUZZ_CXX) $$(FUZZ_BIN_FLAGS) -std=c++20 -w $$(INCLUDE) \
		-o $$@ $$< $$(FUZZ_OBJECTS) $(CUTIL_LIBS)

fuzz-run-$2: ## Run the $2 fuzzer for $$(FUZZ_TIME) seconds
fuzz-run-$2: $$(FUZZ_APP_DIR)/$1
	@mkdir -p $$(FUZZ_CORPUS)/$2
	@printf "\n### Fuzzing $2 for $$(FUZZ_TIME)s ###\n"
	@LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$(FUZZ_APP_DIR)/$1 $$(FUZZ_CORPUS)/$2 \
		-max_total_time=$$(FUZZ_TIME) -print_final_stats=1
endef

# One list, read twice: once to generate each harness's rules and once for the
# aggregate target below. Two lists is how a harness comes to exist, build, and
# never be run by `make fuzz` - which adding the writer harness demonstrated, by
# building and passing while the aggregate still named three.
FUZZ_HARNESSES := stream tar name writer

$(foreach harness,$(FUZZ_HARNESSES),\
	$(eval $(call fuzz-rule,fuzz_$(harness),$(harness))))

fuzz: ## Build and run every fuzzer for $(FUZZ_TIME) seconds each
fuzz: $(addprefix fuzz-run-,$(FUZZ_HARNESSES))

fuzz-clean: ## Remove the fuzz build (keeps the corpus)
	-@rm -rf $(FUZZ_DIR)

####################################################################
# Oracles and the corpus
####################################################################
#
# **Two gates, and the split is the point.** Hashing the committed fixtures needs
# nothing but sha256, so `check-corpus-hashes` is in TEST_GATES and runs on every
# machine. Regenerating them needs the pinned image, so `check-corpus` is
# separate and fails closed without it - its only caller is somebody who typed
# the target. A gate that skipped when the image was absent would make a machine
# with no engine look exactly like one where the references still agree.
#
# What each can and cannot see:
#
#   check-corpus-hashes  a fixture edited, truncated, or dropped by a merge.
#                        **Not** a fixture and its hash edited together; nothing
#                        local can see that.
#   check-corpus         the references no longer producing these bytes, which is
#                        what a raised pin looks like and is a finding to triage
#                        rather than a hash to update.
#   check-oracle         the committed expectations no longer matching what the
#                        live references say about the committed bytes. Distinct
#                        from check-corpus: this one re-reads, that one re-writes,
#                        and a reference can change its reading without changing
#                        its writing.

ORACLE := tools/oracle
ORACLE_RUN := python3 $(ORACLE)/oracle_run.py
ORACLE_IMAGE := localhost/ghoti-archive-oracle-tars:deb13

oracle-build: ## Build the pinned tar, bsdtar and python3 image
	docker build -t $(ORACLE_IMAGE) \
		-f $(ORACLE)/containers/tars/Containerfile \
		$(ORACLE)/containers/tars

oracle-version: ## Print which references would answer, and fail if none would
	@GHOTI_ORACLE_REQUIRED=1 $(ORACLE_RUN) tar,bsdtar,pytarfile -- true

check-corpus-hashes: ## Fail if a committed fixture is not what CORPUS names
	@python3 tools/check_corpus.py

check-fixtures: ## Fail if a test input is excluded from the repository
# Needs git and nothing else, so it is in TEST_GATES beside the hash check rather
# than behind the container. The failure it catches leaves `git status` clean and
# only shows up in somebody else's clone - see tools/check_fixtures.py.
	@python3 tools/check_fixtures.py

corpus: ## Regenerate tests/data/tar/ and containers/CORPUS in the container
	@GHOTI_ORACLE_REQUIRED=1 $(ORACLE_RUN) tar,bsdtar,pytarfile -- \
		python3 $(ORACLE)/make_corpus.py

check-corpus: ## Fail if the pinned references no longer produce the corpus
	@GHOTI_ORACLE_REQUIRED=1 $(ORACLE_RUN) tar,bsdtar,pytarfile -- \
		python3 $(ORACLE)/make_corpus.py --check

check-oracle: ## Fail if the live references disagree with the committed manifest
	@GHOTI_ORACLE_REQUIRED=1 $(ORACLE_RUN) tar,bsdtar,pytarfile -- \
		python3 $(ORACLE)/check_manifest.py

####################################################################
# Install / uninstall
####################################################################

# Where the loader configuration fragment is written. Kept overridable so a
# staged or user-prefix install has somewhere to write it.
LDCONF_INSTALL_PATH ?= /etc/ld.so.conf.d

# What goes in the .pc Requires: field. Built from the same variables the
# compile uses, so a dependency on another branch cannot be named one way for
# the build and another way for consumers.
PC_REQUIRES := $(CUTIL_PC)

# Where this project's own .pc file is installed.
PKGCONFIG_INSTALL_PATH ?= $(PC_INSTALL_PATH)


install: ## Install the library globally, requires sudo
# Depends on all: install used to copy whatever happened to be in the build
# directory, so it could install a stale artifact or fail outright on a clean
# tree.
install: all
	# Installing the shared library.
	@mkdir -p $(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Linux)
	@cp $(APP_DIR)/$(TARGET) $(LIB_INSTALL_PATH)/$(SUITE)/
	@ln -f -s $(TARGET) $(LIB_INSTALL_PATH)/$(SUITE)/$(SO_NAME)
	@ln -f -s $(SO_NAME) $(LIB_INSTALL_PATH)/$(SUITE)/$(BASE_NAME)
	# Installing the ld configuration file.
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then mkdir -p $(LDCONF_INSTALL_PATH); fi
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then echo "$(LIB_INSTALL_PATH)/$(SUITE)" > $(LDCONF_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).conf; fi
endif
ifeq ($(OS_NAME), Windows)
# The .dll goes in bin/, where the loader finds it once that directory is on
# PATH - Windows has no rpath. The import library goes where the .pc's -L
# points, lib/$(SUITE)/, as the .so does on Linux; in lib/ no -L named it.
	@mkdir -p $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH)/$(SUITE)
	@cp $(APP_DIR)/$(TARGET).a $(LIB_INSTALL_PATH)/$(SUITE)/
	@cp $(APP_DIR)/$(TARGET) $(BIN_INSTALL_PATH)/
endif
	# Installing the headers.
	# Removed first: this directory is owned entirely by this project and
	# branch, and copying over the top of it would leave headers behind that
	# have since been renamed or deleted.
	@rm -rf $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@mkdir -p $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@if [ -d include/ghoti.io ]; then \
		cp -r include/ghoti.io $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)/ ; \
	fi
	@if [ -d $(GEN_DIR)/ghoti.io ]; then \
		cp -r $(GEN_DIR)/ghoti.io $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)/ ; \
	fi
	# Installing the pkg-config files.
	@mkdir -p $(PKGCONFIG_INSTALL_PATH)
	@cat pkgconfig/$(SUITE)-$(PROJECT).pc | sed 's/(SUITE)/$(SUITE)/g; s/(PROJECT)/$(PROJECT)/g; s/(BRANCH)/$(BRANCH)/g; s/(VERSION)/$(VERSION)/g; s|(PC_LIB_DIR)|$(PC_LIB_DIR)|g; s|(PC_INCLUDE_DIR)|$(PC_INCLUDE_DIR)|g; s|(REQUIRES)|$(PC_REQUIRES)|g' > $(PKGCONFIG_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).pc
ifeq ($(OS_NAME), Linux)
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then ldconfig >> /dev/null 2>&1; fi
endif
	@echo "Ghoti.io $(PROJECT)$(BRANCH) installed"

uninstall: ## Delete the globally-installed files.  Requires sudo.
ifeq ($(OS_NAME), Linux)
	@rm -f $(LIB_INSTALL_PATH)/$(SUITE)/$(BASE_NAME)*
	@rm -f $(LDCONF_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).conf
endif
ifeq ($(OS_NAME), Windows)
	@rm -f $(LIB_INSTALL_PATH)/$(SUITE)/$(TARGET).a
	@rm -f $(BIN_INSTALL_PATH)/$(TARGET)
endif
	@rm -rf $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@rm -f $(PKGCONFIG_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).pc
	@rmdir --ignore-fail-on-non-empty $(INCLUDE_INSTALL_PATH)/$(SUITE)
	@rmdir --ignore-fail-on-non-empty $(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Linux)
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then ldconfig >> /dev/null 2>&1; fi
endif
	@echo "Ghoti.io $(PROJECT)$(BRANCH) has been uninstalled"

debug: ## Build the project in DEBUG mode
	make all BUILD=debug

install-debug: ## Install the DEBUG library globally, requires sudo
	make install BUILD=debug

uninstall-debug: ## Delete the DEBUG globally-installed files.  Requires sudo.
	make uninstall BUILD=debug

test-debug: ## Make and run the Unit tests in DEBUG mode
	make test BUILD=debug

test-valgrind-debug: ## Run all tests under valgrind in DEBUG mode (Linux only)
	make test-valgrind BUILD=debug

watch-debug: ## Watch the file directory for changes and compile the target in DEBUG mode
	make watch BUILD=debug

test-watch-debug: ## Watch the file directory for changes and run the unit tests in DEBUG mode
	make test-watch BUILD=debug

docs: ## Generate the documentation in the ./docs subdirectory
	doxygen

docs-pdf: docs ## Generate the documentation as a pdf, at ./docs/(SUITE)-(PROJECT)(BRANCH).pdf
	cd ./docs/latex/ && make
	mv -f ./docs/latex/refman.pdf ./docs/$(SUITE)-$(PROJECT)$(BRANCH)-docs.pdf

cloc: ## Count the lines of code used in the project
	cloc src include tests Makefile

coverage: ## Build instrumented, run the tests, and report line coverage
# The instrumented build has a tree of its own, the way the sanitizer builds
# do, and that is the whole of the safety here. It used to share the ordinary
# object tree and clean before and after, which works right up until somebody
# runs the instrumented build by hand instead of through this target.
#
# What happens then is worth spelling out, because the obvious check says the
# tree is fine. The --coverage objects stay behind carrying undefined
# __gcov_* references, but the .so built alongside them was linked WITH
# --coverage, so it resolves them and `nm -D --undefined-only` reports it
# clean. Nothing looks wrong. The contamination is latent in the objects: a
# later plain `make` finds them newer than their sources, does not rebuild
# them, and the first time it has any reason to RELINK it produces a .so with
# three undefined gcov symbols. bootstrap.sh installs that, and every
# downstream library fails to link.
#
# That happened in the workspace, to a sibling. It broke the shared prefix for
# every library and was found by a second project failing to link, not by
# anything in the library that caused it - measured afterwards: instrumented
# object 3 gcov refs, the .so beside it 0, the same .so after a relink 3.
#
# So this is no longer a rule to remember. The release tree is not touched at
# all, there is nothing to clean up afterwards, and the hand-rolled shortcut
# that caused it - wanting the .gcov files, which this target used to destroy
# on its way out - no longer needs taking.
#
# The .gcda counters are removed first rather than the objects: gcov merges
# profiles across runs, so a stale one from a previous source revision reports
# against lines that have moved. The objects themselves are make's business.
	@rm -rf $(COV_BUILD_DIR)/objects/*.gcda \
		$(COV_BUILD_DIR)/objects/*/*.gcda 2> /dev/null || true
# TEST_GATES is cleared because --coverage links the gcov runtime, which
# exports mangle_path. check-symbols is right to reject that in a shipping
# build and wrong to reject it here, and it made this target fail before it
# ever produced a report.
	@status=0; \
	$(MAKE) --no-print-directory test TEST_GATES= \
		BUILD_DIR=$(COV_BUILD_DIR) \
		EXTRA_CFLAGS="--coverage -O0" \
		EXTRA_LDFLAGS="--coverage" > /dev/null || status=$$?; \
	if [ $$status -eq 0 ]; then \
		tools/coverage.sh $(COV_BUILD_DIR)/objects || status=$$?; \
	else \
		printf "coverage: the instrumented test run failed; no report\n" >&2; \
	fi; \
	exit $$status

clean: ## Remove all contents of the build directories.
	-@rm -rvf $(COV_BUILD_DIR)
	-@rm -rvf $(OBJ_DIR)/*
	-@rm -rvf $(APP_DIR)/*
	-@rm -rvf $(GEN_DIR)/*
	-@rm -rvf $(ASAN_BUILD_DIR)

help: ## Display this help
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' Makefile | sort | sed 's/\\([^:]*\\):.*## \\(.*\\)/\\1:\\2/' | awk -F: '{printf "%-20s %s\n", $$1, $$2}' | sed "s/(SUITE)/$(SUITE)/g; s/(PROJECT)/$(PROJECT)/g; s/(BRANCH)/$(BRANCH)/g"


####################################################################
# Flag stamps
####################################################################
# Each build tree carries the flag string it was built with. The stamp is
# rewritten only when that string differs -- written to a scratch file,
# compared, moved into place only on a difference -- so its mtime moves on a
# flag change and on nothing else. The object rules above depend on it.
#
# This replaces listing `Makefile` as a prerequisite, which was too broad (a
# comment-only edit recompiled everything) and too narrow (a command-line
# override such as `make EXTRA_CFLAGS=-O2` changes no file's mtime and so was
# invisible).
#
# These rules sit at the end of the file for two reasons. A rule's target
# expands when make reads the line, so a stamp rule above its own OBJ_DIR
# definition has an empty target: not an error, just a rule that silently does
# not exist. And the first target in a makefile is the default goal, so a stamp
# rule above `all:` makes a bare `make` build the stamp and nothing else.
# Each stamp must record the variables its own recipes expand, not the ones
# they are derived from. The release stamp recorded $(CFLAGS) while the
# library objects compile with $(LIB_CFLAGS); changing a flag that lives only
# in LIB_CFLAGS -- -fvisibility=hidden, -DGARC_BUILD -- then moves no recorded
# string and rebuilds nothing. Measured in model, whose stamp had exactly that
# defect: 0 compiles, where naming Makefile as a prerequisite had rebuilt all
# 10. That is strictly worse than having no stamp, because a rebuild that does
# not happen looks exactly like a build that was already current. Arm the null
# case before believing a 0 here.
#
# The compiler belongs in the string too. `make CC=clang` is a command-line
# override that changes every object and no file's mtime, which is precisely
# the case these stamps exist for.
#
# The check is mechanical and is not yet automated here: for each rule guarded
# by a stamp, every $(VAR) its recipe expands must appear in that stamp. model
# runs it from tools/check-lists.py, which is where to take it from when this
# library has a second list worth checking.
.PHONY: force-flags

$(FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CXX) $(LIB_CFLAGS) $(CFLAGS) $(CXXFLAGS) $(LDFLAGS) $(INCLUDE) $(TEST_DATA) $(ARCHIVELIBRARY) $(CUTIL_LIBS) $(TESTFLAGS) $(TEST_LDFLAGS) $(OS_SPECIFIC_LIBRARY_NAME_FLAG)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

$(ASAN_FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CXX) $(ASAN_CFLAGS) $(ASAN_CXXFLAGS) $(ASAN_LDFLAGS) $(INCLUDE) $(TEST_DATA) $(ASAN_ARCHIVELIBRARY) $(CUTIL_LIBS) $(TESTFLAGS)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

# `-MMD -MP` is in this string literally, and it is the one flag here that is not
# a variable. Two reasons, and the second is why it is worth the oddity:
#
#   - The rule above the stamps says every flag a guarded recipe passes belongs in
#     its stamp, and these are flags the recipe passes.
#   - Without it, adding the depfile flags to the recipe moves nothing in this
#     string, so no existing tree rebuilds - and a fuzz object compiled before the
#     change still has no `.d`, so it goes on ignoring header edits forever. The
#     fix would be armed only for someone who happened to run `make fuzz-clean`.
#     Putting the flags here makes the stamp differ exactly once, which rebuilds
#     the tree that needs it and then stays quiet.
#
# The release and ASan stamps have the same omission and it costs nothing there,
# because those trees have carried depfiles since they were written. Adding the
# flags to their strings would force a full rebuild to record a fact that is
# already true, so they are left alone.
$(FUZZ_FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(FUZZ_CC) $(FUZZ_CXX) $(FUZZ_SAN) $(FUZZ_LIB_FLAGS) $(FUZZ_BIN_FLAGS) $(INCLUDE) $(CUTIL_LIBS) -MMD -MP' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@
