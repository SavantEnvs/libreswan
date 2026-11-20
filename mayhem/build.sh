#!/usr/bin/env bash
#
# mayhem/build.sh — libreswan: sanitized libswan.a + liblswtool.a and the libFuzzer harnesses in
# mayhem/harnesses/, plus upstream's own unit-test programs (testing/programs/*check) built with the
# project's normal flags for mayhem/test.sh. Runs as `mayhem` in /mayhem; re-runnable and offline
# (NSS/NSPR/libevent come from apt in the image; nothing is fetched).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS
cd "$SRC"

# UBSan: two checks are relaxed, each because it fires on a benign pattern on nearly every input
# and would stop every fuzz run at once. ASan and every other UBSan check stay on and halting.
#  - nonnull-attribute: libswan calls memcmp()/memcpy() with (NULL, 0) for empty hunks (e.g.
#    same_dn() on the empty DN of `%fromcert`, lib/libswan/x509dn.c).
#  - shift-base: include/names.h defines NAME_FLAGS as (0x3 << 30) on an int, evaluated by every
#    sparse-name lookup (each ipsec.conf keyword with named values, lib/libswan/sparse_names.c).
SAN="$SANITIZER_FLAGS"
[ -z "$SAN" ] || SAN="$SAN -fno-sanitize=nonnull-attribute,shift-base"

# Optional features that need daemons/libraries the harnesses don't use are switched off; the
# rest (IKEv1, all algorithms, XFRM headers) keep upstream's defaults.
FEATURES=(USE_DNSSEC=false USE_SYSTEMD_WATCHDOG=false USE_LIBCURL=false USE_AUTHPAM=false
	  USE_LIBCAP_NG=false USE_LDAP=false USE_SECCOMP=false USE_LABELED_IPSEC=false
	  USE_LINUX_AUDIT=false USE_NSS_KDF=false)

# 1) Sanitized + coverage-instrumented libraries (libswan.a, liblswtool.a). libreswan's make takes extra flags through
#    USERCOMPILE/USERLINK (overriding USERLAND_CFLAGS would drop its -DUSE_* defines).
#    OBJ.* is gitignored upstream, so `git clean -ffdX` removes these build dirs.
FUZZ_OBJ=OBJ.mayhem-fuzz
make -j"$MAYHEM_JOBS" "${FEATURES[@]}" OBJDIR="$FUZZ_OBJ" CC="$CC" OPTIMIZE_CFLAGS=-O1 \
	USERCOMPILE="$SAN $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
	USERLINK="$SAN -fsanitize=fuzzer-no-link" \
	-C lib base

# The harnesses must see the same -D USE_* defines as libswan.a (struct layouts depend on them).
read -r -a DEFS <<< "$(make -s -C mayhem/harnesses -f flags.mk "${FEATURES[@]}" OBJDIR="$FUZZ_OBJ" print-cflags \
	| tr ' ' '\n' | grep -E '^(-D|-std=|-pthread)' | grep -v FORTIFY | tr '\n' ' ')"
NSS_CFLAGS=$(pkg-config --cflags nss)
NSS_LIBS=$(pkg-config --libs nss)
LIBS=("$FUZZ_OBJ/lib/liblswtool/liblswtool.a" "$FUZZ_OBJ/lib/libswan/libswan.a"
      "$FUZZ_OBJ/lib/liblswtool/liblswtool.a" "$FUZZ_OBJ/lib/libswan/libswan.a")

HOBJ="$FUZZ_OBJ/mayhem"
mkdir -p "$HOBJ"
$CC $SAN $DEBUG_FLAGS -c mayhem/harnesses/lsan_off.c -o "$HOBJ/lsan_off.o"
$CC $SAN $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$HOBJ/standalone_main.o"

# 1b) pluto, the IKE daemon, with the same flags plus UBSan `null` relaxed for pluto's objects only:
#     its notify-response path computes &ike->sa.<field> with ike == NULL when answering an
#     unsolicited message (open_v2_message(), programs/pluto/ikev2_message.c), an address-only
#     member access that fires on most IKEv2 packets. A real NULL dereference still SEGVs under ASan.
SAN_PLUTO="$SAN"
[ -z "$SAN_PLUTO" ] || SAN_PLUTO="$SAN_PLUTO -fno-sanitize=null"
make -j"$MAYHEM_JOBS" "${FEATURES[@]}" OBJDIR="$FUZZ_OBJ" CC="$CC" OPTIMIZE_CFLAGS=-O1 \
	USERCOMPILE="$SAN_PLUTO $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
	USERLINK="$SAN_PLUTO -fsanitize=fuzzer-no-link" \
	-C programs/pluto base
# pluto has no library: link every object except plutomain.o (the daemon's main()) and
# kernel_iface_linux.o (the host interface scan; the harness reports a fixed lo 127.0.0.1 so it
# does not depend on the sandbox's network devices).
PLUTO_OBJS=()
for o in "$FUZZ_OBJ"/programs/pluto/*.o; do
	case "$(basename "$o")" in
	plutomain.o|kernel_iface_linux.o) ;;
	*) PLUTO_OBJS+=("$o") ;;
	esac
done
$CC $SAN_PLUTO $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -Iinclude -Iprograms/pluto -I"$FUZZ_OBJ/programs/pluto" \
	-Iexternal/linux-xfrm-headers $NSS_CFLAGS "${DEFS[@]}" -DHERE_FILENAME='"mayhem/harnesses/fuzz_pluto_ike.c"' \
	-c mayhem/harnesses/fuzz_pluto_ike.c -o "$HOBJ/fuzz_pluto_ike.o"
PLUTO_LIBS=("$FUZZ_OBJ/lib/libswan/libswan.a" "$FUZZ_OBJ/lib/libswan/libswan.a"
	    -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4 -levent -levent_pthreads -lpthread -lrt -lcrypt -lm)
$CC $SAN_PLUTO $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$HOBJ/fuzz_pluto_ike.o" "${PLUTO_OBJS[@]}" "$HOBJ/lsan_off.o" \
	"${PLUTO_LIBS[@]}" -o /mayhem/fuzz_pluto_ike
$CC $SAN_PLUTO $DEBUG_FLAGS "$HOBJ/standalone_main.o" "$HOBJ/fuzz_pluto_ike.o" "${PLUTO_OBJS[@]}" "$HOBJ/lsan_off.o" \
	"${PLUTO_LIBS[@]}" -o /mayhem/fuzz_pluto_ike-standalone

HARNESSES=(fuzz_ipsecconf fuzz_secrets fuzz_proposals fuzz_dn fuzz_id fuzz_ip
	   fuzz_pubkey_der fuzz_ttodata fuzz_whack)
for h in "${HARNESSES[@]}"; do
	$CC $SAN $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -Iinclude -Ilib/libswan $NSS_CFLAGS "${DEFS[@]}" \
		-DHERE_FILENAME="\"mayhem/harnesses/$h.c\"" -c "mayhem/harnesses/$h.c" -o "$HOBJ/$h.o"
	$CC $SAN $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$HOBJ/$h.o" "$HOBJ/lsan_off.o" "${LIBS[@]}" \
		$NSS_LIBS -lrt -lm -o "/mayhem/$h"
	$CC $SAN $DEBUG_FLAGS "$HOBJ/standalone_main.o" "$HOBJ/$h.o" "$HOBJ/lsan_off.o" "${LIBS[@]}" \
		$NSS_LIBS -lrt -lm -o "/mayhem/$h-standalone"
done

# 2) Upstream's unit-test programs (testing/programs/*check), normal flags, separate OBJDIR.
#    (Plain `make` here: env CFLAGS are not read by libreswan's makefiles.)
TEST_OBJ=OBJ.mayhem-test
make -j"$MAYHEM_JOBS" "${FEATURES[@]}" OBJDIR="$TEST_OBJ" CC="$CC" \
	USERCOMPILE="$COVERAGE_FLAGS" USERLINK="$COVERAGE_FLAGS" -C lib base
make -j"$MAYHEM_JOBS" "${FEATURES[@]}" OBJDIR="$TEST_OBJ" CC="$CC" \
	USERCOMPILE="$COVERAGE_FLAGS" USERLINK="$COVERAGE_FLAGS" -C testing/programs base
echo "build.sh: done"
