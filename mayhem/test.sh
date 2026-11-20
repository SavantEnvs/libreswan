#!/usr/bin/env bash
#
# mayhem/test.sh — runs libreswan's own unit-test programs (testing/programs/*check, built by
# mayhem/build.sh with normal flags; upstream runs them via `make check`). Each program asserts its
# own known-answer tables and exits non-zero on a mismatch; on top of that every program's output
# must contain a known-answer line it prints, so a neutered (no-op) binary fails here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T=OBJ.mayhem-test/testing/programs
passed=0 failed=0

# run <name> <expected output line (fixed string)> <program> [args...]
run() {
  local name="$1" expect="$2"; shift 2
  if [ ! -x "$1" ]; then
    echo "FAIL $name: $1 missing (mayhem/build.sh should have built it)"; failed=$((failed+1)); return
  fi
  local out rc
  out=$("$@" 2>&1 | tr -d '\000'); rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ] && grep -qF -- "$expect" <<<"$out"; then
    echo "PASS $name"; passed=$((passed+1))
  else
    echo "FAIL $name (rc=$rc, expected line: $expect)"; tail -5 <<<"$out"; failed=$((failed+1))
  fi
}

run asn1check     "unwrap_asn1_length_check[21]: ok=yes length=258 left=259" $T/asn1check/_asn1check
run authbycheck   "authby_add(19*,19)"                                    $T/authbycheck/_authbycheck
run dncheck       "-> rfc4514: '2.39.16383=#1306303132333435'"            $T/dncheck/_dncheck
run flagscheck    "flags_has_none()"                                      $T/flagscheck/_flagscheck
run hunkcheck     "check__clone_hunk_as_string[13]: input='ab' output='ab'" $T/hunkcheck/_hunkcheck
run ipcheck       "[::1]:0 TCP [::2]:65535 => [::1]-TCP->[::2]:65535"     $T/ipcheck/_ipcheck --dns=no
run jambufcheck   "check_jam_bytes: ucase('aBc') -> 'ABC'"                $T/jambufcheck/_jambufcheck
run keyidcheck    "leak detective found no leaks"                         $T/keyidcheck/_keyidcheck
run namescheck    "leak detective found no leaks"                         $T/namescheck/_namecheck
run seedbitscheck "seedbits=520"                                          $T/seedbitscheck/_seedbitscheck --seedbits 520
run timecheck     "realtime_cmp(realtime_from_seconds(1000), !=, realtime_from_seconds(1001))) -> yes" $T/timecheck/_timecheck
run ttodatacheck  "0x48656c6c_6f"                                         $T/ttodatacheck/_ttodatacheck 0x48656c6c6f
run vendoridcheck "[strongSwan 2.8.6]"                                    $T/vendoridcheck/_vendoridcheck

emit_ctrf "libreswan-testing-programs" "$passed" "$failed" 0
