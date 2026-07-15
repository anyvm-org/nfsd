#!/bin/bash
# pynfs NFSv4.0 / NFSv4.1 / NFSv4.2 conformance run against a
# known-failures baseline.
#
# Runs the pynfs servertests suite against nfsd.py and compares the set of
# failing test codes with the per-minor-version baseline file:
#   - a failure NOT in the baseline is a REGRESSION -> exit 1
#   - a baseline entry that now passes is reported (tighten the baseline)
#
# usage: bash test/conformance.sh [port]
# env:   MINOR     (default 0) - 0 = pynfs nfs4.0, 1 = nfs4.1,
#                  2 = the nfs4.1 suite driven with --minorversion=2, which
#                  is how pynfs covers 4.2 (same suite, 4.2 compounds, plus
#                  its own 4.2-specific tests)
#        PYNFS_DIR (default /tmp/pynfs) - pynfs checkout, cloned if missing
#        REPO      (default: parent of this script) - nfsd-py checkout
set +e
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${REPO:-$(dirname "$HERE")}
PORT=${1:-12061}
MINOR=${MINOR:-0}
PYNFS_DIR=${PYNFS_DIR:-/tmp/pynfs}
if [ "$MINOR" = "2" ]; then
  SUITE=nfs4.1
  MINOR_ARGS=--minorversion=2
  BASELINE="$REPO/test/pynfs42-known-failures.txt"
  MIN_PASS=100
elif [ "$MINOR" = "1" ]; then
  SUITE=nfs4.1
  MINOR_ARGS=--minorversion=1
  BASELINE="$REPO/test/pynfs41-known-failures.txt"
  MIN_PASS=100
else
  SUITE=nfs4.0
  MINOR_ARGS=
  BASELINE="$REPO/test/pynfs-known-failures.txt"
  MIN_PASS=400
fi
OUT=/tmp/pynfs-conformance.txt
LOG=/tmp/nfsdpy-conformance.log

# --- get and build pynfs ---
# The suite ships only .x files; setup.py runs xdrgen to emit the generated
# *_const/_type/_pack modules (rpc.rpc_const, xdrdef.nfs4_const, ...). Build
# whenever those generated modules are absent -- idempotent and quick.
if [ ! -d "$PYNFS_DIR" ]; then
  git clone --depth 1 https://github.com/kofemann/pynfs "$PYNFS_DIR" || exit 1
fi
if ! python3 -c "import sys; sys.path.insert(0, '$PYNFS_DIR/nfs4.0'); \
sys.path.insert(0, '$PYNFS_DIR/nfs4.0/lib'); import rpc.rpc_const" 2>/dev/null; then
  echo "building pynfs (xdrgen) ..."
  (cd "$PYNFS_DIR" && python3 setup.py build) || {
    echo "FATAL: pynfs build failed"; exit 1; }
fi

# --- start server ---
EXP=$(mktemp -d /tmp/nfsdpy-conf.XXXXXX)
chmod 777 "$EXP"
sudo pkill -f "nfsd.py.*-port $PORT" 2>/dev/null
sleep 0.3
(sudo python3 "$REPO/nfsd.py" -dir "$EXP" -port "$PORT" -bind 127.0.0.1 \
  > "$LOG" 2>&1 &)
up=0
for i in $(seq 1 20); do
  bash -c "echo > /dev/tcp/127.0.0.1/$PORT" 2>/dev/null && { up=1; break; }
  sleep 0.5
done
[ "$up" = "1" ] || { echo "FATAL: server did not start"; tail -20 "$LOG"; exit 1; }

# --- run the suite ---
cd "$PYNFS_DIR/$SUITE" || exit 1
timeout 2400 python3 -u testserver.py "127.0.0.1:$PORT/" $MINOR_ARGS \
  --maketree --rundeps --hidepass all > "$OUT" 2>&1
rc=$?
sudo pkill -f "nfsd.py.*-port $PORT" 2>/dev/null
if [ "$rc" != "0" ]; then
  echo "FATAL: testserver exited rc=$rc"
  tail -30 "$OUT"
  exit 1
fi

echo "=== pynfs summary ==="
tail -3 "$OUT"

# --- compare failures against the baseline ---
ACTUAL=$(grep -E ': FAILURE' "$OUT" | awk '{print $1}' | sort -u)
KNOWN=$(grep -vE '^\s*(#|$)' "$BASELINE" 2>/dev/null | awk '{print $1}' | sort -u)

NEW=$(comm -23 <(echo "$ACTUAL") <(echo "$KNOWN"))
FIXED=$(comm -13 <(echo "$ACTUAL") <(echo "$KNOWN"))

if [ -n "$FIXED" ]; then
  echo "--- NOTE: baseline entries that now PASS (tighten the baseline): ---"
  echo "$FIXED" | tr '\n' ' '; echo
fi

PASSED=$(grep -oE '[0-9]+ Passed' "$OUT" | awk '{print $1}')
if [ -z "$PASSED" ] || [ "$PASSED" -lt "$MIN_PASS" ]; then
  echo "FATAL: implausible pass count '$PASSED' (suite broken?)"
  exit 1
fi

if [ -n "$NEW" ]; then
  echo "=== REGRESSION: new conformance failures not in baseline: ==="
  echo "$NEW" | tr '\n' ' '; echo
  echo "--- details ---"
  for code in $NEW; do
    grep -A3 "^$code " "$OUT" | head -5
  done
  exit 1
fi

echo "=== conformance OK: no new failures ($PASSED passed) ==="
exit 0
